"""Durable per-task journal and content-addressed text outputs. Stdlib only.

journal.jsonl holds canonical-JSON events {"seq":n,"kind":k,"data":{}} with seq
contiguous from 1; each append fsyncs before returning. On open, any torn or
unparsable line, non-canonical encoding, or sequence gap is journal_corrupt —
nothing is treated as unwritten. An exclusive nonblocking flock is held for
the journal lifetime; a second open raises journal_locked. Whole task state is
reconstructable from events; the runner owns event kinds.

Fixed codes: journal_corrupt, journal_locked, journal_missing, journal_io,
journal_closed, journal_data_invalid, output_corrupt, output_invalid,
output_ref_invalid (plus common path codes from private_dir).
"""
import dataclasses
import fcntl
import json
import os
import re
import stat
from pathlib import Path

from .. import contracts as _c
from ..output_store import IntegrityError, OutputStore
from .common import TaskError, canonical, private_dir

_KIND_RE = re.compile(r'[a-z][a-z0-9_]{0,39}')
_MAX_BYTES = 64 << 20
_ONOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)


class Journal:
    """One live handle per private task dir; context manager owns the flock."""

    def __init__(self, task_dir: Path, create: bool = False):
        task_dir = Path(task_dir)
        if not create and not os.path.lexists(task_dir):
            raise TaskError('journal_missing', 'task dir is absent')
        private_dir(task_dir, exist_ok=not create)
        self.task_dir = task_dir
        self.task_id = task_dir.name
        self._path = task_dir / 'journal.jsonl'
        st = self._path.lstat() if os.path.lexists(self._path) else None
        if st is not None and (not stat.S_ISREG(st.st_mode)
                               or st.st_uid != os.getuid() or st.st_nlink != 1
                               or stat.S_IMODE(st.st_mode) != 0o600):
            raise TaskError('path_invalid', 'journal must be an owner-private regular file')
        flags = os.O_RDWR | _ONOFOLLOW
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        try:
            self._fd = os.open(self._path, flags, 0o600)
        except FileExistsError:
            raise TaskError('path_conflict', 'journal already exists')
        except FileNotFoundError:
            raise TaskError('journal_missing', 'no journal in task dir')
        except OSError as exc:
            raise TaskError('journal_io', 'journal open failed') from exc
        self._events = []
        self._store = None
        self._closed = False
        # Lock first: no window where this handle exists unlocked, and a
        # foreign lock is never touched by our cleanup path.
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._closed = True
            os.close(self._fd)
            raise TaskError('journal_locked', 'journal is exclusively locked') from exc
        try:
            if create:
                os.fchmod(self._fd, 0o600)
                dfd = os.open(task_dir, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
        except OSError as exc:
            self.close()
            raise TaskError('journal_io', 'could not establish journal') from exc
        try:
            self._load()
        except BaseException:
            self.close()
            raise

    def _load(self):
        if os.fstat(self._fd).st_size > _MAX_BYTES:
            raise TaskError('journal_corrupt', 'journal exceeds size cap')
        blob = b''
        while True:
            chunk = os.read(self._fd, 1 << 20)
            if not chunk:
                break
            if len(blob) + len(chunk) > _MAX_BYTES:
                raise TaskError('journal_corrupt', 'journal exceeds size cap')
            blob += chunk
        try:
            text = blob.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise TaskError('journal_corrupt', 'not strict UTF-8') from exc
        if text and not text.endswith('\n'):
            raise TaskError('journal_corrupt', 'torn final line')
        lines = text.split('\n')[:-1] if text else []
        for n, line in enumerate(lines, 1):
            try:
                event = json.loads(line)
            except ValueError as exc:
                raise TaskError('journal_corrupt', 'line unparsable') from exc
            if (not isinstance(event, dict)
                    or set(event) != {'seq', 'kind', 'data'}
                    or type(event['seq']) is not int or event['seq'] != n
                    or not isinstance(event['kind'], str)
                    or not _KIND_RE.fullmatch(event['kind'])
                    or not isinstance(event['data'], dict)):
                raise TaskError('journal_corrupt', 'line malformed')
            try:
                canon = canonical(event)
            except (ValueError, TypeError) as exc:
                raise TaskError('journal_corrupt', 'line not strict JSON') from exc
            if canon != line:
                raise TaskError('journal_corrupt', 'line not canonical')
            self._events.append(event)

    def _require_open(self):
        if self._closed:
            raise TaskError('journal_closed', 'journal is closed')

    @property
    def events(self) -> list:
        """Deep copies of all verified events; safe to read after close."""
        return [json.loads(canonical(e)) for e in self._events]

    def append(self, kind: str, **data) -> dict:
        """Append one fsync'd event; returns a detached copy with its seq."""
        self._require_open()
        if not isinstance(kind, str) or not _KIND_RE.fullmatch(kind):
            raise TaskError('journal_data_invalid', 'bad event kind')
        event = {'seq': len(self._events) + 1, 'kind': kind, 'data': data}
        try:
            line = canonical(event)
        except (ValueError, TypeError) as exc:
            raise TaskError('journal_data_invalid', 'data not strict JSON') from exc
        stored = json.loads(line)
        if stored != event:
            raise TaskError('journal_data_invalid', 'data not round-trip stable')
        buf = line.encode('utf-8') + b'\n'
        if os.fstat(self._fd).st_size + len(buf) > _MAX_BYTES:
            raise TaskError('journal_data_invalid', 'journal exceeds size cap')
        os.lseek(self._fd, 0, os.SEEK_END)
        view = memoryview(buf)
        while view:
            view = view[os.write(self._fd, view):]
        os.fsync(self._fd)
        self._events.append(stored)
        return json.loads(line)

    def _store_for(self, write: bool) -> OutputStore:
        """Guarded lazy OutputStore; existing entries must be real dirs."""
        root = self.task_dir / 'out'
        for sub in (root, root / 'blobs', root / 'manifests', root / 'tmp'):
            st = sub.lstat() if os.path.lexists(sub) else None
            if st is None and not write:
                raise TaskError('output_corrupt', 'output store entry absent')
            if st is not None and (stat.S_ISLNK(st.st_mode)
                                   or not stat.S_ISDIR(st.st_mode)):
                raise TaskError('output_corrupt', 'output store entry unsafe')
        if self._store is None:
            if not write and not root.is_dir():
                raise TaskError('output_corrupt', 'output store absent')
            self._store = OutputStore(root)
        return self._store

    def put_text(self, step_id: str, call_id: str, text: str) -> dict:
        """Persist one plain-text item; returns a JSON-canonical record.

        The record is the AttemptOutput as plain JSON types (lists, not
        tuples), so it can be journaled via append() and reloaded verbatim.
        Only plain text is stored; raw reasoning or transcripts never are.
        """
        self._require_open()
        for label, value in (('step_id', step_id), ('call_id', call_id)):
            if (not isinstance(value, str) or not value or len(value) > 128
                    or '/' in value or '\\' in value or '\x00' in value):
                raise TaskError('journal_data_invalid', f'bad {label}')
        if not isinstance(text, str):
            raise TaskError('journal_data_invalid', 'text must be str')
        ref = _c.AttemptRef(run_id=self.task_id, job_id=step_id,
                            attempt_id=call_id)
        try:
            committed = self._store_for(True).put(
                ref, (_c.OutputItem(0, 'text/plain', text),))
        except IntegrityError as exc:
            raise TaskError('output_corrupt', 'store integrity failure') from exc
        except ValueError as exc:
            raise TaskError('output_invalid', 'output item rejected') from exc
        try:
            return json.loads(canonical(dataclasses.asdict(committed)))
        except (ValueError, TypeError) as exc:
            raise TaskError('output_invalid', 'record not JSON-serializable') from exc

    def get_text(self, record: dict) -> str:
        """Reconstitute typed refs from a put_text record and re-verify bytes.

        The record must bind this task (attempt_ref.run_id == task_id).
        Read-only: never creates the out store; an absent store, symlinked
        entry, or any digest mismatch is output_corrupt.
        """
        self._require_open()
        try:
            r = record['attempt_ref']
            ref = _c.AttemptRef(run_id=r['run_id'], job_id=r['job_id'],
                                attempt_id=r['attempt_id'])
            items = tuple(_c.OutputItemMeta(
                index=i['index'], media_type=i['media_type'],
                blob_digest=i['blob_digest'], size=i['size'])
                for i in record['items'])
            committed = _c.AttemptOutput(
                attempt_ref=ref, digest=record['digest'], items=items,
                total_bytes=record['total_bytes'],
                created_at=record.get('created_at'))
            out_ref = _c.OutputRef(attempt_ref=ref, digest=record['digest'])
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise TaskError('output_ref_invalid', 'malformed output record') from exc
        if ref.run_id != self.task_id:
            raise TaskError('output_ref_invalid', 'record bound to another task')
        try:
            texts = self._store_for(False).get(out_ref, committed)
        except IntegrityError as exc:
            raise TaskError('output_corrupt', 'store integrity failure') from exc
        if len(texts) != 1:
            raise TaskError('output_corrupt', 'expected a single text item')
        return texts[0]

    def close(self):
        if getattr(self, '_closed', True):
            return
        self._closed = True
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
