"""Content-addressed output blobs for the 0.4 output pipeline.

put() is atomic and idempotent per content: durable item blobs plus a
write-once canonical manifest keyed by the content digest. Per-Attempt
immutability and conflict are owned solely by control state
(record_attempt_output); created_at is stamped there, never here. A crash
between blob/manifest commit and the DB reference leaves only orphans;
GC is deferred. Output text is exact strict UTF-8 with no normalization
or trimming, and no Worker bytes are trusted.
"""
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

from . import contracts as c


DOMAIN = b'co.output/1\n'


class IntegrityError(Exception):
    """Persisted output content no longer matches its committed identity."""


class OutputRejected(ValueError):
    """Collector output violates the frozen output schema; never retried."""


def _is_digest(value) -> bool:
    return (type(value) is str and len(value) == 71
            and value.startswith('sha256:')
            and all(ch in '0123456789abcdef' for ch in value[7:]))


def _hex(data: bytes) -> str:
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def _manifest_bytes(items: tuple[c.OutputItemMeta, ...]) -> bytes:
    """Restricted canonical JSON: str/int scalars, sorted keys, no floats."""
    payload = [{'index': m.index, 'media_type': m.media_type,
                'blob_digest': m.blob_digest, 'size': m.size} for m in items]
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def _parse_manifest(raw: bytes) -> tuple[c.OutputItemMeta, ...]:
    try:
        payload = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as exc:
        raise IntegrityError('manifest is not decodable') from exc
    if not isinstance(payload, list):
        raise IntegrityError('manifest is not an ordered list')
    metas = []
    for entry in payload:
        if (not isinstance(entry, dict)
                or set(entry) != {'index', 'media_type', 'blob_digest', 'size'}):
            raise IntegrityError('manifest item schema mismatch')
        try:
            metas.append(c.OutputItemMeta(entry['index'], entry['media_type'],
                                          entry['blob_digest'], entry['size']))
        except ValueError as exc:
            raise IntegrityError('manifest item rejected') from exc
    return tuple(metas)


class OutputStore:
    """Host-owned blob root; one content digest owns one immutable manifest."""

    def __init__(self, root, guard=None):
        self.root = Path(root)
        if not self.root.is_absolute():
            raise ValueError('absolute output store root required')
        self._guard = guard
        # Guard precedes the first filesystem mutation, not only put().
        if guard is not None:
            guard()
        for name in ('blobs', 'manifests', 'tmp'):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def _commit(self, subdir: str, name: str, data: bytes):
        """Write-once content object; existing different bytes are corruption."""
        tmp = self.root / 'tmp' / uuid4().hex
        with open(tmp, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        target = self.root / subdir / name
        try:
            # Atomic write-once: link never overwrites an existing address.
            os.link(tmp, target)
        except FileExistsError:
            if target.read_bytes() != data:
                raise IntegrityError('content-addressed object conflict')
            # Identical bytes may already be linked, but the linking winner can
            # still be paused before its own directory fsync. Fall through to
            # the same fsync so this call returns only with the entry durable.
        finally:
            tmp.unlink(missing_ok=True)
        directory = os.open(self.root / subdir, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def put(self, ref: c.AttemptRef, items) -> c.AttemptOutput:
        """Durably persist items and their manifest; return unstamped identity."""
        if self._guard is not None:
            self._guard()
        if type(ref) is not c.AttemptRef:
            raise ValueError('typed AttemptRef required')
        if type(items) is not tuple or any(type(i) is not c.OutputItem for i in items):
            raise OutputRejected('collector must return a tuple of OutputItem')
        metas = []
        for index, item in enumerate(items):
            if item.index != index:
                raise OutputRejected('output items must be ordered from zero')
            try:
                data = item.text.encode('utf-8')
            except UnicodeEncodeError as exc:
                raise OutputRejected('output text is not strict UTF-8 encodable') from exc
            blob_digest = _hex(data)
            self._commit('blobs', blob_digest[7:], data)
            metas.append(c.OutputItemMeta(index, item.media_type, blob_digest, len(data)))
        metas = tuple(metas)
        manifest = _manifest_bytes(metas)
        digest = _hex(DOMAIN + manifest)
        self._commit('manifests', digest[7:], manifest)
        return c.AttemptOutput(ref, digest, metas, sum(m.size for m in metas))

    def manifest(self, digest: str) -> tuple[c.OutputItemMeta, ...]:
        """Load and re-verify a manifest by digest."""
        if not _is_digest(digest):
            raise IntegrityError('invalid output digest')
        try:
            raw = (self.root / 'manifests' / digest[7:]).read_bytes()
        except OSError as exc:
            raise IntegrityError('output manifest unavailable') from exc
        if _hex(DOMAIN + raw) != digest:
            raise IntegrityError('manifest digest mismatch')
        return _parse_manifest(raw)

    def get(self, ref: c.OutputRef, committed: c.AttemptOutput) -> tuple[str, ...]:
        """Ordered item texts, after exact ref/digest/metadata/blob checks."""
        if type(ref) is not c.OutputRef or type(committed) is not c.AttemptOutput:
            raise ValueError('typed OutputRef and committed AttemptOutput required')
        if committed.attempt_ref != ref.attempt_ref:
            raise IntegrityError('committed output belongs to another Attempt')
        if committed.digest != ref.digest:
            raise IntegrityError('output digest binding mismatch')
        metas = self.manifest(ref.digest)
        if metas != committed.items or sum(m.size for m in metas) != committed.total_bytes:
            raise IntegrityError('persisted manifest does not match committed metadata')
        texts = []
        for meta in metas:
            try:
                raw = (self.root / 'blobs' / meta.blob_digest[7:]).read_bytes()
            except OSError as exc:
                raise IntegrityError('output blob unavailable') from exc
            if len(raw) != meta.size or _hex(raw) != meta.blob_digest:
                raise IntegrityError('output blob corrupted')
            try:
                texts.append(raw.decode('utf-8'))
            except UnicodeDecodeError as exc:
                raise IntegrityError('output blob is not valid UTF-8') from exc
        return tuple(texts)
