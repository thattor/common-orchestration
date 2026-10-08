"""Shared primitives for co_v4.task modules. Stdlib only, no private state.

Fixed TaskError codes: json_invalid, path_invalid, path_conflict,
lock_unavailable, lock_invalid, and the caller's busy code.
"""
import fcntl
import hashlib
import json
import os
import re
import stat
from pathlib import Path

_CODE_RE = re.compile(r'[a-z][a-z0-9_]{1,39}')


class TaskError(Exception):
    """Fixed-code task failure; .code is the only stable matching surface."""

    def __init__(self, code: str, detail: str = ''):
        if not _CODE_RE.fullmatch(code or ''):
            raise ValueError('invalid TaskError code')
        self.code = code
        self.detail = detail
        super().__init__(code if not detail else f'{code}: {detail}')


_ROUTE_RECOVERABLE = frozenset({
    'route_unavailable', 'route_unmeasured', 'measurement_missing',
    'measurement_drift', 'route_failed', 'route_refused',
    'route_timeout', 'route_overflow'})
_ROUTE_FAILURE_PHASES = frozenset({
    ('not_started', 'preflight'), ('not_started', 'spawn'),
    ('unknown', 'inference')})


class RouteFailure(TaskError):
    """Recoverable route failure; outcome/phase are the only added surface."""

    def __init__(self, code: str, outcome: str, phase: str):
        if not isinstance(code, str) or code not in _ROUTE_RECOVERABLE:
            raise ValueError('non-recoverable RouteFailure code')
        if not isinstance(outcome, str) or not isinstance(phase, str) \
                or (outcome, phase) not in _ROUTE_FAILURE_PHASES:
            raise ValueError('invalid RouteFailure outcome/phase')
        super().__init__(code)
        self.outcome = outcome
        self.phase = phase


def canonical(obj) -> str:
    """Sorted compact strict JSON; rejects NaN/Infinity and unknown types."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False)


def digest(data: bytes) -> str:
    """Exact 'sha256:<64 lowercase hex>' identity, matching co_v4.contracts."""
    return 'sha256:' + hashlib.sha256(data).hexdigest()


_FENCE = re.compile(r'```(json)?[^\S\r\n]*\r?\n(.*?)```', re.S | re.I)


def _no_const(value):
    raise TaskError('json_invalid', 'non-strict JSON constant')


def _no_dup(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise TaskError('json_invalid', 'duplicate key')
        out[key] = value
    return out


def parse_json(text: str) -> dict:
    """One strict JSON object, optionally inside a single fenced block only.

    Rejects prose around JSON, multiple/unbalanced fences, duplicate keys,
    non-strict constants, and non-object top levels.
    """
    if not isinstance(text, str):
        raise TaskError('json_invalid', 'input must be str')
    candidate = text.strip()
    match = _FENCE.fullmatch(candidate)
    if match:
        candidate = match.group(2).strip()
    elif candidate.startswith('```'):
        raise TaskError('json_invalid', 'extra or unbalanced fence markers')
    try:
        obj = json.loads(candidate, object_pairs_hook=_no_dup,
                         parse_constant=_no_const)
    except TaskError:
        raise
    except ValueError as exc:
        raise TaskError('json_invalid', 'unparsable JSON') from exc
    if not isinstance(obj, dict):
        raise TaskError('json_invalid', 'top-level JSON object required')
    return obj


def _is_private_dir(st) -> bool:
    return (not stat.S_ISLNK(st.st_mode) and stat.S_ISDIR(st.st_mode)
            and stat.S_IMODE(st.st_mode) == 0o700
            and st.st_uid == os.getuid())


def private_dir(path: Path, exist_ok: bool = False) -> Path:
    """Return a 0700 same-owner dir, creating it durably when absent.

    Refuses symlinks and non-private existing dirs; never follows links and
    never fixes a permissive existing dir in place.
    """
    path = Path(path)
    if not path.is_absolute():
        raise TaskError('path_invalid', 'absolute path required')
    st = path.lstat() if os.path.lexists(path) else None
    if st is not None:
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise TaskError('path_invalid', 'not a real directory')
        if not exist_ok:
            raise TaskError('path_conflict', 'path already exists')
        if stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.getuid():
            raise TaskError('path_invalid', 'dir is not owner-private 0700')
        return path
    pst = path.parent.lstat() if os.path.lexists(path.parent) else None
    if pst is None or stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
        raise TaskError('path_invalid', 'parent must be an existing real dir')
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        if exist_ok:
            st = path.lstat() if os.path.lexists(path) else None
            if st is not None and _is_private_dir(st):
                return path
        raise TaskError('path_conflict', 'path already exists')
    os.chmod(path, 0o700)  # mkdir mode is umask-masked
    pfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(pfd)
    finally:
        os.close(pfd)
    return path


class PrivateFileLock:
    """Private nonblocking flock; refuse unsafe files without repairing them."""

    def __init__(self, path, busy_code="lock_busy", *, shared=False):
        if not isinstance(shared, bool):
            raise TypeError("shared must be a bool")
        self._path = path
        self._busy_code = busy_code
        self._shared = shared
        self._fd = None

    def __enter__(self):
        try:
            fd = os.open(self._path,
                         os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK, 0o600)
        except OSError as exc:
            raise TaskError("lock_unavailable",
                            "cannot open the lock file safely") from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise TaskError("lock_invalid",
                     "lock file must be an owner-private regular file")
            try:
                op = fcntl.LOCK_SH if self._shared else fcntl.LOCK_EX
                fcntl.flock(fd, op | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise TaskError(
                    self._busy_code,
                    "state lock is held by another process") from exc
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        return self

    def __exit__(self, *exc):
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        return False
