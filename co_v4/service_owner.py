"""Single-owner flock guard for one CO 0.4 local state root.

Qualified platform: Darwin arm64 on an ``apfs`` volume with MNT_LOCAL.
Everything else is refused with a fixed-code ``OwnerUnavailable``; codes
never carry paths, secrets, or raw exception text.
"""
from __future__ import annotations

import ctypes
import fcntl
import os
import platform
import stat
from pathlib import Path

MNT_LOCAL = 0x1000
_STATFS_SIZE = 2168
_FSTYPE_LEN = 16
_LOCK_NAME = "service.lock"
_DB_FILES = ("control.sqlite", "control.sqlite-journal",
             "control.sqlite-wal", "control.sqlite-shm")
_STATFS_OFFSETS = {
    "f_bsize": 0, "f_blocks": 8, "f_bfree": 16, "f_bavail": 24,
    "f_files": 32, "f_ffree": 40, "f_fsid": 48, "f_flags": 64,
    "f_fstypename": 72, "f_mntonname": 88, "f_mntfromname": 1112,
    "f_flags_ext": 2136, "f_reserved": 2140,
}
_OUT_DIRS = ("outputs", "outputs/blobs",
             "outputs/manifests", "outputs/tmp")
_OPEN_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_OPEN_LOCK = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC


class OwnerUnavailable(Exception):
    """Fixed-code ownership failure; the message is the code itself."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _Statfs(ctypes.Structure):  # Darwin arm64 statfs (INODE64 layout)
    _fields_ = [
        ("f_bsize", ctypes.c_uint32), ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64), ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64), ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64), ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32), ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32), ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * _FSTYPE_LEN),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


_libc = None


def _fstatfs_buf(fd: int) -> _Statfs:
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        _libc.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
        _libc.fstatfs.restype = ctypes.c_int
    buf = _Statfs()
    if _libc.fstatfs(fd, ctypes.byref(buf)) != 0:
        raise OwnerUnavailable("fs_unverified")
    return buf


def _cstr(buf, field, size):
    raw = ctypes.string_at(ctypes.addressof(buf) + field.offset, size)
    nul = raw.find(b"\0")
    if nul < 0:
        raise OwnerUnavailable("fs_unverified")
    return raw[:nul]


def _fsinfo(fd: int):
    """Return (fsid, fstypename, flags) after the layout self-check."""
    if ctypes.sizeof(_Statfs) != _STATFS_SIZE or any(
            getattr(_Statfs, n).offset != o
            for n, o in _STATFS_OFFSETS.items()):
        raise OwnerUnavailable("fs_unverified")
    buf = _fstatfs_buf(fd)
    fv = os.fstatvfs(fd)
    if buf.f_bsize not in (fv.f_bsize, fv.f_frsize) \
            or buf.f_blocks != fv.f_blocks:
        raise OwnerUnavailable("fs_unverified")
    if not buf.f_bavail <= buf.f_bfree <= buf.f_blocks \
            or buf.f_ffree > buf.f_files:
        raise OwnerUnavailable("fs_unverified")
    name = _cstr(buf, _Statfs.f_fstypename, _FSTYPE_LEN)
    try:
        name.decode("ascii")
    except UnicodeDecodeError:
        raise OwnerUnavailable("fs_unverified") from None
    mnt = os.fsdecode(_cstr(buf, _Statfs.f_mntonname, 1024))
    _cstr(buf, _Statfs.f_mntfromname, 1024)
    if not os.path.isabs(mnt):
        raise OwnerUnavailable("fs_unverified")
    try:
        mnt_dev = os.stat(mnt).st_dev
    except OSError:
        raise OwnerUnavailable("fs_unverified") from None
    if mnt_dev != os.fstat(fd).st_dev:
        raise OwnerUnavailable("fs_unverified")
    return (int(buf.f_fsid[0]), int(buf.f_fsid[1])), name, \
        int(buf.f_flags)


def _close_fd(fd: int) -> None:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass


class ServiceOwner:
    """Holds the root dirfd and the flock-ed ``service.lock`` fd.

    Same-uid processes are trusted; ``0o700`` on the root excludes all
    others. ``check()`` detects identity swaps; it does not defend
    against a hostile same-uid process.
    """

    def __init__(self, root: Path, root_fd: int, lock_fd: int, fsid):
        self._root = root
        self._root_fd = root_fd
        self._lock_fd = lock_fd
        self._fsid = fsid
        self._closed = False

    @property
    def root(self) -> Path:
        return self._root

    @property
    def lock_path(self) -> Path:
        return self._root / _LOCK_NAME

    @classmethod
    def acquire(cls, root) -> "ServiceOwner":
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise OwnerUnavailable("unsupported_platform")
        root = Path(root)
        try:
            canonical = os.path.realpath(root) == os.fspath(root)
            lst = os.lstat(root)
        except OSError:
            raise OwnerUnavailable("root_unverified") from None
        if not canonical or not stat.S_ISDIR(lst.st_mode) \
                or lst.st_uid != os.getuid() \
                or stat.S_IMODE(lst.st_mode) != 0o700:
            raise OwnerUnavailable("root_unverified")
        root_fd = lock_fd = -1
        try:
            try:
                root_fd = os.open(root, _OPEN_DIR)
            except OSError:
                raise OwnerUnavailable("root_unverified") from None
            st = os.fstat(root_fd)
            if (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino):
                raise OwnerUnavailable("root_unverified")
            fsid, name, flags = _fsinfo(root_fd)
            if name != b"apfs" or not flags & MNT_LOCAL:
                raise OwnerUnavailable("unsupported_filesystem")
            try:
                lock_fd = os.open(_LOCK_NAME, _OPEN_LOCK, 0o600,
                                  dir_fd=root_fd)
            except FileNotFoundError:
                try:
                    lock_fd = os.open(_LOCK_NAME, _OPEN_LOCK, 0o600,
                                      dir_fd=root_fd)
                except OSError:
                    raise OwnerUnavailable("lock_unverified") from None
            except OSError:
                raise OwnerUnavailable("lock_unverified") from None
            st = os.fstat(lock_fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 \
                    or st.st_uid != os.getuid() \
                    or stat.S_IMODE(st.st_mode) != 0o600 \
                    or os.get_inheritable(lock_fd):
                raise OwnerUnavailable("lock_unverified")
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise OwnerUnavailable("owned_elsewhere") from None
            self = cls(root, root_fd, lock_fd, fsid)
            self._check_entries()
            return self
        except BaseException:
            _close_fd(lock_fd)  # closing also releases the flock
            _close_fd(root_fd)
            raise

    def _check_entries(self) -> None:
        """Kind/nlink/uid/device check for DB sidecars and output dirs,
        all via lstat relative to the held root fd."""
        dev = os.fstat(self._root_fd).st_dev
        uid = os.getuid()
        entries = [(n, False) for n in _DB_FILES]
        entries += [(n, True) for n in _OUT_DIRS]
        for name, want_dir in entries:
            try:
                st = os.stat(name, dir_fd=self._root_fd,
                             follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                raise OwnerUnavailable("root_unverified") from None
            kind_ok = stat.S_ISDIR(st.st_mode) if want_dir \
                else stat.S_ISREG(st.st_mode)
            if not kind_ok or st.st_uid != uid \
                    or (not want_dir and st.st_nlink != 1):
                raise OwnerUnavailable("root_unverified")
            if st.st_dev != dev:
                raise OwnerUnavailable("fs_mismatch")

    def check(self) -> None:
        """Verify lock/root identity and fsid; raise ``owner_lost``."""
        if self._closed:
            raise OwnerUnavailable("owner_lost")
        try:
            held_l = os.fstat(self._lock_fd)
            held_r = os.fstat(self._root_fd)
            cur_l = os.stat(_LOCK_NAME, dir_fd=self._root_fd,
                            follow_symlinks=False)
            cur_r = os.lstat(self._root)
        except OSError:
            raise OwnerUnavailable("owner_lost") from None
        if (held_l.st_dev, held_l.st_ino) != (cur_l.st_dev, cur_l.st_ino) \
                or (held_r.st_dev, held_r.st_ino) \
                != (cur_r.st_dev, cur_r.st_ino):
            raise OwnerUnavailable("owner_lost")
        try:
            fsid, _, _ = _fsinfo(self._root_fd)
        except OwnerUnavailable:
            raise OwnerUnavailable("owner_lost") from None
        if fsid != self._fsid:
            raise OwnerUnavailable("owner_lost")

    def bind_stores(self, store, output_store) -> None:
        """Re-verify post-creation layout and store paths. Call before
        any driver start or listener open."""
        self.check()
        if Path(store.controller().storage_path) \
                != self._root / "control.sqlite" \
                or Path(output_store.root) != self._root / "outputs":
            raise OwnerUnavailable("root_unverified")
        self._check_entries()
        dev = os.fstat(self._root_fd).st_dev
        for name in _OUT_DIRS:
            try:
                dfd = os.open(name, _OPEN_DIR, dir_fd=self._root_fd)
            except OSError:
                raise OwnerUnavailable("root_unverified") from None
            try:
                if os.fstat(dfd).st_dev != dev:
                    raise OwnerUnavailable("fs_mismatch")
                fsid, _, _ = _fsinfo(dfd)
                if fsid != self._fsid:
                    raise OwnerUnavailable("fs_mismatch")
            finally:
                _close_fd(dfd)

    def close(self) -> None:
        """Release the flock and close both fds. The lock file itself
        is never unlinked."""
        if self._closed:
            return
        self._closed = True
        lock_fd, root_fd = self._lock_fd, self._root_fd
        self._lock_fd = self._root_fd = -1
        _close_fd(lock_fd)
        _close_fd(root_fd)
