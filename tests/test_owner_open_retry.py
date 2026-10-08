"""Single ENOENT retry on the 'service.lock' dirfd open.

Covers the one identical retry permitted on an initial ENOENT:
success after one retry, refusal on a second ENOENT or any other
errno, negatives (symlink, bad mode, extra link), no fd leaks, and
no truncation of a pre-existing lock file. The real two-process
race lives in test_service_owner.py and is not duplicated here.
"""
import errno
import os
import platform
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import co_v4.service_owner as so
from co_v4.service_owner import OwnerUnavailable, ServiceOwner

_QUALIFIED = platform.system() == "Darwin" \
    and platform.machine() == "arm64"
_LOCK_FLAGS = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC


class _LockOpenSpy:
    """os.open pass-through: records every 'service.lock' dir_fd
    open and injects the queued errnos into successive such calls.
    All other opens delegate to the real os.open unchanged."""

    def __init__(self, errnos=()):
        self.errnos = list(errnos)
        self.calls = []
        self._real = os.open

    def __call__(self, path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None and os.fspath(path) == "service.lock":
            self.calls.append((path, flags, mode, dir_fd))
            if self.errnos:
                # OSError(ENOENT, ...) instantiates FileNotFoundError.
                raise OSError(self.errnos.pop(0), "")
        return self._real(path, flags, mode, dir_fd=dir_fd)


def _open_fds():
    """Open fd set via /dev/fd. The transient enumeration fd is
    excluded consistently: fstat fails on it once listdir closes it."""
    out = set()
    for name in os.listdir("/dev/fd"):
        if name.isdigit():
            try:
                os.fstat(int(name))
            except OSError:
                continue
            out.add(int(name))
    return out


class OwnerOpenRetryTest(unittest.TestCase):
    def make_root(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(os.path.realpath(td.name)) / "state"
        root.mkdir()
        root.chmod(0o700)
        return root

    def acquire(self, root):
        if _QUALIFIED:
            return ServiceOwner.acquire(root)
        with self.assertRaises(OwnerUnavailable) as ei:
            ServiceOwner.acquire(root)
        self.assertEqual(ei.exception.code, "unsupported_platform")
        return None

    def acquire_fails(self, root, code):
        with self.assertRaises(OwnerUnavailable) as ei:
            ServiceOwner.acquire(root)
        exc = ei.exception
        self.assertEqual(exc.code,
                         code if _QUALIFIED else "unsupported_platform")
        self.assertEqual(str(exc), exc.code)

    def test_single_enoent_retried_once_identically(self):
        root = self.make_root()
        if not _QUALIFIED:
            self.acquire_fails(root, "unsupported_platform")
            return
        spy = _LockOpenSpy([errno.ENOENT])
        with mock.patch.object(so.os, "open", spy):
            owner = ServiceOwner.acquire(root)
        try:
            self.assertEqual(len(spy.calls), 2)
            self.assertEqual(spy.calls[0], spy.calls[1])
            path, flags, mode, dir_fd = spy.calls[0]
            self.assertEqual(path, "service.lock")
            self.assertEqual(flags, _LOCK_FLAGS)
            self.assertFalse(flags & (os.O_TRUNC | os.O_EXCL))
            self.assertEqual(mode, 0o600)
            self.assertEqual(dir_fd, owner._root_fd)
            st = os.lstat(root / "service.lock")
            self.assertTrue(stat.S_ISREG(st.st_mode))
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
            self.assertEqual(st.st_nlink, 1)
        finally:
            owner.close()

    def test_second_enoent_refused_no_fd_leak(self):
        root = self.make_root()
        if not _QUALIFIED:
            self.acquire_fails(root, "unsupported_platform")
            return
        spy = _LockOpenSpy([errno.ENOENT, errno.ENOENT])
        before = _open_fds()
        with mock.patch.object(so.os, "open", spy):
            self.acquire_fails(root, "lock_unverified")
        self.assertEqual(len(spy.calls), 2)
        self.assertEqual(spy.calls[0], spy.calls[1])
        self.assertEqual(_open_fds(), before)

    def test_other_errno_never_retried(self):
        for err in (errno.EACCES, errno.ELOOP):
            with self.subTest(errno=err):
                root = self.make_root()
                if not _QUALIFIED:
                    self.acquire_fails(root, "unsupported_platform")
                    continue
                spy = _LockOpenSpy([err])
                with mock.patch.object(so.os, "open", spy):
                    self.acquire_fails(root, "lock_unverified")
                self.assertEqual(len(spy.calls), 1)

    def test_symlink_lock_no_retry_target_untouched(self):
        root = self.make_root()
        if not _QUALIFIED:
            self.acquire_fails(root, "unsupported_platform")
            return
        target = root / "target"
        target.write_bytes(b"payload")
        target.chmod(0o600)
        (root / "service.lock").symlink_to("target")
        spy = _LockOpenSpy()
        with mock.patch.object(so.os, "open", spy):
            self.acquire_fails(root, "lock_unverified")
        self.assertEqual(len(spy.calls), 1)
        self.assertEqual(target.read_bytes(), b"payload")
        self.assertEqual(
            stat.S_IMODE(os.lstat(target).st_mode), 0o600)

    def test_retry_bad_file_still_refused_no_fd_leak(self):
        for case in ("mode", "nlink"):
            with self.subTest(case=case):
                root = self.make_root()
                if not _QUALIFIED:
                    self.acquire_fails(root, "unsupported_platform")
                    continue
                p = root / "service.lock"
                p.write_bytes(b"x")
                p.chmod(0o600)
                if case == "mode":
                    p.chmod(0o644)
                else:
                    os.link(p, root / "alias")
                spy = _LockOpenSpy([errno.ENOENT])
                before = _open_fds()
                with mock.patch.object(so.os, "open", spy):
                    self.acquire_fails(root, "lock_unverified")
                self.assertEqual(len(spy.calls), 2)
                self.assertEqual(_open_fds(), before)

    def test_existing_lock_bytes_and_inode_preserved(self):
        root = self.make_root()
        p = root / "service.lock"
        p.write_bytes(b"owner-bytes")
        p.chmod(0o600)
        ino = os.lstat(p).st_ino
        owner = self.acquire(root)
        if owner is None:
            return
        try:
            self.assertEqual(p.read_bytes(), b"owner-bytes")
            self.assertEqual(os.lstat(p).st_ino, ino)
        finally:
            owner.close()
        self.assertEqual(p.read_bytes(), b"owner-bytes")
        self.assertEqual(os.lstat(p).st_ino, ino)


if __name__ == "__main__":
    unittest.main()
