"""statfs layout self-check tests: offset/size constants, volatile
counter tolerance, injected buffer negatives, unchanged guards, and
a real-host stress run of _fsinfo plus owner.check under file churn.
"""
import ctypes
import os
import platform
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import co_v4.service_owner as so
from co_v4.service_owner import OwnerUnavailable, ServiceOwner

_QUALIFIED = platform.system() == "Darwin" \
    and platform.machine() == "arm64"
_OFFSETS = {"f_bsize": 0, "f_blocks": 8, "f_bfree": 16,
            "f_bavail": 24, "f_files": 32, "f_ffree": 40,
            "f_fsid": 48, "f_flags": 64, "f_fstypename": 72,
            "f_mntonname": 88, "f_mntfromname": 1112,
            "f_flags_ext": 2136, "f_reserved": 2140}
_FV = {"f_bsize": 4096, "f_frsize": 4096, "f_blocks": 2000000,
       "f_bfree": 111, "f_bavail": 222, "f_files": 333,
       "f_ffree": 44, "f_favail": 55, "f_flag": 0, "f_namemax": 255}


def _buf(root, **over):
    """Plausible apfs statfs buffer; mntonname points at root."""
    b = so._Statfs()
    b.f_bsize, b.f_blocks = _FV["f_bsize"], _FV["f_blocks"]
    b.f_bfree, b.f_bavail = 1500000, 1400000
    b.f_files, b.f_ffree = 100000000, 90000000
    b.f_fsid[0], b.f_fsid[1] = 1, 2
    b.f_flags = so.MNT_LOCAL
    b.f_fstypename = b"apfs"
    b.f_mntonname = os.fsencode(os.fspath(root))
    b.f_mntfromname = b"/dev/disk3s1"
    for k, v in over.items():
        setattr(b, k, v)
    return b


def _volatile_fv(fv):
    """Real fstatvfs with usage counters shifted; bsize/blocks kept."""
    return os.statvfs_result(
        (fv.f_bsize, fv.f_frsize, fv.f_blocks, fv.f_bfree + 7,
         fv.f_bavail + 7, fv.f_files + 7, fv.f_ffree + 7,
         fv.f_favail, fv.f_flag, fv.f_namemax))


class OwnerStatfsTest(unittest.TestCase):
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

    def _fsinfo_with(self, buf, fd, **fvo):
        """_fsinfo against an injected buffer and fstatvfs; os.stat
        and os.fstat stay real for the mount cross-check."""
        fv = os.statvfs_result(tuple(fvo.get(k, _FV[k]) for k in _FV))
        with mock.patch.object(so, "_fstatfs_buf", lambda f: buf), \
             mock.patch.object(so.os, "fstatvfs", lambda f: fv):
            return so._fsinfo(fd)

    def test_offsets_and_size(self):
        for name, off in _OFFSETS.items():
            self.assertEqual(getattr(so._Statfs, name).offset, off,
                             name)
        self.assertEqual(ctypes.sizeof(so._Statfs), 2168)
        self.assertEqual(so._STATFS_SIZE, 2168)

    def test_layout_constants_enforced(self):
        root = self.make_root()
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for patch in (mock.patch.object(so, "_STATFS_SIZE", 1),
                          mock.patch.dict(so._STATFS_OFFSETS,
                                          {"f_bsize": 1})):
                with patch:
                    with self.assertRaises(OwnerUnavailable) as ei:
                        self._fsinfo_with(_buf(root), fd)
                self.assertEqual(ei.exception.code, "fs_unverified")
        finally:
            os.close(fd)

    def test_buffer_negatives(self):
        root = self.make_root()
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        cases = (
            ("bsize", _buf(root, f_bsize=8), {}),
            ("blocks", _buf(root, f_blocks=9), {}),
            ("bavail>bfree", _buf(root, f_bavail=1600000), {}),
            ("bfree>blocks", _buf(root, f_bfree=3000000), {}),
            ("ffree>files", _buf(root, f_ffree=200000000), {}),
            ("type_nonascii", _buf(root, f_fstypename=b"\xffa"), {}),
            ("mnt_no_nul", _buf(root, f_mntonname=b"x" * 1024), {}),
            ("mnt_relative", _buf(root, f_mntonname=b"rel"), {}),
            ("mnt_missing",
             _buf(root, f_mntonname=b"/no-such-co04-mnt"), {}),
            ("mnt_otherdev", _buf(root, f_mntonname=b"/dev"), {}),
            ("from_no_nul", _buf(root, f_mntfromname=b"y" * 1024), {}),
            ("zeroed", so._Statfs(), {}),
            ("fv_bsize", _buf(root), dict(f_bsize=1, f_frsize=1)),
            ("fv_blocks", _buf(root), dict(f_blocks=1)),
        )
        try:
            for label, buf, fvo in cases:
                with self.subTest(label=label):
                    with self.assertRaises(OwnerUnavailable) as ei:
                        self._fsinfo_with(buf, fd, **fvo)
                    self.assertEqual(ei.exception.code, "fs_unverified")
        finally:
            os.close(fd)

    def test_volatile_counters_tolerated(self):
        root = self.make_root()
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fsid, name, flags = self._fsinfo_with(_buf(root), fd)
        finally:
            os.close(fd)
        self.assertEqual((name, flags), (b"apfs", so.MNT_LOCAL))
        owner = self.acquire(root)
        if owner is None:
            return
        try:
            real = os.fstatvfs  # capture before patching to avoid
            fake = lambda f: _volatile_fv(real(f))  # recursion
            with mock.patch.object(so.os, "fstatvfs", fake):
                owner.check()
            owner.close()
            with mock.patch.object(so.os, "fstatvfs", fake):
                owner2 = ServiceOwner.acquire(root)
                owner2.close()
        finally:
            owner.close()

    def test_guards_unchanged(self):
        root = self.make_root()
        with mock.patch.object(so, "_fsinfo",
                               lambda fd: ((1, 2), b"apfs", 0)):
            self.acquire_fails(root, "unsupported_filesystem")
        with mock.patch.object(so, "_fsinfo",
                               lambda fd: ((1, 2), b"nfs",
                                           so.MNT_LOCAL)):
            self.acquire_fails(root, "unsupported_filesystem")
        with mock.patch.object(so.platform, "system",
                               return_value="Linux"):
            self.acquire_fails(root, "unsupported_platform")
        owner = self.acquire(root)
        if owner is None:
            return
        try:
            with mock.patch.object(
                    so, "_fsinfo",
                    lambda fd: ((9, 9), b"apfs", so.MNT_LOCAL)):
                with self.assertRaises(OwnerUnavailable) as ei:
                    owner.check()
            self.assertEqual(ei.exception.code, "owner_lost")
        finally:
            owner.close()

    def test_fsinfo_and_check_stress(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        stop = threading.Event()
        churn = root / "stress.bin"
        payload = b"x" * 262144
        counts = {}
        stats = [0, 0]  # completed write+unlink cycles, OSError count

        def writer():
            while not stop.is_set():
                try:
                    churn.write_bytes(payload)
                    churn.unlink()
                    stats[0] += 1
                except OSError:
                    stats[1] += 1

        def run(want):
            ni = nc = 0
            deadline = time.monotonic() + 120
            while (ni < want[0] or nc < want[1]) \
                    and time.monotonic() < deadline:
                if ni < want[0]:
                    so._fsinfo(owner._root_fd)
                    ni += 1
                if nc < want[1]:
                    owner.check()
                    nc += 1
            return ni, nc

        try:
            counts["quiet"] = run((10000, 2000))
            t = threading.Thread(target=writer)
            t.start()
            try:
                counts["busy"] = run((10000, 2000))
            finally:
                stop.set()
                t.join(30)
                self.assertFalse(t.is_alive(),
                                 "churn writer still running")
        finally:
            owner.close()
            try:
                churn.unlink()
            except OSError:
                pass
        self.assertGreater(stats[0], 0,
                           "churn writer completed no cycles")
        print("stress receipt: counts=%r churn_cycles=%d "
              "churn_errors=%d" % (counts, stats[0], stats[1]))
        self.assertEqual(counts, {"quiet": (10000, 2000),
                                  "busy": (10000, 2000)})


if __name__ == "__main__":
    unittest.main()
