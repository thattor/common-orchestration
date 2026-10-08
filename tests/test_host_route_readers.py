"""#190 M3 host_routes reader hardening: the deferred coverage.

Mocks patch ONLY the file-IO seams (os.open/os.fstat/os.fdopen/os.getuid)
to force refusal paths that need no root, chown or faulted hardware; every
descriptor is real and closure is proven by an EBADF fstat taken OUTSIDE
the patch. No Native/Provider qualification is claimed here."""
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4 import host_routes as hr
from co_v4.launch_attestation import RouteUnqualified


def write(path, data, mode=0o600):
    path.write_bytes(data)
    os.chmod(path, mode)
    return path


def open_spy(recorded):
    """Delegate to the real os.open and record every issued descriptor."""
    real = os.open
    def spy(path, flags, *args):
        fd = real(path, flags, *args)
        recorded.append(fd)
        return fd
    return spy


class ProtectedReaderTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()          # Darwin realpath
        self.doc = write(self.base / 'doc.json', b'{"a": 1}')

    def _closed(self, fd):
        """The descriptor must be gone: fstat outside any patch -> EBADF."""
        try:
            os.fstat(fd)
        except OSError as exc:
            self.assertEqual(exc.errno, errno.EBADF)
        else:
            self.fail('leaked descriptor %d' % fd)

    def test_positive_baseline(self):
        self.assertEqual(hr.read_protected(str(self.doc)), b'{"a": 1}')
        self.assertEqual(hr.read_evidence(str(self.doc)), b'{"a": 1}')

    def test_hardlink_refused_fds_closed(self):
        link = self.base / 'hard.json'
        os.link(self.doc, link)                    # same file, nlink=2
        opened = []
        with patch.object(os, 'open', open_spy(opened)):
            for path in (str(link), str(self.doc)):
                with self.subTest(path=path):
                    with self.assertRaises(RouteUnqualified):
                        hr.read_protected(path)
        self.assertEqual(len(opened), 2)
        for fd in opened:
            self._closed(fd)
        os.unlink(link)                            # nlink back to 1
        self.assertEqual(hr.read_protected(str(self.doc)), b'{"a": 1}')

    def test_foreign_uid_refused_fds_closed(self):
        """getuid seam stands in for a foreign owner; no root or chown."""
        opened = []
        with patch.object(os, 'open', open_spy(opened)), \
                patch.object(os, 'getuid',
                             return_value=os.getuid() + 1):
            with self.assertRaises(RouteUnqualified):
                hr.read_protected(str(self.doc))
            with self.assertRaises(RouteUnqualified):
                hr.read_evidence(str(self.doc))
        self.assertEqual(len(opened), 2)
        for fd in opened:
            self._closed(fd)

    def test_fstat_failure_closes_real_fd(self):
        opened = []
        with patch.object(os, 'open', open_spy(opened)), \
                patch.object(os, 'fstat', side_effect=OSError('boom')):
            with self.assertRaises(RouteUnqualified):
                hr.read_protected(str(self.doc))
        self.assertEqual(len(opened), 1)
        self._closed(opened[0])

    def test_read_failure_and_bounded_body(self):
        real_fdopen = os.fdopen

        class BadHandle:
            def __init__(self, handle):
                self._handle = handle
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                self._handle.close()
            def read(self, n=-1):
                raise OSError('boom')

        opened = []
        with patch.object(os, 'open', open_spy(opened)), \
                patch.object(os, 'fdopen',
                             lambda fd, mode:
                                 BadHandle(real_fdopen(fd, mode))):
            with self.assertRaises(RouteUnqualified):
                hr.read_protected(str(self.doc))
        self.assertEqual(len(opened), 1)
        self._closed(opened[0])           # real fd freed on read failure
        opened = []                        # fresh fds for the evidence reader
        with patch.object(os, 'open', open_spy(opened)), \
                patch.object(os, 'fdopen',
                             lambda fd, mode:
                                 BadHandle(real_fdopen(fd, mode))):
            with self.assertRaises(RouteUnqualified):
                hr.read_evidence(str(self.doc))
        self.assertEqual(len(opened), 1)
        self._closed(opened[0])
        big = write(self.base / 'big.doc', b'x' * 8)
        with self.assertRaises(RouteUnqualified):   # body exceeds bound
            hr.read_protected(str(big), maximum=4)

    def test_invalid_maximum_never_opens(self):
        for maximum in (0, -7, True, 1.5, '8', None,
                        hr.MAX_DOC_BYTES + 1):
            with self.subTest(maximum=maximum):
                with patch.object(os, 'open') as trap:
                    with self.assertRaises(RouteUnqualified):
                        hr.read_protected(str(self.doc), maximum=maximum)
                    trap.assert_not_called()        # bound precedes open

    def test_regular_to_fifo_swap_race(self):
        """A regular file swapped for a FIFO between realpath and open:
        O_NONBLOCK means no hang, fstat still rejects, fd is closed."""
        path = str(self.base / 'race.doc')
        write(Path(path), b'{}')
        fds = []
        real = os.open

        def spy(p, flags, *args):
            if p == path and not fds:
                os.unlink(path)                  # simulate the swap race
                os.mkfifo(path)
            assert flags & os.O_NONBLOCK         # pin the no-hang contract
            fd = real(p, flags, *args)
            fds.append(fd)
            return fd

        with patch.object(os, 'open', spy):
            with self.assertRaises(RouteUnqualified):
                hr.read_protected(path)
        self.assertEqual(len(fds), 1)
        self._closed(fds[0])

    def test_evidence_oversize_and_non_regular(self):
        big = self.base / 'big.cap'
        with open(big, 'wb') as handle:
            handle.write(b'x')
            handle.seek(hr.MAX_EVIDENCE_BYTES)   # sparse: bound + 1
            handle.write(b'x')
        self.assertEqual(os.path.getsize(big),
                         hr.MAX_EVIDENCE_BYTES + 1)
        with self.assertRaises(RouteUnqualified):
            hr.read_evidence(str(big))
        with self.assertRaises(RouteUnqualified):
            hr.read_evidence(str(self.base))      # directory, not regular
        fifo = self.base / 'e.fifo'
        os.mkfifo(fifo)                           # NONBLOCK: no hang
        with self.assertRaises(RouteUnqualified):
            hr.read_evidence(str(fifo))


if __name__ == '__main__':
    unittest.main()
