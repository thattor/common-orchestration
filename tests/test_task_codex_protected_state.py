import os
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock
from co_v4.task import admission, codex_route
from co_v4.task.common import TaskError

class ProtectedStateTest(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        for name in ('cwd', 'host', 'store'):
            (base / name).mkdir(448)
        self.cwd, self.root = (base / 'cwd', base / 'host')
        self.ledger = self.root / 'capacity.db'
        self.ledger.touch(384)
        self.generic = base / 'store' / 'note.txt'
        self.generic.touch(420)
        patcher = mock.patch.object(admission, '_host_root', return_value=self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def call(self, files, cwd=None):
        return codex_route._validate_protected_state(files, str(self.cwd) if cwd is None else cwd)

    def reject(self, files, cwd=None):
        with self.assertRaises(TaskError):
            self.call(files, cwd)

    def test_pass_order_freshness(self):
        both = (self.ledger, self.generic)
        self.assertEqual(self.call(both), both)
        self.assertEqual(self.call(both[::-1]), both[::-1])
        self.assertIsNot(self.call(both), self.call(both))
        self.assertEqual(self.call((self.ledger, self.ledger)), (self.ledger, self.ledger))
        sub = type(self.ledger)(os.fspath(self.ledger))
        self.assertEqual(self.call((sub,)), (self.ledger,))
        with mock.patch.object(os, 'open', side_effect=AssertionError):
            self.assertEqual(self.call(both), both)

    def test_bounds_types_and_paths(self):
        for bad in ((), [self.ledger], 'x', (os.fspath(self.ledger),), (PurePosixPath('/x'),), (self.ledger, None), (self.ledger,) + (self.generic,) * 8):
            self.reject(bad)
        (self.root.parent / 'link').symlink_to(self.generic)
        for bad in (self.root / 'missing', self.root, self.cwd, self.root.parent / 'link', Path('relative/x'), Path(os.fspath(self.generic) + '/..')):
            self.reject((self.ledger, bad))

    def test_cwd_overlap(self):
        (self.root.parent / 'cwdlink').symlink_to(self.cwd)
        (self.cwd / 'inner').touch()
        for bad in (self.cwd, str(self.generic), str(self.cwd) + '/', str(self.cwd.parent), os.fspath(self.root.parent / 'cwdlink')):
            self.reject((self.ledger,), cwd=bad)
        self.reject((self.ledger, self.cwd / 'inner'))

    def test_ledger(self):
        self.reject((self.generic,))
        self.ledger.chmod(420)
        self.reject((self.ledger,))
        self.ledger.chmod(384)
        os.link(self.ledger, self.root / 'dup')
        self.reject((self.ledger,))
        os.unlink(self.root / 'dup')
        self.root.chmod(493)
        self.reject((self.ledger,))
        self.root.chmod(448)
        self.ledger.unlink()
        self.reject((self.ledger,))
        self.root.rmdir()
        self.reject((self.ledger,))

    def test_resolver_errors_interrupts(self):
        with mock.patch.object(os, 'getuid', return_value=os.getuid() + 1):
            self.reject((self.ledger,))
        with mock.patch.object(admission, '_host_root', side_effect=OSError('x')):
            self.reject((self.ledger,))
        with mock.patch.object(os.path, 'commonpath', side_effect=ValueError('x')):
            self.reject((self.ledger,))
        interrupt = KeyboardInterrupt()
        with mock.patch.object(os, 'lstat', side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.call((self.ledger,))
        self.assertIs(caught.exception, interrupt)
        exit_error = SystemExit(3)
        with mock.patch.object(admission, 'canonical_ledger_path', side_effect=exit_error):
            with self.assertRaises(SystemExit) as caught:
                self.call((self.ledger,))
        self.assertIs(caught.exception, exit_error)

    def test_rejects_tuple_subclass(self):
        subclass = type('ProtectedStateTuple', (tuple,), {})
        self.reject(subclass((self.ledger,)))

    def test_rejects_cwd_str_subclass(self):
        subclass = type('ProtectedStateCwd', (str,), {})
        self.reject((self.ledger,), cwd=subclass(os.fspath(self.cwd)))

    def test_fspath_str_subclass_error_fails(self):

        class BrokenString(str):

            def __len__(self):
                raise OSError('x')

        class BrokenPath(type(Path())):

            def __fspath__(self):
                return BrokenString(str(self))
        self.reject((self.ledger, BrokenPath(os.fspath(self.generic))))
