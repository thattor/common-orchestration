import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from co_v4.task import codex_route
from co_v4.task.common import TaskError


class CaptureCredentialsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = os.path.realpath(tmp.name)
        self.home, self.cwd = (os.path.join(root, d) for d in ('home', 'cwd'))
        codex = os.path.join(self.home, '.codex')
        os.makedirs(codex); os.mkdir(self.cwd); os.chmod(codex, 0o755)
        self.auth = self._put('auth.json')

    def _put(self, name, mode=0o600, parent=None):
        path = os.path.join(parent or os.path.join(self.home, '.codex'), name)
        with open(path, 'w') as fh:
            fh.write('x')
        os.chmod(path, mode)
        return path

    def call(self, files=None, cwd=None, home=None):
        return codex_route._capture_credentials(
            (self.auth,) if files is None else files, cwd or self.cwd,
            home or self.home)

    def test_success(self):
        extra = self._put('extra')
        calls, real = [], codex_route._validate_credentials
        spy = lambda i, c: calls.append((i, c)) or real(i, c)
        boom = mock.Mock(side_effect=AssertionError('io'))
        files = (Path(extra), self.auth)
        with mock.patch.object(codex_route, '_validate_credentials', spy), \
                mock.patch('builtins.open', boom), \
                mock.patch('subprocess.Popen', boom), \
                mock.patch.multiple(os, open=boom, read=boom, chmod=boom):
            records, forbidden = self.call(files)
        st, st2 = os.lstat(self.auth), os.lstat(extra)
        self.assertEqual([r['path'] for r in records], [extra, self.auth])
        self.assertEqual(records[1], {'path': self.auth, 'dev': st.st_dev,
            'ino': st.st_ino, 'uid': st.st_uid, 'mode': st.st_mode})
        self.assertEqual(forbidden, frozenset({(st.st_dev, st.st_ino),
                                               (st2.st_dev, st2.st_ino)}))
        self.assertEqual(calls, [([records[0], records[1]], self.cwd)])
        again = self.call(files)
        self.assertEqual(again, (records, forbidden))
        self.assertIsNot(again[0][0], records[0])
        self.assertEqual(files, (Path(extra), self.auth))

    def test_failures(self):
        codex = os.path.dirname(self.auth)
        bad = self._put('bad', 0o644)
        extra, inside = self._put('extra'), self._put('in', parent=self.cwd)
        link = os.path.join(codex, 'link')
        os.symlink(self.auth, link)
        dot = os.path.join(codex, '..', '.codex', 'auth.json')
        cases = ((), (extra,), (extra, extra), [self.auth], None, self.auth,
                 (self.auth,) * 9, (self.auth, b'/x'), (self.auth, 5), (dot,),
                 (self.auth, bad), (self.auth, inside), (self.auth, link),
                 (self.auth, codex), (self.auth, self.auth),
                 (self.auth, os.path.join(codex, 'missing')))
        for files in cases:
            with self.assertRaises(TaskError) as ctx:
                codex_route._capture_credentials(files, self.cwd, self.home)
            self.assertEqual(ctx.exception.code, 'route_unmeasured')
        f = codex_route._capture_credentials
        self.assertRaises(TaskError, f, (self.auth,), None, self.home)
        self.assertRaises(TaskError, f, (self.auth,), self.cwd, b'/x')
        os.link(self.auth, os.path.join(codex, 'hard'))
        with self.assertRaises(TaskError):
            self.call((self.auth, os.path.join(codex, 'hard')))

    def test_drift_and_interrupt(self):
        real, seen = codex_route._lstat, set()
        def tamper(path):
            st = real(path)
            if path == self.auth and path in seen:
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev,
                    st.st_nlink, st.st_uid + 1, st.st_gid, st.st_size,
                    st.st_atime, st.st_mtime, st.st_ctime))
            seen.add(path)
            return st
        with mock.patch.object(codex_route, '_lstat', tamper):
            with self.assertRaises(TaskError):
                self.call()
        with mock.patch.object(codex_route, '_lstat',
                               side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.call()

    def test_path_failure_is_closed_and_systemexit_propagates(self):
        class BrokenPath(type(Path())):
            def __fspath__(self): raise OSError('sensitive path detail')
        with self.assertRaises(TaskError) as ctx:
            self.call((self.auth, BrokenPath('/fixed')))
        self.assertEqual((ctx.exception.code, ctx.exception.detail), ('route_unmeasured', ''))
        with mock.patch.object(codex_route, '_lstat', side_effect=SystemExit):
            with self.assertRaises(SystemExit): self.call()
