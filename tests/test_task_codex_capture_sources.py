import hashlib, os, tempfile, unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock
from co_v4.task import codex_route as route
from co_v4.task.common import TaskError


class CaptureSourcesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name).resolve()
        self.data = {name: f'{i}:{name}'.encode() for i, name in enumerate(route.SOURCE_FILES)}
        self.assertEqual(len(self.data), 20)
        for name, data in self.data.items():
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data); os.chmod(path, 0o644)
    def tearDown(self): self.tmp.cleanup()
    def capture(self, forbidden):
        with mock.patch.object(route, '_package_root', return_value=self.root): return route._capture_sources(forbidden)
    def denied(self, forbidden=frozenset({(1, 2)})):
        with self.assertRaises(TaskError) as caught: self.capture(forbidden)
        self.assertEqual(caught.exception.code, 'route_unmeasured')
    @contextmanager
    def io_spy(self, before_open=None, read_error=None):
        real_open, real_read, real_close = os.open, os.read, os.close
        calls = {'open': 0, 'read': 0, 'close': 0}
        def open_wrapped(path, flags, *args):
            calls['open'] += 1
            if before_open: before_open(path)
            return real_open(path, flags, *args)
        def read_wrapped(fd, size):
            calls['read'] += 1
            if read_error: raise read_error
            return real_read(fd, size)
        def close_wrapped(fd):
            calls['close'] += 1
            return real_close(fd)
        with mock.patch.object(route.os, 'open', open_wrapped), mock.patch.object(route.os, 'read', read_wrapped), mock.patch.object(route.os, 'close', close_wrapped):
            yield calls
    def test_exact_fresh_map_and_hash_contract(self):
        forbidden = frozenset({(123, 456)})
        expected = {name: 'sha256:' + hashlib.sha256(data).hexdigest() for name, data in self.data.items()}
        with mock.patch.object(route, '_hash_path', wraps=route._hash_path) as spy:
            first, second = self.capture(forbidden), self.capture(forbidden)
        self.assertEqual((first, second, list(first)), (expected, expected, list(route.SOURCE_FILES)))
        self.assertIsNot(first, second); self.assertEqual(forbidden, frozenset({(123, 456)}))
        self.assertEqual(len(spy.call_args_list), 2 * len(route.SOURCE_FILES))
        for call in spy.call_args_list:
            self.assertEqual((call.args[1], call.kwargs), (route._MAX_SOURCE_BYTES, {'forbidden': forbidden}))
    def test_invalid_forbidden_fails_before_hash_or_open(self):
        bad = (None, frozenset(), {(1, 2)}, [(1, 2)], frozenset({(True, 2)}), frozenset({(1,)}), frozenset({(1, -2)}), frozenset({(1, 2, 3)}), frozenset((n, n) for n in range(9)))
        with mock.patch.object(route, '_hash_path') as hashed, mock.patch.object(route.os, 'open') as opened:
            for forbidden in bad:
                with self.subTest(forbidden=forbidden): self.denied(forbidden)
        hashed.assert_not_called(); opened.assert_not_called()
    def test_missing_oversized_and_nonregular_sources_refuse(self):
        observer = self.root / 'codex_text_observer.py'; observer.unlink(); self.denied()
        observer.write_bytes(self.data['codex_text_observer.py']); common = self.root / 'task/common.py'; common.unlink(); self.denied()
        common.write_bytes(self.data['task/common.py']); engine = self.root / 'codex_engine.py'; engine.write_bytes(b'x' * (route._MAX_SOURCE_BYTES + 1)); self.denied()
        engine.unlink(); os.mkfifo(engine); self.denied()
    def test_source_component_and_outside_symlinks_refuse(self):
        source = self.root / 'codex_engine.py'; source.unlink(); source.symlink_to(self.root / 'codex_host.py'); self.denied()
        source.unlink()
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / 'outside.py'; target.write_bytes(b'outside'); source.symlink_to(target); self.denied()
        source.unlink(); moved = self.root / 'adapters-real'; (self.root / 'adapters').rename(moved)
        (self.root / 'adapters').symlink_to(moved, target_is_directory=True); self.denied()
    def test_commonpath_error_and_forbidden_alias_refuse_before_content_io(self):
        with mock.patch.object(route.os.path, 'commonpath', side_effect=ValueError): self.denied()
        source = self.root / 'codex_engine.py'; os.link(source, self.root / 'fixture-alias')
        identity = os.lstat(source); forbidden = frozenset({(identity.st_dev, identity.st_ino)})
        with mock.patch.object(route.os, 'open', side_effect=AssertionError) as opened, mock.patch.object(route.os, 'read', side_effect=AssertionError) as read:
            self.denied(forbidden)
        opened.assert_not_called(); read.assert_not_called()
    def test_open_identity_read_error_and_interrupt_cleanup(self):
        source = self.root / 'codex_engine.py'; staged = self.root / 'staged-source'; done = []
        def replace_once(path):
            if Path(path) == source and not done: done.append(True); staged.write_bytes(b'changed'); staged.replace(source)
        with self.io_spy(replace_once) as calls: self.denied()
        self.assertEqual((calls['open'], calls['close']), (1, 1))
        with self.io_spy(read_error=OSError('read')) as calls: self.denied()
        self.assertEqual((calls['open'], calls['read'], calls['close']), (1, 1, 1))
        with self.io_spy(read_error=KeyboardInterrupt()) as calls, self.assertRaises(KeyboardInterrupt): self.capture(frozenset({(1, 2)}))
        self.assertEqual((calls['open'], calls['read'], calls['close']), (1, 1, 1))
