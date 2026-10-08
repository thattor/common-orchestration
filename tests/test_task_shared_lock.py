"""Concurrency/race tests for co_v4.task.common shared primitives."""
import os
import stat
from pathlib import Path
from unittest import mock
import tempfile
import unittest
from co_v4.task.common import PrivateFileLock, TaskError, private_dir

def _code(fn, *args, **kwargs):
    with unittest.TestCase().assertRaises(TaskError) as info:
        fn(*args, **kwargs)
    return info.exception.code

def _lost_race(factory):
    """Patch Path.mkdir so the caller loses the creation race to factory."""

    def fake(self, mode=511, parents=False, exist_ok=False):
        factory(self)
        raise FileExistsError(str(self))
    return mock.patch.object(Path, 'mkdir', fake)

class SharedLockTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def test_shared_locks_coexist_on_independent_fds(self):
        tmp_path = self.root
        lock = tmp_path / 'state.lock'
        with PrivateFileLock(lock, shared=True):
            with PrivateFileLock(lock, shared=True):
                pass

    def test_exclusive_refused_while_shared_held(self):
        tmp_path = self.root
        lock = tmp_path / 'state.lock'
        with PrivateFileLock(lock, shared=True):
            assert _code(PrivateFileLock(lock).__enter__) == 'lock_busy'

    def test_shared_refused_while_exclusive_held(self):
        tmp_path = self.root
        lock = tmp_path / 'state.lock'
        with PrivateFileLock(lock):
            code = _code(PrivateFileLock(lock, shared=True).__enter__)
            assert code == 'lock_busy'

    def test_busy_code_passthrough_and_release(self):
        tmp_path = self.root
        lock = tmp_path / 'state.lock'
        with PrivateFileLock(lock, busy_code='state_busy', shared=True):
            code = _code(PrivateFileLock(lock, busy_code='other_busy').__enter__)
            assert code == 'other_busy'
        with PrivateFileLock(lock):
            pass

    def test_shared_param_must_be_bool(self):
        tmp_path = self.root
        lock = tmp_path / 'state.lock'
        with self.assertRaises(TypeError):
            PrivateFileLock(lock, shared=1)
        with self.assertRaises(TypeError):
            PrivateFileLock(lock, shared='yes')

    def test_shared_lock_keeps_unsafe_file_refusals(self):
        tmp_path = self.root
        real = tmp_path / 'real.lock'
        real.write_text('x')
        os.chmod(real, 384)
        link = tmp_path / 'link.lock'
        os.symlink(real, link)
        assert _code(PrivateFileLock(link, shared=True).__enter__) == 'lock_unavailable'
        os.link(real, tmp_path / 'dup.lock')
        assert _code(PrivateFileLock(real, shared=True).__enter__) == 'lock_invalid'
        mode = tmp_path / 'mode.lock'
        mode.write_text('x')
        os.chmod(mode, 420)
        assert _code(PrivateFileLock(mode, shared=True).__enter__) == 'lock_invalid'

    def test_private_dir_creates_owner_private(self):
        tmp_path = self.root
        target = tmp_path / 'd'
        assert private_dir(target) == target
        assert stat.S_IMODE(target.stat().st_mode) == 448

    def test_private_dir_accepts_valid_lost_create_race(self):
        tmp_path = self.root
        target = tmp_path / 'd'
        rival = lambda p: (os.mkdir(p), os.chmod(p, 448))
        with _lost_race(rival):
            assert private_dir(target, exist_ok=True) == target
        assert target.is_dir()

    def test_private_dir_lost_race_respects_exist_ok_false(self):
        tmp_path = self.root
        target = tmp_path / 'd'
        rival = lambda p: (os.mkdir(p), os.chmod(p, 448))
        with _lost_race(rival):
            assert _code(private_dir, target) == 'path_conflict'

    def test_private_dir_lost_race_rejects_unsafe_rival(self):
        tmp_path = self.root
        real = tmp_path / 'real'
        real.mkdir()
        rivals = [lambda p: os.symlink(real, p), lambda p: (os.mkdir(p), os.chmod(p, 493)), lambda p: p.write_text('x')]
        for (i, rival) in enumerate(rivals):
            with _lost_race(rival):
                code = _code(private_dir, tmp_path / f'd{i}', exist_ok=True)
                assert code == 'path_conflict'
if __name__ == '__main__':
    unittest.main()
