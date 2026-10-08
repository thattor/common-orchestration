"""stdlib unittest coverage for co_v4.task.admission."""
from contextlib import closing
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from co_v4.adapter_capacity import MAX_CONCURRENT
from co_v4.task import admission
from co_v4.task.common import RouteFailure, TaskError

ZERO = {'reserved': 0, 'executing': 0}


def _ok_invoke(before_launch, on_stopped):
    before_launch()
    on_stopped(True)
    return 'ok'


def _hold_invoke(before_launch, on_stopped):
    before_launch()
    return 'held-no-proof'


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / 'host-root'
        patcher = mock.patch.object(admission, '_host_root', lambda: self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.cwd = self.tmp / 'native'
        self.cwd.mkdir()
        (self.tmp / 'state' / 'calls').mkdir(parents=True)

    def call_dir(self, name):
        d = self.tmp / 'state' / 'calls' / name
        d.mkdir(mode=0o700)
        os.chmod(d, 0o700)
        return d

    def _make_db(self, config):
        self.root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700)
        dbp = self.root / 'capacity.db'
        admission.CapacityLedger(dbp)
        with closing(sqlite3.connect(dbp)) as conn, conn:
            conn.execute('UPDATE capacity_config SET version=?, maximum=? WHERE id=1', config)
        return dbp

    def test_outside_cwd_call_succeeds(self):
        cd = self.call_dir('c1')
        seen = []
        def invoke(before_launch, on_stopped):
            seen.append('invoke')
            before_launch()
            on_stopped(True)
            return 'result'
        with admission.gate(self.cwd):
            out = admission.model_call('claude', 'm1', 'p', cd, invoke)
        self.assertEqual(out, 'result')
        self.assertEqual(seen, ['invoke'])
        ev = json.loads((cd / 'admission.json').read_text())
        self.assertTrue(ev['confirmed'])
        st = admission.capacity_status()
        self.assertTrue(st['initialized'])
        self.assertEqual(st['limit'], MAX_CONCURRENT)
        self.assertEqual(st['routes']['claude'], ZERO)
        self.assertEqual(st['routes']['devin'], ZERO)

    def test_call_dir_inside_cwd_rejected(self):
        inside = self.cwd / 'call'
        inside.mkdir(mode=0o700)
        os.chmod(inside, 0o700)
        with admission.gate(self.cwd):
            with self.assertRaises(TaskError):
                admission.model_call('claude', 'm', 'p', inside, _ok_invoke)
        self.assertFalse((inside / 'admission.json').exists())

    def test_call_dir_must_be_private_real_dir(self):
        permissive = self.call_dir('perm')
        os.chmod(permissive, 0o755)
        link = self.tmp / 'state' / 'calls' / 'link'
        os.symlink(self.call_dir('target'), link)
        with admission.gate(self.cwd):
            for bad in (permissive, link, self.tmp / 'state' / 'calls' / 'none',
                        'relative/dir', self.root):
                with self.assertRaises(TaskError):
                    admission.model_call('claude', 'm', 'p', bad, _ok_invoke)

    def test_false_proof_and_missing_callback_hold(self):
        def false_proof(before_launch, on_stopped):
            before_launch()
            on_stopped(False)
        def no_stop(before_launch, on_stopped):
            before_launch()
        with admission.gate(self.cwd):
            with self.assertRaises(TaskError) as cm:
                admission.model_call('claude', 'm', 'p',
                                     self.call_dir('f1'), false_proof)
            self.assertIn('route_stop_unconfirmed', str(cm.exception))
            with self.assertRaises(TaskError):
                admission.model_call('claude', 'm', 'p',
                                     self.call_dir('f2'), no_stop)
        self.assertEqual(
            admission.capacity_status()['routes']['claude']['executing'], 2)

    def test_nonbool_and_early_stop_rejected(self):
        def nonbool(before_launch, on_stopped):
            before_launch()
            on_stopped('yes')
        def early(before_launch, on_stopped):
            on_stopped(True)
        with admission.gate(self.cwd):
            with self.assertRaises(TaskError):
                admission.model_call('claude', 'm', 'p',
                                     self.call_dir('n1'), nonbool)
            with self.assertRaises(TaskError):
                admission.model_call('claude', 'm', 'p',
                                     self.call_dir('n2'), early)
        st = admission.capacity_status()['routes']['claude']
        self.assertEqual(st['executing'], 1)
        self.assertEqual(st['reserved'], 0)

    def test_caller_callback_exception_releases_reserved(self):
        def boom():
            raise RuntimeError('caller boom')
        def invoke(before_launch, on_stopped):
            before_launch()
        with admission.gate(self.cwd):
            with self.assertRaises(RuntimeError):
                admission.model_call('claude', 'm', 'p', self.call_dir('cb'),
                                     invoke, before_launch=boom)
        self.assertEqual(
            admission.capacity_status()['routes']['claude'], ZERO)

    def test_exact_no_child_failure_releases(self):
        def invoke(before_launch, on_stopped):
            before_launch()
            raise RouteFailure('route_unavailable', 'not_started', 'spawn')
        with admission.gate(self.cwd):
            with self.assertRaises(RouteFailure):
                admission.model_call('claude', 'm', 'p',
                                     self.call_dir('nc'), invoke)
        self.assertEqual(
            admission.capacity_status()['routes']['claude'], ZERO)

    def test_wrong_phase_failure_holds(self):
        def invoke(before_launch, on_stopped):
            before_launch()
            raise RouteFailure('route_unavailable', 'not_started', 'preflight')
        with admission.gate(self.cwd):
            with self.assertRaises(RouteFailure):
                admission.model_call('claude', 'm', 'p',
                                     self.call_dir('wp'), invoke)
        self.assertEqual(
            admission.capacity_status()['routes']['claude']['executing'], 1)

    def test_global_limit_per_adapter(self):
        calls = [0]
        def hold(before_launch, on_stopped):
            calls[0] += 1
            before_launch()
        with admission.gate(self.cwd):
            for i in range(12):
                with self.assertRaises(TaskError):
                    admission.model_call('claude', 'model-%d' % i, 'p',
                                         self.call_dir('h%d' % i), hold)
            self.assertEqual(calls[0], 12)
            with self.assertRaises(TaskError) as cm:
                admission.model_call('claude', 'm', 'p',
                                     self.call_dir('overflow'), hold)
            self.assertIn('capacity_full', str(cm.exception))
            self.assertEqual(calls[0], 12)
            self.assertEqual(
                admission.model_call('devin', 'm', 'p',
                                     self.call_dir('dv'), _ok_invoke), 'ok')

    def test_preexisting_evidence_never_overwritten(self):
        cd = self.call_dir('pre')
        (cd / 'admission.json').write_text('{"keep": 1}')
        invoked = []
        def invoke(before_launch, on_stopped):
            invoked.append(1)
        with admission.gate(self.cwd):
            with self.assertRaises(TaskError):
                admission.model_call('claude', 'm', 'p', cd, invoke)
        self.assertEqual(invoked, [])
        self.assertEqual((cd / 'admission.json').read_text(), '{"keep": 1}')
        self.assertEqual(
            admission.capacity_status()['routes']['claude'], ZERO)

    def test_symlink_and_permissive_root_refused(self):
        safe = self.tmp / 'real-root'
        safe.mkdir(mode=0o700)
        os.chmod(safe, 0o700)
        os.symlink(safe, self.root)
        with self.assertRaises(TaskError):
            with admission.gate(self.cwd):
                pass
        self.root.unlink()
        self.root.mkdir(mode=0o755)
        with self.assertRaises(TaskError):
            with admission.gate(self.cwd):
                pass

    def test_absent_status_writes_nothing(self):
        st = admission.capacity_status()
        self.assertFalse(st['initialized'])
        self.assertEqual(st['limit'], MAX_CONCURRENT)
        self.assertFalse(self.root.exists())

    def test_unsafe_or_invalid_status_raises(self):
        self.root.mkdir(mode=0o755)
        with self.assertRaises(TaskError):
            admission.capacity_status()
        shutil.rmtree(self.root)
        os.symlink(self.tmp, self.root)
        with self.assertRaises(TaskError):
            admission.capacity_status()
        self.root.unlink()
        dbp = self._make_db((1, 12))
        with self.assertRaises(TaskError):
            admission.capacity_status()
        dbp.unlink()
        dbp.write_bytes(b'junk')
        os.chmod(dbp, 0o600)
        with self.assertRaises(TaskError):
            admission.capacity_status()
        dbp.unlink()
        self._make_db((2, MAX_CONCURRENT))
        os.link(self.root / 'capacity.db', self.root / 'dup.db')
        with self.assertRaises(TaskError):
            admission.capacity_status()

    def test_empty_initialized_status(self):
        self._make_db((2, MAX_CONCURRENT))
        st = admission.capacity_status()
        self.assertTrue(st['initialized'])
        self.assertEqual(st['routes']['claude'], ZERO)
        self.assertEqual(st['routes']['devin'], ZERO)

    def test_held_setup_blocks_normal_gate(self):
        with admission.gate(self.cwd, setup=True):
            with self.assertRaises(TaskError):
                admission.model_call('claude', 'm', 'p',
                                     self.call_dir('s1'), _hold_invoke)
        for kw in ({}, {'setup': True}):
            with self.assertRaises(TaskError) as cm:
                with admission.gate(self.cwd, **kw):
                    pass
            self.assertIn('route_busy', str(cm.exception))

    def test_held_task_row_lets_normal_call_proceed(self):
        with admission.gate(self.cwd):
            with self.assertRaises(TaskError):
                admission.model_call('claude', 'm', 'p',
                                     self.call_dir('t1'), _hold_invoke)
        with admission.gate(self.cwd):
            self.assertEqual(
                admission.model_call('devin', 'm', 'p',
                                     self.call_dir('t2'), _ok_invoke), 'ok')


if __name__ == '__main__':
    unittest.main()
