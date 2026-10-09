"""Focused tests for the Codex admission hold/setup additions.

Standalone unittest suite: stdlib only, patches admission._host_root to an
isolated canonical temporary root, and seeds ledger rows through the real
CapacityLedger/_Request contracts.
"""
import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from co_v4 import contracts as c
from co_v4.adapter_capacity import MAX_CONCURRENT, CapacityLedger
from co_v4.task import admission
from co_v4.task.common import (PrivateFileLock, RouteFailure, TaskError,
                               digest)


def _request(adapter, run_id, tag):
    return admission._Request(
        ref=c.AttemptRef(run_id, 'job-' + tag, 'attempt-' + tag),
        conditions=admission._Conditions(adapter),
        model_digest=digest(('model-' + tag).encode()),
        input_digest=digest(('input-' + tag).encode()),
        binding_digest=digest(('binding-' + tag).encode()))


def _scope(cwd):
    return hashlib.sha256(str(cwd).encode()).hexdigest()


class AdmissionCodexTest(unittest.TestCase):
    """Isolated canonical host root per test; no real host/auth state."""

    def setUp(self):
        self._tmp_obj = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp_obj.cleanup)
        self.tmp = Path(self._tmp_obj.name).resolve()
        self.root = self.tmp / 'host'
        patcher = mock.patch.object(admission, '_host_root',
                                    return_value=self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.cwd = self._mkdir('cwd')
        self.state = self._mkdir('state', 0o700)

    def _mkdir(self, name, mode=0o755, parent=None):
        path = (parent or self.tmp) / name
        path.mkdir()
        os.chmod(path, mode)
        return path

    def _mk_root(self):
        self.root.mkdir()
        os.chmod(self.root, 0o700)
        return self.root

    def _call_dir(self, tag):
        return self._mkdir('calls-' + tag, 0o700)

    def _ledger(self):
        if not self.root.exists():
            self._mk_root()
        return CapacityLedger(self.root / 'capacity.db')

    def _seed(self, adapter, run_id, tag, claim=False):
        ledger = self._ledger()
        req = _request(adapter, run_id, tag)
        self.assertTrue(ledger.reserve(req, 'owner-' + tag))
        if claim:
            ledger.claim(req, 'owner-' + tag)
        return req

    def _code(self, fn, *args, **kwargs):
        with self.assertRaises(TaskError) as cm:
            fn(*args, **kwargs)
        return cm.exception.code

    def _gate_code(self, *args, **kwargs):
        with self.assertRaises(TaskError) as cm:
            with admission.gate(*args, **kwargs):
                pass
        return cm.exception.code

    def _hold_code(self, cwd, state, **kwargs):
        with self.assertRaises(TaskError) as cm:
            with admission.hold(cwd, state, **kwargs):
                pass
        return cm.exception.code

    def _ok_invoke(self, before_launch=None, on_stopped=None):
        before_launch()
        on_stopped(True)
        return 'ok'

    def test_shared_hold_prevents_workspace_setup(self):
        with admission.hold(self.cwd, self.state):
            self.assertEqual(self._gate_code(self.cwd, state_dir=self.state,
                                             setup=True), 'route_busy')

    def test_resolver_ignores_environment_and_creates_nothing(self):
        env = {'HOME': '/nonexistent-home',
               'XDG_STATE_HOME': '/nonexistent-state',
               'XDG_DATA_HOME': '/nonexistent-data'}
        with mock.patch.dict(os.environ, env):
            path = admission.canonical_ledger_path()
        self.assertIsInstance(path, Path)
        self.assertEqual(path, self.root / 'capacity.db')
        self.assertFalse(self.root.exists())
        self._mk_root()
        self.assertEqual(admission.canonical_ledger_path(),
                         self.root / 'capacity.db')
        self.assertFalse((self.root / 'capacity.db').exists())

    def test_resolver_refuses_unsafe_root_and_db(self):
        real = self._mkdir('real-root', 0o700)
        link = self.tmp / 'link-root'
        link.symlink_to(real, target_is_directory=True)
        with mock.patch.object(admission, '_host_root', return_value=link):
            self.assertEqual(self._code(admission.canonical_ledger_path),
                             'capacity_invalid')
        file_root = self.tmp / 'file-root'
        file_root.write_text('x')
        with mock.patch.object(admission, '_host_root',
                               return_value=file_root):
            self.assertEqual(self._code(admission.canonical_ledger_path),
                             'capacity_invalid')
        self._mk_root()
        os.chmod(self.root, 0o755)
        self.assertEqual(self._code(admission.canonical_ledger_path),
                         'capacity_invalid')
        os.chmod(self.root, 0o700)
        db = self.root / 'capacity.db'
        db.touch()
        os.chmod(db, 0o600)
        self.assertEqual(admission.canonical_ledger_path(), db)
        os.chmod(db, 0o644)
        self.assertEqual(self._code(admission.canonical_ledger_path),
                         'capacity_invalid')
        os.chmod(db, 0o600)
        extra_link = self.tmp / 'db-second-link'
        os.link(db, extra_link)
        self.assertEqual(self._code(admission.canonical_ledger_path),
                         'capacity_invalid')
        extra_link.unlink()
        db_target = self.tmp / 'db-target'
        db_target.write_text('x')
        db.unlink()
        db.symlink_to(db_target)
        self.assertEqual(self._code(admission.canonical_ledger_path),
                         'capacity_invalid')

    def test_hold_rejects_bad_state_dirs(self):
        self._mk_root()
        loose = self._mkdir('loose-state', 0o755)
        file_state = self.tmp / 'file-state'
        file_state.write_text('x')
        sym_state = self.tmp / 'sym-state'
        sym_state.symlink_to(self.state, target_is_directory=True)
        inner_state = self._mkdir('inner-state', 0o700, parent=self.cwd)
        outer_state = self._mkdir('outer-state', 0o700)
        nested_cwd = self._mkdir('nested-cwd', parent=outer_state)
        bad_states = [self.tmp / 'missing', loose, 'relative-state',
                      file_state, sym_state, inner_state, self.cwd,
                      self.root, self.tmp]
        for bad in bad_states:
            with self.subTest(state=str(bad)):
                self.assertEqual(self._hold_code(self.cwd, bad),
                                 'capacity_invalid')
        self.assertEqual(self._hold_code(nested_cwd, outer_state),
                         'capacity_invalid')

    def test_hold_yields_none_and_blocks_model_call(self):
        invoked = []

        def invoke(**kwargs):
            invoked.append(kwargs)
            return 'x'

        with admission.hold(self.cwd, self.state,
                            binding={'worker': 'w'}) as token:
            self.assertIsNone(token)
            self.assertIsNone(admission._CURRENT.get())
            self.assertEqual(
                self._code(lambda: admission.model_call(
                    'codex', 'm', 'p', str(self._call_dir('nested')),
                    invoke)),
                'capacity_invalid')
        self.assertEqual(invoked, [])
        self.assertEqual(self._ledger().unresolved(), ())

    def test_active_task_gate_refuses_hold(self):
        with admission.gate(self.cwd):
            self.assertIsNotNone(admission._CURRENT.get())
            self.assertEqual(self._hold_code(self.cwd, self.state),
                             'capacity_invalid')

    def test_shared_holds_and_task_gates_overlap(self):
        entered = threading.Event()
        done = threading.Event()
        errors = []

        def worker():
            try:
                with admission.hold(self.cwd, self.state):
                    entered.set()
                    if not done.wait(10):
                        errors.append('worker timeout')
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker)
        thread.start()
        self.assertTrue(entered.wait(10))
        state2 = self._mkdir('state2', 0o700)
        cwd2 = self._mkdir('cwd2')
        try:
            with admission.hold(self.cwd, state2):
                with admission.gate(self.cwd):
                    pass
            with admission.hold(cwd2, self.state):
                pass
        finally:
            done.set()
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_exclusive_locks_refuse(self):
        self._mk_root()
        with PrivateFileLock(self.state / 'infer.lock',
                             busy_code='route_busy'):
            self.assertEqual(self._hold_code(self.cwd, self.state),
                             'route_busy')
        with admission.hold(self.cwd, self.state):
            with self.assertRaises(TaskError) as cm:
                with PrivateFileLock(self.state / 'infer.lock',
                                     busy_code='route_busy'):
                    pass
            self.assertEqual(cm.exception.code, 'route_busy')
        with admission.gate(self.cwd, setup=True):
            self.assertEqual(self._gate_code(self.cwd), 'route_busy')
        with admission.gate(self.cwd):
            with admission.gate(self._mkdir('cwd3')):
                pass

    def test_partial_entry_failure_releases_infer_lock(self):
        self._seed('claude.print', f'setup-cwd:{_scope(self.cwd)}', 'seed')
        self.assertEqual(self._hold_code(self.cwd, self.state), 'route_busy')
        with PrivateFileLock(self.state / 'infer.lock',
                             busy_code='route_busy'):
            pass
        self.assertEqual(self._hold_code(self.cwd, self.state), 'route_busy')

    def test_service_codex_rows_block_explicit_setup_only(self):
        self._seed('codex.app-server', 'svc-a', 'a')
        self._seed('codex.app-server', 'svc-b', 'b', claim=True)
        other_cwd = self._mkdir('other-cwd')
        other_state = self._mkdir('other-state', 0o700)
        self.assertEqual(
            self._gate_code(other_cwd, state_dir=other_state, setup=True,
                            codex_setup=True),
            'route_busy')
        with admission.gate(other_cwd, state_dir=other_state, setup=True):
            pass
        with admission.gate(other_cwd, state_dir=other_state):
            pass
        with admission.hold(other_cwd, other_state):
            pass
        status = admission.capacity_status()
        self.assertEqual(status['routes']['codex'],
                         {'reserved': 1, 'executing': 1})

    def test_noncodex_rows_do_not_block_codex_setup(self):
        self._seed('claude.print', 'svc-c', 'c', claim=True)
        self._seed('devin.acp', 'svc-d', 'd')
        with admission.gate(self.cwd, state_dir=self.state, setup=True,
                            codex_setup=True):
            pass

    def test_codex_setup_flag_validation(self):
        for bad in (0, 1, 'true', None, object()):
            with self.subTest(bad=repr(bad)):
                self.assertEqual(
                    self._gate_code(self.cwd, setup=True, codex_setup=bad),
                    'capacity_invalid')
        self.assertEqual(self._gate_code(self.cwd, codex_setup=True),
                         'capacity_invalid')
        self.assertEqual(
            self._gate_code(self.cwd, setup=False, codex_setup=True),
            'capacity_invalid')
        self._seed('codex.app-server', 'svc-e', 'e')
        with admission.gate(self.cwd, setup=True):
            pass
        with admission.gate(self.cwd):
            pass

    def test_codex_model_call_full_lifecycle(self):
        events = []

        def invoke(before_launch=None, on_stopped=None):
            events.append('invoke')
            before_launch()
            events.append('launched')
            rows = self._ledger().unresolved()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].adapter, 'codex.app-server')
            self.assertEqual(rows[0].phase, 'executing')
            on_stopped(True)
            events.append('stopped')
            return 'answer'

        with admission.gate(self.cwd):
            result = admission.model_call('codex', 'codex-model', 'prompt',
                                          str(self._call_dir('life')), invoke)
        self.assertEqual(result, 'answer')
        self.assertEqual(events, ['invoke', 'launched', 'stopped'])
        self.assertEqual(self._ledger().unresolved(), ())
        self.assertTrue((self.tmp / 'calls-life' / 'admission.json').exists())
        status = admission.capacity_status()
        self.assertEqual(status['routes']['codex'],
                         {'reserved': 0, 'executing': 0})

    def test_codex_unconfirmed_stop_stays_durable(self):
        def make_invoke(stop):
            def invoke(before_launch=None, on_stopped=None):
                before_launch()
                if stop is not None:
                    on_stopped(stop)
                return 'x'
            return invoke

        for idx, stop in enumerate((False, None)):
            with self.subTest(stop=stop):
                with admission.gate(self.cwd):
                    self.assertEqual(
                        self._code(lambda: admission.model_call(
                            'codex', 'm', 'p',
                            str(self._call_dir('stop%d' % idx)),
                            make_invoke(stop))),
                        'route_stop_unconfirmed')
                rows = self._ledger().unresolved()
                self.assertEqual(len(rows), idx + 1)
                self.assertEqual(rows[idx].adapter, 'codex.app-server')
                self.assertEqual(rows[idx].phase, 'executing')
        other = self._mkdir('late-cwd')
        self.assertEqual(
            self._gate_code(other, setup=True, codex_setup=True),
            'route_busy')
        with admission.gate(other, setup=True):
            pass

    def test_spawn_no_child_releases_but_wrong_phase_holds(self):
        def spawn_fail(before_launch=None, on_stopped=None):
            before_launch()
            raise RouteFailure('route_unavailable', 'not_started', 'spawn')

        def preflight_fail(before_launch=None, on_stopped=None):
            before_launch()
            raise RouteFailure('route_unavailable', 'not_started', 'preflight')

        with admission.gate(self.cwd):
            with self.assertRaises(RouteFailure):
                admission.model_call('codex', 'm', 'p',
                                     str(self._call_dir('spawn')),
                                     spawn_fail)
        self.assertEqual(self._ledger().unresolved(), ())
        with admission.gate(self.cwd):
            with self.assertRaises(RouteFailure):
                admission.model_call('codex', 'm', 'p',
                                     str(self._call_dir('pre')),
                                     preflight_fail)
        rows = self._ledger().unresolved()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].phase, 'executing')

    def test_capacity_shared_and_adapters_independent(self):
        for i in range(MAX_CONCURRENT):
            self._seed('codex.app-server', 'svc-%d' % i, 'cap%d' % i)
        invoked = []

        def codex_invoke(**kwargs):
            invoked.append(kwargs)

        with admission.gate(self.cwd):
            self.assertEqual(
                self._code(lambda: admission.model_call(
                    'codex', 'm', 'p', str(self._call_dir('full')),
                    codex_invoke)),
                'capacity_full')
            result = admission.model_call('claude', 'm', 'p',
                                          str(self._call_dir('claude')),
                                          self._ok_invoke)
            self.assertEqual(result, 'ok')
        self.assertEqual(invoked, [])
        self.assertEqual(self._ledger().count('codex.app-server'),
                         MAX_CONCURRENT)
        self.assertEqual(self._ledger().count('claude.print'), 0)

    def test_legacy_routes_and_default_setup_checks(self):
        for route in ('claude', 'devin'):
            with self.subTest(route=route):
                with admission.gate(self.cwd):
                    result = admission.model_call(
                        route, 'm', 'p', str(self._call_dir(route)),
                        self._ok_invoke)
                    self.assertEqual(result, 'ok')
                self.assertEqual(self._ledger().unresolved(), ())
        self._seed('claude.print', f'setup-cwd:{_scope(self.cwd)}', 'legacy')
        self.assertEqual(self._gate_code(self.cwd), 'route_busy')
        self.assertEqual(self._gate_code(self.cwd, setup=True), 'route_busy')


if __name__ == '__main__':
    unittest.main()
