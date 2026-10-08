"""Synthetic Controller composition only; no Native calls or qualification claim."""
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4.adapter_capacity import CapacityLedger
from co_v4.state import ControlStore, StoreUnavailable
from probes import t3code_controller_acceptance as probe
from test_controller import NativeFixture


class ControllerProbeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.descriptor = {'source_revision': 'synthetic', 'implementation': {'synthetic': 'yes'}}
        self.facts = {'children': [dict(native_turn_id='fixture-turn', config_verified=True, subscription_verified=True,
            native_completed=True, failed=False, escaped_group=False, stdout_eof=True,
            stderr_eof=True, reaped=True, done=True)]}
        self.value = dict(environment_ref='fixture:environment', environment_descriptor=self.descriptor,
            status='passed', result_state='completed', text=probe.EXPECTED,
            stop_status='confirmed', native_completed=True, server_reaped=True,
            local_service_auth_state_deleted=True, cessation_evidence_ref='fixture:ceased', owner=self.facts)
        self.path = self.root / 'qualification.json'
        self.write()
        self.child = NativeFixture()
        self.child.close = lambda: None
        self.child.text_output = lambda ref: probe.EXPECTED
        self.request = c.ExecuteRequest(c.AttemptRef('run', 'job', 'placeholder'),
            c.Job('run', 'job', 'fixture', ('text', 'binding', 'cessation'), '{}'),
            c.ExecutionConditions('fixture-model', probe.ADAPTER, str(self.root / 'worker'), 'fixture:environment', ('fixture:checked-controls',)))
        self.addCleanup(patch.stopall)
        patch('subprocess.Popen', side_effect=AssertionError('Native forbidden')).start()

    def write(self):
        self.path.write_text(json.dumps(self.value))
        self.sha = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def run_probe(self, **changes):
        args = dict(root=self.root, request=self.request, make_adapter=lambda _: self.child,
            admission=lambda: True, owner=SimpleNamespace(observation=lambda: self.facts),
            qualification_path=self.path, qualification_sha256=self.sha,
            descriptor=self.descriptor, authorization_ref='fixture:explicit-operator')
        args.update(changes)
        return probe.run(**args)

    def test_real_controller_ac_and_protected_capacity_composition(self):
        report = self.run_probe()
        self.assertTrue(report['accepted'], report)
        self.assertEqual(report['check_verdicts'], ['pass', 'pass'])
        self.assertEqual((report['capacity_peak'], report['capacity_final'], report['capacity_limit']), (1, 0, 12))
        self.assertEqual((report['attempts'], report['job_goal_count'], report['run_goal_count']), (1, 1, 1))
        self.assertEqual(len(self.child.requests), 1)
        self.assertNotEqual(self.child.requests[0].ref.attempt_id, 'placeholder')
        self.assertFalse(report['human_gateway_exercised'])
        self.assertFalse(report['catalog_promoted'])
        with self.assertRaises(FileExistsError): self.run_probe()
        self.assertEqual(len(self.child.requests), 1)

    def test_unreviewed_changed_or_incomplete_qualification_before_control(self):
        for change in ({'status': 'unverified'}, {'environment_ref': 'other'},
                {'native_completed': False}, {'stop_status': 'unconfirmed'}):
            old = dict(self.value); self.value.update(change); self.write()
            with self.assertRaises(ValueError): self.run_probe()
            self.value = old
        self.write()
        with self.assertRaises(ValueError): self.run_probe(qualification_sha256='0' * 64)
        with self.assertRaises(ValueError): self.run_probe(authorization_ref='')
        self.assertEqual(self.child.requests, [])
        self.assertFalse((self.root / 'control').exists())

    def test_missing_effective_config_or_original_reap_blocks_qualification(self):
        for key in ('config_verified', 'subscription_verified', 'stdout_eof', 'reaped'):
            self.facts['children'][0][key] = False; self.write()
            with self.assertRaises(ValueError): self.run_probe()
            self.facts['children'][0][key] = True
        self.assertEqual(self.child.requests, [])

    def test_wrong_output_records_failed_job_without_run_acceptance(self):
        self.child.text_output = lambda _: 'wrong'
        report = self.run_probe()
        self.assertFalse(report['accepted'])
        self.assertEqual(report['check_verdicts'], ['fail'])
        self.assertEqual(report['job_goal_count'], 1)
        self.assertEqual(report['controller_state'], 'failed')
        self.assertEqual(report['run_goal_count'], 0)

    def test_changed_readiness_prevents_dispatch(self):
        # Per the current ruling a trusted readiness resolver refusal is
        # GLOBAL, not per-Run recoverable: evaluate() wraps it as
        # StoreUnavailable, which escapes step() unchanged before any
        # controller_error handling — no Attempt, no execute, no lease.
        with self.assertRaises(StoreUnavailable) as ctx:
            self.run_probe(admission=lambda: False)
        self.assertEqual(ctx.exception.args[0],
                         'trusted judgment evidence unavailable')
        self.assertEqual(self.child.requests, [])
        # The probe's finally still persisted the report: peak stays 0
        # because the refusal precedes pool.reserve/factory admission.
        control = self.root / 'control'
        report = json.loads(
            (control / 'controller-result.json').read_text())
        self.assertFalse(report['accepted'])
        self.assertEqual(report['capacity_peak'], 0)
        # Real ledger and real store reopened: zero lease and zero
        # Attempt admissions; the Run is untouched at PENDING, no ERROR.
        self.assertEqual(
            CapacityLedger(control / 'capacity.sqlite').count(
                probe.ADAPTER), 0)
        store = ControlStore(control / 'control.db',
                             verifier=lambda ref: None,
                             evidence=lambda *_: None)
        try:
            state = store.controller()
            self.assertEqual(len(state.attempts('run')), 0)
            self.assertIs(state.get_run('run').state, c.State.PENDING)
        finally:
            store.close()
