"""Real Controller/host/state gates with owned offline ACP children, never Native."""
from dataclasses import replace
from pathlib import Path
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.codex_host import HostUnverified
from co_v4.controller import Controller, JobPlan
from co_v4.devin_host import DevinLaunchTemplate
from co_v4.devin_route import DevinTextRoute, environment_definition
from co_v4.judgment import JudgmentRequest
from co_v4.state import Limits, body_digest
from co_v4.usage import UsageStore
from test_state import Harness


class DevinRouteTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.h = Harness(self.root)
        self.addCleanup(self.h.store.close)
        self.worker = self.root / 'worker'
        self.worker.mkdir()
        self.auth = self.root / 'auth-metadata-only'
        self.auth.write_text('synthetic credential fixture; never read')
        self.executable = self.root / 'offline-cli'
        fixture = Path(__file__).with_name('fixtures') / 'devin_cessation.py'
        self.executable.write_text(f'#!{sys.executable}\n' + fixture.read_text())
        self.executable.chmod(0o700)
        for name, value in (('platform.system', 'Darwin'), ('platform.machine', 'arm64')):
            patcher = patch(name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.conditions = c.ExecutionConditions('swe-2-high', 'devin.acp', str(self.worker),
                                                'fixture:launch-gates', ('fixture:host-state',))
        self.job = c.Job('r', 'j', 'Return text only; use no tools.', ('Verified bound completion.',))
        self.template = DevinLaunchTemplate(self.conditions, self.executable,
            'devin-cessation-fixture 0', (self.h.path,), (self.auth,))
        self.route = DevinTextRoute(self.template, self.job,
            human_intent_ref='origin:r', state=self.h.ctrl)
        self.addCleanup(self.route.close)
        self.protection = True
        original = self.h.evidence
        def evidence(run, request):
            receipt = (self.route.bind(c.ExecuteRequest(c.AttemptRef(request.ref.run_id,
                request.ref.job_id, request.ref.attempt_id), self.job, request.conditions), run.revision)
                if request.ref.attempt_id else
                self.route.assess(self.job, request.conditions, run.revision))
            base = original(run, request)
            return replace(base, conditions_verified=True, protection_verified=self.protection,
                           evidence_refs=base.evidence_refs + (receipt.evidence_ref,))
        self.h.store._evidence = evidence
        use = UseCase('other', 'fixture text completion')
        self.catalog = Catalog((CatalogEntry('swe-2-high', 'devin.acp', {}, (
            Verification('swe-2-high', 'devin.acp', use, self.conditions.environment_ref,
                'fixture:official', 'fixture:implementation', 'fixture:measurement', 'fixture:ac'),)),))
        self.plan = JobPlan(self.job, self.h.action, 'bounded-text', use, (self.conditions,))
        self.checks = []
        def verify(request):
            # The model's Result cannot supply this owned-process observation.
            proof = self.route.observation(request.result.ref if request.result else
                                           request.jobs[0].result.ref).get('cessation', {})
            okay = (proof.get('stdout_eof_validated') is True
                    and proof.get('native_stop_reason') == 'end_turn'
                    and proof.get('owned_exit_code') is not None)
            finding = Finding('pass' if okay else 'fail', ('fixture:independent-process-inspection',))
            self.checks.append(request.kind)
            return CheckEvidence(body_digest(request), finding,
                                 (finding,) if request.kind == 'job' else ())
        self.controller = Controller('r', state=self.h.ctrl, judgment=self.h.judgment,
            catalog=self.catalog, usage=UsageStore(), adapters={'devin.acp': self.route},
            acceptance=Acceptance(verify), planner=lambda *_: self.plan)

    def reserve(self):
        self.assertEqual(self.controller.step().reason, 'next_job')
        self.assertEqual(self.controller.step().reason, 'execute_receipt')
        return self.h.ctrl.attempts('r')[0].ref

    def drive(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            progress = self.controller.step()
            if progress.state in c.TERMINAL or progress.state == c.State.WAITING_HUMAN:
                return progress
            time.sleep(.005)
        self.fail('offline fixture timed out')

    def test_exact_model_and_selection_sources_change_environment_identity(self):
        self.worker.chmod(0o700)
        original, descriptor = environment_definition(self.template, policy_ref='fixture:policy')
        for effort in ('medium', 'max'):
            changed = replace(self.template, conditions=replace(self.conditions, model='swe-2-' + effort))
            ref, definition = environment_definition(changed, policy_ref='fixture:policy')
            self.assertNotEqual(ref, original)
            self.assertEqual(definition['selection']['effort'], effort)
        self.assertIn('co_v4.devin_selection', dict(descriptor['implementation_sha256']))

    def test_controller_dispatches_exact_late_binding_then_independent_goal(self):
        self.controller.step()
        self.assertTrue(self.route.admissions)
        self.assertTrue(all(not r.native_handoff_verified for r in self.route.admissions))
        self.assertEqual(self.route._bound, {})
        self.assertEqual(self.controller.step().reason, 'execute_receipt')
        ref = self.h.ctrl.attempts('r')[0].ref
        self.assertFalse(self.route.observation(ref)['native_handoff_verified'])
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(self.checks, ['job', 'run'])
        self.assertTrue(self.route.observation(ref)['native_handoff_verified'])
        self.assertTrue(all(not r.native_handoff_verified for r in self.route.admissions))
        record, = self.h.ctrl.history('r', 'routing_history')
        self.assertEqual(record.ref.attempt_id, ref.attempt_id)
        self.assertEqual(self.h.ctrl.get_attempt(ref).stop_reply.status, c.StopStatus.CONFIRMED)

    def test_missing_separate_host_protection_blocks_dispatch(self):
        self.protection = False
        self.assertEqual(self.drive().state, c.State.WAITING_HUMAN)
        self.assertEqual(self.h.ctrl.attempts('r'), ())
        self.assertEqual(self.route._bound, {})

    def test_changed_job_conditions_or_attempt_cannot_use_admission(self):
        receipt = self.route.assess(self.job, self.conditions, self.h.rev())
        self.assertFalse(receipt.native_handoff_verified)
        for conditions in (replace(self.conditions, model='other'),
                           replace(self.conditions, environment_ref='other'),
                           replace(self.conditions, workspace=str(self.root))):
            with self.subTest(conditions=conditions), self.assertRaises(HostUnverified):
                self.route.assess(self.job, conditions, self.h.rev())
        with self.assertRaises(HostUnverified):
            self.route.assess(replace(self.job, context_json='{"changed":true}'), self.conditions, self.h.rev())
        request = c.ExecuteRequest(c.AttemptRef('r', 'j', 'exact'), self.job, self.conditions)
        bound = self.route.bind(request, self.h.rev())
        self.assertEqual(self.route.bind(request, self.h.rev()), bound)
        wrong = replace(request, ref=replace(request.ref, attempt_id='wrong'))
        self.assertEqual(self.route.execute(wrong).status, c.OperationStatus.UNSUPPORTED)
        self.assertFalse(self.route.observation(request.ref)['native_handoff_verified'])
        with self.assertRaises(HostUnverified):
            self.route.bind(request, self.h.rev() + 1)

    def test_bound_request_without_controller_reservation_cannot_start(self):
        request = c.ExecuteRequest(c.AttemptRef('r', 'j', 'not-reserved'), self.job, self.conditions)
        self.route.bind(request, self.h.rev())
        reply = self.route.execute(request)
        self.assertIsNone(reply.never_started)
        self.assertEqual(self.route._submitted, set())

    def test_executable_environment_or_target_changes_invalidate_readiness(self):
        self.route.assess(self.job, self.conditions, self.h.rev())
        with patch.dict(os.environ, {'LANG': 'changed-for-test'}), self.assertRaises(HostUnverified):
            self.route.assess(self.job, self.conditions, self.h.rev())
        self.auth.chmod(0o400)
        with self.assertRaises(HostUnverified):
            self.route.assess(self.job, self.conditions, self.h.rev())

    def test_binary_replacement_or_wrong_version_is_not_admitted(self):
        self.route.close()
        wrong = DevinTextRoute(replace(self.template, expected_version='wrong version'), self.job,
            human_intent_ref='origin:r', state=self.h.ctrl)
        self.addCleanup(wrong.close)
        with self.assertRaises(HostUnverified):
            wrong.assess(self.job, self.conditions, self.h.rev())
        wrong.close()
        self.route = DevinTextRoute(self.template, self.job, human_intent_ref='origin:r', state=self.h.ctrl)
        self.addCleanup(self.route.close)
        self.route.assess(self.job, self.conditions, self.h.rev())
        self.executable.write_text(self.executable.read_text() + '\n# replaced\n')
        with self.assertRaises(HostUnverified):
            self.route.assess(self.job, self.conditions, self.h.rev())

    def test_swapped_gate_factory_cannot_use_original_receipt(self):
        self.route.assess(self.job, self.conditions, self.h.rev())
        with patch('co_v4.devin_host.DevinTextHost.make_adapter'), self.assertRaises(HostUnverified):
            self.route.assess(self.job, self.conditions, self.h.rev())

    def test_state_change_between_reservation_and_execute_is_never_started(self):
        execute = self.route.execute
        def changed(request):
            self.h.ctrl.set_limits('r', Limits(jobs=19), self.h.rev())
            return execute(request)
        self.route.execute = changed
        self.controller.step()
        self.assertEqual(self.controller.step().reason, 'execute_never_started')
        self.assertEqual(self.route._submitted, set())
        self.assertEqual(self.h.ctrl.history('r', 'execute_history')[0].status,
                         c.OperationStatus.UNSUPPORTED)

    def test_reconstructed_route_cannot_claim_an_existing_or_ambiguous_attempt(self):
        ref = self.reserve()
        request = self.route._bound[ref][0]
        self.route.close()
        fresh = DevinTextRoute(self.template, self.job, human_intent_ref='origin:r', state=self.h.ctrl)
        self.addCleanup(fresh.close)
        with self.assertRaises(HostUnverified):
            fresh.bind(request, self.h.rev() - 1)
        reply = fresh.execute(request)
        self.assertIsNone(reply.never_started)
        self.assertNotEqual(reply.status, c.OperationStatus.ACCEPTED)

    def test_crash_after_reservation_before_receipt_cannot_rebind(self):
        begin = self.h.ctrl.begin_attempt
        def crash(*args, **kwargs):
            begin(*args, **kwargs)
            raise KeyboardInterrupt('offline crash after reservation')
        self.h.ctrl.begin_attempt = crash
        self.controller.step()
        with self.assertRaises(KeyboardInterrupt): self.controller.step()
        ref, = self.route._bound
        request = self.route._bound[ref][0]
        self.assertIsNone(self.h.ctrl.execute_receipt(ref))
        self.route.close()
        fresh = DevinTextRoute(self.template, self.job, human_intent_ref='origin:r', state=self.h.ctrl)
        self.addCleanup(fresh.close)
        with self.assertRaises(HostUnverified): fresh.bind(request, self.h.rev() - 1)
        self.assertIsNone(fresh.execute(request).never_started)

    def test_two_routes_prepared_before_reservation_cannot_both_own_launch(self):
        self.route.assess(self.job, self.conditions, self.h.rev())
        with self.assertRaises(HostUnverified):
            DevinTextRoute(self.template, self.job, human_intent_ref='origin:r', state=self.h.ctrl)
        self.assertEqual(self.h.ctrl.attempts('r'), ())
        self.route.close()
        with self.assertRaises(HostUnverified):
            self.route.assess(self.job, self.conditions, self.h.rev())

    def test_environment_definition_checks_its_fresh_private_workspace_rule(self):
        self.worker.chmod(0o755)
        with self.assertRaises(HostUnverified):
            environment_definition(self.template, policy_ref='fixture:policy')
        self.worker.chmod(0o700)
        reference, descriptor = environment_definition(self.template, policy_ref='fixture:policy')
        self.assertTrue(reference.startswith('devin-text-template:'))
        self.assertEqual(descriptor['native_mode_required'], 'plan')
        (self.worker / 'existing-file').touch()
        with self.assertRaises(HostUnverified):
            environment_definition(self.template, policy_ref='fixture:policy')

    def test_mode_gate_failure_cannot_submit_any_prompt(self):
        # Offline executable advertises a different effective mode; initial
        # host admission is still honest about only admitting a guarded launch.
        source = self.executable.read_text().replace('"currentModeId": "plan"', '"currentModeId": "bypass"')
        self.executable.write_text(source)
        self.controller.step()
        self.controller.step()
        ref = self.h.ctrl.attempts('r')[0].ref
        for _ in range(100):
            self.controller.step()
            if self.h.ctrl.get_attempt(ref).result is not None: break
            time.sleep(.005)
        self.assertIsNotNone(self.h.ctrl.get_attempt(ref).result)
        observation = self.route.observation(ref)
        self.assertFalse(observation['native_handoff_verified'])
        self.assertFalse(self.route._bound[ref][2]._transport.submitted)
        self.assertEqual(self.checks, [])


if __name__ == '__main__': unittest.main()
