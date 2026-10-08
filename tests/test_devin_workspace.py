"""Offline logical-scope bindings; no live authority or Native evidence."""
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4.delegation import DelegatedScope, DelegatedTransport, job_payload
from co_v4.devin_host import DevinHostConfig, DevinLaunchTemplate, DevinTextHost
from co_v4.devin_route import DevinTextRoute, environment_definition
from co_v4.devin_workspace import DevinWorkspaceBinding, WorkspaceBindingError
from co_v4.judgment import JudgmentRequest
from test_devin_host import Wire
import test_preexecution_human


class DevinWorkspaceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.worker = self.root / 'worker'; self.worker.mkdir(mode=0o700)
        self.control = self.root / 'control'; self.control.mkdir(mode=0o700)
        self.state = self.control / 'control.sqlite'; self.state.write_text('fixture')
        self.auth = self.root / 'auth'; self.auth.write_text('fixture metadata only')
        self.exe = self.root / 'cli'; self.exe.write_text('fixture executable')
        self.conditions = c.ExecutionConditions('swe-2-high', 'devin.acp', 'candidate-workspace:fixture',
            'fixture:original-approved-environment', ('fixture:original-control-reference',))
        self.request = c.ExecuteRequest(c.AttemptRef('r', 'j', 'a'),
            c.Job('r', 'j', 'Return fixed text without tools.', ('exact text',)), self.conditions)
        self.binding = self.bind()
        self.wire = Wire()
        self.host = self.make_host()
        self.adapter = self.host.make_adapter(); self.addCleanup(self.adapter.close)
        for name, value in (('platform.system', 'Darwin'), ('platform.machine', 'arm64')):
            p = patch(name, return_value=value); p.start(); self.addCleanup(p.stop)
        p = patch('co_v4.devin_host.AcpTransport', return_value=self.wire)
        self.factory = p.start(); self.addCleanup(p.stop)

    def bind(self, **changes):
        values = dict(request=self.request, physical_workspace=self.worker,
            protected_state=(self.state,), environment_evidence_ref='fixture:new-resolved-config')
        return DevinWorkspaceBinding(**(values | changes))

    def make_host(self, binding=None):
        return DevinTextHost(DevinHostConfig(self.conditions, self.exe, 'fixture-version',
            (self.state,), (self.auth,), DelegatedScope('fixture:intent', self.request.ref,
                self.conditions.workspace, 'devin.text.only'), workspace_binding=binding or self.binding))

    def test_original_request_preserved_in_launch_session_and_delegation(self):
        self.assertEqual(self.adapter.execute(self.request).status, c.OperationStatus.ACCEPTED)
        for _ in range(4): self.adapter.events(self.request.ref)
        self.assertEqual(self.factory.call_args.args[1], str(self.worker))
        session = next(m for m in self.wire.sent if m.get('method') == 'session/new')
        self.assertEqual(session['params']['cwd'], str(self.worker))
        prompt = next(m for m in self.wire.sent if m.get('method') == 'session/prompt')
        delegated = json.loads(prompt['params']['prompt'][0]['text'])['delegation']
        self.assertEqual(delegated['workspace'], self.conditions.workspace)
        self.assertEqual(delegated['resolved_workspace'], str(self.worker))
        self.assertEqual(delegated['workspace_binding_ref'], self.binding.binding_ref)
        self.assertIs(self.host._request, self.request)
        self.assertEqual(self.host._transport.request.conditions, self.conditions)

    def test_missing_binding_refuses_portable_workspace(self):
        host = DevinTextHost(replace(self.host.config, workspace_binding=None))
        adapter = host.make_adapter(); self.addCleanup(adapter.close)
        self.assertEqual(adapter.execute(self.request).status, c.OperationStatus.INVALID_STATE)
        self.factory.assert_not_called()

    def test_binding_rejects_attempt_context_conditions_and_request_replacement(self):
        wrong = (replace(self.request, ref=c.AttemptRef('r', 'j', 'other')),
            replace(self.request, job=replace(self.request.job, context_json='{"changed":true}')),
            replace(self.request, conditions=replace(self.conditions, model='other')),
            replace(self.request, conditions=replace(self.conditions, workspace=str(self.worker))))
        for request in wrong:
            with self.subTest(request=request):
                self.assertEqual(self.adapter.execute(request).status, c.OperationStatus.UNSUPPORTED)
        self.factory.assert_not_called()
        with self.assertRaises(FrozenInstanceError): self.binding.physical_workspace = self.root

    def test_mutable_nested_request_and_mutated_original_cannot_reuse_digest(self):
        with self.assertRaises(WorkspaceBindingError):
            self.bind(request=replace(self.request, job=replace(self.request.job, acceptance_criteria=['mutable'])))
        with self.assertRaises(WorkspaceBindingError):
            self.bind(request=replace(self.request, conditions=replace(self.conditions, control_evidence_refs=['mutable'])))
        # Even deliberate mutation of a frozen nested object cannot preserve the old binding.
        object.__setattr__(self.request.job, 'instructions', 'changed after binding')
        with self.assertRaises(WorkspaceBindingError): self.binding.validate(self.request)

    def test_binding_cannot_remap_absolute_request_or_omit_new_evidence(self):
        with self.assertRaises(WorkspaceBindingError):
            self.bind(request=replace(self.request, conditions=replace(self.conditions, workspace=str(self.worker))))
        with self.assertRaises(WorkspaceBindingError): self.bind(environment_evidence_ref='')

    def test_symlink_private_owner_and_protected_overlap_rejected(self):
        link = self.root / 'link'; link.symlink_to(self.worker, target_is_directory=True)
        with self.assertRaises(WorkspaceBindingError): self.bind(physical_workspace=link)
        self.worker.chmod(0o755)
        with self.assertRaises(WorkspaceBindingError): self.bind()
        self.worker.chmod(0o700)
        with patch('co_v4.devin_workspace.os.getuid', return_value=os.getuid() + 1):
            with self.assertRaises(WorkspaceBindingError): self.bind()
        inside = self.control / 'inside'; inside.mkdir(mode=0o700)
        with self.assertRaises(WorkspaceBindingError): self.bind(physical_workspace=inside)

    def test_workspace_or_protected_inode_replacement_refused_before_launch(self):
        self.worker.rename(self.root / 'old-worker'); self.worker.mkdir(mode=0o700)
        self.assertEqual(self.adapter.execute(self.request).status, c.OperationStatus.UNSUPPORTED)
        self.factory.assert_not_called()
        self.binding = self.bind(); self.host = self.make_host()
        adapter = self.host.make_adapter(); self.addCleanup(adapter.close)
        replacement = self.control / 'replacement'; replacement.write_text('fixture')
        replacement.replace(self.state)
        self.assertEqual(adapter.execute(self.request).status, c.OperationStatus.UNSUPPORTED)
        self.factory.assert_not_called()

    def test_drift_before_session_new_blocks_cwd_submission(self):
        self.assertEqual(self.adapter.execute(self.request).status, c.OperationStatus.ACCEPTED)
        self.worker.chmod(0o755)
        for _ in range(3): self.adapter.events(self.request.ref)
        self.assertFalse(any(m.get('method') in ('session/new', 'session/prompt') for m in self.wire.sent))

    def test_prompt_gate_rechecks_binding_after_session_admission(self):
        delegated = DelegatedTransport(self.wire, self.request, self.host.config.delegation,
            admitted=lambda: True, workspace_binding=self.binding)  # Synthetic gate test only.
        self.worker.chmod(0o755)
        with self.assertRaises(WorkspaceBindingError):
            delegated.send({'method': 'session/prompt', 'params': {'prompt': [
                {'type': 'text', 'text': json.dumps(job_payload(self.request))}]}})
        self.assertFalse(delegated.submitted)
        self.assertEqual(self.wire.sent, [])

    def test_protected_inventory_mismatch_and_old_descriptor_alias_refused(self):
        other = self.control / 'other.sqlite'; other.write_text('fixture')
        host = DevinTextHost(replace(self.host.config, protected_state=(other,)))
        adapter = host.make_adapter(); self.addCleanup(adapter.close)
        self.assertEqual(adapter.execute(self.request).status, c.OperationStatus.UNSUPPORTED)
        logical = DevinLaunchTemplate(self.conditions, self.exe, 'fixture-version', (self.state,),
            (self.auth,), workspace_binding=self.binding)
        physical = replace(logical, conditions=replace(self.conditions, workspace=str(self.worker)),
                           workspace_binding=None)
        bound_ref, descriptor = environment_definition(logical, policy_ref='fixture:policy')
        plain_ref, _ = environment_definition(physical, policy_ref='fixture:policy')
        self.assertNotEqual(bound_ref, plain_ref)
        self.assertEqual(descriptor['workspace_resolution'], 'devin-exact-request-binding-v1')


class HumanWorkspaceAdmissionTests(unittest.TestCase):
    def test_approval_rejudgment_reservation_driver_claim_and_bound_prompt(self):
        class Fixture(test_preexecution_human.PreExecutionTests):
            route = None
            def evidence(self, run, request):
                base = super().evidence(run, request)
                if self.route is None: return base
                admission = self.route.bind(self.request(), run.revision)
                return replace(base, conditions_verified=True, protection_verified=True,
                    evidence_refs=base.evidence_refs + (admission.evidence_ref,))
            def factory(self, request):
                self.assertEqual(request, self.request())
                self.assertFalse(self.driver.guard(self.approvers))
                self.assertEqual(json.loads((self.root / 'driver.json').read_text())['phase'], 'launch_claimed')
                return self.route
        f = Fixture(methodName='runTest'); f.setUp(); self.addCleanup(f.doCleanups)
        f.conditions = replace(f.conditions, model='swe-2-high', workspace='candidate-workspace:fixture')
        wait = f.wait(); approval = f.approve(wait)
        original_approvals = f.driver.state.history('r', 'approvals')
        original_conditions = f.conditions
        blocked = f.driver.judgment.judge(JudgmentRequest(c.QuestionRef('r', 'j', 'a'),
            f.action, 'text', f.conditions))
        self.assertEqual(blocked.reason, 'environment_or_protection_unproven')
        worker = f.root.parent / 'worker'; worker.mkdir(mode=0o700)
        auth = f.root.parent / 'auth'; auth.write_text('fixture metadata only')
        exe = f.root.parent / 'cli'; exe.write_text('fixture executable')
        protected = tuple(f.root / name for name in ('control.sqlite', 'gateway.sqlite', 'trace.sqlite'))
        binding = DevinWorkspaceBinding(f.request(), worker, protected, 'fixture:fresh-config')
        template = DevinLaunchTemplate(f.conditions, exe, 'fixture-version', protected, (auth,),
                                       workspace_binding=binding)
        wire = Wire()
        with patch('platform.system', return_value='Darwin'), patch('platform.machine', return_value='arm64'), \
                patch('co_v4.devin_route.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=b'fixture-version')), \
                patch('co_v4.devin_host.AcpTransport', return_value=wire) as factory:
            f.route = DevinTextRoute(template, f.job, human_intent_ref=f.origin_ref, state=f.driver.state)
            self.addCleanup(f.route.close)
            decision = f.driver.judgment.judge(JudgmentRequest(c.QuestionRef('r', 'j', 'a'),
                f.action, 'text', f.conditions))
            self.assertEqual(decision.reason, 'authenticated_approval')
            self.assertIn(approval.approval_id, decision.evidence_refs)
            self.assertFalse(f.route.admissions[0].native_handoff_verified)
            self.assertEqual(f.route.admissions[0].workspace_binding_ref, binding.binding_ref)
            self.assertEqual(f.route.admissions[0].workspace_environment_evidence_ref, binding.environment_evidence_ref)
            factory.assert_not_called()
            f.driver.state.begin_attempt(f.request(), decision.decision_id, decision.state_revision)
            factory.assert_not_called()
            marker_before = (f.root / 'driver.json').stat().st_ino
            reply = f.driver.execute(f.request())
            self.assertEqual(reply.status, c.OperationStatus.ACCEPTED)
            self.assertNotEqual((f.root / 'driver.json').stat().st_ino, marker_before)
            for _ in range(4): f.driver.events(f.request().ref)
            self.assertTrue(any(m.get('method') == 'session/prompt' for m in wire.sent))
            self.assertEqual(f.driver.state.get_attempt(f.request().ref).conditions, original_conditions)
            self.assertEqual(f.driver.state.history('r', 'approvals'), original_approvals)
            self.assertEqual(binding.validate(f.request()), str(worker))
