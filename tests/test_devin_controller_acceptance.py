"""Offline qualification -> reviewed fixture Catalog -> product Controller/AC/Goal.

Owned synthetic subprocesses provide ACP responses. No Native/auth/network calls
and no production Catalog promotion occur here.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from co_v4.catalog import Catalog, CatalogEntry, Verification
from co_v4.judgment import TrustedEvidence
from co_v4.state import IngressReceipt, body_digest, create_run_body
from probes.devin_controller_acceptance import EXPECTED, USE, qualify, reopen, run


class ControllerAcceptanceProbeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.auth = self.root / 'synthetic-auth'
        self.auth.write_text('metadata fixture only')
        self.executable = self.root / 'offline-acp'
        fixture = Path(__file__).with_name('fixtures') / 'devin_cessation.py'
        source = fixture.read_text().replace(
            'if scenario in {"late_model", "late_model_match", "late_model_empty", "model_advertised"}:',
            'if scenario != "missing_model":')
        injected = '''        observed = ("WRONG" if scenario == "wrong" else "CO03_CONTROLLER_GOAL_OK")
        pieces = [observed[:7], observed[7:]] if scenario == "split" else [observed]
        if scenario == "overflow": pieces = ["x" * 129]
        for piece in pieces:
            emit(update("agent_message_chunk", content={"type": "text", "text": piece}))
'''
        source = source.replace('        prompt = message\n', '        prompt = message\n' + injected)
        self.executable.write_text(f'#!{sys.executable}\n' + source)
        self.executable.chmod(0o700)
        for name, value in (('platform.system', 'Darwin'), ('platform.machine', 'arm64')):
            patcher = patch(name, return_value=value)
            patcher.start(); self.addCleanup(patcher.stop)

    def inputs(self, run_id, model='normal', protection=True):
        self.executable.with_suffix('.scenario').write_text(model)
        intent = 'Synthetic host authorizes one bounded fixed-response test.'
        source = 'fixture-origin:' + run_id
        origin = IngressReceipt('fixture-human', source,
            body_digest(create_run_body(run_id, intent)), datetime.now(timezone.utc).isoformat())
        def provenance(ref):
            if ref != source: raise ValueError('wrong fixture origin')
            return origin
        def evidence(snapshot, request, admission):
            # Human/state facts are synthetic fixtures. Actual gate readiness
            # still comes from the product route's checked subprocess/targets.
            valid = (admission.phase == 'dispatch_admission' and not admission.native_handoff_verified
                     and admission.state_revision == snapshot.revision
                     and admission.conditions_digest == body_digest(request.conditions))
            return TrustedEvidence(body_digest(request), 'fixture:policy',
                ('fixture:host-state', admission.evidence_ref), body_digest(request.action),
                intent_contained=True, intent_authorizes=True,
                conditions_verified=valid, protection_verified=protection and valid)
        return dict(run_id=run_id, human_intent=intent, human_intent_ref=source,
            origin_verifier=provenance, evidence_resolver=evidence,
            executable=self.executable, native_version='devin-cessation-fixture 0', model='swe-2-high',
            credential_files=(self.auth,), control_evidence_refs=('fixture:host-state',),
            policy_ref='fixture:adopted-handoff-policy', timeout=3)

    def qualify(self, model='normal', protection=True):
        root = self.root / ('qualification-' + model)
        result = qualify(root, **self.inputs('qualify-' + model, model, protection), environment_ref=None)
        return root, result

    def catalog(self, model, environment, qualification):
        return Catalog((CatalogEntry(model, 'devin.acp', {}, (Verification(model, 'devin.acp', USE,
            environment, 'fixture:official-reference', 'fixture:implementation-reference',
            str(qualification / 'evidence.json'), str(qualification / 'control/checks/0.json')),)),))

    def test_two_phases_retain_real_observation_before_catalog_and_goal(self):
        qualified, proof = self.qualify()
        self.assertTrue(proof['accepted'], proof)
        self.assertFalse(proof['controller_exercised'])
        self.assertFalse(proof['catalog_promoted'])
        self.assertEqual(proof['model_turns_submitted'], 1)
        self.assertEqual(proof['qualification_ac'], 'pass')
        self.assertEqual(proof['run_goal_count'], 0)
        self.assertTrue((qualified / 'control/checks/0.json').is_file())
        destination = self.root / 'controller'
        result = run(destination, **self.inputs('controller'), environment_ref=proof['environment_ref'],
                     catalog=self.catalog('swe-2-high', proof['environment_ref'], qualified))
        self.assertTrue(result['accepted'], result)
        self.assertTrue(result['controller_exercised'])
        self.assertEqual(result['model_turns_submitted'], 1)
        self.assertEqual(result['controller_state'], 'completed')
        self.assertEqual(result['check_verdicts'], ['pass', 'pass'])
        observation = next((destination / 'control/observations').glob('*.json'))
        fixed = json.loads(observation.read_text())['fixed_response']
        self.assertEqual(fixed['observed_sha256'], hashlib.sha256(EXPECTED.encode()).hexdigest())
        self.assertEqual(fixed['observed_utf8_bytes'], len(EXPECTED.encode()))
        self.assertNotIn(EXPECTED, observation.read_text())
        check = json.loads((destination / 'control/checks/0.json').read_text())
        self.assertEqual(check['observations'][0][1], hashlib.sha256(observation.read_bytes()).hexdigest())
        self.assertEqual(reopen(destination, 'controller'), {'state': 'completed',
            'routing_records': 1, 'ac_records': 1, 'run_goals': 1, 'new_dispatches': 0})

    def test_invocation_only_model_does_not_qualify(self):
        _, proof = self.qualify('missing_model')
        self.assertFalse(proof['accepted'], proof)
        self.assertEqual(proof['qualification_ac'], 'fail')
        observed = proof['host_observations'][0]
        self.assertTrue(observed['native_handoff_verified'])
        self.assertFalse(observed['effective_model_verified'])
        self.assertEqual(observed['model_binding'], 'invocation_bound_only')
        self.assertIsNone(observed['effective_model'])

    def test_split_chunks_are_compared_after_validated_eof(self):
        _, proof = self.qualify('split')
        self.assertTrue(proof['accepted'], proof)
        fixed = proof['host_observations'][0]['fixed_response']
        self.assertEqual(fixed['chunks'], 2)
        self.assertEqual(fixed['observed_sha256'], hashlib.sha256(EXPECTED.encode()).hexdigest())

    def test_wrong_overflow_and_late_extra_text_do_not_qualify(self):
        for model in ('wrong', 'overflow', 'late_benign'):
            with self.subTest(model=model):
                _, proof = self.qualify(model)
                self.assertFalse(proof['accepted'], proof)
                self.assertEqual(proof['qualification_ac'], 'fail')
                self.assertEqual(proof['model_turns_submitted'], 1)
                self.assertTrue(proof['owned_cli_reaped'])
                fixed = proof['host_observations'][0]['fixed_response']
                self.assertNotEqual(fixed['observed_sha256'], hashlib.sha256(EXPECTED.encode()).hexdigest())

    def test_missing_host_protection_launches_nothing(self):
        _, proof = self.qualify(protection=False)
        self.assertFalse(proof['accepted'])
        self.assertEqual(proof['model_turns_submitted'], 0)
        self.assertTrue(proof['owned_cli_reaped'])

    def test_changed_definition_and_missing_catalog_never_promote(self):
        qualified, proof = self.qualify()
        with self.assertRaises(ValueError):
            run(self.root / 'wrong-environment', **self.inputs('wrong-environment'),
                environment_ref='old-environment-not-an-alias', catalog=Catalog())
        result = run(self.root / 'empty-catalog', **self.inputs('empty-catalog'),
            environment_ref=proof['environment_ref'], catalog=Catalog())
        self.assertFalse(result['accepted'])
        self.assertEqual(result['model_turns_submitted'], 0)

    def test_independent_ac_does_not_use_matched_boolean_as_its_oracle(self):
        from co_v4.devin_route import DevinTextRoute
        observation = DevinTextRoute.observation
        def false_boolean(route, ref):
            value = observation(route, ref)
            if 'fixed_response' in value:
                value['fixed_response'] = {**value['fixed_response'], 'matched': False}
            return value
        with patch.object(DevinTextRoute, 'observation', false_boolean):
            _, proof = self.qualify()
        self.assertTrue(proof['accepted'], proof)
        self.assertFalse(proof['host_observations'][0]['fixed_response']['matched'])


if __name__ == '__main__': unittest.main()
