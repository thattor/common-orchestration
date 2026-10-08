"""Synthetic Native/authority fixtures; product Controller/Adapter/AC exercised.

No Native CLI, authentication or network calls. Fixture evidence is not live.
"""
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4.adapters.claude import ClaudeAdapter
from co_v4.catalog import Catalog, CatalogEntry, Verification
from co_v4.judgment import TrustedEvidence
from co_v4.state import IngressReceipt, body_digest, create_run_body
from probes import claude_controller_acceptance as probe
from probes.claude_text_worker import UsageProof
from test_claude import Wire, frames


class ClaudeControllerAcceptanceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.executable = self.root / 'fixture-cli'
        self.executable.write_text('not executable; no Native invocation')
        self.environment = 'fixture:exact-environment'
        self.descriptor = {'fixture': 'explicitly synthetic qualification'}
        self.output = probe.EXPECTED
        self.normal = True
        self.launches = []
        self.configs = []
        self.usage_calls = []
        outer = self

        class FixtureHost:
            def __init__(self, config, *, verify_launch_policy):
                self.config, self.policy = config, verify_launch_policy
                outer.configs.append(config)
                self.observation = {'native_handoff_verified': False}
            def launch_arguments(self, session):
                return probe.invocation(self.config.executable, self.config.conditions.model, session,
                                        disabled_plugin_ids=self.config.disabled_plugin_ids)
            def verify(self, request):
                self.config.delegation.validate(request, 'claude.text.only')
                self.policy(request, tuple(self.launch_arguments(probe.ZERO_SESSION)), frozenset(probe.os.environ))
            def make_adapter(self):
                def factory(request, session, payload):
                    self.policy(request, tuple(self.launch_arguments(session)), frozenset(probe.os.environ))
                    outer.launches.append(request)
                    messages = frames(request, session)
                    messages[1]['message']['content'][0]['text'] = outer.output
                    messages[2]['result'] = outer.output
                    return Wire(messages)
                def completion(request, session, result_uuid):
                    if not outer.normal:
                        return None
                    self.observation.update(native_handoff_verified=True, cessation={
                        'environment_ref': request.conditions.environment_ref,
                        'attempt': [request.ref.run_id, request.ref.job_id, request.ref.attempt_id],
                        'stdout_eof_validated': True, 'owned_exit_code': 0,
                        'evidence_ref': 'fixture:normal-completion'})
                    return 'fixture:normal-completion'
                return ClaudeAdapter(verify_host=self.verify, transport_factory=factory, verify_completion=completion)
            def diagnostic_observation(self):
                return {'stdout_drained': outer.normal, 'normal_wait_exit_code': 0 if outer.normal else None}

        self.addCleanup(patch.stopall)
        patch.object(probe, 'environment_definition', return_value=(self.environment, self.descriptor)).start()
        patch.object(probe, 'ClaudeTextHost', FixtureHost).start()
        patch('probes.claude_text_worker.managed_policy_observation', return_value={
            'known_managed_sources_present': [False] * 5, 'preference_scopes_present': [False] * 4,
            'preference_values_read': False, 'normal_settings_sources_retained': True}).start()
        patch('subprocess.Popen', side_effect=AssertionError('No subprocess permitted in this fixture')).start()

    def inputs(self, *, protection=True, deny=False, origin=True, model=probe.MODEL):
        run_id, intent, source = 'fixture-run', 'Fixture authorizes the exact fixed text Job.', 'fixture:platform-origin'
        received_at = datetime.now(timezone.utc).isoformat()
        def provenance(ref):
            if not origin or ref != source:
                raise ValueError('fixture origin refused')
            return IngressReceipt('fixture-owner', source, body_digest(create_run_body(run_id, intent)),
                                  received_at)
        def evidence(snapshot, request, admission):
            refs = ('fixture:host-owned-state',)
            valid = admission is not None and admission.request_digest == body_digest(request)
            if admission is not None:
                self.assertFalse(admission.native_handoff_verified)
                self.assertEqual(admission.state_revision, snapshot.revision)
                refs += (admission.evidence_ref,)
            return TrustedEvidence(body_digest(request), 'fixture:policy', refs, body_digest(request.action),
                hard_deny=deny, intent_contained=True, intent_authorizes=True,
                conditions_verified=valid, protection_verified=valid and protection)
        def usage(request):
            self.usage_calls.append(request)
            return UsageProof('fixture:usage-not-real-authorization', True, True, '2099-01-01T00:00:00Z')
        catalog = Catalog((CatalogEntry(model, probe.ADAPTER, {}, (
            Verification(model, probe.ADAPTER, probe.USE, self.environment,
                'fixture:official', 'fixture:implementation', 'fixture:prior-native-measurement', 'fixture:prior-ac'),)),))
        return dict(run_id=run_id, model=model, human_intent=intent, human_intent_ref=source,
            origin_verifier=provenance, evidence_resolver=evidence, authorize_usage=usage,
            executable=self.executable, catalog=catalog, environment_ref=self.environment, timeout=2)

    def test_product_controller_job_independent_ac_and_run_goal_one_attempt(self):
        report = probe.run(self.root / 'run', **self.inputs())
        self.assertTrue(report['accepted'], report)
        self.assertEqual((report['attempts'], report['job_goal_count'], report['run_goal_count']), (1, 1, 1))
        self.assertEqual(report['check_verdicts'], ['pass', 'pass'])
        self.assertEqual(len(self.launches), 1)
        self.assertGreaterEqual(len(self.usage_calls), 3)
        self.assertFalse(report['catalog_promoted'])
        self.assertFalse(report['human_gateway_exercised'])
        self.assertEqual(report['effort'], 'not_recorded')
        self.assertNotIn(probe.EXPECTED, (self.root / 'run/control/observation.json').read_text())
        self.assertTrue((self.root / 'run/control/submission-claim.json').exists())
        self.assertTrue((self.root / 'run/control/session-binding.json').exists())

    def test_sonnet_exact_model_uses_same_controller_ac_without_opus_alias(self):
        report = probe.run(self.root / 'sonnet', **self.inputs(model='claude-sonnet-5'))
        self.assertTrue(report['accepted'], report)
        self.assertEqual(report['model'], 'claude-sonnet-5')
        self.assertEqual(report['check_verdicts'], ['pass', 'pass'])
        self.assertEqual(len(self.launches), 1)
        self.assertEqual(self.launches[0].conditions.model, 'claude-sonnet-5')
        self.assertTrue(all(config.conditions.model == 'claude-sonnet-5' for config in self.configs))
        for call in probe.environment_definition.call_args_list:
            self.assertEqual(call.kwargs['model'], 'claude-sonnet-5')

    def test_sonnet_cannot_reuse_opus_catalog_qualification(self):
        inputs = self.inputs()  # Only Opus was reviewed in this fixture Catalog.
        inputs['model'] = 'claude-sonnet-5'
        with self.assertRaises(ValueError):
            probe.run(self.root / 'wrong-model-catalog', **inputs)
        self.assertFalse((self.root / 'wrong-model-catalog').exists())
        self.assertEqual(self.launches, [])

    def test_unknown_model_refused_before_environment_or_factory(self):
        inputs = self.inputs()
        inputs['model'] = 'claude-unreviewed'
        with self.assertRaises(ValueError):
            probe.run(self.root / 'unknown-model', **inputs)
        probe.environment_definition.assert_not_called()
        self.assertEqual(self.launches, [])

    def test_wrong_text_result_cannot_pass_independent_goal(self):
        self.output = 'WRONG'
        report = probe.run(self.root / 'wrong', **self.inputs())
        self.assertFalse(report['accepted'])
        self.assertEqual(report['check_verdicts'], ['fail'])
        self.assertEqual(len(self.launches), 1)

    def test_unconfirmed_completion_cannot_pass_ac_or_goal(self):
        self.normal = False
        report = probe.run(self.root / 'unconfirmed', **self.inputs())
        self.assertFalse(report['accepted'])
        self.assertEqual(report['check_verdicts'], [])
        self.assertEqual(len(self.launches), 1)

    def test_missing_or_denied_host_protection_launches_nothing(self):
        for name, options in [('unknown', {'protection': False}), ('deny', {'deny': True}), ('origin', {'origin': False})]:
            with self.subTest(name=name):
                report = probe.run(self.root / name, **self.inputs(**options))
                self.assertFalse(report['accepted'])
                self.assertFalse(report['submission_claimed'])
                self.assertEqual(self.launches, [])

    def test_no_catalog_or_wrong_environment_cannot_start(self):
        for key, value in [('catalog', Catalog()), ('environment_ref', 'old:generic-label')]:
            inputs = self.inputs()
            inputs[key] = value
            with self.assertRaises(ValueError):
                probe.run(self.root / key, **inputs)
        self.assertEqual(self.launches, [])

    def test_usage_failure_refuses_before_factory(self):
        inputs = self.inputs()
        inputs['authorize_usage'] = lambda _: UsageProof('fixture:expired', True, True, '2000-01-01T00:00:00Z')
        report = probe.run(self.root / 'expired', **inputs)
        self.assertFalse(report['accepted'])
        self.assertFalse(report['submission_claimed'])
        self.assertEqual(self.launches, [])

    def test_environment_drift_after_catalog_review_refuses_submission(self):
        with patch.object(probe, 'environment_definition', side_effect=[
                (self.environment, self.descriptor), ('changed:environment', self.descriptor)]):
            report = probe.run(self.root / 'drift', **self.inputs())
        self.assertFalse(report['accepted'])
        self.assertEqual(self.launches, [])

    def test_unbound_dispatch_evidence_cannot_supply_authority(self):
        inputs = self.inputs()
        resolver = inputs['evidence_resolver']
        from dataclasses import replace
        def unbound(snapshot, request, admission):
            evidence = resolver(snapshot, request, admission)
            return replace(evidence, evidence_refs=('fixture:unbound',)) if admission else evidence
        inputs['evidence_resolver'] = unbound
        report = probe.run(self.root / 'unbound', **inputs)
        self.assertFalse(report['accepted'])
        self.assertEqual(self.launches, [])

    def test_actual_host_argv_uses_same_canonical_executable_as_descriptor(self):
        alias = self.root / 'symlink-cli'
        alias.symlink_to(self.executable)
        inputs = self.inputs()
        inputs['executable'] = alias
        report = probe.run(self.root / 'canonical', **inputs)
        self.assertTrue(report['accepted'], report)
        self.assertTrue(self.configs)
        self.assertTrue(all(config.executable == self.executable.resolve() for config in self.configs))

    def test_callbacks_required_and_same_root_never_resends(self):
        inputs = self.inputs()
        inputs['authorize_usage'] = None
        with self.assertRaises(ValueError):
            probe.run(self.root / 'absent', **inputs)
        probe.run(self.root / 'once', **self.inputs())
        with self.assertRaises(FileExistsError):
            probe.run(self.root / 'once', **self.inputs())
        self.assertEqual(len(self.launches), 1)

    def test_descriptor_binds_executable_overlay_and_role_sources(self):
        # Restore only this function; all policy observations remain fixtures.
        from importlib.util import spec_from_file_location, module_from_spec
        spec = spec_from_file_location('descriptor_fixture', probe.__file__)
        module = module_from_spec(spec)
        import sys
        sys.modules[spec.name] = module
        self.addCleanup(sys.modules.pop, spec.name)
        spec.loader.exec_module(module)
        with patch.object(module, 'managed_policy_observation', return_value={'fixture': 'metadata'}):
            first, data = module.environment_definition(self.executable)
            sonnet, sonnet_data = module.environment_definition(self.executable, model='claude-sonnet-5')
            with self.assertRaises(ValueError):
                module.environment_definition(self.executable, model='unknown')
            self.executable.write_text('changed executable')
            second, _ = module.environment_definition(self.executable)
            third, _ = module.environment_definition(self.executable, disabled_plugin_ids=('fixture@marketplace',))
        self.assertNotEqual(first, sonnet)
        self.assertEqual(sonnet_data['model'], 'claude-sonnet-5')
        self.assertNotEqual(data['argv_template_sha256'], sonnet_data['argv_template_sha256'])
        self.assertNotEqual(first, second)
        self.assertNotEqual(second, third)
        self.assertEqual(data['effort'], 'not_recorded')
        self.assertEqual(data['model'], probe.MODEL)
        self.assertNotIn(str(self.executable), str(data))


if __name__ == '__main__':
    unittest.main()
