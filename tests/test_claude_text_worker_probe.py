"""Offline fixtures only: no actual policy probe, Native/auth, credits or prompt."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4.claude_host import ClaudeHostConfig
from co_v4.delegation import DelegatedScope
from probes import claude_text_worker as probe
from test_claude import request, frames, Wire


ABSENT = {'known_managed_sources_present': [False] * 5,
          'preference_scopes_present': [False] * 4, 'preference_values_read': False,
          'normal_settings_sources_retained': True}


def synthetic_usage(req):
    return probe.UsageProof('OFFLINE-SYNTHETIC-NOT-OWNER-ANSWER', True, True,
        (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat())


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.executable = self.root / 'fixture-claude'; self.executable.write_text('fixture')
        patch.dict(os.environ, {'HOME': str(self.root), 'PATH': '/usr/bin:/bin'}, clear=True).start()
        self.addCleanup(patch.stopall)
        self.metadata = patch.object(probe, 'managed_policy_observation', return_value=ABSENT).start()
        def metadata_cli(exe, args, env, cwd):
            if args == ['--version']: return 0, b'2.1.285 (Claude Code)'
            if args == ['auth', 'status']:
                return 0, json.dumps(dict(loggedIn=True, authMethod='claude.ai',
                    apiProvider='firstParty', subscriptionType='pro')).encode()
            self.fail('unexpected metadata CLI')
        self.native = patch.object(probe.claude_host, '_probe', side_effect=metadata_cli).start()

    def run_probe(self, name='out', **kwargs):
        return probe.run(self.root / name, executable=self.executable,
                         model='claude-sonnet-4-6', **kwargs)

    def test_default_preflight_never_creates_model_transport_or_claim(self):
        with patch.object(probe.claude_host, 'PrintTransport') as factory:
            result = self.run_probe()
        factory.assert_not_called()
        self.assertEqual(result['model_submission_attempts'], 0)
        self.assertEqual(result['result'], 'preflight_passed_no_prompt')
        self.assertEqual(result['independent_ac'], 'not_run')
        self.assertEqual(result['policy_checks'], 2)
        self.assertFalse((self.root / 'out/submission-claim.json').exists())
        with self.assertRaises(FileExistsError): self.run_probe()

    def test_distinct_probe_runs_have_distinct_identity_without_native_submission(self):
        with patch.object(probe.claude_host, 'PrintTransport') as factory:
            first = self.run_probe('first')
            second = self.run_probe('second')
        factory.assert_not_called()
        self.assertNotEqual(first['attempt_ref']['run_id'], second['attempt_ref']['run_id'])
        self.assertEqual(first['attempt_ref']['job_id'], 'fixed-response')
        self.assertEqual(first['attempt_ref']['attempt_id'], 'one')
        self.assertEqual((first['model_submission_attempts'], second['model_submission_attempts']), (0, 0))

    def test_live_requires_real_host_verifier_no_cli_boolean_bypass(self):
        with self.assertRaisesRegex(ValueError, 'trusted usage verifier'):
            self.run_probe(live=True)
        self.assertFalse((self.root / 'out').exists())
        self.native.assert_not_called()

    def test_invalid_or_expired_usage_refuses_before_native_metadata(self):
        for number, proof in enumerate((None, replace(synthetic_usage(None), extra_credit_off=False),
                replace(synthetic_usage(None), quota_available=False),
                replace(synthetic_usage(None), valid_until='2000-01-01T00:00:00Z'))):
            result = self.run_probe(str(number), live=True, authorize_usage=lambda req: proof)
            self.assertEqual(result['result'], 'probe_failed_closed')
            self.assertEqual(result['model_submission_attempts'], 0)
        self.native.assert_not_called()

    def test_synthetic_full_mapping_preserves_independent_ac_and_no_process_proof(self):
        def factory(exe, workspace, model, session, prompt, env):
            payload = json.loads(prompt)
            self.assertIn(probe.EXPECTED, payload['instructions'])
            req = request(); req = replace(req, conditions=replace(req.conditions, workspace=workspace))
            messages = frames(req, session)
            messages[-1]['result'] = probe.EXPECTED
            return Wire(messages)
        with patch.object(probe.claude_host, 'PrintTransport', side_effect=factory) as native:
            result = self.run_probe(live=True, authorize_usage=synthetic_usage)
        self.assertEqual(native.call_count, 1)
        self.assertEqual(result['result'], 'completed')
        self.assertEqual(result['independent_ac'], 'pass')
        self.assertEqual(result['cessation'], 'unconfirmed')
        self.assertEqual(result['actual_output_sha256'], result['expected_output_sha256'])
        self.assertFalse(result['host_observation']['native_handoff_verified'])
        self.assertEqual(result['run_goal'], 'not_evaluated')
        self.assertFalse(result['catalog_promoted'])
        self.assertNotIn('OFFLINE-SYNTHETIC', json.dumps(result))
        claim_path = self.root / 'out/submission-claim.json'
        claim_before = claim_path.read_bytes()
        claim = json.loads(claim_before)
        binding = json.loads((self.root / 'out/session-binding.json').read_text())
        self.assertEqual(claim['attempt_ref'], result['attempt_ref'])
        self.assertEqual(binding['attempt_ref'], claim['attempt_ref'])
        self.assertEqual(len(binding['native_session_sha256']), 64)
        with self.assertRaises(FileExistsError): self.run_probe(live=True, authorize_usage=synthetic_usage)
        self.assertEqual(claim_path.read_bytes(), claim_before)

    def test_launch_policy_rejects_drift_and_only_normalizes_generated_uuid(self):
        worker = self.root / 'worker'; worker.mkdir()
        req = request(); req = replace(req, conditions=replace(req.conditions, workspace=str(worker)))
        config = ClaudeHostConfig(req.conditions, self.executable,
            DelegatedScope('fixture', req.ref, str(worker), 'claude.text.only'))
        policy = probe.LaunchPolicy(req, config)
        args = tuple(probe.claude_host.invocation(self.executable, req.conditions.model, probe.ZERO_SESSION))
        policy(req, args, frozenset(os.environ))
        with self.assertRaises(ValueError): policy(req, args + ('--bare',), frozenset(os.environ))
        with self.assertRaises(ValueError): policy(req, args, frozenset({'OTHER'}))
        with patch.object(probe, 'source_identity', return_value={'wrong': 'hash'}):
            with self.assertRaises(ValueError): policy(req, args, frozenset(os.environ))
        self.metadata.side_effect = PermissionError('PRIVATE-PATH')
        with self.assertRaises(PermissionError): policy(req, args, frozenset(os.environ))

    def test_plugin_profile_bound_by_policy_and_redacted_from_report(self):
        ids = ('PRIVATE-CANARY@fixture-market',)
        with patch.object(probe.claude_host, 'PrintTransport') as factory:
            result = self.run_probe(disabled_plugin_ids=ids)
        factory.assert_not_called()
        self.assertEqual(result['host_observation']['plugin_suppression_count'], 1)
        self.assertNotIn('PRIVATE-CANARY', json.dumps(result))
        req = request(); req = replace(req, conditions=replace(req.conditions, workspace=str(self.root)))
        config = ClaudeHostConfig(req.conditions, self.executable,
            DelegatedScope('fixture', req.ref, str(self.root), 'claude.text.only'), disabled_plugin_ids=ids)
        policy = probe.LaunchPolicy(req, config)
        args = tuple(probe.claude_host.invocation(self.executable, req.conditions.model,
            probe.ZERO_SESSION, disabled_plugin_ids=ids))
        policy(req, args, frozenset(os.environ))
        with self.assertRaises(ValueError): policy(req, args[:-2], frozenset(os.environ))
        changed = list(args); changed[-1] = '{"enabledPlugins":{"other@fixture-market":false}}'
        with self.assertRaises(ValueError): policy(req, tuple(changed), frozenset(os.environ))
        policy.config = replace(config, disabled_plugin_ids=())
        with self.assertRaises(ValueError): policy(req, args, frozenset(os.environ))

    def test_metadata_refusal_never_becomes_absence_or_leaks_error(self):
        self.metadata.side_effect = PermissionError('PRIVATE-CANARY')
        with patch.object(probe.claude_host, 'PrintTransport') as factory:
            result = self.run_probe()
        self.assertEqual(result['result'], 'probe_failed_closed')
        self.assertNotIn('PRIVATE-CANARY', json.dumps(result))
        self.native.assert_not_called(); factory.assert_not_called()


class PolicyMetadataTests(unittest.TestCase):
    def test_scoped_absence_presence_and_read_errors(self):
        with patch.object(probe.platform, 'system', return_value='Darwin'), \
             patch.object(probe.Path, 'lstat', side_effect=FileNotFoundError) as lookup, \
             patch.object(probe, 'cf_policy_present', return_value=(False,) * 4) as preferences:
            observed = probe.managed_policy_observation()
            self.assertEqual(observed, ABSENT)
            self.assertEqual(lookup.call_count, 5)
            preferences.return_value = (False, True, False, False)
            with self.assertRaises(ValueError): probe.managed_policy_observation()
            preferences.return_value = (False,) * 4
            lookup.side_effect = None
            with self.assertRaises(ValueError): probe.managed_policy_observation()
            lookup.side_effect = PermissionError('fixture inaccessible')
            with self.assertRaises(PermissionError): probe.managed_policy_observation()


if __name__ == '__main__': unittest.main()
