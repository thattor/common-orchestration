"""Explicit Effort fixtures; no Claude process, auth or model requests."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4 import claude_host
from co_v4.contracts import State
from co_v4.delegation import DelegatedScope, job_payload
from probes import claude_text_worker as probe
from test_claude import request, frames, Wire
from test_claude_text_worker_probe import ABSENT


SESSION = '00000000-0000-0000-0000-000000000001'


class ClaudeEffortTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.executable = self.root / 'claude'; self.executable.write_text('fixture only')
        self.worker = self.root / 'worker'; self.worker.mkdir()
        original = request()
        self.req = replace(original, conditions=replace(original.conditions,
            workspace=str(self.worker), model='claude-opus-5-5', environment_ref='fixture:effort=medium'))
        self.config = claude_host.ClaudeHostConfig(self.req.conditions, self.executable,
            DelegatedScope('fixture:intent', self.req.ref, str(self.worker), 'claude.text.only'), effort='medium')
        patch.dict(os.environ, {'HOME': str(self.root), 'PATH': '/usr/bin:/bin'}, clear=True).start()
        self.addCleanup(patch.stopall)
        def metadata(executable, args, env, cwd):
            if args == ['--version']: return 0, b'2.1.285 (Claude Code)'
            if args == ['auth', 'status']:
                return 0, json.dumps({'loggedIn': True, 'authMethod': 'claude.ai',
                    'apiProvider': 'firstParty', 'subscriptionType': 'pro'}).encode()
            self.fail('unexpected Native metadata')
        patch.object(claude_host, '_probe', side_effect=metadata).start()
        self.digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        patch.object(claude_host, 'BUNDLED_PLUGIN_EXECUTABLE_SHA256', self.digest).start()

    def host(self, **kwargs):
        return claude_host.ClaudeTextHost(self.config, verify_launch_policy=lambda *a: None, **kwargs)

    def test_legacy_default_has_no_flag_or_application_claim(self):
        host = claude_host.ClaudeTextHost(replace(self.config, effort=None),
                                        verify_launch_policy=lambda *a: None)
        host.verify(self.req)
        self.assertNotIn('--effort', host.launch_arguments(SESSION))
        self.assertFalse(host.observation['effort_explicitly_selected'])
        self.assertEqual(host.observation['effective_effort'], 'not_recorded')
        self.assertFalse(host.observation['effort_applied_verified'])

    def test_exact_model_values_are_selection_candidates_only(self):
        for model in ('claude-opus-5-5', 'claude-sonnet-5', 'claude-sonnet-5-5'):
            for effort in claude_host.EFFORT_LEVELS:
                argv = claude_host.invocation(self.executable, model, SESSION, effort=effort)
                self.assertEqual(argv[argv.index('--effort') + 1], effort)
                self.assertEqual(argv.count('--effort'), 1)
        for model, effort in (('claude-sonnet', 'medium'), ('claude-opus', 'high'), ('claude-haiku-4-5', 'low'),
                             ('claude-opus-5-5', 'ultra'), ('claude-opus-5-5', 'ultracode'),
                             ('claude-opus-5-5', True), ('claude-opus-5-5', '--bad')):
            with self.assertRaises(claude_host.HostUnverified):
                claude_host.invocation(self.executable, model, SESSION, effort=effort)

    def test_default_or_flag_callbacks_do_not_grant_support(self):
        for callback in (None, lambda *a: True, lambda *a: False, lambda *a: 'supported'):
            host = self.host(**({'verify_effort_support': callback} if callback is not None else {}))
            with patch.object(claude_host, 'PrintTransport') as factory:
                result = host.make_adapter().execute(self.req)
            self.assertEqual(result.status.value, 'unsupported')
            self.assertIsNotNone(result.never_started)
            self.assertFalse(host.observation['effort_support_attested'])
            factory.assert_not_called()

    def test_support_rechecked_and_exact_effort_reaches_owned_invocation(self):
        calls, captured = [], {}
        def support(req, effort, digest):
            calls.append((req, effort, digest))
        host = self.host(verify_effort_support=support)
        def transport(exe, workspace, model, session, prompt, env, *, effort):
            captured.update(effort=effort, model=model,
                argv=claude_host.invocation(exe, model, session, effort=effort))
            return Wire(frames(self.req, session))
        adapter = host.make_adapter(); self.addCleanup(adapter.close)
        with patch.object(claude_host, 'PrintTransport', side_effect=transport):
            self.assertEqual(adapter.execute(self.req).status.value, 'accepted')
            self.assertEqual(adapter.status(self.req.ref).state, State.COMPLETED)
        self.assertEqual(calls, [(self.req, 'medium', self.digest)] * 2)
        self.assertEqual(captured['effort'], 'medium')
        self.assertTrue(host.observation['effort_support_attested'])
        self.assertEqual(host.observation['effective_effort'], 'not_recorded')
        self.assertFalse(host.observation['effort_applied_verified'])

    def test_changed_caps_profile_and_source_refuse_before_transport(self):
        calls = []
        def support(*args):
            calls.append(1)
            if len(calls) > 1: raise ValueError('PRIVATE-CAP-CHANGE')
        host = self.host(verify_effort_support=support)
        host.verify(self.req)
        with patch.object(claude_host, 'PrintTransport') as factory:
            with self.assertRaises(ValueError): host.transport(self.req, SESSION, job_payload(self.req))
        factory.assert_not_called()
        self.assertFalse(host.observation['effort_support_attested'])
        host.config = replace(self.config, effort='high')
        with self.assertRaises(claude_host.HostUnverified): host.launch_arguments(SESSION)
        with patch.object(claude_host, 'BUNDLED_PLUGIN_EXECUTABLE_SHA256', 'unqualified'):
            with self.assertRaises(claude_host.HostUnverified):
                self.host(verify_effort_support=lambda *a: None).verify(self.req)

    def test_probe_qualifies_environment_and_keeps_effective_unknown(self):
        with patch.object(probe, 'managed_policy_observation', return_value=ABSENT), \
                patch.object(claude_host, 'PrintTransport') as factory:
            report = probe.run(self.root / 'probe', executable=self.executable,
                model='claude-opus-5-5', effort='medium', verify_effort_support=lambda *a: None)
        factory.assert_not_called()
        self.assertEqual(report['result'], 'preflight_passed_no_prompt')
        self.assertEqual(report['environment_ref'], 'claude-text-probe:effort=medium')
        self.assertEqual(report['requested_effort'], 'medium')
        self.assertEqual(report['effective_effort'], 'not_recorded')
        self.assertFalse(report['effort_applied_verified'])
        self.assertEqual(report['effort_qualification'], 'blocked_effective_metadata_unavailable')
        self.assertEqual(report['model_submission_attempts'], 0)
        policy = probe.LaunchPolicy(self.req, self.config)
        argv = claude_host.invocation(self.executable, self.req.conditions.model, SESSION, effort='high')
        with self.assertRaises(ValueError): policy(self.req, tuple(argv), frozenset(os.environ))

    def test_source_pinned_verifier_matrix_and_refusals(self):
        verify, pin = claude_host.source_pinned_effort_support, claude_host.BUNDLED_PLUGIN_EXECUTABLE_SHA256
        def req(model): return replace(self.req, conditions=replace(self.req.conditions, model=model))
        for model in ('claude-opus-5-5', 'claude-sonnet-5', 'claude-sonnet-5-5'):
            for effort in claude_host.EFFORT_LEVELS:
                self.assertIsNone(verify(req(model), effort, pin))
        for model, effort, digest in (('claude-opus-5-5', 'ultracode', pin), ('claude-opus-5-5', None, pin),
                ('claude-opus-5-5', 'medium', 'changed'), ('claude-sonnet', 'medium', pin),
                ('claude-opus', 'medium', pin), ('claude-haiku-4-5', 'low', pin)):
            with self.assertRaises(claude_host.HostUnverified): verify(req(model), effort, digest)

    def test_host_with_verifier_requests_effort_without_effective_claim(self):
        host = self.host(verify_effort_support=claude_host.source_pinned_effort_support)
        host.verify(self.req)
        self.assertTrue(host.observation['effort_support_attested'])
        self.assertEqual(host.observation['requested_effort'], 'medium')
        self.assertEqual(host.observation['effective_effort'], 'not_recorded')
        self.assertFalse(host.observation['effort_applied_verified'])
        self.assertIn('--effort', host.launch_arguments(SESSION))

    def test_probe_default_uses_verifier_but_blocks_qualification(self):
        for model in ('claude-opus-5-5', 'claude-sonnet-5-5'):
            with patch.object(probe, 'managed_policy_observation', return_value=ABSENT), \
                    patch.object(claude_host, 'PrintTransport') as factory:
                report = probe.run(self.root / ('p-' + model), executable=self.executable,
                    model=model, effort='xhigh')
            factory.assert_not_called()
            self.assertEqual(report['result'], 'preflight_passed_no_prompt')
            self.assertEqual(report['requested_effort'], 'xhigh')
            self.assertEqual(report['effort_qualification'], 'blocked_effective_metadata_unavailable')
        with self.assertRaises(claude_host.HostUnverified):
            probe.run(self.root / 'p-alias', executable=self.executable, model='claude-sonnet', effort='high')


if __name__ == '__main__': unittest.main()
