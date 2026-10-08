"""Model routing fixtures; no Native, account, fee, or provider qualification."""
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4 import antigravity_host as host
from co_v4.antigravity_profiles import AntigravityRouteProfile, CANDIDATE_ROUTES, LEGACY_ROUTE
from co_v4.contracts import OperationStatus
from co_v4.delegation import DelegatedScope
from probes import antigravity_text_worker as probe
from probes import antigravity_controller_acceptance as controller_probe


class ProfileTests(unittest.TestCase):
    def test_exact_six_advertised_combinations_and_no_cross_effort(self):
        self.assertEqual(len(CANDIDATE_ROUTES), 6)
        for family in ('opus', 'sonnet'):
            for effort in ('low', 'medium', 'high'):
                route = AntigravityRouteProfile(f'claude-{family}-5-5-{effort}', effort, '1.2.16')
                argv = host.invocation('/fixture/agy', 'PUBLIC', route)
                self.assertEqual(argv[argv.index('--model') + 1], route.model)
                self.assertEqual(argv[argv.index('--effort') + 1], effort)
                self.assertEqual(argv[-1], 'PUBLIC')
        for model, effort, version in (
            ('claude-opus-5-5-high', 'low', '1.2.16'),
            ('claude-opus-5-5-high', 'xhigh', '1.2.16'),
            ('claude-opus-5-5-high', 'max', '1.2.16'),
            ('claude-opus-5-5', 'high', '1.2.16'),
            ('claude-opus-5-5-high', 'high', '1.2.15'),
            ('claude-sonnet-5-5-high', 'high', '1.2.17'),
            ('gemini-3.8-flash-high', 'high', '1.2.16'),
        ):
            with self.assertRaises(ValueError):
                AntigravityRouteProfile(model, effort, version)

    def test_legacy_tuple_is_preserved_without_fresh_binary_inheritance(self):
        argv = host.invocation('/fixture/agy', 'PUBLIC')
        self.assertEqual(argv, host.invocation('/fixture/agy', 'PUBLIC', LEGACY_ROUTE))
        self.assertEqual(LEGACY_ROUTE.binary_sha256, host.BINARY_SHA)
        self.assertTrue(LEGACY_ROUTE.native_done_lf)
        self.assertTrue(LEGACY_ROUTE.plan_expansion)
        for route in CANDIDATE_ROUTES:
            self.assertNotEqual(route.binary_sha256, host.BINARY_SHA)
            self.assertTrue(route.native_done_lf)
            self.assertTrue(route.plan_expansion)

    def test_environment_identity_changes_with_exact_effort_and_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            routes = [AntigravityRouteProfile('claude-opus-5-5-' + effort, effort, '1.2.16')
                      for effort in ('low', 'high')]
            identities = []
            for route in routes:
                with patch.object(host, '_ordinary', side_effect=[route.binary_sha256, host.HOOK_SHA, host.SKILL_SHA]), patch.dict(os.environ, {k: '' for k in host.ORCA_KEYS}):
                    identity, descriptor = controller_probe.environment_definition(
                        root / 'agy', root / 'hook', root / 'skill', root, route_profile=route)
                identities.append(identity)
                self.assertEqual(descriptor['requested_effort'], route.effort)
                self.assertEqual(descriptor['native_version'], '1.2.16')
                self.assertIn('route_profiles', descriptor['implementation'])
            self.assertNotEqual(*identities)

    def test_fresh_route_requires_current_source_request_and_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            workspace = root / 'worker'
            workspace.mkdir(mode=0o700)
            for route in CANDIDATE_ROUTES:
                request = probe.make_request(workspace, 'fixture:current', route_profile=route)
                config = host.AntigravityHostConfig(request.conditions, root / 'agy',
                    DelegatedScope('fixture:human', request.ref, str(workspace), host.CAPABILITY),
                    root / 'hook', root / 'skill', route)
                def source(path, **kwargs):
                    return {config.executable: route.binary_sha256,
                            config.hook_source: host.HOOK_SHA, config.skill_source: host.SKILL_SHA}[path]
                with patch.object(host, '_ordinary', side_effect=source), patch.dict(os.environ, {k: '' for k in host.ORCA_KEYS}):
                    denied = host.AntigravityTextHost(config, request)
                    with patch.object(host.subprocess, 'Popen') as launch:
                        self.assertEqual(denied.make_adapter().execute(request).status, OperationStatus.UNSUPPORTED)
                        launch.assert_not_called()
                    checked = []
                    bound = host.AntigravityTextHost(config, request, verify_launch_policy=lambda *args: checked.append(args))
                    bound.verify(request, bound.profile)
                    self.assertEqual(checked[0][2], host.invocation(config.executable, bound.prompt(), route))
                    self.assertEqual(bound.profile.effort, route.effort)
                    self.assertEqual(bound.observation['native_version'], '1.2.16')
                    self.assertFalse(bound.observation['provider_turn_effort_verified'])
                    self.assertFalse(bound.observation['fast_qualified'])
                    with patch.object(host, '_ordinary', return_value=host.BINARY_SHA):
                        with self.assertRaisesRegex(ValueError, 'executable changed'):
                            bound.verify(request, bound.profile)
                    wrong = replace(request, conditions=replace(request.conditions, model=LEGACY_ROUTE.model))
                    wrong_host = host.AntigravityTextHost(replace(config, conditions=wrong.conditions), wrong,
                        verify_launch_policy=lambda *args: None)
                    with self.assertRaisesRegex(ValueError, 'unsupported exact route'):
                        wrong_host.verify(wrong, wrong_host.profile)
