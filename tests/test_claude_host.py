"""Offline host and actual owned subprocess fixtures; never launch Claude."""
from dataclasses import replace
import json
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from co_v4.claude_host import (ClaudeHostConfig, ClaudeTextHost, HostUnverified,
    PrintTransport, CLI_VERSION, invocation, launch_environment, _probe)
from co_v4.contracts import State, StopStatus
from co_v4.delegation import DelegatedScope, job_payload
from test_claude import request, frames, Wire


class ClaudeHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.worker = self.root / 'worker'; self.worker.mkdir()
        self.executable = self.root / 'claude'; self.executable.write_text('fixture executable')
        req = request()
        self.req = replace(req, conditions=replace(req.conditions, workspace=str(self.worker)))
        self.config = ClaudeHostConfig(self.req.conditions, self.executable,
            DelegatedScope('intent', self.req.ref, str(self.worker), 'claude.text.only'))
        self.policy_calls = []
        self.host = ClaudeTextHost(self.config, verify_launch_policy=lambda *args: self.policy_calls.append(args))
        self.adapter = self.host.make_adapter()
        self.addCleanup(self.adapter.close)
        self.auth = {'loggedIn': True, 'authMethod': 'claude.ai', 'apiProvider': 'firstParty',
                     'subscriptionType': 'pro', 'email': 'PRIVATE-CANARY'}
        def metadata(executable, args, env, cwd):
            if args == ['--version']: return 0, (CLI_VERSION + ' (Claude Code)\n').encode()
            if args == ['auth', 'status']: return 0, json.dumps(self.auth).encode()
            self.fail('unexpected metadata request')
        self.probe = patch('co_v4.claude_host._probe', side_effect=metadata).start()
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {'HOME': str(self.root), 'PATH': '/usr/bin:/bin',
            'DISABLE_TELEMETRY': '1', 'OTEL_SERVICE_NAME': 'existing-setting'}, clear=True).start()

    def test_launch_flags_existing_auth_and_exact_context(self):
        captured = {}
        def factory(executable, workspace, model, session, prompt, env):
            captured.update(prompt=json.loads(prompt), env=env, argv=invocation(executable, model, session))
            return Wire(frames(self.req, session))
        with patch('co_v4.claude_host.PrintTransport', side_effect=factory):
            self.assertEqual(self.adapter.execute(self.req).status.value, 'accepted')
            self.assertEqual(self.adapter.status(self.req.ref).state, State.COMPLETED)
        self.assertEqual(captured['prompt']['context'], {'input': 'fixture'})
        self.assertEqual(captured['prompt']['delegation']['capability'], 'claude.text.only')
        argv = captured['argv']
        for key, value in (('--tools', ''), ('--mcp-config', '{"mcpServers":{}}'),
            ('--permission-mode', 'dontAsk'), ('--max-turns', '1'), ('--disallowedTools', 'mcp__*')):
            self.assertEqual(argv[argv.index(key) + 1], value)
        for forbidden in ('--bare', '--fallback-model', '--dangerously-skip-permissions', '--resume',
                          '--restricted', '--setting-sources', '--settings'):
            self.assertNotIn(forbidden, argv)
        self.assertEqual(captured['env'], dict(os.environ))
        self.assertEqual(len(self.policy_calls), 2)
        self.assertNotIn('PRIVATE-CANARY', repr(self.host.observation))
        self.assertFalse(self.host.observation['native_handoff_verified'])
        self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.UNCONFIRMED)

    def test_actual_owned_fixture_failure_preserves_cleanup_fact_not_cessation(self):
        def command(executable, model, session):
            code = ('import json,sys; sys.stdin.read(); '
                    'print(json.dumps({"type":"system","subtype":"init",'
                    '"session_id":sys.argv[1],"model":"PRIVATE-CANARY"}))')
            return [sys.executable, '-u', '-c', code, session]
        with patch('co_v4.claude_host.invocation', side_effect=command):
            self.assertEqual(self.adapter.execute(self.req).status.value, 'accepted')
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                if self.adapter.status(self.req.ref).state == State.ERROR:
                    break
                time.sleep(.005)
            else:
                self.fail('owned fixture did not reach error')
        diagnostic = self.adapter.protocol_diagnostic(self.req.ref)
        self.assertEqual(diagnostic['phase'], 'native_init')
        observation = self.host.diagnostic_observation()
        self.assertTrue(observation['owned_process_observed'])
        self.assertTrue(observation['cleanup_reaped'])
        self.assertIsInstance(observation['owned_exit_code'], int)
        self.assertFalse(observation['cleanup_certifies_cessation'])
        self.assertFalse(self.host.observation['native_handoff_verified'])
        self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.UNCONFIRMED)
        self.assertNotIn('PRIVATE-CANARY', repr((diagnostic, observation)))

    def test_bundled_plugin_profile_requires_owned_bound_pinned_executable(self):
        session = '11111111-1111-4111-8111-111111111111'
        plugin = {'name': 'cc-plugin-telemetry', 'path': 'builtin',
                  'source': 'cc-plugin-telemetry@builtin'}
        self.host.verify(self.req)
        self.assertFalse(self.host.verify_native_plugins(self.req, session, [plugin]))
        def command(executable, model, session):
            return [sys.executable, '-c', 'import sys; sys.stdin.read()']
        with patch('co_v4.claude_host.invocation', side_effect=command):
            transport = self.host.transport(self.req, session, job_payload(self.req))
            self.addCleanup(transport.close)
            self.assertFalse(self.host.verify_native_plugins(self.req, session, [plugin]))
            self.assertEqual(self.host.observation['native_plugin_diagnostic']['reason'], 'executable_fingerprint_unqualified')
            digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
            with patch('co_v4.claude_host.BUNDLED_PLUGIN_EXECUTABLE_SHA256', digest):
                self.assertTrue(self.host.verify_native_plugins(self.req, session, [plugin]))
                self.assertTrue(self.host.observation['native_plugins_verified'])
                self.assertEqual(self.host.observation['native_plugin_count'], 1)
                self.assertFalse(self.host.verify_native_plugins(self.req, 'wrong-session', [plugin]))
                self.assertEqual(self.host.observation['native_plugin_diagnostic']['reason'], 'session_unbound')
                wrong = replace(self.req, conditions=replace(self.req.conditions, workspace='/wrong'))
                self.assertFalse(self.host.verify_native_plugins(wrong, session, [plugin]))
                self.assertEqual(self.host.observation['native_plugin_diagnostic']['reason'], 'request_or_submission_unbound')
                bad = [(None, 'list_shape_rejected'), ({}, 'list_shape_rejected'),
                    ([None], 'entry_shape_rejected'),
                    ([dict(plugin, path='builtin/PRIVATE-CANARY')], 'builtin_path_mismatch'),
                    ([dict(plugin, source='PRIVATE-CANARY')], 'registry_source_mismatch'),
                    ([dict(plugin, name='cc-plugin-unknown')], 'registry_name_unqualified'),
                    ([dict(plugin, name='cc-plugin-telemetry-copy')], 'registry_name_unqualified'),
                    ([dict(plugin, version='1')], 'version_field_unqualified'),
                    ([dict(plugin, extra='PRIVATE-CANARY')], 'keys_schema_rejected'),
                    ([dict(plugin, name=[])], 'registry_name_unqualified'),
                    ([plugin, plugin], 'duplicate_entry')]
                for value, reason in bad:
                    with self.subTest(value_type=type(value).__name__):
                        self.assertFalse(self.host.verify_native_plugins(self.req, session, value))
                        self.assertEqual(self.host.observation['native_plugin_diagnostic']['reason'], reason)
                        self.assertNotIn('PRIVATE-CANARY', repr(self.host.observation))
                projection = [{key: value for key, value in plugin.items() if key != 'source'}] * 4
                self.assertFalse(self.host.verify_native_plugins(self.req, session, projection))
                diagnostic = self.host.observation['native_plugin_diagnostic']
                self.assertEqual(diagnostic['reason'], 'keys_schema_rejected')
                self.assertEqual(diagnostic['registered_name_count'], 4)
                self.assertEqual(diagnostic['builtin_path_count'], 4)
                self.assertEqual(diagnostic['source_present_count'], 0)
                self.assertEqual(diagnostic['exact_tuple_count'], 0)
                original = self.host._transport
                self.host._transport = Wire([])
                self.assertFalse(self.host.verify_native_plugins(self.req, session, [plugin]))
                self.assertEqual(self.host.observation['native_plugin_diagnostic']['reason'], 'unowned_transport')
                self.host._transport = original
                original.argv.append('unbound-option')
                self.assertFalse(self.host.verify_native_plugins(self.req, session, [plugin]))
                self.assertEqual(self.host.observation['native_plugin_diagnostic']['reason'], 'invocation_unbound')
                original.argv.pop()
                original.prompt_sha256 = 'wrong-payload'
                self.assertFalse(self.host.verify_native_plugins(self.req, session, [plugin]))
                self.assertEqual(self.host.observation['native_plugin_diagnostic']['reason'], 'payload_unbound')

    def test_owned_fixture_builtin_projection_completes_without_native(self):
        ids = ('PRIVATE-CANARY@fixture-market',)
        self.host = ClaudeTextHost(replace(self.config, disabled_plugin_ids=ids),
                                   verify_launch_policy=lambda *args: None)
        self.adapter = self.host.make_adapter(); self.addCleanup(self.adapter.close)
        def command(executable, model, session, *, disabled_plugin_ids):
            self.assertEqual(disabled_plugin_ids, ids)
            messages = frames(self.req, session)
            messages[0]['plugins'] = [{'name': 'cc-plugin-telemetry', 'path': 'builtin',
                                       'source': 'cc-plugin-telemetry@builtin'}]
            messages.insert(1, {'type': 'system', 'subtype': 'commands_changed',
                'session_id': session, 'uuid': '11111111-1111-4111-8111-111111111111',
                'commands': [{'name': 'PRIVATE-COMMAND', 'description': 'PRIVATE-DESCRIPTION',
                              'argumentHint': '', 'aliases': ['PRIVATE-ALIAS'], 'builtin': True}]})
            code = 'import sys; sys.stdin.read(); print(' + repr('\n'.join(map(json.dumps, messages))) + ')'
            return [sys.executable, '-u', '-c', code]
        digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        with patch('co_v4.claude_host.invocation', side_effect=command), \
                patch('co_v4.claude_host.BUNDLED_PLUGIN_EXECUTABLE_SHA256', digest):
            self.assertEqual(self.adapter.execute(self.req).status.value, 'accepted')
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                state = self.adapter.status(self.req.ref).state
                if state in {State.COMPLETED, State.ERROR}: break
                time.sleep(.005)
            self.assertEqual(state, State.COMPLETED)
        self.assertTrue(self.host.observation['native_plugins_verified'])
        self.assertEqual(self.host.observation['native_plugin_count'], 1)
        self.assertNotIn('cc-plugin-telemetry', repr(self.host.observation))

        self.assertTrue(self.host.observation['native_commands_verified'])
        self.assertEqual(self.adapter.commands_observation(self.req.ref)['last_command_count'], 1)
        self.assertNotIn('PRIVATE-COMMAND', repr(self.host.observation))
        self.assertNotIn('PRIVATE-DESCRIPTION', repr(self.host.observation))

    def test_commands_inventory_requires_bound_owned_source_and_builtin_marker(self):
        session = '11111111-1111-4111-8111-111111111111'
        row = {'name': 'PRIVATE-CANARY', 'description': '', 'argumentHint': '', 'builtin': True}
        self.host.verify(self.req)
        def command(executable, model, session):
            return [sys.executable, '-c', 'import sys; sys.stdin.read()']
        with patch('co_v4.claude_host.invocation', side_effect=command):
            transport = self.host.transport(self.req, session, job_payload(self.req))
            self.addCleanup(transport.close)
            self.assertFalse(self.host.verify_native_commands(self.req, session, [row]))
            digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
            with patch('co_v4.claude_host.BUNDLED_PLUGIN_EXECUTABLE_SHA256', digest):
                self.assertTrue(self.host.verify_native_commands(self.req, session, [row]))
                self.assertFalse(self.host.verify_native_commands(self.req, 'wrong', [row]))
                wrong = replace(self.req, conditions=replace(self.req.conditions, workspace='/wrong'))
                self.assertFalse(self.host.verify_native_commands(wrong, session, [row]))
                for candidate in [dict(row, builtin=False), {k: v for k, v in row.items() if k != 'builtin'},
                                  dict(row, builtin=1), dict(row, extra='PRIVATE-CANARY')]:
                    self.assertFalse(self.host.verify_native_commands(self.req, session, [candidate]))
                original = self.host._transport; self.host._transport = Wire([])
                self.assertFalse(self.host.verify_native_commands(self.req, session, [row]))
                self.host._transport = original
                original.argv.append('unbound-option')
                self.assertFalse(self.host.verify_native_commands(self.req, session, [row]))
                original.argv.pop()
                original.prompt_sha256 = 'wrong'
                self.assertFalse(self.host.verify_native_commands(self.req, session, [row]))
        self.assertNotIn('PRIVATE-CANARY', repr(self.host.observation))

    def test_process_only_plugin_profile_exact_flags_binding_and_privacy(self):
        ids = ('PRIVATE-CANARY@fixture-market',)
        config = replace(self.config, disabled_plugin_ids=ids)
        host = ClaudeTextHost(config, verify_launch_policy=lambda *args: None)
        adapter = host.make_adapter(); self.addCleanup(adapter.close)
        captured = {}
        def factory(exe, workspace, model, session, prompt, env, *, disabled_plugin_ids):
            captured.update(argv=invocation(exe, model, session, disabled_plugin_ids=disabled_plugin_ids),
                            prompt=prompt, env=env)
            return Wire(frames(self.req, session))
        with patch('co_v4.claude_host.PrintTransport', side_effect=factory):
            self.assertEqual(adapter.execute(self.req).status.value, 'accepted')
            self.assertEqual(adapter.status(self.req.ref).state, State.COMPLETED)
        argv = captured['argv']
        self.assertEqual(argv.count('--settings'), 1)
        overlay = json.loads(argv[argv.index('--settings') + 1])
        self.assertEqual(overlay, {'enabledPlugins': {ids[0]: False}})
        self.assertEqual(captured['env'], dict(os.environ))
        self.assertNotIn('PRIVATE-CANARY', captured['prompt'])
        self.assertNotIn('PRIVATE-CANARY', repr(config))
        self.assertNotIn('PRIVATE-CANARY', repr(host.observation))
        self.assertEqual(host.observation['plugin_suppression_count'], 1)
        self.assertFalse(host.observation['native_handoff_verified'])
        host.config = replace(config, disabled_plugin_ids=('other@fixture-market',))
        with self.assertRaises(HostUnverified): host.launch_arguments('11111111-1111-4111-8111-111111111111')

    def test_plugin_profile_rejects_malformed_reserved_and_drift_before_factory(self):
        bad = [['x@market'], {'enabledPlugins': {'x@market': False}}, ('x',),
               ('x@builtin',), ('x@BUILTIN',), ('x@synced',), ('x@skills-dir',), ('x@inline',),
               ('x@market', 'x@market'), ('x@market\n',), ('--option@market',), (None,)]
        with patch('co_v4.claude_host.PrintTransport') as factory:
            for value in bad:
                with self.subTest(value_type=type(value).__name__):
                    with self.assertRaises(HostUnverified):
                        ClaudeTextHost(replace(self.config, disabled_plugin_ids=value))
            config = replace(self.config, disabled_plugin_ids=('x@market',))
            host = ClaudeTextHost(config, verify_launch_policy=lambda *args: None)
            host.verify(self.req)
            host.config = replace(config, disabled_plugin_ids=())
            with self.assertRaises(HostUnverified):
                host.transport(self.req, '11111111-1111-4111-8111-111111111111', job_payload(self.req))
        factory.assert_not_called()

    def test_default_policy_refuses_before_transport_creation(self):
        host = ClaudeTextHost(self.config)
        with patch('co_v4.claude_host.PrintTransport') as factory:
            result = host.make_adapter().execute(self.req)
        self.assertEqual(result.status.value, 'unsupported')
        self.assertIsNotNone(result.never_started)
        factory.assert_not_called()

    def test_auth_not_available_never_falls_back(self):
        authenticated = dict(self.auth)
        for fields in ({'loggedIn': False}, {'authMethod': 'api_key'}, {'apiProvider': 'bedrock'},
                       {'subscriptionType': 'max'}):
            with self.subTest(fields=fields):
                self.auth = {**authenticated, **fields}
                host = ClaudeTextHost(self.config, verify_launch_policy=lambda *a: None)
                with patch('co_v4.claude_host.PrintTransport') as factory:
                    reply = host.make_adapter().execute(self.req)
                self.assertEqual(reply.status.value, 'unavailable')
                self.assertIsNotNone(reply.never_started)
                factory.assert_not_called()

    def test_environment_override_is_rejected_not_scrubbed(self):
        for key in ('ANTHROPIC_API_KEY', 'ANTHROPIC_BASE_URL', 'CLAUDE_CONFIG_DIR',
                    'CLAUDE_CODE_UNKNOWN_OVERRIDE', 'NODE_OPTIONS'):
            with patch.dict(os.environ, {key: 'PRIVATE-CANARY'}):
                with self.assertRaises(HostUnverified): launch_environment()
                self.assertEqual(os.environ[key], 'PRIVATE-CANARY')
        with patch.dict(os.environ, {'CLAUDE_CODE_ENABLE_TELEMETRY': '0'}):
            self.assertEqual(launch_environment(), dict(os.environ))

    def test_wrong_request_or_changed_executable_never_launches(self):
        changed = replace(self.req, job=replace(self.req.job, context_json='{"changed":true}'))
        self.host.verify(self.req)
        with patch('co_v4.claude_host.PrintTransport') as factory:
            with self.assertRaises(HostUnverified): self.host.transport(changed, 'unused', {})
            self.executable.write_text('changed executable')
            with self.assertRaises(HostUnverified): self.host.transport(self.req, 'unused', {})
            factory.assert_not_called()


class OwnedProcessTests(unittest.TestCase):
    def make_transport(self, code):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        # Patch argv only: the actual owned Popen/pipes/poll/wait/cleanup execute.
        with patch('co_v4.claude_host.invocation', return_value=[sys.executable, '-u', '-c', code]):
            transport = PrintTransport(Path(sys.executable), str(root), 'fixture',
                '00000000-0000-0000-0000-000000000001', 'fixture prompt', dict(os.environ))
        self.addCleanup(transport.close)
        return transport

    def collect(self, transport):
        messages = []
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            messages.extend(transport.poll())
            if transport.drained() and transport.wait_owned() is not None:
                return messages
            time.sleep(.005)
        self.fail('owned fixture did not finish')

    def test_real_pipe_partial_write_multiple_frames_eof_and_wait(self):
        transport = self.make_transport('import sys; assert sys.stdin.read() == "fixture prompt"; print("{}\\n{}")')
        self.assertEqual(self.collect(transport), [{}, {}])
        self.assertEqual(transport._waited_exit, 0)
        self.assertTrue(transport.drained())

    def test_duplicate_malformed_truncated_and_overflow_rejected(self):
        for code in ('import sys; sys.stdin.read(); print(\'{"x":1,"x":2}\')',
                     'import sys; sys.stdin.read(); print("not-json")',
                     'import sys; sys.stdin.read(); sys.stdout.write("{}")',
                     'import sys; sys.stdin.read(); print("x" * (2 * 1024 * 1024))'):
            with self.subTest(code=code):
                transport = self.make_transport(code)
                with self.assertRaises((ValueError, HostUnverified)):
                    self.collect(transport)
                transport.close()
                self.assertIsNotNone(transport._process.poll())

    def test_cleanup_reaps_only_owned_sleeping_process(self):
        transport = self.make_transport('import time; time.sleep(20)')
        transport.close()
        self.assertIsNotNone(transport._process.poll())
        self.assertFalse(transport.drained())
        self.assertIsNone(transport._waited_exit)

    def test_metadata_probe_bounded_without_auth_or_secret_output(self):
        code, raw = _probe(Path(sys.executable), ['-c', 'print("fixture")'], dict(os.environ), None)
        self.assertEqual((code, raw), (0, b'fixture\n'))
        with self.assertRaises(HostUnverified):
            _probe(Path(sys.executable), ['-c', 'print("x" * 100000)'], dict(os.environ), None)


if __name__ == '__main__': unittest.main()
