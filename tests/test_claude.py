"""Synthetic Native frames only; no Claude/auth/model invocation."""
from copy import deepcopy
from dataclasses import replace
import unittest

from co_v4.adapters.claude import ADAPTER, CLI_VERSION, ClaudeAdapter, NativeUnavailable
from co_v4.contracts import (AttemptRef, ExecuteRequest, ExecutionConditions, Job,
    ResultEvent, ResumeState, State, StopStatus)


def request():
    return ExecuteRequest(AttemptRef('run', 'job', 'attempt'),
        Job('run', 'job', 'Return OK', ('exact response',), '{"input":"fixture"}'),
        ExecutionConditions('claude-sonnet-4-6', ADAPTER, '/fixture/worker', 'env', ('controls',)))


def frames(req, session):
    return [dict(type='system', subtype='init', session_id=session,
                 model=req.conditions.model, cwd=req.conditions.workspace,
                 claude_code_version=CLI_VERSION, tools=[], mcp_servers=[], permissionMode='dontAsk'),
            dict(type='assistant', session_id=session, parent_tool_use_id=None,
                 message={'role': 'assistant', 'model': req.conditions.model,
                          'content': [{'type': 'text', 'text': 'PRIVATE-CANARY'}]}),
            dict(type='result', subtype='success', is_error=False, session_id=session,
                 uuid='result-uuid', result='OK', num_turns=1, stop_reason='end_turn',
                 terminal_reason='completed', permission_denials=[], modelUsage={req.conditions.model: {}})]


class Wire:
    def __init__(self, messages):
        self.messages = messages
        self.eof = True
        self.code = 0
        self.closed = False
    def poll(self):
        batch, self.messages = self.messages[:128], self.messages[128:]
        return tuple(batch)
    def drained(self): return self.eof and not self.messages
    def wait_owned(self): return self.code
    def close(self): self.closed = True


class ClaudeTests(unittest.TestCase):
    def setUp(self):
        self.req = request()
        self.clock = 0
        self.calls = []
        def factory(req, session, payload):
            self.calls.append((req, session, payload))
            self.wire = Wire(frames(req, session))
            return self.wire
        self.adapter = ClaudeAdapter(verify_host=lambda req: None, transport_factory=factory,
                                     clock=lambda: self.clock)
        self.addCleanup(self.adapter.close)

    def start(self):
        self.reply = self.adapter.execute(self.req)
        return self.wire.messages

    def result(self):
        return next(e.result for e in self.adapter.events(self.req.ref) if isinstance(e, ResultEvent))

    def test_exact_delegation_and_success_result_cursor_output(self):
        self.start()
        self.assertEqual(self.reply.status.value, 'accepted')
        self.assertEqual(self.calls[0][2], {'instructions': 'Return OK',
            'context': {'input': 'fixture'}, 'acceptance_criteria': ['exact response']})
        events = self.adapter.events(self.req.ref)
        self.assertEqual(events[-1].result.status, State.COMPLETED)
        self.assertEqual(self.adapter.events(self.req.ref), events)
        self.assertEqual(self.adapter.events(self.req.ref, after=events[-1].event_id), ())
        self.assertNotIn('PRIVATE-CANARY', repr(events))
        self.assertEqual(self.adapter.text_output(self.req.ref), 'OK')
        self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.UNCONFIRMED)
        self.assertTrue(self.wire.closed)
        self.assertEqual(self.adapter.execute(self.req).status.value, 'invalid_state')
        self.assertEqual(len(self.calls), 1)
        with self.assertRaises(ValueError): self.adapter.events(self.req.ref, 'bad-cursor')

    def test_default_host_refuses_without_factory(self):
        adapter = ClaudeAdapter(transport_factory=lambda *args: self.fail('factory invoked'))
        reply = adapter.execute(self.req)
        self.assertEqual(reply.status.value, 'unsupported')
        self.assertIsNotNone(reply.never_started)

    def test_builtin_looking_plugin_is_rejected_without_trusted_host_profile(self):
        messages = self.start()
        messages[0]['plugins'] = [{'name': 'cc-plugin-telemetry', 'path': 'builtin',
                                   'source': 'cc-plugin-telemetry@builtin'}]
        self.assertEqual(self.adapter.status(self.req.ref).state, State.ERROR)
        self.assertEqual(self.adapter.protocol_diagnostic(self.req.ref)['failed_checks'],
                         ('plugins_verified',))
        self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.UNCONFIRMED)

    def test_auth_unavailable_distinct_and_no_native_creation(self):
        def denied(req): raise NativeUnavailable('SECRET')
        adapter = ClaudeAdapter(verify_host=denied, transport_factory=lambda *args: self.fail())
        reply = adapter.execute(self.req)
        self.assertEqual(reply.status.value, 'unavailable')
        self.assertIsNotNone(reply.never_started)
        self.assertNotIn('SECRET', repr(reply))

    def test_factory_failure_has_no_never_started_and_cannot_retry(self):
        def failed(*args): raise RuntimeError('SECRET')
        adapter = ClaudeAdapter(verify_host=lambda req: None, transport_factory=failed)
        reply = adapter.execute(self.req)
        self.assertEqual(reply.status.value, 'error')
        self.assertIsNone(reply.never_started)
        self.assertEqual(adapter.execute(self.req).status.value, 'invalid_state')
        self.assertNotIn('SECRET', repr(adapter.events(self.req.ref)))

    def test_result_waits_for_eof_and_owned_wait(self):
        self.start(); self.wire.eof = False
        self.assertEqual(self.adapter.status(self.req.ref).state, State.RUNNING)
        with self.assertRaises(ValueError): self.adapter.text_output(self.req.ref)
        self.wire.eof = True; self.wire.code = None
        self.assertEqual(self.adapter.status(self.req.ref).state, State.RUNNING)
        self.wire.code = 0
        self.assertEqual(self.result().status, State.COMPLETED)

    def test_late_activity_invalidates_success_candidate(self):
        self.start(); self.wire.eof = False
        self.adapter.events(self.req.ref)
        self.wire.messages = [dict(type='tool_progress', session_id=self.calls[0][1])]
        self.wire.eof = True
        self.assertEqual(self.result().status, State.ERROR)
        self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.UNCONFIRMED)

    def test_only_trusted_completion_callback_can_supply_normal_stop_proof(self):
        self.adapter._completion = lambda req, session, result: 'fixture-only-proof'
        self.start(); self.result()
        self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.CONFIRMED)

    def test_stop_never_polls_into_success_or_forges_cancel(self):
        self.start()
        self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.UNCONFIRMED)
        self.assertTrue(self.wire.closed)
        self.assertEqual(self.result().reason, 'stop_requested_cessation_unconfirmed')

    def test_timeout_sanitizes_failure_and_closes(self):
        self.start(); self.clock = 121
        self.assertEqual(self.result().reason, 'native_turn_timeout')
        self.assertTrue(self.wire.closed)

    def test_no_result_or_nonzero_exit_is_not_success(self):
        for mode in ('empty', 'assistant', 'exit'):
            with self.subTest(mode=mode):
                self.setUp(); self.start()
                if mode == 'empty': self.wire.messages = []
                elif mode == 'assistant': self.wire.messages.pop()
                else: self.wire.code = 1
                self.assertEqual(self.result().status, State.ERROR)

    def test_role_identity_configuration_and_unknown_frames_fail_closed(self):
        mutations = [lambda fs: fs[0].update(model='other'),
            lambda fs: fs[0].update(session_id='other'),
            lambda fs: fs[0].update(tools=['Bash']),
            lambda fs: fs[0].update(mcp_servers=[{'name': 'unexpected'}]),
            lambda fs: fs[0].update(permissionMode='bypassPermissions'),
            lambda fs: fs[0].update(claude_code_version='2.1.286'),
            lambda fs: fs[1]['message']['content'].append({'type': 'tool_use'}),
            lambda fs: fs[1].update(parent_tool_use_id='parent'),
            lambda fs: fs[1].update(origin='human'),
            lambda fs: fs[1].update(type='user'),
            lambda fs: fs[1]['message'].update(model='other'),
            lambda fs: fs[2].update(permission_denials=[{'tool': 'Bash'}]),
            lambda fs: fs[2].update(deferred_tool_use=[{}]),
            lambda fs: fs[2].update(stop_reason='tool_use'),
            lambda fs: fs[2].update(terminal_reason='aborted_tools'),
            lambda fs: fs[2].update(subtype='unknown'),
            lambda fs: fs[2].update(modelUsage={'other': {}}),
            lambda fs: fs[2].update(num_turns=True),
            lambda fs: fs.append(deepcopy(fs[-1])),
            lambda fs: fs.reverse()]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.setUp(); fs = self.start(); mutate(fs)
                self.assertEqual(self.result().status, State.ERROR)
                self.assertTrue(self.wire.closed)

    def test_native_error_and_limit_never_become_success(self):
        for subtype in ('success', 'error_during_execution', 'error_max_turns', 'error_max_budget_usd'):
            with self.subTest(subtype=subtype):
                self.setUp(); self.start()[-1].update(subtype=subtype, is_error=True, num_turns=0)
                self.assertEqual(self.result().reason, 'native_result_error')

    def test_private_diagnostic_classifies_failed_stages_without_native_values(self):
        cases = (
            ('init', 'native_init', 'init_configuration_rejected'),
            ('assistant', 'native_assistant', 'assistant_envelope_rejected'),
            ('result', 'native_result', 'result_success_rejected'),
            ('transport', 'transport_poll', 'transport_poll_failed'),
            ('metadata', 'native_rate_limit', 'rate_limit_metadata_rejected'),
        )
        for mode, phase, category in cases:
            with self.subTest(mode=mode):
                self.setUp(); messages = self.start()
                if mode == 'init': messages[0]['model'] = 'PRIVATE-CANARY'
                elif mode == 'assistant': messages[1]['message']['model'] = 'PRIVATE-CANARY'
                elif mode == 'result': messages[-1]['terminal_reason'] = 'PRIVATE-CANARY'
                elif mode == 'metadata':
                    messages.insert(1, {'type': 'rate_limit_event', 'session_id': self.calls[0][1],
                                       'rate_limit_info': {'status': 'allowed'}})
                else:
                    def fail(): raise OSError('PRIVATE-CANARY')
                    self.wire.poll = fail
                self.assertEqual(self.result().reason, 'native_protocol_or_transport_error')
                diagnostic = self.adapter.protocol_diagnostic(self.req.ref)
                self.assertEqual((diagnostic['phase'], diagnostic['category']), (phase, category))
                self.assertNotIn('PRIVATE-CANARY', repr(diagnostic))
                self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.UNCONFIRMED)
                if mode == 'init':
                    self.assertEqual(diagnostic['failed_checks'], ('model_matches',))
                    self.assertFalse(diagnostic['init_observed'])
                if mode in ('assistant', 'result', 'metadata'):
                    self.assertTrue(diagnostic['init_observed'])
                diagnostic['category'] = 'tampered'
                self.assertNotEqual(self.adapter.protocol_diagnostic(self.req.ref)['category'], 'tampered')

    def test_rate_limit_metadata_preserves_terminal_eof_and_empty_usage(self):
        for status in ('allowed', 'allowed_warning'):
            with self.subTest(status=status):
                self.setUp(); messages = self.start()
                event = {'type': 'rate_limit_event', 'session_id': self.calls[0][1],
                    'uuid': '11111111-1111-4111-8111-111111111111',
                    'rate_limit_info': {'status': status, 'resetsAt': 1800000000,
                        'rateLimitType': 'five_hour', 'utilization': 1.1,
                        'unifiedWindows': {'five_hour': {'utilization': 1.1, 'resetsAt': 1800000000}},
                        'overageStatus': 'rejected', 'overageDisabledReason': 'org_level_disabled',
                        'isUsingOverage': False, 'overageInUse': False}}
                messages.insert(2, event)
                self.wire.eof = False
                self.assertEqual(self.adapter.status(self.req.ref).state, State.RUNNING)
                self.assertEqual(self.adapter.rate_limit_observation(self.req.ref),
                    {'accepted_event_count': 1, 'last_status': status, 'remaining_usage': 'unknown'})
                self.wire.eof = True
                self.assertEqual(self.result().status, State.COMPLETED)
                self.assertEqual(self.adapter.usage(), ())
                self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.UNCONFIRMED)

    def test_rate_limit_rejected_unknown_overage_malformed_and_order_fail_closed(self):
        changes = [('info', {'status': 'rejected'}), ('info', {'status': 'PRIVATE-CANARY'}),
            ('info', {'unexpected': 'PRIVATE-CANARY'}), ('info', {'isUsingOverage': True}),
            ('info', {'overageInUse': True}), ('info', {'overageStatus': 'allowed'}),
            ('info', {'overageStatus': 'allowed_warning'}), ('info', {'rateLimitType': 'overage'}),
            ('info', {'errorCode': 'credits_required'}), ('info', {'resetsAt': True}),
            ('info', {'utilization': float('nan')}), ('info', {'utilization': -1}),
            ('info', {'unifiedWindows': {'PRIVATE-CANARY': {}}}),
            ('info', {'unifiedWindows': {'five_hour': {'utilization': 0}}}),
            ('event', {'uuid': 'not-uuid'}), ('event', {'session_id': 'wrong'}),
            ('event', {'origin': {'kind': 'human'}}), ('event', {'extra': 'PRIVATE-CANARY'}),
            ('before_init', {}), ('after_result', {})]
        for mode, values in changes:
            with self.subTest(mode=mode):
                self.setUp(); messages = self.start()
                event = {'type': 'rate_limit_event', 'session_id': self.calls[0][1],
                    'uuid': '11111111-1111-4111-8111-111111111111', 'rate_limit_info': {'status': 'allowed'}}
                (event['rate_limit_info'] if mode == 'info' else event).update(values)
                messages.insert(0 if mode == 'before_init' else len(messages) if mode == 'after_result' else 2, event)
                self.assertEqual(self.result().status, State.ERROR)
                self.assertEqual(self.adapter.rate_limit_observation(self.req.ref)['accepted_event_count'], 0)
                self.assertNotIn('PRIVATE-CANARY', repr(self.adapter.protocol_diagnostic(self.req.ref)))
                self.assertNotIn('PRIVATE-CANARY', repr(self.adapter.rate_limit_observation(self.req.ref)))
                self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.UNCONFIRMED)

    def test_empty_commands_inventory_does_not_execute_or_certify_completion(self):
        messages = self.start()
        messages.insert(1, {'type': 'system', 'subtype': 'commands_changed', 'commands': [],
            'session_id': self.calls[0][1], 'uuid': '11111111-1111-4111-8111-111111111111'})
        self.wire.eof = False
        self.assertEqual(self.adapter.status(self.req.ref).state, State.RUNNING)
        self.assertEqual(self.adapter.commands_observation(self.req.ref),
            {'accepted_event_count': 1, 'last_command_count': 0, 'commands_executed_by_adapter': 0})
        self.wire.eof = True
        self.assertEqual(self.result().status, State.COMPLETED)
        self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.UNCONFIRMED)

    def test_commands_inventory_nonempty_default_schema_session_and_order_rejected(self):
        row = {'name': 'PRIVATE-CANARY', 'description': 'PRIVATE-CANARY', 'argumentHint': '', 'builtin': True}
        cases = [('commands', [row]), ('commands', None), ('commands', [dict(row, extra='PRIVATE-CANARY')]),
            ('commands', [dict(row, aliases='PRIVATE-CANARY')]), ('commands', [dict(row, builtin=1)]),
            ('commands', [dict(row, description='x' * 8193)]), ('commands', [row] * 257),
            ('session_id', 'wrong'), ('uuid', 'wrong'), ('extra', 'PRIVATE-CANARY'),
            ('before_init', None), ('after_result', None)]
        for key, value in cases:
            with self.subTest(key=key):
                self.setUp(); messages = self.start()
                event = {'type': 'system', 'subtype': 'commands_changed', 'commands': [],
                    'session_id': self.calls[0][1], 'uuid': '11111111-1111-4111-8111-111111111111'}
                if key not in {'before_init', 'after_result'}: event[key] = value
                messages.insert(0 if key == 'before_init' else len(messages) if key == 'after_result' else 1, event)
                self.assertEqual(self.result().status, State.ERROR)
                self.assertEqual(self.adapter.commands_observation(self.req.ref)['accepted_event_count'], 0)
                self.assertNotIn('PRIVATE-CANARY', repr(self.adapter.protocol_diagnostic(self.req.ref)))

    def test_system_subtype_diagnostic_is_allowlisted_without_accepting_metadata(self):
        for subtype, label in [('status', 'status'), ('notification', 'notification'),
                               ('hook_response', 'hook_response'), ('PRIVATE-CANARY', 'unknown'),
                               (['PRIVATE-CANARY'], 'unknown'), (None, 'unknown')]:
            with self.subTest(expected=label):
                self.setUp(); messages = self.start()
                messages.insert(1, {'type': 'system', 'subtype': subtype,
                    'session_id': self.calls[0][1], 'text': 'PRIVATE-CANARY', 'status': 'PRIVATE-CANARY'})
                self.assertEqual(self.result().reason, 'native_protocol_or_transport_error')
                diagnostic = self.adapter.protocol_diagnostic(self.req.ref)
                self.assertEqual(diagnostic['system_subtype'], label)
                self.assertEqual(diagnostic['phase'], 'native_system')
                self.assertEqual(diagnostic['category'], 'frame_kind_or_order_rejected')
                self.assertTrue(diagnostic['init_observed'])
                self.assertEqual(diagnostic['frames_seen'], 2)
                self.assertNotIn('PRIVATE-CANARY', repr(diagnostic))
                self.assertEqual(self.adapter.stop(self.req.ref).status, StopStatus.UNCONFIRMED)

    def test_unsupported_extensions_and_empty_usage(self):
        self.start()
        self.assertEqual(self.adapter.usage(), ())
        self.assertEqual(self.adapter.respond(type('Reply', (), {'ref': self.req.ref})()).status.value, 'unsupported')
        self.assertEqual(self.adapter.resume(ResumeState(ADAPTER, self.req.ref, b'private')).status.value, 'unsupported')
        self.assertEqual(self.adapter.resume(ResumeState('other', self.req.ref, b'private')).status.value, 'invalid_state')
        unknown = replace(self.req.ref, attempt_id='unknown')
        self.assertEqual(self.adapter.respond(type('Reply', (), {'ref': unknown})()).status.value, 'invalid_state')
        self.result()
        self.assertEqual(self.adapter.respond(type('Reply', (), {'ref': self.req.ref})()).status.value, 'invalid_state')
        self.assertEqual(self.adapter.resume(ResumeState(ADAPTER, self.req.ref, b'private')).status.value, 'invalid_state')


if __name__ == '__main__': unittest.main()
