"""Synthetic T3 wire/profile mapping; these are not live Native qualification."""
from copy import deepcopy
from dataclasses import replace
import json
import unittest

from co_v4.adapters.t3code import (ADAPTER, MAX_FRAME, PROJECTION_ARRAYS,
                                  T3CodeAdapter, T3Profile)
from co_v4.contracts import (AttemptRef, ConfirmationResponse, Action, Scope, Resolution,
    ExecuteRequest, ExecutionConditions, Job, OperationStatus, ResumeState,
    ResultEvent, State, StopStatus)


class Transport:
    def __init__(self):
        self.sent, self.frames = [], []
        self.closed = False
        self.liveness = True
        self.fail_send = False

    def send(self, message):
        self.sent.append(deepcopy(message))
        if self.fail_send:
            raise ValueError('PRIVATE SENTINEL')

    def poll(self):
        batch, self.frames = tuple(self.frames), []
        return batch

    def alive(self):
        return self.liveness

    def close(self):
        self.closed = True

    def reply(self, value, request=None):
        self.frames.append({'_tag': 'Exit', 'requestId': (request or self.sent[-1])['id'],
                            'exit': {'_tag': 'Success', 'value': value}})


class T3CodeTests(unittest.TestCase):
    def setUp(self):
        self.ref = AttemptRef('run', 'job', 'attempt')
        self.request = ExecuteRequest(self.ref, Job('run', 'job', 'Return OK', ('exact OK',),
            '{"provided":"context"}'), ExecutionConditions('model-id', ADAPTER, '/workspace', 'fixture:host'))
        self.profile = T3Profile(self.request, 'project', 'instance', 'fixture:intent')
        self.transport = Transport()
        self.launch = None
        self.now = 0

    def factory(self, request, launch):
        self.assertEqual(request, self.request)
        self.launch = deepcopy(launch)
        return self.transport

    def adapter(self, **kwargs):
        args = dict(profile=self.profile, verify_host=lambda *args: None,
                    transport_factory=self.factory, poll_interval=0, clock=lambda: self.now)
        args.update(kwargs)
        return T3CodeAdapter(**args)

    def projection(self, status='running'):
        launch = self.launch
        value = {key: [] for key in PROJECTION_ARRAYS}
        value.update(updatedAt='2026-10-04T00:00:01.000Z', thread={
            'id': launch['threadId'], 'projectId': 'project', 'providerInstanceId': 'instance',
            'modelSelection': launch['modelSelection'], 'runtimeMode': 'approval-required',
            'interactionMode': 'default', 'worktreePath': None})
        value['runs'] = [{'id': 't3-run', 'threadId': launch['threadId'],
            'userMessageId': launch['initialMessage']['messageId'], 'providerInstanceId': 'instance',
            'modelSelection': launch['modelSelection'], 'status': status,
            'completedAt': '2026-10-04T00:00:01.000Z' if status in
                {'completed', 'failed', 'cancelled', 'interrupted', 'rolled_back'} else None}]
        value['messages'] = [{'id': launch['initialMessage']['messageId'],
            'threadId': launch['threadId'], 'runId': 't3-run', 'role': 'user',
            'text': launch['initialMessage']['text'], 'streaming': False, 'attachments': []}]
        if status == 'completed':
            value['messages'].append({'id': 'assistant', 'threadId': launch['threadId'],
                'runId': 't3-run', 'role': 'assistant', 'text': 'OK',
                'streaming': False, 'attachments': []})
        return value

    def launch_reply(self, value=None):
        self.transport.reply({'threadId': self.launch['threadId'], 'projection': value or self.projection(),
                              'resumed': False}, self.transport.sent[0])

    def start(self, adapter):
        self.assertEqual(adapter.execute(self.request).status, OperationStatus.ACCEPTED)
        self.launch_reply()
        self.assertEqual(adapter.status(self.ref).state, State.RUNNING)

    def test_default_preflight_no_transport_and_false_attestations(self):
        for verifier in (None, lambda *a: True, lambda *a: False):
            args = {'profile': self.profile, 'transport_factory': self.factory}
            if verifier is not None:
                args['verify_host'] = verifier
            result = T3CodeAdapter(**args).execute(self.request)
            self.assertEqual(result.status, OperationStatus.UNSUPPORTED)
            self.assertEqual(result.never_started.request, self.request)
            self.assertIsNone(self.launch)
        result = self.adapter(profile=replace(self.profile, request=replace(self.request,
            job=replace(self.request.job, instructions='changed')))).execute(self.request)
        self.assertIsNotNone(result.never_started)

    def test_fresh_launch_exact_payload_and_single_submission(self):
        adapter = self.adapter()
        self.start(adapter)
        frame = self.transport.sent[0]
        self.assertEqual(set(frame), {'_tag', 'id', 'tag', 'payload', 'headers'})
        self.assertEqual(frame['tag'], 'orchestration.launchThread')
        payload = frame['payload']
        self.assertFalse(payload['reuseExistingThread'])
        self.assertFalse(payload['generateTitle'])
        self.assertEqual(payload['workspaceStrategy'], {'type': 'root'})
        text = json.loads(payload['initialMessage']['text'])
        self.assertEqual(text['instructions'], self.request.job.instructions)
        self.assertEqual(text['context'], {'provided': 'context'})
        self.assertEqual(text['acceptance_criteria'], ['exact OK'])
        self.assertEqual(text['delegation']['attempt_id'], self.ref.attempt_id)
        self.assertEqual(adapter.execute(self.request).status, OperationStatus.INVALID_STATE)
        self.assertEqual(sum(f['tag'] == 'orchestration.launchThread' for f in self.transport.sent), 1)

    def test_result_cursor_text_and_stop_never_native_cessation(self):
        adapter = self.adapter()
        self.start(adapter)
        before = adapter.events(self.ref)
        self.transport.reply(self.projection('completed'))
        events = adapter.events(self.ref, before[-1].event_id)
        result = next(e.result for e in events if isinstance(e, ResultEvent))
        self.assertEqual(result.status, State.COMPLETED)
        self.assertIn('cessation unverified', result.detail)
        self.assertEqual(adapter.text_output(self.ref), 'OK')
        self.assertTrue(self.transport.closed)
        self.assertEqual(adapter.events(self.ref, events[-1].event_id), ())
        self.assertEqual(adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        with self.assertRaises(ValueError):
            adapter.events(self.ref, 'unknown-cursor')

    def test_factory_and_send_failure_ambiguous_never_retried(self):
        def fail(*args):
            raise RuntimeError('PRIVATE SENTINEL')
        for factory in (fail, self.factory):
            self.transport = Transport()
            self.transport.fail_send = True
            adapter = self.adapter(transport_factory=factory)
            reply = adapter.execute(self.request)
            self.assertEqual(reply.status, OperationStatus.ERROR)
            self.assertIsNone(reply.never_started)
            self.assertNotIn('PRIVATE', repr(reply))
            self.assertEqual(adapter.execute(self.request).status, OperationStatus.INVALID_STATE)
            self.assertEqual(adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)

    def test_unknown_reply_duplicate_reply_resume_and_connection_fail_closed(self):
        for change in ('id', 'tag', 'duplicate', 'resumed', 'error', 'dead', 'bool'):
            with self.subTest(change=change):
                self.transport = Transport()
                adapter = self.adapter()
                adapter.execute(self.request)
                self.launch_reply()
                if change == 'id': self.transport.frames[0]['requestId'] = 'other'
                if change == 'tag': self.transport.frames[0]['_tag'] = 'Chunk'
                if change == 'duplicate': self.transport.frames.append(deepcopy(self.transport.frames[0]))
                if change == 'resumed': self.transport.frames[0]['exit']['value']['resumed'] = True
                if change == 'error': self.transport.frames[0]['exit'] = {'_tag': 'Failure', 'cause': 'PRIVATE'}
                if change == 'dead': self.transport.liveness = False
                if change == 'bool': self.transport.liveness = 1
                self.assertEqual(adapter.status(self.ref).state, State.ERROR)
                self.assertNotIn('PRIVATE', repr(adapter.events(self.ref)))

    def test_changed_scope_or_unknown_activity_rejected(self):
        mutations = {
            'thread': lambda p: p['thread'].update(id='other'),
            'project': lambda p: p['thread'].update(projectId='other'),
            'model': lambda p: p['thread'].update(modelSelection={'instanceId': 'instance', 'model': 'other'}),
            'mode': lambda p: p['thread'].update(runtimeMode='full-access'),
            'workspace': lambda p: p['thread'].update(worktreePath='/other'),
            'run': lambda p: p['runs'][0].update(userMessageId='other'),
            'instance': lambda p: p['runs'][0].update(providerInstanceId='other'),
            'extra_run': lambda p: p['runs'].append(deepcopy(p['runs'][0])),
            'prompt': lambda p: p['messages'][0].update(text='injected'),
            'extra_message': lambda p: p['messages'].append(deepcopy(p['messages'][0])),
            'human': lambda p: p['runtimeRequests'].append({'status': 'pending'}),
            'resolved_human': lambda p: p['runtimeRequests'].append({'status': 'resolved'}),
            'subagent': lambda p: p['subagents'].append({'status': 'completed'}),
            'tool': lambda p: p['nodes'].append({'kind': 'tool_call'}),
            'item': lambda p: p['turnItems'].append({'type': 'tool_call'}),
            'foreign_interrupt': lambda p: p['turnItems'].append({'type': 'run_interrupt_request',
                'threadId': p['thread']['id'], 'runId': 't3-run', 'message': 'Interrupted'}),
            'continuation': lambda p: p['runs'][0].update(restartContinuationOfRunId='other'),
            'recovery': lambda p: p['attempts'].append({'reason': 'provider_recovery'}),
            'unknown': lambda p: p.update(newActivity=[]),
            'status': lambda p: p['runs'][0].update(status='invented'),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.transport = Transport()
                adapter = self.adapter()
                adapter.execute(self.request)
                projection = self.projection()
                mutate(projection)
                self.launch_reply(projection)
                self.assertEqual(adapter.status(self.ref).state, State.ERROR)
                self.assertEqual(adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)

    def test_stop_bound_run_once_ack_only_requested(self):
        adapter = self.adapter()
        adapter.execute(self.request)
        self.assertEqual(adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        self.assertEqual(len(self.transport.sent), 1)
        self.launch_reply()
        adapter.status(self.ref)
        projection_request = self.transport.sent[-1]
        self.assertEqual(adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        stop = self.transport.sent[-1]
        self.assertEqual(stop['tag'], 'orchestration.dispatchCommand')
        self.assertEqual(stop['payload']['runId'], 't3-run')
        self.assertEqual(stop['payload']['threadId'], self.launch['threadId'])
        self.assertTrue(stop['payload']['holdQueue'])
        count = len(self.transport.sent)
        adapter.stop(self.ref)
        self.assertEqual(len(self.transport.sent), count)
        self.transport.reply(self.projection(), projection_request)
        self.transport.reply({'sequence': 7}, stop)
        adapter.events(self.ref)
        self.assertEqual(adapter.stop(self.ref).status, StopStatus.REQUESTED)
        projection = self.projection('interrupted')
        projection['turnItems'] = [{'type': kind, 'threadId': self.launch['threadId'],
            'runId': 't3-run', 'message': 'Interrupted'} for kind in
            ('run_interrupt_request', 'run_interrupt_result')]
        self.transport.reply(projection)
        self.assertEqual(adapter.status(self.ref).state, State.FAILED)
        self.assertEqual(adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)

    def test_terminal_inconsistency_or_trailing_frames_not_success(self):
        for change in ('timestamp', 'streaming', 'active_node', 'pending_rpc', 'trailing'):
            with self.subTest(change=change):
                self.transport = Transport()
                adapter = self.adapter()
                self.start(adapter)
                projection = self.projection('completed')
                request = self.transport.sent[-1]
                if change == 'timestamp': projection['runs'][0]['completedAt'] = None
                if change == 'streaming': projection['messages'][1]['streaming'] = True
                if change == 'active_node': projection['nodes'].append({
                    'threadId': self.launch['threadId'], 'runId': 't3-run', 'kind': 'root_turn', 'status': 'running'})
                if change == 'pending_rpc': adapter.stop(self.ref)
                self.transport.reply(projection, request)
                if change == 'trailing': self.transport.frames.append(deepcopy(self.transport.frames[0]))
                self.assertEqual(adapter.status(self.ref).state, State.ERROR)
                with self.assertRaises(ValueError): adapter.text_output(self.ref)

    def test_timeout_bounds_invalid_inputs_and_fixed_errors(self):
        adapter = self.adapter(timeout=1)
        adapter.execute(self.request)
        self.now = 1
        self.assertEqual(adapter.status(self.ref).state, State.ERROR)
        self.assertTrue(self.transport.closed)
        for timeout in (float('nan'), float('inf'), True, 0, 601):
            with self.assertRaises(ValueError): self.adapter(timeout=timeout)
        for options in ('{}', '[{"id":"effort","value":"max"}]',
                        '[{"id":"reasoningEffort","value":"invented"}]',
                        '[{"id":"reasoningEffort","value":true}]',
                        '[{"id":"reasoningEffort","value":"medium"},{"id":"reasoningEffort","value":"high"}]',
                        '[{"id":"serviceTier","id":"serviceTier","value":"fast"}]'):
            with self.assertRaises(ValueError): replace(self.profile, options_json=options)
        for mode in ('full-access', 'auto', 'auto-accept-edits'):
            with self.assertRaises(ValueError): replace(self.profile, runtime_mode=mode)
        self.now = 0
        self.transport = Transport()
        adapter = self.adapter()
        adapter.execute(self.request)
        self.transport.frames = [{'large': 'x' * MAX_FRAME}]
        self.assertEqual(adapter.status(self.ref).state, State.ERROR)

    def test_root_preparation_bookkeeping_does_not_admit_commands(self):
        from co_v4.adapters.t3code import _root_preparation
        run = {'id': 'run:1', 'rootNodeId': 'root', 'workspacePreparation': {'type': 'root'}}
        row = {'id': 'turn-item:provider:codex:native-item:workspace-preparation%3Arun%3A1',
               'nodeId': 'root', 'type': 'command_execution', 'nativeItemRef': None,
               'providerTurnId': None, 'parentItemId': None, 'input': 'Preparing workspace',
               'status': 'running', 'title': 'Preparing workspace', 'completedAt': None}
        self.assertTrue(_root_preparation(row, run))
        for key, value in (('id', 'native-command'), ('input', 'rm -rf .'),
                           ('title', 'Starting setup script'), ('nodeId', 'other'),
                           ('providerTurnId', 'turn'), ('nativeItemRef', 'item')):
            self.assertFalse(_root_preparation({**row, key: value}, run))
        completed = {**row, 'status': 'completed', 'title': 'Workspace ready',
                     'output': 'Workspace preparation completed.', 'exitCode': 0,
                     'completedAt': '2026-10-05T00:00:00Z'}
        self.assertTrue(_root_preparation(completed, run))
        self.assertTrue(_root_preparation({k: v for k, v in completed.items() if k != 'output'}, run))
        self.assertFalse(_root_preparation({**completed, 'exitCode': 1}, run))
        self.assertFalse(_root_preparation(row, {**run, 'workspacePreparation': {'type': 'worktree'}}))

    def test_completed_empty_root_checkpoint_and_changed_files(self):
        for change in (None, 'files', 'scope', 'workspace', 'native'):
            self.setUp()
            adapter = self.adapter()
            self.start(adapter)
            value = self.projection('completed')
            run = value['runs'][0]
            run['rootNodeId'] = 'root'
            value['checkpointScopes'] = [{'id': 'scope', 'threadId': self.launch['threadId'],
                'runId': 't3-run', 'nodeId': 'root', 'kind': 'root_run',
                'parentScopeId': None, 'cwd': '/workspace'}]
            value['checkpoints'] = [{'id': 'checkpoint', 'scopeId': 'scope',
                'threadId': self.launch['threadId'], 'runId': 't3-run', 'nodeId': 'root',
                'status': 'missing', 'files': []}]
            row = {'id': 'turn-item:provider:codex:native-item:checkpoint%3Acheckpoint',
                'type': 'checkpoint', 'threadId': self.launch['threadId'], 'runId': 't3-run',
                'nodeId': 'root', 'nativeItemRef': None, 'providerTurnId': None,
                'parentItemId': None, 'status': 'completed', 'completedAt': '2026-10-05T00:00:00Z',
                'files': [], 'checkpointId': 'checkpoint', 'scopeId': 'scope'}
            value['turnItems'] = [row]
            if change == 'files':
                row['files'] = ['unexpected-change']
            elif change == 'scope':
                value['checkpoints'][0]['scopeId'] = 'other'
            elif change == 'workspace':
                value['checkpointScopes'][0]['cwd'] = '/other'
            elif change == 'native':
                row['nativeItemRef'] = 'tool-item'
            self.transport.reply(value)
            self.assertEqual(adapter.status(self.ref).state,
                State.COMPLETED if change is None else State.ERROR)
            self.assertEqual(adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)

    def test_terminal_cessation_requires_exact_trusted_reply(self):
        from co_v4.contracts import StopReply
        for mode in ('none', 'boolean', 'other', 'error', 'valid'):
            self.setUp()
            calls = []
            def verify(request, profile, thread, run, projection):
                calls.append(projection)
                self.assertEqual(request, self.request)
                self.assertEqual(profile, self.profile)
                self.assertEqual(thread, self.launch['threadId'])
                self.assertEqual(run, 't3-run')
                if mode == 'error':
                    raise ValueError('owner unavailable')
                if mode == 'none':
                    return None
                if mode == 'boolean':
                    return True
                return StopReply(self.ref if mode == 'valid' else AttemptRef('other', 'job', 'attempt'),
                    StopStatus.CONFIRMED, 'owned EOF/reap', 'owned:fixture')
            adapter = self.adapter(verify_cessation=verify)
            self.start(adapter)
            self.transport.reply(self.projection('completed'))
            self.assertEqual(adapter.status(self.ref).state, State.COMPLETED)
            expected = StopStatus.CONFIRMED if mode == 'valid' else StopStatus.UNCONFIRMED
            self.assertEqual(adapter.stop(self.ref).status, expected)
            if mode == 'valid':
                self.assertEqual(adapter.stop(self.ref).status, expected)
                self.assertEqual(len(calls), 1)

    def test_native_tier_ids_are_not_ui_labels(self):
        for tier in ('default', 'priority', 'fast'):
            profile = replace(self.profile, options_json=json.dumps([
                {'id': 'serviceTier', 'value': tier}]))
            self.assertEqual(profile.model_selection()['options'][0]['value'], tier)
        for label in ('Standard', 'Fast', 'Priority', 'automatic'):
            with self.assertRaises(ValueError):
                replace(self.profile, options_json=json.dumps([
                    {'id': 'serviceTier', 'value': label}]))

    def test_extensions_unknown_identity_and_exact_selection(self):
        options = [{'id': 'reasoningEffort', 'value': 'medium'}, {'id': 'serviceTier', 'value': 'default'}]
        self.profile = replace(self.profile, options_json=json.dumps(options))
        adapter = self.adapter()
        adapter.execute(self.request)
        self.assertEqual(self.launch['modelSelection']['options'], options)
        state = ResumeState(ADAPTER, self.ref, b'private')
        self.assertEqual(adapter.resume(state).status, OperationStatus.UNSUPPORTED)
        self.assertEqual(adapter.resume(replace(state, adapter='other')).status, OperationStatus.INVALID_STATE)
        response = ConfirmationResponse(self.ref, 'callback', Action('unknown', Scope(())), Resolution.DENY, 'decision')
        self.assertEqual(adapter.respond(response).status, OperationStatus.UNSUPPORTED)
        self.assertEqual(adapter.usage(), ())
        unknown = AttemptRef('other', 'job', 'attempt')
        with self.assertRaises(ValueError): adapter.status(unknown)
        self.assertEqual(adapter.stop(unknown).status, StopStatus.ERROR)
        adapter.close()
        self.assertEqual(adapter.resume(state).status, OperationStatus.INVALID_STATE)
        self.assertEqual(adapter.respond(response).status, OperationStatus.INVALID_STATE)
        self.assertEqual(adapter.execute(self.request).status, OperationStatus.INVALID_STATE)


    def checkpoint_pending(self):
        value = self.projection('completed')
        run = value['runs'][0]
        run.update(status='waiting', completedAt=None, checkpointId=None,
                   rootNodeId='root', activeAttemptId='try', providerThreadId='provider', workspacePreparation={'type': 'root'})
        value['nodes'] = [{'id': 'root', 'threadId': run['threadId'], 'runId': run['id'],
            'kind': 'root_turn', 'status': 'waiting', 'completedAt': None,
            'runtimeRequestId': None, 'checkpointScopeId': 'scope'}]
        value['attempts'] = [{'id': 'try', 'runId': run['id'], 'reason': 'initial',
            'providerInstanceId': 'instance', 'rootNodeId': 'root', 'status': 'completed',
            'completedAt': 'now', 'providerThreadId': 'provider', 'providerTurnId': None}]
        value['providerThreads'] = [{'id': 'provider', 'appThreadId': run['threadId'],
            'providerInstanceId': 'instance', 'pendingBackgroundTasks': [], 'handoffIds': [],
            'nativeThreadRef': {'driver': 'codex', 'strength': 'strong', 'nativeId': 'native-thread'}}]
        value['providerTurns'] = [{'id': 'turn', 'providerThreadId': 'provider',
            'nodeId': 'root', 'runAttemptId': 'try', 'status': 'completed', 'completedAt': 'now',
            'nativeTurnRef': {'driver': 'codex', 'strength': 'strong', 'nativeId': 'native-turn'}}]
        value['checkpointScopes'] = [{'id': 'scope', 'threadId': run['threadId'], 'runId': run['id'],
            'nodeId': 'root', 'kind': 'root_run', 'parentScopeId': None, 'cwd': '/workspace'}]
        return value

    def test_checkpoint_pending_polls_without_result_then_completes(self):
        adapter = self.adapter()
        self.start(adapter)
        self.transport.reply(self.checkpoint_pending())
        self.assertEqual(adapter.status(self.ref).state, State.RUNNING)
        self.assertFalse(self.transport.closed)
        self.assertFalse(any(isinstance(e, ResultEvent) for e in adapter.events(self.ref)))
        with self.assertRaises(ValueError): adapter.text_output(self.ref)
        self.transport.reply(self.projection('completed'))
        self.assertEqual(adapter.status(self.ref).state, State.COMPLETED)

    def test_checkpoint_pending_missing_or_conflicting_evidence_rejected(self):
        cases = [('runtimeRequests', None, {'id': 'approval'}),
            ('providerTurns', 'status', 'running'), ('providerTurns', 'runAttemptId', 'other'),
            ('providerThreads', 'pendingBackgroundTasks', [{'id': 'background'}]),
            ('checkpointScopes', 'cwd', '/other'), ('nodes', 'runtimeRequestId', 'approval'),
            ('attempts', 'providerTurnId', 'other'), ('messages', 'streaming', True),
            ('providerTurns', 'nativeTurnRef', None), ('runs', 'activeAttemptId', 'other'),
            ('checkpoints', None, {'files': [{'path': 'changed'}]})]
        for key, field, new in cases:
            with self.subTest(key=key, field=field):
                self.transport = Transport()
                adapter = self.adapter()
                self.start(adapter)
                value = self.checkpoint_pending()
                if field is None: value[key].append(new)
                else: value[key][-1][field] = new
                self.transport.reply(value)
                self.assertEqual(adapter.status(self.ref).state, State.ERROR)

    def test_checkpoint_pending_still_expires_at_original_deadline(self):
        adapter = self.adapter(timeout=1)
        self.start(adapter)
        self.transport.reply(self.checkpoint_pending())
        self.assertEqual(adapter.status(self.ref).state, State.RUNNING)
        self.now = 2
        self.assertEqual(adapter.status(self.ref).state, State.ERROR)
        self.assertEqual(adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)

    def test_diagnostic_uses_only_known_local_error_vocabulary(self):
        adapter = self.adapter()
        self.start(adapter)
        self.transport.poll = lambda: (_ for _ in ()).throw(ValueError('PRIVATE SENTINEL'))
        self.assertEqual(adapter.status(self.ref).state, State.ERROR)
        self.assertEqual(adapter.diagnostic(self.ref), 'unclassified protocol or transport failure')
        self.assertNotIn('PRIVATE', adapter.diagnostic(self.ref))


if __name__ == '__main__':
    unittest.main()
