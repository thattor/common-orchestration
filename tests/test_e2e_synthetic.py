"""Cross-module synthetic acceptance and explicit Native limitations.

Passing these tests is not Native/live acceptance. Remaining Native limits retain negative assertions. Shared API fixes are checked
through product Controller behavior and independent artifact verification.
"""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4.adapters.codex import CodexAdapter
from co_v4.adapters.devin import DevinAdapter
from co_v4.catalog import Catalog
from co_v4.controller import Transition
from co_v4.judgment import JudgmentRequest
from co_v4.state import Conflict, InvalidTransition, UntrustedInput
from co_v4.waiting import utc, wait_link
from fixture_e2e import Scenario, ProtocolWire, EXPECTED


class E2ECase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # Any accidental fallback to a real external transport fails this suite.
        self.addCleanup(patch.stopall)
        patch('socket.socket', side_effect=AssertionError('E2E forbids sockets')).start()
        patch('subprocess.Popen', side_effect=AssertionError('E2E forbids Native processes')).start()

    def scenario(self, **kwargs):
        directory = Path(self.tmp.name) / str(len(list(Path(self.tmp.name).iterdir())))
        kwargs.setdefault('models', ('fixture-a',))
        h = Scenario(directory, **kwargs)
        self.addCleanup(h.close)
        return h

    def assert_trace_links(self, h):
        records = h.trace.records()
        by_id = {r['record_id']: r for r in records}
        for record in records:
            for link in record['links']:
                self.assertIn(link['record_id'], by_id, (record['record_id'], link))
                self.assertEqual(by_id[link['record_id']]['kind'], link['kind'])
        self.assertEqual(len(h.trace.jsonl().splitlines()), len(records))
        return by_id

    def preflight_wait(self, h):
        h.confirm = True
        self.assertEqual(h.drive().state, c.State.WAITING_HUMAN)
        wait = h.current_wait()
        self.assertIsNone(wait.ref.attempt_id)
        self.assertEqual(h.adapter.requests, [])
        h.publish(wait)
        return wait

    def active_wait(self, h):
        self.assertEqual(h.step().reason, 'next_job')
        self.assertEqual(h.step().reason, 'execute_receipt')
        h.confirm = True
        self.assertEqual(h.step().state, c.State.WAITING_HUMAN)
        wait = h.current_wait()
        self.assertIsNotNone(wait.ref.attempt_id)
        h.publish(wait)
        return wait


class SyntheticE2E(E2ECase):
    def test_artifacts_retry_reroute_next_job_goal_and_resolvable_trace(self):
        h = self.scenario(scripts={'squares': ['wrong', 'provider_error', 'good']},
                          models=('fixture-a', 'fixture-b'))
        final = h.drive()
        self.assertEqual(final.state, c.State.COMPLETED)
        self.assertEqual([r.conditions.model for r in h.adapter.requests],
                         ['fixture-a', 'fixture-a', 'fixture-b', 'fixture-a'])
        transitions = [v for v in h.controller.records if isinstance(v, Transition)]
        self.assertEqual([v.kind for v in transitions], ['execute', 'retry', 'reroute', 'execute'])
        self.assertEqual([r.ref.job_id for r in h.adapter.requests], ['squares'] * 3 + ['total'])
        self.assertEqual(len({r.ref.attempt_id for r in h.adapter.requests}), 4)
        history = h.state.history('run', 'ac_history')
        self.assertEqual([(r.status.value, r.reason, ac.verdict) for r, ac in history], [
            ('completed', None, 'fail'), ('error', 'provider_error', 'fail'),
            ('completed', None, 'pass'), ('completed', None, 'pass')])
        first, failed, recovered, total = [h.state.get_attempt(r.ref) for r in h.adapter.requests]
        self.assertEqual(h.read_result(first.result)[0], [0])
        self.assertEqual(failed.result.artifact_refs, ())
        self.assertEqual(h.read_result(recovered.result)[0], EXPECTED['squares'])
        self.assertEqual(h.read_result(total.result)[0], EXPECTED['total'])
        self.assertEqual([v['verdict'] for v in h.checks if v['kind'] == 'run'], ['incomplete', 'pass'])
        self.assertEqual(len(h.plan_calls), 2)
        self.assertEqual(h.plan_calls[1][2].finding.verdict, 'incomplete')
        self.assertEqual(final.goal.finding.verdict, 'pass')
        for result, ac in history:
            for relative in ac.evidence_refs:
                evidence = json.loads((h.root / relative).read_text())
                self.assertEqual(evidence['verdict'], ac.verdict)
                self.assertEqual(evidence['observed'][0][0], result.ref.job_id)
        by_id = self.assert_trace_links(h)
        self.assertEqual(by_id['result:' + first.ref.attempt_id]['summary']['status'], 'completed')
        self.assertEqual(by_id['ac:' + first.ref.attempt_id]['summary']['verdict'], 'fail')
        self.assertNotIn('synthetic-never-publish', h.trace.jsonl())
        self.assertNotIn('origin=human', h.trace.jsonl())
        # Repeated terminal calls cannot submit more work or duplicate trace.
        before = h.trace.jsonl()
        self.assertEqual(h.step(), final)
        self.assertEqual(h.trace.jsonl(), before)
        self.assertEqual(len(h.adapter.requests), 4)

    def test_preexecution_approve_gateway_notification_rejudgment_and_goal(self):
        h = self.scenario()
        wait = self.preflight_wait(h)
        self.assertEqual((utc(wait.deadline) - utc(h.now)).total_seconds(), 24 * 60 * 60)
        self.assertEqual(h.gateway.notify(wait.ref, wait.request_id), 'transport_accepted')
        h.gateway.notify(wait.ref, wait.request_id)
        self.assertEqual(len(h.smtp.messages), 1)
        self.assertEqual(h.state.history('run', 'approvals'), ())
        receipt = h.receive(wait, h.comment(wait))
        self.assertEqual(receipt.disposition, 'applied')
        h.protection = False
        self.assertEqual(h.step().state, c.State.WAITING_HUMAN)
        self.assertEqual(h.adapter.requests, [])
        h.protection = True
        # First exact target approved; the second target still needs its own answer.
        self.assertEqual(h.drive().state, c.State.WAITING_HUMAN)
        second = h.current_wait()
        self.assertEqual(second.ref.job_id, 'total')
        self.assertNotEqual(second.action, wait.action)
        h.publish(second)
        h.receive(second, h.comment(second))
        self.assertEqual(h.drive().state, c.State.COMPLETED)
        self.assertEqual(len(h.state.history('run', 'approvals')), 2)
        self.assert_trace_links(h)

    def test_active_callback_answer_relay_same_attempt_and_independent_ac(self):
        h = self.scenario(callback=True)
        wait = self.active_wait(h)
        ref = h.adapter.requests[0].ref
        comment = h.comment(wait)
        receipt = h.receive(wait, comment)
        self.assertEqual(h.receive(wait, comment), receipt)
        self.assertEqual(h.adapter.responses, [])
        self.assertEqual(h.step().reason, 'relay_receipt')
        self.assertEqual(h.adapter.responses[0].ref, ref)
        self.assertEqual(h.adapter.responses[0].resolution, c.Resolution.ALLOW)
        self.assertEqual(h.step().reason, 'job_goal_verified')
        snapshot = h.state.get_attempt(ref)
        self.assertEqual((snapshot.result.status, snapshot.ac.verdict), (c.State.COMPLETED, 'pass'))
        self.assertEqual(len(h.adapter.requests), 1)
        self.assert_trace_links(h)

    def test_forged_human_actor_and_worker_claim_cannot_authorize(self):
        h = self.scenario()
        wait = self.preflight_wait(h)
        # Matching display name is insufficient; numeric source identity is wrong.
        forged = h.comment(wait, user=999)
        with self.assertRaises(UntrustedInput): h.receive(wait, forged)
        with self.assertRaises(UntrustedInput):
            h.store.intake().record_answer(c.HumanResponse('fake', wait.ref, wait.request_id,
                wait.action, c.HumanAnswer.APPROVE, 'worker:origin=human'), 'worker:origin=human', h.revision())
        self.assertEqual(h.state.history('run', 'approvals'), ())
        self.assertEqual(h.step().state, c.State.WAITING_HUMAN)
        self.assertEqual(h.adapter.requests, [])
        h.isolated = False
        with self.assertRaises(UntrustedInput): h.receive(wait, h.comment(wait))

    def test_action_scope_and_environment_mismatch_never_reuse_approval(self):
        h = self.scenario()
        wait = self.preflight_wait(h)
        with self.assertRaises(Conflict):
            h.receive(wait, h.comment(wait, presentation_digest='different-presentation'))
        h.receive(wait, h.comment(wait))
        self.assertEqual(h.judgment.judge(h.request(wait)).reason, 'authenticated_approval')
        for action in (replace(wait.action, name='network.publish'),
                       replace(wait.action, scope=c.Scope((('path', '/synthetic/other'),), True)),
                       replace(wait.action, scope=c.Scope((('path', None),)))):
            with self.subTest(action=action):
                self.assertNotEqual(h.judgment.judge(h.request(wait, action=action)).decision, c.Decision.NORMAL)
        changed = replace(h.conditions[0], environment_ref='fixture:changed')
        self.assertEqual(h.judgment.judge(h.request(wait, conditions=changed)).decision, c.Decision.CONFIRM)
        h.deny = True
        self.assertEqual(h.judgment.judge(h.request(wait)).decision, c.Decision.DENY)
        self.assertEqual(h.adapter.requests, [])

    def test_rejection_and_timeout_block_renamed_route_but_allow_different_effect(self):
        for outcome in ('reject', 'timeout'):
            with self.subTest(outcome=outcome):
                h = self.scenario()
                wait = self.preflight_wait(h)
                if outcome == 'reject':
                    h.receive(wait, h.comment(wait, 'reject'))
                else:
                    h.now = wait.deadline
                    h.waiting.expire(wait.ref, wait.request_id, expected_revision=h.revision())
                job = c.Job('run', 'renamed', 'Same effect with a new label', ('check artifact',))
                changed = replace(h.conditions[0], model='renamed-model', adapter='renamed-adapter')
                request = h.request(wait, job='renamed', conditions=changed, method='renamed-method')
                d = h.judgment.judge(replace(request, proposed_job=job))
                h.state.add_job(job, d.decision_id, d.state_revision)
                h.confirm = False  # Even changed policy cannot silently erase the history.
                d = h.judgment.judge(request)
                self.assertEqual(d.reason, 'human_rejected_operation' if outcome == 'reject' else 'unanswered_operation')
                alternative = replace(request, action=replace(wait.action, name='filesystem.read'))
                self.assertEqual(h.judgment.judge(alternative).decision, c.Decision.NORMAL)
                self.assertEqual(h.step().reason, 'replanned')
                self.assertEqual(h.adapter.requests, [])
                self.assertEqual(h.state.history('run', 'approvals'), ())
                self.assertEqual(len(h.state.history('run', 'rejections')), int(outcome == 'reject'))
                self.assertEqual(len(h.state.history('run', 'timeouts')), int(outcome == 'timeout'))

    def test_timeout_late_response_and_late_native_completion_do_not_resurrect(self):
        h = self.scenario(callback=True)
        wait = self.active_wait(h)
        # Created before deadline; received at deadline still cannot backdate approval.
        comment = h.comment(wait)
        h.now = wait.deadline
        h.waiting.expire(wait.ref, wait.request_id, expected_revision=h.revision())
        receipt = h.receive(wait, comment)
        self.assertEqual((receipt.disposition, receipt.approval_id), ('late', None))
        ref = h.adapter.requests[0].ref
        h.adapter.stop_status = c.StopStatus.UNCONFIRMED
        h.adapter.finish(ref)  # Native late completed observation is retained separately.
        for _ in range(2): self.assertEqual(h.step().reason, 'stop_unconfirmed')
        # The genuine Native Result arrived: COMPLETED, never rewritten with
        # a fabricated timeout reason and never AC/output evaluated.
        self.assertEqual(h.state.get_attempt(ref).result.status, c.State.COMPLETED)
        self.assertIsNone(h.state.get_attempt(ref).result.reason)
        self.assertIsNone(h.state.get_attempt(ref).ac)
        self.assertIsNone(h.state.get_attempt(ref).output)
        self.assertEqual(h.adapter.responses, [])
        self.assertEqual(h.state.history('run', 'approvals'), ())
        self.assertEqual(h.state.history('run', 'rejections'), ())
        self.assertEqual(len(h.adapter.requests), 1)
        h.adapter.stop_status = c.StopStatus.CONFIRMED
        final = h.step()
        self.assertEqual((final.state, final.reason), (c.State.PENDING, 'replanned'))
        self.assertEqual(h.state.get_attempt(ref).stop_reply.status, c.StopStatus.CONFIRMED)
        self.assertIsNone(h.state.get_attempt(ref).ac)
        with self.assertRaises(InvalidTransition):
            h.store.bridge(h.conditions[0].adapter).get_resume(ref, h.conditions[0].adapter, 'unused')
        self.assert_trace_links(h)

    def test_human_stop_waits_for_cessation_and_never_checks_goal(self):
        h = self.scenario(callback=True)
        wait = self.active_wait(h)
        h.receive(wait, h.comment(wait, 'stop_run'))
        h.adapter.stop_status = c.StopStatus.REQUESTED
        self.assertTrue(h.state.get_run('run').stop_requested)
        self.assertEqual(h.step().reason, 'stop_unconfirmed')
        self.assertEqual(h.adapter.responses, [])
        self.assertEqual(h.checks, [])
        h.adapter.stop_status = c.StopStatus.CONFIRMED
        # Confirmed cessation without a Result is a held state, never a
        # synthesized failure: no Result, AC or output is fabricated.
        held = h.step()
        self.assertEqual((held.state, held.reason, held.cessation_confirmed),
                         (c.State.RUNNING, 'stop_result_missing', True))
        attempt = h.state.get_attempt(h.adapter.requests[0].ref)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.ac)
        self.assertIsNone(attempt.output)
        self.assertNotIn(h.state.get_run('run').state, c.TERMINAL)
        h.adapter.finish(h.adapter.requests[0].ref)  # the real Result arrives
        final = h.step()
        self.assertEqual((final.state, final.reason, final.cessation_confirmed), (c.State.FAILED, 'human_stop', True))
        self.assertEqual(h.state.history('run', 'approvals'), ())
        self.assertEqual(h.state.history('run', 'ac_history'), ())
        self.assertEqual(len(h.adapter.requests), 1)
        self.assert_trace_links(h)

    def test_wait_binds_exact_supplied_judgment_and_presented_conditions(self):
        h = self.scenario(models=('fixture-a', 'fixture-b'))
        h.step()  # Insert the contained Job without dispatching it.
        h.confirm = True
        ref = c.QuestionRef('run', 'squares')
        requests = [JudgmentRequest(ref, h.action('squares'), 'compute-artifact',
                    replace(v, environment_ref='fixture:route-' + v.model))
                    for v in h.conditions]
        decisions = [(h.judgment.judge(r), r) for r in requests]
        # Choose the lower sorted ID to reproduce the original wrong-candidate bug.
        (intended, intended_request), (other, other_request) = sorted(
            decisions, key=lambda pair: pair[0].decision_id)
        h.trace.record_judgment(intended, at=h.now, links=())
        wait = h.waiting.open(ref, 'explicit-question', intended.action, intended.decision,
            intended.reason, intended_request.method, expected_revision=h.revision(),
            judgment_ref=intended.decision_id)
        h.publish(wait)
        presentation = h.journal.publication(wait_link(wait.ref, wait.request_id))['presentation']
        conditions = intended_request.conditions
        self.assertEqual(presentation['judgment_ref'], intended.decision_id)
        self.assertEqual(presentation['execution_conditions'], {
            'model': conditions.model, 'adapter': conditions.adapter,
            'workspace': conditions.workspace, 'environment_ref': conditions.environment_ref,
            'control_evidence_refs': list(conditions.control_evidence_refs)})
        h.receive(wait, h.comment(wait))
        approved_conditions = h.state.history('run', 'approvals')[0][1]
        self.assertEqual(approved_conditions, intended_request.conditions)
        self.assertNotEqual(approved_conditions, other_request.conditions)
        self.assertEqual(h.judgment.judge(intended_request).reason, 'authenticated_approval')
        self.assertEqual(h.judgment.judge(other_request).decision, c.Decision.CONFIRM)
        self.assertEqual(h.adapter.requests, [])

    def test_authenticated_instruction_rejection_timeout_replan_same_required_job(self):
        for answer in ('instruct', 'reject', 'timeout'):
            with self.subTest(answer=answer):
                h = self.scenario()
                wait = self.preflight_wait(h)
                required = h.state.get_job('run', 'squares')
                if answer == 'timeout':
                    h.now = wait.deadline
                    h.waiting.expire(wait.ref, wait.request_id, expected_revision=h.revision())
                else:
                    self.assertEqual(h.receive(wait, h.comment(wait, answer)).disposition, 'applied')
                self.assertEqual(h.step().reason, 'replanned')
                self.assertEqual(len(h.replan_calls), 1)
                self.assertEqual(h.state.get_job('run', 'squares'), required)
                self.assertEqual(h.state.history('run', 'approvals'), ())
                self.assertEqual(h.step().reason, 'execute_receipt')
                self.assertEqual(h.step().reason, 'job_goal_verified')
                self.assertEqual(h.adapter.requests[0].job, required)
                self.assertEqual(len(h.state.history('run', 'rejections')), int(answer == 'reject'))
                self.assertEqual(len(h.state.history('run', 'timeouts')), int(answer == 'timeout'))
                self.assertEqual(len(h.state.get_run('run').human_instructions), int(answer == 'instruct'))
                # Required next Job still needs its own scoped authorization.
                self.assertEqual(h.drive().state, c.State.WAITING_HUMAN)
                next_wait = h.current_wait()
                self.assertEqual(next_wait.ref.job_id, 'total')
                h.publish(next_wait)
                h.receive(next_wait, h.comment(next_wait))
                self.assertEqual(h.drive().state, c.State.COMPLETED)

    def test_final_job_and_run_goals_durable_and_restart_returns_same_result(self):
        h = self.scenario()
        final = h.drive()
        self.assertEqual(final.state, c.State.COMPLETED)
        self.assertEqual(h.state.get_run('run').state, c.State.COMPLETED)
        self.assertEqual(h.build().step(), final)
        self.assertEqual(len(h.state.history('run', 'job_goals')), 2)
        self.assertEqual(h.state.history('run', 'run_goals')[-1], final.goal)
        self.assertEqual(len(h.state.history('run', 'ac_history')), 2)

    def test_empty_catalog_never_promotes_fixture_or_live_route(self):
        h = self.scenario()
        h.catalog = Catalog()
        h.controller = h.build()
        self.assertEqual(h.drive().reason, 'no_eligible_route_or_pair_limit')
        self.assertEqual(h.adapter.requests, [])
        self.assertEqual(h.checks, [])
        self.assertEqual(Catalog().entries, ())

    def test_codex_unstarted_refusal_reconciles_result_ac_and_bounded_retry(self):
        calls = []
        adapter = CodexAdapter(transport_factory=lambda request: calls.append(request))
        h = self.scenario(adapter=adapter, adapter_id='codex.app-server', models=('fixture-model',))
        self.assertEqual(h.drive().state, c.State.FAILED)
        self.assertEqual(calls, [])
        attempts = h.state.attempts('run')
        self.assertEqual(len(attempts), 2)
        for attempt in attempts:
            # Exact request-matched refusal only: no Result, AC verdict,
            # cessation or output is fabricated for a never-started Attempt.
            self.assertIsNone(attempt.result)
            self.assertIsNone(attempt.ac)
            self.assertIsNone(attempt.stop_reply)
            self.assertIsNone(attempt.started_at)
            self.assertIsNotNone(attempt.ended_at)
            self.assertEqual(h.state.attempt_settlement(attempt.ref), 'never_started')
        self.assertEqual(h.checks, [])
        self.assertEqual(len(h.state.history('run', 'execute_history')), 2)

    def test_devin_unstarted_refusal_reconciles_result_ac_and_bounded_retry(self):
        calls = []
        adapter = DevinAdapter(transport_factory=lambda request: calls.append(request))
        h = self.scenario(adapter=adapter, adapter_id='devin.acp', models=('fixture-model',))
        self.assertEqual(h.drive().state, c.State.FAILED)
        self.assertEqual(calls, [])
        attempts = h.state.attempts('run')
        self.assertEqual(len(attempts), 2)
        for attempt in attempts:
            # Exact request-matched refusal only: no Result, AC verdict,
            # cessation or output is fabricated for a never-started Attempt.
            self.assertIsNone(attempt.result)
            self.assertIsNone(attempt.ac)
            self.assertIsNone(attempt.stop_reply)
            self.assertIsNone(attempt.started_at)
            self.assertIsNotNone(attempt.ended_at)
            self.assertEqual(h.state.attempt_settlement(attempt.ref), 'never_started')
        self.assertEqual(h.checks, [])
        self.assertEqual(len(h.state.history('run', 'execute_history')), 2)


class NativeMappingE2E(E2ECase):
    def native(self, kind):
        wire = ProtocolWire()
        checks = []
        cls, adapter_id = (CodexAdapter, 'codex.app-server') if kind == 'codex' else (DevinAdapter, 'devin.acp')
        adapter = cls(verify_host=lambda request, phase, native: checks.append(phase),
                      transport_factory=lambda _: wire, clock=lambda: 0)
        h = self.scenario(adapter=adapter, adapter_id=adapter_id, models=('fixture-model',))
        h.step(); h.step()
        ref = next(v.ref for v in h.controller.records if isinstance(v, Transition))
        wire.reply('initialize', {'userAgent': 'fixture'} if kind == 'codex' else {'protocolVersion': 1})
        h.step()
        if kind == 'codex':
            wire.reply('thread/start', {'thread': {'id': 'private-thread'}, 'model': 'fixture-model',
                'modelProvider': 'openai', 'cwd': str(h.root), 'approvalPolicy': 'on-request',
                'approvalsReviewer': 'user', 'sandbox': {'type': 'readOnly'}})
            h.step()
            wire.reply('turn/start', {'turn': {'id': 'private-turn', 'status': 'inProgress'}})
        else:
            # Live ACP ordering; the trusted constructor default desires plan.
            # Synthetic host checks do not establish live action interception.
            config_options = [{'id': 'mode', 'name': 'Mode', 'type': 'select',
                'currentValue': 'accept-edits', 'options': [
                    {'value': mode, 'name': mode}
                    for mode in ('accept-edits', 'smart', 'ask', 'plan', 'bypass')]}]
            wire.incoming.append({'jsonrpc': '2.0', 'method': 'session/update', 'params': {
                'sessionId': 'private-session', 'update': {
                    'sessionUpdate': 'config_option_update', 'configOptions': config_options}}})
            wire.reply('session/new', {'sessionId': 'private-session', 'configOptions': config_options})
            h.step()
            self.assertEqual(wire.sent[-1]['method'], 'session/set_config_option')
            self.assertEqual(wire.sent[-1]['params'],
                             {'sessionId': 'private-session', 'configId': 'mode', 'value': 'plan'})
            self.assertEqual(checks, ['launch'])
            self.assertFalse(any(m.get('method') == 'session/prompt' for m in wire.sent))
            wire.reply('session/set_config_option', {'configOptions': [
                {**config_options[0], 'currentValue': 'plan'}]})
        h.step()
        self.assertEqual(checks, ['launch', 'turn' if kind == 'codex' else 'session'])
        return h, wire, ref

    def callback(self, kind, wire, h):
        if kind == 'codex':
            wire.incoming.append({'id': 7, 'method': 'item/commandExecution/requestApproval', 'params': {
                'threadId': 'private-thread', 'turnId': 'private-turn', 'itemId': 'private-item',
                'command': 'printf fixture', 'cwd': str(h.root), 'environmentId': 'local'}})
        else:
            wire.incoming.append({'jsonrpc': '2.0', 'id': 7, 'method': 'session/request_permission', 'params': {
                'sessionId': 'private-session', 'toolCall': {'toolCallId': 'private-item',
                    'kind': 'execute', 'title': 'Synthetic command', 'rawInput': {'command': 'printf fixture'}},
                'options': [{'optionId': 'reject', 'kind': 'reject_once'}]}})

    def test_native_completed_result_blocks_ac_and_retry_without_cessation(self):
        for kind in ('codex', 'devin'):
            with self.subTest(kind=kind):
                h, wire, ref = self.native(kind)
                if kind == 'codex':
                    wire.incoming.append({'method': 'turn/completed', 'params': {'threadId': 'private-thread',
                        'turn': {'id': 'private-turn', 'status': 'completed'}}})
                else: wire.reply('session/prompt', {'stopReason': 'end_turn'})
                for _ in range(2): self.assertEqual(h.step().reason, 'terminal_cessation_unconfirmed')
                attempt = h.state.get_attempt(ref)
                self.assertEqual((attempt.result.status, attempt.ac.verdict), (c.State.COMPLETED, 'blocked'))
                self.assertEqual(attempt.result.artifact_refs, ())
                self.assertEqual(attempt.stop_reply.status, c.StopStatus.UNCONFIRMED)
                self.assertEqual(h.checks, [])
                self.assertEqual(len([v for v in h.controller.records if isinstance(v, Transition)]), 1)
                self.assert_trace_links(h)

    def test_native_provider_failure_is_error_and_does_not_become_ac_fail(self):
        for kind in ('codex', 'devin'):
            with self.subTest(kind=kind):
                h, wire, ref = self.native(kind)
                if kind == 'codex':
                    wire.incoming.append({'method': 'turn/completed', 'params': {'threadId': 'private-thread',
                        'turn': {'id': 'private-turn', 'status': 'failed', 'error': 'secret=provider-details'}}})
                else: wire.reply('session/prompt', error={'code': -1, 'message': 'secret=provider-details'})
                self.assertEqual(h.step().reason, 'terminal_cessation_unconfirmed')
                snapshot = h.state.get_attempt(ref)
                self.assertEqual(snapshot.result.status, c.State.ERROR)
                self.assertEqual(snapshot.result.reason, 'native_turn_failed' if kind == 'codex' else 'native_rpc_error')
                self.assertEqual(snapshot.ac.verdict, 'blocked')
                self.assertEqual(h.checks, [])
                self.assertNotIn('provider-details', h.trace.jsonl())

    def test_native_scope_cannot_be_approved_resume_unsupported_stop_unconfirmed(self):
        for kind in ('codex', 'devin'):
            with self.subTest(kind=kind):
                h, wire, ref = self.native(kind)
                self.callback(kind, wire, h)
                self.assertEqual(h.step().state, c.State.WAITING_HUMAN)
                wait = h.current_wait()
                self.assertFalse(wait.action.scope.known)
                h.publish(wait)
                with self.assertRaises(UntrustedInput): h.receive(wait, h.comment(wait))
                resume = h.adapter.resume(c.ResumeState(h.conditions[0].adapter, ref, b'synthetic-private-state'))
                self.assertEqual(resume.status, c.OperationStatus.UNSUPPORTED)
                self.assertEqual(h.state.history('run', 'approvals'), ())
                h.receive(wait, h.comment(wait, 'stop_run'))
                self.assertEqual(h.step().reason, 'stop_unconfirmed')
                self.assertFalse(h.progress[-1].cessation_confirmed)
                self.assertEqual(h.checks, [])
                self.assertNotIn('synthetic-private-state', h.trace.jsonl())
                self.assertNotIn('private-thread', h.trace.jsonl())
                self.assertNotIn('private-session', h.trace.jsonl())


if __name__ == '__main__': unittest.main()
