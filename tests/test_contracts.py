from dataclasses import replace
import json
from pathlib import Path
import unittest

from co_v4.contracts import (
    ACRecord, Action, Adapter, Approval, AttemptRef, ConfirmationResponse,
    ConfirmationTimeout, Decision, ExecuteRequest, ExecutionConditions,
    HumanAnswer, Job, OperationStatus, QuestionRef, Rejection, Resolution,
    Result, ResultEvent, Scope, State, StopReply, StopStatus, Usage,
    approval_key, approval_target, same_target, validate_response,
)
from co_v4.native_notifications import COMMAND_APPROVAL, codex_confirmation
from fixture_adapter import FixtureAdapter


class ContractTests(unittest.TestCase):
    def setUp(self):
        data = json.loads((Path(__file__).parent / 'fixtures/confirmation.json').read_text())
        self.ref = AttemptRef(**data['ref'])
        self.action = Action(data['action'], Scope(tuple(data['scope'].items()), complete=True))
        self.request = ExecuteRequest(self.ref, Job(self.ref.run_id, self.ref.job_id,
                                      "create fixture output", ("output inspected",)),
                                      ExecutionConditions('fixture-model', 'fixture', '/fixture', 'fixture:env'))
        self.adapter: Adapter = FixtureAdapter(self.action)
        self.approval = Approval('approval-1', self.ref.run_id, self.action, 'verified-ingress:1')

    def response(self, resolution=Resolution.ALLOW):
        return ConfirmationResponse(self.ref, 'confirmation-1', self.action, resolution, 'judgment:1')

    def test_e2e_confirm_approval_resume_result_and_independent_ac(self):
        reply = self.adapter.execute(self.request)
        self.assertEqual(reply.status, OperationStatus.ACCEPTED)
        self.assertEqual(self.adapter.effects, [])
        self.assertEqual(self.adapter.status(self.ref).state, State.WAITING_HUMAN)
        self.assertEqual(self.adapter.resume(reply.resume_state).ref, self.ref)
        self.assertTrue(self.approval.covers(self.ref.run_id, self.action))
        self.adapter.respond(self.response())
        result = self.adapter.events(self.ref)[-1].result
        self.assertEqual(result.status, State.COMPLETED)
        self.assertEqual(self.adapter.effects, [self.action])
        ac = ACRecord(self.ref, 'fail', ('fixture:independent-inspection',))
        self.assertEqual(ac.verdict, 'fail')
        self.assertEqual(result.status, State.COMPLETED)
        self.assertEqual(self.adapter.resume(reply.resume_state).status, OperationStatus.INVALID_STATE)
        self.assertEqual(self.adapter.respond(self.response()).status, OperationStatus.INVALID_STATE)
        self.assertEqual(len(self.adapter.effects), 1)

    def test_display_is_exact_reuse_key_and_scope_order_is_irrelevant(self):
        self.assertEqual(json.loads(approval_key(self.ref.run_id, self.action)),
                         approval_target(self.ref.run_id, self.action))
        reordered = replace(self.action, scope=Scope(tuple(reversed(self.action.scope.dimensions)), True))
        self.assertTrue(same_target(self.action, reordered))
        # Job/Attempt IDs are deliberately excluded; Run and target are included.
        self.assertTrue(self.approval.covers(self.ref.run_id, reordered))
        self.assertFalse(self.approval.covers('other-run', reordered))
        for field in dict(self.action.scope.dimensions):
            with self.subTest(field=field):
                changed = dict(self.action.scope.dimensions); changed[field] += '/different'
                self.assertFalse(self.approval.covers(self.ref.run_id,
                    replace(self.action, scope=Scope(tuple(changed.items()), True))))

    def test_unknown_scope_never_matches_even_itself(self):
        for scope in (Scope((), True), Scope((("branch", None),), True),
                      Scope((("branch", "topic"),)), Scope((("path", None),))):
            action = Action('filesystem.write', scope)
            self.assertIsNone(approval_key('r', action))
            self.assertFalse(same_target(action, action))
        with self.assertRaises(ValueError):
            Scope((("branch", "a"), ("branch", "b")), True)

    def test_wrong_callback_attempt_or_action_cannot_relay(self):
        self.adapter.execute(self.request)
        for response in (replace(self.response(), request_id='confirmation-2'),
                         replace(self.response(), ref=replace(self.ref, attempt_id='other')),
                         replace(self.response(), action=replace(self.action, name='filesystem.delete')),
                         replace(self.response(), decision_ref='')):
            with self.subTest(response=response), self.assertRaises(ValueError):
                self.adapter.respond(response)
        self.assertEqual(self.adapter.effects, [])

    def test_native_hard_deny_cannot_be_overridden(self):
        self.adapter.execute(self.request)
        for request in (replace(self.adapter.confirmation, decision=Decision.DENY),
                        replace(self.adapter.confirmation, can_respond=False)):
            with self.assertRaises(ValueError):
                validate_response(request, self.response())

    def test_rejection_and_timeout_are_not_approval(self):
        self.adapter.execute(self.request)
        self.adapter.respond(self.response(Resolution.DENY))
        result = self.adapter.events(self.ref)[-1].result
        self.assertEqual(result.reason, 'human_rejected')
        self.assertEqual(self.adapter.effects, [])
        before_execution = QuestionRef(self.ref.run_id, self.ref.job_id)
        rejection = Rejection(before_execution, self.action, 'write-empty-file', 'human:reject')
        timeout = ConfirmationTimeout(before_execution, 'preflight-1', self.action, '2026-09-29T00:00:00Z')
        self.assertIsNone(timeout.ref.attempt_id)
        self.assertFalse(isinstance(rejection, Approval))
        self.assertFalse(isinstance(timeout, Rejection))
        self.assertIn(HumanAnswer.INSTRUCT, HumanAnswer)

    def test_stop_ack_is_not_confirmation_and_does_not_complete(self):
        self.adapter.execute(self.request)
        stop = self.adapter.stop(self.ref)
        self.assertEqual(stop.status, StopStatus.REQUESTED)
        self.assertEqual(self.adapter.status(self.ref).state, State.WAITING_HUMAN)
        self.assertEqual(self.adapter.respond(self.response()).status, OperationStatus.INVALID_STATE)
        self.assertEqual(self.adapter.observe_stopped().status, StopStatus.CONFIRMED)
        self.assertEqual(self.adapter.status(self.ref).state, State.FAILED)
        with self.assertRaises(ValueError):
            StopReply(self.ref, StopStatus.CONFIRMED, 'no proof')
        self.assertEqual(self.adapter.effects, [])

    def test_resume_state_is_opaque_bound_and_not_in_repr(self):
        reply = self.adapter.execute(self.request)
        self.assertNotIn('fixture-secret', repr(reply))
        self.assertNotIn('fixture-secret', repr(reply.resume_state))
        for state in (replace(reply.resume_state, adapter='other'),
                      replace(reply.resume_state, ref=replace(self.ref, attempt_id='other')),
                      replace(reply.resume_state, opaque=b'expired')):
            self.assertEqual(self.adapter.resume(state).status, OperationStatus.INVALID_STATE)

    def test_events_replay_with_stable_cursor_and_unknown_usage(self):
        self.adapter.execute(self.request)
        events = self.adapter.events(self.ref)
        self.assertEqual(events, self.adapter.events(self.ref))
        self.assertEqual(self.adapter.events(self.ref, events[0].event_id), events[1:])
        self.assertEqual(self.adapter.usage(), ())
        for percent in (-1, 101, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                Usage('m', 'a', percent, '2026-09-28T00:00:00Z', 'source:1', 'weekly')

    def test_result_and_job_identity_errors(self):
        with self.assertRaises(ValueError):
            Result(self.ref, State.RUNNING)
        with self.assertRaises(ValueError):
            Result(self.ref, State.FAILED, 'ac_unmet')
        with self.assertRaises(ValueError):
            replace(self.request, ref=replace(self.ref, job_id='other'))
        with self.assertRaises(ValueError):
            ResultEvent(self.ref, 'event', Result(replace(self.ref, attempt_id='other'), State.COMPLETED))

    def test_schema_notification_does_not_claim_semantic_scope_or_live_control(self):
        params = {'command': 'git push', 'cwd': '/fixture', 'itemId': 'shared-item'}
        a = codex_confirmation(self.ref, 'callback-1', COMMAND_APPROVAL, params)
        b = codex_confirmation(self.ref, 'callback-2', COMMAND_APPROVAL, params)
        self.assertNotEqual(a.request_id, b.request_id)
        self.assertEqual(a.decision, Decision.UNDETERMINED)
        self.assertFalse(a.requested_action.scope.known)
        self.assertFalse(same_target(a.requested_action, a.requested_action))
        with self.assertRaises(ValueError):
            validate_response(a, ConfirmationResponse(self.ref, a.request_id,
                              a.requested_action, Resolution.ALLOW, 'judgment:1'))
        validate_response(a, ConfirmationResponse(self.ref, a.request_id,
                          a.requested_action, Resolution.DENY, 'judgment:2'))
        unknown = codex_confirmation(self.ref, 'callback-3', 'future/method', {})
        self.assertEqual(unknown.decision, Decision.UNDETERMINED)
        self.assertFalse(unknown.can_respond)


if __name__ == '__main__':
    unittest.main()
