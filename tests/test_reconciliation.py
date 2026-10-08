"""Synthetic host/Adapter evidence only: crash, authority and continuation edges."""
from dataclasses import replace
from unittest import TestCase
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4.adapters.codex import CodexAdapter
from co_v4.state import Conflict, InvalidTransition, Limits
import test_controller as fixtures


class ReconciliationTests(TestCase):
    setUp = fixtures.ControllerTests.setUp
    plan = fixtures.ControllerTests.plan
    build = fixtures.ControllerTests.build
    verify = fixtures.ControllerTests.verify
    start = fixtures.ControllerTests.start
    drive = fixtures.ControllerTests.drive

    def restart_store(self):
        self.h.store.close()
        self.h.store = self.h.connect()
        self.addCleanup(self.h.store.close)
        self.h.refresh()
        self.controller = self.build()

    def wait(self):
        self.h.confirm = True
        self.drive()
        return next(r for r in self.controller.records if isinstance(r, c.WaitingHuman))

    def alternative(self, run, current, disposition):
        # Trusted synthetic planner, still subject to real containment/Judgment.
        return replace(current, action=replace(current.action, name='fixture.alternative'),
                       method='alternative')

    def test_restart_after_job_insertion_does_not_invoke_planner_again(self):
        self.controller.step()
        self.restart_store()
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(len(self.native.requests), 1)

    def test_restart_after_result_journal_before_ac_keeps_original_result(self):
        ref = self.start()
        # Crash after events committed, before the Controller's poll/AC step.
        for event in self.native.events(ref):
            self.h.ctrl.record_event(event, self.h.ctrl.get_attempt(ref).revision)
        before = self.h.ctrl.get_attempt(ref).result
        self.restart_store()
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(self.h.ctrl.get_attempt(ref).result, before)
        self.assertEqual(len(self.native.requests), 1)
        self.assertEqual(len(self.h.ctrl.history('r', 'job_goals')), 1)

    def test_restart_after_job_goal_commit_before_checkpoint(self):
        self.start()
        with patch.object(self.controller, '_save', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.controller.step()
        self.restart_store()
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(len(self.native.requests), 1)
        self.assertEqual(len(self.h.ctrl.history('r', 'ac_history')), 1)

    def test_restart_preflight_wait_uses_original_question_and_exact_approval(self):
        wait = self.wait()
        self.restart_store()
        self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        self.assertEqual(self.h.ctrl.waits('r'), (wait,))
        self.h.answer(wait)
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(len(self.native.requests), 1)

    def test_restart_callback_keeps_cursor_and_does_not_duplicate_relay(self):
        self.native.confirmation = self.h.action
        self.start()
        self.h.confirm = True
        self.controller.step()
        wait = next(r for r in self.controller.records if isinstance(r, c.WaitingHuman))
        self.h.answer(wait)
        self.assertEqual(self.controller.step().reason, 'relay_receipt')
        self.restart_store()
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(len(self.native.responses), 1)
        self.assertEqual(len(self.native.requests), 1)

    def test_crash_during_execute_cannot_redispatch_reserved_identity(self):
        self.controller.step()
        def ambiguous(request):
            self.native.requests.append(request)
            raise KeyboardInterrupt
        with patch.object(self.native, 'execute', side_effect=ambiguous):
            with self.assertRaises(KeyboardInterrupt): self.controller.step()
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        self.restart_store()
        for _ in range(2):
            self.assertEqual(self.controller.step().state, c.State.RUNNING)
        self.assertEqual(len(self.native.requests), 1)
        self.assertIsNone(self.h.ctrl.attempts('r')[0].result)
        self.assertEqual(self.h.ctrl.history('r', 'execute_history'), ())

    def test_crash_during_relay_never_resends_allow(self):
        self.native.confirmation = self.h.action
        self.start()
        def ambiguous(response):
            self.native.responses.append(response)
            raise KeyboardInterrupt
        with patch.object(self.native, 'respond', side_effect=ambiguous):
            with self.assertRaises(KeyboardInterrupt): self.controller.step()
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        self.restart_store()
        self.assertEqual(self.controller.step().reason, 'stop_unconfirmed')
        self.assertEqual(len(self.native.responses), 1)
        self.assertEqual(len(self.native.requests), 1)

    def test_never_started_receipt_recovery_and_limits(self):
        def refusal(request):
            self.native.requests.append(request)
            return c.OperationReply(request.ref, c.OperationStatus.UNSUPPORTED, 'fixture host refusal',
                never_started=c.NeverStarted(request, 'fixture:before-transport'))
        self.native.execute = refusal
        self.controller.step()
        self.assertEqual(self.controller.step().reason, 'execute_never_started')
        self.restart_store()
        self.assertEqual(self.drive().state, c.State.FAILED)
        self.assertEqual(len(self.native.requests), 4)  # two per Model+Adapter
        for attempt in self.h.ctrl.attempts('r'):
            # Exact request-matched receipt only: no Result, AC, cessation or
            # output is ever fabricated for a never-started Attempt.
            self.assertIsNone(attempt.result)
            self.assertIsNone(attempt.ac)
            self.assertIsNone(attempt.stop_reply)
            self.assertIsNone(attempt.started_at)
            self.assertIsNotNone(attempt.ended_at)
            self.assertEqual(self.h.ctrl.attempt_settlement(attempt.ref),
                             'never_started')
        self.assertEqual(self.h.ctrl.history('r', 'job_goals'), ())

    def test_never_started_attestation_must_match_exact_request(self):
        self.controller.step()
        def forged(request):
            altered = replace(request, conditions=replace(request.conditions, environment_ref='other'))
            return c.OperationReply(request.ref, c.OperationStatus.ERROR, 'fixture',
                                    never_started=c.NeverStarted(altered, 'fixture:unbound'))
        self.native.execute = forged
        # The forged receipt is an integrity contradiction: the Controller
        # latches a fatal hold rather than an ordinary controller error.
        progress = self.controller.step()
        self.assertEqual(progress.reason, 'integrity_violation_result_missing')
        self.assertIs(progress.cessation_confirmed, True)
        self.assertEqual(self.controller.step().reason,
                         'integrity_violation_result_missing')
        self.assertEqual(self.h.ctrl.checkpoint('r').halted, 'integrity_violation')
        attempt, = self.h.ctrl.attempts('r')
        self.assertIsNone(attempt.result)
        # The real CONFIRMED reply is the committed capacity proof; no
        # Result or settlement is fabricated to release the held Attempt.
        self.assertEqual(attempt.stop_reply.status, c.StopStatus.CONFIRMED)
        self.assertIsNone(self.h.ctrl.attempt_settlement(attempt.ref))
        self.assertEqual(self.h.ctrl.history('r', 'execute_history'), ())
        self.assertNotIn(self.h.ctrl.get_run('r').state, c.TERMINAL)

    def test_factory_exception_is_ambiguous_even_before_initialize_send(self):
        conditions = replace(self.h.conditions, adapter='codex.app-server', workspace=self.tmp.name)
        request = c.ExecuteRequest(c.AttemptRef('r', 'j', 'a'), self.plan().job, conditions)
        def factory(request): raise OSError('fixture after possible process creation')
        adapter = CodexAdapter(verify_host=lambda *args: None, transport_factory=factory)
        self.addCleanup(adapter.close)
        reply = adapter.execute(request)
        self.assertEqual(reply.status, c.OperationStatus.UNAVAILABLE)
        self.assertIsNone(reply.never_started)

    def test_stale_judgment_or_other_question_cannot_open_wait(self):
        self.controller.step()
        self.h.confirm = True
        request = self.h.request()
        d = self.h.judgment.judge(request)
        wait = c.WaitingHuman(request.ref, 'exact', request.action, d.decision, d.reason,
                              '2026-09-29T00:00:00Z')
        with self.assertRaises(InvalidTransition):
            self.h.ctrl.open_wait(wait, request.method, self.h.rev())
        with self.assertRaises(InvalidTransition):
            self.h.ctrl.open_wait(replace(wait, action=replace(wait.action, name='other')),
                                  request.method, self.h.rev(), d.decision_id)
        self.h.ctrl.set_limits('r', Limits(jobs=19), self.h.rev())
        with self.assertRaises(Conflict):
            self.h.ctrl.open_wait(wait, request.method, self.h.rev(), d.decision_id)
        self.assertEqual(self.h.ctrl.waits('r'), ())

    def test_old_approval_does_not_authorize_changed_environment_after_restart(self):
        wait = self.wait()
        self.h.answer(wait)
        self.h.protection = False
        self.restart_store()
        self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        self.assertEqual(self.native.requests, [])
        self.h.protection = True
        self.assertEqual(self.drive().state, c.State.COMPLETED)

    def test_active_instruction_stops_before_alternative_and_preserves_result(self):
        self.native.confirmation = self.h.action
        self.start()
        self.h.confirm = True
        self.controller.step()
        wait = next(r for r in self.controller.records if isinstance(r, c.WaitingHuman))
        self.h.answer(wait, c.HumanAnswer.INSTRUCT, detail='Use a legitimate alternative')
        self.controller.replanner = self.alternative
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        self.assertEqual(self.controller.step().reason, 'stop_unconfirmed')
        self.assertEqual(len(self.native.requests), 1)
        self.native.stop_status = c.StopStatus.CONFIRMED
        # Confirmed cessation without a Result holds; nothing is synthesized
        # — the applied INSTRUCT persists but cannot run until settlement.
        progress = self.controller.step()
        self.assertEqual((progress.reason, progress.cessation_confirmed),
                         ('stop_result_missing', True))
        self.assertIsNone(
            self.h.ctrl.get_attempt(self.native.requests[0].ref).result)
        self.native.finish(self.native.requests[0].ref, c.State.FAILED)
        self.assertEqual(self.controller.step().reason, 'replanned')
        old = self.h.ctrl.get_attempt(self.native.requests[0].ref).result
        self.assertEqual(old.status, c.State.FAILED)
        self.native.confirmation = None
        self.h.confirm = False
        self.restart_store()
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(self.h.ctrl.get_attempt(old.ref).result, old)
        self.assertEqual(len(self.native.requests), 2)
        self.assertEqual(self.native.responses, [])

    def test_replanning_cannot_drop_required_job_or_expand_ac(self):
        wait = self.wait()
        self.h.answer(wait, c.HumanAnswer.INSTRUCT, detail='Use a legitimate alternative')
        self.controller.replanner = lambda run, plan, details: replace(
            plan, job=replace(plan.job, acceptance_criteria=()))
        self.assertEqual(self.controller.step().reason, 'replan_changed_required_job')
        self.assertEqual(self.h.ctrl.get_job('r', 'j').acceptance_criteria, ('output checked',))
        self.assertEqual(self.native.requests, [])

    def test_replanning_same_rejected_effect_does_not_bypass_or_loop(self):
        wait = self.wait()
        self.h.answer(wait, c.HumanAnswer.REJECT)
        self.controller.replanner = lambda run, plan, details: replace(plan, method='renamed')
        self.assertEqual(self.controller.step().reason, 'replanned')
        self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        for _ in range(3): self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        self.assertEqual(self.native.requests, [])
        self.assertEqual(len(self.h.ctrl.history('r', 'rejections')), 1)

    def test_replan_budget_survives_restart_without_spending_attempts(self):
        self.h.ctrl.set_limits('r', Limits(attempts_per_job=1), self.h.rev())
        wait = self.wait()
        self.h.answer(wait, c.HumanAnswer.INSTRUCT, detail='Use a legitimate alternative')
        self.controller.replanner = lambda run, plan, details: plan
        self.assertEqual(self.controller.step().reason, 'replanned')
        self.controller.step()
        next_wait = next(r for r in reversed(self.controller.records) if isinstance(r, c.WaitingHuman))
        self.h.answer(next_wait, c.HumanAnswer.INSTRUCT, name='second', detail='Reconsider within scope')
        self.restart_store()
        self.assertEqual(self.controller.step().reason, 'replan_limit')
        self.assertEqual(self.native.requests, [])

    def test_restart_after_blocked_ac_commit_does_not_retry(self):
        self.verdicts = ['blocked']
        self.start()
        with patch.object(self.controller, '_save', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.controller.step()
        self.restart_store()
        self.assertEqual(self.controller.step().reason, 'job_ac_blocked')
        self.assertEqual(len(self.native.requests), 1)

    def test_crash_after_releasing_stopped_attempt_still_continues(self):
        self.native.confirmation = self.h.action
        self.start()
        self.h.confirm = True
        self.controller.step()
        wait = next(r for r in self.controller.records if isinstance(r, c.WaitingHuman))
        self.h.answer(wait, c.HumanAnswer.INSTRUCT, detail='Use an alternative')
        # First persist stopping while cessation is unconfirmed.
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        self.controller.step()
        self.native.stop_status = c.StopStatus.CONFIRMED
        # Confirmed cessation without a Result holds before any replan.
        self.assertEqual(self.controller.step().reason, 'stop_result_missing')
        self.native.finish(self.native.requests[0].ref, c.State.FAILED)
        with patch.object(self.controller, '_replan', side_effect=KeyboardInterrupt), \
             patch.object(self.controller, '_save', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.controller.step()
        self.restart_store()
        self.controller.replanner = self.alternative
        self.assertEqual(self.controller.step().reason, 'replanned')
        self.assertEqual(len(self.native.requests), 1)

    def test_stop_reason_string_is_not_typed_never_started_evidence(self):
        ref = self.start()
        a = self.h.ctrl.get_attempt(ref)
        self.h.ctrl.record_stop(c.StopReply(ref, c.StopStatus.CONFIRMED,
                                          'never_started', 'fixture:cessation-only'), a.revision)
        # An ordinary cessation receipt cannot suppress Result or AC collection.
        self.restart_store()
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(self.h.ctrl.get_attempt(ref).ac.verdict, 'pass')

    def test_final_goal_does_not_resurrect_on_late_answer_or_new_job(self):
        wait = self.wait()
        self.h.answer(wait)
        final = self.drive()
        self.restart_store()
        self.assertEqual(self.controller.step(), final)
        job = replace(self.plan().job, job_id='after-final')
        # Post-terminal evaluation itself rejects; no decision exists to carry.
        with self.assertRaises(InvalidTransition):
            self.h.judgment.judge(self.h.request(job='after-final', proposed=job))
        self.assertEqual(self.h.ctrl.get_run('r').state, c.State.COMPLETED)
