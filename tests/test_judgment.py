"""Synthetic Judgment checks; no Native capability is established here."""
from dataclasses import replace
import tempfile
import unittest
from co_v4 import contracts as c
from co_v4.state import Conflict, InvalidTransition, StoreUnavailable
from test_state import Harness


class JudgmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.h=Harness(self.tmp.name); self.h.job()

    def tearDown(self): self.h.store.close(); self.tmp.cleanup()
    def decision(self, **kw): return self.h.judgment.judge(self.h.request(**kw))

    def test_four_decisions_and_deny_first(self):
        h=self.h
        self.assertEqual(self.decision().decision,c.Decision.NORMAL)
        h.confirm=True; self.assertEqual(self.decision().decision,c.Decision.CONFIRM)
        unknown=replace(h.action,scope=c.Scope((('path',None),)))
        self.assertEqual(self.decision(action=unknown).decision,c.Decision.UNDETERMINED)
        h.deny=True; self.assertEqual(self.decision(action=unknown).decision,c.Decision.DENY)

    def test_protection_and_resolver_failure_fail_closed(self):
        h=self.h; h.protection=False
        self.assertEqual(self.decision(attempt='a').reason,'environment_or_protection_unproven')
        with self.assertRaises(InvalidTransition): h.begin()
        h.store._evidence=lambda *_: (_ for _ in ()).throw(RuntimeError('unavailable'))
        with self.assertRaises(StoreUnavailable): self.decision()

    def test_exact_approval_reuse_across_jobs(self):
        h=self.h; h.answer(h.wait()); h.job('next')
        d=self.decision(job='next',attempt='a')
        self.assertEqual(d.reason,'authenticated_approval'); h.begin(job='next')
        self.assertEqual(len(h.ctrl.history('r','answers')),1)
        self.assertEqual(len(h.ctrl.history('r','approvals')),1)
        h.deny=True; self.assertEqual(self.decision().decision,c.Decision.DENY)

    def test_changed_target_environment_run_cannot_reuse(self):
        h=self.h; h.answer(h.wait())
        for key in ('repository','branch','path','content_digest'):
            dims=dict(h.action.scope.dimensions); dims[key]+='-changed'
            self.assertEqual(self.decision(action=replace(h.action,scope=c.Scope(tuple(dims.items()),True))).decision,c.Decision.CONFIRM)
        self.assertEqual(self.decision(conditions=replace(h.conditions,environment_ref='new')).decision,c.Decision.CONFIRM)
        h.create('other')
        request=replace(h.request(),ref=c.QuestionRef('other','new'),proposed_job=c.Job('other','new','create output',('inspect',)))
        d=h.judgment.judge(request); h.ctrl.add_job(request.proposed_job,d.decision_id,h.rev('other'))
        self.assertEqual(h.judgment.judge(replace(request,proposed_job=None)).decision,c.Decision.CONFIRM)

    def test_rejection_blocks_relabels_but_allows_removed_operation(self):
        h=self.h; h.answer(h.wait(),c.HumanAnswer.REJECT); h.job('renamed')
        request=replace(h.request(job='renamed',conditions=replace(h.conditions,model='new',adapter='new')),method='renamed')
        self.assertEqual(h.judgment.judge(request).reason,'human_rejected_operation')
        dims=dict(h.action.scope.dimensions); dims['content_digest']='changed'
        self.assertEqual(self.decision(action=replace(h.action,scope=c.Scope(tuple(dims.items()),True))).reason,'human_rejected_operation')
        h.confirm=False
        self.assertEqual(self.decision(action=c.Action('filesystem.read',h.action.scope)).decision,c.Decision.NORMAL)

    def test_timeout_and_pending_question_cannot_be_bypassed(self):
        h=self.h; w=h.wait(); h.job('renamed'); h.confirm=False
        self.assertEqual(self.decision(job='renamed').reason,'awaiting_human')
        h.now=w.deadline; h.store.scheduler().expire_wait(w.ref,w.request_id,h.rev())
        self.assertEqual(self.decision(job='renamed').reason,'unanswered_operation')
        self.assertEqual(h.ctrl.history('r','rejections'),())
        self.assertEqual(self.decision(action=c.Action('filesystem.read',h.action.scope)).decision,c.Decision.NORMAL)

    def test_dispatch_rechecks_state_policy_and_conditions(self):
        h=self.h; request=c.ExecuteRequest(c.AttemptRef('r','j','a'),h.ctrl.get_job('r','j'),h.conditions)
        d=self.decision(attempt='a'); h.policy='changed'
        with self.assertRaises(Conflict): h.ctrl.begin_attempt(request,d.decision_id,h.rev())
        d=self.decision(attempt='a'); h.job('next')
        with self.assertRaises(Conflict): h.ctrl.begin_attempt(request,d.decision_id,h.rev())
        d=self.decision(attempt='a')
        with self.assertRaises(InvalidTransition):
            h.ctrl.begin_attempt(replace(request,conditions=replace(h.conditions,workspace='/other')),d.decision_id,h.rev())

    def test_native_confirm_intent_reuse_and_exact_relay(self):
        h=self.h; a=h.begin(); callback=h.callback(); h.event(c.ConfirmationEvent(a.ref,'e',callback))
        d=self.decision(attempt='a',confirmation=callback); self.assertEqual(d.decision,c.Decision.NORMAL)
        response=c.ConfirmationResponse(a.ref,'q',h.action,c.Resolution.ALLOW,d.decision_id)
        h.ctrl.validate_relay(response)
        with self.assertRaises(Conflict): h.ctrl.validate_relay(replace(response,request_id='other'))
        h.policy='changed'
        with self.assertRaises(Conflict): h.ctrl.validate_relay(response)
        self.assertEqual(h.ctrl.history('r','answers'),())

    def test_multiple_callbacks_cannot_cross_answers(self):
        h=self.h; h.begin(); first=h.wait('q1',attempt='a')
        read=replace(h.action,name='filesystem.read'); second=h.wait('q2',attempt='a',action=read)
        r=h.response(first); crossed=replace(r,request_id='q2'); h.authenticate(crossed.authenticated_source_ref,crossed)
        with self.assertRaises(Conflict): h.intake.record_answer(crossed,crossed.authenticated_source_ref,h.rev())
        h.answer(first); h.answer(second,c.HumanAnswer.REJECT,name='answer2')
        self.assertEqual(self.decision(attempt='a',confirmation=h.callback('q1')).decision,c.Decision.NORMAL)
        self.assertEqual(self.decision(attempt='a',action=read,confirmation=h.callback('q2',action=read)).reason,'human_rejected_operation')

    def test_native_deny_unanswerable_and_unrecorded(self):
        h=self.h; a=h.begin(); callback=h.callback()
        with self.assertRaises(Conflict): self.decision(attempt='a',confirmation=callback)
        for i,changed in enumerate((replace(callback,decision=c.Decision.DENY),replace(callback,can_respond=False))):
            changed=replace(changed,request_id='q'+str(i)); h.event(c.ConfirmationEvent(a.ref,'e'+str(i),changed))
            d=self.decision(attempt='a',confirmation=changed); self.assertEqual(d.decision,c.Decision.DENY)
            with self.assertRaises((ValueError,InvalidTransition)):
                h.ctrl.validate_relay(c.ConfirmationResponse(a.ref,changed.request_id,h.action,c.Resolution.ALLOW,d.decision_id))

    def test_callback_deadline_and_terminal_attempt(self):
        h=self.h; a=h.begin(); w=h.wait(attempt='a'); h.now=w.deadline
        self.assertEqual(self.decision(attempt='a',confirmation=h.callback()).reason,'human_confirmation_timeout')
        h.store.scheduler().expire_wait(w.ref,w.request_id,h.rev())
        # No synthetic Result: the still-live Attempt's callback stays
        # blocked by the timeout wait fact, never by a fabricated terminal.
        self.assertEqual(self.decision(attempt='a',confirmation=h.callback()).reason,'human_confirmation_timeout')
        live = h.ctrl.get_attempt(a.ref)
        self.assertIsNone(live.result)
        self.assertIsNone(live.stop_reply)
        # Only a real terminal Result makes the Attempt genuinely unresumable.
        h.finish(a.ref, c.State.FAILED)
        self.assertEqual(self.decision(attempt='a',confirmation=h.callback()).reason,'attempt_not_resumable')

    def test_timeout_requires_fresh_answer_and_never_resurrects_old_attempt(self):
        h = self.h
        attempt = h.begin()
        wait = h.wait(attempt='a')
        h.now = wait.deadline
        h.store.scheduler().expire_wait(wait.ref, wait.request_id, h.rev())
        self.assertEqual(h.answer(wait).disposition, 'late')
        self.assertEqual(self.decision().reason, 'unanswered_operation')
        # A new question/answer is allowed after rejudging the current Job.
        record = self.decision()
        fresh = c.WaitingHuman(c.QuestionRef('r', 'j'), 'fresh', h.action,
            record.decision, record.reason, '2026-09-30T00:00:00Z')
        h.ctrl.open_wait(fresh, 'write-output', h.rev(), record.decision_id)
        h.answer(fresh, name='fresh-answer')
        self.assertEqual(self.decision(attempt='new').reason, 'authenticated_approval')
        # The old Attempt is still live: its callback is blocked by the
        # timeout wait fact, and fresh approval invents nothing for it.
        self.assertEqual(self.decision(attempt='a', confirmation=h.callback()).reason, 'human_confirmation_timeout')
        live = h.ctrl.get_attempt(attempt.ref)
        self.assertIsNone(live.result)
        self.assertIsNone(live.ac)
        # Even new authorization cannot ignore the timed-out Native's liveness.
        with self.assertRaises(InvalidTransition):
            h.begin('new')
        old = h.ctrl.get_attempt(attempt.ref)
        h.ctrl.record_stop(c.StopReply(attempt.ref, c.StopStatus.CONFIRMED,
            'fixture cessation', 'fixture:stopped'), old.revision)
        # CONFIRMED cessation without a Result is still not settlement: the
        # fresh approved Attempt cannot begin until the real Result arrives.
        with self.assertRaises(InvalidTransition):
            h.begin('new')
        h.finish(attempt.ref, c.State.FAILED)
        self.assertEqual(h.begin('new').state, c.State.PENDING)


if __name__=='__main__': unittest.main()
