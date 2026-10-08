"""Synthetic core tests, not evidence of host isolation."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from co_v4 import contracts as c
from co_v4.judgment import JudgmentRequest, TrustedEvidence
from co_v4.state import (ControlStore, Conflict, IntegrityViolation, InvalidTransition, LimitExceeded,
    NotFound, StoreUnavailable, UntrustedInput, Limits, IngressReceipt,
    body_digest, create_run_body)


class Harness:
    def __init__(self, directory):
        self.path = Path(directory) / 'control.sqlite'
        self.now = '2026-09-28T00:00:00Z'
        self.receipts = {}
        self.policy, self.protection = 'policy:1', True  # Fixture, not host proof.
        self.confirm, self.contained, self.authorizes, self.deny = False, True, True, False
        self.conditions = c.ExecutionConditions('m', 'adapter', '/fixture', 'env:1', ('controls:fixture',))
        self.action = c.Action('filesystem.write', c.Scope((('repository', 'repo'), ('branch', 'topic'),
            ('path', '/fixture/out'), ('content_digest', 'sha256:one')), True))
        self.store = self.connect(); self.refresh(); self.create()

    def connect(self):
        return ControlStore(self.path, verifier=self.receipts.__getitem__, evidence=self.evidence,
                            clock=lambda: self.now)

    def refresh(self):
        self.ctrl, self.intake, self.judgment = self.store.controller(), self.store.intake(), self.store.judgment()

    def evidence(self, run, request):
        dims = dict(request.action.scope.dimensions)
        operation = repr((request.action.name, dims.get('repository'), dims.get('branch'), dims.get('path')))
        return TrustedEvidence(body_digest(request), self.policy, ('fixture:protection',), operation,
            self.deny, self.confirm, self.contained, self.authorizes, True, self.protection)

    def authenticate(self, source, body, limits=None):
        self.receipts[source] = IngressReceipt('fixture-human', source, body_digest(body), self.now, limits)

    def create(self, run='r', limits=None):
        self.authenticate('origin:' + run, create_run_body(run, 'create tested fixture output'), limits)
        return self.intake.create_run(run, 'create tested fixture output', 'origin:' + run)

    def rev(self, run='r'): return self.ctrl.get_run(run).revision

    def request(self, job='j', attempt=None, action=None, conditions=None, proposed=None, confirmation=None):
        return JudgmentRequest(c.QuestionRef('r', job, attempt), action or self.action, 'write-output',
                               conditions or self.conditions, confirmation, proposed)

    def job(self, name='j'):
        job = c.Job('r', name, 'create output', ('inspect output',))
        d = self.judgment.judge(self.request(job=name, proposed=job))
        return self.ctrl.add_job(job, d.decision_id, self.rev())

    def begin(self, name='a', job='j', conditions=None):
        conditions = conditions or self.conditions
        request = c.ExecuteRequest(c.AttemptRef('r', job, name), self.ctrl.get_job('r', job), conditions)
        d = self.judgment.judge(self.request(job, name, conditions=conditions))
        return self.ctrl.begin_attempt(request, d.decision_id, self.rev())

    def event(self, event): return self.ctrl.record_event(event, self.ctrl.get_attempt(event.ref).revision)

    def finish(self, ref, status=c.State.FAILED):
        return self.event(c.ResultEvent(ref, 'result:' + ref.attempt_id,
            c.Result(ref, status, None if status == c.State.COMPLETED else 'fixture_failure')))

    def callback(self, name='q', attempt='a', action=None):
        return c.Confirmation(c.AttemptRef('r', 'j', attempt), name, c.Decision.CONFIRM,
                              action or self.action, 'confirm', 'fixture', True)

    def wait(self, name='q', attempt=None, action=None):
        self.confirm = True
        action, callback = action or self.action, None
        if attempt is not None:
            callback = self.callback(name, attempt, action)
            self.event(c.ConfirmationEvent(callback.ref, 'event:' + name, callback))
        request = self.request(attempt=attempt, action=action, confirmation=callback)
        d = self.judgment.judge(request)
        wait = c.WaitingHuman(request.ref, name, action, d.decision, d.reason, '2026-09-29T00:00:00Z')
        return self.ctrl.open_wait(wait, request.method, self.rev(), d.decision_id)

    def response(self, wait, answer=c.HumanAnswer.APPROVE, name='answer', detail=''):
        source = 'source:' + name
        response = c.HumanResponse(name, wait.ref, wait.request_id, wait.action, answer, source, detail)
        self.authenticate(source, response)
        return response

    def answer(self, wait, answer=c.HumanAnswer.APPROVE, name='answer', detail=''):
        response = self.response(wait, answer, name, detail)
        return self.intake.record_answer(response, response.authenticated_source_ref, self.rev())


    def stop_run(self, name='stop-intake', run='r'):
        """Real authenticated northbound cancel through Intake."""
        source = 'source:' + name
        self.authenticate(source, {'operation': 'stop_run', 'run_id': run})
        return self.intake.record_stop_request(run, source)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.h = Harness(self.tmp.name)

    def tearDown(self):
        self.h.store.close(); self.tmp.cleanup()

    def test_authenticated_origin_replay_and_immutability(self):
        h = self.h; original = h.ctrl.get_run('r')
        with self.assertRaises(UntrustedInput): h.intake.create_run('evil', 'origin=human', 'forged')
        with self.assertRaises(UntrustedInput): h.intake.create_run('r', 'expanded', 'origin:r')
        with self.assertRaises(FrozenInstanceError): original.original_intent = 'worker'
        h.job()
        self.assertEqual(h.intake.create_run('r', original.original_intent, 'origin:r'), original)
        with self.assertRaises(NotFound): h.ctrl.get_run('missing')
        with self.assertRaises(NotFound): h.ctrl.get_attempt(c.AttemptRef('r','j','missing'))
        h.receipts['other'] = replace(h.receipts['origin:r'], body_digest=body_digest(create_run_body('other','intent')))
        with self.assertRaises(Conflict): h.intake.create_run('other','intent','other')

    def test_handles_and_forged_source_do_not_grant_authority(self):
        h = self.h
        for handle, method in ((h.ctrl,'record_answer'),(h.intake,'begin_attempt'),
                               (h.store.scheduler(),'create_run'),(h.ctrl,'get_resume')):
            self.assertFalse(hasattr(handle, method))
        h.job(); w = h.wait(); r = h.response(w)
        with self.assertRaises(UntrustedInput): h.intake.record_answer(r, 'origin=human', h.rev())
        with self.assertRaises(UntrustedInput):
            h.intake.record_answer(replace(r, detail='forged'), r.authenticated_source_ref, h.rev())
        self.assertEqual(h.ctrl.history('r','approvals'), ())

    def test_containment_and_exact_job_binding(self):
        h = self.h; h.contained = None
        with self.assertRaises(InvalidTransition): h.job()
        h.contained = True
        job = c.Job('r','j','create output',('inspect output',))
        d = h.judgment.judge(h.request(proposed=job))
        with self.assertRaises(InvalidTransition): h.ctrl.add_job(replace(job,instructions='expanded'),d.decision_id,h.rev())
        h.policy = 'changed'
        with self.assertRaises(Conflict): h.ctrl.add_job(job,d.decision_id,h.rev())
        self.assertEqual(h.ctrl.get_run('r').job_ids, ())

    def test_attempt_replay_and_failure_history_survive_restart(self):
        h = self.h; h.job(); a = h.begin()
        request = c.ExecuteRequest(a.ref,h.ctrl.get_job('r','j'),h.conditions)
        self.assertEqual(h.ctrl.begin_attempt(request,'replay',-1),a)
        with self.assertRaises(Conflict):
            h.ctrl.begin_attempt(replace(request,conditions=replace(h.conditions,model='other')),'x',-1)
        ended = h.finish(a.ref)
        ended = h.ctrl.record_stop(c.StopReply(a.ref, c.StopStatus.CONFIRMED,
                                             'fixture', 'ev:a'), ended.revision)
        h.begin('b')
        h.store.close(); h.store = h.connect(); h.refresh()
        self.assertEqual(h.ctrl.get_attempt(a.ref),ended)
        self.assertEqual(h.ctrl.get_run('r').original_intent,'create tested fixture output')
        with self.assertRaises(InvalidTransition): h.begin('concurrent')

    def test_default_attempt_limits(self):
        h = self.h; h.job()
        for name in ('a','b'):
            a = h.finish(h.begin(name).ref)
            h.ctrl.record_stop(c.StopReply(a.ref, c.StopStatus.CONFIRMED,
                                           'fixture', 'ev:' + name), a.revision)
        with self.assertRaises(LimitExceeded): h.begin('pair-overflow')
        for i in range(3):
            a = h.finish(h.begin('reroute'+str(i),conditions=replace(h.conditions,model=str(i))).ref)
            h.ctrl.record_stop(c.StopReply(a.ref, c.StopStatus.CONFIRMED,
                                           'fixture', 'ev:' + str(i)), a.revision)
        with self.assertRaises(LimitExceeded): h.begin('job-overflow',conditions=replace(h.conditions,model='new'))
        self.assertEqual(len(h.ctrl.history('r','events')),5)

    def test_job_limit_under_competing_connections(self):
        h = self.h
        for i in range(19): h.job('job'+str(i))
        rev = h.rev()
        jobs = [c.Job('r',name,'create output',('inspect',)) for name in ('left','right')]
        ds = [h.judgment.judge(h.request(job=j.job_id,proposed=j)) for j in jobs]
        second = h.connect()
        try:
            def add(args):
                ctrl,j,d = args
                try: return ctrl.add_job(j,d.decision_id,rev)
                except Conflict as exc: return exc
            with ThreadPoolExecutor(2) as pool:
                outcomes = list(pool.map(add,[(h.ctrl,jobs[0],ds[0]),(second.controller(),jobs[1],ds[1])]))
            self.assertEqual(sum(isinstance(v,Conflict) for v in outcomes),1)
            self.assertEqual(len(h.ctrl.get_run('r').job_ids),20)
            loser = jobs[next(i for i,v in enumerate(outcomes) if isinstance(v,Conflict))]
            d = h.judgment.judge(h.request(job=loser.job_id,proposed=loser))
            with self.assertRaises(LimitExceeded): h.ctrl.add_job(loser,d.decision_id,h.rev())
        finally: second.close()

    def test_limit_adjustments_require_grant(self):
        h = self.h
        with self.assertRaises(UntrustedInput): h.ctrl.set_limits('r',Limits(21,ceilings=(21,5,2)),h.rev())
        h.create('granted',Limits(20,ceilings=(22,6,3)))
        changed = h.ctrl.set_limits('granted',Limits(22,6,3,ceilings=(22,6,3)),h.rev('granted'))
        self.assertEqual(changed.limits.jobs,22)
        self.assertEqual(len(h.ctrl.history('granted','limit_history')),1)
        with self.assertRaises(ValueError): Limits(jobs=True)

    def test_status_result_ac_and_event_idempotence(self):
        h = self.h; h.job(); a = h.begin()
        event = c.StatusEvent(a.ref,'status',c.State.COMPLETED)
        receipt = h.event(event)
        self.assertIsNone(receipt.result); self.assertEqual(receipt.state,c.State.PENDING)
        with self.assertRaises(InvalidTransition): h.ctrl.record_ac(c.ACRecord(a.ref,'pass',('e',)),receipt.revision)
        a = h.finish(a.ref,c.State.COMPLETED)
        a = h.ctrl.record_ac(c.ACRecord(a.ref,'fail',('independent:inspection',)),a.revision)
        self.assertEqual(a.result.status,c.State.COMPLETED); self.assertEqual(a.ac.verdict,'fail')
        self.assertEqual(h.ctrl.record_event(event,-1),receipt)
        with self.assertRaises(Conflict): h.ctrl.record_event(replace(event,state=c.State.RUNNING),-1)
        with self.assertRaises(InvalidTransition): h.event(c.StatusEvent(a.ref,'resurrect',c.State.RUNNING))
        with self.assertRaises(IntegrityViolation): h.event(c.ResultEvent(a.ref,'rewrite',c.Result(a.ref,c.State.FAILED,'failed')))

    def test_stop_receipt_never_invents_result(self):
        h = self.h; h.job(); a = h.begin()
        for status in (c.StopStatus.REQUESTED,c.StopStatus.UNCONFIRMED,c.StopStatus.CONFIRMED):
            a = h.ctrl.record_stop(c.StopReply(a.ref,status,'fixture','cessation' if status==c.StopStatus.CONFIRMED else None),a.revision)
            self.assertIsNone(a.result); self.assertEqual(a.stop_reply.status,status)
        self.assertEqual(len(h.ctrl.history('r','stop_history')),3)
        with self.assertRaises(InvalidTransition): h.begin('new')

    def test_resume_binding_secret_separation_restart_and_terminal(self):
        h = self.h; h.job(); a = h.begin(); bridge = h.store.bridge('adapter')
        state = c.ResumeState('adapter',a.ref,b'one-secret')
        handle = bridge.put_resume(state,a.revision)
        self.assertEqual(bridge.put_resume(state,-1),handle)
        next_handle = bridge.put_resume(replace(state,opaque=b'next-secret'),h.ctrl.get_attempt(a.ref).revision)
        with self.assertRaises(Conflict): bridge.get_resume(a.ref,'adapter',handle)
        with self.assertRaises(UntrustedInput): h.store.bridge('worker').get_resume(a.ref,'adapter',next_handle)
        h.store.close(); h.store=h.connect(); h.refresh(); bridge=h.store.bridge('adapter')
        self.assertEqual(bridge.get_resume(a.ref,'adapter',next_handle).opaque,b'next-secret')
        with sqlite3.connect(h.path) as db: self.assertNotIn('next-secret',db.execute('SELECT body FROM runs').fetchone()[0])
        h.finish(a.ref)
        with self.assertRaises(InvalidTransition): bridge.get_resume(a.ref,'adapter',next_handle)

    def test_answer_replay_conflict_and_atomic_approval(self):
        h = self.h; h.job(); w=h.wait(); r=h.response(w); revision=h.rev()
        receipt=h.intake.record_answer(r,r.authenticated_source_ref,revision)
        self.assertEqual(h.intake.record_answer(r,r.authenticated_source_ref,-1),receipt)
        self.assertEqual(len(h.ctrl.history('r','answers')),1)
        self.assertEqual(len(h.ctrl.history('r','approvals')),1)
        changed=replace(r,answer=c.HumanAnswer.REJECT); h.authenticate(changed.authenticated_source_ref,changed)
        with self.assertRaises(Conflict): h.intake.record_answer(changed,changed.authenticated_source_ref,h.rev())

    def test_instruct_and_stop_do_not_create_approval(self):
        h=self.h; h.job(); h.answer(h.wait('q1'),c.HumanAnswer.INSTRUCT,detail='only reviewed content')
        self.assertEqual(len(h.ctrl.get_run('r').human_instructions),1)
        h.answer(h.wait('q2'),c.HumanAnswer.STOP_RUN,name='stop')
        self.assertTrue(h.ctrl.get_run('r').stop_requested)
        self.assertEqual(h.ctrl.history('r','approvals'),())
        with self.assertRaisesRegex(Conflict, 'stop_requested'): h.begin()
        with self.assertRaisesRegex(Conflict, 'stop_requested'): h.job('new')

    def test_after_deadline_timeout_late_answer_and_native_liveness(self):
        h=self.h; h.job(); a=h.begin(); w=h.wait(attempt='a'); h.now='2026-09-29T00:00:00.000001Z'
        self.assertEqual(h.answer(w).disposition,'late')
        self.assertEqual(h.ctrl.history('r','approvals'),())
        # A timeout is a wait fact only: no Result, ended_at or StopReply is
        # fabricated and the still-live Attempt accepts a real resume state.
        attempt = h.ctrl.get_attempt(a.ref)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.ended_at)
        self.assertIsNone(attempt.stop_reply)
        self.assertEqual(h.store.scheduler().expire_wait(w.ref,w.request_id,-1).deadline,w.deadline)
        self.assertTrue(h.store.bridge('adapter').put_resume(
            c.ResumeState('adapter',a.ref,b'secret'),attempt.revision))
        h.finish(a.ref,c.State.COMPLETED)  # the real Result arrives late
        self.assertEqual(h.ctrl.get_attempt(a.ref).result.status,c.State.COMPLETED)
        self.assertIsNone(h.ctrl.get_attempt(a.ref).result.reason)
        self.assertEqual(h.ctrl.history('r','events')[-1].result.status,c.State.COMPLETED)

    def test_preexecution_timeout_has_no_attempt(self):
        h=self.h; h.job(); w=h.wait()
        with self.assertRaises(InvalidTransition): h.store.scheduler().expire_wait(w.ref,w.request_id,h.rev())
        h.now=w.deadline; h.store.scheduler().expire_wait(w.ref,w.request_id,h.rev())
        with self.assertRaises(NotFound): h.ctrl.get_attempt(c.AttemptRef('r','j','a'))
        self.assertEqual(len(h.ctrl.history('r','timeouts')),1)

    def test_answer_timeout_race(self):
        h=self.h; h.job(); w=h.wait(); h.now=w.deadline; r=h.response(w); revision=h.rev(); second=h.connect()
        try:
            def answer():
                try: return second.intake().record_answer(r,r.authenticated_source_ref,revision)
                except Conflict: return None
            with ThreadPoolExecutor(2) as pool:
                future=pool.submit(answer)
                try: h.store.scheduler().expire_wait(w.ref,w.request_id,revision)
                except (Conflict, InvalidTransition): pass
                result=future.result()
            if result is None: result=second.intake().record_answer(r,r.authenticated_source_ref,h.rev())
            self.assertIn(result.disposition, ('applied', 'late'))
            self.assertEqual(len(h.ctrl.history('r','timeouts')), result.disposition == 'late')
            self.assertEqual(len(h.ctrl.history('r','answers')),1)
            self.assertEqual(len(h.ctrl.history('r','approvals')), result.disposition == 'applied')
        finally: second.close()

    def test_storage_fault_rolls_back_entire_answer(self):
        h=self.h; h.job(); w=h.wait(); r=h.response(w); revision=h.rev()
        h.store._db.execute("CREATE TRIGGER fail_write BEFORE UPDATE ON runs BEGIN SELECT RAISE(ABORT,'fixture fault'); END")
        with self.assertRaises(StoreUnavailable): h.intake.record_answer(r,r.authenticated_source_ref,revision)
        h.store._db.execute('DROP TRIGGER fail_write')
        self.assertEqual(h.rev(),revision)
        self.assertEqual(h.ctrl.history('r','answers'),()); self.assertEqual(h.ctrl.history('r','approvals'),())
        self.assertEqual(h.answer(w).disposition,'applied')

    def test_process_crash_before_commit_preserves_unanswered_wait(self):
        h=self.h; h.job(); w=h.wait(); revision=h.rev()
        code='''
import os,sys
from co_v4.state import ControlStore,IngressReceipt,body_digest
from co_v4.contracts import HumanResponse,HumanAnswer,QuestionRef
s=ControlStore(sys.argv[1],verifier=lambda _:receipt,evidence=lambda *_:None,clock=lambda:'2026-09-28T00:00:00Z')
w=s.controller().get_wait(QuestionRef('r','j'),'q')
r=HumanResponse('crash-answer',w.ref,w.request_id,w.action,HumanAnswer.APPROVE,'crash-source')
receipt=IngressReceipt('human','crash-source',body_digest(r),'2026-09-28T00:00:00Z')
s._db.create_function('crash',0,lambda:os._exit(77))
s._db.execute('CREATE TEMP TRIGGER crash_update BEFORE UPDATE ON runs BEGIN SELECT crash(); END')
s.intake().record_answer(r,'crash-source',int(sys.argv[2]))
'''
        result=subprocess.run([sys.executable,'-c',code,str(h.path),str(revision)],capture_output=True,text=True)
        self.assertEqual(result.returncode,77,result.stderr)
        h.store.close(); h.store=h.connect(); h.refresh()
        self.assertEqual(h.rev(),revision)
        self.assertEqual(h.ctrl.history('r','answers'),()); self.assertEqual(h.ctrl.history('r','approvals'),())
        self.assertEqual(h.answer(w).disposition,'applied')

    def test_store_and_verifier_fail_closed(self):
        h=self.h; h.job(); w=h.wait(); r=h.response(w); h.receipts.clear()
        with self.assertRaises(UntrustedInput): h.intake.record_answer(r,r.authenticated_source_ref,h.rev())
        h.store.close()
        with self.assertRaises(StoreUnavailable): h.judgment.judge(h.request())

    def test_competing_attempt_reservations_do_not_exceed_pair_limit(self):
        h = self.h
        h.job()
        first = h.finish(h.begin('first').ref)
        h.ctrl.record_stop(c.StopReply(first.ref, c.StopStatus.CONFIRMED,
                                       'fixture', 'ev:first'), first.revision)
        revision = h.rev()
        requests = [c.ExecuteRequest(c.AttemptRef('r', 'j', name), h.ctrl.get_job('r', 'j'), h.conditions)
                    for name in ('left', 'right')]
        decisions = [h.judgment.judge(h.request(attempt=r.ref.attempt_id)) for r in requests]
        second = h.connect()
        try:
            def reserve(args):
                controller, request, decision = args
                try:
                    return controller.begin_attempt(request, decision.decision_id, revision)
                except Conflict as exc:
                    return exc
            with ThreadPoolExecutor(2) as pool:
                outcomes = list(pool.map(reserve, [(h.ctrl, requests[0], decisions[0]),
                    (second.controller(), requests[1], decisions[1])]))
            winner = next(a for a in outcomes if not isinstance(a, Conflict))
            self.assertEqual(sum(isinstance(a, Conflict) for a in outcomes), 1)
            winner = h.finish(winner.ref)
            h.ctrl.record_stop(c.StopReply(winner.ref, c.StopStatus.CONFIRMED,
                                           'fixture', 'ev:winner'), winner.revision)
            with self.assertRaises(LimitExceeded):
                h.begin('third')
        finally:
            second.close()

    def test_before_deadline_answer_wins_and_scheduler_cannot_rewrite(self):
        h = self.h
        h.job()
        wait = h.wait()
        receipt = h.answer(wait)
        h.now = wait.deadline
        with self.assertRaises(InvalidTransition):
            h.store.scheduler().expire_wait(wait.ref, wait.request_id, h.rev())
        self.assertEqual(receipt.disposition, 'applied')
        self.assertEqual(h.ctrl.history('r', 'timeouts'), ())
        self.assertEqual(h.ctrl.get_run('r').state, c.State.PENDING)

    def test_mutable_shared_records_cannot_escape_as_snapshots(self):
        h = self.h
        h.job()
        attempt = h.begin()
        result = c.Result(attempt.ref, c.State.COMPLETED, artifact_refs=['mutable'])
        with self.assertRaises(ValueError):
            h.event(c.ResultEvent(attempt.ref, 'mutable', result))
        self.assertIsNone(h.ctrl.get_attempt(attempt.ref).result)
        with self.assertRaises(ValueError):
            h.request(conditions=replace(h.conditions, control_evidence_refs=['mutable']))

    def test_terminal_result_closes_wait_and_keeps_late_answer(self):
        h = self.h
        h.job()
        attempt = h.begin()
        wait = h.wait(attempt='a')
        h.finish(attempt.ref)
        self.assertEqual(h.answer(wait).disposition, 'late')
        self.assertEqual(h.ctrl.history('r', 'approvals'), ())
        # A Result alone is not settlement: RUNNING until confirmed cessation.
        self.assertEqual(h.ctrl.get_run('r').state, c.State.RUNNING)
        h.ctrl.record_stop(c.StopReply(attempt.ref, c.StopStatus.CONFIRMED,
                                       'fixture', 'ev:a'),
                           h.ctrl.get_attempt(attempt.ref).revision)
        self.assertEqual(h.ctrl.get_run('r').state, c.State.PENDING)

    def test_timeout_fault_rolls_back_timeout_and_result_together(self):
        h = self.h
        h.job()
        attempt = h.begin()
        wait = h.wait(attempt='a')
        revision = h.rev()
        h.now = wait.deadline
        h.store._db.execute("CREATE TRIGGER fail_timeout BEFORE UPDATE ON runs BEGIN SELECT RAISE(ABORT,'fault'); END")
        with self.assertRaises(StoreUnavailable):
            h.store.scheduler().expire_wait(wait.ref, wait.request_id, revision)
        h.store._db.execute('DROP TRIGGER fail_timeout')
        self.assertEqual(h.ctrl.history('r', 'timeouts'), ())
        self.assertIsNone(h.ctrl.get_attempt(attempt.ref).result)
        h.store.scheduler().expire_wait(wait.ref, wait.request_id, revision)
        # Atomic commit: the timeout is only a wait fact, never a Result.
        self.assertEqual(len(h.ctrl.history('r', 'timeouts')), 1)
        self.assertIsNone(h.ctrl.get_attempt(attempt.ref).result)
        self.assertIsNone(h.ctrl.get_attempt(attempt.ref).stop_reply)

    def test_unknown_approval_and_conflicting_request_id_fail(self):
        h = self.h
        h.job()
        unknown = c.Action('filesystem.write', c.Scope((('path', None),)))
        wait = h.wait(action=unknown)
        with self.assertRaises(UntrustedInput):
            h.answer(wait)
        with self.assertRaises(Conflict):
            h.ctrl.open_wait(replace(wait, action=h.action), 'write-output', h.rev())
        self.assertEqual(h.ctrl.history('r', 'answers'), ())

    def test_late_stop_requests_run_stop_and_preserves_timeout(self):
        h = self.h
        h.job(); attempt = h.begin(); wait = h.wait(attempt='a')
        other = h.wait('other')
        h.now = '2026-09-29T00:00:00.000001Z'
        response = h.response(wait, c.HumanAnswer.STOP_RUN)
        receipt = h.intake.record_answer(response, response.authenticated_source_ref, h.rev())
        self.assertEqual(receipt.disposition, 'late')
        self.assertIsNone(receipt.approval_id)
        self.assertTrue(h.ctrl.get_run('r').stop_requested)
        self.assertEqual(h.ctrl.wait_details(other.ref, other.request_id).disposition, 'stopped')
        # Timeout preserved as a wait fact; the Attempt carries no
        # fabricated Result or StopReply.
        live = h.ctrl.get_attempt(attempt.ref)
        self.assertIsNone(live.result)
        self.assertIsNone(live.stop_reply)
        self.assertEqual(h.intake.record_answer(response, response.authenticated_source_ref, -1), receipt)
        self.assertEqual(len(h.ctrl.history('r', 'timeouts')), 1)
        self.assertEqual(len(h.ctrl.history('r', 'answers')), 1)
        self.assertEqual(h.ctrl.history('r', 'approvals'), ())

    def test_stop_after_scheduler_timeout_preserves_terminal_attempt(self):
        h = self.h
        h.job(); attempt = h.begin(); wait = h.wait(attempt='a')
        h.now = wait.deadline
        h.store.scheduler().expire_wait(wait.ref, wait.request_id, h.rev())
        terminal = h.ctrl.get_attempt(attempt.ref)
        self.assertEqual(h.answer(wait, c.HumanAnswer.STOP_RUN).disposition, 'late')
        self.assertTrue(h.ctrl.get_run('r').stop_requested)
        self.assertEqual(h.ctrl.get_attempt(attempt.ref), terminal)
        self.assertEqual(len(h.ctrl.history('r', 'timeouts')), 1)
        self.assertEqual(h.ctrl.history('r', 'approvals'), ())

    def test_response_after_stop_before_deadline_has_no_timeout_or_result(self):
        h = self.h
        h.job(); attempt = h.begin()
        active = h.wait(attempt='a'); stop = h.wait('stop')
        h.answer(stop, c.HumanAnswer.STOP_RUN, name='stop-answer')
        before = h.ctrl.get_attempt(attempt.ref)
        self.assertEqual(h.answer(active).disposition, 'late')
        self.assertEqual(h.ctrl.get_attempt(attempt.ref), before)
        self.assertIsNone(before.result)
        self.assertIsNone(before.stop_reply)
        self.assertEqual(h.ctrl.history('r', 'timeouts'), ())
        self.assertEqual(h.ctrl.history('r', 'approvals'), ())

    def test_terminal_run_response_does_not_invent_timeout(self):
        h = self.h
        h.job(); wait = h.wait()
        terminal = h.ctrl.finalize_run('r', c.State.FAILED, 'fixture_cancelled', h.rev())
        response = h.response(wait)
        # A post-terminal answer rejects at the boundary; nothing is recorded.
        with self.assertRaises(InvalidTransition):
            h.intake.record_answer(response, response.authenticated_source_ref, h.rev())
        self.assertEqual(h.ctrl.history('r', 'answers'), ())
        self.assertEqual(h.ctrl.history('r', 'timeouts'), ())
        self.assertEqual(h.ctrl.history('r', 'approvals'), ())
        self.assertEqual(h.ctrl.wait_details(wait.ref, wait.request_id).disposition, 'terminal')
        self.assertEqual(h.ctrl.get_run('r').state, terminal.state)
        self.assertEqual(h.ctrl.get_run('r').final_reason, terminal.final_reason)

    def test_stop_after_terminal_attempt_preserves_result_without_timeout(self):
        h = self.h
        h.job(); attempt = h.begin(); wait = h.wait(attempt='a')
        terminal = h.finish(attempt.ref)
        self.assertEqual(h.answer(wait, c.HumanAnswer.STOP_RUN).disposition, 'late')
        self.assertTrue(h.ctrl.get_run('r').stop_requested)
        self.assertEqual(h.ctrl.get_attempt(attempt.ref), terminal)
        self.assertEqual(h.ctrl.history('r', 'timeouts'), ())
        self.assertEqual(h.ctrl.history('r', 'approvals'), ())

    def test_limits_replay_and_stop_during_another_question(self):
        h = self.h
        revision = h.rev()
        limits = Limits(jobs=19)
        receipt = h.ctrl.set_limits('r', limits, revision)
        self.assertEqual(h.ctrl.set_limits('r', limits, revision), receipt)
        h.job()
        first = h.wait('first')
        second = h.wait('second')
        h.answer(first, c.HumanAnswer.STOP_RUN)
        self.assertEqual(h.answer(second, name='other').disposition, 'late')
        self.assertEqual(h.ctrl.history('r', 'approvals'), ())


if __name__=='__main__': unittest.main()
