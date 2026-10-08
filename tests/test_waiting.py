"""Waiting service against trusted state APIs; no invented Attempts."""
from pathlib import Path
import tempfile
import unittest
from co_v4 import contracts as c
from co_v4.state import Conflict, InvalidTransition
from co_v4.trace import PublicationPolicy, Trace
from co_v4.waiting import WaitingService, wait_link
from test_state import Harness


class WaitingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.h = Harness(self.tmp.name)
        self.h.job(); self.trace = Trace(Path(self.tmp.name)/'trace.sqlite', PublicationPolicy(lambda _: True))
        self.service = WaitingService(self.h.ctrl,self.h.store.scheduler(),clock=lambda:self.h.now,trace=self.trace)

    def tearDown(self):
        self.h.store.close(); self.trace.close(); self.tmp.cleanup()

    def open(self, deadline=None, name='q'):
        self.h.confirm=True; request=self.h.request(); d=self.h.judgment.judge(request)
        return self.service.open(request.ref,name,request.action,d.decision,d.reason,request.method,
                                 expected_revision=self.h.rev(),deadline=deadline,judgment_ref=d.decision_id),d

    def test_default_deadline_pre_execution_and_replay(self):
        w,d=self.open()
        self.assertEqual(w.deadline,'2026-09-29T00:00:00Z'); self.assertIsNone(w.ref.attempt_id)
        self.assertEqual(self.h.ctrl.get_run('r').state,c.State.WAITING_HUMAN)
        self.h.now='2026-09-28T02:00:00Z'
        self.assertEqual(self.service.open(w.ref,w.request_id,w.action,w.decision,w.reason,'write-output',
            expected_revision=-1,judgment_ref=d.decision_id),w)
        self.assertEqual(len(self.trace.records()),1)
        self.assertEqual(self.trace.records()[0]['at'],'2026-09-28T00:00:00Z')
        self.assertEqual(self.h.ctrl.history('r','events'),())

    def test_custom_deadline_has_actual_observation_time(self):
        w,_=self.open('2026-09-28T02:00:00Z')
        self.assertEqual(w.deadline,'2026-09-28T02:00:00Z')
        self.assertEqual(self.trace.records()[0]['at'],self.h.now)
        with self.assertRaises(ValueError): self.open('2026-09-28T03:00:00')
        with self.assertRaises(Conflict): self.open('2026-09-28T03:00:00Z')

    def test_timeout_exact_deadline_no_attempt_or_rejection(self):
        w,_=self.open()
        with self.assertRaises(InvalidTransition): self.service.expire(w.ref,w.request_id,expected_revision=self.h.rev())
        self.h.now=w.deadline
        result=self.service.expire(w.ref,w.request_id,expected_revision=self.h.rev())
        self.assertEqual(self.service.expire(w.ref,w.request_id,expected_revision=-1),result)
        self.assertEqual(self.h.ctrl.history('r','events'),())
        self.assertEqual(self.h.ctrl.history('r','rejections'),())
        self.assertEqual(self.h.ctrl.history('r','approvals'),())
        self.assertEqual(self.h.ctrl.get_run('r').state,c.State.PENDING)
        self.assertEqual(len(self.trace.records()),2)

    def test_answer_timeout_race_is_serialized_by_state(self):
        w,_=self.open(); self.h.answer(w)
        self.h.now=w.deadline
        with self.assertRaises((Conflict,InvalidTransition)):
            self.service.expire(w.ref,w.request_id,expected_revision=self.h.rev())
        self.assertEqual(self.h.ctrl.history('r','timeouts'),())

    def test_trace_ids_include_run_and_question_identity(self):
        self.assertNotEqual(wait_link(c.QuestionRef('r','j'),'q'),wait_link(c.QuestionRef('r2','j'),'q'))
        self.assertNotEqual(wait_link(c.QuestionRef('r','j','a'),'q'),wait_link(c.QuestionRef('r','j','a'),'q2'))

    def test_due_receipt_is_applied_without_timeout_trace(self):
        w, _ = self.open()
        response = self.h.response(w)
        self.h.intake.record_receipt(response, response.authenticated_source_ref)
        self.h.now = w.deadline
        self.assertIsNone(self.service.expire(w.ref, w.request_id, expected_revision=self.h.rev()))
        self.assertEqual(len(self.h.ctrl.history('r', 'approvals')), 1)
        self.assertEqual([r['kind'] for r in self.trace.records()], ['waiting'])


if __name__ == '__main__': unittest.main()
