"""Receipt/expiry ordering on real SQLite, with synthetic trusted ingress."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import tempfile
from threading import Event
import unittest

from co_v4 import contracts as c
from co_v4.state import Conflict, ControlStore, StoreUnavailable, UntrustedInput
from test_state import Harness


BEFORE = '2026-09-28T23:59:59.999999Z'
AFTER = '2026-09-29T00:00:00.000001Z'


class HumanDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.h = Harness(self.tmp.name)
        self.h.job()

    def tearDown(self):
        self.h.store.close()
        self.tmp.cleanup()

    def receive(self, response, intake=None):
        return (intake or self.h.intake).record_receipt(response, response.authenticated_source_ref)

    def apply(self, response, revision=None, intake=None):
        return (intake or self.h.intake).record_answer(response, response.authenticated_source_ref,
            self.h.rev() if revision is None else revision)

    def test_just_before_receipt_after_deadline_apply_for_all_four_answers(self):
        for answer in c.HumanAnswer:
            with self.subTest(answer=answer), tempfile.TemporaryDirectory() as directory:
                h = Harness(directory)
                try:
                    h.job(); attempt = h.begin(); wait = h.wait(attempt='a')
                    h.now = BEFORE
                    response = h.response(wait, answer, detail='use reviewed alternative')
                    with self.assertRaises(Conflict):
                        h.intake.record_answer(response, response.authenticated_source_ref, -1)
                    self.assertEqual(h.ctrl.history('r', 'answers'), ())
                    h.now = AFTER
                    receipt = h.intake.record_answer(response, response.authenticated_source_ref, h.rev())
                    self.assertEqual(receipt.disposition, 'applied')
                    self.assertEqual(h.intake.record_answer(response, response.authenticated_source_ref, -1), receipt)
                    self.assertEqual(h.ctrl.history('r', 'timeouts'), ())
                    self.assertEqual(len(h.ctrl.history('r', 'answers')), 1)
                    self.assertEqual(len(h.ctrl.history('r', 'approvals')), answer == c.HumanAnswer.APPROVE)
                    self.assertEqual(len(h.ctrl.history('r', 'rejections')), answer == c.HumanAnswer.REJECT)
                    self.assertEqual(bool(h.ctrl.get_run('r').human_instructions), answer == c.HumanAnswer.INSTRUCT)
                    self.assertEqual(h.ctrl.get_run('r').stop_requested, answer == c.HumanAnswer.STOP_RUN)
                    self.assertIsNone(h.ctrl.get_attempt(attempt.ref).result)
                    self.assertIsNone(h.ctrl.get_attempt(attempt.ref).stop_reply)
                finally:
                    h.store.close()

    def test_exact_deadline_receipt_is_eligible_if_expiry_has_not_won(self):
        h = self.h; wait = h.wait(); h.now = wait.deadline
        response = h.response(wait)
        self.assertEqual(self.receive(response).received_at, wait.deadline)
        h.now = AFTER
        self.assertEqual(self.apply(response).disposition, 'applied')
        self.assertEqual(h.ctrl.history('r', 'timeouts'), ())

    def test_expiry_wins_at_equal_deadline_and_cannot_be_reversed(self):
        h = self.h; attempt = h.begin(); wait = h.wait(attempt='a')
        h.now = wait.deadline
        second = h.connect()
        try:
            second.scheduler().expire_wait(wait.ref, wait.request_id, h.rev())
            terminal = h.ctrl.get_attempt(attempt.ref)
            response = h.response(wait)
            self.assertEqual(self.apply(response).disposition, 'late')
            self.assertEqual(h.ctrl.get_attempt(attempt.ref), terminal)
            self.assertEqual(h.ctrl.history('r', 'approvals'), ())
        finally:
            second.close()

    def test_receipt_wins_and_scheduler_applies_it_after_restart_without_verifier(self):
        h = self.h; attempt = h.begin(); wait = h.wait(attempt='a'); h.now = BEFORE
        response = h.response(wait)
        first = self.receive(response)
        h.store.close(); h.store = h.connect(); h.refresh()
        h.now = AFTER
        second = ControlStore(h.path, verifier=lambda _: self.fail('no source discovery at expiry'),
                              evidence=h.evidence, clock=lambda: h.now)
        try:
            self.assertIsNone(second.scheduler().expire_wait(wait.ref, wait.request_id, h.rev()))
            self.assertEqual(self.receive(response), first)
            receipt = self.apply(response, -1)
            self.assertEqual(receipt.disposition, 'applied')
            self.assertEqual(self.apply(response, -1), receipt)
            self.assertEqual(len(h.ctrl.history('r', 'approvals')), 1)
            self.assertIsNone(h.ctrl.get_attempt(attempt.ref).result)
            self.assertEqual(h.ctrl.history('r', 'answers')[0][1].received_at, BEFORE)
        finally:
            second.close()

    def test_old_source_receipt_cannot_backdate_first_control_receipt(self):
        h = self.h; attempt = h.begin(); wait = h.wait(attempt='a'); h.now = BEFORE
        before = h.ctrl.get_attempt(attempt.ref)
        response = h.response(wait)  # Authenticated transport evidence only.
        h.now = AFTER
        self.assertEqual(self.receive(response).received_at, AFTER)
        self.assertEqual(self.apply(response).disposition, 'late')
        # The late receipt grants nothing and the timeout is a wait fact
        # only: the committed Attempt is identical to its post-wait snapshot
        # — no fabricated Result, StopReply or ended_at.
        self.assertEqual(h.ctrl.get_attempt(attempt.ref), before)
        self.assertIsNone(before.result)
        self.assertEqual(h.ctrl.history('r', 'approvals'), ())

    def test_clock_is_sampled_after_authentication_not_before(self):
        h = self.h; wait = h.wait(); h.now = BEFORE; response = h.response(wait)
        def slow_verifier(source):
            h.now = AFTER
            return h.receipts[source]
        second = ControlStore(h.path, verifier=slow_verifier, evidence=h.evidence, clock=lambda: h.now)
        try:
            self.assertEqual(self.receive(response, second.intake()).received_at, AFTER)
            self.assertEqual(self.apply(response).disposition, 'late')
        finally:
            second.close()

    def test_lock_delay_cannot_backdate_receipt(self):
        h = self.h; wait = h.wait(); h.now = BEFORE; response = h.response(wait)
        second = h.connect(); started = Event()
        def receive():
            started.set()
            return self.receive(response, second.intake())
        try:
            with ThreadPoolExecutor(1) as pool:
                with h.store._tx('r'):
                    future = pool.submit(receive)
                    self.assertTrue(started.wait(2))
                    h.now = AFTER
                self.assertEqual(future.result(timeout=5).received_at, AFTER)
            self.assertEqual(self.apply(response).disposition, 'late')
        finally:
            second.close()

    def test_invalid_receipts_do_not_reserve_or_delay_expiry(self):
        h = self.h; wait = h.wait()
        for response in (replace(h.response(wait), action=c.Action('other', h.action.scope)),
                         h.response(wait, c.HumanAnswer.INSTRUCT)):
            h.authenticate(response.authenticated_source_ref, response)
            with self.assertRaises((Conflict, ValueError)):
                self.receive(response)
        response = h.response(wait)
        h.receipts.clear()
        with self.assertRaises(UntrustedInput): self.receive(response)
        self.assertEqual(h.ctrl.history('r', 'human_receipts'), ())
        h.now = wait.deadline
        self.assertIsNotNone(h.store.scheduler().expire_wait(wait.ref, wait.request_id, h.rev()))
        self.assertEqual(h.ctrl.history('r', 'approvals'), ())

    def test_first_receipt_cannot_be_replaced_by_another_answer(self):
        h = self.h; wait = h.wait(); first = h.response(wait); self.receive(first)
        other = h.response(wait, c.HumanAnswer.REJECT, name='other')
        with self.assertRaises(Conflict): self.receive(other)
        altered = replace(first, detail='changed')
        h.authenticate(altered.authenticated_source_ref, altered)
        with self.assertRaises(Conflict): self.receive(altered)
        h.authenticate(first.authenticated_source_ref, first)
        h.now = AFTER
        self.assertEqual(self.apply(first).disposition, 'applied')
        self.assertEqual(h.ctrl.history('r', 'rejections'), ())

    def test_timely_receipt_never_revives_attempt_ended_before_application(self):
        h = self.h; attempt = h.begin(); wait = h.wait(attempt='a')
        response = h.response(wait); self.receive(response)
        terminal = h.finish(attempt.ref)
        h.now = AFTER
        self.assertEqual(self.apply(response).disposition, 'late')
        self.assertEqual(h.ctrl.get_attempt(attempt.ref), terminal)
        self.assertEqual(h.ctrl.history('r', 'timeouts'), ())
        self.assertEqual(h.ctrl.history('r', 'approvals'), ())

    def test_receipt_commit_failure_cannot_reserve_deadline(self):
        h = self.h; wait = h.wait(); response = h.response(wait)
        h.store._db.execute("CREATE TRIGGER fail_receipt BEFORE UPDATE ON runs BEGIN SELECT RAISE(ABORT,'fault'); END")
        with self.assertRaises(StoreUnavailable): self.receive(response)
        h.store._db.execute('DROP TRIGGER fail_receipt')
        self.assertEqual(h.ctrl.history('r', 'human_receipts'), ())
        h.now = AFTER
        self.assertEqual(self.receive(response).received_at, AFTER)
        self.assertEqual(self.apply(response).disposition, 'late')

    def test_application_commit_failure_keeps_receipt_for_scheduler_recovery(self):
        h = self.h; wait = h.wait(); response = h.response(wait); self.receive(response)
        h.store._db.execute("CREATE TRIGGER fail_apply BEFORE UPDATE ON runs BEGIN SELECT RAISE(ABORT,'fault'); END")
        with self.assertRaises(StoreUnavailable): self.apply(response)
        h.store._db.execute('DROP TRIGGER fail_apply')
        self.assertEqual(h.ctrl.history('r', 'answers'), ())
        self.assertEqual(len(h.ctrl.history('r', 'human_receipts')), 1)
        h.now = AFTER
        self.assertIsNone(h.store.scheduler().expire_wait(wait.ref, wait.request_id, h.rev()))
        self.assertEqual(self.apply(response, -1).disposition, 'applied')
        self.assertEqual(len(h.ctrl.history('r', 'approvals')), 1)


if __name__ == '__main__': unittest.main()
