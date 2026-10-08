"""Timeout truth: expiry is a wait fact, never an Attempt fact.

Drives the real v4 control-state/Scheduler paths through the shared
Harness; no adapters, transports, providers or Native work are involved.
Fixtures only — nothing here is a claim that these tests were executed.
"""
import tempfile
import unittest
from pathlib import Path

from co_v4 import contracts as c
from co_v4.state import (Conflict, IntegrityViolation, InvalidTransition,
                         NotFound)
from test_state import Harness


PAST = '2026-09-29T00:00:01Z'  # past the Harness wait deadline


class TimeoutTruthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve() / 'run'
        root.mkdir(mode=0o700)
        self.h = Harness(root)
        self.addCleanup(self.h.store.close)

    def attempt(self):
        self.h.job()
        return self.h.begin('a')

    def expire(self, wait):
        self.h.now = PAST
        return self.h.store.scheduler().expire_wait(
            wait.ref, wait.request_id, self.h.rev())

    def test_timeout_writes_wait_fact_only_and_run_stays_held(self):
        attempt = self.attempt()
        w = self.h.wait('q', 'a')
        before = self.h.ctrl.get_attempt(attempt.ref)
        timeout = self.expire(w)
        self.assertIsNotNone(timeout)
        self.assertEqual((timeout.ref, timeout.request_id), (w.ref, 'q'))
        details = self.h.ctrl.wait_details(w.ref, 'q')
        self.assertEqual(details.disposition, 'timeout')
        timeouts = self.h.ctrl.history('r', 'timeouts')
        self.assertEqual(len(timeouts), 1)
        # No Attempt fact is fabricated: result, state, ended_at, StopReply,
        # AC, output and even the attempt revision are byte-identical, and
        # no cessation or settlement is inferred.
        after = self.h.ctrl.get_attempt(attempt.ref)
        self.assertEqual(after, before)
        self.assertIsNone(after.result)
        self.assertIsNone(after.ended_at)
        self.assertIsNone(after.stop_reply)
        self.assertIsNone(after.ac)
        self.assertIsNone(after.output)
        self.assertIsNone(self.h.ctrl.attempt_settlement(attempt.ref))
        self.assertFalse([e for e in self.h.ctrl.history('r', 'events')
                          if isinstance(e, c.ResultEvent)])
        # Held, not terminal: the unsettled Attempt keeps the Run RUNNING.
        self.assertEqual(self.h.ctrl.get_run('r').state, c.State.RUNNING)

    def test_sibling_waits_close_stopped_never_terminal(self):
        self.attempt()
        w1 = self.h.wait('q1', 'a')
        self.h.wait('q2', 'a')
        w3 = self.h.wait('p')  # Job-preflight wait, different ref
        self.expire(w1)
        self.assertEqual(
            self.h.ctrl.wait_details(w1.ref, 'q1').disposition, 'timeout')
        self.assertEqual(
            self.h.ctrl.wait_details(w1.ref, 'q2').disposition, 'stopped')
        self.assertIsNone(
            self.h.ctrl.wait_details(w3.ref, 'p').disposition)

    def test_timely_receipt_beats_expiry(self):
        attempt = self.attempt()
        w = self.h.wait('q', 'a')
        response = self.h.response(w)  # authenticated before deadline
        self.h.intake.record_receipt(response,
                                     response.authenticated_source_ref)
        self.h.now = PAST
        self.assertIsNone(self.h.store.scheduler().expire_wait(
            w.ref, w.request_id, self.h.rev()))
        self.assertEqual(
            self.h.ctrl.wait_details(w.ref, 'q').disposition, 'answered')
        self.assertEqual(self.h.ctrl.history('r', 'timeouts'), ())
        self.assertEqual(len(self.h.ctrl.history('r', 'approvals')), 1)
        self.assertIsNone(self.h.ctrl.get_attempt(attempt.ref).result)

    def test_expired_wait_never_applies_late_answer(self):
        attempt = self.attempt()
        w = self.h.wait('q', 'a')
        self.assertIsNotNone(self.expire(w))
        receipt = self.h.answer(w)  # authenticated APPROVE after timeout
        self.assertEqual(receipt.disposition, 'late')
        self.assertEqual(
            self.h.ctrl.wait_details(w.ref, 'q').disposition, 'timeout')
        self.assertEqual(self.h.ctrl.history('r', 'approvals'), ())
        self.assertIsNone(self.h.ctrl.get_attempt(attempt.ref).result)

    def test_committed_real_result_survives_preflight_expiry(self):
        attempt = self.attempt()
        real = self.h.finish(attempt.ref, c.State.COMPLETED)
        w = self.h.wait('p')  # Job-preflight wait is unaffected by it
        self.assertIsNotNone(self.expire(w))
        # The committed real Result is preserved byte-identically; only
        # the wait fact was written.
        self.assertEqual(self.h.ctrl.get_attempt(attempt.ref).result,
                         real.result)
        self.assertEqual(self.h.ctrl.wait_details(w.ref, 'p').disposition,
                         'timeout')

    def test_genuine_result_after_expiry_commits_without_conflict(self):
        attempt = self.attempt()
        w = self.h.wait('q', 'a')
        self.assertIsNotNone(self.expire(w))
        # No fake Result exists to collide: a real later Native Result is
        # ordinary evidence and commits; the closed wait never reopens.
        real = self.h.finish(attempt.ref, c.State.COMPLETED)
        self.assertEqual(self.h.ctrl.get_attempt(attempt.ref).result,
                         real.result)
        self.assertEqual(
            self.h.ctrl.wait_details(w.ref, 'q').disposition, 'timeout')

    def test_stop_requested_before_timeout_expiry_is_noop(self):
        attempt = self.attempt()
        w = self.h.wait('q', 'a')
        self.h.authenticate('stop:1',
                            {'operation': 'stop_run', 'run_id': 'r'})
        run = self.h.intake.record_stop_request('r', 'stop:1')
        self.assertTrue(run.stop_requested)
        # The stop already closed the wait 'stopped'; no timeout fact or
        # Attempt write is produced on top of the first decisive stop.
        with self.assertRaises(InvalidTransition):
            self.expire(w)
        self.assertEqual(
            self.h.ctrl.wait_details(w.ref, 'q').disposition, 'stopped')
        self.assertEqual(self.h.ctrl.history('r', 'timeouts'), ())
        self.assertIsNone(self.h.ctrl.get_attempt(attempt.ref).result)

    def test_expiry_on_terminal_run_writes_nothing(self):
        attempt = self.attempt()
        w = self.h.wait('q', 'a')
        self.h.finish(attempt.ref, c.State.COMPLETED)
        self.h.ctrl.record_stop(
            c.StopReply(attempt.ref, c.StopStatus.CONFIRMED, 'x', 'ev'),
            self.h.ctrl.get_attempt(attempt.ref).revision)
        self.h.ctrl.finalize_run('r', c.State.FAILED, 'fixture_cancelled',
                                 self.h.rev())
        revision = self.h.rev()
        self.assertIsNone(self.expire(w))
        self.assertEqual(self.h.rev(), revision)
        self.assertEqual(self.h.ctrl.history('r', 'timeouts'), ())

    def test_restart_preserves_timeout_and_replays_same_record(self):
        attempt = self.attempt()
        w = self.h.wait('q', 'a')
        self.assertIsNotNone(self.expire(w))
        self.h.store.close()
        self.h.store = self.h.connect()
        self.h.refresh()
        self.assertEqual(
            self.h.ctrl.wait_details(w.ref, 'q').disposition, 'timeout')
        attempt = self.h.ctrl.get_attempt(attempt.ref)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.stop_reply)
        self.assertIsNone(self.h.ctrl.attempt_settlement(attempt.ref))
        # Re-expiry replays the same committed timeout; no second write.
        self.assertEqual(self.expire(w).request_id, 'q')

    def test_deadline_and_identity_boundaries_unchanged(self):
        attempt = self.attempt()
        w = self.h.wait('q', 'a')
        with self.assertRaises(InvalidTransition):  # deadline not reached
            self.h.store.scheduler().expire_wait(w.ref, 'q', self.h.rev())
        with self.assertRaises(NotFound):
            self.h.store.scheduler().expire_wait(w.ref, 'missing',
                                                 self.h.rev())
        self.h.now = PAST
        with self.assertRaises(Conflict):  # stale CAS
            self.h.store.scheduler().expire_wait(w.ref, 'q', 0)

    def test_timeout_reason_result_is_immutable_like_any_result(self):
        # A real Native Result carrying the former synthetic timeout
        # reason is immutable exactly like any committed Result: a
        # differing ResultEvent is an IntegrityViolation before CAS —
        # under a fresh event ID or the committed one — and mutates
        # neither the Result nor the event history.
        attempt = self.attempt()
        first = self.h.ctrl.record_event(
            c.ResultEvent(attempt.ref, 'e:timeout',
                c.Result(attempt.ref, c.State.FAILED,
                         'human_confirmation_timeout')),
            self.h.ctrl.get_attempt(attempt.ref).revision)
        events = self.h.ctrl.history('r', 'events')
        revision = self.h.ctrl.get_attempt(attempt.ref).revision
        for event in (
            c.ResultEvent(attempt.ref, 'e:completed',
                c.Result(attempt.ref, c.State.COMPLETED)),
            c.ResultEvent(attempt.ref, 'e:timeout',
                c.Result(attempt.ref, c.State.FAILED, 'changed')),
        ):
            for rev in (revision, -1):
                with self.assertRaises(IntegrityViolation):
                    self.h.ctrl.record_event(event, rev)
        self.assertEqual(self.h.ctrl.get_attempt(attempt.ref).result,
                         first.result)
        self.assertEqual(self.h.ctrl.history('r', 'events'), events)
        self.assertEqual(self.h.ctrl.get_attempt(attempt.ref).revision,
                         revision)
        # An exact committed replay remains a safe no-op, and a host
        # restart preserves the committed Result byte-identically.
        replay = self.h.ctrl.record_event(
            c.ResultEvent(attempt.ref, 'e:timeout',
                c.Result(attempt.ref, c.State.FAILED,
                         'human_confirmation_timeout')), -1)
        self.assertEqual(replay.result, first.result)
        self.h.store.close()
        self.h.store = self.h.connect()
        self.h.refresh()
        self.assertEqual(self.h.ctrl.get_attempt(attempt.ref).result,
                         first.result)
        self.assertEqual(self.h.ctrl.history('r', 'events'), events)

    def test_duplicate_event_id_divergent_content_stays_integrity(self):
        # Same event_id, different content: IntegrityViolation both before
        # and after a Result commits; the late-status path cannot mask a
        # committed journal identity.
        attempt = self.attempt()
        self.h.ctrl.record_event(
            c.StatusEvent(attempt.ref, 'e:dup', c.State.RUNNING),
            self.h.ctrl.get_attempt(attempt.ref).revision)
        with self.assertRaises(IntegrityViolation):
            self.h.ctrl.record_event(
                c.StatusEvent(attempt.ref, 'e:dup', c.State.COMPLETED),
                self.h.ctrl.get_attempt(attempt.ref).revision)
        self.h.finish(attempt.ref, c.State.COMPLETED)
        events = self.h.ctrl.history('r', 'events')
        # After the Result commits, an exact replay of the committed
        # identity is a safe no-op; only genuinely divergent content is
        # IntegrityViolation, and neither mutates the event history.
        self.h.ctrl.record_event(
            c.StatusEvent(attempt.ref, 'e:dup', c.State.RUNNING), -1)
        self.assertEqual(self.h.ctrl.history('r', 'events'), events)
        with self.assertRaises(IntegrityViolation):
            self.h.ctrl.record_event(
                c.StatusEvent(attempt.ref, 'e:dup', c.State.COMPLETED),
                self.h.ctrl.get_attempt(attempt.ref).revision)
        self.assertEqual(self.h.ctrl.history('r', 'events'), events)
        self.assertEqual(
            self.h.ctrl.get_attempt(attempt.ref).result.status,
            c.State.COMPLETED)
        self.assertEqual(
            [e.event_id for e in self.h.ctrl.history('r', 'events')],
            ['e:dup', 'result:' + attempt.ref.attempt_id])


if __name__ == '__main__':
    unittest.main()
