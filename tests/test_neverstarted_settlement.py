"""NeverStarted settlement: admission plus request-matched receipt only.

Drives the real v4 control-state paths through the shared Harness; no
adapters, transports, providers or Native work are involved.
"""
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from co_v4 import contracts as c
from co_v4.ac import Finding, JobGoal
from co_v4.state import (Conflict, IntegrityViolation, InvalidTransition,
                         LimitExceeded)
from co_v4.summary import render_run_summary
from test_state import Harness


class NeverStartedSettlementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve() / 'run'
        root.mkdir(mode=0o700)
        self.h = Harness(root)
        self.addCleanup(self.h.store.close)

    def _receipt(self, attempt, evidence='ev:preflight'):
        """Adapter receipt attesting the exact admitted request never ran."""
        job = self.h.ctrl.get_job('r', attempt.ref.job_id)
        request = c.ExecuteRequest(attempt.ref, job, self.h.conditions)
        return c.OperationReply(
            attempt.ref, c.OperationStatus.UNAVAILABLE, 'preflight refusal',
            never_started=c.NeverStarted(request, evidence))

    def _never_started(self, name='a', job='j'):
        attempt = self.h.begin(name, job)
        return self.h.ctrl.record_execute(
            self._receipt(attempt), attempt.revision)

    def test_receipt_settles_same_transaction_and_quiesces(self):
        h = self.h
        h.job()
        attempt = h.begin('a')
        self.assertEqual(h.ctrl.get_run('r').state, c.State.RUNNING)
        attempt = h.ctrl.record_execute(self._receipt(attempt),
                                        attempt.revision)
        # The committed receipt must be visible to _progress inside the same
        # transaction: the settled Attempt leaves the Run PENDING.
        self.assertEqual(h.ctrl.get_run('r').state, c.State.PENDING)
        self.assertEqual(h.ctrl.attempt_settlement(attempt.ref),
                         'never_started')
        self.assertIsNotNone(attempt.ended_at)
        # Admission plus receipt only: no fabricated Native facts.
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.ac)
        self.assertIsNone(attempt.stop_reply)
        self.assertIsNone(attempt.output)
        self.assertIsNone(attempt.collection_failure)
        self.assertEqual(h.ctrl.history('r', 'events'), ())
        self.assertEqual(h.ctrl.history('r', 'ac_history'), ())
        self.assertEqual(h.ctrl.history('r', 'stop_history'), ())
        self.assertEqual(len(h.ctrl.history('r', 'execute_history')), 1)
        # The exact receipt evidence releases the capacity slot.
        h.ctrl.release_attempt(attempt.ref)
        self.assertIn(attempt.ref, h.ctrl.history('r', 'released_attempts'))

    def test_replay_stable_and_divergent_receipt_is_integrity(self):
        h = self.h
        h.job()
        attempt = h.begin('a')
        receipt = self._receipt(attempt)
        committed = h.ctrl.record_execute(receipt, attempt.revision)
        # Identical canonical replay returns the committed record, no bump.
        self.assertEqual(h.ctrl.record_execute(receipt, -1), committed)
        self.assertEqual(h.ctrl.get_attempt(attempt.ref).revision,
                         committed.revision)
        # A different receipt for the same Attempt is integrity, not CAS.
        for other in (replace(receipt, reason='another refusal'),
                      c.OperationReply(attempt.ref, c.OperationStatus.ACCEPTED,
                                       'sent anyway')):
            with self.assertRaises(IntegrityViolation):
                h.ctrl.record_execute(other, -1)
        self.assertEqual(h.ctrl.get_attempt(attempt.ref).revision,
                         committed.revision)
        self.assertEqual(h.ctrl.attempt_settlement(attempt.ref),
                         'never_started')

    def test_late_native_records_are_integrity_violations(self):
        h = self.h
        h.job()
        attempt = self._never_started()
        ref, revision = attempt.ref, attempt.revision
        job = h.ctrl.get_job('r', 'j')
        result = c.Result(ref, c.State.COMPLETED)
        blob = 'sha256:' + '0' * 64
        run_revision = h.rev()
        writes = (
            lambda: h.ctrl.record_event(
                c.StatusEvent(ref, 'e:status', c.State.RUNNING), revision),
            lambda: h.ctrl.record_event(
                c.ResultEvent(ref, 'e:result', result), revision),
            lambda: h.ctrl.record_event(c.ConfirmationEvent(
                ref, 'e:confirm', h.callback('cb')), revision),
            lambda: h.ctrl.record_stop(
                c.StopReply(ref, c.StopStatus.CONFIRMED, 'x', 'ev'), revision),
            lambda: h.ctrl.record_attempt_output(
                ref, c.AttemptOutput(ref, blob, (
                    c.OutputItemMeta(0, 'text/plain', blob, 5),), 5),
                revision),
            lambda: h.ctrl.record_ac(
                c.ACRecord(ref, 'pass', ('e',)), revision),
            lambda: h.ctrl.record_job_goal(
                JobGoal(job, result, c.ACRecord(ref, 'pass', ('e',)),
                        Finding('pass', ('e',))), h.rev()),
            lambda: h.ctrl.record_job_failure(
                c.JobFailure(job, result, 'collection_unavailable', ('e',)),
                revision),
        )
        for write in writes:
            with self.assertRaises(IntegrityViolation):
                write()
        # A stale revision cannot mask a committed-record contradiction as
        # CAS: the integrity guard precedes the revision check.
        with self.assertRaises(IntegrityViolation):
            h.ctrl.record_event(
                c.StatusEvent(ref, 'e:stale', c.State.RUNNING), -1)
        # Resume stays closed for a settled never-started Attempt.
        with self.assertRaises(InvalidTransition):
            h.store.bridge('adapter').put_resume(
                c.ResumeState('adapter', ref, b'opaque'), revision)
        self.assertEqual(h.rev(), run_revision)
        self.assertEqual(h.ctrl.attempt_settlement(ref), 'never_started')
        self.assertIsNone(h.ctrl.get_attempt(ref).result)
        self.assertEqual(h.ctrl.history('r', 'events'), ())
        self.assertEqual(h.ctrl.history('r', 'ac_history'), ())
        self.assertEqual(h.ctrl.history('r', 'stop_history'), ())

    def test_unknown_attempt_is_held_until_settled(self):
        h = self.h
        h.job()
        attempt = h.begin('a')
        self.assertIsNone(h.ctrl.attempt_settlement(attempt.ref))
        with self.assertRaises(InvalidTransition):
            h.ctrl.release_attempt(attempt.ref)
        with self.assertRaisesRegex(InvalidTransition, 'prior Attempt'):
            h.begin('b')
        with self.assertRaisesRegex(InvalidTransition, 'unresolved'):
            h.ctrl.finalize_run('r', c.State.FAILED, 'held', h.rev())
        # A terminal Result alone is not settlement: CONFIRMED cessation is
        # also required before a retry or finalization.
        attempt = h.finish(attempt.ref, c.State.COMPLETED)
        self.assertIsNone(h.ctrl.attempt_settlement(attempt.ref))
        with self.assertRaisesRegex(InvalidTransition, 'prior Attempt'):
            h.begin('b')
        attempt = h.ctrl.record_stop(
            c.StopReply(attempt.ref, c.StopStatus.CONFIRMED, 'x', 'ev'),
            attempt.revision)
        self.assertEqual(h.ctrl.attempt_settlement(attempt.ref), 'native')
        h.begin('b')

    def test_all_never_started_stop_terminal_has_no_selection(self):
        h = self.h
        h.job()
        h.job('k')
        self._never_started('a')
        self._never_started('b', job='k')
        h.authenticate('stop:1', {'operation': 'stop_run', 'run_id': 'r'})
        h.intake.record_stop_request('r', 'stop:1')
        with self.assertRaisesRegex(InvalidTransition, 'Job Goals'):
            h.ctrl.finalize_run('r', c.State.COMPLETED, 'unmet', h.rev())
        run = h.ctrl.finalize_run('r', c.State.FAILED, 'fixture_cancelled',
                                  h.rev())
        self.assertEqual(run.state, c.State.FAILED)
        self.assertIsNone(run.output_selection)
        summary = render_run_summary(h.ctrl, 'r')
        self.assertIn('not_started=2', summary)
        self.assertIn('not_applicable=2', summary)
        self.assertIn('missing=0', summary)
        self.assertNotIn('cessation unconfirmed', summary)
        self.assertIn('stop requested', summary)

    def test_stop_then_receipt_and_post_stop_admission_conflict(self):
        h = self.h
        h.job()
        attempt = h.begin('a')
        h.authenticate('stop:1', {'operation': 'stop_run', 'run_id': 'r'})
        h.intake.record_stop_request('r', 'stop:1')
        # Evidence for the already-admitted Attempt still commits under stop.
        attempt = h.ctrl.record_execute(self._receipt(attempt),
                                        attempt.revision)
        self.assertEqual(h.ctrl.attempt_settlement(attempt.ref),
                         'never_started')
        # Admission stays closed with the canonical stop reason, not CAS.
        with self.assertRaisesRegex(Conflict, 'stop_requested'):
            h.begin('b')
        with self.assertRaisesRegex(Conflict, 'stop_requested'):
            h.job('new')
        run = h.ctrl.finalize_run('r', c.State.FAILED, 'fixture_cancelled',
                                  h.rev())
        self.assertEqual(run.state, c.State.FAILED)
        self.assertIsNone(run.output_selection)

    def test_retry_restart_replay_and_pair_budget(self):
        h = self.h
        h.job()
        a = self._never_started('a')
        self.assertIsNone(a.ac)
        # A settled prior Attempt admits a retry/reroute with no AC pass.
        self._never_started('b')
        # Both consumed the pair budget; a third same-pair Attempt is refused.
        with self.assertRaises(LimitExceeded):
            h.begin('c')
        h.store.close()
        h.store = h.connect()
        h.refresh()
        self.assertEqual(h.ctrl.attempt_settlement(a.ref), 'never_started')
        # Identical replay survives restart with no fabricated facts.
        replay = h.ctrl.record_execute(self._receipt(a), -1)
        self.assertEqual(replay.ref, a.ref)
        self.assertIsNone(replay.result)
        self.assertEqual(h.ctrl.attempt_settlement(a.ref), 'never_started')


if __name__ == '__main__':
    unittest.main()
