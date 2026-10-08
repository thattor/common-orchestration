"""AC finality and terminal-Result contradiction (Opus #190 M3 P2 rulings).

State-level only: the first committed Job Goal makes attempt.ac final, and a
different terminal Result for an Attempt is integrity, not a stale write.
Controller-level drain/latch coverage is a separate Root follow-up.
"""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.ac import Finding, JobGoal
from co_v4.output_store import OutputStore
from co_v4.state import IntegrityViolation, InvalidTransition
from test_state import Harness


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.h = Harness(self.tmp.name)
        self.outputs = OutputStore(Path(self.tmp.name) / 'outputs')

    def tearDown(self):
        self.h.store.close()
        self.tmp.cleanup()

    def add_job(self, candidate=False):
        h = self.h
        job = c.Job('r', 'j', 'create output', ('inspect output',),
                    output_candidate=candidate)
        decision = h.judgment.judge(h.request(job='j', proposed=job))
        h.ctrl.add_job(job, decision.decision_id, h.rev())
        return job

    def stop(self, attempt, status):
        return self.h.ctrl.record_stop(
            c.StopReply(attempt.ref, status, 'fixture',
                        'ev:' + attempt.ref.attempt_id
                        if status == c.StopStatus.CONFIRMED else None),
            attempt.revision)


class ACFinalityTests(Fixture):
    def test_after_goal_ac_output_digest_rebinding_rejected(self):
        h = self.h
        _, attempt, _, ac, goal = self.superseded(True)
        committed = h.ctrl.get_attempt(attempt.ref)
        forged = c.ACRecord(attempt.ref, 'pass', ('fixture:inspection',),
                            output_digest='sha256:' + '0' * 64)
        with self.assertRaises(IntegrityViolation):
            h.ctrl.record_ac(forged, committed.revision)
        self.assertEqual(h.ctrl.get_attempt(attempt.ref), committed)
        self.assertEqual(committed.output.digest, ac.output_digest)
        self.assertEqual(h.ctrl.history('r', 'job_goals'), (goal,))

    def superseded(self, candidate):
        """Genuine placeholder flow: Result, UNCONFIRMED stop, blocked AC,
        CONFIRMED stop, persisted candidate output, then the first Goal."""
        h = self.h
        job = self.add_job(candidate)
        attempt = h.finish(h.begin().ref, c.State.COMPLETED)
        attempt = self.stop(attempt, c.StopStatus.UNCONFIRMED)
        blocked = c.ACRecord(attempt.ref, 'blocked', ('fixture:unconfirmed',))
        attempt = h.ctrl.record_ac(blocked, attempt.revision)
        self.assertEqual(attempt.ac, blocked)
        attempt = self.stop(attempt, c.StopStatus.CONFIRMED)
        digest = None
        if candidate:
            output = self.outputs.put(attempt.ref,
                                      (c.OutputItem(0, 'text/plain', 'done'),))
            attempt = h.ctrl.record_attempt_output(attempt.ref, output,
                                                   attempt.revision)
            digest = output.digest
        ac = c.ACRecord(attempt.ref, 'pass', ('fixture:inspection',),
                        output_digest=digest)
        goal = JobGoal(job, attempt.result, ac, Finding('pass', ('fixture:goal',)))
        self.assertEqual(h.ctrl.record_job_goal(goal, h.rev()), goal)
        attempt = h.ctrl.get_attempt(attempt.ref)
        self.assertEqual(attempt.ac, ac)
        self.assertEqual([a for _, a in h.ctrl.history('r', 'ac_history')],
                         [blocked, ac])
        self.assertEqual(h.ctrl.history('r', 'job_goals'), (goal,))
        if candidate:
            self.assertEqual(attempt.ac.output_digest, attempt.output.digest)
        return job, attempt, blocked, ac, goal

    def test_placeholder_superseded_by_first_goal(self):
        self.superseded(candidate=False)

    def test_placeholder_superseded_on_output_candidate(self):
        self.superseded(candidate=True)

    def test_after_goal_ac_final(self):
        h = self.h
        _, attempt, blocked, ac, _ = self.superseded(False)
        committed = h.ctrl.get_attempt(attempt.ref)
        history = h.ctrl.history('r', 'ac_history')
        # Equal AC is a no-op even at a stale revision: same Attempt, no
        # history entry, no bump.
        self.assertEqual(h.ctrl.record_ac(ac, -1), committed)
        # The superseded placeholder's committed key cannot replay its stale
        # AC, and any other AC violates integrity before CAS.
        for record in (blocked, c.ACRecord(attempt.ref, 'fail', ('x',)),
                       c.ACRecord(attempt.ref, 'pass', ('different',))):
            with self.assertRaises(IntegrityViolation):
                h.ctrl.record_ac(record, -1)
        self.assertEqual(h.ctrl.get_attempt(attempt.ref), committed)
        self.assertEqual(h.ctrl.history('r', 'ac_history'), history)

    def test_after_goal_divergent_job_goal_rejected(self):
        h = self.h
        job, attempt, _, ac, goal = self.superseded(False)
        revision = h.rev()
        self.assertEqual(h.ctrl.record_job_goal(goal, -1), goal)
        variants = (
            JobGoal(job, attempt.result, c.ACRecord(attempt.ref, 'fail', ('x',)),
                    Finding('fail', ('x',))),                    # verdict
            JobGoal(job, attempt.result, ac,
                    Finding('incomplete', ('x',))),             # completed flag
            JobGoal(job, replace(attempt.result, reason='changed'), ac,
                    Finding('pass', ('fixture:goal',))),         # result digest
        )
        for variant in variants:
            with self.assertRaises(IntegrityViolation):
                h.ctrl.record_job_goal(variant, -1)
        self.assertEqual(h.rev(), revision)
        self.assertEqual(h.ctrl.history('r', 'job_goals'), (goal,))

    def test_finality_holds_on_terminal_run(self):
        h = self.h
        job, attempt, blocked, ac, goal = self.superseded(False)
        committed = h.ctrl.get_attempt(attempt.ref)
        h.ctrl.finalize_run('r', c.State.FAILED, 'fixture_cancelled', h.rev())
        self.assertEqual(h.ctrl.record_ac(ac, -1), committed)
        # A terminal Run does not soften the contradiction: both the stale
        # placeholder replay and a divergent Goal are integrity violations.
        for record in (blocked, c.ACRecord(attempt.ref, 'fail', ('x',))):
            with self.assertRaises(IntegrityViolation):
                h.ctrl.record_ac(record, -1)
        self.assertEqual(h.ctrl.record_job_goal(goal, -1), goal)
        with self.assertRaises(IntegrityViolation):
            h.ctrl.record_job_goal(JobGoal(job, attempt.result,
                c.ACRecord(attempt.ref, 'fail', ('x',)),
                Finding('fail', ('x',))), h.rev())
        self.assertEqual(h.ctrl.get_attempt(attempt.ref), committed)

    def test_terminal_run_without_goal_still_rejects_new_ac(self):
        h = self.h
        self.add_job()
        attempt = self.stop(h.finish(h.begin().ref, c.State.COMPLETED),
                            c.StopStatus.CONFIRMED)
        h.ctrl.finalize_run('r', c.State.FAILED, 'fixture_cancelled', h.rev())
        with self.assertRaises(InvalidTransition):
            h.ctrl.record_ac(c.ACRecord(attempt.ref, 'pass', ('x',)), -1)


class TerminalResultTests(Fixture):
    def test_different_terminal_result_is_integrity_violation(self):
        h = self.h
        h.job()
        attempt = h.begin()
        committed = h.finish(attempt.ref, c.State.COMPLETED)
        different = c.ResultEvent(attempt.ref, 'result:other',
            c.Result(attempt.ref, c.State.FAILED, 'changed'))
        # A second, different Result is integrity and precedes CAS.
        for revision in (committed.revision, -1):
            with self.assertRaises(IntegrityViolation):
                h.ctrl.record_event(different, revision)
        self.assertEqual(h.ctrl.get_attempt(attempt.ref), committed)
        self.assertEqual(len(h.ctrl.history('r', 'events')), 1)
        # Reused event ID with contradictory content stays integrity.
        with self.assertRaises(IntegrityViolation):
            h.ctrl.record_event(replace(different, event_id='result:a'), -1)
        # Same Result under a new event ID keeps its journal behavior.
        replay = h.event(c.ResultEvent(attempt.ref, 'result:again',
                                       committed.result))
        self.assertEqual(replay.result, committed.result)
        self.assertNotEqual(replay.revision, committed.revision)
        self.assertEqual(len(h.ctrl.history('r', 'events')), 2)
        # On a terminal Run the exact committed event still replays, the
        # divergent Result is still integrity, and a fresh same-content ID
        # keeps the existing run_terminal rejection.
        attempt = self.stop(h.ctrl.get_attempt(attempt.ref),
                            c.StopStatus.CONFIRMED)
        h.ctrl.finalize_run('r', c.State.FAILED, 'fixture_cancelled', h.rev())
        original = c.ResultEvent(attempt.ref, 'result:a', committed.result)
        self.assertEqual(h.ctrl.record_event(original, -1), committed)
        with self.assertRaises(IntegrityViolation):
            h.ctrl.record_event(different, -1)
        with self.assertRaises(InvalidTransition):
            h.ctrl.record_event(c.ResultEvent(attempt.ref, 'result:third',
                                              committed.result), -1)
        self.assertEqual(h.ctrl.get_attempt(attempt.ref), attempt)


    def test_reused_event_id_different_content_terminal_run(self):
        # P2-1: a committed event ID reused with different content is
        # integrity on a terminal Run — never a quiet run_terminal
        # discard — and writes nothing to the journal. The exact
        # committed replay still returns the stored record.
        h = self.h
        h.job()
        attempt = h.begin()
        committed = h.finish(attempt.ref, c.State.COMPLETED)
        attempt = self.stop(h.ctrl.get_attempt(attempt.ref),
                            c.StopStatus.CONFIRMED)
        h.ctrl.finalize_run('r', c.State.FAILED, 'fixture_cancelled',
                            h.rev())
        journaled = h.ctrl.history('r', 'events')
        self.assertEqual(
            h.ctrl.record_event(
                c.ResultEvent(attempt.ref, 'result:a', committed.result),
                -1), committed)
        for event in (
                c.StatusEvent(attempt.ref, 'result:a', c.State.RUNNING),
                c.ResultEvent(attempt.ref, 'result:a',
                              c.Result(attempt.ref, c.State.FAILED,
                                       'other'))):
            with self.assertRaises(IntegrityViolation):
                h.ctrl.record_event(event, -1)
        self.assertEqual(h.ctrl.history('r', 'events'), journaled)
        self.assertEqual(h.ctrl.get_attempt(attempt.ref), attempt)

if __name__ == '__main__':
    unittest.main()
