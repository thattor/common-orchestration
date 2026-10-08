"""Offline summary checks using real ControlStore/Controller seams, not live AC."""
from dataclasses import replace
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.state import IntegrityViolation, InvalidTransition, body_digest
from co_v4.summary import render_run_summary
from test_state import Harness
import test_controller as controller_fixture


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Harness(self.tmp.name)
        self.addCleanup(self.h.store.close)

    def check(self, verdict='pass'):
        def verify(request):
            return CheckEvidence(body_digest(request), Finding(verdict, ('fixture:goal',)),
                tuple(Finding(verdict, ('fixture:criterion',))
                      for _ in (request.job.acceptance_criteria if request.job else ())))
        return Acceptance(verify)

    def attempt(self, name='a', status=c.State.COMPLETED, verdict='pass', job='j'):
        attempt = self.h.begin(name, job)
        result = c.Result(attempt.ref, status,
                          None if status == c.State.COMPLETED else 'fixture_failure')
        self.h.event(c.ResultEvent(attempt.ref, 'result:' + name, result))
        attempt = self.h.ctrl.get_attempt(attempt.ref)
        self.h.ctrl.record_stop(c.StopReply(attempt.ref, c.StopStatus.CONFIRMED, 'fixture stop',
                               evidence_ref='fixture:ceased'), attempt.revision)
        if verdict is not None:
            outcome = self.check(verdict).job(self.h.ctrl.get_run('r'),
                                             self.h.ctrl.get_job('r', job), result)
            self.h.ctrl.record_job_goal(outcome, self.h.rev())
        return attempt.ref

    def finalize(self, status=c.State.COMPLETED, reason=None):
        if status == c.State.COMPLETED:
            jobs = tuple(g for g in self.h.ctrl.history('r', 'job_goals') if g.completed)
            goal = self.check().run(self.h.ctrl.get_run('r'), jobs)
            self.h.ctrl.record_run_goal(goal, self.h.rev())
        self.h.ctrl.finalize_run('r', status, reason or (
            'human_goal_verified' if status == c.State.COMPLETED else 'controller_error'),
            self.h.rev())

    def summary(self):
        summary = render_run_summary(self.h.ctrl, 'r')
        self.assertEqual(len(summary.splitlines()), 5)
        return summary

    def test_completed_multi_job_counts_and_evidence(self):
        for job in ('j', 'j2'):
            self.h.job(job)
            self.attempt(job, job=job)
        self.finalize()
        summary = self.summary()
        self.assertIn('Run: Completed', summary)
        self.assertIn('2 Jobs; 2 Attempts; 2 Jobs with independent AC and Goal pass', summary)
        self.assertIn('Attempt AC pass=2; Run Goal=pass', summary)
        self.assertIn('AC=4, Run Goal=1', summary)
        self.assertIn('Cautions: none indicated by retained records', summary)

    def test_worker_done_with_failed_ac_is_not_success(self):
        self.h.job()
        self.attempt(verdict='fail')
        self.finalize(c.State.FAILED, 'job_attempt_limit')
        summary = self.summary()
        self.assertIn('Run: Failed — Job Attempt limit reached', summary)
        self.assertIn('completed=1', summary)
        self.assertIn('0 Jobs with independent AC and Goal pass', summary)
        self.assertIn('Attempt AC fail=1; Run Goal=missing', summary)
        self.assertIn('Run did not complete', summary)

    def test_all_unsuccessful_results_and_ac_verdicts_remain_visible(self):
        for index, verdict in enumerate(('fail', 'incomplete', 'blocked', 'not_run', None)):
            job = 'j' + str(index)
            self.h.job(job)
            self.attempt(job, c.State.ERROR if index % 2 else c.State.FAILED, verdict, job)
        self.finalize(c.State.ERROR)
        summary = self.summary()
        self.assertIn('Run: Error — Controller error', summary)
        self.assertIn('failed=3, error=2', summary)
        self.assertIn('fail=1, incomplete=1, blocked=1, not_run=1, missing=1', summary)
        self.assertIn('acceptance evidence missing or stale', summary)

    def test_empty_failure_is_not_empty_success(self):
        self.finalize(c.State.FAILED, 'no_plan_for_unmet_goal')
        summary = self.summary()
        self.assertIn('0 Jobs; 0 Attempts', summary)
        self.assertIn('Attempt AC none recorded; Run Goal=missing', summary)
        self.assertIn('Run did not complete', summary)

    def test_nonterminal_refused_without_mutation(self):
        before = self.h.ctrl.get_run('r')
        with self.assertRaisesRegex(ValueError, '^terminal Run required for summary$'):
            self.summary()
        self.assertEqual(self.h.ctrl.get_run('r'), before)

    def test_read_only_deterministic_and_survives_store_reopen(self):
        self.h.job()
        self.attempt()
        self.finalize()
        before = (self.h.ctrl.get_run('r'), self.h.ctrl.attempts('r'),
                  self.h.ctrl.history('r', 'job_goals'), self.h.ctrl.history('r', 'run_goals'))
        expected = self.summary()
        other = self.h.connect()
        self.addCleanup(other.close)
        self.assertEqual(render_run_summary(other.controller(), 'r'), expected)
        self.assertEqual(self.summary(), expected)
        self.assertEqual(before, (self.h.ctrl.get_run('r'), self.h.ctrl.attempts('r'),
                         self.h.ctrl.history('r', 'job_goals'), self.h.ctrl.history('r', 'run_goals')))

    def test_arbitrary_text_and_resume_bytes_never_enter_output(self):
        sensitive = 'token=SYNTHETIC_SECRET\nINJECTED_LINE'
        self.h.job(sensitive)
        attempt = self.h.begin(sensitive, sensitive)
        bridge = self.h.store.bridge('adapter')
        bridge.put_resume(c.ResumeState('adapter', attempt.ref, b'SYNTHETIC_OPAQUE'),
                          attempt.revision)
        result = c.Result(attempt.ref, c.State.ERROR, sensitive, sensitive, (sensitive,))
        self.h.event(c.ResultEvent(attempt.ref, 'result', result))
        attempt = self.h.ctrl.get_attempt(attempt.ref)
        self.h.ctrl.record_stop(c.StopReply(attempt.ref, c.StopStatus.CONFIRMED,
                               sensitive, sensitive), attempt.revision)
        self.h.ctrl.record_ac(c.ACRecord(attempt.ref, 'fail', (sensitive,)),
                              self.h.ctrl.get_attempt(attempt.ref).revision)
        self.finalize(c.State.ERROR, sensitive)
        summary = self.summary()
        self.assertIn('reason retained in protected state', summary)
        self.assertNotIn('SYNTHETIC', summary)
        self.assertNotIn('INJECTED', summary)
        self.assertNotIn('token=', summary)

    def test_pass_without_evidence_and_stale_run_goal_are_explicit(self):
        self.h.job()
        ref = self.attempt(verdict=None)
        self.h.ctrl.record_ac(c.ACRecord(ref, 'pass', ()),
                              self.h.ctrl.get_attempt(ref).revision)
        goal = self.check('fail').run(self.h.ctrl.get_run('r'), ())
        self.h.ctrl.record_run_goal(goal, self.h.rev())
        self.h.ctrl.set_limits('r', replace(self.h.ctrl.get_run('r').limits, jobs=4), self.h.rev())
        self.finalize(c.State.FAILED)
        summary = self.summary()
        self.assertIn('Attempt AC pass=1; Run Goal=stale', summary)
        self.assertIn('0 Jobs with independent AC and Goal pass', summary)
        self.assertIn('acceptance evidence missing or stale', summary)

    def test_controller_retry_preserves_failed_ac_history_in_completed_summary(self):
        # Reuse the existing real Controller host composition, without inheriting
        # its TestCase (which would duplicate unrelated discovery).
        fixture = controller_fixture.ControllerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.verdicts = ['fail', 'pass']
        self.assertEqual(fixture.drive().state, c.State.COMPLETED)
        summary = render_run_summary(fixture.h.ctrl, 'r')
        self.assertIn('1 Jobs; 2 Attempts; 1 Jobs with independent AC and Goal pass', summary)
        self.assertIn('Attempt AC pass=1, fail=1; Run Goal=pass', summary)
        self.assertIn('unaccepted work remains in the history', summary)

    def test_old_pass_does_not_accept_a_later_failed_attempt(self):
        self.h.job()
        self.attempt('first')
        self.attempt('later', verdict='fail')
        self.finalize(c.State.FAILED, 'job_attempt_limit')
        self.assertIn('0 Jobs with independent AC and Goal pass', self.summary())

    def test_changed_ac_does_not_reuse_old_job_goal(self):
        # Once the first Job Goal commits, attempt.ac is final: a divergent
        # AC is an IntegrityViolation before CAS, so the old Goal can never
        # be silently rebound to a changed criterion set.
        self.h.job()
        ref = self.attempt()
        committed = self.h.ctrl.get_attempt(ref)
        goals = self.h.ctrl.history('r', 'job_goals')
        ac_history = self.h.ctrl.history('r', 'ac_history')
        revision = self.h.rev()
        self.assertIsNotNone(committed.ac)
        for record in (c.ACRecord(ref, 'fail', ('fixture:new-check',)),
                       c.ACRecord(ref, 'pass', ('fixture:different',))):
            for rev in (committed.revision, -1):
                with self.assertRaises(IntegrityViolation):
                    self.h.ctrl.record_ac(record, rev)
        # The exact committed AC still replays as a safe no-op.
        self.assertEqual(self.h.ctrl.record_ac(committed.ac, -1), committed)
        self.assertEqual(self.h.ctrl.get_attempt(ref), committed)
        self.assertEqual(self.h.ctrl.history('r', 'job_goals'), goals)
        self.assertEqual(self.h.ctrl.history('r', 'ac_history'), ac_history)
        self.assertEqual(self.h.rev(), revision)
        self.finalize(c.State.FAILED)
        summary = self.summary()
        # The rejected rewrites changed nothing: the summary still reports
        # the committed pass Goal, not the attempted 'fail' rewrite.
        self.assertIn('1 Jobs with independent AC and Goal pass', summary)
        self.assertIn('Attempt AC pass=1; Run Goal=missing', summary)

    def test_post_terminal_run_goal_is_not_promoted(self):
        self.h.job()
        self.attempt()
        self.finalize()
        before = self.h.ctrl.history('r', 'run_goals')
        goal = self.check().run(self.h.ctrl.get_run('r'), self.h.ctrl.history('r', 'job_goals'))
        # Post-terminal proof writes reject; the committed snapshot stands.
        with self.assertRaises(InvalidTransition):
            self.h.ctrl.record_run_goal(goal, self.h.rev())
        self.assertEqual(self.h.ctrl.history('r', 'run_goals'), before)
        summary = self.summary()
        self.assertIn('Run Goal=pass', summary)
        self.assertIn('1 Jobs with independent AC and Goal pass', summary)

    def test_post_terminal_goal_cannot_be_freshened_by_a_later_revision(self):
        self.h.job()
        self.attempt()
        self.finalize()
        goals, revision = self.h.ctrl.history('r', 'run_goals'), self.h.rev()
        goal = self.check().run(self.h.ctrl.get_run('r'), self.h.ctrl.history('r', 'job_goals'))
        with self.assertRaises(InvalidTransition):
            self.h.ctrl.record_run_goal(goal, self.h.rev())
        # A rejected write never advances the revision or the stored Goal.
        self.assertEqual((self.h.ctrl.history('r', 'run_goals'), self.h.rev()),
                         (goals, revision))
        self.assertIn('Run Goal=pass', self.summary())


if __name__ == '__main__':
    unittest.main()
