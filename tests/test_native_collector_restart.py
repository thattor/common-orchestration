"""Bare-adapter collection loss after a Controller restart (M1 ruling).

A fresh Native adapter instance holds no Attempt; its public collector
refuses the committed ref with contracts.CollectionError, which the
Controller maps to collection_unavailable — never controller_error and
never a re-execution of the same Attempt. A known Attempt whose in-memory
state contradicts the committed Result keeps ValueError, escaping to
controller_error with no JobFailure. The pooled path reports CapacityError
for a lost child and is covered unchanged by
test_output_pipeline.PoolOutputTests
.test_restart_loses_retained_child_and_reports_unavailable.

Drives the real v4 Controller/state/output-store paths through the shared
synthetic composition; no Native provider, transport or pooled child.
"""
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.adapters import antigravity, claude, t3code
from fixture_e2e import ArtifactAdapter
from test_output_pipeline import drive_until, output_run, profile

UNKNOWN = 'attempt unavailable in this adapter instance'


class BareCollector(ArtifactAdapter):
    """In-memory attempt ledger like the Native text collectors: a fresh
    instance knows only the refs it executed itself."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.collected = []

    def collect_output(self, ref):
        self.collected.append(ref)
        if not any(request.ref == ref for request in self.requests):
            raise c.CollectionError(UNKNOWN)
        return super().collect_output(ref)


class ContradictingCollector(BareCollector):
    """Knows the ref, but its in-memory state contradicts the committed
    COMPLETED Result — an internal bug, not an availability failure."""

    def collect_output(self, ref):
        if not any(request.ref == ref for request in self.requests):
            raise c.CollectionError(UNKNOWN)
        raise ValueError('successful text output unavailable')


class BareRestartTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _held(self, directory, **kwargs):
        """Committed COMPLETED + CONFIRMED cessation, output unpersisted; the
        adapter is then replaced by a fresh instance as a restart leaves it."""
        s = output_run(directory,
                       adapter=BareCollector(directory, {'squares': ['good']}),
                       **kwargs)
        drive_until(s, 'cessation_confirmed')
        attempt = s.state.get_attempt(s.controller._active)
        self.assertEqual(attempt.result.status, c.State.COMPLETED)
        self.assertEqual(attempt.stop_reply.status, c.StopStatus.CONFIRMED)
        self.assertIsNone(attempt.output)
        s.adapter = BareCollector(s.root, {'squares': ['good']})
        s.controller = s.build()
        return s, attempt.ref

    def test_real_collectors_refuse_foreign_ref_with_fixed_error(self):
        foreign = c.AttemptRef('run', 'job', 'never-owned')
        for adapter in (claude.ClaudeAdapter(), t3code.T3CodeAdapter(),
                        antigravity.AntigravityTextAdapter()):
            with self.subTest(adapter=type(adapter).__name__):
                with self.assertRaises(c.CollectionError) as ctx:
                    adapter.collect_output(foreign)
                self.assertEqual(str(ctx.exception), UNKNOWN)
                self.assertNotIn('never-owned', repr(ctx.exception))
            adapter.close()

    def test_pure_profile_records_failure_and_retries_new_attempt(self):
        s, old_ref = self._held(self.dir / 'pure')
        try:
            progress = s.step()
            self.assertEqual((progress.state, progress.reason),
                             (c.State.PENDING, 'job_output_collect_unavailable'))
            failure, = s.state.history('run', 'job_failures')
            self.assertEqual(failure.kind, 'collection_unavailable')
            final = s.drive()
            self.assertEqual(final.state, c.State.COMPLETED)
            attempts = s.state.attempts('run')
            # Exactly two Attempts for the lost Job: the held original and
            # one bounded new Attempt; the other required Jobs still run.
            job_attempts = [a for a in attempts
                            if a.ref.job_id == old_ref.job_id]
            self.assertEqual(len(job_attempts), 2)
            self.assertEqual(job_attempts[0].ref, old_ref)
            new_ref = job_attempts[1].ref
            self.assertNotEqual(new_ref, old_ref)
            # Exactly one NEW execute for that Job; old_ref is executed and
            # collected nowhere — only at the committed-loss boundary.
            same_job = [r for r in s.adapter.requests
                        if r.ref.job_id == old_ref.job_id]
            self.assertEqual(len(same_job), 1)
            self.assertEqual(same_job[0].ref, new_ref)
            self.assertNotIn(old_ref, [r.ref for r in s.adapter.requests])
            self.assertEqual(s.adapter.collected, [old_ref, new_ref])
            self.assertIsNone(job_attempts[0].output)
            self.assertIsNotNone(job_attempts[1].output)
            # Every required Job completes; the selected output binds the
            # new candidate only.
            self.assertEqual(
                s.state.get_run('run').output_selection.attempt_ref,
                new_ref)
            goals = s.state.history('run', 'job_goals')
            self.assertEqual(len(goals), 2)
            self.assertTrue(all(g.completed for g in goals))
        finally:
            s.close()

    def test_effectful_profile_fails_approval_required_without_retry(self):
        s, _ = self._held(self.dir / 'effectful',
                          profile=profile(effect_class='effectful'))
        try:
            final = s.drive()
            self.assertEqual((final.state, final.reason),
                             (c.State.FAILED, 'approval_required'))
            self.assertEqual(s.adapter.requests, [])  # zero new executes
            failure, = s.state.history('run', 'job_failures')
            self.assertEqual(failure.kind, 'collection_unavailable')
            attempt, = s.state.attempts('run')
            self.assertIsNone(attempt.output)
            self.assertIsNone(attempt.ac)
            self.assertIsNone(s.state.get_run('run').output_selection)
        finally:
            s.close()

    def test_no_profile_halts_waiting_human_no_retry(self):
        s, old_ref = self._held(self.dir / 'noprofile', profile=None)
        try:
            progress = s.step()
            self.assertEqual((progress.state, progress.reason),
                             (c.State.WAITING_HUMAN,
                              'job_output_collection_unavailable'))
            failure, = s.state.history('run', 'job_failures')
            self.assertEqual(failure.kind, 'collection_unavailable')
            self.assertEqual(s.adapter.requests, [])
            attempt, = s.state.attempts('run')
            self.assertEqual(attempt.ref, old_ref)
            self.assertNotIn(s.state.get_run('run').state, c.TERMINAL)
        finally:
            s.close()

    def test_known_attempt_contradiction_is_controller_error(self):
        s = output_run(
            self.dir / 'contradiction',
            adapter=ContradictingCollector(self.dir / 'contradiction',
                                           {'squares': ['good']}))
        try:
            drive_until(s, 'cessation_confirmed')
            ref = s.controller._active
            # ValueError from a known Attempt is not an availability failure:
            # it escapes to controller_error and fails closed.
            self.assertEqual(s.step().reason, 'controller_error_stop_required')
            final = s.step()
            self.assertEqual((final.state, final.reason),
                             (c.State.ERROR, 'controller_error'))
            self.assertEqual(s.state.history('run', 'job_failures'), ())
            self.assertEqual(len(s.adapter.requests), 1)  # no retry
            attempt = s.state.get_attempt(ref)
            self.assertIsNone(attempt.output)
            self.assertIsNone(attempt.collection_failure)
            self.assertIsNone(attempt.ac)
        finally:
            s.close()


if __name__ == '__main__':
    unittest.main()
