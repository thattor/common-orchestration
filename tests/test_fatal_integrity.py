"""Fatal integrity_violation latch: held Attempt, real cleanup only.

Drives the real v4 Controller/state/Judgment paths through the shared
Harness and the deterministic NativeFixture; no transports, providers,
SDK or Native work are involved. Fixtures only — nothing here is a claim
that these tests were executed.
"""
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.controller import Controller, JobPlan
from co_v4.state import Conflict, body_digest
from co_v4.usage import UsageStore
from test_state import Harness
from test_controller import NOW, USE, NativeFixture, catalog


class FatalIntegrityLatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve() / 'run'
        root.mkdir(mode=0o700)
        self.h = Harness(root)
        self.addCleanup(self.h.store.close)
        self.native = NativeFixture()
        self.plans = [self.plan()]
        self.usage = UsageStore()
        self.controller = self.build()

    def plan(self, name="j", models=("a", "b")):
        return JobPlan(c.Job("r", name, "create tested output " + name,
            ("output checked",)), self.h.action, "write-output", USE,
            tuple(replace(self.h.conditions, model=m) for m in models),
            usage_window="comparable-fixture-window")

    def verify(self, request):
        return CheckEvidence(body_digest(request),
            Finding("pass", ("fixture:goal-check",)),
            tuple(Finding("pass", ("fixture:artifact-check",))
                  for _ in (request.job.acceptance_criteria
                            if request.job else ())))

    def build(self, **overrides):
        args = dict(state=self.h.ctrl, judgment=self.h.judgment,
            catalog=catalog(), usage=self.usage,
            adapters={"adapter": self.native},
            acceptance=Acceptance(self.verify),
            planner=lambda *args: self.plans.pop(0) if self.plans else None,
            clock=lambda: NOW)
        args.update(overrides)
        return Controller("r", **args)

    def start(self):
        self.assertEqual(self.controller.step().reason, "next_job")
        self.assertEqual(self.controller.step().reason, "execute_receipt")
        return self.native.requests[-1].ref

    def inject_divergent_event(self, ref, before_last=False):
        """Commit an event the next Adapter emission contradicts.

        before_last inserts the divergent emission ahead of an already
        queued terminal event, so the contradiction drains before the
        real Result instead of arriving as a skippable late status."""
        self.h.ctrl.record_event(
            c.StatusEvent(ref, 'divergent', c.State.RUNNING),
            self.h.ctrl.get_attempt(ref).revision)
        event = c.StatusEvent(ref, 'divergent', c.State.COMPLETED)
        if before_last:
            self.native.logs[ref].insert(-1, event)
        else:
            self.native.logs[ref].append(event)

    def held(self, progress, ref, reason, cessation):
        """Latched, unsettled: RUNNING hold, slot kept, latch persisted.

        The internal reason carries the cessation detail; the projected
        code stays in the integrity_violation family in every held state.
        """
        self.assertEqual(progress.state, c.State.RUNNING)
        self.assertEqual(progress.reason, reason)
        self.assertTrue(progress.reason.startswith('integrity_violation'))
        self.assertIs(progress.cessation_confirmed, cessation)
        self.assertEqual(progress.active, ref)
        self.assertEqual(self.h.ctrl.checkpoint('r').halted,
                         'integrity_violation')

    def held_unconfirmed(self, progress, ref):
        self.held(progress, ref, 'integrity_violation_stop_unconfirmed',
                  False)

    def held_result_missing(self, progress, ref):
        self.held(progress, ref, 'integrity_violation_result_missing',
                  True)

    def test_pending_continuation_latches_without_replan_or_dispatch(self):
        # Opus 1: contradiction while an applied continuation is pending.
        replans = []
        self.controller = self.build(
            replanner=lambda *args: replans.append(args) or self.plan())
        self.native.confirmation = self.h.action
        ref = self.start()
        self.h.confirm = True
        self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        wait = next(r for r in self.controller.records
                    if isinstance(r, c.WaitingHuman))
        self.inject_divergent_event(ref)
        receipt = self.h.answer(wait, c.HumanAnswer.INSTRUCT,
                                detail='fixture instruction')
        self.assertEqual(receipt.disposition, 'applied')
        self.held_result_missing(self.controller.step(), ref)
        for _ in range(3):
            self.held_result_missing(self.controller.step(), ref)
        self.assertEqual(replans, [])
        self.assertEqual(len(self.native.requests), 1)
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.ac)
        self.assertEqual(self.h.ctrl.history('r', 'job_goals'), ())

    def test_human_stop_never_replaces_integrity_reason(self):
        # Opus 2: a Human stop after the latch keeps the closed reason.
        self.native.auto_complete = False
        ref = self.start()
        self.inject_divergent_event(ref)
        self.held_result_missing(self.controller.step(), ref)
        self.h.authenticate('stop:1',
                            {'operation': 'stop_run', 'run_id': 'r'})
        self.h.intake.record_stop_request('r', 'stop:1')
        self.held_result_missing(self.controller.step(), ref)
        self.native.finish(ref, c.State.FAILED)
        final = self.controller.step()
        self.assertEqual(final.state, c.State.FAILED)
        self.assertEqual(final.reason, 'integrity_violation')
        self.assertTrue(final.cessation_confirmed)
        run = self.h.ctrl.get_run('r')
        self.assertTrue(run.stop_requested)
        self.assertEqual(run.final_reason, 'integrity_violation')
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.reason,
                         'fixture_failure')
        self.assertEqual(len(self.native.requests), 1)

    def test_restart_restores_latch_then_finalizes_when_settled(self):
        # Opus 3: restart restores the checkpoint latch; gate runs first.
        self.native.auto_complete = False
        ref = self.start()
        self.inject_divergent_event(ref)
        self.held_result_missing(self.controller.step(), ref)
        self.controller = self.build()  # serialized host restart
        self.held_result_missing(self.controller.step(), ref)
        self.assertEqual(len(self.native.requests), 1)
        self.native.finish(ref, c.State.FAILED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.reason,
                         'fixture_failure')

    def test_unknown_active_real_reply_only_no_controller_result(self):
        # Opus 4: real StopReply/events only; no fabricated Native Result.
        self.native.auto_complete = False
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        ref = self.start()
        self.inject_divergent_event(ref)
        self.held_unconfirmed(self.controller.step(), ref)
        self.assertEqual(self.native.stops, [ref])
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.ac)
        self.assertEqual(attempt.stop_reply.status,
                         c.StopStatus.UNCONFIRMED)
        # CONFIRMED cessation alone is not settlement without a real Result.
        self.native.stop_status = c.StopStatus.CONFIRMED
        self.held_result_missing(self.controller.step(), ref)
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.ac)
        self.assertEqual(attempt.stop_reply.status, c.StopStatus.CONFIRMED)
        # A real Result then settles the Attempt; the Run ends FAILED.
        self.native.finish(ref, c.State.FAILED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.reason,
                         'fixture_failure')
        self.assertEqual(len(self.native.requests), 1)
        self.assertEqual(self.h.ctrl.history('r', 'ac_history'), ())
        self.assertEqual(self.h.ctrl.history('r', 'job_failures'), ())

    def test_latch_save_conflict_retried_then_memory_latched(self):
        # Opus 5: a save Conflict during latching is retried, not swallowed.
        self.native.auto_complete = False
        ref = self.start()
        self.inject_divergent_event(ref)
        original = self.h.ctrl.save_checkpoint
        calls = []
        def flaky(run_id, checkpoint, expected_revision):
            calls.append(checkpoint)
            if len(calls) == 1:
                raise Conflict('injected fixture conflict')
            return original(run_id, checkpoint, expected_revision)
        self.h.ctrl.save_checkpoint = flaky
        self.held_result_missing(self.controller.step(), ref)
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(self.h.ctrl.checkpoint('r').halted,
                         'integrity_violation')
        # Exhaustion: held view returns (no exception), the lock is
        # released, and the unsaved latch is audited locally each step.
        self.h.ctrl.save_checkpoint = lambda *a: (_ for _ in ()).throw(
            Conflict('injected fixture conflict'))
        for _ in range(3):
            held = self.controller.step()
            self.assertEqual((held.state, held.reason,
                              held.cessation_confirmed),
                             (c.State.RUNNING,
                              'integrity_violation_result_missing', True))
            self.assertFalse(self.controller._lock.locked())
        # Edge-triggered: three lost saves produce exactly one record.
        self.assertEqual(self.controller.records.count(
            ('fatal_latch_checkpoint_unsaved', ref)), 1)
        # Held means held: no dispatch, relay, AC, goal or output.
        self.assertEqual(len(self.native.requests), 1)
        self.assertEqual(self.native.stops, [ref])
        self.assertEqual(self.native.responses, [])
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.ac)
        self.assertIsNone(attempt.output)
        self.assertIsNone(attempt.collection_failure)
        self.assertEqual(self.h.ctrl.history('r', 'job_goals'), ())
        self.assertEqual(self.h.ctrl.history('r', 'ac_history'), ())
        self.assertNotIn(self.h.ctrl.get_run('r').state, c.TERMINAL)
        # Save restored: the step still holds, and the committed
        # checkpoint carries the latch and the current cursor.
        self.h.ctrl.save_checkpoint = original
        self.held_result_missing(self.controller.step(), ref)
        checkpoint = self.h.ctrl.checkpoint('r')
        self.assertEqual(checkpoint.halted, 'integrity_violation')
        self.assertEqual(checkpoint.cursor, 'divergent')
        # A successful save re-arms the edge: the next loss records again.
        self.h.ctrl.save_checkpoint = lambda *a: (_ for _ in ()).throw(
            Conflict('injected fixture conflict'))
        self.held_result_missing(self.controller.step(), ref)
        self.assertEqual(self.controller.records.count(
            ('fatal_latch_checkpoint_unsaved', ref)), 2)
        self.h.ctrl.save_checkpoint = original


    def test_latch_never_durable_until_save_then_real_result_settles(self):
        # Every save fails from the first latch attempt: the in-memory
        # latch alone blocks dispatch, and no durability is claimed.
        self.native.auto_complete = False
        ref = self.start()
        self.inject_divergent_event(ref)
        original = self.h.ctrl.save_checkpoint
        self.h.ctrl.save_checkpoint = lambda *a: (_ for _ in ()).throw(
            Conflict('injected fixture conflict'))
        try:
            for _ in range(3):
                held = self.controller.step()
                self.assertEqual((held.state, held.reason,
                                  held.cessation_confirmed),
                                 (c.State.RUNNING,
                                  'integrity_violation_result_missing',
                                  True))
                self.assertFalse(self.controller._lock.locked())
            self.assertEqual(self.controller.records.count(
                ('fatal_latch_checkpoint_unsaved', ref)), 1)
            # Honest non-durability: the committed checkpoint never
            # carried the latch across the failing saves.
            self.assertIsNone(self.h.ctrl.checkpoint('r').halted)
            self.assertEqual(len(self.native.requests), 1)
            self.assertEqual(self.native.responses, [])
            attempt = self.h.ctrl.get_attempt(ref)
            self.assertIsNone(attempt.result)
            self.assertIsNone(attempt.ac)
            self.assertEqual(self.h.ctrl.history('r', 'job_goals'), ())
        finally:
            self.h.ctrl.save_checkpoint = original
        # Save restored: the latch commits first, then a real Result plus
        # CONFIRMED cessation settles and finalizes — one Native request.
        self.held_result_missing(self.controller.step(), ref)
        self.assertEqual(self.h.ctrl.checkpoint('r').halted,
                         'integrity_violation')
        self.native.finish(ref, c.State.FAILED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertTrue(final.cessation_confirmed)
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.reason,
                         'fixture_failure')
        self.assertEqual(len(self.native.requests), 1)

    def test_late_answer_persists_but_triggers_nothing(self):
        # Opus 6: an accepted answer persists; no relay/replan/dispatch.
        self.native.confirmation = self.h.action
        ref = self.start()
        self.h.confirm = True
        self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        wait = next(r for r in self.controller.records
                    if isinstance(r, c.WaitingHuman))
        self.inject_divergent_event(ref)
        self.held_result_missing(self.controller.step(), ref)
        receipt = self.h.answer(wait)
        self.assertEqual(receipt.disposition, 'applied')
        self.held_result_missing(self.controller.step(), ref)
        self.assertEqual(len(self.h.ctrl.history('r', 'answers')), 1)
        self.assertEqual(len(self.h.ctrl.history('r', 'approvals')), 1)
        self.assertEqual(self.native.responses, [])
        self.assertEqual(len(self.native.requests), 1)
        self.assertIsNone(self.h.ctrl.get_attempt(ref).result)

    def test_settled_attempts_finalize_immediately_failed(self):
        # Gate order: settled evidence + real CONFIRMED stop -> FAILED.
        ref = self.start()  # auto_complete queues the real Result emission
        self.inject_divergent_event(ref, before_last=True)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertTrue(final.cessation_confirmed)
        self.assertEqual(self.h.ctrl.get_run('r').final_reason,
                         'integrity_violation')
        # The retained Result is the real one, not a controller fabrication.
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.status,
                         c.State.COMPLETED)
        self.assertEqual(len(self.native.requests), 1)

    def test_event_cas_conflict_retried_and_commits_same_step(self):
        # New 1a: a stale CAS on a real Result is retried, not skipped.
        self.native.auto_complete = False
        ref = self.start()
        self.inject_divergent_event(ref)
        self.held_result_missing(self.controller.step(), ref)
        self.native.finish(ref, c.State.FAILED)
        result_id = self.native.logs[ref][-1].event_id
        original = self.h.ctrl.record_event
        calls = []
        def flaky(event, expected_revision):
            calls.append(event.event_id)
            if len(calls) == 1:
                raise Conflict('injected fixture conflict')
            return original(event, expected_revision)
        self.h.ctrl.record_event = flaky
        final = self.controller.step()
        self.assertEqual(calls, [result_id, result_id])
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.reason,
                         'fixture_failure')
        self.assertEqual(len(self.native.requests), 1)

    def test_event_cas_exhaustion_keeps_cursor_then_commits(self):
        # New 1b: bounded CAS exhaustion holds the cursor; the next step
        # resumes the drain and commits with no new Native execute.
        self.native.auto_complete = False
        ref = self.start()
        self.inject_divergent_event(ref)
        self.held_result_missing(self.controller.step(), ref)
        self.native.finish(ref, c.State.FAILED)
        result_id = self.native.logs[ref][-1].event_id
        calls = []
        def failing(event, expected_revision):
            calls.append(event.event_id)
            raise Conflict('injected fixture conflict')
        self.h.ctrl.record_event = failing
        self.held_result_missing(self.controller.step(), ref)
        # Bounded retry of the same event, then the drain stops honestly.
        self.assertEqual(calls, [result_id] * 3)
        self.assertEqual(self.h.ctrl.checkpoint('r').cursor, 'divergent')
        self.assertIsNone(self.h.ctrl.get_attempt(ref).result)
        del self.h.ctrl.record_event
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.reason,
                         'fixture_failure')
        self.assertEqual(len(self.native.requests), 1)

    def test_contradiction_advances_cursor_and_real_result_commits(self):
        # New 2: a permanent contradiction audits + advances the cursor;
        # a later real Result still commits and settles the Attempt.
        self.native.auto_complete = False
        ref = self.start()
        self.inject_divergent_event(ref)
        self.held_result_missing(self.controller.step(), ref)
        self.assertEqual(self.h.ctrl.checkpoint('r').cursor, 'divergent')
        self.assertIn(("integrity_violation_event", ref, 'divergent'),
                      self.controller.records)
        # The committed record, not the contradicting emission, won.
        committed = [e for e in self.h.ctrl.history('r', 'events')
                     if e.event_id == 'divergent']
        self.assertEqual([e.state for e in committed], [c.State.RUNNING])
        self.native.finish(ref, c.State.FAILED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.reason,
                         'fixture_failure')

    def test_unexpected_invalid_transition_holds_cursor_no_skip(self):
        # New 3: a refused transition is held, never skipped past cursor.
        self.native.auto_complete = False
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        ref = self.start()
        self.inject_divergent_event(ref)
        self.held_unconfirmed(self.controller.step(), ref)
        # A real terminal Result commits; cessation stays unconfirmed.
        self.h.finish(ref, c.State.FAILED)
        # A genuine ConfirmationEvent after the Result is refused by the
        # journal (terminal Attempt cannot confirm) — never skippable.
        callback = self.h.callback('late-confirm', ref.attempt_id)
        self.native.logs[ref].append(
            c.ConfirmationEvent(ref, 'late-confirm', callback))
        self.held_unconfirmed(self.controller.step(), ref)
        self.assertEqual(self.h.ctrl.checkpoint('r').cursor, 'divergent')
        self.assertNotIn('late-confirm',
            [e.event_id for e in self.h.ctrl.history('r', 'events')])
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.reason,
                         'fixture_failure')
        # Settlement then finalizes; the refused event stays uncommitted.
        self.native.stop_status = c.StopStatus.CONFIRMED
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertNotIn('late-confirm',
            [e.event_id for e in self.h.ctrl.history('r', 'events')])

    def test_confirmed_stop_without_result_held_truthfully(self):
        # New 4: CONFIRMED cessation and settlement are separate facts.
        self.native.auto_complete = False
        ref = self.start()
        self.inject_divergent_event(ref)
        progress = self.controller.step()
        self.held_result_missing(progress, ref)
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertEqual(attempt.stop_reply.status, c.StopStatus.CONFIRMED)
        self.assertIsNone(attempt.result)
        # No state-ledger release without full settlement; the real
        # StopReply itself is the adapter-side capacity proof.
        self.assertNotIn(ref, self.h.ctrl.history('r', 'released_attempts'))
        self.assertEqual(self.native.stops, [ref])
        self.assertEqual(self.h.ctrl.get_run('r').state, c.State.RUNNING)

    def test_unconfirmed_stop_held_truthfully_slot_held(self):
        # New 5: without committed CONFIRMED cessation, slot stays held.
        self.native.auto_complete = False
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        ref = self.start()
        self.inject_divergent_event(ref)
        progress = self.controller.step()
        self.held_unconfirmed(progress, ref)
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertEqual(attempt.stop_reply.status,
                         c.StopStatus.UNCONFIRMED)
        self.assertIsNone(attempt.result)
        self.assertNotIn(ref, self.h.ctrl.history('r', 'released_attempts'))
        self.assertEqual(self.h.ctrl.get_run('r').state, c.State.RUNNING)

    def test_projection_stays_integrity_violation_through_terminal(self):
        # New 6: the projected code is integrity_violation in every held
        # state and at the terminal, never completed/cancelled (M3 maps
        # it northbound; no gateway change here).
        self.native.auto_complete = False
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        ref = self.start()
        self.inject_divergent_event(ref)
        self.held_unconfirmed(self.controller.step(), ref)
        self.native.stop_status = c.StopStatus.CONFIRMED
        self.held_result_missing(self.controller.step(), ref)
        self.native.finish(ref, c.State.FAILED)
        final = self.controller.step()
        self.assertEqual(final.state, c.State.FAILED)
        self.assertEqual(final.reason, 'integrity_violation')
        self.assertNotEqual(final.state, c.State.COMPLETED)
        self.assertEqual(len(self.native.requests), 1)


    def test_checkpoint_unsaved_edge_triggered_and_rearmed(self):
        # Non-fatal checkpoint loss on a live active Run is edge-triggered:
        # one record per uninterrupted loss run; a successful save re-arms
        # the edge so the next loss records again. Nothing else changes —
        # no Native call, relay, Goal or fabricated outcome.
        self.native.auto_complete = False
        ref = self.start()
        original = self.h.ctrl.save_checkpoint
        failing = lambda *a: (_ for _ in ()).throw(
            Conflict('injected fixture conflict'))
        self.h.ctrl.save_checkpoint = failing
        try:
            for _ in range(3):
                held = self.controller.step()
                self.assertEqual((held.state, held.reason, held.active),
                                 (c.State.RUNNING, 'awaiting_native_event',
                                  ref))
                self.assertFalse(self.controller._lock.locked())
            self.assertEqual(self.controller.records.count(
                ('checkpoint_unsaved', ref)), 1)
            self.h.ctrl.save_checkpoint = original
            self.assertEqual(self.controller.step().reason,
                             'awaiting_native_event')
            self.h.ctrl.save_checkpoint = failing
            self.assertEqual(self.controller.step().reason,
                             'awaiting_native_event')
            self.assertEqual(self.controller.records.count(
                ('checkpoint_unsaved', ref)), 2)
        finally:
            self.h.ctrl.save_checkpoint = original
        self.assertEqual(len(self.native.requests), 1)
        self.assertEqual(self.native.responses, [])
        self.assertEqual(self.h.ctrl.history('r', 'job_goals'), ())

    def test_checkpoint_unsaved_then_fatal_latch_distinct_labels(self):
        # A non-fatal loss and a fatal-latch loss are distinct labels on the
        # same held Attempt; each edge records exactly once. The latch is
        # in-memory only while every save loses the CAS — never durable.
        self.native.auto_complete = False
        ref = self.start()
        original = self.h.ctrl.save_checkpoint
        self.h.ctrl.save_checkpoint = lambda *a: (_ for _ in ()).throw(
            Conflict('injected fixture conflict'))
        try:
            self.assertEqual(self.controller.step().reason,
                             'awaiting_native_event')
            self.assertEqual(self.controller.records.count(
                ('checkpoint_unsaved', ref)), 1)
            self.inject_divergent_event(ref)
            held = self.controller.step()
            self.assertEqual((held.state, held.reason, held.active,
                              held.cessation_confirmed),
                             (c.State.RUNNING,
                              'integrity_violation_result_missing',
                              ref, True))
            # The committed checkpoint never carried the latch across the
            # failing saves.
            self.assertIsNone(self.h.ctrl.checkpoint('r').halted)
            self.assertIn(('integrity_violation_event', ref, 'divergent'),
                          self.controller.records)
            self.assertEqual(self.controller.records.count(
                ('checkpoint_unsaved', ref)), 1)
            self.assertEqual(self.controller.records.count(
                ('fatal_latch_checkpoint_unsaved', ref)), 1)
            self.assertFalse(self.controller._lock.locked())
        finally:
            self.h.ctrl.save_checkpoint = original
        self.assertEqual(len(self.native.requests), 1)
        self.assertEqual(self.native.responses, [])
        self.assertIsNone(self.h.ctrl.get_attempt(ref).result)

if __name__ == '__main__':
    unittest.main()
