"""Real state/Judgment/routing/AC seams; synthetic Native and host evidence.

Nothing here establishes production isolation or promotes a live route.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding, JobGoal
from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.controller import Controller, JobPlan, Transition
from co_v4.state import Conflict, InvalidTransition, Limits, body_digest, create_run_body
from co_v4.usage import UsageStore
from test_state import Harness
from test_codex import Wire
from co_v4.adapters.codex import CodexAdapter, ADAPTER, COMMAND_APPROVAL


USE = UseCase("coding")
NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)


def catalog(models=("a", "b"), adapter="adapter"):
    return Catalog(tuple(CatalogEntry(model, adapter, {USE: 2}, (
        Verification(model, adapter, USE, "env:1", "fixture:official",
                     "fixture:implementation", "fixture:measurement", "fixture:ac"),))
                         for model in models))


class NativeFixture:
    """Multi-attempt deterministic fixture behind the actual Adapter Contract."""
    def __init__(self):
        self.requests, self.logs, self.responses = [], {}, []
        self.auto_complete, self.confirmation = True, None
        self.stop_status = c.StopStatus.CONFIRMED
        self.stops = []
        self.execute_status = c.OperationStatus.ACCEPTED

    def event(self, ref, cls, *args):
        log = self.logs[ref]
        event = cls(ref, ref.attempt_id + ":" + str(len(log)), *args)
        log.append(event)

    def finish(self, ref, state=c.State.COMPLETED):
        self.event(ref, c.ResultEvent, c.Result(ref, state,
            None if state == c.State.COMPLETED else "fixture_failure"))

    def execute(self, request):
        self.requests.append(request)
        self.logs[request.ref] = []
        self.event(request.ref, c.StatusEvent, c.State.RUNNING)
        if self.confirmation:
            callback = c.Confirmation(request.ref, "q:" + request.ref.attempt_id,
                c.Decision.CONFIRM, self.confirmation, "fixture", "fixture", True)
            self.event(request.ref, c.ConfirmationEvent, callback)
        elif self.auto_complete:
            self.finish(request.ref)
        return c.OperationReply(request.ref, self.execute_status, "fixture receipt")

    def events(self, ref, after=None):
        log = self.logs[ref]
        if after is None:
            return tuple(log)
        index = next(i for i, e in enumerate(log) if e.event_id == after)
        return tuple(log[index + 1:])

    def respond(self, response):
        self.responses.append(response)
        self.finish(response.ref, c.State.COMPLETED if response.resolution == c.Resolution.ALLOW else c.State.FAILED)
        return c.OperationReply(response.ref, c.OperationStatus.ACCEPTED, "fixture relay")

    def stop(self, ref):
        self.stops.append(ref)
        return c.StopReply(ref, self.stop_status, "fixture stop",
            "fixture:cessation" if self.stop_status == c.StopStatus.CONFIRMED else None)


class ControllerTests(unittest.TestCase):
    def profile_run(self, run='pr'):
        """Real pinned-profile Run on the shared Harness; routes cover a/b."""
        profile = c.TaskProfile('fixture-profile', 'sha256:' + '0' * 64, 'pure',
            routes=(('a', 'adapter', 'env:1'), ('b', 'adapter', 'env:1')))
        self.h.authenticate('origin:' + run,
            create_run_body(run, 'create tested fixture output'))
        self.h.intake.create_run(run, 'create tested fixture output',
                                 'origin:' + run, profile)
        plan = self.plan()
        self.plans = [replace(plan, job=replace(plan.job, run_id=run))]
        self.controller = Controller(run, state=self.h.ctrl,
            judgment=self.h.judgment, catalog=catalog(), usage=self.usage,
            adapters={"adapter": self.native},
            acceptance=Acceptance(self.verify),
            planner=lambda *args: self.plans.pop(0) if self.plans else None,
            clock=lambda: NOW)
        return run

    def test_profile_pre_result_confirmation_latches_approval_barrier(self):
        run = self.profile_run()
        self.native.confirmation = self.h.action  # log: RUNNING, Confirmation
        self.assertEqual(self.controller.step().reason, "next_job")
        self.assertEqual(self.controller.step().reason, "execute_receipt")
        ref = self.native.requests[-1].ref
        held = self.controller.step()
        # The committed confirmation is real evidence; the durable barrier
        # latches and the Run holds for a genuine Result, not a wait/relay.
        self.assertEqual((held.state, held.reason),
                         (c.State.RUNNING, 'stop_result_missing'))
        self.assertEqual(self.h.ctrl.stop_origin(run), 'approval_required')
        self.assertTrue(any(isinstance(e, c.ConfirmationEvent)
                            for e in self.h.ctrl.history(run, 'events')))
        self.assertEqual(tuple(self.h.ctrl.waits(run)), ())
        self.assertEqual(self.native.responses, [])
        # Result processing can never precede the committed barrier.
        self.native.finish(ref, c.State.FAILED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'approval_required'))
        self.assertTrue(final.cessation_confirmed)

    def test_profile_post_result_confirmation_is_ordinary_discard(self):
        run = self.profile_run()
        ref = self.start()  # log: RUNNING, Result(COMPLETED)
        confirmation = c.Confirmation(ref, 'q:post', c.Decision.CONFIRM,
                                      self.h.action, 'fixture', 'fixture', True)
        self.native.event(ref, c.ConfirmationEvent, confirmation)
        event_id = self.native.logs[ref][-1].event_id
        progress = self.controller.step()
        self.assertEqual(progress.reason, 'job_goal_verified')
        self.assertIn(("post_terminal_event_discarded", ref, event_id),
                      self.controller.records)
        self.assertIsNone(self.h.ctrl.stop_origin(run))  # no barrier
        self.assertFalse(any(isinstance(e, c.ConfirmationEvent)
                             for e in self.h.ctrl.history(run, 'events')))
        self.assertEqual(tuple(self.h.ctrl.waits(run)), ())
        self.assertEqual(self.native.responses, [])
        self.assertEqual(self.drive().reason, 'human_goal_verified')

    def test_second_different_result_enters_fatal_latch(self):
        ref = self.start()  # log: RUNNING, Result(COMPLETED)
        committed = self.native.logs[ref][1].result
        forged = c.ResultEvent(ref, ref.attempt_id + ':forged',
                               c.Result(ref, c.State.FAILED, 'different'))
        self.native.logs[ref].append(forged)
        progress = self.controller.step()
        self.assertEqual((progress.state, progress.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertIn(("integrity_violation", ref), self.controller.records)
        # The fatal drain treats the permanent rejection as cursor-advancing.
        self.assertIn(("integrity_violation_event", ref, forged.event_id),
                      self.controller.records)
        # Original Result byte-identical; the forged Result was never journaled.
        self.assertEqual(self.h.ctrl.get_attempt(ref).result, committed)
        journal = self.h.ctrl.history('r', 'events')
        self.assertEqual(len(journal), 2)
        self.assertNotIn(forged, journal)
        self.assertEqual(len(self.native.requests), 1)

    def test_fatal_drain_holds_post_result_confirmation_but_settles(self):
        self.native.auto_complete = False
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        ref = self.start()  # log: RUNNING only
        self.h.ctrl.record_event(
            c.StatusEvent(ref, 'divergent', c.State.RUNNING),
            self.h.ctrl.get_attempt(ref).revision)
        self.native.logs[ref].append(
            c.StatusEvent(ref, 'divergent', c.State.COMPLETED))
        self.assertEqual(self.controller.step().reason,
                         'integrity_violation_stop_unconfirmed')
        self.native.finish(ref, c.State.FAILED)   # real Result via the drain
        confirmation = c.Confirmation(ref, 'q:held', c.Decision.CONFIRM,
                                      self.h.action, 'fixture', 'fixture', True)
        self.native.event(ref, c.ConfirmationEvent, confirmation)
        result_id, held_id = (e.event_id for e in self.native.logs[ref][-2:])
        held = self.controller.step()
        # The refused post-Result event is held, not discarded: cursor stays
        # on the committed Result; unsettled while cessation is unconfirmed.
        self.assertEqual(held.reason, 'integrity_violation_stop_unconfirmed')
        self.assertEqual(self.h.ctrl.checkpoint('r').cursor, result_id)
        self.assertIn(("drain_held", ref, held_id), self.controller.records)
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.reason,
                         'fixture_failure')
        self.native.stop_status = c.StopStatus.CONFIRMED
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertNotIn(held_id,
            [e.event_id for e in self.h.ctrl.history('r', 'events')])
        self.assertEqual(len(self.native.requests), 1)

    def test_divergent_first_goal_latches_and_reopen_never_reevaluates(self):
        ref = self.start()  # Result + CONFIRMED settle in the same step
        original = self.h.ctrl.record_job_goal
        def poisoned(outcome, revision):
            original(JobGoal(outcome.job, outcome.result,
                c.ACRecord(ref, 'fail', ('fixture:poison',)),
                Finding('fail', ('fixture:poison',))), revision)
            return original(outcome, revision)  # divergent -> integrity
        self.h.ctrl.record_job_goal = poisoned
        try:
            progress = self.controller.step()
        finally:
            self.h.ctrl.record_job_goal = original
        self.assertEqual((progress.state, progress.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertIn(("integrity_violation", ref), self.controller.records)
        # The committed Goal and frozen AC are the divergent record, and the
        # Attempt's Result stays byte-identical.
        self.assertEqual([g.ac.verdict
                          for g in self.h.ctrl.history('r', 'job_goals')],
                         ['fail'])
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertEqual(attempt.ac.verdict, 'fail')
        self.assertEqual(attempt.result.status, c.State.COMPLETED)
        calls = []
        verify = self.verify
        self.controller = self.build(acceptance=Acceptance(
            lambda request: calls.append(request.kind) or verify(request)))
        self.assertEqual(self.controller.step().reason, 'integrity_violation')
        self.assertEqual(calls, [])  # recovery never re-evaluates the Attempt

    def test_reopen_after_committed_goal_does_not_reevaluate_attempt(self):
        ref = self.start()
        self.assertEqual(self.controller.step().reason, 'job_goal_verified')
        committed_ac = self.h.ctrl.get_attempt(ref).ac
        calls = []
        verify = self.verify
        self.controller = self.build(acceptance=Acceptance(
            lambda request: calls.append(request.kind) or verify(request)))
        self.assertEqual(self.drive().reason, 'human_goal_verified')
        self.assertEqual(calls, ['run'])  # only the Run Goal is evaluated
        self.assertEqual(self.h.ctrl.get_attempt(ref).ac, committed_ac)
        self.assertEqual(len(self.native.requests), 1)

    def test_post_result_confirmation_same_poll_is_discarded(self):
        ref = self.start()  # log: RUNNING, Result(COMPLETED)
        confirmation = c.Confirmation(ref, 'q:post', c.Decision.CONFIRM,
                                      self.h.action, 'fixture', 'fixture', True)
        self.native.event(ref, c.ConfirmationEvent, confirmation)
        event_id = self.native.logs[ref][-1].event_id
        progress = self.controller.step()  # one drain: Result commits, then discard
        self.assertEqual(progress.reason, 'job_goal_verified')
        self.assertEqual(self.h.ctrl.checkpoint('r').cursor, event_id)
        self.assertIn(("post_terminal_event_discarded", ref, event_id),
                      self.controller.records)
        self.assertEqual(tuple(self.h.ctrl.waits('r')), ())
        self.assertEqual(self.native.responses, [])
        self.assertIsNone(self.h.ctrl.stop_origin('r'))
        self.assertFalse(any(isinstance(e, c.ConfirmationEvent)
                             for e in self.h.ctrl.history('r', 'events')))
        self.assertFalse(any(isinstance(r, tuple) and r and r[0] == 'controller_error'
                             for r in self.controller.records))
        self.assertEqual(self.h.ctrl.get_attempt(ref).state, c.State.COMPLETED)
        self.assertEqual(self.drive().reason, 'human_goal_verified')

    def test_post_result_confirmation_later_poll_is_discarded(self):
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        ref = self.start()
        self.assertEqual(self.controller.step().reason,
                         'terminal_cessation_unconfirmed')  # Result committed, held
        committed = self.h.ctrl.get_attempt(ref).result
        confirmation = c.Confirmation(ref, 'q:late', c.Decision.CONFIRM,
                                      self.h.action, 'fixture', 'fixture', True)
        self.native.event(ref, c.ConfirmationEvent, confirmation)
        event_id = self.native.logs[ref][-1].event_id
        self.native.stop_status = c.StopStatus.CONFIRMED
        self.h.stop_run()
        progress = self.controller.step()  # _stop drains the late event
        self.assertEqual((progress.state, progress.reason),
                         (c.State.FAILED, 'human_stop'))
        self.assertIn(("post_terminal_event_discarded", ref, event_id),
                      self.controller.records)
        self.assertEqual(self.h.ctrl.get_attempt(ref).result, committed)
        self.assertEqual(tuple(self.h.ctrl.waits('r')), ())
        self.assertEqual(self.native.responses, [])
        self.assertFalse(any(isinstance(e, c.ConfirmationEvent)
                             for e in self.h.ctrl.history('r', 'events')))
        self.assertFalse(any(isinstance(r, tuple) and r and r[0] == 'controller_error'
                             for r in self.controller.records))

    def test_post_result_confirmation_redelivery_skipped_after_reopen(self):
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        ref = self.start()
        confirmation = c.Confirmation(ref, 'q:again', c.Decision.CONFIRM,
                                      self.h.action, 'fixture', 'fixture', True)
        self.native.event(ref, c.ConfirmationEvent, confirmation)
        event_id = self.native.logs[ref][-1].event_id
        self.controller.step()  # discarded in the Result drain; Attempt held
        journal = self.h.ctrl.history('r', 'events')
        self.assertEqual(len(journal), 2)  # status + result only
        self.h.store.close()
        self.h.store = self.h.connect()
        self.h.refresh()
        self.controller = self.build()  # journal replay resets cursor to the Result
        self.native.stop_status = c.StopStatus.CONFIRMED
        self.h.stop_run()
        progress = self.controller.step()  # redelivered, discarded again
        self.assertEqual((progress.state, progress.reason),
                         (c.State.FAILED, 'human_stop'))
        self.assertIn(("post_terminal_event_discarded", ref, event_id),
                      self.controller.records)
        self.assertEqual(self.h.ctrl.history('r', 'events'), journal)
        self.assertEqual(len(self.native.requests), 1)  # never re-executed
        self.assertEqual(len(self.native.responses), 0)

    def test_post_result_reused_id_confirmation_is_integrity_violation(self):
        ref = self.start()  # log: RUNNING, Result(COMPLETED)
        reused = self.native.logs[ref][-1].event_id  # committed Result's event_id
        forged = c.ConfirmationEvent(ref, reused, c.Confirmation(
            ref, 'q:forged', c.Decision.CONFIRM, self.h.action,
            'forged', 'fixture', True))
        self.native.logs[ref].append(forged)
        progress = self.controller.step()
        self.assertEqual((progress.state, progress.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertIn(("integrity_violation", ref), self.controller.records)
        self.assertNotIn(("post_terminal_event_discarded", ref, reused),
                         self.controller.records)
        self.assertEqual(self.h.ctrl.get_attempt(ref).result,
                         self.native.logs[ref][1].result)  # byte-identical
        self.assertEqual(tuple(self.h.ctrl.waits('r')), ())
        self.assertEqual(self.native.responses, [])
        self.assertFalse(any(isinstance(e, c.ConfirmationEvent)
                             for e in self.h.ctrl.history('r', 'events')))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Harness(self.tmp.name)
        self.addCleanup(self.h.store.close)
        self.native = NativeFixture()
        self.verdicts, self.run_verdicts = [], []
        self.plans = [self.plan()]
        self.usage = UsageStore()
        self.controller = self.build()

    def plan(self, name="j", models=("a", "b"), adapter="adapter"):
        return JobPlan(c.Job("r", name, "create tested output " + name, ("output checked",)),
            self.h.action, "write-output", USE, tuple(replace(self.h.conditions, model=m, adapter=adapter)
            for m in models), usage_window="comparable-fixture-window")

    def verify(self, request):
        choices = self.verdicts if request.kind == "job" else self.run_verdicts
        verdict = choices.pop(0) if choices else "pass"
        return CheckEvidence(body_digest(request), Finding(verdict, ("fixture:goal-check",)),
            tuple(Finding("pass", ("fixture:artifact-check",))
                  for _ in (request.job.acceptance_criteria if request.job else ())))

    def build(self, **overrides):
        args = dict(state=self.h.ctrl, judgment=self.h.judgment, catalog=catalog(),
            usage=self.usage, adapters={"adapter": self.native}, acceptance=Acceptance(self.verify),
            planner=lambda *args: self.plans.pop(0) if self.plans else None, clock=lambda: NOW)
        args.update(overrides)
        return Controller("r", **args)

    def drive(self, limit=30):
        for _ in range(limit):
            progress = self.controller.step()
            if progress.state in c.TERMINAL or progress.state == c.State.WAITING_HUMAN:
                return progress
        self.fail("finite progression failed")

    def start(self):
        self.assertEqual(self.controller.step().reason, "next_job")
        self.assertEqual(self.controller.step().reason, "execute_receipt")
        return self.native.requests[-1].ref

    def test_stop_committed_during_add_job_finishes_human_stop(self):
        original = self.h.ctrl.add_job
        def inject(job, *args, **kwargs):
            self.h.stop_run()
            return original(job, *args, **kwargs)
        self.h.ctrl.add_job = inject
        try:
            progress = self.controller.step()
            self.assertEqual(progress.reason, 'job_snapshot_changed')
            self.assertNotIn(progress.state, c.TERMINAL)
        finally:
            self.h.ctrl.add_job = original
        final = self.drive()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'human_stop'))
        self.assertEqual(self.h.ctrl.stop_origin('r'), 'intake')
        self.assertEqual(self.h.ctrl.get_run('r').final_reason, 'human_stop')
        self.assertEqual(self.native.requests, [])
        self.assertEqual(self.h.ctrl.attempts('r'), ())

    def test_stop_committed_during_no_route_routing_retention(self):
        self.controller = self.build(catalog=Catalog())
        self.assertEqual(self.controller.step().reason, 'next_job')
        original = self.h.ctrl.record_routing
        def inject(routing):
            self.h.stop_run()
            return original(routing)
        self.h.ctrl.record_routing = inject
        try:
            progress = self.controller.step()
            self.assertEqual(progress.reason, 'routing_snapshot_changed')
            self.assertNotIn(progress.state, c.TERMINAL)
        finally:
            self.h.ctrl.record_routing = original
        final = self.drive()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'human_stop'))
        self.assertEqual(self.native.requests, [])
        self.assertEqual(self.h.ctrl.attempts('r'), ())

    def test_stop_committed_during_preflight_wait_open(self):
        self.h.confirm = True
        self.assertEqual(self.controller.step().reason, 'next_job')
        original = self.h.ctrl.open_wait
        def inject(*args, **kwargs):
            self.h.stop_run()
            return original(*args, **kwargs)
        self.h.ctrl.open_wait = inject
        try:
            progress = self.controller.step()
            self.assertEqual(progress.reason, 'routing_snapshot_changed')
            self.assertNotIn(progress.state, c.TERMINAL)
        finally:
            self.h.ctrl.open_wait = original
        final = self.drive()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'human_stop'))
        self.assertEqual(self.h.ctrl.waits('r'), ())
        self.assertEqual(self.native.requests, [])

    def test_committed_stop_supersedes_controller_fault_without_attempt(self):
        def planner(*args):
            self.h.stop_run()
            raise ValueError('planner bug')
        controller = self.build(planner=planner)
        final = controller.step()
        # The mid-step committed stop is decisive: FAILED/human_stop, never
        # ERROR/controller_error, and no fabricated dispatch.
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'human_stop'))
        self.assertEqual(self.h.ctrl.get_run('r').final_reason, 'human_stop')
        self.assertEqual(self.h.ctrl.stop_origin('r'), 'intake')
        self.assertEqual(self.native.requests, [])

    def test_checkpoint_cas_loss_does_not_mask_progress_or_propagate(self):
        original = self.h.ctrl.save_checkpoint
        calls = []
        def flaky(*args, **kwargs):
            if not calls:
                calls.append(1)
                raise Conflict('stale revision; read and rejudge')
            return original(*args, **kwargs)
        self.h.ctrl.save_checkpoint = flaky
        try:
            self.assertEqual(self.controller.step().reason, 'next_job')
        finally:
            self.h.ctrl.save_checkpoint = original
        self.assertEqual(calls, [1])
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertIsNotNone(self.h.ctrl.checkpoint('r'))

    def test_completed_failed_ac_retry_then_goal_and_separate_history(self):
        self.verdicts = ["fail", "pass"]
        final = self.drive()
        self.assertEqual(final.state, c.State.COMPLETED)
        self.assertEqual(len(self.native.requests), 2)
        first, second = [r.ref for r in self.native.requests]
        self.assertNotEqual(first, second)
        self.assertEqual(self.h.ctrl.get_attempt(first).result.status, c.State.COMPLETED)
        self.assertEqual(self.h.ctrl.get_attempt(first).ac.verdict, "fail")
        self.assertEqual([r.kind for r in self.controller.records if isinstance(r, Transition)], ["execute", "retry"])
        self.assertEqual(len(self.h.ctrl.history("r", "ac_history")), 2)
        self.assertEqual(self.controller.step(), final)
        self.assertEqual(len(self.native.requests), 2)
        # Final Goal is durable, independently of historical Attempt failures.
        self.assertEqual(self.h.ctrl.get_run("r").state, c.State.COMPLETED)

    def test_reroute_after_pair_limit_without_hiding_old_failure(self):
        self.verdicts = ["fail", "fail", "pass"]
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual([r.conditions.model for r in self.native.requests], ["a", "a", "b"])
        self.assertEqual([r.kind for r in self.controller.records if isinstance(r, Transition)],
                         ["execute", "retry", "reroute"])

    def test_explicit_model_never_falls_back(self):
        self.plans = [replace(self.plan(), explicit_model="a")]
        self.verdicts = ["fail"] * 5
        self.assertEqual(self.drive().state, c.State.FAILED)
        self.assertEqual([r.conditions.model for r in self.native.requests], ["a", "a"])

    def test_job_attempt_limit_and_run_job_limit(self):
        self.h.ctrl.set_limits("r", Limits(attempts_per_job=3), self.h.rev())
        self.verdicts = ["fail"] * 6
        self.assertEqual(self.drive().reason, "job_attempt_limit")
        self.assertEqual(len(self.native.requests), 3)

    def test_next_job_requires_independent_run_goal(self):
        self.plans = [self.plan("j1"), self.plan("j2")]
        self.run_verdicts = ["incomplete", "pass"]
        final = self.drive()
        self.assertEqual(final.state, c.State.COMPLETED)
        self.assertEqual([j.job.job_id for j in final.jobs], ["j1", "j2"])

    def test_run_limit_stops_replanning(self):
        self.h.ctrl.set_limits("r", Limits(jobs=1), self.h.rev())
        self.plans = [self.plan("j1"), self.plan("j2")]
        self.run_verdicts = ["fail"]
        final = self.drive()
        self.assertEqual(final.reason, "run_job_limit")
        self.assertEqual(len(self.native.requests), 1)

    def test_no_catalog_or_unverified_environment_never_executes(self):
        self.controller = self.build(catalog=Catalog())
        self.assertEqual(self.drive().state, c.State.FAILED)
        self.assertEqual(self.native.requests, [])

    def test_host_protection_unknown_waits_without_attempt(self):
        self.h.protection = False
        final = self.drive()
        self.assertEqual(final.state, c.State.WAITING_HUMAN)
        self.assertEqual(self.native.requests, [])
        waits = [r for r in self.controller.records if isinstance(r, c.WaitingHuman)]
        self.assertEqual(len(waits), 1)
        self.assertIsNone(waits[0].ref.attempt_id)
        self.assertEqual(waits[0].deadline, "2026-09-29T00:00:00+00:00")

    def test_preflight_approval_rejudged_and_rejection_not_rerouted(self):
        self.h.confirm = True
        self.assertEqual(self.drive().state, c.State.WAITING_HUMAN)
        wait = next(r for r in self.controller.records if isinstance(r, c.WaitingHuman))
        self.h.answer(wait, c.HumanAnswer.REJECT)
        self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        self.assertEqual(self.native.requests, [])

    def test_current_usage_tie_and_stale_usage_fallback(self):
        for model, amount in (("a", 10), ("b", 80)):
            self.usage.update(c.Usage(model, "adapter", amount, NOW.isoformat(), "fixture:usage", "comparable-fixture-window"))
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(self.native.requests[0].conditions.model, "b")

    def test_stale_usage_does_not_promote_route(self):
        for model, amount in (("a", 10), ("b", 80)):
            self.usage.update(c.Usage(model, "adapter", amount, (NOW-timedelta(days=1)).isoformat(),
                                     "fixture:old", "comparable-fixture-window"))
        self.drive()
        self.assertEqual(self.native.requests[0].conditions.model, "a")

    def test_catalog_only_model_addition_uses_existing_adapter(self):
        self.plans = [self.plan(models=("new-model",))]
        self.controller = self.build(catalog=catalog(("new-model",)))
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(self.native.requests[0].conditions.model, "new-model")

    def test_callback_current_judgment_auto_relay_then_independent_ac(self):
        self.native.confirmation = self.h.action
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(len(self.native.responses), 1)
        self.assertEqual(self.native.responses[0].resolution, c.Resolution.ALLOW)
        self.assertEqual(len(self.native.requests), 1)

    def test_callback_wait_approve_and_stop_run(self):
        self.native.confirmation = self.h.action
        self.start()
        self.h.confirm = True
        self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        wait = next(r for r in self.controller.records if isinstance(r, c.WaitingHuman))
        self.h.answer(wait)
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(len(self.native.responses), 1)

    def test_unknown_stop_does_not_retry_or_claim_cessation(self):
        self.native.confirmation = self.h.action
        self.start()
        self.h.confirm = True
        self.controller.step()
        wait = next(r for r in self.controller.records if isinstance(r, c.WaitingHuman))
        self.h.answer(wait, c.HumanAnswer.STOP_RUN)
        self.native.stop_status = c.StopStatus.REQUESTED
        p = self.controller.step()
        self.assertEqual((p.state, p.cessation_confirmed), (c.State.RUNNING, False))
        self.assertEqual(self.native.responses, [])
        self.native.stop_status = c.StopStatus.CONFIRMED
        # Confirmed cessation without a Result is a held state, never a
        # synthesized failure: no Result, AC or retry is invented.
        held = self.controller.step()
        self.assertEqual((held.state, held.reason, held.cessation_confirmed),
                         (c.State.RUNNING, 'stop_result_missing', True))
        self.assertIsNone(self.h.ctrl.get_attempt(
            self.native.requests[0].ref).result)
        self.assertEqual(self.native.responses, [])
        # The real Result then settles into the committed stop terminal.
        self.native.finish(self.native.requests[0].ref, c.State.FAILED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason, final.cessation_confirmed),
                         (c.State.FAILED, 'human_stop', True))
        self.assertEqual(len(self.native.requests), 1)

    def test_timely_receipt_applied_by_scheduler_continues_same_attempt(self):
        self.native.confirmation = self.h.action
        ref = self.start()
        self.h.confirm = True
        self.controller.step()
        wait = next(r for r in self.controller.records if isinstance(r, c.WaitingHuman))
        self.h.now = '2026-09-28T23:59:59.999999Z'
        response = self.h.response(wait)
        self.h.intake.record_receipt(response, response.authenticated_source_ref)
        self.h.now = '2026-09-29T00:00:01Z'
        self.assertIsNone(self.h.store.scheduler().expire_wait(wait.ref, wait.request_id, self.h.rev()))
        self.controller = self.build()
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(len(self.native.requests), 1)
        self.assertEqual(self.native.responses[0].ref, ref)
        self.assertEqual(self.h.ctrl.history('r', 'timeouts'), ())

    def test_timeout_preserved_and_unknown_stop_blocks_new_attempt(self):
        self.native.confirmation = self.h.action
        ref = self.start()
        self.h.confirm = True
        self.controller.step()
        wait = next(r for r in self.controller.records if isinstance(r, c.WaitingHuman))
        self.h.now = wait.deadline
        self.h.store.scheduler().expire_wait(wait.ref, wait.request_id, self.h.rev())
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        self.assertEqual(self.controller.step().reason, "stop_unconfirmed")
        self.assertEqual(len(self.native.requests), 1)
        self.native.stop_status = c.StopStatus.CONFIRMED
        # Confirmed cessation without a Result holds truthfully; the timeout
        # stays a wait fact, never a fabricated Result.
        held = self.controller.step()
        self.assertEqual((held.reason, held.cessation_confirmed),
                         ("stop_result_missing", True))
        self.assertIsNone(self.h.ctrl.get_attempt(ref).result)
        self.assertEqual(len(self.native.requests), 1)
        # The genuine Result then settles; the bounded continuation still
        # finds no alternative plan and the timeout history is preserved.
        self.native.finish(ref, c.State.FAILED)
        self.assertEqual(self.controller.step().reason, "no_alternative_plan")
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.reason,
                         "fixture_failure")
        self.assertEqual(len(self.h.ctrl.history("r", "timeouts")), 1)

    def test_check_failure_does_not_leak_or_trigger_retry(self):
        def broken(request):
            raise RuntimeError("SECRET verifier error")
        self.controller = self.build(acceptance=Acceptance(broken))
        self.start()
        self.assertEqual(self.controller.step().reason, "controller_error_stop_required")
        self.assertEqual(self.controller.step().state, c.State.ERROR)
        self.assertNotIn("SECRET", repr(self.controller.records))
        self.assertEqual(len(self.native.requests), 1)

    def test_blocked_ac_does_not_spend_worker_attempt(self):
        self.verdicts = ["blocked"]
        self.assertEqual(self.drive().reason, "job_ac_blocked")
        self.controller.step()
        self.assertEqual(len(self.native.requests), 1)

    def test_reconstruction_polls_existing_attempt_without_duplicate_execute(self):
        ref = self.start()
        self.controller = self.build()
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual([r.ref for r in self.native.requests], [ref])

    def test_completed_turn_without_cessation_blocks_ac_and_retry(self):
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        ref = self.start()
        progress = self.controller.step()
        self.assertEqual(progress.reason, "terminal_cessation_unconfirmed")
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.status, c.State.COMPLETED)
        self.assertEqual(self.h.ctrl.get_attempt(ref).ac.verdict, "blocked")
        self.controller.step()
        self.assertEqual(len(self.native.requests), 1)
        self.native.stop_status = c.StopStatus.CONFIRMED
        self.assertEqual(self.drive().state, c.State.COMPLETED)

    def test_fresh_judgment_after_routing_blocks_changed_protection(self):
        self.controller.step()
        judge = self.h.judgment.judge
        def changed(request):
            if request.ref.attempt_id:
                self.h.protection = False
            return judge(request)
        self.h.judgment.judge = changed
        self.assertEqual(self.controller.step().reason, "dispatch_rejudgment_not_normal")
        self.assertEqual(self.native.requests, [])

    def test_ac_check_cannot_ignore_concurrent_state_change(self):
        # A trusted intake mutation during verification invalidates its snapshot.
        verify = self.verify
        def changed(request):
            result = verify(request)
            if request.kind == "job":
                self.h.ctrl.set_limits("r", Limits(jobs=19), self.h.rev())
            return result
        self.controller = self.build(acceptance=Acceptance(changed))
        self.start()
        self.assertEqual(self.controller.step().reason, "ac_snapshot_changed")
        self.assertEqual(self.h.ctrl.history("r", "ac_history"), ())

    def test_cross_attempt_event_stops_without_acceptance(self):
        ref = self.start()
        self.native.logs[ref] = [c.ResultEvent(c.AttemptRef("other", "j", "a"), "bad",
            c.Result(c.AttemptRef("other", "j", "a"), c.State.COMPLETED))]
        self.assertEqual(self.controller.step().reason, "controller_error_stop_required")
        self.assertIsNone(self.h.ctrl.get_attempt(ref).result)
        # Confirmed stop without a Result holds; the permanently corrupt
        # event keeps blocking the drain, so no FAILED Result or ERROR
        # terminal is ever invented — the hold is stable across steps.
        for _ in range(2):
            held = self.controller.step()
            self.assertEqual((held.state, held.reason, held.cessation_confirmed),
                             (c.State.RUNNING, 'stop_result_missing', True))
        self.assertIsNone(self.h.ctrl.get_attempt(ref).result)
        self.assertNotIn(self.h.ctrl.get_run('r').state, c.TERMINAL)

    def test_execute_error_does_not_reroute_until_cessation(self):
        self.native.execute_status = c.OperationStatus.ERROR
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        self.start()
        self.assertEqual(self.controller.step().reason, "stop_unconfirmed")
        self.assertEqual(len(self.native.requests), 1)

    def test_independent_artifact_inspection_rejects_worker_completed_claim(self):
        artifact = Path(self.tmp.name) / "output.txt"
        execute = self.native.execute
        def write_then_execute(request):
            artifact.write_text("wrong" if not self.native.requests else "expected")
            return execute(request)
        self.native.execute = write_then_execute
        def inspect(request):
            # Actual file inspection outside the Worker/Adapter result path.
            verdict = "pass" if artifact.read_text() == "expected" else "fail"
            finding = Finding(verdict, ("fixture:inspected-output-content",))
            return CheckEvidence(body_digest(request), finding,
                                 (finding,) if request.kind == "job" else ())
        self.controller = self.build(acceptance=Acceptance(inspect))
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        history = self.h.ctrl.history("r", "ac_history")
        self.assertEqual([(r.status, ac.verdict) for r, ac in history],
                         [(c.State.COMPLETED, "fail"), (c.State.COMPLETED, "pass")])

    def test_preflight_approve_requires_current_protection(self):
        self.h.confirm = True
        self.drive()
        wait = next(r for r in self.controller.records if isinstance(r, c.WaitingHuman))
        self.h.answer(wait)
        self.h.protection = False
        self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        self.assertEqual(self.native.requests, [])
        self.h.protection = True
        self.assertEqual(self.drive().state, c.State.COMPLETED)

    def test_hard_deny_and_unknown_environment_never_launch(self):
        self.h.deny = True
        self.assertEqual(self.drive().reason, "job_containment_not_normal")
        self.assertEqual(self.native.requests, [])

    def test_verified_model_different_environment_not_promoted(self):
        plan = self.plan()
        self.plans = [replace(plan, conditions=tuple(replace(v, environment_ref="unverified")
                                                     for v in plan.conditions))]
        self.assertEqual(self.drive().state, c.State.FAILED)
        self.assertEqual(self.native.requests, [])

    def test_default_five_attempt_limit_even_with_more_catalog_routes(self):
        self.plans = [self.plan(models=("a", "b", "c"))]
        self.verdicts = ["fail"] * 10
        self.controller = self.build(catalog=catalog(("a", "b", "c")))
        self.assertEqual(self.drive().reason, "job_attempt_limit")
        self.assertEqual([r.conditions.model for r in self.native.requests], ["a", "a", "b", "b", "c"])


class CodexControllerTests(unittest.TestCase):
    """Use the actual Codex Adapter parser/handshake, without a Native process."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Harness(self.tmp.name)
        self.addCleanup(self.h.store.close)
        self.wire = Wire()
        self.adapter = CodexAdapter(verify_host=lambda *args: None,
                                   transport_factory=lambda _: self.wire)
        self.addCleanup(self.adapter.close)
        self.conditions = replace(self.h.conditions, model="synthetic-model", adapter=ADAPTER,
                                  workspace=self.tmp.name)
        plan = JobPlan(c.Job("r", "j", "synthetic task", ("check artifact",)), self.h.action,
                       "write-output", USE, (self.conditions,))
        self.checks = []
        def check(request):
            self.checks.append(request)
            return CheckEvidence(body_digest(request), Finding("pass", ("fixture:check",)),
                (Finding("pass", ("fixture:check",)),) if request.job else ())
        self.controller = Controller("r", state=self.h.ctrl, judgment=self.h.judgment,
            catalog=catalog(("synthetic-model",), ADAPTER), usage=UsageStore(),
            adapters={ADAPTER: self.adapter}, acceptance=Acceptance(check),
            planner=lambda *args: plan, clock=lambda: NOW)
        self.controller.step()
        self.ref = self.controller.step().active

    def running(self):
        self.wire.reply("initialize", {"userAgent": "synthetic"})
        self.controller.step()
        self.wire.reply("thread/start", {"thread": {"id": "fixture-thread"},
            "model": "synthetic-model", "modelProvider": "openai", "cwd": self.tmp.name,
            "approvalPolicy": "on-request", "approvalsReviewer": "user", "sandbox": {"type": "readOnly"}})
        self.controller.step()
        self.wire.reply("turn/start", {"turn": {"id": "fixture-turn", "status": "inProgress"}})
        self.controller.step()

    def test_real_adapter_completed_turn_does_not_promote_cessation_or_ac(self):
        self.running()
        self.wire.incoming.append({"method": "turn/completed", "params": {
            "threadId": "fixture-thread", "turn": {"id": "fixture-turn", "status": "completed"}}})
        progress = self.controller.step()
        self.assertEqual(progress.reason, "terminal_cessation_unconfirmed")
        attempt = self.h.ctrl.get_attempt(self.ref)
        self.assertEqual(attempt.result.status, c.State.COMPLETED)
        self.assertEqual(attempt.ac.verdict, "blocked")
        self.assertEqual(self.checks, [])
        self.assertEqual(sum(m.get("method") == "turn/start" for m in self.wire.sent), 1)

    def test_real_adapter_unknown_callback_waits_then_stop_stays_unconfirmed(self):
        self.running()
        self.wire.incoming.append({"id": 3, "method": COMMAND_APPROVAL, "params": {
            "threadId": "fixture-thread", "turnId": "fixture-turn", "itemId": "fixture-item",
            "command": "printf fixture", "cwd": self.tmp.name, "environmentId": "local"}})
        self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        wait = next(r for r in self.controller.records if isinstance(r, c.WaitingHuman))
        self.assertFalse(wait.action.scope.known)
        self.h.answer(wait, c.HumanAnswer.STOP_RUN)
        self.assertEqual(self.controller.step().reason, "stop_unconfirmed")
        self.assertFalse(any(m.get("result", {}).get("decision") == "accept" for m in self.wire.sent))

    def test_real_adapter_bootstrap_stop_confirms_without_submitting_turn(self):
        # A separate preflight wait gives authenticated stop_run ingress.
        self.h.job("stop-question")
        self.h.confirm = True
        request = self.h.request(job="stop-question")
        decision = self.h.judgment.judge(request)
        wait = c.WaitingHuman(request.ref, "stop-q", request.action, decision.decision,
                              decision.reason, "2026-09-29T00:00:00Z")
        self.h.ctrl.open_wait(wait, request.method, self.h.rev(), decision.decision_id)
        self.h.answer(wait, c.HumanAnswer.STOP_RUN)
        final = self.controller.step()
        self.assertEqual((final.state, final.cessation_confirmed), (c.State.FAILED, True))
        self.assertFalse(any(m.get("method") == "turn/start" for m in self.wire.sent))


if __name__ == "__main__":
    unittest.main()
