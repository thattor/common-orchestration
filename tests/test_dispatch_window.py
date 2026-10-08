"""Regression: a transient store failure after begin_attempt commits must not
strand the admitted Attempt untracked in memory.

Real state/Judgment/routing/AC seams; synthetic Native and host evidence.
Nothing here establishes production isolation or promotes a live route.
"""
from dataclasses import replace
from datetime import datetime, timezone
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.controller import Controller, JobPlan, Transition
from co_v4.state import StoreUnavailable, body_digest
from co_v4.usage import UsageStore
from test_state import Harness


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
        self.requests, self.logs, self.stops = [], {}, []
        self.auto_complete = True
        self.stop_status = c.StopStatus.CONFIRMED
        self.execute_status = c.OperationStatus.ACCEPTED

    def event(self, ref, cls, *args):
        log = self.logs.setdefault(ref, [])
        log.append(cls(ref, ref.attempt_id + ":" + str(len(log)), *args))

    def finish(self, ref, state=c.State.COMPLETED):
        self.event(ref, c.ResultEvent, c.Result(ref, state,
            None if state == c.State.COMPLETED else "fixture_failure"))

    def execute(self, request):
        self.requests.append(request)
        self.logs[request.ref] = []
        self.event(request.ref, c.StatusEvent, c.State.RUNNING)
        if self.auto_complete:
            self.finish(request.ref)
        return c.OperationReply(request.ref, self.execute_status, "fixture receipt")

    def events(self, ref, after=None):
        log = self.logs.get(ref, [])
        if after is None:
            return tuple(log)
        index = next(i for i, e in enumerate(log) if e.event_id == after)
        return tuple(log[index + 1:])

    def respond(self, response):
        return c.OperationReply(response.ref, c.OperationStatus.ACCEPTED, "fixture relay")

    def stop(self, ref):
        self.stops.append(ref)
        return c.StopReply(ref, self.stop_status, "fixture stop",
            "fixture:cessation" if self.stop_status == c.StopStatus.CONFIRMED else None)


class DispatchWindowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Harness(self.tmp.name)
        self.addCleanup(self.h.store.close)
        self.native = NativeFixture()
        self.verdicts, self.run_verdicts = [], []
        self.plans = [self.plan()]
        self.controller = self.build()

    def plan(self, name="j"):
        return JobPlan(c.Job("r", name, "create tested output " + name, ("output checked",)),
            self.h.action, "write-output", USE, tuple(replace(self.h.conditions, model=m)
            for m in ("a", "b")), usage_window="comparable-fixture-window")

    def verify(self, request):
        choices = self.verdicts if request.kind == "job" else self.run_verdicts
        verdict = choices.pop(0) if choices else "pass"
        return CheckEvidence(body_digest(request), Finding(verdict, ("fixture:goal-check",)),
            tuple(Finding("pass", ("fixture:artifact-check",))
                  for _ in (request.job.acceptance_criteria if request.job else ())))

    def build(self, **overrides):
        args = dict(state=self.h.ctrl, judgment=self.h.judgment, catalog=catalog(),
            usage=UsageStore(), adapters={"adapter": self.native},
            acceptance=Acceptance(self.verify),
            planner=lambda *args: self.plans.pop(0) if self.plans else None,
            clock=lambda: NOW)
        args.update(overrides)
        return Controller("r", **args)

    def drive(self, limit=30):
        for _ in range(limit):
            progress = self.controller.step()
            if progress.state in c.TERMINAL or progress.state == c.State.WAITING_HUMAN:
                return progress
        self.fail("finite progression failed")

    def settle_first_attempt(self):
        self.verdicts = ["fail"]
        self.assertEqual(self.controller.step().reason, "next_job")
        self.assertEqual(self.controller.step().reason, "execute_receipt")
        first = self.native.requests[-1].ref
        self.assertEqual(self.controller.step().reason, "job_goal_unmet")
        return first

    def test_transient_lookup_failure_after_admission_keeps_attempt_tracked(self):
        first = self.settle_first_attempt()
        admitted, fired = [], []
        begin, lookup = self.h.ctrl.begin_attempt, self.h.ctrl.get_attempt

        def begin_then_arm(request, *args, **kwargs):
            result = begin(request, *args, **kwargs)
            admitted.append(request.ref)
            return result

        def transient(ref):
            if admitted and not fired:
                fired.append(ref)
                raise StoreUnavailable("transient store unavailable")
            return lookup(ref)

        self.h.ctrl.begin_attempt = begin_then_arm
        self.h.ctrl.get_attempt = transient
        # Baseline before the global failure: the committed checkpoint and
        # the Native stop log as they stood after the first settlement.
        baseline = self.h.ctrl.checkpoint("r")
        stops = tuple(self.native.stops)
        # begin_attempt commits; the first post-commit journal read is the
        # previous-Attempt lookup for retry/reroute classification. That
        # StoreUnavailable is a GLOBAL failure: step() re-raises it
        # unchanged, skips the final _save, and performs no Native stop,
        # kill, lease release, finalization or checkpoint write on the
        # way out.
        with self.assertRaises(StoreUnavailable):
            self.controller.step()
        self.h.ctrl.begin_attempt, self.h.ctrl.get_attempt = begin, lookup
        # Exact proof of the no-write/no-Native contract: the committed
        # checkpoint is byte-identical, no stop was requested on either
        # Attempt, and the Run is not terminal.
        self.assertEqual(self.h.ctrl.checkpoint("r"), baseline)
        self.assertEqual(tuple(self.native.stops), stops)
        self.assertNotIn(self.h.ctrl.get_run("r").state, c.TERMINAL)
        self.assertEqual(fired, [first])
        self.assertEqual(len(admitted), 1)
        second = admitted[0]
        self.assertNotEqual(second, first)
        # The committed Attempt was tracked as active before the fallible
        # read; the discarded Controller's in-memory view still names it.
        self.assertEqual(self.controller._active, second)
        # No Native execute, no fabricated NeverStarted receipt or settlement.
        self.assertEqual([r.ref for r in self.native.requests], [first])
        self.assertIsNone(self.h.ctrl.execute_receipt(second))
        self.assertIsNone(self.h.ctrl.attempt_settlement(second))
        # Explicit restart only: the same Controller must NOT step after a
        # global failure. A fresh Controller over the persisted state
        # recovers the unresolved committed admission — no execute receipt
        # — into recovery_ambiguous_send, then performs the real stop; an
        # honest hold while no real Result exists, then the real Result
        # settles into the committed recovery terminal. No retry, no
        # second Native execute, no fabricated Result.
        recovered = self.build()
        self.assertEqual(recovered._active, second)
        # Per-Attempt drain state must not carry the first Attempt's
        # cursor/callbacks across the recovery rebind.
        self.assertIsNone(recovered._cursor)
        self.assertEqual(recovered._callbacks, {})
        self.assertEqual(recovered._answered, set())
        held = recovered.step()
        self.assertEqual((held.state, held.reason, held.cessation_confirmed),
                         (c.State.RUNNING, "stop_result_missing", True))
        self.assertEqual(held.active, second)
        self.assertEqual(self.native.stops, [first, second])
        self.native.finish(second, c.State.FAILED)
        final = recovered.step()
        self.assertEqual((final.state, final.reason, final.cessation_confirmed),
                         (c.State.FAILED, "recovery_ambiguous_send", True))
        self.assertIsNone(final.active)
        self.assertEqual(self.h.ctrl.get_attempt(second).result.status, c.State.FAILED)
        self.assertIsNotNone(self.h.ctrl.attempt_settlement(second))
        self.assertEqual([r.ref for r in self.native.requests], [first])
        self.assertEqual(len(self.h.ctrl.attempts("r")), 2)
        self.assertEqual(recovered.step(), final)

    def test_retry_dispatch_unchanged(self):
        self.verdicts = ["fail", "pass"]
        final = self.drive()
        self.assertEqual(final.state, c.State.COMPLETED)
        self.assertEqual(len(self.native.requests), 2)
        self.assertEqual([r.kind for r in self.controller.records
                          if isinstance(r, Transition)], ["execute", "retry"])
        self.assertEqual(len(self.h.ctrl.history("r", "ac_history")), 2)


if __name__ == "__main__":
    unittest.main()
