"""Real stop truth: no controller-authored Result on any stop path.

A real CONFIRMED StopReply without a real Result holds as
stop_result_missing (cessation True); the Attempt, cursor and first
decisive stop reason stay held until a real Result settles. Drives the
real v4 Controller/state/Judgment paths through the shared Harness and
the deterministic NativeFixture; no transports, providers, SDK or Native
work are involved. Fixtures only — nothing here is a claim that these
tests were executed.
"""
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.controller import Controller, JobPlan
from co_v4.state import body_digest
from co_v4.usage import UsageStore
from test_state import Harness
from test_controller import NOW, USE, NativeFixture, catalog


class StopTruthTests(unittest.TestCase):
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

    def human_stop(self, source='stop:1'):
        self.h.authenticate(source,
                            {'operation': 'stop_run', 'run_id': 'r'})
        self.h.intake.record_stop_request('r', source)

    def held_missing(self, ref):
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertEqual(attempt.stop_reply.status, c.StopStatus.CONFIRMED)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.ac)
        self.assertIsNone(attempt.output)
        self.assertIsNone(attempt.collection_failure)
        self.assertFalse([e for e in self.h.ctrl.history('r', 'events')
                          if isinstance(e, c.ResultEvent)])
        self.assertEqual(self.h.ctrl.history('r', 'ac_history'), ())
        self.assertEqual(self.h.ctrl.history('r', 'job_goals'), ())
        self.assertEqual(self.h.ctrl.history('r', 'job_failures'), ())
        self.assertNotIn(ref, self.h.ctrl.history('r', 'released_attempts'))
        self.assertNotIn(self.h.ctrl.get_run('r').state, c.TERMINAL)

    def test_human_stop_confirmed_no_result_held_truthfully(self):
        # Real CONFIRMED StopReply, no real Result: held, nothing
        # synthesized. The committed reply is the adapter-side capacity
        # proof; state settlement/release stays distinct.
        self.native.auto_complete = False
        ref = self.start()
        self.human_stop()
        progress = self.controller.step()
        self.assertEqual((progress.state, progress.reason),
                         (c.State.RUNNING, 'stop_result_missing'))
        self.assertIs(progress.cessation_confirmed, True)
        self.held_missing(ref)
        self.assertEqual(self.native.stops, [ref])
        # Stable hold; a committed CONFIRMED reply is never re-requested.
        for _ in range(2):
            progress = self.controller.step()
            self.assertEqual((progress.state, progress.reason),
                             (c.State.RUNNING, 'stop_result_missing'))
        self.assertEqual(self.native.stops, [ref])
        self.assertEqual(len(self.native.requests), 1)

    def test_pending_instruct_waits_for_real_result_then_replans(self):
        # An applied INSTRUCT persists but cannot run until settlement;
        # only a real Result lets the settled continuation replan.
        self.native.confirmation = self.h.action
        replans = []
        self.controller = self.build(
            replanner=lambda *args: replans.append(args) or self.plan())
        ref = self.start()
        self.h.confirm = True
        self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        wait = next(r for r in self.controller.records
                    if isinstance(r, c.WaitingHuman))
        receipt = self.h.answer(wait, c.HumanAnswer.INSTRUCT,
                                detail='fixture instruction')
        self.assertEqual(receipt.disposition, 'applied')
        progress = self.controller.step()
        self.assertEqual((progress.state, progress.reason),
                         (c.State.RUNNING, 'stop_result_missing'))
        self.held_missing(ref)
        self.controller.step()
        self.assertEqual(replans, [])
        self.assertEqual(len(self.native.requests), 1)
        self.native.finish(ref, c.State.FAILED)
        progress = self.controller.step()
        self.assertEqual(progress.reason, 'replanned')
        self.assertEqual(len(replans), 1)
        self.assertIn(ref, self.h.ctrl.history('r', 'released_attempts'))
        self.assertIsNone(self.h.ctrl.get_attempt(ref).ac)
        self.assertEqual(self.h.ctrl.history('r', 'job_goals'), ())
        # The settled continuation replans, but the same-action dispatch
        # still requires a fresh Human confirmation: protection is never
        # silently carried forward into the new Attempt.
        self.assertEqual(self.controller.step().reason,
                         'policy_confirmation_required')
        self.assertEqual(len(self.native.requests), 1)
        wait = next(r for r in reversed(self.controller.records)
                    if isinstance(r, c.WaitingHuman))
        self.h.answer(wait, name='replan-confirm')
        self.assertEqual(self.controller.step().reason, 'execute_receipt')
        self.assertEqual(len(self.native.requests), 2)

    def test_channel_error_audits_only_and_restart_resumes_drain(self):
        # A broken event channel after CONFIRMED is audit only: no
        # controller_error finalization, decisive reason kept, real drain
        # retried from the persisted cursor after a host restart with no
        # duplicate stop call.
        self.native.auto_complete = False
        ref = self.start()
        self.human_stop()
        original = self.native.events
        def broken(ref_, after=None):
            raise RuntimeError('fixture channel broken')
        self.native.events = broken
        progress = self.controller.step()
        self.assertEqual((progress.state, progress.reason),
                         (c.State.RUNNING, 'stop_result_missing'))
        self.assertIs(progress.cessation_confirmed, True)
        self.assertIn(('stopped_event_channel_error', ref),
                      self.controller.records)
        self.held_missing(ref)
        self.native.events = original
        self.native.finish(ref, c.State.FAILED)
        self.controller = self.build()  # serialized host restart
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'human_stop'))
        self.assertTrue(final.cessation_confirmed)
        self.assertEqual(self.native.stops, [ref])
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.reason,
                         'fixture_failure')
        self.assertEqual(self.h.ctrl.get_run('r').final_reason,
                         'human_stop')

    def test_late_completed_result_finalizes_stop_never_evaluated(self):
        # A late real Result — even COMPLETED — is settlement evidence
        # only after a committed stop: never AC, output or publication.
        self.native.auto_complete = False
        ref = self.start()
        self.human_stop()
        self.assertEqual(self.controller.step().reason,
                         'stop_result_missing')
        self.native.finish(ref, c.State.COMPLETED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'human_stop'))
        self.assertTrue(final.cessation_confirmed)
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertEqual(attempt.result.status, c.State.COMPLETED)
        self.assertIsNone(attempt.ac)
        self.assertIsNone(attempt.output)
        self.assertEqual(self.h.ctrl.history('r', 'ac_history'), ())
        self.assertEqual(self.h.ctrl.history('r', 'job_goals'), ())
        self.assertIsNone(self.h.ctrl.get_run('r').output_selection)
        self.assertEqual(len(self.native.requests), 1)

    def test_divergent_status_after_result_latches_fatal_not_error(self):
        # A duplicate event_id whose content contradicts the committed
        # journal is fatal even arriving after the Result: the late-status
        # skip may not mask it (equal replay safe, divergent fatal).
        ref = self.start()  # auto_complete queues the real Result
        self.h.ctrl.record_event(
            c.StatusEvent(ref, 'divergent', c.State.RUNNING),
            self.h.ctrl.get_attempt(ref).revision)
        self.native.logs[ref].append(
            c.StatusEvent(ref, 'divergent', c.State.COMPLETED))
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertTrue(final.cessation_confirmed)
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.status,
                         c.State.COMPLETED)
        # Terminal supersession: the durable Run record is the authority and
        # the non-authoritative checkpoint is cleared to canonical content.
        self.assertIsNone(self.h.ctrl.checkpoint('r').halted)
        self.assertEqual((self.h.ctrl.get_run('r').state,
                          self.h.ctrl.get_run('r').final_reason,
                          self.h.ctrl.get_run('r').cessation_confirmed),
                         (c.State.FAILED, 'integrity_violation', True))
        self.controller = self.build()  # reopening returns the same failure
        again = self.controller.step()
        self.assertEqual((again.state, again.reason, again.cessation_confirmed),
                         (c.State.FAILED, 'integrity_violation', True))
        self.assertEqual(len(self.native.requests), 1)

    def test_divergent_event_during_stop_drain_latches_fatal(self):
        # A contradiction surfaced mid stop-drain latches integrity, never
        # controller_error/ERROR or a fabricated Result.
        self.native.auto_complete = False
        ref = self.start()
        self.h.ctrl.record_event(
            c.StatusEvent(ref, 'divergent', c.State.RUNNING),
            self.h.ctrl.get_attempt(ref).revision)
        self.native.logs[ref].append(
            c.StatusEvent(ref, 'divergent', c.State.COMPLETED))
        self.human_stop()
        progress = self.controller.step()
        self.assertEqual((progress.state, progress.reason),
                         (c.State.RUNNING,
                          'integrity_violation_result_missing'))
        self.assertIs(progress.cessation_confirmed, True)
        self.held_missing(ref)
        self.assertEqual(self.h.ctrl.checkpoint('r').halted,
                         'integrity_violation')

    def test_unconfirmed_stop_held_cessation_false_no_finalization(self):
        self.native.auto_complete = False
        self.native.stop_status = c.StopStatus.UNCONFIRMED
        ref = self.start()
        self.human_stop()
        progress = self.controller.step()
        self.assertEqual((progress.state, progress.reason),
                         (c.State.RUNNING, 'stop_unconfirmed'))
        self.assertIs(progress.cessation_confirmed, False)
        self.assertIsNone(self.h.ctrl.get_attempt(ref).result)
        self.assertNotIn(ref, self.h.ctrl.history('r', 'released_attempts'))
        self.assertNotIn(self.h.ctrl.get_run('r').state, c.TERMINAL)


if __name__ == '__main__':
    unittest.main()
