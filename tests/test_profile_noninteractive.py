"""Profile Run approval_required stop barrier: real Controller, real
PooledAdapter on the canonical CapacityLedger, real ControlStore/Gateway.

Synthetic child Adapter fixtures supply real Adapter-contract evidence
(events, StopReplies, receipts) behind the real pool — they do NOT qualify
actual Native behavior. No StopReply or Result is minted by hand; nothing
here establishes production isolation or promotes a live route.
"""
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.adapter_capacity import CapacityLedger, PooledAdapter
from co_v4.controller import Controller, JobPlan
from co_v4.gateway_store import Gateway, cancel_body
from co_v4.state import (IngressReceipt, IntegrityViolation,
                         _request_stop_locked, body_digest, create_run_body)
from co_v4.usage import UsageStore
from test_controller import NOW, USE, NativeFixture, catalog
from test_service_driver_pool import DriverPoolFixture, INTENT, PROFILE
from test_service_driver_pool import ADAPTER as DRIVER_ADAPTER
from test_state import Harness


ADAPTER = DRIVER_ADAPTER          # real registered 'codex.app-server'
GW_NOW = '2026-09-28T00:00:00Z'


class ProfileControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Harness(self.tmp.name)
        self.addCleanup(self.h.store.close)
        self.children, self.calls = {}, []
        self.child_confirmation, self.child_auto = None, True
        self.ledger = CapacityLedger(Path(self.tmp.name).resolve()
                                   / 'capacity.sqlite')
        self.pool = PooledAdapter(ADAPTER, ledger=self.ledger,
                                  canonical_ledger=self.ledger.path,
                                  factory=self._child)
        self.conditions = replace(self.h.conditions, model='a', adapter=ADAPTER)
        route = (self.conditions.model, self.conditions.adapter,
                 self.conditions.environment_ref)
        self.profile = c.TaskProfile('fixture-task', 'sha256:' + '0' * 64,
                                     'pure', False, (route,))
        self.controller = None

    def _child(self, request):
        child = NativeFixture()
        child.confirmation = self.child_confirmation
        child.auto_complete = self.child_auto
        self.children[request.ref] = child
        return child

    def verify(self, request):
        return CheckEvidence(body_digest(request),
            Finding('pass', ('fixture:goal-check',)),
            tuple(Finding('pass', ('fixture:artifact-check',))
                  for _ in (request.job.acceptance_criteria
                            if request.job else ())))

    def make_run(self, run_id, profile=True):
        self.h.authenticate(run_id + ':origin',
                            create_run_body(run_id, INTENT))
        self.h.store.intake().create_run(
            run_id, INTENT, run_id + ':origin',
            profile=self.profile if profile else None)

    def build(self, run_id):
        plan = JobPlan(c.Job(run_id, 'j', 'produce fixture output',
            ('output checked',)), self.h.action, 'write-output', USE,
            (self.conditions,), usage_window='comparable-fixture-window')
        return Controller(run_id, state=self.h.ctrl,
            judgment=self.h.judgment, catalog=catalog(adapter=ADAPTER),
            usage=UsageStore(),
            adapters={ADAPTER: self.pool}, acceptance=Acceptance(self.verify),
            planner=lambda *args: self.calls.append(1) or plan,
            clock=lambda: NOW)

    def dispatch(self, run_id='p'):
        self.make_run(run_id)
        self.controller = self.build(run_id)
        self.assertEqual(self.controller.step().reason, 'next_job')
        self.assertEqual(self.controller.step().reason, 'execute_receipt')
        return self.h.ctrl.attempts(run_id)[0].ref

    def test_preadmission_job_judgment_ends_profile_run(self):
        self.h.deny = True
        seen = []
        judge = self.h.judgment.judge
        def spy(request):
            d = judge(request)
            seen.append(d.decision)
            return d
        self.h.judgment.judge = spy
        self.make_run('p')
        final = self.build('p').step()
        self.h.judgment.judge = judge
        self.assertEqual(seen, [c.Decision.DENY])   # observed job decision
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'approval_required'))
        self.assertEqual(self.calls, [1])       # planner not re-invoked
        self.assertEqual(self.h.ctrl.attempts('p'), ())
        self.assertEqual(self.h.ctrl.waits('p'), ())
        self.assertIsNone(self.h.ctrl.stop_origin('p'))
        self.assertFalse(self.h.ctrl.get_run('p').stop_requested)

    def test_preadmission_job_decision_variants_observed(self):
        # The deny flag proves the gate; whether confirm/protection reach a
        # proposed_job judgment is asserted from the real observed decision,
        # never assumed.
        for flag, value in (('confirm', True), ('protection', False)):
            with self.subTest(flag=flag):
                seen = []
                judge = self.h.judgment.judge
                def spy(request):
                    d = judge(request)
                    if request.proposed_job is not None:
                        seen.append(d.decision)
                    return d
                self.h.judgment.judge = spy
                prior = getattr(self.h, flag)
                setattr(self.h, flag, value)
                self.make_run('p-' + flag)
                progress = self.build('p-' + flag).step()
                setattr(self.h, flag, prior)
                self.h.judgment.judge = judge
                if seen and seen[0] != c.Decision.NORMAL:
                    self.assertEqual((progress.state, progress.reason),
                                     (c.State.FAILED, 'approval_required'))
                else:
                    # Flag does not produce a non-NORMAL job judgment: this
                    # variant is unreachable in the fixture, not covered.
                    self.assertEqual(seen, [c.Decision.NORMAL])

    def test_preflight_unresolved_ends_without_wait_or_attempt(self):
        for flag, value, observed in (
                ('confirm', True, c.Decision.CONFIRM),
                ('protection', False, c.Decision.UNDETERMINED)):
            with self.subTest(flag=flag):
                run_id = 'p-' + flag
                self.make_run(run_id)
                controller = self.build(run_id)
                seen = []
                judge = self.h.judgment.judge
                def spy(request):
                    d = judge(request)
                    seen.append(d.decision)
                    return d
                self.h.judgment.judge = spy
                self.assertEqual(controller.step().reason, 'next_job')
                prior = getattr(self.h, flag)
                setattr(self.h, flag, value)
                final = controller.step()
                setattr(self.h, flag, prior)      # exact prior value, not True
                self.h.judgment.judge = judge
                self.assertEqual((final.state, final.reason),
                                 (c.State.FAILED, 'approval_required'))
                self.assertIn(observed, seen)     # real CONFIRM/UNDETERMINED
                # The Job was admitted first: this is the preflight gate,
                # not the job-judgment gate.
                self.assertEqual(self.h.ctrl.get_run(run_id).job_ids, ('j',))
                self.assertEqual(self.h.ctrl.attempts(run_id), ())
                self.assertEqual(self.h.ctrl.waits(run_id), ())
                self.assertIsNone(self.h.ctrl.stop_origin(run_id))
        self.assertTrue(all(not ch.requests for ch in self.children.values()))

    def test_dispatch_rejudgment_non_normal_ends_profile_run(self):
        self.make_run('p')
        controller = self.build('p')
        self.assertEqual(controller.step().reason, 'next_job')
        judge = self.h.judgment.judge
        def changed(request):
            if request.ref.attempt_id:
                self.h.protection = False
            return judge(request)
        self.h.judgment.judge = changed
        final = controller.step()
        self.h.judgment.judge = judge
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'approval_required'))
        self.assertEqual(self.h.ctrl.attempts('p'), ())
        self.assertEqual(self.h.ctrl.waits('p'), ())
        self.assertTrue(all(not ch.requests for ch in self.children.values()))
        self.assertEqual(self.ledger.count(ADAPTER), 0)   # lease cancelled
        self.assertIsNone(self.h.ctrl.stop_origin('p'))
        self.assertTrue(self.h.ctrl.history('p', 'routing_history'))

    def test_live_callback_latches_and_holds_for_real_settlement(self):
        self.child_confirmation, self.child_auto = self.h.action, False
        ref = self.dispatch()
        child = self.children[ref]
        held = self.controller.step()
        self.assertEqual((held.state, held.reason, held.cessation_confirmed),
                         (c.State.RUNNING, 'stop_result_missing', True))
        self.assertEqual(self.h.ctrl.stop_origin('p'), 'approval_required')
        self.assertEqual(child.stops, [ref])            # real pool stop
        self.assertEqual(child.responses, [])           # zero respond()
        self.assertEqual(self.h.ctrl.waits('p'), ())
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.ac)
        child.finish(ref, c.State.COMPLETED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason, final.cessation_confirmed),
                         (c.State.FAILED, 'approval_required', True))
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertEqual(attempt.result.status, c.State.COMPLETED)
        self.assertIsNone(attempt.ac)
        self.assertIsNone(attempt.output)
        self.assertEqual(self.h.ctrl.history('p', 'ac_history'), ())
        self.assertEqual(self.h.ctrl.history('p', 'job_goals'), ())
        self.assertEqual(len(self.h.ctrl.attempts('p')), 1)

    def test_cobatched_confirmation_and_result_never_publish(self):
        # Barrier lands at the committed ConfirmationEvent, before the
        # ResultEvent later in the same drain reaches result processing.
        self.child_confirmation, self.child_auto = self.h.action, False
        ref = self.dispatch()
        child = self.children[ref]
        child.finish(ref, c.State.COMPLETED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason, final.cessation_confirmed),
                         (c.State.FAILED, 'approval_required', True))
        attempt = self.h.ctrl.get_attempt(ref)
        self.assertEqual(attempt.result.status, c.State.COMPLETED)
        self.assertIsNone(attempt.ac)
        self.assertIsNone(attempt.output)
        self.assertIsNone(attempt.collection_failure)
        self.assertEqual(self.h.ctrl.history('p', 'ac_history'), ())
        self.assertEqual(self.h.ctrl.history('p', 'job_goals'), ())
        self.assertEqual(child.responses, [])
        self.assertEqual(self.h.ctrl.waits('p'), ())
        self.assertEqual(self.h.ctrl.stop_origin('p'), 'approval_required')

    def test_no_result_stays_held_across_controller_reopen(self):
        self.child_confirmation, self.child_auto = self.h.action, False
        ref = self.dispatch()
        child = self.children[ref]
        for _ in range(2):
            self.assertEqual(self.controller.step().reason,
                             'stop_result_missing')
        self.controller = self.build('p')   # serialized host restart
        held = self.controller.step()
        self.assertEqual((held.state, held.reason, held.cessation_confirmed),
                         (c.State.RUNNING, 'stop_result_missing', True))
        self.assertIsNone(self.h.ctrl.attempt_settlement(ref))
        self.assertNotIn(ref, self.h.ctrl.history('p', 'released_attempts'))
        self.assertEqual(child.stops, [ref])     # never re-requested
        self.assertEqual(child.responses, [])
        self.assertNotIn(self.h.ctrl.get_run('p').state, c.TERMINAL)

    def test_earlier_committed_origin_keeps_first_label(self):
        self.child_confirmation, self.child_auto = self.h.action, False
        ref = self.dispatch()
        with self.h.store._tx('p') as data:     # committed client cancel
            _request_stop_locked(self.h.store, data, 'gateway_cancel')
        held = self.controller.step()
        self.assertEqual((held.state, held.reason),
                         (c.State.RUNNING, 'stop_result_missing'))
        self.assertEqual(self.h.ctrl.stop_origin('p'), 'gateway_cancel')
        self.children[ref].finish(ref, c.State.FAILED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'human_stop'))
        self.assertEqual(self.h.ctrl.stop_origin('p'), 'gateway_cancel')
        self.assertEqual(self.children[ref].responses, [])

    def test_fatal_latch_supersedes_approval_barrier(self):
        self.child_confirmation, self.child_auto = self.h.action, False
        ref = self.dispatch()
        child = self.children[ref]
        self.h.ctrl.record_event(c.StatusEvent(ref, 'divergent',
            c.State.RUNNING), self.h.ctrl.get_attempt(ref).revision)
        # Divergent committed event_id lands before the callback in the drain.
        child.logs[ref].insert(1, c.StatusEvent(ref, 'divergent',
                                                c.State.COMPLETED))
        child.finish(ref, c.State.FAILED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason, final.cessation_confirmed),
                         (c.State.FAILED, 'integrity_violation', True))
        self.assertIsNone(self.h.ctrl.stop_origin('p'))
        self.assertEqual(self.h.ctrl.get_attempt(ref).result.status,
                         c.State.FAILED)

    def test_recovery_derives_label_from_committed_origin(self):
        self.child_confirmation, self.child_auto = self.h.action, False
        ref = self.dispatch()
        # Barrier committed outside the Controller: crash before checkpoint.
        self.h.ctrl.request_internal_stop('p', 'approval_required')
        self.controller = self.build('p')
        held = self.controller.step()
        self.assertEqual(held.reason, 'stop_result_missing')
        self.assertEqual(self.children[ref].stops, [ref])
        self.children[ref].finish(ref, c.State.FAILED)
        final = self.controller.step()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'approval_required'))

    def test_profile_none_callback_waits_and_relays_unchanged(self):
        self.child_confirmation = self.h.action
        self.controller = self.build('r')
        self.assertEqual(self.controller.step().reason, 'next_job')
        self.assertEqual(self.controller.step().reason, 'execute_receipt')
        # confirm applies to the live-callback judgment, not preflight.
        self.h.confirm = True
        child = self.children[next(iter(self.children))]
        self.assertEqual(self.controller.step().state, c.State.WAITING_HUMAN)
        wait = next(r for r in self.controller.records
                    if isinstance(r, c.WaitingHuman))
        self.assertIsNone(self.h.ctrl.stop_origin('r'))
        self.h.answer(wait)
        for _ in range(10):
            progress = self.controller.step()
            if progress.state in c.TERMINAL:
                break
        self.assertEqual(progress.state, c.State.COMPLETED)
        self.assertEqual(child.responses[0].resolution, c.Resolution.ALLOW)
        self.assertIsNone(self.h.ctrl.stop_origin('r'))

    def test_profile_none_preadmission_paths_unchanged(self):
        self.h.confirm = True                      # preflight wait, no fail
        self.make_run('n1', profile=False)
        controller = self.build('n1')
        controller.step()
        self.assertEqual(controller.step().state, c.State.WAITING_HUMAN)
        self.assertNotEqual(self.h.ctrl.waits('n1'), ())
        self.assertEqual(self.h.ctrl.attempts('n1'), ())
        self.h.confirm, self.h.deny = False, True  # job halt, no fail
        self.make_run('n2', profile=False)
        self.assertEqual(self.build('n2').step().reason,
                         'job_containment_not_normal')
        self.h.deny = False
        self.make_run('n3', profile=False)         # rejudgment stays PENDING
        controller = self.build('n3')
        controller.step()
        judge = self.h.judgment.judge
        self.h.judgment.judge = lambda req: (
            setattr(self.h, 'protection', False) or judge(req)
            if req.ref.attempt_id else judge(req))
        self.assertEqual(controller.step().reason,
                         'dispatch_rejudgment_not_normal')
        self.h.judgment.judge = judge

    def test_internal_stop_contract_idempotent_no_ingress(self):
        for origin in ('intake', 'gateway_cancel', 'bogus', ''):
            with self.subTest(origin=origin):
                self.assertRaises(ValueError,
                    self.h.ctrl.request_internal_stop, 'r', origin)
        claims = self.h.store._db.execute(
            'SELECT count(*) FROM ingress').fetchone()[0]
        self.assertTrue(
            self.h.ctrl.request_internal_stop('r', 'approval_required'))
        self.assertFalse(
            self.h.ctrl.request_internal_stop('r', 'projection_decided'))
        self.assertFalse(
            self.h.ctrl.request_internal_stop('r', 'approval_required'))
        self.assertEqual(self.h.ctrl.stop_origin('r'), 'approval_required')
        self.assertEqual(claims, self.h.store._db.execute(
            'SELECT count(*) FROM ingress').fetchone()[0])
        run = self.h.ctrl.get_run('r')
        self.h.ctrl.finalize_run('r', c.State.FAILED, 'fixture_end',
                                 run.revision)
        self.assertFalse(
            self.h.ctrl.request_internal_stop('r', 'approval_required'))


class GatewayOriginTests(unittest.TestCase):
    """Persisted-row validation and committed-origin projection."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.fx = DriverPoolFixture(Path(tmp.name).resolve() / 'root')
        self.addCleanup(self.fx.close)

    def new_run(self, run_id, resp):
        fx = self.fx
        fx.receipts[run_id] = IngressReceipt(
            'fixture-principal', run_id,
            body_digest(create_run_body(run_id, INTENT)), GW_NOW)
        fx.store.intake().create_run(run_id, INTENT, run_id, profile=PROFILE)
        fx.store._db.execute(
            'INSERT INTO gateway_responses VALUES (?,?,?,?,?,?)',
            (resp, 'fixture-principal', run_id, 'd', 'fixture-task', GW_NOW))
        return run_id

    def project(self, resp, run_id, row):
        self.fx.store._db.execute(
            'INSERT INTO gateway_projections VALUES (?,?,?,?,?)',
            (resp,) + row[:2] + (self.fx.state.get_run(run_id).revision,
                                 GW_NOW))
        return self.fx.gateway.project(run_id)

    def test_cancelled_row_over_approval_origin_fails_closed(self):
        run_id = self.new_run('run-a', 'resp-a')
        self.fx.state.request_internal_stop(run_id, 'approval_required')
        with self.assertRaises(IntegrityViolation):
            self.project('resp-a', run_id, ('cancelled', None))

    def test_terminal_cancelled_row_without_stop_flag_fails_closed(self):
        run_id = self.new_run('run-b', 'resp-b')
        run = self.fx.state.get_run(run_id)
        self.fx.state.finalize_run(run_id, c.State.FAILED, 'fixture_end',
                                   run.revision)
        with self.fx.store._tx(run_id) as data:
            data['stop_origin'] = 'intake'   # tamper: origin, no stop flag
        with self.assertRaises(IntegrityViolation):
            self.project('resp-b', run_id, ('cancelled', None))

    def test_nonterminal_approval_failed_wrong_origin_fails_closed(self):
        run_id = self.new_run('run-c', 'resp-c')
        with self.fx.store._tx(run_id) as data:
            data['run'] = replace(data['run'], stop_requested=True)
            data['stop_origin'] = 'gateway_cancel'
        with self.assertRaises(IntegrityViolation):
            self.project('resp-c', run_id, ('failed', 'approval_required'))

    def test_approval_origin_projects_failed_immediately(self):
        fx = self.fx
        fx.driver.start()
        fx.dispatch()
        fx.state.request_internal_stop(fx.run_id, 'approval_required')
        view = fx.gateway.project(fx.run_id)
        self.assertEqual((view.status, view.code, view.decided),
                         ('failed', 'approval_required', True))
        self.assertEqual(fx.projection_row()[:2],
                         ('failed', 'approval_required'))
        self.assertEqual(fx.run().state, c.State.RUNNING)  # held, not terminal

    def test_cancel_first_origin_and_cancelled_projection(self):
        fx = self.fx
        # Trusted bound configured before cancel so a zero-expiry failed row
        # cannot legitimately win the write-once race ahead of the real stop.
        fx.gateway = Gateway(fx.store, bound_resolver=lambda *_: 86400)
        fx.receipts['c1'] = IngressReceipt(
            'fixture-principal', 'c1',
            body_digest(cancel_body(fx.response_id)), GW_NOW)
        fx.driver.start()
        fx.dispatch()
        fx.gateway.cancel(fx.response_id, 'c1')
        self.assertFalse(fx.state.request_internal_stop(
            fx.run_id, 'approval_required'))
        self.assertEqual(fx.state.stop_origin(fx.run_id), 'gateway_cancel')
        child = fx.children[next(iter(fx.children))]
        child.stop_status = c.StopStatus.CONFIRMED
        # Child configuration alone is no proof: the real Controller commits
        # the actual CONFIRMED StopReply through the real PooledAdapter.
        held = fx.build_controller().step()
        self.assertEqual((held.reason, held.cessation_confirmed),
                         ('stop_result_missing', True))
        self.assertEqual(fx.ledger.count(DRIVER_ADAPTER), 0)
        view = fx.gateway.project(fx.run_id)
        self.assertEqual((view.status, view.decided), ('cancelled', True))
        self.assertEqual(fx.projection_row()[0], 'cancelled')


if __name__ == '__main__':
    unittest.main()
