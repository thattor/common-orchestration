"""Durable admission and real Controller budget tests; no provider inference."""
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from pathlib import Path
import multiprocessing
import os
import sqlite3
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.adapter_capacity import (ADAPTERS, PRIMARY_ADAPTERS, CapacityError,
    CHILD_LACKS_COLLECTOR, CapacityLedger, NativeAdapterPools, PooledAdapter)
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.catalog import Catalog
from co_v4.controller import Controller, JobPlan
from co_v4.service_owner import OwnerUnavailable
from co_v4.state import StoreUnavailable, body_digest
from co_v4.usage import UsageStore
import test_controller as fixtures
from test_state import Harness


def request(index, adapter='codex.app-server', model='a'):
    ref = c.AttemptRef('run-' + str(index), 'job', 'attempt')
    return c.ExecuteRequest(ref, c.Job(ref.run_id, ref.job_id, 'fixture', ()),
        c.ExecutionConditions(model, adapter, '/fixture', 'env:1', ('fixture:controls',)))


def reserve_process(path, index):
    ledger = CapacityLedger(path)
    pool = PooledAdapter('codex.app-server', ledger=ledger, canonical_ledger=path,
        factory=lambda _: None)
    return pool.reserve(request(index))


def crash_after_controller_reserve(root, ledger_path):
    h = Harness(root)
    run = 'crash-run'; h.create(run)
    job = c.Job(run, 'crash-job', 'fixture', ('checked',))
    conditions = replace(h.conditions, adapter='codex.app-server', model='a')
    plan = JobPlan(job, h.action, 'write-output', fixtures.USE, (conditions,))
    pools = NativeAdapterPools(canonical_ledger=ledger_path,
        factories={adapter: lambda _: None for adapter in PRIMARY_ADAPTERS})
    controller = Controller(run, state=h.ctrl, judgment=h.judgment,
        catalog=fixtures.catalog(adapter='codex.app-server'), usage=UsageStore(),
        adapters=pools, acceptance=Acceptance(lambda _: None), planner=lambda *_: plan,
        clock=lambda: fixtures.NOW)
    assert controller.step().reason == 'next_job'
    pool = pools['codex.app-server']; reserve = pool.reserve
    def crash(request):
        assert reserve(request)
        os._exit(23)  # No Python finally, Controller checkpoint or begin_attempt.
    pool.reserve = crash
    controller.step()


class Child(fixtures.NativeFixture):
    def __init__(self):
        super().__init__()
        self.auto_complete = False
        self.stop_status = c.StopStatus.UNCONFIRMED
        self.closed = False
    def close(self): self.closed = True
    def status(self, ref): return c.StatusEvent(ref, 'fixture-status', c.State.RUNNING)
    def resume(self, state): return c.OperationReply(state.ref, c.OperationStatus.ACCEPTED, 'fixture resume')


class PoolTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.path = Path(temp.name).resolve() / 'capacity.sqlite'
        self.ledger = CapacityLedger(self.path)
        self.children = {}
    def factory(self, req):
        child = Child(); self.children[req.ref] = child; return child
    def pool(self, adapter='codex.app-server', factory=None, ledger=None):
        return PooledAdapter(adapter, ledger=ledger or self.ledger,
            canonical_ledger=self.path, factory=factory or self.factory)

    def test_atomic_limit_across_processes_and_models(self):
        with ProcessPoolExecutor(max_workers=6, mp_context=multiprocessing.get_context('spawn')) as workers:
            results = list(workers.map(reserve_process, [self.path] * 24, range(24)))
        self.assertEqual(sum(results), 12)
        self.assertEqual(self.ledger.count('codex.app-server'), 12)
        self.assertFalse(self.pool().reserve(request(99, model='another-model')))

    def test_adapter_independence_and_exact_factory_binding(self):
        for adapter in ADAPTERS:
            pool = self.pool(adapter)
            for index in range(12):
                req = request(adapter + str(index), adapter, model='a' if index % 2 else 'b')
                self.assertEqual(pool.execute(req).status, c.OperationStatus.ACCEPTED)
                self.assertEqual(self.children[req.ref].requests, [req])
            blocked = request(adapter + '-full', adapter)
            self.assertEqual(pool.execute(blocked).never_started.request, blocked)
            self.assertNotIn(blocked.ref, self.children)
            self.assertEqual(self.ledger.count(adapter), 12)
        self.assertEqual(len(self.children), 12 * len(ADAPTERS))

    def test_terminal_close_and_unconfirmed_stop_do_not_release(self):
        pool = self.pool(); req = request(0); pool.execute(req)
        child = self.children[req.ref]; child.finish(req.ref)
        self.assertTrue(any(isinstance(event, c.ResultEvent) for event in pool.events(req.ref)))
        for status in (c.StopStatus.REQUESTED, c.StopStatus.UNCONFIRMED, c.StopStatus.ERROR, c.StopStatus.UNSUPPORTED):
            child.stop_status = status
            self.assertEqual(pool.stop(req.ref).status, status)
            self.assertEqual(self.ledger.count(pool.adapter), 1)
        pool.close(); self.assertTrue(child.closed)
        self.assertEqual(self.ledger.count(pool.adapter), 1)
        child.stop_status = c.StopStatus.CONFIRMED
        self.assertEqual(pool.stop(req.ref).status, c.StopStatus.CONFIRMED)
        self.assertEqual(self.ledger.count(pool.adapter), 0)
        self.assertEqual(pool.execute(req).status, c.OperationStatus.INVALID_STATE)
        self.assertEqual(pool.resume(c.ResumeState(pool.adapter, req.ref, b'fixture')).status, c.OperationStatus.INVALID_STATE)

    def test_cross_attempt_identity_and_late_response_cannot_free_or_reuse_slot(self):
        pool = self.pool(); req = request(0); pool.execute(req)
        child = self.children[req.ref]
        child.stop = lambda ref: c.StopReply(request(99).ref, c.StopStatus.CONFIRMED, 'wrong', 'fixture:wrong')
        self.assertEqual(pool.stop(req.ref).status, c.StopStatus.UNCONFIRMED)
        self.assertEqual(self.ledger.count(pool.adapter), 1)
        child.stop = lambda ref: c.StopReply(ref, c.StopStatus.CONFIRMED, 'correct', 'fixture:correct')
        pool.stop(req.ref)
        response = c.ConfirmationResponse(req.ref, 'q', c.Action('fixture', c.Scope((('x', 'y'),), True)),
            c.Resolution.ALLOW, 'fixture:judgment')
        self.assertEqual(pool.respond(response).status, c.OperationStatus.INVALID_STATE)
        self.assertEqual(child.responses, [])
        with self.assertRaises(CapacityError): self.pool().reserve(req)

    def test_ambiguous_factory_and_execute_exceptions_hold_capacity(self):
        def fail(_): raise RuntimeError('ambiguous transport creation')
        pool = self.pool(factory=fail); req = request(0)
        reply = pool.execute(req)
        self.assertIsNone(reply.never_started)
        self.assertEqual(pool.stop(req.ref).status, c.StopStatus.UNCONFIRMED)
        self.assertEqual(self.ledger.count(pool.adapter), 1)
        class Raising(Child):
            def execute(self, req): raise RuntimeError('possibly delivered')
        pool = self.pool(factory=lambda _: Raising())
        self.assertIsNone(pool.execute(request(1)).never_started)
        self.assertEqual(self.ledger.count(pool.adapter), 2)

    def test_exact_never_started_releases_but_rebound_receipt_does_not(self):
        class Refuse(Child):
            def execute(self, req):
                return c.OperationReply(req.ref, c.OperationStatus.UNSUPPORTED, 'preflight',
                    never_started=c.NeverStarted(req, 'fixture:before-transport'))
        pool = self.pool(factory=lambda _: Refuse())
        self.assertIsNotNone(pool.execute(request(0)).never_started)
        self.assertEqual(self.ledger.count(pool.adapter), 0)
        class Rebound(Child):
            def execute(self, req):
                wrong = replace(req, conditions=replace(req.conditions, model='other'))
                return c.OperationReply(req.ref, c.OperationStatus.UNSUPPORTED, 'preflight',
                    never_started=c.NeverStarted(wrong, 'fixture:wrong-request'))
        pool = self.pool(factory=lambda _: Rebound())
        self.assertIsNone(pool.execute(request(1)).never_started)
        self.assertEqual(self.ledger.count(pool.adapter), 1)

    def test_restart_retains_slots_and_requires_exact_trusted_reattachment(self):
        pool = self.pool(); req = request(0); pool.execute(req)
        restarted = self.pool(ledger=CapacityLedger(self.path))
        self.assertEqual(restarted.stop(req.ref).status, c.StopStatus.UNCONFIRMED)
        self.assertEqual(restarted.ledger.count(pool.adapter), 1)
        with self.assertRaises(CapacityError): restarted.execute(req)
        with self.assertRaises(CapacityError):
            restarted.reattach(replace(req, conditions=replace(req.conditions, model='other')), self.children[req.ref])
        restarted.reattach(req, self.children[req.ref])
        self.children[req.ref].stop_status = c.StopStatus.CONFIRMED
        self.assertEqual(pool.stop(req.ref).status, c.StopStatus.UNCONFIRMED)
        self.assertEqual(restarted.stop(req.ref).status, c.StopStatus.CONFIRMED)
        self.assertEqual(self.ledger.count(pool.adapter), 0)

    def test_unsubmitted_reservation_recovery_cannot_race_into_execution(self):
        pool = self.pool(); req = request(0); self.assertTrue(pool.reserve(req))
        restarted = self.pool(ledger=CapacityLedger(self.path))
        self.assertEqual(restarted.recover_unstarted(req).never_started.request, req)
        with self.assertRaises(CapacityError): pool.execute(req)
        self.assertNotIn(req.ref, self.children)
        req = request(1); pool.execute(req)
        with self.assertRaises(CapacityError): restarted.recover_unstarted(req)
        self.assertEqual(self.ledger.count(pool.adapter), 1)

    def test_snapshot_cancellation_rejects_drift_and_preserves_executing_rows(self):
        pool = self.pool(); req = request(0); pool.reserve(req)
        snapshot, = self.ledger.unresolved()
        for changed in (replace(snapshot, request_digest='wrong'),
                        replace(snapshot, ref=replace(req.ref, attempt_id='other')),
                        replace(snapshot, adapter='claude.print')):
            with self.assertRaises(CapacityError): self.ledger.cancel_unstarted(changed)
        pool.execute(req)
        with self.assertRaises(CapacityError): self.ledger.cancel_unstarted(snapshot)
        executing, = self.ledger.unresolved()
        self.assertEqual(executing.phase, 'executing')
        with self.assertRaises(CapacityError): self.ledger.cancel_unstarted(executing)
        self.assertEqual(self.ledger.count('codex.app-server'), 1)
        other = request(1); pool.reserve(other)
        reserved = next(row for row in self.ledger.unresolved() if row.ref == other.ref)
        self.ledger.cancel_unstarted(reserved)
        with self.assertRaises(CapacityError): pool.execute(other)
        self.assertNotIn(other.ref, self.children)
        self.assertEqual(self.ledger.unresolved(), (executing,))

    def test_canonical_ledger_composition_and_replacement_fail_closed(self):
        with self.assertRaises(CapacityError):
            PooledAdapter('codex.app-server', ledger=self.ledger,
                canonical_ledger=self.path.with_name('another.sqlite'), factory=self.factory)
        with self.assertRaises(CapacityError): self.pool('opencode')
        all_pools = NativeAdapterPools(canonical_ledger=self.path, factories={k: self.factory for k in ADAPTERS})
        self.assertEqual({pool.ledger.path for pool in all_pools.values()}, {self.path})
        other = NativeAdapterPools(canonical_ledger=self.path, factories={k: self.factory for k in PRIMARY_ADAPTERS})
        for i in range(12): self.assertTrue(all_pools['codex.app-server'].reserve(request(i)))
        self.assertFalse(other['codex.app-server'].reserve(request(13)))
        backup = self.path.with_suffix('.preserved'); self.path.rename(backup)
        self.path.touch(mode=0o600)
        with self.assertRaises(CapacityError): self.ledger.count('codex.app-server')


    def test_execute_release_global_faults_propagate_proof_retained(self):
        """Each GLOBAL_FAILURES class on BOTH release paths escapes
        execute() unchanged (the exact instance); the request-bound
        NeverStarted receipt stays in memory, the lease stays held, no
        resend occurs, and a restored ledger's stop settles on that
        retained proof — no child call, no invented Result."""
        for i, fault in enumerate((StoreUnavailable('x'),
                OwnerUnavailable('x'), sqlite3.Error('x'))):
            for j, kind in enumerate(('collector', 'never_started')):
                with self.subTest(fault=type(fault).__name__, kind=kind):
                    req = request((i, j))
                    calls = {'factory': 0, 'execute': 0, 'stop': 0}
                    if kind == 'collector':
                        req = replace(req, job=replace(
                            req.job, output_candidate=True))
                        def factory(_):
                            calls['factory'] += 1
                            return object()     # not an OutputCollector
                        evidence = CHILD_LACKS_COLLECTOR
                    else:
                        child = Child()
                        def factory(_):
                            calls['factory'] += 1
                            return child
                        def child_execute(request):
                            calls['execute'] += 1
                            return c.OperationReply(
                                request.ref, c.OperationStatus.UNSUPPORTED,
                                'preflight', never_started=c.NeverStarted(
                                    request, 'fixture:before-transport'))
                        child.execute = child_execute
                        real_stop = child.stop
                        def counted_stop(ref):
                            calls['stop'] += 1
                            return real_stop(ref)
                        child.stop = counted_stop
                        evidence = 'fixture:before-transport'
                    pool = self.pool(factory=factory)
                    def release(*_a, **_k):
                        raise fault
                    pool.ledger.release = release
                    with self.assertRaises(type(fault)) as raised:
                        pool.execute(req)
                    self.assertIs(raised.exception, fault)
                    self.assertEqual(calls, {'factory': 1,
                        'execute': 1 if kind == 'never_started' else 0,
                        'stop': 0})
                    proof = pool._receipts[req.ref]
                    self.assertIsNotNone(proof.never_started)
                    self.assertIs(proof.never_started.request, req)
                    self.assertEqual(self.ledger.count(pool.adapter), 1)
                    # No resend: the retained receipt makes re-execute
                    # INVALID_STATE rather than a second dispatch.
                    self.assertEqual(pool.execute(req).status,
                                     c.OperationStatus.INVALID_STATE)
                    del pool.ledger.release
                    reply = pool.stop(req.ref)
                    self.assertIs(reply.status, c.StopStatus.CONFIRMED)
                    self.assertEqual(reply.evidence_ref, evidence)
                    self.assertEqual(calls['stop'], 0)   # real instrumentation:
                                                         # proof path, not child
                    self.assertEqual(self.ledger.count(pool.adapter), 0)

    def test_stop_globals_propagate_and_only_exact_proof_releases(self):
        """All three global classes propagate out of stop's release write
        (not UNCONFIRMED); the retained CONFIRMED proof releases on the
        restored ledger with zero re-calls. Planted foreign/wrong-ref/
        non-CONFIRMED values in _stops and foreign NeverStarted receipts
        never free a lease."""
        for i, fault in enumerate((StoreUnavailable('x'),
                OwnerUnavailable('x'), sqlite3.Error('x'))):
            with self.subTest(fault=type(fault).__name__):
                req = request(('s', i))
                pool = self.pool()
                pool.execute(req)
                child = self.children[req.ref]
                calls = {'stop': 0}
                real_stop = child.stop
                def counted(ref):
                    calls['stop'] += 1
                    return real_stop(ref)
                child.stop = counted
                child.stop_status = c.StopStatus.CONFIRMED
                def release(*_a, **_k):
                    raise fault
                pool.ledger.release = release
                with self.assertRaises(type(fault)) as raised:
                    pool.stop(req.ref)
                self.assertIs(raised.exception, fault)
                self.assertEqual(calls['stop'], 1)
                self.assertIs(pool._stops[req.ref].status,
                              c.StopStatus.CONFIRMED)
                self.assertEqual(self.ledger.count(pool.adapter), 1)
                del pool.ledger.release
                reply = pool.stop(req.ref)
                self.assertIs(reply.status, c.StopStatus.CONFIRMED)
                self.assertEqual(calls['stop'], 1)     # not re-called
                self.assertEqual(self.ledger.count(pool.adapter), 0)
        req = request('invalid')
        pool = self.pool()
        pool.execute(req)
        for bad in (c.StopReply(request('z').ref, c.StopStatus.CONFIRMED,
                                'x', 'e'),
                    c.StopReply(req.ref, c.StopStatus.UNCONFIRMED, 'x', 'e'),
                    'not-a-stopreply'):
            pool._stops[req.ref] = bad
            self.assertIsNot(pool.stop(req.ref).status,
                             c.StopStatus.CONFIRMED)
            self.assertEqual(self.ledger.count(pool.adapter), 1)
        # A coherent foreign ExecuteRequest (its own bound Job); the
        # planted receipt's ref != req.ref AND its NeverStarted.request
        # != the bound request — both exact guards must hold it out.
        foreign = request('z')
        pool._receipts[req.ref] = c.OperationReply(
            foreign.ref, c.OperationStatus.UNSUPPORTED, 'x',
            never_started=c.NeverStarted(foreign, 'fixture:f'))
        self.assertIsNot(pool.stop(req.ref).status,
                         c.StopStatus.CONFIRMED)
        self.assertEqual(self.ledger.count(pool.adapter), 1)

class ControllerCapacityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve(); self.h = Harness(self.root)
        self.addCleanup(self.h.store.close)
        self.children = {}
        def factory(req):
            child = Child(); self.children[req.ref] = child; return child
        self.pools = NativeAdapterPools(canonical_ledger=self.root / 'capacity.sqlite',
            factories={key: factory for key in ADAPTERS})
        self.catalog = Catalog(tuple(entry for key in ADAPTERS for entry in fixtures.catalog(adapter=key).entries))
    def controller(self, index, adapter='codex.app-server', model='a'):
        run = 'run-' + str(index); self.h.create(run)
        job = c.Job(run, 'job', 'create tested output', ('checked',))
        conditions = replace(self.h.conditions, adapter=adapter, model=model)
        plan = JobPlan(job, self.h.action, 'write-output', fixtures.USE, (conditions,), explicit_model=model, explicit_adapter=adapter)
        def verify(req):
            return CheckEvidence(body_digest(req), Finding('pass', ('fixture:verified',)),
                (Finding('pass', ('fixture:criterion',)),) if req.kind == 'job' else ())
        return Controller(run, state=self.h.ctrl, judgment=self.h.judgment, catalog=self.catalog,
            usage=UsageStore(), adapters=self.pools, acceptance=Acceptance(verify), planner=lambda *_: plan,
            clock=lambda: fixtures.NOW)

    def test_release_global_fault_escapes_step_no_post_fault_save(self):
        """Dispatch-path proof: a global fault inside the pool's
        never_started release crosses Controller.step() unchanged.
        The Controller legitimately write-aheads its checkpoint AFTER
        begin_attempt and BEFORE adapter.execute (pending_io='execute'
        pinned to the committed Attempt), so the honest baseline is the
        checkpoint committed at fault time — captured INSIDE the
        injected release fault. After propagation the digest is
        byte-identical: the finally never saved post-fault, no audit or
        receipt landed, the admitted Attempt and lease stay held, and
        explicit stop settles on the retained in-memory proof."""
        controller = self.controller(0)
        self.assertEqual(controller.step().reason, 'next_job')
        pool = self.pools['codex.app-server']

        class Refuse(Child):
            def execute(self, req):
                return c.OperationReply(
                    req.ref, c.OperationStatus.UNSUPPORTED, 'preflight',
                    never_started=c.NeverStarted(
                        req, 'fixture:before-transport'))

        calls = {'factory': 0}
        def factory(req):
            calls['factory'] += 1
            return Refuse()
        pool.factory = factory
        fault = StoreUnavailable('injected')
        at_fault = {}
        def release(*_a, **_k):
            # The committed write-ahead checkpoint is the true baseline:
            # snapshot it immediately before raising.
            ckpt = self.h.ctrl.checkpoint(controller.run_id)
            at_fault['digest'] = body_digest(ckpt)
            at_fault['active'] = ckpt.active
            at_fault['pending_io'] = ckpt.pending_io
            raise fault
        pool.ledger.release = release
        with self.assertRaises(StoreUnavailable) as raised:
            controller.step()
        self.assertIs(raised.exception, fault)
        ref, = (a.ref for a in self.h.ctrl.attempts(controller.run_id))
        # No _save after the global failure: the committed checkpoint is
        # exactly the write-ahead record observed inside the fault.
        self.assertEqual(body_digest(
            self.h.ctrl.checkpoint(controller.run_id)),
            at_fault['digest'])
        self.assertEqual(at_fault['active'], ref)
        self.assertEqual(at_fault['pending_io'], 'execute')
        self.assertEqual(self.h.ctrl.history(
            controller.run_id, 'driver_audit'), ())
        self.assertEqual(self.pools.ledger.count(pool.adapter), 1)
        del pool.ledger.release
        reply = pool.stop(ref)
        self.assertIs(reply.status, c.StopStatus.CONFIRMED)
        self.assertEqual(calls['factory'], 1)          # zero resend
        self.assertEqual(self.pools.ledger.count(pool.adapter), 0)

    def test_thirteenth_pending_preserves_budget_until_confirmed_stop(self):
        controllers = [self.controller(i, model='a' if i % 2 else 'b') for i in range(13)]
        for controller in controllers: self.assertEqual(controller.step().reason, 'next_job')
        for controller in controllers[:12]: self.assertEqual(controller.step().reason, 'execute_receipt')
        last = controllers[-1]
        for _ in range(8): self.assertEqual(last.step().reason, 'adapter_capacity_full')
        self.assertEqual(self.h.ctrl.attempts(last.run_id), ())
        self.assertEqual(self.h.ctrl.history(last.run_id, 'routing_history'), ())
        self.assertEqual(last._attempts, [])
        for key in ('claude.print', 'devin.acp', 'antigravity.text.only', 't3code.orchestration-v2'):
            independent = self.controller(key, key)
            independent.step(); self.assertEqual(independent.step().reason, 'execute_receipt')
        first = controllers[0]; ref = first._active; child = self.children[ref]; child.finish(ref)
        child.stop_status = c.StopStatus.REQUESTED
        self.assertEqual(first.step().reason, 'terminal_cessation_unconfirmed')
        self.assertEqual(last.step().reason, 'adapter_capacity_full')
        child.stop_status = c.StopStatus.CONFIRMED
        self.assertEqual(first.step().reason, 'job_goal_verified')
        self.assertEqual(last.step().reason, 'execute_receipt')
        self.assertEqual(len(self.h.ctrl.attempts(last.run_id)), 1)
        self.assertEqual(self.pools.ledger.count('codex.app-server'), 12)
        for controller in controllers[1:]:
            controller.step()
            self.assertEqual(len(self.h.ctrl.attempts(controller.run_id)), 1)

    def test_crash_after_reserve_before_begin_recovers_uuid_without_original_request(self):
        process = multiprocessing.get_context('spawn').Process(target=crash_after_controller_reserve,
            args=(self.root, self.pools.ledger.path))
        process.start(); process.join(timeout=10)
        if process.is_alive():
            process.terminate(); process.join(timeout=5)
            self.fail('bounded crash fixture did not terminate')
        self.assertEqual(process.exitcode, 23)
        self.assertEqual(self.h.ctrl.attempts('crash-run'), ())
        self.assertIsNone(self.h.ctrl.checkpoint('crash-run').active)
        reopened = CapacityLedger(self.pools.ledger.path)
        retained, = reopened.unresolved()
        self.assertEqual((retained.ref.run_id, retained.ref.job_id), ('crash-run', 'crash-job'))
        self.assertEqual(len(retained.ref.attempt_id), 32)
        self.assertEqual(len(retained.request_digest), 64)
        self.assertEqual(reopened.count('codex.app-server'), 1)
        reply = reopened.cancel_unstarted(retained)
        self.assertEqual(reply.ref, retained.ref)
        self.assertEqual(reply.status, c.StopStatus.CONFIRMED)
        self.assertEqual(reopened.count('codex.app-server'), 0)
        self.assertEqual(reopened.unresolved(), ())
        self.assertEqual(self.h.ctrl.attempts('crash-run'), ())
        self.assertEqual(self.children, {})

    def test_controller_rejects_pools_split_across_host_ledgers(self):
        controller = self.controller(0)
        other_root = self.root / 'other'; other_root.mkdir(mode=0o700)
        other = CapacityLedger(other_root / 'capacity.sqlite')
        adapters = dict(self.pools)
        adapters['codex.app-server'] = PooledAdapter('codex.app-server', ledger=other,
            canonical_ledger=other.path, factory=lambda _: Child())
        with self.assertRaisesRegex(ValueError, 'canonical host ledger'):
            Controller(controller.run_id, state=self.h.ctrl, judgment=self.h.judgment,
                catalog=self.catalog, usage=UsageStore(), adapters=adapters,
                acceptance=controller.acceptance, planner=controller.planner)

    def test_dispatch_rejudgment_failure_cancels_unused_reservation(self):
        controller = self.controller(0); controller.step()
        original = controller.judgment.judge
        def refuse(req):
            if req.ref.attempt_id: self.h.protection = False
            return original(req)
        controller.judgment.judge = refuse
        self.assertEqual(controller.step().reason, 'dispatch_rejudgment_not_normal')
        self.assertEqual(self.pools.ledger.count('codex.app-server'), 0)
        self.assertEqual(self.h.ctrl.attempts(controller.run_id), ())
        self.assertEqual(self.children, {})
