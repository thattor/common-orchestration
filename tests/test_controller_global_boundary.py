"""Global-failure boundary: real Controller/ServiceDriver/ControlStore (#190 M3).

Real ControlStore + real Judgment through the bound make_evidence
resolver + real CapacityLedger/PooledAdapter admission with the owned
CollectingChild contract fixture + real OutputStore (the pinned profile
requires output). The Owner is a controllable guard callable only —
NOT flock/fsid proof. The HttpService 503 surface, held-owner-across-
processes proof and SIGTERM lifecycle are an explicit followup on the
real ServiceHost stack; the existing host suite injects a driver-side
RuntimeError, not a Controller-level global. A Controller whose step
escapes a global failure is production-discarded; recovery assertions
use a freshly opened Controller on the same committed store. No Native
process, no provider contact, no fabricated AC — Acceptance is armed
to explode.
"""
import json
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from co_v4 import contracts as c
from co_v4 import controller as ctl_mod
from co_v4 import host_routes as hr
from co_v4 import service_driver as drv_mod
from co_v4 import service_owner, state
from co_v4.ac import Acceptance
from co_v4.adapter_capacity import CapacityLedger, PooledAdapter
from co_v4.controller import Controller
from co_v4.failures import GLOBAL_FAILURES
from co_v4.gateway_store import submit_body
from co_v4.host_policy import make_evidence
from co_v4.http_auth import IngressBroker
from co_v4.output_store import OutputStore
from co_v4.profile_planner import ProfilePlanner
from co_v4.profile_registry import load_registry, revision_digest
from co_v4.responses_input import parse
from co_v4.service_driver import ServiceDriver
from co_v4.service_owner import OwnerUnavailable
from co_v4.state import (ControlStore, IntegrityViolation, NotFound,
                         StoreUnavailable)
from co_v4.usage import UsageStore
from test_adapter_capacity import Child
import test_host_routes as thr
import test_profile_registry as tpr

NOW = '2026-10-06T00:00:00Z'
NOW_DT = datetime(2026, 10, 6, tzinfo=timezone.utc)
ALIAS, MODEL, RESPONSES = 'co-text', thr.MODEL, thr.RESPONSES


class CollectingChild(Child, c.OutputCollector):
    """Real OutputCollector qualification for the dispatch admission
    guard; collect_output is never invoked on this suite's paths."""
    def collect_output(self, ref):
        return ()


class Owner:
    """Guard double: controllable OwnerUnavailable, NOT real flock."""
    def __init__(self):
        self.broken, self.calls = False, 0

    def check(self):
        self.calls += 1
        if self.broken:
            raise OwnerUnavailable('owner_lost')


class GlobalBoundaryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name).resolve()
        tmp = Path(tempfile.mkdtemp(dir=str(base)))
        cred = thr.write(tmp / 'cred', secrets.token_hex(32).encode())
        mpath = thr.write(tmp / 'manifest.json',
                          thr.manifest_dict(tmp, cred))
        helper = thr.HostRoutesTests()
        spec = helper.spec_for(tmp, cred, mpath)
        self.bundle = hr.build_routes(helper.config(tmp, (spec,), cred))
        self.env = spec.environment_ref
        wire = tpr.wire_entry(env=self.env,
            routes=[[MODEL, RESPONSES, self.env]],
            route_bounds=[{'route': [MODEL, RESPONSES, self.env],
                           'total_s': 120, 'max_drain_s': 30}])
        self.registry = load_registry(json.dumps(tpr.registry_doc(
            [wire], [{'alias': ALIAS, 'profile_id': 'co-text',
                      'revision_digest': revision_digest(wire)}])),
            catalog=self.bundle.catalog,
            routes=self.bundle.route_configs)
        self.broker = None
        self.owner = Owner()
        self.store = ControlStore(
            base / 'control.sqlite',
            verifier=lambda ref: self.broker.verifier(ref),
            evidence=lambda run, req: self._resolver(run, req),
            clock=lambda: NOW,
            profile_resolver=self.registry.resolve,
            guard=self.owner.check)
        self.addCleanup(self.store.close)
        self.broker = IngressBroker(self.store.now)
        self._resolver = make_evidence(self.store, self.registry,
                                       self.bundle)
        self.gateway = self.store.gateway()
        self.ctrl = self.store.controller()
        self.planner = ProfilePlanner(self.registry,
                                      self.bundle.route_configs,
                                      hr.TEXT_WORKSPACE)
        self.ledger = CapacityLedger(base / 'cap.sqlite')
        self.out = OutputStore(base / 'outputs')
        self.children, self.built, self._key = [], [], 0
        self.pool = PooledAdapter(RESPONSES, ledger=self.ledger,
            canonical_ledger=self.ledger.path,
            factory=lambda req: (
                self.children.append(req), CollectingChild())[1])
        self.addCleanup(self.pool.close)   # store/ledger are fd-free
        trap = mock.patch.object(hr, 'HttpSseTransport')
        self.transport = trap.start()      # provider IO trapped
        self.addCleanup(trap.stop)

    def submit(self) -> str:
        self._key += 1
        key = 'k%d' % self._key
        intent = parse(json.dumps({'model': ALIAS, 'input': 'x'}).encode())
        with self.broker.receipt_ref(
                'p1', submit_body(intent.body_hash, key)) as ref:
            return self.gateway.submit(intent, key, ref).run_id

    def controller(self, run_id, **kw):
        args = dict(state=self.ctrl, judgment=self.store.judgment(),
            catalog=self.bundle.catalog, usage=UsageStore(),
            adapters={RESPONSES: self.pool},
            acceptance=Acceptance(lambda req: (_ for _ in ()).throw(
                AssertionError('AC must not run'))),
            planner=self.planner, clock=lambda: NOW_DT,
            output_store=self.out)
        args.update(kw)
        return Controller(run_id, **args)

    def driver(self):
        def factory(run_id, snapshot):
            self.built.append(run_id)
            return self.controller(run_id)
        return ServiceDriver(self.owner, self.store, self.gateway,
                             controller_factory=factory)

    def admit_attempt(self, run_id):
        """Two real steps: plan judgment, then dispatch admission."""
        ctl = self.controller(run_id)
        self.assertEqual(ctl.step().reason, 'next_job')
        self.assertEqual(ctl.step().reason, 'execute_receipt')
        attempts = self.ctrl.attempts(run_id)
        self.assertEqual(len(attempts), 1)
        return ctl, attempts[0].ref

    def test_tuple_identity_shared_across_modules(self):
        self.assertIs(ctl_mod.GLOBAL_FAILURES, GLOBAL_FAILURES)
        self.assertIs(drv_mod.GLOBAL_FAILURES, GLOBAL_FAILURES)
        self.assertEqual(len(GLOBAL_FAILURES), 3)
        self.assertIs(GLOBAL_FAILURES[0], state.StoreUnavailable)
        self.assertIs(GLOBAL_FAILURES[1], service_owner.OwnerUnavailable)
        self.assertIs(GLOBAL_FAILURES[2], sqlite3.Error)
        self.assertNotIn(NotFound, GLOBAL_FAILURES)
        self.assertNotIn(IntegrityViolation, GLOBAL_FAILURES)
        root = str(Path(__file__).resolve().parent.parent)
        out = subprocess.run(
            [sys.executable, '-c',
             'import co_v4.failures as f\n'
             'assert len(f.GLOBAL_FAILURES) == 3'],
            env={'PATH': '/usr/bin:/bin', 'PYTHONPATH': root},
            cwd=root, capture_output=True, timeout=30)
        self.assertEqual(out.returncode, 0)

    def test_resolver_typeerror_escapes_unchanged(self):
        run_id = self.submit()
        ctl = self.controller(run_id)
        before = self.ctrl.get_run(run_id)
        baseline = self.ctrl.checkpoint(run_id)
        real = self.store.judgment_view
        self.store.judgment_view = lambda rid: (_ for _ in ()).throw(
            TypeError('resolver code bug'))
        try:
            with self.assertRaises(StoreUnavailable):
                ctl.step()
        finally:
            self.store.judgment_view = real
        self.assertFalse(ctl._lock.locked())      # lock released
        after = self.ctrl.get_run(run_id)
        self.assertEqual((after.state, after.revision),
                         (before.state, before.revision))
        self.assertEqual(self.ctrl.checkpoint(run_id), baseline)
        self.assertEqual(self.ctrl.history(run_id, 'driver_audit'), ())
        self.assertNotIn(after.state, c.TERMINAL)

    def test_caller_handled_global_does_not_skip_clean_save(self):
        # Regression for the sys.exc_info design: a clean step run by a
        # caller still inside its `except StoreUnavailable` block must
        # checkpoint — the marker is local to the escaping step only.
        run_id = self.submit()
        ctl = self.controller(run_id)
        try:
            raise StoreUnavailable('caller-handled elsewhere')
        except StoreUnavailable:
            self.assertEqual(ctl.step().reason, 'next_job')
            self.assertIsNotNone(
                self.ctrl.checkpoint(run_id).plan)

    def test_driver_global_propagates_no_audit_owner_consulted(self):
        self.submit()
        run_id = self.gateway.pending_work()[0]
        drv = self.driver()
        real = self.store.judgment_view
        self.store.judgment_view = lambda rid: (_ for _ in ()).throw(
            TypeError('resolver code bug'))
        try:
            for _ in range(2):                  # every tick re-fails
                with self.assertRaises(StoreUnavailable):
                    drv.tick()
        finally:
            self.store.judgment_view = real
        self.assertEqual(self.ctrl.history(run_id, 'driver_audit'), ())
        self.assertNotIn(self.ctrl.get_run(run_id).state, c.TERMINAL)
        self.assertGreater(self.owner.calls, 0)     # owner consulted
        drv.tick()                                  # healthy tick works
        self.assertEqual(self.built, [run_id])

    def test_owner_loss_mid_poll_held_attempt_zero_stops(self):
        run_id = self.submit()
        ctl, ref = self.admit_attempt(run_id)
        self.assertEqual(self.ledger.row(ref, RESPONSES)[2], 'executing')
        baseline = self.ctrl.checkpoint(run_id)
        stops = []
        real_stop = self.pool.stop
        self.pool.stop = lambda r: (stops.append(r), real_stop(r))[1]
        real_events = self.pool.events
        def events(r, after=None):
            self.owner.broken = True      # owner lost inside the poll
            return real_events(r, after)
        self.pool.events = events
        calls = self.owner.calls
        with self.assertRaises(OwnerUnavailable) as caught:
            ctl.step()
        self.assertEqual(caught.exception.code, 'owner_lost')
        self.assertGreater(self.owner.calls, calls)   # guard consulted
        self.assertEqual(stops, [])                   # zero Native stop
        self.owner.broken = False     # restore before guarded reads
        self.pool.events = real_events   # disarm before restart step
        self.pool.stop = real_stop
        self.assertEqual(self.ledger.row(ref, RESPONSES)[2], 'executing')
        self.assertEqual(self.ctrl.checkpoint(run_id), baseline)
        self.assertIsNone(self.ctrl.get_attempt(ref).result)
        self.assertFalse(ctl._lock.locked())          # lock released
        # Production-discarded instance: recovery goes through a fresh
        # Controller on the same committed store.
        progress = self.controller(run_id).step()
        self.assertEqual(progress.state, c.State.RUNNING)
        self.assertEqual(self.ledger.row(ref, RESPONSES)[2], 'executing')

    def test_sqlite_error_in_reserve_global_no_attempt(self):
        run_id = self.submit()
        ctl = self.controller(run_id)
        self.assertEqual(ctl.step().reason, 'next_job')
        baseline = self.ctrl.checkpoint(run_id)
        with mock.patch.object(self.ledger, 'reserve',
                               side_effect=sqlite3.Error('raw db error')):
            with self.assertRaises(sqlite3.Error):
                ctl.step()
        self.assertFalse(ctl._lock.locked())
        self.assertEqual(self.ctrl.attempts(run_id), ())   # no admission
        self.assertEqual(self.ctrl.checkpoint(run_id), baseline)
        self.assertNotIn(self.ctrl.get_run(run_id).state, c.TERMINAL)
        reopened = self.controller(run_id)                 # discard+restart
        self.assertEqual(reopened.step().reason, 'execute_receipt')

    def test_global_inside_fatal_cleanup_propagates_original(self):
        run_id = self.submit()
        ctl, ref = self.admit_attempt(run_id)
        ctl._halted = 'integrity_violation'    # enter the fatal gate
        self.assertEqual(ctl.step().reason,
                         'integrity_violation_stop_unconfirmed')
        baseline = self.ctrl.checkpoint(run_id)   # latch persisted
        self.assertEqual(baseline.halted, 'integrity_violation')
        self.assertEqual(self.ledger.row(ref, RESPONSES)[2], 'executing')
        real_stop = self.pool.stop
        def stop(r):
            reply = real_stop(r)
            self.owner.broken = True   # store dies inside fatal cleanup
            return reply
        self.pool.stop = stop
        with self.assertRaises(OwnerUnavailable) as caught:
            ctl.step()
        self.assertEqual(caught.exception.code, 'owner_lost')
        self.owner.broken = False     # restore before guarded reads
        self.pool.stop = real_stop     # disarm before restart step
        self.assertFalse(ctl._lock.locked())
        self.assertEqual(self.ctrl.checkpoint(run_id), baseline)
        self.assertEqual(self.ledger.row(ref, RESPONSES)[2], 'executing')
        self.assertIsNone(self.ctrl.get_attempt(ref).result)
        self.assertNotIn(self.ctrl.get_run(run_id).state, c.TERMINAL)
        # Restart recovers the persisted latch; real cleanup is honest:
        # held view, no invented Result, lease still held.
        held = self.controller(run_id).step()
        self.assertEqual((held.state, held.reason),
                         (c.State.RUNNING,
                          'integrity_violation_stop_unconfirmed'))
        self.assertIsNone(self.ctrl.get_attempt(ref).result)
        self.assertEqual(self.ledger.row(ref, RESPONSES)[2], 'executing')

    def test_ordinary_valueerror_per_run_error_other_normal(self):
        bad_id = self.submit()
        good_id = self.submit()
        bad = self.controller(bad_id, planner=lambda *a: (
            _ for _ in ()).throw(ValueError('planner bug')))
        progress = bad.step()
        self.assertEqual((progress.state, progress.reason),
                         (c.State.ERROR, 'controller_error'))
        self.assertEqual(self.ctrl.get_run(bad_id).final_reason,
                         'controller_error')
        good = self.controller(good_id)
        self.assertEqual(good.step().reason, 'next_job')
        self.assertEqual(self.ctrl.get_run(good_id).state,
                         c.State.PENDING)


if __name__ == '__main__':
    unittest.main()
