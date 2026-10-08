"""#190 M3 service_host lifecycle on the real protected stack.

Real ServiceOwner on a same-uid 0700 APFS root, guard-bound ControlStore,
OutputStore, Gateway, CapacityLedger, PooledAdapter, real registry/check_
store/recovery and real Controller construction on ticks. Runs are seeded
through the real Gateway.submit with one-shot IngressBroker receipts and
canonical intents. The only stand-in is the HTTP fixture (counted close
contract); SDK round-trip coverage lives in the HTTP tests. Planner is a
fixed None -- this is host lifecycle, not task planning.
"""
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
from threading import Event
import time
import unittest
from unittest import mock

from co_v4 import contracts as c
from co_v4.ac import Acceptance
from co_v4.adapter_capacity import CapacityLedger, PooledAdapter
from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.controller import Controller
from co_v4.gateway_store import Gateway, submit_body
from co_v4.http_auth import IngressBroker
from co_v4.judgment import TrustedEvidence
from co_v4.openai_transport import Deadlines
from co_v4.output_store import OutputStore
from co_v4.profile_registry import (ProfileRegistryMismatch, RouteConfig,
                                    load_registry, revision_digest)
from co_v4.protocol_profile import RouteProtocolProfile, environment_ref
from co_v4.responses_input import parse
from co_v4.service_driver import ServiceDriver
from co_v4.service_owner import OwnerUnavailable, ServiceOwner
import co_v4.service_host as sh
from co_v4.service_host import Components, ServiceHost
from co_v4.state import ControlStore, body_digest
from co_v4.usage import UsageStore
from test_adapter_capacity import Child
from test_profile_registry import registry_doc, wire_entry

NOW = '2026-10-06T00:00:00Z'
NOW_DT = datetime(2026, 10, 6, tzinfo=timezone.utc)
MODEL, ADAPTER = 'm', 'openai.responses'
ENDPOINT, AUTH_REF = 'https://provider.test/v1', 'cred-main'
ROUTE_PROFILE = RouteProtocolProfile('responses', 'present', 'present',
                                     {}, MODEL, 'ab' * 32)
ENV = environment_ref(ENDPOINT, AUTH_REF, ROUTE_PROFILE.profile_digest)
USE = UseCase('general')
CATALOG = Catalog((CatalogEntry(MODEL, ADAPTER, {USE: 2}, (
    Verification(MODEL, ADAPTER, USE, ENV, 'r:o', 'r:i', 'r:m', 'r:a',
                 output_mode='collect'),)),))
ROUTE = RouteConfig(MODEL, ADAPTER, ENV, ENDPOINT, AUTH_REF,
                    Deadlines(total=100), 20, ROUTE_PROFILE)
GHOST = c.TaskProfile('co-text', 'sha256:' + '9' * 64, 'pure', True,
                      ((MODEL, ADAPTER, ENV),))


class HttpFixture:
    """Only stand-in: counted close() honoring the fixed contract."""
    def __init__(self):
        self.result, self.exc, self.calls = 'stopped', None, 0
        self.starts = 0

    def start(self):
        self.starts += 1              # unstarted-object contract: no-op

    def close(self):
        self.calls += 1
        if self.exc is not None:
            raise self.exc
        return self.result


class ServiceHostTests(unittest.TestCase):
    def setUp(self):
        self.tmpd = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpd.cleanup)
        self.tmp = Path(self.tmpd.name)
        self.root = (self.tmp / 'root').resolve()
        self.root.mkdir(mode=0o700)
        w = wire_entry()
        self.registry = load_registry(json.dumps(registry_doc([w],
            [{'alias': 'co-text', 'profile_id': 'co-text',
              'revision_digest': revision_digest(w)}])),
            catalog=CATALOG, routes=(ROUTE,))
        self.pinned = self.registry.resolve('co-text')
        self._reset()

    def _reset(self):
        self.children, self.built, self.order = [], [], []
        self.http, self.comp, self.pool = None, None, None

    def _evidence(self, run, request):
        return TrustedEvidence(body_digest(request), 'f:policy',
            ('f:controls',), 'f:op', False, False, True, True, True, True)

    def seed(self, specs):
        """Real Gateway.submit Runs; optional pinned-field/terminal edits."""
        owner = ServiceOwner.acquire(self.root)
        broker = IngressBroker(lambda: NOW)
        store = ControlStore(self.root / 'control.sqlite',
            verifier=broker.verifier, evidence=self._evidence,
            clock=lambda: NOW, profile_resolver=self.registry.resolve,
            guard=owner.check)
        gateway = Gateway(store,
            bound_resolver=self.registry.unconfirmed_after_seconds)
        try:
            for spec in specs:
                intent = parse(json.dumps(
                    {'model': 'co-text', 'input': 'x'}).encode())
                with broker.receipt_ref('p', submit_body(
                        intent.body_hash, None)) as ref:
                    run_id = gateway.submit(intent, None, ref).run_id
                if spec.get('profile') is not None:
                    self._patch_run(store, run_id, profile=spec['profile'])
                if spec.get('terminal'):
                    self._patch_run(store, run_id, state=c.State.FAILED,
                                    final_reason='run_failed')
        finally:
            store.close()
            owner.close()

    @staticmethod
    def _patch_run(store, run_id, **fields):
        with store._tx():
            data, before = store._load_locked(run_id)
            data['run'] = replace(data['run'], **fields)
            store._store_locked(run_id, data, before)

    def build(self, owner, retain):
        # Owner must already hold the lock before build constructs anything.
        with self.assertRaises(OwnerUnavailable) as caught:
            ServiceOwner.acquire(self.root)
        self.assertEqual(caught.exception.code, 'owned_elsewhere')
        self.order.append('build')
        self.broker = IngressBroker(lambda: NOW)
        store = retain(ControlStore(self.root / 'control.sqlite',
            verifier=self.broker.verifier,
            evidence=self._evidence, clock=lambda: NOW,
            profile_resolver=self.registry.resolve, guard=owner.check))
        out = OutputStore(self.root / 'outputs', guard=owner.check)
        ledger = CapacityLedger(self.root / 'capacity.sqlite')
        self.pool = retain(PooledAdapter(ADAPTER, ledger=ledger,
            canonical_ledger=ledger.path,
            factory=lambda req: (self.children.append(req), Child())[1]))
        self.comp = Components(store,
            Gateway(store,
                    bound_resolver=self.registry.unconfirmed_after_seconds),
            out, ledger, {ADAPTER: self.pool}, self.registry,
            self.http_factory, self.controller_factory)
        return self.comp

    def http_factory(self, available):
        self.order.append('http')
        self.avail = available
        self.http = HttpFixture()
        return self.http

    def controller_factory(self, run_id, snapshot):
        self.built.append(run_id)
        store = self.comp.store
        return Controller(run_id, state=store.controller(),
            judgment=store.judgment(), catalog=Catalog(),
            usage=UsageStore(), adapters={ADAPTER: self.pool},
            acceptance=Acceptance(lambda req: (_ for _ in ()).throw(
                AssertionError('verifier must not run'))),
            planner=lambda *_: None, clock=lambda: NOW_DT,
            output_store=self.comp.output_store)

    def host(self, **kw):
        kw.setdefault('tick_interval', 0.02)
        kw.setdefault('join_bound', 0.3)
        host = ServiceHost(self.root, self.build, **kw)
        self.addCleanup(host.close)
        return host

    def held(self):
        with self.assertRaises(OwnerUnavailable) as caught:
            ServiceOwner.acquire(self.root)
        self.assertEqual(caught.exception.code, 'owned_elsewhere')

    def released(self):
        ServiceOwner.acquire(self.root).close()

    def test_order_owner_first_http_last(self):
        real_cs, real_rs = sh.check_store, sh.recovery_scan

        def cs(*a):
            self.order.append('check_store')
            return real_cs(*a)

        def rs(*a):
            self.order.append('recovery')
            return real_rs(*a)

        def drv(*a, **kw):
            d = ServiceDriver(*a, **kw)
            self.order.append('driver_new')
            orig = d.start
            d.start = lambda: (self.order.append('driver_start'), orig())[1]
            return d

        with mock.patch.object(sh, 'check_store', cs), \
                mock.patch.object(sh, 'recovery_scan', rs), \
                mock.patch.object(sh, 'ServiceDriver', drv):
            host = self.host()
            host.start()
        self.assertEqual(self.order, ['build', 'check_store', 'recovery',
                                      'driver_new', 'driver_start', 'http'])
        self.assertEqual(self.http.starts, 1)
        self.assertTrue(self.avail())
        self.assertEqual(host.close(), 'stopped')
        self.assertFalse(self.avail())
        self.released()

    def test_missing_revision_no_http_no_tick_single_shot(self):
        self.seed([{'profile': GHOST}])
        host = self.host()
        with self.assertRaises(ProfileRegistryMismatch):
            host.start()
        self.assertIsNone(self.http)
        self.assertIsNone(host._thread)
        self.released()                     # clean teardown freed the lock
        with self.assertRaises(ValueError):
            host.start()                    # single-shot after failure

    def test_quarantine_audit_once_zero_controller(self):
        bad = replace(self.pinned, routes=((MODEL, ADAPTER, 'env:x'),))
        self.seed([{}, {'profile': bad}])
        host = self.host()
        host.start()
        state = self.comp.store.controller()
        bad_id = [r for r in self.gateway_runs()
                  if state.get_run(r).profile.routes[0][2] == 'env:x'][0]
        audits = state.history(bad_id, 'driver_audit')
        self.assertEqual([a[:2] for a in audits],
                         [('driver_project_error', 'integrity')])
        deadline = time.monotonic() + 5
        while not self.built and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertNotIn(bad_id, self.built)
        self.assertEqual(len(self.built), 1)
        self.assertEqual(self.children, [])
        self.assertEqual(host.close(), 'stopped')

    def gateway_runs(self):
        return tuple(r[0] for r in self.comp.store._db.execute(
            'SELECT run_id FROM gateway_work'))

    def test_terminal_failed_row_validated_at_start(self):
        self.seed([{'terminal': True}])
        host = self.host()
        host.start()
        row = self.comp.store._db.execute(
            'SELECT status, code FROM gateway_projections').fetchone()
        self.assertEqual(row, ('failed', 'run_failed'))
        self.assertEqual(host.close(), 'stopped')

    def test_global_tick_failure_latches_leases_held(self):
        self.seed([])
        host = self.host()
        host.start()
        real_tick = host._driver.tick
        calls = []
        host._driver.tick = lambda: (calls.append(1), real_tick())[1]
        ref = c.AttemptRef('held', 'j', 'a')
        request = c.ExecuteRequest(ref, c.Job('held', 'j', 'do', ('k',)),
            c.ExecutionConditions(MODEL, ADAPTER, '/w', ENV))
        self.pool.reserve(request)
        self.comp.store._db.execute(
            'INSERT INTO gateway_work VALUES (?,?)', ('ghost', NOW))
        deadline = time.monotonic() + 5
        while self.avail() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(self.avail())          # latched, ticking stopped
        n = len(calls)
        time.sleep(0.15)
        self.assertEqual(len(calls), n)
        self.assertEqual(self.comp.ledger.row(ref, ADAPTER)[2], 'reserved')
        self.assertEqual(host.close(), 'stopped')
        # pools.close makes no cessation claim: the lease is still held.
        self.assertEqual(self.comp.ledger.row(ref, ADAPTER)[2], 'reserved')
        self.assertEqual(self.children, [])      # zero factory/Native calls
        self.released()

    def test_blocked_driver_unconfirmed_then_retry_owner_last(self):
        self.seed([])
        host = self.host(join_bound=0.2)
        host.start()
        entered, release = Event(), Event()
        real_tick = host._driver.tick

        def blocked():
            entered.set()
            release.wait(30)
            return real_tick()

        host._driver.tick = blocked
        try:
            self.assertTrue(entered.wait(5))
            closed = []
            real_sc = self.comp.store.close
            self.comp.store.close = \
                lambda: (closed.append('store'), real_sc())[1]
            real_oc = host._owner.close
            host._owner.close = \
                lambda: (closed.append('owner'), real_oc())[1]
            self.assertEqual(host.close(), 'host_stop_unconfirmed')
            host._owner.check()                  # owner still held
            self.assertEqual(self.comp.store._db.execute(
                'SELECT 1').fetchone(), (1,))    # store still usable
            self.held()
        finally:
            release.set()                        # never hang the fixture
        self.assertEqual(host.close(), 'stopped')
        self.assertEqual(closed, ['store', 'owner'])
        self.released()

    def test_http_factory_failure_no_socket_releases(self):
        self.seed([])
        self.http_factory = lambda _avail: (_ for _ in ()).throw(
            OSError('socket refused'))
        host = self.host()
        with self.assertRaises(OSError):
            host.start()
        self.assertIsNone(self.http)             # no listener bound
        self.released()
        with self.assertRaises(ValueError):
            host.start()                         # single-shot

    def test_http_failure_blocked_driver_retains_owner(self):
        # http_factory raises while the driver thread is inside a blocked
        # tick: teardown cannot confirm the writer, so owner/stores/leases
        # stay held until a later close() after the writer is released.
        self.seed([])
        entered, release = Event(), Event()
        real_driver = ServiceDriver

        def drv(*a, **kw):
            d = real_driver(*a, **kw)
            d.tick = lambda: (entered.set(), release.wait(30),
                              ServiceDriver.tick(d))[2]
            return d

        def http_factory(_avail):
            self.assertTrue(entered.wait(5))     # tick is blocked NOW
            raise OSError('socket refused')

        self.http_factory = http_factory
        host = self.host(join_bound=0.2)
        try:
            with mock.patch.object(sh, 'ServiceDriver', drv):
                with self.assertRaises(OSError):
                    host.start()
            self.assertIsNone(self.http)
            self.held()                          # retained, not released
        finally:
            release.set()                        # never hang the fixture
        self.assertEqual(host.close(), 'stopped')
        self.released()

    def test_driver_thread_start_failure_releases_owner(self):
        # Real Thread objects, real stack: start() raises before the
        # thread is ever spawned. _drain must not join() it (RuntimeError
        # would mask the refusal and hold the owner forever); the
        # original error propagates and the owner is released.
        self.seed([])
        constructed = []
        real_thread = sh.Thread

        def thread_ctor(*a, **kw):
            t = real_thread(*a, **kw)
            constructed.append(t)
            t.start = lambda: (_ for _ in ()).throw(
                OSError('start refused'))
            return t

        host = self.host()
        with mock.patch.object(sh, 'Thread', thread_ctor):
            with self.assertRaises(OSError) as caught:
                host.start()
        self.assertEqual(str(caught.exception), 'start refused')
        self.assertEqual(len(constructed), 1)      # real object retained
        self.assertIsNone(host._thread)            # dropped, never joined
        self.assertIsNone(host._http)              # never reached
        self.released()                            # real acquire: freed


    def test_http_close_unconfirmed_variants(self):
        self.seed([])
        host = self.host()
        host.start()
        for result in (None, False, 'host_stop_unconfirmed', 'other'):
            self.http.result = result
            self.assertEqual(host.close(), 'host_stop_unconfirmed')
            self.held()
        self.http.exc = OSError('fixture')
        self.assertEqual(host.close(), 'host_stop_unconfirmed')
        self.held()
        self.http.exc = None
        self.http.result = 'stopped'
        self.assertEqual(host.close(), 'stopped')
        self.released()
        self.assertGreaterEqual(self.http.calls, 5)

    def test_resource_close_failure_retained_then_retry(self):
        for which in ('adapters', 'store'):
            with self.subTest(which=which):
                self._reset()
                self.seed([])
                host = self.host()
                host.start()
                calls = []
                target = (self.pool if which == 'adapters'
                          else self.comp.store)
                real = target.close

                def flaky():
                    calls.append(1)
                    if len(calls) == 1:
                        raise OSError('fixture')
                    return real()

                target.close = flaky
                self.assertEqual(host.close(), 'host_stop_unconfirmed')
                self.held()                     # owner retained on failure
                self.assertEqual(host.close(), 'stopped')
                self.released()
                self.assertEqual(len(calls), 2)

    def test_bounds_and_single_shot_after_close(self):
        for kw in ({'tick_interval': True}, {'tick_interval': float('nan')},
                   {'tick_interval': float('inf')}, {'tick_interval': 0},
                   {'tick_interval': -1}, {'join_bound': False},
                   {'join_bound': float('nan')}, {'join_bound': 'x'}):
            with self.subTest(kw=kw):
                with self.assertRaises(ValueError):
                    ServiceHost(self.root, self.build, **kw)
        with self.assertRaises(ValueError):
            ServiceHost(self.root, None)
        host = self.host()
        host.start()
        self.assertEqual(host.close(), 'stopped')
        with self.assertRaises(ValueError):
            host.start()                        # single-shot after close
        self.assertEqual(host.close(), 'stopped')   # idempotent
        self.released()

    def test_gateway_must_bind_the_same_store(self):
        other = ControlStore(self.tmp / 'other.sqlite',
            verifier=lambda ref: None,
            evidence=self._evidence, clock=lambda: NOW)
        self.addCleanup(other.close)
        real_build = self.build

        def bad_build(owner, retain):
            comp = real_build(owner, retain)
            return replace(comp, gateway=Gateway(
                other, bound_resolver=lambda *_: None))

        host = ServiceHost(self.root, bad_build, tick_interval=0.02,
                           join_bound=0.3)
        with self.assertRaises(ValueError):
            host.start()
        self.assertIsNone(self.http)
        # Owned comp.store is torn down by _release; the foreign Gateway's
        # store is the fixture's own (addCleanup), never touched by the host.
        with self.assertRaises(sqlite3.ProgrammingError):
            self.comp.store._db.execute('SELECT 1')
        self.released()                         # refusal freed the lock


if __name__ == '__main__':
    unittest.main()
