"""#190 M3 retain handoff for partial host builds (Opus ownership ruling).

Real ServiceOwner on a same-uid 0700 root, real ControlStore/OutputStore/
CapacityLedger/PooledAdapter. The builder retains each handle-owning
object (the ControlStore and each pool) at birth and never closes
anything; OutputStore is descriptor-free and verified, not retained.
Injected faults live only in resource close() methods and persist
through automatic teardown AND the
first explicit close() so the unconfirmed path is genuinely exercised.
Ownership proof is a real second process probing the flock. Nothing here
fakes Native or cessation evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.adapter_capacity import (CapacityError, CapacityLedger,
                                    PooledAdapter)
from co_v4.gateway_store import Gateway
from co_v4.http_auth import IngressBroker
from co_v4.judgment import TrustedEvidence
from co_v4.output_store import OutputStore
from co_v4.profile_registry import load_registry, revision_digest
from co_v4.service_host import Components, ServiceHost
from co_v4.state import ControlStore, StoreUnavailable, body_digest
from test_adapter_capacity import Child
from test_profile_registry import registry_doc, wire_entry
from test_service_host import ADAPTER, CATALOG, HttpFixture, NOW, ROUTE


class _Dummy:
    """Closeable foreign/extra resource; records every close call."""
    def __init__(self):
        self.closed = 0
    def close(self):
        self.closed += 1


class PartialBuildRetainTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()          # Darwin realpath
        self.root = self.tmp / 'root'
        self.root.mkdir(mode=0o700)
        w = wire_entry()
        self.registry = load_registry(json.dumps(registry_doc([w], [])),
                                      catalog=CATALOG, routes=(ROUTE,))
        self.order = []

    def probe(self):
        """Real second-process owner probe; fixed code only."""
        script = ('import os, sys\n'
                  'sys.path.insert(0, %r)\n'
                  'from co_v4.service_owner import (ServiceOwner,'
                  ' OwnerUnavailable)\n'
                  'try:\n'
                  '    owner = ServiceOwner.acquire(sys.argv[1])\n'
                  '    owner.close()\n'
                  '    print("free")\n'
                  'except OwnerUnavailable as e:\n'
                  '    print(e.code)\n' % os.getcwd())
        out = subprocess.run([sys.executable, '-c', script, str(self.root)],
                             capture_output=True, text=True, timeout=30,
                             env={'PATH': '/usr/bin:/bin'})
        self.assertEqual(out.returncode, 0, out.stderr[:500])
        return out.stdout.strip()

    def _store(self, owner, retain):
        return retain(ControlStore(
            self.root / 'control.sqlite',
            verifier=IngressBroker(lambda: NOW).verifier,
            evidence=lambda r, q: TrustedEvidence(
                body_digest(q), 'f:policy', ('f:controls',), 'f:op',
                False, False, True, True, True, True),
            clock=lambda: NOW,
            profile_resolver=self.registry.resolve,
            guard=owner.check))

    def _pool(self, ledger):
        return PooledAdapter(ADAPTER, ledger=ledger,
            canonical_ledger=ledger.path,
            factory=lambda req: Child())

    def _comp(self, store, out, ledger, pools):
        return Components(
            store=store,
            gateway=Gateway(
                store,
                bound_resolver=self.registry.unconfirmed_after_seconds),
            output_store=out, ledger=ledger, adapters=pools,
            registry=self.registry,
            http_factory=lambda avail: HttpFixture(),
            controller_factory=lambda run_id, snap: None)

    def test_store_close_fault_held_then_released_last(self):
        fault = {'on': True}
        calls, order = [], []

        def build(owner, retain):
            store = self._store(owner, retain)
            real_sc = store.close
            def flaky():
                calls.append('store')
                if fault['on']:
                    raise OSError('fixture')
                order.append('store')
                return real_sc()
            store.close = flaky
            OutputStore(self.root / 'outputs', guard=owner.check)
            ledger = CapacityLedger(self.root / 'capacity.sqlite')
            # Real pool-constructor failure after both stores retained.
            PooledAdapter('bogus.adapter', ledger=ledger,
                          canonical_ledger=ledger.path,
                          factory=lambda r: None)

        host = ServiceHost(self.root, build, tick_interval=0.02,
                           join_bound=0.3)
        self.addCleanup(host.close)
        # LIFO: registered after host.close, so the fault is cleared
        # BEFORE the real host close and TemporaryDirectory teardown —
        # never owned state removed under an unconfirmed owner.
        self.addCleanup(fault.update, {'on': False})
        with self.assertRaises(CapacityError):
            host.start()              # auto-teardown already hit the fault
        self.assertEqual(calls, ['store'])
        self.assertEqual(host.close(), 'host_stop_unconfirmed')
        self.assertEqual(calls, ['store', 'store'])   # fault persists
        self.assertEqual(self.probe(), 'owned_elsewhere')
        fault['on'] = False
        real_own = host._owner.close
        host._owner.close = lambda: (order.append('owner'), real_own())[1]
        self.assertEqual(host.close(), 'stopped')
        self.assertEqual(calls, ['store', 'store', 'store'])
        self.assertEqual(order, ['store', 'owner'])
        self.assertEqual(self.probe(), 'free')

    def test_pool_close_fault_order_and_owner_last(self):
        fault = {'on': True}
        order = []

        def build(owner, retain):
            store = self._store(owner, retain)
            real_sc = store.close
            store.close = lambda: (order.append('store'), real_sc())[1]
            OutputStore(self.root / 'outputs', guard=owner.check)
            ledger = CapacityLedger(self.root / 'capacity.sqlite')
            pool = retain(self._pool(ledger))
            real_pc = pool.close
            def flaky():
                order.append('pool')
                if fault['on']:
                    raise OSError('fixture')
                return real_pc()
            pool.close = flaky
            raise RuntimeError('post-pool failure')

        host = ServiceHost(self.root, build, tick_interval=0.02,
                           join_bound=0.3)
        self.addCleanup(host.close)
        self.addCleanup(fault.update, {'on': False})   # LIFO before close
        with self.assertRaises(RuntimeError):
            host.start()
        # First failure stopped the order: the store was NOT closed
        # while the pool close was unconfirmed.
        self.assertEqual(order, ['pool'])
        self.assertEqual(host.close(), 'host_stop_unconfirmed')
        self.assertEqual(order, ['pool', 'pool'])
        self.assertEqual(self.probe(), 'owned_elsewhere')
        fault['on'] = False
        real_own = host._owner.close
        host._owner.close = lambda: (order.append('owner'),
                                     real_own())[1]
        self.assertEqual(host.close(), 'stopped')
        self.assertEqual(order,
                         ['pool', 'pool', 'pool', 'store', 'owner'])
        self.assertEqual(self.probe(), 'free')

    def test_failure_before_any_retain_releases_owner(self):
        def build(owner, retain):
            raise RuntimeError('phase-B refusal before any handle')
        host = ServiceHost(self.root, build, tick_interval=0.02,
                           join_bound=0.3)
        self.addCleanup(host.close)
        with self.assertRaises(RuntimeError):
            host.start()
        self.assertEqual(host.close(), 'stopped')
        self.assertEqual(self.probe(), 'free')

    def test_identity_mismatch_never_accepts_comp(self):
        for variant in ('skip_pool', 'extra', 'skip_store', 'alias_pool'):
            with self.subTest(variant=variant):
                self.order = []
                self.orphan, dummy = None, _Dummy()

                def build(owner, retain):
                    keep = retain if variant != 'skip_store' \
                        else (lambda r: r)
                    store = self._store(owner, keep)
                    out = OutputStore(self.root / 'outputs',
                                      guard=owner.check)
                    ledger = CapacityLedger(
                        self.root / 'capacity.sqlite')
                    pool = self._pool(ledger)
                    pools = ({ADAPTER: pool, 'openai.chat': pool}
                             if variant == 'alias_pool'
                             else {ADAPTER: pool})
                    if variant == 'alias_pool':
                        real_pc = pool.close
                        pool.close = lambda: (
                            self.order.append('pool'), real_pc())[1]
                    if variant == 'skip_pool':
                        self.orphan = pool      # test-owned cleanup
                    else:
                        retain(pool)
                    if variant == 'extra':
                        retain(dummy)
                    if variant == 'skip_store':
                        self.orphan = store
                    return self._comp(store, out, ledger, pools)

                host = ServiceHost(self.root, build,
                                   tick_interval=0.02, join_bound=0.3)
                self.addCleanup(host.close)
                try:
                    with self.assertRaises(ValueError):
                        host.start()
                finally:
                    if self.orphan is not None:   # fixture-owned cleanup
                        self.orphan.close()
                if variant == 'extra':
                    self.assertEqual(dummy.closed, 1)
                if variant == 'alias_pool':
                    self.assertEqual(self.order, ['pool'])  # no double close
                self.assertEqual(host.close(), 'stopped')
                self.assertEqual(self.probe(), 'free')

    def test_retain_scope_and_duplicate_refusal(self):
        captured = []

        def build(owner, retain):
            store = self._store(owner, retain)
            out = OutputStore(self.root / 'outputs', guard=owner.check)
            ledger = CapacityLedger(self.root / 'capacity.sqlite')
            pool = retain(self._pool(ledger))
            captured.append(retain)
            return self._comp(store, out, ledger, {ADAPTER: pool})

        host = ServiceHost(self.root, build, tick_interval=0.02,
                           join_bound=0.3)
        self.addCleanup(host.close)
        host.start()
        with self.assertRaises(ValueError):   # late retain, no authority
            captured[0](_Dummy())
        with self.assertRaises(ValueError):   # non-closeable retained
            captured[0](object())
        self.assertEqual(host.close(), 'stopped')

        def dup(owner, retain):
            store = self._store(owner, retain)
            retain(store)                     # duplicate identity refuse
        host2 = ServiceHost(self.root, dup, tick_interval=0.02,
                            join_bound=0.3)
        self.addCleanup(host2.close)
        with self.assertRaises(ValueError):
            host2.start()
        self.assertEqual(host2.close(), 'stopped')
        self.assertEqual(self.probe(), 'free')

    def test_output_store_construction_failure_unwinds(self):
        """The retained real store unwinds after a REAL OutputStore
        constructor failure. The bad root is a TEST-OWNED foreign path —
        a regular file — never inside the owner root: _check_entries at
        acquire would refuse it before build, and owner.check verifies
        the actual owner root, so guard=owner.check passes and mkdir
        performs the real failing mutation (NotADirectoryError)."""
        bad = self.tmp / 'bad_outputs'
        bad.write_bytes(b'x')                 # file, not a directory

        def build(owner, retain):
            store = self._store(owner, retain)
            real = store.close
            store.close = lambda: (self.order.append('store'), real())[1]
            OutputStore(bad, guard=owner.check)   # real OSError here

        host = ServiceHost(self.root, build, tick_interval=0.02,
                           join_bound=0.3)
        self.addCleanup(host.close)
        with self.assertRaises(OSError):
            host.start()
        self.assertEqual(self.order, ['store'])
        self.assertEqual(host.close(), 'stopped')
        self.assertEqual(self.probe(), 'free')

    def test_control_store_construction_failure(self):
        """A REAL ControlStore constructor failure unwinds with nothing
        retained. The bad DB path is a TEST-OWNED foreign directory —
        never inside the owner root: _check_entries at acquire would
        refuse it before build. owner.check verifies the actual owner
        root (guard passes); sqlite3.connect on a directory fails and
        ControlStore wraps it as StoreUnavailable — the fixed error, not
        the raw sqlite3 exception."""
        bad = self.tmp / 'bad_db'
        bad.mkdir()                           # directory, not a file

        def build(owner, retain):
            retain(ControlStore(              # ctor raises; retain()
                bad,                          # is never reached
                verifier=IngressBroker(lambda: NOW).verifier,
                evidence=lambda r, q: TrustedEvidence(
                    body_digest(q), 'f:policy', ('f:controls',), 'f:op',
                    False, False, True, True, True, True),
                clock=lambda: NOW,
                profile_resolver=self.registry.resolve,
                guard=owner.check))

        host = ServiceHost(self.root, build, tick_interval=0.02,
                           join_bound=0.3)
        self.addCleanup(host.close)
        with self.assertRaises(StoreUnavailable):
            host.start()
        self.assertEqual(host.close(), 'stopped')
        self.assertEqual(self.probe(), 'free')

    def test_retain_output_store_refused(self):
        """OutputStore has no close(): _retain refuses with ValueError and
        the already-retained store unwinds in order."""
        def build(owner, retain):
            self._store(owner, retain)
            retain(OutputStore(self.root / 'outputs', guard=owner.check))

        host = ServiceHost(self.root, build, tick_interval=0.02,
                           join_bound=0.3)
        self.addCleanup(host.close)
        with self.assertRaises(ValueError):
            host.start()
        self.assertEqual(host.close(), 'stopped')
        self.assertEqual(self.probe(), 'free')

    def test_output_store_verification_variants(self):
        class _OutSub(OutputStore):
            pass

        for variant in ('subclass', 'no_guard', 'foreign'):
            with self.subTest(variant=variant):
                def build(owner, retain):
                    store = self._store(owner, retain)
                    if variant == 'subclass':
                        out = _OutSub(self.root / 'outputs',
                                      guard=owner.check)
                    elif variant == 'no_guard':
                        out = OutputStore(self.root / 'outputs')
                    else:
                        out = OutputStore(
                            self.tmp / 'foreign' / 'outputs',
                            guard=owner.check)
                    ledger = CapacityLedger(
                        self.root / 'capacity.sqlite')
                    pool = retain(self._pool(ledger))
                    return self._comp(store, out, ledger,
                                      {ADAPTER: pool})

                host = ServiceHost(self.root, build,
                                   tick_interval=0.02, join_bound=0.3)
                self.addCleanup(host.close)
                with self.assertRaises(ValueError):
                    host.start()
                self.assertEqual(host.close(), 'stopped')
                self.assertEqual(self.probe(), 'free')

    def test_happy_path_output_store_and_order(self):
        def build(owner, retain):
            store = self._store(owner, retain)
            real_sc = store.close
            store.close = lambda: (self.order.append('store'),
                                   real_sc())[1]
            self.out = OutputStore(self.root / 'outputs',
                                   guard=owner.check)
            ledger = CapacityLedger(self.root / 'capacity.sqlite')
            pool = retain(self._pool(ledger))
            real_pc = pool.close
            pool.close = lambda: (self.order.append('pool'),
                                  real_pc())[1]
            return self._comp(store, self.out, ledger, {ADAPTER: pool})

        host = ServiceHost(self.root, build, tick_interval=0.02,
                           join_bound=0.3)
        self.addCleanup(host.close)
        host.start()
        ref = c.AttemptRef('r', 'j', 'a')
        committed = self.out.put(
            ref, (c.OutputItem(0, 'text/plain', 'hello'),))
        self.assertEqual(self.out.get(
            c.OutputRef(ref, committed.digest), committed), ('hello',))
        real_own = host._owner.close
        host._owner.close = lambda: (self.order.append('owner'),
                                     real_own())[1]
        self.assertEqual(host.close(), 'stopped')
        self.assertEqual(self.order, ['pool', 'store', 'owner'])
        self.assertEqual(self.probe(), 'free')

if __name__ == '__main__':
    unittest.main()
