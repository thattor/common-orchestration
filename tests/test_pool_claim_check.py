"""Isolated unit tests for PooledAdapter.assert_executing.

Covers the synchronous retained executing-claim check invoked from
child.execute on the controller thread while pool.execute holds the
reentrant lock. Fake ledger/request fixtures only; no SQLite, no Native.
"""
import threading
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from co_v4 import contracts as c
from co_v4 import adapter_capacity as ac
from co_v4.adapter_capacity import CapacityError, PooledAdapter

LEDGER = '/canonical/host-ledger.sqlite3'
ADAPTER = 'codex.app-server'
MESSAGE = 'executing claim does not bind this request'


@dataclass(frozen=True)
class _Conditions:
    adapter: str


@dataclass(frozen=True)
class _Job:
    output_candidate: bool = False


@dataclass(frozen=True)
class _Request:
    ref: c.AttemptRef
    conditions: _Conditions
    job: _Job
    digest: str


class _FakeLedger:
    """In-memory row store recording each mutating call in .writes."""

    def __init__(self, path):
        self.path = Path(path)
        self.rows = {}
        self.writes = []
        self.last_owner = None

    def reserve(self, request, owner):
        self.writes.append('reserve')
        self.last_owner = owner
        self.rows[(request.ref, request.conditions.adapter)] = (
            request.digest, owner, 'reserved', None)
        return True

    def claim(self, request, owner):
        self.writes.append('claim')
        key = (request.ref, request.conditions.adapter)
        digest, _, _, evidence = self.rows[key]
        self.rows[key] = (digest, owner, 'executing', evidence)

    def release_reserved(self, request, owner):
        self.writes.append('release_reserved')
        return True

    def release(self, request, owner, evidence):
        self.writes.append('release')

    def row(self, ref, adapter):
        return self.rows.get((ref, adapter))


class AssertExecutingTest(unittest.TestCase):

    def setUp(self):
        patcher = mock.patch.object(ac, 'body_digest',
                                    lambda request: request.digest)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.ledger = _FakeLedger(LEDGER)
        self.children = []
        self.pool = PooledAdapter(ADAPTER, ledger=self.ledger,
                                  canonical_ledger=LEDGER,
                                  factory=self._factory)
        self.request = _Request(c.AttemptRef('run-1', 'job-1', 'attempt-1'),
                                _Conditions(ADAPTER), _Job(), 'digest-1')

    def _factory(self, request):
        child = mock.Mock(name='child')
        self.children.append(child)
        return child

    def _executing(self):
        self.assertTrue(self.pool.reserve(self.request))
        self.ledger.claim(self.request, self.ledger.last_owner)

    def _set_row(self, phase, owner=None):
        key = (self.request.ref, self.pool.adapter)
        digest, real_owner, _, evidence = self.ledger.rows[key]
        self.ledger.rows[key] = (digest, owner or real_owner, phase, evidence)

    def test_retained_executing_claim_passes(self):
        self._executing()
        self.assertIsNone(self.pool.assert_executing(self.request))

    def test_missing_retained_request_rejected(self):
        self._executing()
        stranger = _Request(c.AttemptRef('run-2', 'job-2', 'attempt-2'),
                            _Conditions(ADAPTER), _Job(), 'digest-2')
        for request in (stranger,):
            with self.assertRaises(CapacityError) as cm:
                self.pool.assert_executing(request)
            self.assertEqual(str(cm.exception), MESSAGE)
        fresh = PooledAdapter(ADAPTER, ledger=_FakeLedger(LEDGER),
                              canonical_ledger=LEDGER, factory=self._factory)
        with self.assertRaises(CapacityError):
            fresh.assert_executing(self.request)

    def test_equal_request_remains_bound_to_same_executing_claim(self):
        self._executing()
        twin = _Request(self.request.ref, self.request.conditions,
                        self.request.job, self.request.digest)
        self.assertEqual(twin, self.request)
        self.assertIsNot(twin, self.request)
        self.assertIsNone(self.pool.assert_executing(twin))

    def test_adapter_mismatch_rejected(self):
        self._executing()
        foreign = _Request(self.request.ref, _Conditions('devin.acp'),
                           self.request.job, self.request.digest)
        self.pool._requests[foreign.ref] = foreign
        with self.assertRaises(CapacityError):
            self.pool.assert_executing(foreign)

    def test_foreign_owner_rejected(self):
        self._executing()
        self._set_row('executing', owner='foreign-owner')
        with self.assertRaises(CapacityError):
            self.pool.assert_executing(self.request)

    def test_reserved_and_released_phases_rejected(self):
        for phase in ('reserved', 'released'):
            with self.subTest(phase=phase):
                ledger = _FakeLedger(LEDGER)
                pool = PooledAdapter(ADAPTER, ledger=ledger,
                                     canonical_ledger=LEDGER,
                                     factory=self._factory)
                self.assertTrue(pool.reserve(self.request))
                key = (self.request.ref, pool.adapter)
                digest, owner, _, evidence = ledger.rows[key]
                ledger.rows[key] = (digest, owner, phase, evidence)
                with self.assertRaises(CapacityError):
                    pool.assert_executing(self.request)

    def test_check_writes_nothing_and_needs_no_child_or_receipt(self):
        self._executing()
        writes = list(self.ledger.writes)
        self.assertNotIn(self.request.ref, self.pool._children)
        self.assertNotIn(self.request.ref, self.pool._receipts)
        self.pool.assert_executing(self.request)
        self.assertEqual(self.ledger.writes, writes)
        self.assertEqual(self.children, [])
        self.assertNotIn(self.request.ref, self.pool._children)
        self.assertNotIn(self.request.ref, self.pool._receipts)

    def test_child_execute_checks_claim_under_pool_lock(self):
        observed = []
        pool = self.pool

        class Child:
            def execute(self, request):
                pool.assert_executing(request)
                observed.append(request.ref)
                return c.OperationReply(
                    request.ref, c.OperationStatus.ACCEPTED,
                    'claim verified inside child.execute')

        locked_pool = PooledAdapter(ADAPTER, ledger=self.ledger,
                                    canonical_ledger=LEDGER,
                                    factory=lambda request: Child())
        pool = locked_pool
        outcome = {}
        worker = threading.Thread(
            target=lambda: outcome.__setitem__('reply',
                                               locked_pool.execute(self.request)),
            daemon=True)
        worker.start()
        worker.join(10)
        self.assertFalse(worker.is_alive(),
                         'assert_executing deadlocked under the pool lock')
        reply = outcome['reply']
        self.assertEqual(reply.status, c.OperationStatus.ACCEPTED)
        self.assertEqual(reply.ref, self.request.ref)
        self.assertIsNone(reply.never_started)
        self.assertEqual(observed, [self.request.ref])
        self.assertEqual(self.ledger.writes, ['reserve', 'claim'])


if __name__ == '__main__':
    unittest.main()
