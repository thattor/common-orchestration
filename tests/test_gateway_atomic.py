"""M3 Gateway atomicity: mid-transaction fault rollback and two-process
concurrent submits. Real SQLite files, spawned processes; synthetic
receipts only, no network or provider.
"""
import json
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.gateway_store import submit_body
from co_v4.responses_input import parse
from co_v4.state import (ControlStore, Conflict, IngressReceipt,
                         StoreUnavailable, body_digest, create_run_body)

NOW = '2026-10-06T00:00:00Z'
DIGEST = 'sha256:' + '0' * 64
PURE = c.TaskProfile('p-pure', DIGEST, 'pure')
TABLES = ('runs', 'ingress', 'gateway_responses', 'gateway_keys',
          'gateway_work', 'gateway_projections')
# Every write inside Gateway.submit's single transaction, in order.
FRAGMENTS = ('INSERT INTO runs', 'INSERT INTO gateway_responses',
             'INSERT INTO gateway_keys', 'INSERT INTO gateway_work',
             'INSERT OR IGNORE INTO ingress')


def intent(**kw):
    return parse(json.dumps({'model': 'co-auto', 'input': 'x', **kw}).encode())


def _submit_worker(path, source, raw, key, barrier, queue):
    """Own store, own receipt, own connection; one synchronized submit."""
    req = parse(raw)
    receipts = {source: IngressReceipt(
        'p1', source, body_digest(submit_body(req.body_hash, key)), NOW)}
    store = ControlStore(path, verifier=receipts.__getitem__,
        evidence=lambda *_: None, clock=lambda: NOW,
        profile_resolver=lambda alias: PURE)
    try:
        barrier.wait(timeout=20)
        sub = store.gateway().submit(req, key, source)
        queue.put(('ok', sub.response_id, sub.run_id, sub.created))
    except Exception as exc:
        queue.put(('err', type(exc).__name__, str(exc)))
    finally:
        store.close()


class FaultConnection:
    """Delegates to the real connection; fires one sqlite3.Error at the
    first statement containing `fragment` — before it, or after real
    execution so the row exists only inside the doomed transaction."""

    def __init__(self, real, fragment, after):
        self._real, self._fragment, self._after = real, fragment, after
        self.fired = False

    def execute(self, sql, parameters=()):
        if not self.fired and self._fragment in sql:
            self.fired = True
            if self._after:
                self._real.execute(sql, parameters)
            raise sqlite3.OperationalError('injected gateway write fault')
        return self._real.execute(sql, parameters)

    def __getattr__(self, name):
        return getattr(self._real, name)


class GatewayAtomicTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'control.sqlite'
        self.receipts = {}
        self.store = ControlStore(
            self.path, verifier=self.receipts.__getitem__,
            evidence=lambda *_: None, clock=lambda: NOW,
            profile_resolver=lambda alias: PURE)
        self.gateway = self.store.gateway()
        self.addCleanup(self.store.close)

    def auth(self, source, body):
        self.receipts[source] = IngressReceipt(
            'p1', source, body_digest(body), NOW)
        return source

    def rows(self, table):
        return self.store._db.execute(
            'SELECT COUNT(*) FROM ' + table).fetchone()[0]

    def counts(self):
        return tuple(self.rows(t) for t in TABLES)

    def inject(self, req, fragment, after):
        """One submit with a fault at `fragment`; the proxy always restores."""
        self.auth('e1', submit_body(req.body_hash, 'k'))
        proxy = FaultConnection(self.store._db, fragment, after)
        self.store._db = proxy
        try:
            with self.assertRaises(StoreUnavailable):
                self.gateway.submit(req, 'k', 'e1')
        finally:
            self.store._db = proxy._real
        self.assertTrue(proxy.fired)

    def test_rollback_every_write_point_empty_store(self):
        req = intent()
        for fragment in FRAGMENTS:
            for after in (False, True):
                with self.subTest(fragment=fragment, after=after):
                    self.inject(req, fragment, after)
                    self.assertEqual(self.counts(), (0,) * len(TABLES))
        # Rolled-back faults leave 'e1' unclaimed and the store fully live.
        self.assertTrue(self.gateway.submit(
            req, 'k', self.auth('e1', submit_body(req.body_hash, 'k'))).created)

    def test_rollback_every_write_point_preserves_committed_run(self):
        self.auth('origin:u', create_run_body('u', 'unrelated'))
        self.store.intake().create_run('u', 'unrelated', 'origin:u')
        baseline = self.counts()
        self.assertEqual(baseline[:2], (1, 1))  # nonzero Run+ingress baseline
        req = intent()
        for fragment in FRAGMENTS:
            for after in (False, True):
                with self.subTest(fragment=fragment, after=after):
                    self.inject(req, fragment, after)
                    self.assertEqual(self.counts(), baseline)

    def race(self, raws):
        """Spawn one real process per request body; barrier-start, join,
        terminate owned children in finally. No thread substitution."""
        ctx = multiprocessing.get_context('spawn')
        barrier, queue = ctx.Barrier(len(raws)), ctx.Queue()
        children = [ctx.Process(
            target=_submit_worker,
            args=(str(self.path), 'ev%d' % i, raw, 'shared-key',
                  barrier, queue))
            for i, raw in enumerate(raws)]
        results = []
        try:
            for child in children:
                child.start()
            for _ in children:
                results.append(queue.get(timeout=60))
            for child in children:
                child.join(timeout=30)
        finally:
            for child in children:
                if child.is_alive():
                    child.terminate()
                    child.join(timeout=10)
        return results

    def test_concurrent_same_key_same_body_one_response(self):
        raw = json.dumps({'model': 'co-auto', 'input': 'x'}).encode()
        results = self.race([raw, raw])
        self.assertEqual([r[0] for r in results].count('ok'), 2)
        ids = {(r[1], r[2]) for r in results}
        self.assertEqual(len(ids), 1)   # same response_id and run_id
        self.assertEqual(sorted(r[3] for r in results), [False, True])
        self.assertEqual(self.counts(), (1, 2, 1, 1, 1, 0))
        self.assertEqual(len(self.gateway.pending_work()), 1)

    def test_concurrent_same_key_different_body_one_conflict(self):
        raw_a = json.dumps({'model': 'co-auto', 'input': 'x'}).encode()
        raw_b = json.dumps({'model': 'co-auto', 'input': 'y'}).encode()
        results = self.race([raw_a, raw_b])
        self.assertEqual(sorted(r[0] for r in results), ['err', 'ok'])
        loser, = (r for r in results if r[0] == 'err')
        self.assertEqual((loser[1], loser[2]),
                         ('Conflict', 'idempotency_conflict'))
        self.assertEqual(self.counts(), (1, 1, 1, 1, 1, 0))
        winner, = (r for r in results if r[0] == 'ok')
        self.assertTrue(winner[3])
        self.assertEqual(self.gateway.pending_work(), (winner[2],))


if __name__ == '__main__':
    unittest.main()
