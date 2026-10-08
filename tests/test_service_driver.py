"""M3 ServiceDriver unit tests: real control store + real Gateway.

FakeOwner is a guard double and FakeController a step recorder — these
tests do NOT prove real flock/fstatfs ownership, a real Controller
restart, pooled-adapter ledger behavior or process-kill recovery; that
mandatory suite is a separate chunk. No provider, network or subprocess.
"""
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4.gateway_store import submit_body
from co_v4.responses_input import parse
from co_v4.service_driver import ServiceDriver
from co_v4.state import (Conflict, ControlStore, IngressReceipt,
                         IntegrityViolation, NotFound, StoreUnavailable,
                         body_digest)

NOW = '2026-10-06T00:00:00Z'
PURE = c.TaskProfile('p-pure', 'sha256:' + '0' * 64, 'pure')
CANARY = 'raw-exception-canary-never-stored'


class OwnerLost(Exception):
    """Test-side owner-loss signal; must propagate through driver unchanged."""


class FakeOwner:
    """Guard callable double; NOT real flock/fsid ownership proof."""
    def __init__(self):
        self.calls, self.broken = 0, False
    def check(self):
        self.calls += 1
        if self.broken:
            raise OwnerLost('owner_lost')


class FakeController:
    """Step recorder; its return is never a Progress — the driver must
    read committed Run state, never the step result."""
    def __init__(self, stepper, run_id):
        self._stepper, self.run_id = stepper, run_id
    def step(self):
        return self._stepper(self.run_id)


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name).resolve() / 'control.sqlite'
        self.owner = FakeOwner()
        self.receipts = {}
        self.store = self._open()
        self.addCleanup(self.store.close)
        self.gateway = self.store.gateway()
        self.ctrl = self.store.controller()
        self.factory_calls, self.stepped = [], []
        self.stepper = lambda run_id: self.stepped.append(run_id) or object()

    def _open(self):
        return ControlStore(self.path, verifier=self.receipts.__getitem__,
            evidence=lambda *_: None, clock=lambda: NOW,
            profile_resolver=lambda alias: PURE, guard=self.owner.check)

    def driver(self, store=None, stepper=None):
        store = store or self.store
        def factory(run_id, run):
            self.factory_calls.append((run_id, run))
            return FakeController(stepper or self.stepper, run_id)
        return ServiceDriver(self.owner, store, store.gateway(),
                             controller_factory=factory)

    def submit(self, key, source):
        req = parse(b'{"model":"co-auto","input":"x"}')
        self.receipts[source] = IngressReceipt(
            'p1', source, body_digest(submit_body(req.body_hash, key)), NOW)
        return self.gateway.submit(req, key, source)

    def audit(self, run_id):
        return self.ctrl.history(run_id, 'driver_audit')

    def finalize(self, run_id, reason='provider_refusal'):
        self.ctrl.finalize_run(run_id, c.State.FAILED, reason,
                               self.ctrl.get_run(run_id).revision)

    def test_tick_steps_pending_once_in_order_then_projects(self):
        a, b = self.submit('a', 'e1'), self.submit('b', 'e2')
        driver = self.driver()
        expected = list(self.gateway.pending_work())  # actual queue order
        self.assertEqual(set(expected), {a.run_id, b.run_id})
        driver.tick()
        self.assertEqual(self.stepped, expected)
        self.assertEqual(len(self.factory_calls), 2)
        driver.tick()
        self.assertEqual(self.stepped, expected * 2)   # one cached each
        self.assertEqual(len(self.factory_calls), 2)

    def test_factory_receives_committed_snapshot_and_cache_evicts(self):
        sub = self.submit('k', 'e1')
        def closer(run_id):
            self.stepped.append(run_id)
            self.finalize(run_id)
            return object()          # not a Progress; must not matter
        driver = self.driver(stepper=closer)
        results = driver.tick()
        self.assertEqual(self.factory_calls[0][1].run_id, sub.run_id)
        self.assertEqual([p.status for p in results], ['failed'])
        self.assertNotIn(sub.run_id, driver._controllers)
        driver.close()
        self.assertEqual(driver._controllers, {})
        self.assertEqual(driver._quarantined, set())

    def test_start_projects_every_enqueued_run_without_factory(self):
        pending = self.submit('p', 'e1')
        # Terminal Run in the finalize/project crash window: committed but
        # never projected; start() owes it a row.
        term = self.submit('t', 'e2')
        self.finalize(term.run_id)
        results = self.driver().start()
        self.assertEqual(self.factory_calls, [])
        self.assertEqual({p.status for p in results},
                         {'queued', 'failed'})
        self.assertEqual(self.store._db.execute(
            'SELECT status, code FROM gateway_projections').fetchall(),
            [('failed', 'provider_refusal')])
        self.assertEqual(self.gateway.unprojected_work(), (pending.run_id,))
        self.stepped.clear()
        self.driver().tick()                          # pending still steps
        self.assertEqual(self.stepped, [pending.run_id])

    def test_corrupt_row_quarantines_a_while_b_continues(self):
        a, b = self.submit('a', 'e1'), self.submit('b', 'e2')
        self.store._db.execute(
            'INSERT INTO gateway_projections VALUES (?,?,?,?,?)',
            (a.response_id, 'bogus', None, 0, NOW))
        driver = self.driver()
        driver.start()                                # validates all rows
        self.assertIn(a.run_id, driver._quarantined)
        self.assertEqual(self.audit(a.run_id)[0][:2],
                         ('driver_project_error', 'integrity'))
        driver.tick()
        self.assertEqual(self.stepped, [b.run_id])    # A: zero steps
        driver.tick()
        self.assertEqual(self.stepped, [b.run_id] * 2)
        self.assertEqual(len(self.audit(a.run_id)), 1)
        # Restart (new driver, same store): quarantine re-detects, B ok.
        again = self.driver()
        again.start()
        self.assertIn(a.run_id, again._quarantined)
        again.tick()
        self.assertEqual(self.stepped, [b.run_id] * 3)
        self.assertEqual(len(self.audit(a.run_id)), 1)   # dedupe, same rev

    def test_decided_nonterminal_row_without_stop_quarantines(self):
        sub = self.submit('k', 'e1')
        self.store._db.execute(
            'INSERT INTO gateway_projections VALUES (?,?,?,?,?)',
            (sub.response_id, 'failed', 'run_failed', 0, NOW))
        driver = self.driver()
        driver.start()
        self.assertIn(sub.run_id, driver._quarantined)
        driver.tick()
        self.assertEqual(self.stepped, [])

    def test_global_failures_propagate_without_audit(self):
        sub = self.submit('k', 'e1')
        self.store._db.execute(
            "INSERT INTO gateway_work VALUES ('ghost', 'x')")
        with self.assertRaises(IntegrityViolation):
            self.driver().start()                     # missing Run row
        self.store._db.execute("DELETE FROM gateway_work WHERE run_id='ghost'")
        self.store._db.execute(
            'DELETE FROM gateway_responses WHERE run_id=?', (sub.run_id,))
        with self.assertRaises(IntegrityViolation):
            self.driver().start()                     # missing response row
        self.assertEqual(self.audit(sub.run_id), ())   # Run readable, no audit

    def test_unreadable_aggregate_and_store_fault_propagate(self):
        sub = self.submit('k', 'e1')
        original = self.store._db.execute(
            'SELECT body FROM runs WHERE id=?', (sub.run_id,)).fetchone()[0]
        self.store._db.execute(
            'UPDATE runs SET body=? WHERE id=?', ('not-json', sub.run_id))
        with self.assertRaises(StoreUnavailable):
            self.driver().tick()
        # Restore the exact original canonical bytes, not a fake dict.
        self.store._db.execute(
            'UPDATE runs SET body=? WHERE id=?', (original, sub.run_id))
        # A decisive derivation must exist or the guarded INSERT is never
        # attempted; finalize the real Run so project() reaches the row write.
        self.finalize(sub.run_id)
        self.store._db.execute(
            "CREATE TRIGGER f BEFORE INSERT ON gateway_projections"
            " BEGIN SELECT RAISE(ABORT,'f'); END")
        with self.assertRaises(StoreUnavailable):
            self.driver().tick()                      # insert fault: global
        self.assertEqual(self.store._db.execute(
            'SELECT COUNT(*) FROM gateway_projections').fetchone()[0], 0)
        self.store._db.execute('DROP TRIGGER f')
        self.driver().tick()
        self.assertEqual(self.store._db.execute(
            'SELECT status FROM gateway_projections').fetchall(),
            [('failed',)])

    def test_owner_loss_propagates_and_writes_nothing(self):
        self.submit('k', 'e1')
        self.owner.broken = True
        with self.assertRaises(OwnerLost):
            self.driver().tick()
        self.assertEqual(self.stepped, [])
        self.assertEqual(self.store._db.execute(
            'SELECT COUNT(*) FROM gateway_projections').fetchone()[0], 0)

    def test_per_run_errors_audit_closed_deduped_sanitized(self):
        sub = self.submit('k', 'e1')
        bad = ServiceDriver(self.owner, self.store, self.gateway,
            controller_factory=lambda r, s: (_ for _ in ()).throw(
                RuntimeError(CANARY)))
        bad.tick(); bad.tick()                        # same revision: dedupe
        driver = self.driver(stepper=lambda r: (_ for _ in ()).throw(
            Conflict('stale-secret')))
        driver.tick(); driver.tick()
        audit = self.audit(sub.run_id)
        self.assertEqual([e[:2] for e in audit],
            [('controller_factory_error', 'other'),
             ('driver_step_error', 'conflict')])
        raw = self.store._db.execute(
            'SELECT body FROM runs WHERE id=?', (sub.run_id,)).fetchone()[0]
        self.assertNotIn(CANARY, raw)
        self.assertNotIn('stale-secret', raw)

    def test_audit_bound_suppressed_norevbump_terminal_allowed(self):
        sub = self.submit('k', 'e1')
        rev = self.ctrl.get_run(sub.run_id).revision
        with patch('co_v4.state.ControllerState.DRIVER_AUDIT_LIMIT', 3):
            for code in ('integrity', 'conflict', 'value', 'other', 'other'):
                self.ctrl.record_driver_event(
                    sub.run_id, 'driver_step_error', code)
        self.assertEqual(len(self.audit(sub.run_id)), 3)
        body = json.loads(self.store._db.execute(
            'SELECT body FROM runs WHERE id=?', (sub.run_id,)).fetchone()[0])
        self.assertEqual(body['driver_audit_suppressed'], 2)  # corrected
        self.assertEqual(self.ctrl.get_run(sub.run_id).revision, rev)
        self.ctrl.finalize_run(sub.run_id, c.State.FAILED, 'run_failed', rev)
        self.ctrl.record_driver_event(sub.run_id, 'driver_project_error',
                                      'other')
        self.assertEqual(len(self.audit(sub.run_id)), 4)
        for bad in (('bogus', 'value'), ('driver_step_error', 'bogus')):
            with self.assertRaises(ValueError):
                self.ctrl.record_driver_event(sub.run_id, *bad)

    def test_audit_write_fault_rolls_back(self):
        sub = self.submit('k', 'e1')
        self.store._db.execute("CREATE TRIGGER f BEFORE UPDATE ON runs"
                               " BEGIN SELECT RAISE(ABORT,'f'); END")
        driver = self.driver(stepper=lambda r: (_ for _ in ()).throw(
            ValueError('x')))
        with self.assertRaises(StoreUnavailable):
            driver.tick()
        self.store._db.execute('DROP TRIGGER f')
        self.assertEqual(self.audit(sub.run_id), ())

    def test_reopen_recovers_work_fakecontroller_only(self):
        """New connection over the same SQLite + FakeController; NOT the
        real Controller/pool/process-kill restart proof."""
        sub = self.submit('k', 'e1')
        self.driver().tick()
        self.store.close()
        self.store, self.ctrl = self._open(), None
        self.ctrl = self.store.controller()
        gateway = self.store.gateway()
        self.assertEqual(gateway.pending_work(), (sub.run_id,))
        self.driver().tick()
        self.assertIn(sub.run_id, self.stepped)


    def test_factory_or_step_notfound_is_global_no_audit(self):
        sub = self.submit('k', 'e1')
        bad_factory = ServiceDriver(self.owner, self.store, self.gateway,
            controller_factory=lambda r, s: (_ for _ in ()).throw(
                NotFound('Run not found')))
        with self.assertRaises(NotFound):
            bad_factory.tick()                        # global, not audited
        driver = self.driver(stepper=lambda r: (_ for _ in ()).throw(
            NotFound('Run not found')))
        with self.assertRaises(NotFound):
            driver.tick()
        self.assertEqual(self.audit(sub.run_id), ())


if __name__ == '__main__':
    unittest.main()
