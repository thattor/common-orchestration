# tests/test_service_driver_pool.py
"""#190 M3 driver: bound projection decision vs late genuine Native evidence.

Real ServiceDriver + real Controller + real PooledAdapter on the canonical
CapacityLedger, owner-locked 0o700 root, real ControlStore reopen (no fake
Controller). Only the request-bound child Adapter is synthetic — it supplies
real Adapter-contract events and StopReplies; no StopReply is minted by hand.

Frozen fixture API for the next chunk (owner kill / new-process restart,
retry race, corrupt rows): DriverPoolFixture.dispatch, .reopen, .driver,
.pool, .ledger, .state, .projection_row, .child_calls, .children, .run_id,
.response_id, .output_store, .owner, .store.
"""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.adapter_capacity import CapacityLedger, PooledAdapter
from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.controller import Controller, JobPlan
from co_v4.gateway_store import Gateway
from co_v4.judgment import TrustedEvidence
from co_v4.output_store import OutputStore
from co_v4.service_driver import ServiceDriver
from co_v4.service_owner import ServiceOwner
from co_v4.state import (ControlStore, IngressReceipt, body_digest,
                         create_run_body)
from co_v4.trace import canonical
from co_v4.usage import UsageStore
from test_adapter_capacity import Child

NOW = '2026-09-28T00:00:00Z'
NOW_DT = datetime(2026, 9, 28, tzinfo=timezone.utc)
USE = UseCase('coding')
ADAPTER = 'codex.app-server'
MODEL, ENV = 'm', 'env:1'
RUN_ID, INTENT = 'run-driver', 'produce the fixture artifact'
# Pure profile, requires_output, one allowed route: minimal and coherent.
PROFILE = c.TaskProfile('fixture-task', 'sha256:' + '0' * 64, 'pure', True,
                        ((MODEL, ADAPTER, ENV),))


class DriverPoolFixture:
    """Owner-locked root; all immutable inputs spun here. The real Controller
    produces the only admission/routing history — nothing is hand-minted."""

    def __init__(self, root):
        self.root = root
        root.mkdir(mode=0o700)
        self.owner = ServiceOwner.acquire(root)
        self.receipts, self.child_calls, self.children = {}, [], {}
        self._open()
        self.output_store = OutputStore(root / 'outputs')
        self.owner.bind_stores(self.store, self.output_store)
        self.ledger = CapacityLedger(root / 'capacity.sqlite')
        self.pool = self._new_pool()
        self.catalog = Catalog((CatalogEntry(MODEL, ADAPTER, {USE: 2}, (
            Verification(MODEL, ADAPTER, USE, ENV, 'fixture:official',
                         'fixture:implementation', 'fixture:measurement',
                         'fixture:ac', output_mode='collect'),)),))
        action = c.Action('fixture.write', c.Scope(
            (('repository', 'fixture/co'), ('path', '/fixture')), True))
        self.plan = JobPlan(
            c.Job(RUN_ID, 'job', 'produce the fixture output',
                  ('exact content checked',)),
            action, 'write-output', USE,
            (c.ExecutionConditions(MODEL, ADAPTER, '/fixture', ENV,
                                   ('fixture:controls',)),))
        self.run_id, self.response_id = RUN_ID, 'resp_fixture'
        self.receipts['origin'] = IngressReceipt(
            'fixture-principal', 'origin',
            body_digest(create_run_body(RUN_ID, INTENT)), NOW)
        self.store.intake().create_run(RUN_ID, INTENT, 'origin',
                                       profile=PROFILE)
        # Six-column fixture binding of the existing Run (no northbound auth).
        self.store._db.execute(
            'INSERT INTO gateway_responses VALUES (?,?,?,?,?,?)',
            (self.response_id, 'fixture-principal', RUN_ID,
             body_digest('fixture-request'), 'fixture-task', NOW))
        self.store._db.execute('INSERT INTO gateway_work VALUES (?,?)',
                               (RUN_ID, NOW))

    def _open(self):
        self.store = ControlStore(
            self.root / 'control.sqlite',
            verifier=lambda source: self.receipts[source],
            evidence=self._evidence, clock=lambda: NOW,
            guard=self.owner.check)
        self.state = self.store.controller()
        # Bound resolves to zero: a stamped admission expires immediately.
        self.gateway = Gateway(self.store, bound_resolver=lambda *_: 0)
        self.driver = ServiceDriver(
            self.owner, self.store, self.gateway,
            controller_factory=lambda _r, _s: self.build_controller())

    def _evidence(self, run, request):
        dims = dict(request.action.scope.dimensions)
        return TrustedEvidence(
            body_digest(request), 'fixture:policy', ('fixture:controls',),
            canonical([request.action.name, dims.get('repository'),
                       dims.get('path')]),
            False, False, True, True, True, True)

    def _new_pool(self):
        return PooledAdapter(ADAPTER, ledger=self.ledger,
                             canonical_ledger=self.ledger.path,
                             factory=self._child_factory)

    def _child_factory(self, request):
        self.child_calls.append(request)
        child = self.children[request.ref] = Child()
        return child

    def build_controller(self):
        return Controller(
            self.run_id, state=self.state,
            judgment=self.store.judgment(), catalog=self.catalog,
            usage=UsageStore(), adapters={ADAPTER: self.pool},
            acceptance=Acceptance(lambda req: CheckEvidence(
                body_digest(req), Finding('pass', ('e',)), ())),
            planner=lambda run, completed, goal:
                None if run.job_ids else self.plan,
            clock=lambda: NOW_DT, output_store=self.output_store)

    def reopen(self):
        """Actual DB reopen and a fresh pool: retained children are lost."""
        self.store.close()
        self._open()
        self.pool = self._new_pool()

    def dispatch(self):
        """Real Controller admission + execute + drain; returns AttemptRef."""
        controller = self.build_controller()
        for expected in ('next_job', 'execute_receipt',
                         'awaiting_native_event'):
            progress = controller.step()
            if progress.reason != expected:
                raise AssertionError(
                    'dispatch expected %r, got %r: progress=%r run=%r '
                    'attempts=%r audit=%r' % (
                        expected, progress.reason, progress, self.run(),
                        self.state.attempts(self.run_id),
                        self.state.history(self.run_id, 'driver_audit')))
        return self.attempt().ref

    def run(self):
        return self.state.get_run(self.run_id)

    def attempt(self):
        attempts = self.state.attempts(self.run_id)
        return attempts[0] if attempts else None

    def projection_row(self):
        return self.store._db.execute(
            'SELECT status, code, run_revision, at FROM gateway_projections'
            ' WHERE response_id=?', (self.response_id,)).fetchone()

    def ingress_claims(self):
        return self.store._db.execute(
            'SELECT count(*) FROM ingress').fetchone()[0]

    def close(self):
        self.store.close()
        self.owner.close()


def late_result(child, ref):
    child.finish(ref)
    return next(e for e in child.events(ref)
                if isinstance(e, c.ResultEvent)).result


class DriverBoundDecisionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.fx = DriverPoolFixture(Path(tmp.name).resolve() / 'root')
        self.addCleanup(self.fx.close)

    def test_bound_decision_then_late_confirmed_result_releases_once(self):
        fx = self.fx
        (queued,) = fx.driver.start()
        self.assertEqual((queued.status, queued.decided), ('queued', False))
        ref = fx.dispatch()
        child = fx.children[ref]
        self.assertEqual(fx.ledger.count(ADAPTER), 1)   # initial slot held
        self.assertEqual(len(fx.child_calls), 1)
        self.assertEqual(len(child.requests), 1)
        before = fx.run().revision
        (decided,) = fx.driver.tick()
        # Atomic: single Run bump carries stop + decisive row; zero claims.
        self.assertEqual((decided.status, decided.code, decided.decided),
                         ('failed', 'cessation_unconfirmed', True))
        run = fx.run()
        self.assertEqual(run.revision, before + 1)
        self.assertEqual(decided.run_revision, run.revision)
        self.assertTrue(run.stop_requested)
        self.assertEqual(fx.state.stop_origin(fx.run_id),
                         'projection_decided')
        self.assertEqual(fx.ingress_claims(), 1)        # create-run claim only
        row = fx.projection_row()
        self.assertEqual(row, ('failed', 'cessation_unconfirmed',
                               run.revision, NOW))
        self.assertEqual(fx.ledger.count(ADAPTER), 1)   # still held, no proof
        # Genuine but UNCONFIRMED cessation: no release, no fabrication.
        child.stop_status = c.StopStatus.UNCONFIRMED
        fx.driver.tick()
        self.assertEqual(fx.ledger.count(ADAPTER), 1)
        self.assertIsNone(fx.attempt().result)
        self.assertEqual(fx.projection_row(), row)
        # Genuine late evidence: CONFIRMED stop + real COMPLETED Result.
        child.stop_status = c.StopStatus.CONFIRMED
        expected = late_result(child, ref)
        fx.driver.tick()
        run = fx.run()
        self.assertEqual((run.state, run.final_reason),
                         (c.State.FAILED, 'projection_decided'))
        self.assertTrue(run.cessation_confirmed)
        attempt = fx.attempt()
        self.assertEqual(attempt.result, expected)      # exact Result identity
        self.assertIsNone(attempt.ac)
        self.assertIsNone(attempt.output)
        self.assertIsNone(attempt.collection_failure)
        self.assertEqual(fx.state.history(fx.run_id, 'ac_history'), ())
        self.assertEqual(fx.state.history(fx.run_id, 'job_goals'), ())
        self.assertIsNone(run.output_selection)
        self.assertEqual(len(fx.state.attempts(fx.run_id)), 1)
        self.assertEqual(len(fx.child_calls), 1)        # zero retry executes
        self.assertEqual(len(child.requests), 1)
        self.assertEqual(fx.ledger.count(ADAPTER), 0)   # real stop released it
        self.assertEqual(fx.projection_row(), row)      # byte-identical row
        self.assertEqual(fx.state.history(fx.run_id, 'driver_audit'), ())
        for sub in ('blobs', 'manifests'):              # zero output writes
            self.assertEqual(
                list((fx.output_store.root / sub).iterdir()), [])

    def test_run_failed_decision_holds_for_late_result(self):
        fx = self.fx
        fx.driver.start()
        ref = fx.dispatch()
        child = fx.children[ref]
        # Real CONFIRMED cessation, no Result, before any decision: the pool's
        # own confirmed StopReply is what releases the slot.
        child.stop_status = c.StopStatus.CONFIRMED
        reply = fx.pool.stop(ref)
        self.assertEqual(reply.status, c.StopStatus.CONFIRMED)
        self.assertEqual(fx.ledger.count(ADAPTER), 0)
        fx.state.record_stop(reply, fx.attempt().revision)
        before = fx.run().revision
        (decided,) = fx.driver.tick()
        self.assertEqual((decided.status, decided.code, decided.decided),
                         ('failed', 'run_failed', True))
        run = fx.run()
        self.assertEqual(run.revision, before + 1)
        self.assertTrue(run.stop_requested)
        self.assertEqual(fx.state.stop_origin(fx.run_id),
                         'projection_decided')
        self.assertEqual(fx.ingress_claims(), 1)
        row = fx.projection_row()
        self.assertEqual(row, ('failed', 'run_failed', run.revision, NOW))
        # The genuine late Result settles under the same barrier: recorded,
        # never evaluated, never published.
        expected = late_result(child, ref)
        fx.driver.tick()
        run = fx.run()
        self.assertEqual((run.state, run.final_reason),
                         (c.State.FAILED, 'projection_decided'))
        attempt = fx.attempt()
        self.assertEqual(attempt.result, expected)
        self.assertIsNone(attempt.ac)
        self.assertIsNone(attempt.output)
        self.assertIsNone(run.output_selection)
        self.assertEqual(fx.projection_row(), row)
        self.assertEqual(len(fx.child_calls), 1)
        self.assertEqual(len(fx.state.attempts(fx.run_id)), 1)
        self.assertEqual(fx.ledger.count(ADAPTER), 0)
        self.assertEqual(fx.state.history(fx.run_id, 'driver_audit'), ())
        self.assertEqual(len(fx.state.history(fx.run_id, 'stop_history')), 1)

    def test_restart_lost_child_holds_slot_without_fabrication(self):
        fx = self.fx
        fx.driver.start()
        fx.dispatch()
        (decided,) = fx.driver.tick()
        self.assertEqual(decided.code, 'cessation_unconfirmed')
        row = fx.projection_row()
        self.assertEqual(fx.ledger.count(ADAPTER), 1)
        fx.reopen()  # real ControlStore reopen; new pool lost the child
        calls = len(fx.child_calls)
        for _ in range(3):
            (view,) = fx.driver.tick()
            self.assertEqual((view.status, view.code, view.decided),
                             ('failed', 'cessation_unconfirmed', True))
            run = fx.run()
            self.assertEqual(run.state, c.State.RUNNING)   # held, not terminal
            self.assertTrue(run.stop_requested)
            self.assertIsNone(fx.attempt().result)         # no fabricated Result
            self.assertEqual(len(fx.state.attempts(fx.run_id)), 1)
            self.assertEqual(fx.ledger.count(ADAPTER), 1)  # slot never released
            self.assertEqual(fx.projection_row(), row)     # row unchanged
            self.assertEqual(len(fx.child_calls), calls)   # zero extra executes
            self.assertEqual(len(fx.children), 1)          # no new child
        self.assertEqual(fx.state.stop_origin(fx.run_id), 'projection_decided')
        self.assertEqual(fx.state.history(fx.run_id, 'driver_audit'), ())
        for sub in ('blobs', 'manifests'):
            self.assertEqual(
                list((fx.output_store.root / sub).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
