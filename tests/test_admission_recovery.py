# tests/test_admission_recovery.py
"""#190 F2 admission recovery: real store, ledger, pool and driver.

Real ControlStore/Gateway/CapacityLedger/PooledAdapter on an owner-locked
root. The only synthetic piece is the request-bound child Adapter. Every
NeverStarted receipt is minted by the pool; the Native factory call count
is asserted throughout.
"""
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.ac import Acceptance
from co_v4.adapter_capacity import (CapacityError, CapacityLedger,
                                    PooledAdapter)
from co_v4.admission_recovery import recovery_scan
from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.controller import Controller
from co_v4.gateway_store import Gateway
from co_v4.judgment import JudgmentRequest, TrustedEvidence
from co_v4.output_store import OutputStore
from co_v4.service_driver import ServiceDriver
from co_v4.service_owner import ServiceOwner
from co_v4.state import (Conflict, ControlStore, IngressReceipt,
                         IntegrityViolation, InvalidTransition, NotFound,
                         _attempt_key, body_digest, commit_execute_receipt,
                         create_run_body)
from co_v4.trace import canonical
from co_v4.usage import UsageStore
from test_adapter_capacity import Child

NOW = '2026-09-28T00:00:00Z'
NOW_DT = datetime(2026, 9, 28, tzinfo=timezone.utc)
ADAPTER, MODEL, ENV = 'codex.app-server', 'm', 'env:1'
PROFILE = c.TaskProfile('task', 'sha256:' + '0' * 64, 'pure', True,
                        ((MODEL, ADAPTER, ENV),))
NEVER_DISPATCHED = 'capacity:reservation-never-dispatched'


class Fixture:
    """Owner-locked real stack; immutable inputs spun once."""

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
        self.use = UseCase('coding')
        self.catalog = Catalog((CatalogEntry(MODEL, ADAPTER, {self.use: 1}, (
            Verification(MODEL, ADAPTER, self.use, ENV, 'f:o', 'f:i',
                         'f:m', 'f:a'),)),))
        self.action = c.Action('fixture.write', c.Scope(
            (('repository', 'r'),), True))
        self.conditions = c.ExecutionConditions(MODEL, ADAPTER, '/w', ENV,
                                                ('f:controls',))

    def _open(self):
        self.store = ControlStore(
            self.root / 'control.sqlite',
            verifier=self.receipts.__getitem__, evidence=self._evidence,
            clock=lambda: NOW, guard=self.owner.check)
        self.state = self.store.controller()
        self.gateway = Gateway(self.store, bound_resolver=lambda *_: None)

    def _evidence(self, run, request):
        return TrustedEvidence(body_digest(request), 'f:policy',
            ('f:controls',), canonical([request.action.name]),
            False, False, True, True, True, True)

    def _new_pool(self):
        return PooledAdapter(ADAPTER, ledger=self.ledger,
                             canonical_ledger=self.ledger.path,
                             factory=self._child)

    def _child(self, request):
        self.child_calls.append(request)
        child = self.children[request.ref] = Child()
        return child

    def reopen(self):
        """Real store reopen plus a fresh pool (new owner token)."""
        self.store.close()
        self._open()
        self.pool = self._new_pool()

    def close(self):
        self.store.close()
        self.owner.close()

    def make_run(self, run_id, gateway=True):
        self.receipts[run_id] = IngressReceipt(
            'p', run_id, body_digest(create_run_body(run_id, 'i')), NOW)
        self.store.intake().create_run(run_id, 'i', run_id, profile=PROFILE)
        if gateway:
            self.store._db.execute(
                'INSERT INTO gateway_responses VALUES (?,?,?,?,?,?)',
                ('resp-' + run_id, 'p', run_id, body_digest('r'), 't', NOW))
            self.store._db.execute('INSERT INTO gateway_work VALUES (?,?)',
                                   (run_id, NOW))

    def mark_terminal(self, run_id):
        """Fixture transition to committed terminal for ordering tests."""
        with self.store._tx(run_id) as data:
            data['run'] = replace(data['run'], state=c.State.FAILED,
                                  final_reason='run_failed')

    def prepare(self, run_id, job='j', attempt='a', model=MODEL):
        job_obj = c.Job(run_id, job, 'do', ('check',))
        self.receipts.setdefault(run_id, IngressReceipt(
            'p', run_id, body_digest(create_run_body(run_id, 'i')), NOW))
        if job not in self.state.get_run(run_id).job_ids:
            d = self.store.judgment().judge(JudgmentRequest(
                c.QuestionRef(run_id, job), self.action, 'm',
                self.conditions, proposed_job=job_obj))
            self.state.add_job(job_obj, d.decision_id,
                               self.rev(run_id))
        return c.ExecuteRequest(
            c.AttemptRef(run_id, job, attempt), job_obj,
            replace(self.conditions, model=model))

    def admit(self, run_id, **kw):
        """Real admission: committed Attempt + request, no execute receipt."""
        request = self.prepare(run_id, **kw)
        d = self.store.judgment().judge(JudgmentRequest(
            c.QuestionRef(request.ref.run_id, request.ref.job_id,
                          request.ref.attempt_id),
            self.action, 'm', request.conditions))
        self.state.begin_attempt(request, d.decision_id, self.rev(run_id))
        return request

    def rev(self, run_id):
        return self.state.get_run(run_id).revision

    def scan(self, quarantine=()):
        return recovery_scan(self.gateway, self.state, self.ledger,
                             {ADAPTER: self.pool}, quarantine)

    def build_controller(self, run_id):
        return Controller(
            run_id, state=self.state, judgment=self.store.judgment(),
            catalog=self.catalog, usage=UsageStore(),
            adapters={ADAPTER: self.pool},
            # Real Controller; planner returns None so the verifier must
            # never run — no fabricated AC outcome is produced as proof.
            acceptance=Acceptance(lambda req: (_ for _ in ()).throw(
                AssertionError('verifier must not be invoked'))),
            planner=lambda *_: None, clock=lambda: NOW_DT,
            output_store=self.output_store)


class AccessorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fx = Fixture(Path(self.tmp.name).resolve() / 'root')
        self.addCleanup(self.fx.close)

    def test_contract_and_corruption(self):
        fx = self.fx
        fx.make_run('r1')
        request = fx.admit('r1')
        self.assertEqual(fx.state.admitted_request(request.ref), request)
        ghost = c.AttemptRef('r1', 'j', 'ghost')
        self.assertIsNone(fx.state.admitted_request(ghost))
        with self.assertRaises(NotFound):
            fx.state.admitted_request(c.AttemptRef('absent', 'j', 'a'))
        with self.assertRaises(ValueError):
            fx.state.admitted_request('r1')
        # Orphan request for an unadmitted key: corruption, not None.
        with fx.store._tx('r1') as data:
            data['requests'][_attempt_key(ghost)] = replace(
                request, ref=ghost)
        with self.assertRaises(IntegrityViolation):
            fx.state.admitted_request(ghost)
        # Orphan 'attempt:' write and request-vs-admission divergence.
        for key, mutate in (
                ('w2', lambda data, key: data['writes'].__setitem__(
                    'attempt:' + key, (request, request))),
                ('w3', lambda data, key: data['requests'].__setitem__(
                    key, replace(request, conditions=replace(
                        request.conditions, model='other'))))):
            fx2 = Fixture((Path(tempfile.mkdtemp(
                dir=self.tmp.name)) / key).resolve())
            try:
                fx2.make_run('r1')
                req = fx2.admit('r1')
                with fx2.store._tx('r1') as data:
                    mutate(data, _attempt_key(req.ref))
                with self.assertRaises(IntegrityViolation):
                    fx2.state.attempts('r1')
            finally:
                fx2.close()


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fx = Fixture(Path(self.tmp.name).resolve() / 'root')
        self.addCleanup(self.fx.close)

    def test_scan_b_reserved_before_begin_cancels(self):
        fx = self.fx
        fx.make_run('r1')
        request = fx.prepare('r1')
        fx.pool.reserve(request)
        self.assertEqual(fx.scan(), frozenset())
        row = fx.ledger.row(request.ref, ADAPTER)
        self.assertEqual((row[2], row[3]), ('released', NEVER_DISPATCHED))
        self.assertEqual(fx.state.attempts('r1'), ())   # no journal write
        self.assertEqual(fx.child_calls, [])

    def test_scan_b_terminal_gateway_run_cancels(self):
        fx = self.fx
        fx.make_run('r1')
        # Judgment and add_job run while the Run is live; the lease
        # predates terminalization — exactly the crash window under test.
        request = fx.prepare('r1')
        fx.pool.reserve(request)
        fx.mark_terminal('r1')
        fx.scan()
        self.assertEqual(fx.ledger.row(request.ref, ADAPTER)[2], 'released')

    def test_scan_a_admitted_reservation_commits_pool_receipt(self):
        fx = self.fx
        fx.make_run('r1')
        request = fx.prepare('r1')
        fx.pool.reserve(request)
        fx.admit('r1')
        self.assertEqual(fx.scan(), frozenset())
        receipt = fx.state.execute_receipt(request.ref)
        self.assertEqual(receipt.never_started.request, request)
        self.assertEqual(receipt.never_started.evidence_ref,
                         NEVER_DISPATCHED)
        self.assertEqual(fx.state.attempt_settlement(request.ref),
                         'never_started')
        self.assertEqual(fx.ledger.row(request.ref, ADAPTER)[2], 'released')
        self.assertEqual(fx.child_calls, [])

    def test_release_before_commit_restart_idempotent(self):
        fx = self.fx
        fx.make_run('r1')
        request = fx.prepare('r1')
        fx.pool.reserve(request)
        fx.admit('r1')
        # Crash window: ledger released, receipt never committed.
        fx.ledger.recover_reserved(request, fx.pool._owner)
        fx.reopen()                      # restart one
        self.assertEqual(fx.scan(), frozenset())
        first = fx.state.execute_receipt(request.ref)
        self.assertEqual(first.never_started.evidence_ref, NEVER_DISPATCHED)
        fx.reopen()                      # restart two: exact replay only
        self.assertEqual(fx.scan(), frozenset())
        self.assertEqual(fx.state.execute_receipt(request.ref), first)
        self.assertEqual(fx.ledger.row(request.ref, ADAPTER)[2], 'released')
        self.assertEqual(fx.child_calls, [])

    def test_executing_missing_and_wrong_digest_held(self):
        fx = self.fx
        fx.make_run('r1')
        executing = fx.admit('r1', attempt='x')
        fx.pool.execute(executing)
        fx.make_run('r2')
        missing = fx.admit('r2')
        fx.make_run('r3')
        wrong = fx.admit('r3')
        fx.ledger.reserve(replace(wrong, conditions=replace(
            wrong.conditions, model='other')), 'other-owner')
        self.assertEqual(fx.scan(), frozenset())
        for ref in (executing.ref, missing.ref, wrong.ref):
            self.assertIsNone(fx.state.execute_receipt(ref))
        self.assertEqual(fx.ledger.row(executing.ref, ADAPTER)[2],
                         'executing')
        self.assertIsNone(fx.ledger.row(missing.ref, ADAPTER))
        self.assertEqual(fx.ledger.row(wrong.ref, ADAPTER)[2], 'reserved')
        self.assertEqual(len(fx.child_calls), 1)   # only the real dispatch

    def test_foreign_and_internal_collision_leases_untouched(self):
        fx = self.fx
        fx.make_run('internal', gateway=False)      # intake-only Run
        snapshots = {}
        for run_id in ('internal', 'run_foreign'):
            request = c.ExecuteRequest(
                c.AttemptRef(run_id, 'j', 'a'),
                c.Job(run_id, 'j', 'do', ('check',)), fx.conditions)
            self.assertTrue(fx.ledger.reserve(request, 'other-owner'))
            snapshots[run_id] = fx.ledger.row(request.ref, ADAPTER)
        fx.scan()
        for run_id in ('internal', 'run_foreign'):
            ref = c.AttemptRef(run_id, 'j', 'a')
            # Byte-exact row: owner, digest, phase and evidence all
            # unchanged — untouched, not merely still 'reserved'.
            self.assertEqual(fx.ledger.row(ref, ADAPTER),
                             snapshots[run_id])

    def test_quarantine_skips_both_scans(self):
        fx = self.fx
        fx.make_run('r1')
        request = fx.prepare('r1')
        fx.pool.reserve(request)
        fx.admit('r1')
        orphan = c.ExecuteRequest(c.AttemptRef('r1', 'j', 'b'),
                                  request.job, fx.conditions)
        fx.pool.reserve(orphan)
        self.assertEqual(fx.scan({'r1'}), frozenset({'r1'}))
        for ref in (request.ref, orphan.ref):
            self.assertEqual(fx.ledger.row(ref, ADAPTER)[2], 'reserved')
        self.assertIsNone(fx.state.execute_receipt(request.ref))

    def test_contradictory_admission_quarantines_without_writes(self):
        fx = self.fx
        fx.make_run('r1')
        request = fx.prepare('r1')
        fx.pool.reserve(request)
        fx.admit('r1')
        with fx.store._tx('r1') as data:
            data['requests'][_attempt_key(request.ref)] = replace(
                request, conditions=replace(request.conditions,
                                            model='other'))
        self.assertEqual(fx.scan(), frozenset({'r1'}))
        self.assertIsNone(fx.state.execute_receipt(request.ref))
        self.assertEqual(fx.ledger.row(request.ref, ADAPTER)[2],
                         'reserved')
        self.assertEqual(fx.child_calls, [])

    def test_scan_b_orphan_request_quarantines(self):
        fx = self.fx
        fx.make_run('r1')
        ghost = c.AttemptRef('r1', 'j', 'z')
        request = c.ExecuteRequest(ghost, c.Job('r1', 'j', 'do', ('c',)),
                                   fx.conditions)
        fx.ledger.reserve(request, 'owner-x')
        with fx.store._tx('r1') as data:
            data['requests'][_attempt_key(ghost)] = request
        self.assertEqual(fx.scan(), frozenset({'r1'}))
        self.assertEqual(fx.ledger.row(ghost, ADAPTER)[2], 'reserved')


    def test_divergent_committed_receipt_quarantines_run(self):
        fx = self.fx
        fx.make_run('r1')
        request = fx.prepare('r1')
        fx.pool.reserve(request)
        fx.admit('r1')
        # Bound accessor seam: the first read sees no receipt; the commit
        # read exposes a divergent committed record (CAS-boundary fault
        # injection only — no hand-minted Native proof).
        divergent = c.OperationReply(
            request.ref, c.OperationStatus.UNAVAILABLE, 'other receipt',
            never_started=c.NeverStarted(request, 'other:evidence'))
        committed, calls = fx.state.execute_receipt, []
        def seam(ref):
            calls.append(ref)
            return committed(ref) if len(calls) == 1 else divergent
        fx.state.execute_receipt = seam
        try:
            self.assertEqual(fx.scan(), frozenset({'r1'}))
        finally:
            fx.state.execute_receipt = committed
        # No unsafe ledger action beyond the legitimate never-dispatched
        # release, no committed receipt, no Controller, no factory call.
        self.assertIsNone(fx.state.execute_receipt(request.ref))
        self.assertEqual(fx.ledger.row(request.ref, ADAPTER)[3],
                         NEVER_DISPATCHED)
        self.assertEqual(fx.child_calls, [])
    def test_capacity_error_is_global(self):
        fx = self.fx
        fx.make_run('r1')
        request = fx.prepare('r1')
        fx.pool.reserve(request)

        def boom(*args):
            raise CapacityError('injected')
        fx.ledger.cancel_unstarted = boom
        with self.assertRaises(CapacityError):
            fx.scan()
        self.assertEqual(fx.ledger.row(request.ref, ADAPTER)[2],
                         'reserved')

    def test_recover_capacity_error_is_global(self):
        fx = self.fx
        fx.make_run('r1')
        request = fx.prepare('r1')
        fx.pool.reserve(request)
        fx.admit('r1')
        fx.pool.recover_unstarted = lambda *a: (_ for _ in ()).throw(
            CapacityError('injected'))
        with self.assertRaises(CapacityError):
            fx.scan()
        self.assertIsNone(fx.state.execute_receipt(request.ref))

    def test_commit_helper_replay_conflict_and_cas(self):
        fx = self.fx
        fx.make_run('r1')
        request = fx.prepare('r1')
        fx.pool.reserve(request)
        fx.admit('r1')
        reply = fx.pool.recover_unstarted(request)
        commit_execute_receipt(fx.state, reply)
        revision = fx.rev('r1')
        commit_execute_receipt(fx.state, reply)      # exact replay
        self.assertEqual(fx.rev('r1'), revision)
        self.assertEqual(fx.state.execute_receipt(request.ref), reply)
        # Intentional committed-record tamper: a receipt that binds the
        # same ref but different evidence must fail closed.
        divergent = replace(reply, never_started=c.NeverStarted(
            request, 'other:evidence'))
        with self.assertRaises(IntegrityViolation):
            commit_execute_receipt(fx.state, divergent)
        # Stale-CAS retry succeeds; permanent Conflict -> InvalidTransition.
        fx.make_run('r2')
        request2 = fx.prepare('r2')
        fx.pool.reserve(request2)
        fx.admit('r2')
        reply2 = fx.pool.recover_unstarted(request2)
        record, calls = fx.state.record_execute, []
        def flaky(r, rev):
            if not calls:
                calls.append(1)
                raise Conflict('stale')
            return record(r, rev)
        fx.state.record_execute = flaky
        commit_execute_receipt(fx.state, reply2)
        self.assertEqual(calls, [1])
        fx.state.record_execute = record
        self.assertEqual(fx.state.execute_receipt(request2.ref), reply2)
        fx.make_run('r3')
        request3 = fx.prepare('r3')
        fx.pool.reserve(request3)
        fx.admit('r3')
        reply3 = fx.pool.recover_unstarted(request3)
        fx.state.record_execute = lambda *a: (_ for _ in ()).throw(
            Conflict('stale'))
        with self.assertRaises(InvalidTransition):
            commit_execute_receipt(fx.state, reply3)
        fx.state.record_execute = record
        self.assertIsNone(fx.state.execute_receipt(request3.ref))


class DriverQuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fx = Fixture(Path(self.tmp.name).resolve() / 'root')
        self.addCleanup(self.fx.close)

    def test_initial_quarantine_audited_once_never_stepped(self):
        fx = self.fx
        fx.make_run('run-q')
        fx.make_run('run-ok')
        built = []
        driver = ServiceDriver(
            fx.owner, fx.store, fx.gateway,
            controller_factory=lambda rid, snap: (
                built.append(rid), fx.build_controller(rid))[1],
            initial_quarantine={'run-q'})
        audits = fx.state.history('run-q', 'driver_audit')
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0][:2],
                         ('driver_project_error', 'integrity'))
        driver.start()
        driver.tick()
        driver.tick()
        self.assertEqual(built, ['run-ok'])          # one Controller only
        self.assertEqual(
            len(fx.state.history('run-q', 'driver_audit')), 1)
        self.assertEqual(fx.child_calls, [])


if __name__ == '__main__':
    unittest.main()
