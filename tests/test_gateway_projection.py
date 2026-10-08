"""M3 cancel + write-once projection backend tests; synthetic, no provider."""
import multiprocessing
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.controller import ControllerCheckpoint
from co_v4.gateway_store import (Gateway, cancel_body, lookup_body,
                                 submit_body)
from co_v4.judgment import JudgmentRequest, TrustedEvidence
from co_v4.responses_input import parse
from co_v4.state import (ControlStore, IngressReceipt, IntegrityViolation,
                         NotFound, StoreUnavailable, UntrustedInput,
                         body_digest)
from test_output_pipeline import output_run

NOW = '2026-10-06T00:00:00Z'
DIGEST = 'sha256:' + '0' * 64
PURE = c.TaskProfile('p-pure', DIGEST, 'pure')


def _cancel_worker(path, source, response_id, barrier, queue):
    store = ControlStore(
        path, verifier=lambda ref: IngressReceipt(
            'p1', ref, body_digest(cancel_body(response_id)), NOW),
        evidence=lambda *_: None, clock=lambda: NOW,
        profile_resolver=lambda alias: PURE)
    try:
        barrier.wait(timeout=20)
        p = store.gateway().cancel(response_id, source)
        queue.put(('ok', p.status, p.decided))
    except Exception as exc:
        queue.put(('err', type(exc).__name__, str(exc)))
    finally:
        store.close()


class Harness:
    def __init__(self, path):
        self.path, self.now, self.receipts = path, NOW, {}
        self.deny, self.confirm = False, False
        self.contained, self.authorizes, self.protection = True, True, True
        self.store = ControlStore(path, verifier=self.receipts.__getitem__,
            evidence=self.evidence, clock=lambda: self.now,
            profile_resolver=lambda alias: PURE)
        self.ctrl, self.intake = self.store.controller(), self.store.intake()
        self.gateway, self.judgment = self.store.gateway(), self.store.judgment()
        self.conditions = c.ExecutionConditions('m', 'adapter', '/f', 'env:1')
        self.action = c.Action('filesystem.write',
                               c.Scope((('path', '/f/out'),), True))

    def evidence(self, run, request):
        return TrustedEvidence(body_digest(request), 'policy:1',
            ('fixture:protection',), 'fixture-op', self.deny, self.confirm,
            self.contained, self.authorizes, True, self.protection)

    def auth(self, source, body, principal='p1'):
        self.receipts[source] = IngressReceipt(
            principal, source, body_digest(body), self.now)
        return source

    def submit(self, source='submit:1'):
        req = parse(b'{"model":"co-auto","input":"x"}')
        return self.gateway.submit(req, 'k',
            self.auth(source, submit_body(req.body_hash, 'k')))

    def cancel(self, response_id, source='cancel:1', principal='p1'):
        return self.gateway.cancel(response_id,
            self.auth(source, cancel_body(response_id), principal))

    def rows(self, table):
        return self.store._db.execute(
            'SELECT COUNT(*) FROM ' + table).fetchone()[0]

    def admit(self, run_id, attempt='a'):
        job = c.Job(run_id, 'j', 'create output', ('inspect',))
        d = self.judgment.judge(JudgmentRequest(
            c.QuestionRef(run_id, 'j'), self.action, 'write-output',
            self.conditions, None, job))
        self.ctrl.add_job(job, d.decision_id,
                          self.ctrl.get_run(run_id).revision)
        ref = c.AttemptRef(run_id, 'j', attempt)
        req = c.ExecuteRequest(ref, self.ctrl.get_job(run_id, 'j'),
                               self.conditions)
        d = self.judgment.judge(JudgmentRequest(
            c.QuestionRef(run_id, 'j', attempt), self.action, 'write-output',
            self.conditions))
        return self.ctrl.begin_attempt(
            req, d.decision_id, self.ctrl.get_run(run_id).revision)

    def wait(self, run_id, name='q1'):
        # Admit the exact Job before opening its confirmation wait.
        job = c.Job(run_id, 'j', 'create output', ('inspect',))
        d = self.judgment.judge(JudgmentRequest(
            c.QuestionRef(run_id, 'j'), self.action, 'write-output',
            self.conditions, None, job))
        self.ctrl.add_job(job, d.decision_id,
                          self.ctrl.get_run(run_id).revision)
        self.confirm = True
        d = self.judgment.judge(JudgmentRequest(
            c.QuestionRef(run_id, 'j'), self.action, 'write-output',
            self.conditions))
        wait = c.WaitingHuman(c.QuestionRef(run_id, 'j'), name, self.action,
            d.decision, d.reason, '2026-10-08T00:00:00Z')
        return self.ctrl.open_wait(wait, 'write-output',
            self.ctrl.get_run(run_id).revision, d.decision_id)

    def latch(self, run_id, halted='integrity_violation'):
        self.ctrl.save_checkpoint(run_id, ControllerCheckpoint(
            None, None, None, (), (), (), None, halted, (), 0, None),
            self.ctrl.get_run(run_id).revision)

    def stop(self, ref, status, evidence=None):
        a = self.ctrl.get_attempt(ref)
        return self.ctrl.record_stop(
            c.StopReply(ref, status, 'fixture', evidence), a.revision)


class CancelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Harness(Path(self.tmp.name) / 'control.sqlite')
        self.addCleanup(self.h.store.close)

    def test_cancel_scope_single_claim_and_noop_replays(self):
        h = self.h
        sub = h.submit(); rid, run_id = sub.response_id, sub.run_id
        h.wait(run_id)
        with self.assertRaises(UntrustedInput):
            h.gateway.cancel(rid, 'no-receipt')
        h.auth('c:p2', cancel_body(rid), principal='p2')
        with self.assertRaises(NotFound):          # foreign == absent
            h.gateway.cancel(rid, 'c:p2')
        h.auth('c:absent', cancel_body('resp_absent'))
        with self.assertRaises(NotFound):
            h.gateway.cancel('resp_absent', 'c:absent')
        rev, ingress = h.ctrl.get_run(run_id).revision, h.rows('ingress')
        projection = h.cancel(rid)
        self.assertEqual((projection.status, projection.decided),
                         ('in_progress', False))    # never derives decisive
        run = h.ctrl.get_run(run_id)
        self.assertTrue(run.stop_requested)
        self.assertEqual(run.revision, rev + 1)     # one bump, one claim
        self.assertEqual(h.rows('ingress'), ingress + 1)
        self.assertEqual(h.ctrl.wait_details(
            c.QuestionRef(run_id, 'j'), 'q1').disposition, 'stopped')
        self.assertEqual(h.ctrl.history(run_id, 'answers'), ())
        self.assertEqual(h.ctrl.history(run_id, 'human_receipts'), ())
        h.cancel(rid, 'cancel:2')                   # stopped: write-free no-op
        self.assertEqual(h.ctrl.get_run(run_id).revision, run.revision)
        self.assertEqual(h.rows('ingress'), ingress + 1)
        decided = h.gateway.project(run_id)
        self.assertEqual((decided.status, decided.decided), ('cancelled', True))
        h.auth('r:1', lookup_body(rid))
        self.assertEqual(h.gateway.read(rid, 'r:1').status, 'cancelled')

    def test_terminal_cancel_is_write_free_and_reason_maps_closed(self):
        for reason, code in (('provider_refusal', 'provider_refusal'),
                             ('approval_required', 'approval_required'),
                             ('integrity_violation', 'integrity_violation'),
                             ('opaque_internal_cause', 'run_failed')):
            with self.subTest(reason=reason):
                h = Harness(Path(self.tmp.name) / (code + '.sqlite'))
                self.addCleanup(h.store.close)
                sub = h.submit()
                h.ctrl.finalize_run(sub.run_id, c.State.FAILED, reason,
                                    h.ctrl.get_run(sub.run_id).revision)
                rev = h.ctrl.get_run(sub.run_id).revision
                h.cancel(sub.response_id)
                self.assertEqual(h.ctrl.get_run(sub.run_id).revision, rev)
                self.assertEqual(h.rows('ingress'), 1)   # submit claim only
                p = h.gateway.project(sub.run_id)
                self.assertEqual((p.status, p.code), ('failed', code))

    def test_unconfirmed_stop_without_bound_stays_undecided(self):
        h = self.h
        sub = h.submit(); rid, run_id = sub.response_id, sub.run_id
        ref = h.admit(run_id).ref
        h.cancel(rid)
        self.assertEqual(h.gateway.project(run_id).status, 'in_progress')
        h.stop(ref, c.StopStatus.REQUESTED)         # ack only: not decisive
        self.assertEqual(h.gateway.project(run_id).status, 'in_progress')
        h.stop(ref, c.StopStatus.UNCONFIRMED)
        # Legacy admit() commits no RoutingRecord: with no admission bound,
        # an UNCONFIRMED stop is held evidence, never an immediate decision.
        p = h.gateway.project(run_id)
        self.assertEqual((p.status, p.code, p.decided),
                         ('in_progress', None, False))

    def test_confirmed_stop_without_result_is_cancelled(self):
        h = self.h
        sub = h.submit(); ref = h.admit(sub.run_id).ref
        h.stop(ref, c.StopStatus.CONFIRMED, 'ev:a')  # held: no Result yet
        h.cancel(sub.response_id)
        self.assertEqual(h.gateway.project(sub.run_id).status, 'cancelled')

    def test_unconfirmed_cessation_without_bound_is_undecided(self):
        h = self.h
        sub = h.submit(); ref = h.admit(sub.run_id).ref
        a = h.ctrl.record_event(c.ResultEvent(ref, 'ev:r',
            c.Result(ref, c.State.COMPLETED)), h.ctrl.get_attempt(ref).revision)
        h.ctrl.record_stop(c.StopReply(ref, c.StopStatus.UNCONFIRMED,
                                       'fixture'), a.revision)
        # Real Result + UNCONFIRMED cessation stay committed; without a bound
        # admission record the expiry rule cannot decide — held truthfully.
        p = h.gateway.project(sub.run_id)
        self.assertEqual((p.status, p.code),
                         ('in_progress', None))

    def test_committed_fatal_latch_precedes_any_cancel_projection(self):
        h = self.h
        sub = h.submit(); h.latch(sub.run_id)         # fatal before any row
        p = h.gateway.project(sub.run_id)
        self.assertEqual((p.status, p.code, p.decided),
                         ('failed', 'integrity_violation', True))

    def test_latch_and_stop_same_unprojected_state_latch_wins(self):
        h = self.h
        sub = h.submit()
        h.cancel(sub.response_id)                   # stop committed
        h.latch(sub.run_id)                         # latch also committed
        p = h.gateway.project(sub.run_id)           # conservative status wins
        self.assertEqual((p.status, p.code),
                         ('failed', 'integrity_violation'))

    def test_write_once_row_never_rewritten(self):
        h = self.h
        sub = h.submit(); h.cancel(sub.response_id)
        first = h.gateway.project(sub.run_id)
        self.assertEqual(first.status, 'cancelled')
        h.ctrl.finalize_run(sub.run_id, c.State.FAILED, 'integrity_violation',
                            h.ctrl.get_run(sub.run_id).revision)
        h.latch(sub.run_id)
        again = h.gateway.project(sub.run_id)       # later fatal cannot move it
        self.assertEqual((again.status, again.decided), ('cancelled', True))
        self.assertEqual(h.rows('gateway_projections'), 1)

    def test_completed_run_projects_output_refs_and_stays_write_once(self):
        s = output_run(Path(self.tmp.name) / 'complete',
                       scripts={'squares': ['good']})
        try:
            self.assertEqual(s.drive().state, c.State.COMPLETED)
            run = s.state.get_run('run')
            self.assertIsNotNone(run.output_selection)
            s.store._db.execute(
                'INSERT INTO gateway_responses VALUES (?,?,?,?,?,?)',
                ('resp_c', 'p1', 'run', 'd', 'co-auto', s.now))
            gateway = Gateway(s.store)
            p = gateway.project('run')
            self.assertEqual((p.status, p.decided), ('completed', True))
            ref, output = p.output
            self.assertEqual((ref.attempt_ref, ref.digest),
                (run.output_selection.attempt_ref,
                 run.output_selection.output_digest))
            self.assertEqual(output.digest, run.output_selection.output_digest)
            self.assertEqual(gateway.project('run'), p)      # write-once
            body = lookup_body('resp_c')
            s.journal.bind('read:1', body, IngressReceipt(
                'p1', 'read:1', body_digest(body), s.now))
            seen = gateway.read('resp_c', 'read:1')
            self.assertEqual((seen.status, seen.decided, seen.output),
                             ('completed', True, p.output))
        finally:
            s.close()

    def test_tampered_rows_fail_closed(self):
        h = self.h
        sub = h.submit(); rid, run_id = sub.response_id, sub.run_id
        for row in (('exploded', None, 0), ('failed', 'invented', 0),
                    ('failed', None, 0), ('cancelled', None, 10 ** 9),
                    ('failed', 'run_failed', -1), ('completed', None, 0),
                    ('cancelled', None, 0)):
            h.store._db.execute('DELETE FROM gateway_projections')
            h.store._db.execute(
                'INSERT INTO gateway_projections VALUES (?,?,?,?,?)',
                (rid,) + row + (NOW,))
            with self.subTest(row=row), self.assertRaises(IntegrityViolation):
                h.gateway.project(run_id)
        h.store._db.execute('DELETE FROM gateway_projections')
        h.cancel(rid)                                # stop now committed
        h.store._db.execute(
            'INSERT INTO gateway_projections VALUES (?,?,?,?,?)',
            (rid, 'cancelled', None, 0, NOW))
        self.assertEqual(h.gateway.project(run_id).status, 'cancelled')

    def test_read_is_write_free_and_run_id_free(self):
        h = self.h
        sub = h.submit(); rid = sub.response_id
        h.auth('r:foreign', lookup_body(rid), principal='p2')
        with self.assertRaises(NotFound):
            h.gateway.read(rid, 'r:foreign')
        changes = h.store._db.total_changes
        h.auth('r:1', lookup_body(rid))
        view = h.gateway.read(rid, 'r:1')
        self.assertEqual((view.status, view.decided), ('queued', False))
        self.assertFalse(hasattr(view, 'run_id'))
        h.cancel(rid)                                # decisive derivation ready
        self.assertEqual(h.gateway.read(rid, 'r:1').status, 'in_progress')
        self.assertEqual(h.rows('gateway_projections'), 0)
        self.assertEqual(h.store._db.total_changes, changes + 2)

    def test_cancel_fault_rolls_back_stop_and_claim(self):
        h = self.h
        sub = h.submit(); rid, run_id = sub.response_id, sub.run_id
        for ddl in ("CREATE TRIGGER f1 BEFORE UPDATE ON runs"
                    " BEGIN SELECT RAISE(ABORT,'f'); END",
                    "CREATE TRIGGER f2 BEFORE INSERT ON ingress"
                    " BEGIN SELECT RAISE(ABORT,'f'); END"):
            h.store._db.execute(ddl)
            with self.assertRaises(StoreUnavailable):
                h.cancel(rid)
            h.store._db.execute('DROP TRIGGER ' + ddl.split()[2])
            self.assertFalse(h.ctrl.get_run(run_id).stop_requested)
            self.assertEqual(h.rows('ingress'), 1)
        self.assertEqual(h.cancel(rid).status, 'in_progress')
        self.assertTrue(h.ctrl.get_run(run_id).stop_requested)

    def test_concurrent_cancel_applies_once(self):
        h = self.h
        sub = h.submit(); rid, run_id = sub.response_id, sub.run_id
        ctx = multiprocessing.get_context('spawn')
        barrier, queue = ctx.Barrier(2), ctx.Queue()
        children = [ctx.Process(target=_cancel_worker,
            args=(str(h.path), 'cc%d' % i, rid, barrier, queue))
            for i in range(2)]
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
        self.assertEqual([r[0] for r in results], ['ok', 'ok'])
        run = h.ctrl.get_run(run_id)
        self.assertTrue(run.stop_requested)
        self.assertEqual(run.revision, 1)           # exactly one bump
        self.assertEqual(h.rows('ingress'), 2)      # submit + one cancel claim


if __name__ == '__main__':
    unittest.main()
