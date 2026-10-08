"""M3 bound-expiry and atomic projection_decided barrier tests; synthetic.

Positive coverage drives only real committed state: gateway submit,
Judgment, begin_attempt with its atomic RoutingRecord, record_event and
record_stop. The expiry bound arrives through the pinned host resolver
callback; registry load validation and startup mismatch refusal are a
later composition chunk. Canonical-ledger/PooledAdapter driver and
owner-kill/restart coverage stays required in the separate driver chunk.
_tx injections below only commit records no product path can produce
(malformed 'at', duplicate/wrong-typed routing, synthetic waits) for
negative cases; no admission is mutated and no fake proof is fabricated.
"""
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.gateway_store import Gateway, lookup_body
from co_v4.judgment import JudgmentRequest
from co_v4.state import (Conflict, ControlStore, RoutingRecord,
                         StoreUnavailable)
from test_gateway_projection import DIGEST, Harness, NOW, PURE

BASE = datetime.fromisoformat(NOW.replace('Z', '+00:00'))
BOUND = 60
ROUTING = ('{"selected":{"model":"m","adapter":"adapter"},'
           '"assessments":[]}')


def stamp(seconds):
    return (BASE + timedelta(seconds=seconds)).isoformat()


def resolver(value):
    return lambda profile_id, revision_digest: value


class BoundHarness(Harness):
    """admit_bound commits a real atomic RoutingRecord so the expiry bound
    can engage; legacy admit() stays bound-free. Injections are labelled
    fixture corruption for negative cases only."""

    def admit_bound(self, run_id, attempt='a', job_id='j', at=None):
        job = c.Job(run_id, job_id, 'create output', ('inspect',))
        d = self.judgment.judge(JudgmentRequest(
            c.QuestionRef(run_id, job_id), self.action, 'write-output',
            self.conditions, None, job))
        self.ctrl.add_job(job, d.decision_id,
                          self.ctrl.get_run(run_id).revision)
        ref = c.AttemptRef(run_id, job_id, attempt)
        req = c.ExecuteRequest(ref, self.ctrl.get_job(run_id, job_id),
                               self.conditions)
        d = self.judgment.judge(JudgmentRequest(
            c.QuestionRef(run_id, job_id, attempt), self.action,
            'write-output', self.conditions))
        revision = self.ctrl.get_run(run_id).revision
        routing = RoutingRecord('route:%s:%s' % (job_id, attempt),
            c.QuestionRef(run_id, job_id, attempt), revision,
            at or self.now, ROUTING, d.decision_id)
        return self.ctrl.begin_attempt(req, d.decision_id, revision,
                                       routing=routing)

    def inject_routing(self, run_id, record_id, value):
        """Committed routing_history content no product path writes."""
        with self.store._tx(run_id) as data:
            data.setdefault('routing_history', {})[record_id] = value

    def inject_wait(self, run_id, attempt='a', job_id='j', closed=None):
        """Committed fixture wait record bound to the Attempt's exact ref."""
        with self.store._tx(run_id) as data:
            data['waits']['wait:' + attempt] = dict(
                wait=c.WaitingHuman(c.QuestionRef(run_id, job_id, attempt),
                    'wait:' + attempt, self.action, c.Decision.CONFIRM,
                    'fixture wait', '2026-10-08T00:00:00Z'),
                closed=closed)

    def row(self, response_id):
        return self.store._db.execute(
            'SELECT status, code, run_revision, at FROM gateway_projections'
            ' WHERE response_id=?', (response_id,)).fetchone()


class BoundTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def harness(self, name='control.sqlite'):
        h = BoundHarness(self.dir / name)
        self.addCleanup(h.store.close)
        return h

    def expired(self, name='b.sqlite', **kw):
        """Submitted Run with one bound-admitted unsettled Attempt; clock
        already past admitted_at + BOUND."""
        h = self.harness(name)
        sub = h.submit()
        h.admit_bound(sub.run_id, **kw)
        h.now = stamp(BOUND + 60)
        return h, sub

    def test_within_bound_unchanged_and_write_free(self):
        h = self.harness()
        sub = h.submit()
        attempt = h.admit_bound(sub.run_id)
        h.now = stamp(BOUND - 1)                     # inside the interval
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual((p.status, p.decided), ('in_progress', False))
        self.assertEqual(h.rows('gateway_projections'), 0)
        self.assertEqual(h.ctrl.attempts(sub.run_id), (attempt,))
        self.assertEqual(h.ctrl.history(sub.run_id, 'execute_history'), ())
        self.assertIsNone(h.ctrl.stop_origin(sub.run_id))
        self.assertFalse(h.ctrl.get_run(sub.run_id).stop_requested)

    def test_boundary_at_after_and_backward_clock(self):
        for seconds, status in ((BOUND - 1, 'in_progress'), (BOUND, 'failed'),
                                (BOUND + 1, 'failed')):
            with self.subTest(seconds=seconds):
                h = self.harness('t%d' % seconds)
                sub = h.submit()
                h.admit_bound(sub.run_id)
                h.now = stamp(seconds)
                p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
                self.assertEqual((p.status, p.decided),
                                 (status, status == 'failed'))
        h = self.harness('future')
        sub = h.submit()
        h.admit_bound(sub.run_id, at=stamp(BOUND * 2))   # future stamp
        for now in (NOW, stamp(-BOUND), stamp(BOUND * 3 - 1)):
            h.now = now                                  # backward only delays
            p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
            self.assertEqual(p.status, 'in_progress')
        h.now = stamp(BOUND * 3)
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual(p.code, 'cessation_unconfirmed')

    def test_decision_commits_stop_barrier_atomically(self):
        h, sub = self.expired()
        rev, ingress = h.ctrl.get_run(sub.run_id).revision, h.rows('ingress')
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual((p.status, p.code, p.decided),
                         ('failed', 'cessation_unconfirmed', True))
        run = h.ctrl.get_run(sub.run_id)
        self.assertTrue(run.stop_requested)
        self.assertEqual(run.revision, rev + 1)          # exactly one bump
        self.assertEqual(h.ctrl.stop_origin(sub.run_id), 'projection_decided')
        self.assertEqual((h.row(sub.response_id)[2], p.run_revision),
                         (run.revision, run.revision))
        self.assertEqual(h.rows('ingress'), ingress)     # zero ingress claims

    def test_insert_failure_rolls_back_row_and_stop(self):
        h, sub = self.expired()
        h.store._db.execute("CREATE TRIGGER f BEFORE INSERT ON"
            " gateway_projections BEGIN SELECT RAISE(ABORT,'f'); END")
        rev = h.ctrl.get_run(sub.run_id).revision
        with self.assertRaises(StoreUnavailable):
            Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        run = h.ctrl.get_run(sub.run_id)
        self.assertFalse(run.stop_requested)
        self.assertEqual(run.revision, rev)
        self.assertIsNone(h.ctrl.stop_origin(sub.run_id))
        self.assertIsNone(h.row(sub.response_id))
        h.store._db.execute('DROP TRIGGER f')
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual((p.status, p.decided), ('failed', True))

    def test_late_confirmed_facts_never_rewrite_decided_row(self):
        h, sub = self.expired()
        gw = Gateway(h.store, resolver(BOUND))
        gw.project(sub.run_id)
        row = h.row(sub.response_id)
        ref = h.ctrl.attempts(sub.run_id)[0].ref
        a = h.ctrl.get_attempt(ref)
        h.ctrl.record_stop(c.StopReply(ref, c.StopStatus.CONFIRMED,
                           'fixture', 'ev:late'), a.revision)
        a = h.ctrl.record_event(c.ResultEvent(ref, 'ev:result',
            c.Result(ref, c.State.COMPLETED)),
            h.ctrl.get_attempt(ref).revision)
        self.assertEqual(h.ctrl.attempt_settlement(ref), 'native')
        final = h.ctrl.finalize_run(sub.run_id, c.State.FAILED,
            'projection_decided', h.ctrl.get_run(sub.run_id).revision)
        self.assertEqual(final.final_reason, 'projection_decided')
        again = gw.project(sub.run_id)
        self.assertEqual((again.status, again.code, again.decided,
                          again.output),
                         ('failed', 'cessation_unconfirmed', True, None))
        self.assertEqual(h.row(sub.response_id), row)    # byte-identical
        self.assertIsNone(a.ac)
        self.assertIsNone(a.output)
        self.assertIsNone(final.output_selection)
        self.assertEqual(h.ctrl.history(sub.run_id, 'execute_history'), ())

    def test_decided_run_admits_no_retry(self):
        h, sub = self.expired()
        Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        req = c.ExecuteRequest(c.AttemptRef(sub.run_id, 'j', 'b'),
            h.ctrl.get_job(sub.run_id, 'j'), h.conditions)
        with self.assertRaisesRegex(Conflict, 'stop_requested'):
            h.ctrl.begin_attempt(req, 'unused',
                                 h.ctrl.get_run(sub.run_id).revision)
        self.assertEqual(len(h.ctrl.attempts(sub.run_id)), 1)
        self.assertEqual(h.ctrl.history(sub.run_id, 'execute_history'), ())

    def test_read_and_cancel_never_insert_or_project_stop(self):
        h, sub = self.expired()
        h.auth('r:1', lookup_body(sub.response_id))
        view = h.gateway.read(sub.response_id, 'r:1')
        self.assertEqual((view.status, view.decided), ('in_progress', False))
        self.assertEqual(h.rows('gateway_projections'), 0)
        self.assertIsNone(h.ctrl.stop_origin(sub.run_id))
        self.assertFalse(h.ctrl.get_run(sub.run_id).stop_requested)
        p = h.cancel(sub.response_id)
        self.assertEqual(p.status, 'in_progress')        # decision held
        self.assertEqual(h.rows('gateway_projections'), 0)
        self.assertEqual(h.ctrl.stop_origin(sub.run_id), 'gateway_cancel')

    def test_cancel_then_expiry_keeps_gateway_cancel_origin(self):
        h, sub = self.expired()
        rev = h.ctrl.get_run(sub.run_id).revision
        h.cancel(sub.response_id)
        self.assertEqual(h.ctrl.stop_origin(sub.run_id), 'gateway_cancel')
        self.assertEqual(h.rows('gateway_projections'), 0)
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual((p.status, p.code),
                         ('failed', 'cancellation_unconfirmed'))
        self.assertEqual(h.ctrl.stop_origin(sub.run_id), 'gateway_cancel')
        self.assertEqual(h.ctrl.get_run(sub.run_id).revision, rev + 1)

    def test_cancel_is_immediate_zero_attempts_and_confirmed_missing(self):
        h = self.harness('zero')
        sub = h.submit()
        h.cancel(sub.response_id)
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual((p.status, p.decided), ('cancelled', True))
        h = self.harness('confirmed')
        sub = h.submit()
        attempt = h.admit_bound(sub.run_id)
        h.stop(attempt.ref, c.StopStatus.CONFIRMED, 'ev:a')
        h.cancel(sub.response_id)                        # before any bound
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual((p.status, p.code, p.decided),
                         ('cancelled', None, True))
        self.assertEqual(h.ctrl.stop_origin(sub.run_id), 'gateway_cancel')

    def test_confirmed_stop_no_result_no_wait_is_run_failed(self):
        h = self.harness()
        sub = h.submit()
        attempt = h.admit_bound(sub.run_id)
        h.stop(attempt.ref, c.StopStatus.CONFIRMED, 'ev:a')
        gw = Gateway(h.store, resolver(BOUND))
        h.now = stamp(BOUND - 1)
        self.assertEqual(gw.project(sub.run_id).status, 'in_progress')
        h.now = stamp(BOUND)
        p = gw.project(sub.run_id)
        self.assertEqual((p.status, p.code), ('failed', 'run_failed'))
        self.assertEqual(h.ctrl.stop_origin(sub.run_id), 'projection_decided')
        self.assertIsNone(h.ctrl.get_attempt(attempt.ref).result)

    def test_prior_closed_wait_blocks_run_failed(self):
        h = self.harness()
        sub = h.submit()
        attempt = h.admit_bound(sub.run_id)
        h.inject_wait(sub.run_id, closed='answered')
        h.stop(attempt.ref, c.StopStatus.CONFIRMED, 'ev:a')
        h.now = stamp(BOUND + 60)
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual(p.status, 'in_progress')
        self.assertIsNone(h.ctrl.stop_origin(sub.run_id))

    def test_open_wait_excludes_attempt_from_expiry(self):
        h = self.harness()
        sub = h.submit()
        h.admit_bound(sub.run_id)
        h.inject_wait(sub.run_id, closed=None)           # open wait
        h.now = stamp(BOUND + 60)
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual((p.status, p.decided), ('in_progress', False))
        self.assertFalse(h.ctrl.get_run(sub.run_id).stop_requested)

    def test_mixed_expired_unconfirmed_wins_over_confirmed_missing(self):
        h = self.harness()
        sub = h.submit()
        a = h.admit_bound(sub.run_id, attempt='a', job_id='j')
        b = h.admit_bound(sub.run_id, attempt='b', job_id='j2')
        h.stop(a.ref, c.StopStatus.UNCONFIRMED)
        h.stop(b.ref, c.StopStatus.CONFIRMED, 'ev:b')
        h.now = stamp(BOUND + 60)
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual((p.status, p.code),
                         ('failed', 'cessation_unconfirmed'))

    def test_settled_attempt_awaiting_ac_output_never_expires(self):
        h = self.harness()
        sub = h.submit()
        attempt = h.admit_bound(sub.run_id)
        ref = attempt.ref
        h.ctrl.record_event(c.ResultEvent(ref, 'ev:r',
            c.Result(ref, c.State.COMPLETED)),
            h.ctrl.get_attempt(ref).revision)
        h.stop(ref, c.StopStatus.CONFIRMED, 'ev:a')      # settled
        h.now = stamp(BOUND + 60)
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual((p.status, p.decided), ('in_progress', False))
        self.assertEqual(h.rows('gateway_projections'), 0)
        self.assertIsNone(h.ctrl.get_attempt(ref).ac)    # AC still pending

    def test_missing_mismatched_or_nonunique_admission_is_undecided(self):
        qref_at = lambda h: c.QuestionRef(h, 'j', 'a')
        for name, records in (
                ('missing', {}),
                ('nonunique', ('valid', 'valid')),
                ('noexec', ('noexec',)),
                ('wrongattempt', ('otherattempt',)),
                ('wrongjob', ('otherjob',)),
                ('wrongrun', ('otherrun',)),
                ('wrongtype', ('garbage',))):
            with self.subTest(case=name):
                h = self.harness(name)
                sub = h.submit()
                h.admit(sub.run_id)                      # legacy: no routing
                qref = c.QuestionRef(sub.run_id, 'j', 'a')
                for index, kind in enumerate(records):
                    rid = 'r:%d' % index
                    if kind == 'valid':
                        value = RoutingRecord(rid, qref, 0, NOW, '{}', 'd')
                    elif kind == 'noexec':
                        value = RoutingRecord(rid, qref, 0, NOW, '{}', None)
                    elif kind == 'otherattempt':
                        value = RoutingRecord(rid, c.QuestionRef(
                            sub.run_id, 'j', 'other'), 0, NOW, '{}', 'd')
                    elif kind == 'otherjob':
                        value = RoutingRecord(rid, c.QuestionRef(
                            sub.run_id, 'other', 'a'), 0, NOW, '{}', 'd')
                    elif kind == 'otherrun':
                        value = RoutingRecord(rid, c.QuestionRef(
                            'other', 'j', 'a'), 0, NOW, '{}', 'd')
                    else:
                        value = 'not a routing record'
                    h.inject_routing(sub.run_id, rid, value)
                h.now = stamp(BOUND + 60)
                p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
                self.assertEqual((p.status, p.decided),
                                 ('in_progress', False))
                self.assertIsNone(h.row(sub.response_id))

    def test_malformed_admission_stamp_is_undecided_without_exception(self):
        for index, at in enumerate(('not-a-time', '2026-10-06T00:00:00',
                                    '2026-10-06T00:00:00+05:00', 123, None)):
            with self.subTest(at=at):
                h = self.harness('at%d' % index)
                sub = h.submit()
                h.admit(sub.run_id)
                h.inject_routing(sub.run_id, 'r:bad', RoutingRecord(
                    'r:bad', c.QuestionRef(sub.run_id, 'j', 'a'), 0, at,
                    '{}', 'd'))
                h.now = stamp(BOUND + 60)
                p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
                self.assertEqual((p.status, p.decided),
                                 ('in_progress', False))

    def test_near_max_stamp_sum_overflow_is_undecided(self):
        h = self.harness()
        sub = h.submit()
        h.admit_bound(sub.run_id, at='9999-12-31T23:59:59+00:00')
        h.now = stamp(BOUND + 60)
        p = Gateway(h.store, resolver(10 ** 9)).project(sub.run_id)
        self.assertEqual((p.status, p.decided), ('in_progress', False))
        self.assertIsNone(h.row(sub.response_id))

    def test_invalid_bound_values_reject_write_free(self):
        for index, value in enumerate((True, 'x', -1, -0.5, float('nan'),
                                       float('inf'), -float('inf'),
                                       10 ** 40, object())):
            with self.subTest(index=index):
                h, sub = self.expired('v%d' % index)
                with self.assertRaises(ValueError):
                    Gateway(h.store, resolver(value)).project(sub.run_id)
                self.assertIsNone(h.row(sub.response_id))
                run = h.ctrl.get_run(sub.run_id)
                self.assertFalse(run.stop_requested)
                self.assertIsNone(h.ctrl.stop_origin(sub.run_id))

    def test_resolver_miss_absent_or_raising(self):
        h, sub = self.expired('miss')
        p = Gateway(h.store, resolver(None)).project(sub.run_id)
        self.assertEqual((p.status, p.decided), ('in_progress', False))
        self.assertIsNone(h.row(sub.response_id))
        h, sub = self.expired('absent')
        p = Gateway(h.store).project(sub.run_id)           # no resolver
        self.assertEqual((p.status, p.decided), ('in_progress', False))
        h, sub = self.expired('raising')
        with self.assertRaises(ZeroDivisionError):
            Gateway(h.store, lambda *_: 1 / 0).project(sub.run_id)
        self.assertIsNone(h.row(sub.response_id))
        self.assertFalse(h.ctrl.get_run(sub.run_id).stop_requested)

    def test_resolver_receives_exact_pinned_profile_identity(self):
        h, sub = self.expired()
        calls = []
        gw = Gateway(h.store,
                     lambda pid, rev: calls.append((pid, rev)) or BOUND)
        gw.project(sub.run_id)
        self.assertEqual(calls, [('p-pure', DIGEST)])

    def test_unconfirmed_stop_without_admission_bound_is_held(self):
        # Documents the corrected legacy expectation: no RoutingRecord means
        # no bound, so an UNCONFIRMED stop alone is never decisive.
        h = self.harness()
        sub = h.submit()
        attempt = h.admit(sub.run_id)
        h.stop(attempt.ref, c.StopStatus.UNCONFIRMED)
        h.now = stamp(10 ** 5)
        p = Gateway(h.store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual((p.status, p.decided), ('in_progress', False))
        self.assertIsNone(h.row(sub.response_id))

    def test_reopen_with_later_clock_still_decides(self):
        h = self.harness()
        sub = h.submit()
        h.admit_bound(sub.run_id)
        h.store.close()
        store = ControlStore(h.path, verifier=h.receipts.__getitem__,
            evidence=h.evidence, clock=lambda: stamp(BOUND * 4),
            profile_resolver=lambda alias: PURE)
        self.addCleanup(store.close)
        p = Gateway(store, resolver(BOUND)).project(sub.run_id)
        self.assertEqual((p.status, p.code, p.decided),
                         ('failed', 'cessation_unconfirmed', True))


if __name__ == '__main__':
    unittest.main()
