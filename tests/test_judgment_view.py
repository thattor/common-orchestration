"""JudgmentView: detached read-only facade inside the active transaction.

The facade is exercised inside the actual evidence callback of a real
judge() transaction — never simulated. Corrupt rows prove the resolver's
existing fail-closed seam (facade IntegrityViolation wrapped by evaluate).
No providers, no Native claims, no proof asserted from mocks.
"""
from dataclasses import FrozenInstanceError, fields, is_dataclass
from pathlib import Path
import tempfile
import threading
import unittest

from co_v4 import contracts as c
from co_v4.judgment import JudgmentRequest, TrustedEvidence
from co_v4.state import (ControlStore, IngressReceipt, IntegrityViolation,
                         JudgmentView, NotFound, StoreUnavailable,
                         body_digest, create_run_body)

NOW = '2026-10-06T00:00:00Z'
INTENT = 'produce fixture output'
DIGEST = body_digest('fixture-request')


class JudgmentViewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.views, self.facade_errors, self.probes = [], [], []
        self.traced, self.probe, self.probe_delta = [], False, None
        self.receipts = {}
        self.store = ControlStore(
            Path(self.tmp.name) / 'control.sqlite',
            verifier=self.receipts.__getitem__, evidence=self._evidence,
            clock=lambda: NOW)
        self.ctrl = self.store.controller()
        self.addCleanup(self.store.close)
        self.store._db.set_trace_callback(self.traced.append)
        self.new_run('r')

    def new_run(self, run_id):
        self.receipts[run_id] = IngressReceipt(
            'p', run_id, body_digest(create_run_body(run_id, INTENT)), NOW)
        self.store.intake().create_run(run_id, INTENT, run_id)

    def _evidence(self, run, request):
        # Runs inside the real Judgment transaction.
        try:
            view = self.store.judgment_view(run.run_id)
            self.views.append((view, self.store._db.total_changes))
        except IntegrityViolation:
            self.facade_errors.append(run.run_id)
            raise
        if self.probe:
            self.probe = False
            self._other_thread(run.run_id)
        return TrustedEvidence(
            body_digest(request), 'fixture:policy', ('fixture:ref',),
            'fixture:op', intent_contained=True, intent_authorizes=True,
            conditions_verified=True, protection_verified=True)

    def _other_thread(self, run_id):
        before = len(self.traced)
        done = []
        def call():
            try:
                self.store.judgment_view(run_id)
                done.append('ok')
            except StoreUnavailable:
                done.append('refused')
        t = threading.Thread(target=call)
        t.start()
        t.join(2)               # known immediate refusal; must not block
        self.probes.append('blocked' if t.is_alive() or not done else done[0])
        self.probe_delta = len(self.traced) - before

    def request(self, run_id, job_id, proposed=None):
        return JudgmentRequest(c.QuestionRef(run_id, job_id),
            c.Action('fixture.write', c.Scope((('k', 'v'),), True)),
            'write', c.ExecutionConditions('m', 'a', '/w', 'env:1'),
            proposed_job=proposed)

    def add_job(self, run_id='r', job_id='j'):
        job = c.Job(run_id, job_id, 'produce', ('check',))
        d = self.store.judgment().judge(
            self.request(run_id, job_id, proposed=job))
        self.ctrl.add_job(job, d.decision_id,
                          self.ctrl.get_run(run_id).revision)
        return job

    def gateway_row(self, run_id, digest=DIGEST, alias='co-text', at=NOW):
        self.store._db.execute(
            'INSERT INTO gateway_responses VALUES (?,?,?,?,?,?)',
            ('resp:' + run_id, 'p', run_id, digest, alias, at))

    def test_committed_values_no_writes_no_revision_change(self):
        self.gateway_row('r')
        job = self.add_job()
        before = self.store._db.total_changes
        rev = self.ctrl.get_run('r').revision
        record = self.store.judgment().judge(self.request('r', 'j'))
        view, changes_at_view = self.views[-1]
        self.assertEqual(view.gateway, (DIGEST, 'co-text', NOW))
        self.assertEqual(view.jobs, (job,))
        self.assertEqual(changes_at_view, before)   # facade wrote nothing
        # The Judgment record write, not the facade, moved total_changes.
        self.assertGreater(self.store._db.total_changes, before)
        self.assertEqual(self.ctrl.get_run('r').revision, rev)
        self.assertEqual(record.decision, c.Decision.NORMAL)

    def test_missing_gateway_row_is_none(self):
        job = self.add_job()
        self.store.judgment().judge(self.request('r', 'j'))
        view, _ = self.views[-1]
        self.assertIsNone(view.gateway)
        self.assertEqual(view.jobs, (job,))

    def test_outside_and_other_thread_refuse_without_begin(self):
        outside = len(self.traced)
        with self.assertRaises(StoreUnavailable):
            self.store.judgment_view('r')
        self.assertEqual(len(self.traced), outside)   # zero statements
        self.probe = True
        self.store.judgment().judge(
            self.request('r', 'j', proposed=c.Job('r', 'j', 'x', ('c',))))
        self.assertEqual(self.probes, ['refused'])    # immediate, not blocked
        self.assertEqual(self.probe_delta, 0)         # no BEGIN from it

    def test_frozen_detached_surface_only(self):
        self.gateway_row('r')
        self.add_job()
        self.store.judgment().judge(self.request('r', 'j'))
        view, _ = self.views[-1]
        self.assertIs(type(view), JudgmentView)
        self.assertTrue(type(view).__dataclass_params__.frozen)
        self.assertEqual({f.name for f in fields(view)}, {'gateway', 'jobs'})
        with self.assertRaises(FrozenInstanceError):
            view.gateway = None
        self.assertIs(type(view.jobs), tuple)
        self.assertIs(type(view.gateway), tuple)
        self.assertNotIn('sqlite', repr(view))

    def test_corrupt_gateway_rows_fail_closed(self):
        for i, row in enumerate((('bad-digest', 'co-text', NOW),
                                 (DIGEST, '', NOW),
                                 (DIGEST, 'co-text', 'not-a-time'),
                                 (DIGEST, 'co-text', '2026-10-06 00:00:00'))):
            with self.subTest(row=i):
                run_id = 'r%d' % i
                self.new_run(run_id)
                self.gateway_row(run_id, *row)
                job = c.Job(run_id, 'j', 'x', ('c',))
                with self.assertRaises(StoreUnavailable):
                    self.store.judgment().judge(
                        self.request(run_id, 'j', proposed=job))
                # The facade raised IntegrityViolation; the resolver's
                # existing fail-closed seam surfaces it as unavailable.
                self.assertIn(run_id, self.facade_errors)


    def test_failed_transaction_never_leaves_facade_open(self):
        # Missing-Run and corrupt-aggregate loads raise inside _tx: the
        # marker must not survive the aborted span; the refused facade
        # emits zero statements; a later valid transaction still works.
        valid = self.store._db.execute(
            'SELECT body FROM runs WHERE id=?', ('r',)).fetchone()[0]
        for body, exc in ((None, NotFound), ('{corrupt', StoreUnavailable)):
            with self.subTest(exc=exc.__name__):
                if body is None:
                    run_id = 'ghost'
                else:
                    self.store._db.execute(
                        'UPDATE runs SET body=? WHERE id=?', (body, 'r'))
                    run_id = 'r'
                before = len(self.traced)
                with self.assertRaises(exc):
                    self.ctrl.get_run(run_id)
                self.assertFalse(self.store._db.in_transaction)
                # The actual failed tx as recorded: BEGIN, SELECT, ROLLBACK.
                tail = self.traced[before:]
                self.assertEqual(len(tail), 3)
                self.assertTrue(tail[0].startswith('BEGIN'))
                self.assertTrue(tail[2].startswith('ROLLBACK'))
                with self.assertRaises(StoreUnavailable):
                    self.store.judgment_view(run_id)
                self.assertEqual(len(self.traced), before + 3)
                if body is not None:
                    self.store._db.execute(
                        'UPDATE runs SET body=? WHERE id=?', (valid, 'r'))
        self.store.judgment().judge(self.request('r', 'j',
            proposed=c.Job('r', 'j', 'x', ('c',))))
        self.assertEqual(self.views[-1][0].jobs, ())


if __name__ == '__main__':
    unittest.main()
