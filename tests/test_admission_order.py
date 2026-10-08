"""Attempt order authority: immutable original admission revision only.

Synthetic core tests: persisted JSON object key order of data['attempts'] is
sorted-key order, never admission order. These pin the sole ordering
authority — the original 'attempt:' admission write — for attempts() and for
latest-per-Job selection, including across reopen.
"""
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from co_v4 import contracts as c
from co_v4.judgment import JudgmentRequest
from co_v4.state import (IntegrityViolation, Limits, _admission_order,
                         _attempt_key, _latest_attempts)
from test_state import Harness


class AdmissionOrderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Harness(Path(self.tmp.name).resolve())
        self.addCleanup(self.h.store.close)
        self.h.job()

    def _settle(self, ref, status=c.State.FAILED):
        attempt = self.h.finish(ref, status)
        return self.h.ctrl.record_stop(
            c.StopReply(ref, c.StopStatus.CONFIRMED, 'fixture', 'cessation'),
            attempt.revision)

    def _job(self, run, name='j'):
        h = self.h
        job = c.Job(run, name, 'create output', ('inspect output',))
        d = h.judgment.judge(JudgmentRequest(
            c.QuestionRef(run, name), h.action, 'write-output',
            h.conditions, None, job))
        return h.ctrl.add_job(job, d.decision_id, h.rev(run))

    def _admit(self, ref):
        h = self.h
        request = c.ExecuteRequest(
            ref, h.ctrl.get_job(ref.run_id, ref.job_id), h.conditions)
        d = h.judgment.judge(JudgmentRequest(
            c.QuestionRef(ref.run_id, ref.job_id, ref.attempt_id), h.action,
            'write-output', h.conditions, None, None))
        return h.ctrl.begin_attempt(request, d.decision_id, h.rev(ref.run_id))

    def _never_started(self, attempt):
        request = c.ExecuteRequest(
            attempt.ref, self.h.ctrl.get_job(attempt.ref.run_id, attempt.ref.job_id),
            self.h.conditions)
        return self.h.ctrl.record_execute(
            c.OperationReply(attempt.ref, c.OperationStatus.UNAVAILABLE,
                             'preflight refusal',
                             never_started=c.NeverStarted(request, 'ev:preflight')),
            attempt.revision)

    def test_admission_order_not_json_key_or_live_revision(self):
        h = self.h
        # Authenticated grant raises only this Run's per-pair cap so three
        # same-pair Attempts are legal; product defaults stay untouched.
        h.create('o', Limits(attempts_per_pair=3, ceilings=(20, 5, 3)))
        self._job('o')
        # 'z' admitted first, 'a' second, 'm' last: sorted JSON keys invert it.
        z = self._settle(self._admit(c.AttemptRef('o', 'j', 'z')).ref)
        a = self._settle(self._admit(c.AttemptRef('o', 'j', 'a')).ref)
        m = self._never_started(self._admit(c.AttemptRef('o', 'j', 'm')))
        self.assertEqual([x.ref.attempt_id for x in h.ctrl.attempts('o')],
                         ['z', 'a', 'm'])
        # Legal mutable updates to an older Attempt bump its live revision but
        # never move it past a later admission.
        z = h.ctrl.record_ac(c.ACRecord(z.ref, 'fail', ('independent:inspection',)),
                             z.revision)
        z = h.ctrl.record_stop(c.StopReply(z.ref, c.StopStatus.CONFIRMED,
                                           'fixture', 'cessation'), z.revision)
        self.assertGreater(h.ctrl.get_attempt(z.ref).revision,
                           h.ctrl.get_attempt(a.ref).revision)
        self.assertEqual([x.ref.attempt_id for x in h.ctrl.attempts('o')],
                         ['z', 'a', 'm'])

    def test_admission_order_survives_reopen(self):
        h = self.h
        self._settle(h.begin('z').ref)
        h.begin('a')
        h.store.close()
        h.store = h.connect()
        h.refresh()
        self.assertEqual([x.ref.attempt_id for x in h.ctrl.attempts('r')],
                         ['z', 'a'])
        with h.store._tx('r') as data:
            self.assertEqual(
                _latest_attempts(data)['j'].ref.attempt_id, 'a')

    def test_stale_old_success_never_supersedes_later_attempt(self):
        h = self.h
        z = self._settle(h.begin('z').ref, c.State.COMPLETED)
        h.ctrl.record_ac(c.ACRecord(z.ref, 'pass', ('independent:inspection',)),
                         z.revision)
        self._settle(h.begin('a').ref)
        with h.store._tx('r') as data:
            latest = _latest_attempts(data)
        self.assertEqual(latest['j'].ref.attempt_id, 'a')
        self.assertEqual(latest['j'].result.status, c.State.FAILED)

    def test_malformed_originals_are_integrity_violations(self):
        h = self.h
        z = self._settle(h.begin('z').ref)
        a = h.begin('a')
        with h.store._tx('r') as data:
            key = _attempt_key(a.ref)
            wkey = 'attempt:' + _attempt_key(a.ref)
            record = data['writes'][wkey]
            request, original = record
            live, mirrored = data['attempts'][key], data['requests'][key]
            job = data['jobs']['j']
            z_revision = data['writes']['attempt:' + _attempt_key(z.ref)][1].revision
            forged_ref = c.AttemptRef('x', 'j', 'a')
            forged_job = replace(job, run_id='x')
            forged_request = replace(request, ref=forged_ref, job=forged_job)
            ghost = 'attempt:' + _attempt_key(c.AttemptRef('r', 'j', 'ghost'))

            def reset():
                data['attempts'][key] = live
                data['writes'][wkey] = record
                data['writes'].pop(ghost, None)
                data['requests'][key] = mirrored
                data['jobs']['j'] = job

            cases = (
                ('missing_record', lambda: data['writes'].pop(wkey)),
                ('malformed_record', lambda: data['writes'].__setitem__(wkey, 'junk')),
                ('extra_record', lambda: data['writes'].__setitem__(ghost, record)),
                ('missing_ref', lambda: data['writes'].__setitem__(
                    wkey, (request, replace(original, ref=None)))),
                ('ref_mismatch', lambda: data['writes'].__setitem__(
                    wkey, (request, replace(original, ref=c.AttemptRef('r', 'j', 'forged'))))),
                ('request_mismatch', lambda: data['writes'].__setitem__(
                    wkey, (replace(request, conditions=replace(
                        request.conditions, model='forged')), original))),
                ('stale_request_mirror', lambda: data['requests'].__setitem__(
                    key, replace(mirrored, conditions=replace(
                        mirrored.conditions, model='stale')))),
                ('duplicate_revision', lambda: data['writes'].__setitem__(
                    wkey, (request, replace(original, revision=z_revision)))),
                ('future_revision', lambda: data['writes'].__setitem__(
                    wkey, (request, replace(original, revision=data['run'].revision + 1)))),
                ('bool_revision', lambda: data['writes'].__setitem__(
                    wkey, (request, replace(original, revision=True)))),
                ('negative_revision', lambda: data['writes'].__setitem__(
                    wkey, (request, replace(original, revision=-1)))),
                ('zero_revision', lambda: data['writes'].__setitem__(
                    wkey, (request, replace(original, revision=0)))),
                ('job_binding', lambda: data['jobs'].__setitem__(
                    'j', replace(job, instructions='forged'))),
                ('live_ref_malformed', lambda: data['attempts'].__setitem__(
                    key, replace(live, ref='forged'))),
                ('live_type_malformed', lambda: data['attempts'].__setitem__(
                    key, 'forged')),
                ('cross_run_forge', lambda: (
                    data['attempts'].__setitem__(key, replace(live, ref=forged_ref)),
                    data['writes'].__setitem__(
                        wkey, (forged_request, replace(original, ref=forged_ref))),
                    data['requests'].__setitem__(key, forged_request),
                    data['jobs'].__setitem__('j', forged_job))),
            )
            for name, bad in cases:
                with self.subTest(case=name):
                    bad()
                    with self.assertRaises(IntegrityViolation):
                        _admission_order(data)
                    reset()
            self.assertEqual([x.ref for x in _admission_order(data)],
                             [z.ref, a.ref])
