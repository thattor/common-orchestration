"""M3 projection integrity: tampered committed aggregates must fail closed.

Synthetic only. A fixture Scenario is driven through the real Controller,
OutputStore, AC and selection code to a completed Run; a host-only
gateway_responses row is attached as fixture metadata; then the committed
aggregate is corrupted through the private ControlStore._tx handle. Each
tamper below is labelled and produces a combination no production write can
commit. Expected behavior: a new projection derives failed/integrity_violation
(output_unavailable only when no selection exists), a corrupt original
admission propagates IntegrityViolation, and an already-persisted decisive
row raises IntegrityViolation on read/cancel/project without being rewritten
and without output. No Native calls, no provider evidence, no qualification.
"""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.ac import Finding, JobGoal
from co_v4.controller import ControllerCheckpoint
from co_v4.gateway_store import (Gateway, PROJECTION_CODES, cancel_body,
                                 lookup_body)
from co_v4.state import (IngressReceipt, IntegrityViolation, NotFound,
                         _attempt_key, body_digest)
from test_output_pipeline import authenticate_stop, output_run


OTHER = 'sha256:' + '9' * 64


def _bind(s, source, body, principal='p1'):
    """Attach an authenticated principal receipt to the fixture journal."""
    s.journal.bind(source, body, IngressReceipt(
        principal, source, body_digest(body), s.now))
    return source


def _attach(s, response_id='resp_t', principal='p1'):
    """Host-only fixture metadata mapping the Run to an opaque response ID."""
    s.store._db.execute('INSERT INTO gateway_responses VALUES (?,?,?,?,?,?)',
                        (response_id, principal, 'run', 'd', 'co-auto', s.now))
    return Gateway(s.store)


def _row(s, response_id='resp_t'):
    return s.store._db.execute(
        'SELECT status, code, run_revision, at FROM gateway_projections'
        ' WHERE response_id=?', (response_id,)).fetchone()


def _tamper(s, fn):
    """FIXTURE CORRUPTION of committed state; no product path writes this."""
    with s.store._tx('run') as data:
        fn(data)


def _run(data, **changes):
    data['run'] = replace(data['run'], **changes)


def _selected(s):
    sel = s.state.get_run('run').output_selection
    return sel, s.state.get_attempt(sel.attempt_ref)


class SelectionIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def completed(self, name, **kwargs):
        kwargs.setdefault('scripts', {'squares': ['good']})
        s = output_run(self.dir / name, **kwargs)
        self.addCleanup(s.close)
        self.assertEqual(s.drive().state, c.State.COMPLETED)
        self.assertIsNotNone(s.state.get_run('run').output_selection)
        return s, _attach(s)

    def assert_new_projection(self, s, gateway, code):
        """A new projection on tampered committed state persists a decisive
        failed row; reads stay non-decisive until the driver wrote it."""
        view = gateway.read('resp_t', _bind(s, 'r:a', lookup_body('resp_t')))
        self.assertEqual((view.status, view.decided, view.output),
                         ('in_progress', False, None))
        self.assertFalse(hasattr(view, 'run_id'))  # internal ID never exposed
        projection = gateway.project('run')
        self.assertIn(projection.code, PROJECTION_CODES)
        self.assertEqual((projection.status, projection.code,
                          projection.decided, projection.output),
                         ('failed', code, True, None))
        row = _row(s)
        again = gateway.read('resp_t', _bind(s, 'r:b', lookup_body('resp_t')))
        self.assertEqual((again.status, again.code, again.decided),
                         ('failed', code, True))
        self.assertEqual(_row(s), row)           # write-once, no rewrite
        with self.assertRaises(NotFound):        # foreign principal is 404
            gateway.read('resp_t', _bind(s, 'r:f', lookup_body('resp_t'),
                                         principal='p2'))

    def test_wrong_selection_identity_rejected(self):
        forges = (
            ('run_id', lambda sel: c.RunOutputSelection(
                'other', sel.job_id, c.AttemptRef('other', sel.job_id, 'x'),
                sel.output_digest, sel.selected_at)),
            ('job_id', lambda sel: c.RunOutputSelection(
                'run', 'otherjob', c.AttemptRef('run', 'otherjob', 'x'),
                sel.output_digest, sel.selected_at)),
            ('attempt_ref', lambda sel: replace(
                sel, attempt_ref=c.AttemptRef('run', sel.job_id, 'forged'))),
            ('digest', lambda sel: replace(sel, output_digest=OTHER)),
        )
        for name, forge in forges:
            with self.subTest(field=name):
                s, gateway = self.completed('identity-' + name)
                sel, _ = _selected(s)
                _tamper(s, lambda data: _run(
                    data, output_selection=forge(sel)))
                self.assert_new_projection(s, gateway, 'integrity_violation')

    def test_superseded_attempt_selection_rejected(self):
        s, gateway = self.completed('superseded',
                                    scripts={'squares': ['wrong', 'good']})
        sel, _ = _selected(s)
        first = next(a for a in s.state.attempts('run')
                     if a.ref.job_id == 'squares' and a.ref != sel.attempt_ref)
        _tamper(s, lambda data: _run(data, output_selection=replace(
            sel, attempt_ref=first.ref, output_digest=first.output.digest)))
        self.assert_new_projection(s, gateway, 'integrity_violation')

    def test_nonlatest_goal_cannot_complete_selection(self):
        s, gateway = self.completed('nonlatest',
                                    scripts={'squares': ['wrong', 'good']})
        sel, _ = _selected(s)
        first = next(a for a in s.state.attempts('run')
                     if a.ref.job_id == 'squares' and a.ref != sel.attempt_ref)

        def forge(data):
            stale = JobGoal(data['jobs']['squares'], first.result,
                            replace(first.ac, verdict='pass'),
                            Finding('pass', ('evidence:stale',)))
            data['job_goals'] = [stale if g.job.job_id == 'squares'
                                 and g.completed else g
                                 for g in data.get('job_goals', [])]
        _tamper(s, forge)
        self.assert_new_projection(s, gateway, 'integrity_violation')

    def test_ac_digest_and_empty_items_rejected(self):
        for name in ('ac_digest', 'empty_items'):
            with self.subTest(case=name):
                s, gateway = self.completed(name)
                sel, attempt = _selected(s)

                def forge(data):
                    key = _attempt_key(attempt.ref)
                    current = data['attempts'][key]
                    if name == 'ac_digest':
                        data['attempts'][key] = replace(
                            current, ac=replace(current.ac,
                                                output_digest=OTHER))
                    else:
                        data['attempts'][key] = replace(
                            current, output=replace(
                                current.output, items=(), total_bytes=0))
                _tamper(s, forge)
                self.assert_new_projection(s, gateway, 'integrity_violation')

    def test_second_accepted_candidate_rejected(self):
        # Two genuinely accepted candidates through the real drive: the
        # Controller already fails closed without a selection. Fixture-only
        # tamper then presents a completed Run plus a well-formed selection —
        # committed metadata only, no Job/admission/attempt/goal mutation.
        s = output_run(self.dir / 'twice',
                       candidate_jobs=('squares', 'total'))
        self.addCleanup(s.close)
        final = s.drive()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'output_unavailable'))
        gateway = _attach(s)
        squares = next(a for a in s.state.attempts('run')
                       if a.ref.job_id == 'squares')
        total = next(a for a in s.state.attempts('run')
                     if a.ref.job_id == 'total')
        for attempt in (squares, total):
            self.assertEqual(attempt.result.status, c.State.COMPLETED)
            self.assertEqual(attempt.stop_reply.status, c.StopStatus.CONFIRMED)
            self.assertIsNotNone(attempt.output)
            self.assertEqual(attempt.ac.output_digest, attempt.output.digest)

        def forge(data):
            sel = c.RunOutputSelection('run', 'squares', squares.ref,
                                       squares.output.digest, s.now)
            _run(data, state=c.State.COMPLETED,
                 final_reason='human_goal_verified',
                 cessation_confirmed=True, output_selection=sel)
        _tamper(s, forge)
        self.assert_new_projection(s, gateway, 'integrity_violation')

    def test_missing_bound_job_goal_rejected(self):
        s, gateway = self.completed('nogoal')
        _tamper(s, lambda data: data.__setitem__('job_goals', [
            g for g in data.get('job_goals', [])
            if g.job.job_id != 'squares']))
        self.assert_new_projection(s, gateway, 'integrity_violation')

    def test_run_goal_verdict_and_revision_rejected(self):
        def nonpass(data):
            goals = list(data.get('run_goals', []))
            goals[-1] = replace(goals[-1], finding=Finding('incomplete'))
            data['run_goals'] = goals

        def future(data):
            goals = list(data.get('run_goals', []))
            goals[-1] = replace(goals[-1], revision=data['run'].revision)
            data['run_goals'] = goals

        for name, forge in (('nonpass', nonpass), ('future', future)):
            with self.subTest(case=name):
                s, gateway = self.completed('goal-' + name)
                _tamper(s, forge)
                self.assert_new_projection(s, gateway, 'integrity_violation')

    def test_completed_with_committed_stop_is_integrity_violation(self):
        s, gateway = self.completed('stopcombo')
        _tamper(s, lambda data: _run(data, stop_requested=True))
        self.assert_new_projection(s, gateway, 'integrity_violation')

    def test_completed_without_selection_is_output_unavailable(self):
        s, gateway = self.completed('nosel')
        _tamper(s, lambda data: _run(data, output_selection=None))
        self.assert_new_projection(s, gateway, 'output_unavailable')

    def test_corrupt_original_admission_raises_integrity_violation(self):
        def drop(data, key):
            del data['writes']['attempt:' + key]

        def zero(data, key):
            request, original = data['writes']['attempt:' + key]
            data['writes']['attempt:' + key] = (
                request, replace(original, revision=0))

        for name, forge in (('missing', drop), ('revision', zero)):
            with self.subTest(case=name):
                s, gateway = self.completed('adm-' + name)
                sel, attempt = _selected(s)
                key = _attempt_key(attempt.ref)
                _tamper(s, lambda data: forge(data, key))
                for surface, call in (
                        ('project', lambda: gateway.project('run')),
                        ('read', lambda: gateway.read(
                            'resp_t', _bind(s, 'r:c', lookup_body('resp_t')))),
                        ('cancel', lambda: gateway.cancel(
                            'resp_t', _bind(s, 'c:c',
                                            cancel_body('resp_t'))))):
                    with self.subTest(surface=surface):
                        with self.assertRaises(IntegrityViolation):
                            call()
                self.assertIsNone(_row(s))       # nothing persisted

    def test_persisted_completed_row_raises_after_corruption(self):
        for name in ('stop', 'digest', 'admission', 'cancel_row'):
            with self.subTest(case=name):
                s, gateway = self.completed('row-' + name)
                good = gateway.project('run')
                self.assertEqual((good.status, good.decided),
                                 ('completed', True))
                sel, attempt = _selected(s)
                if name == 'stop':
                    _tamper(s, lambda data: _run(data, stop_requested=True))
                elif name == 'digest':
                    _tamper(s, lambda data: _run(
                        data, output_selection=replace(sel,
                                                       output_digest=OTHER)))
                elif name == 'admission':
                    key = _attempt_key(attempt.ref)
                    _tamper(s, lambda data: data['writes'].__delitem__(
                        'attempt:' + key))
                else:
                    # FIXTURE row tamper: 'cancelled' with no committed stop.
                    s.store._db.execute(
                        'UPDATE gateway_projections SET status=?'
                        ' WHERE response_id=?', ('cancelled', 'resp_t'))
                row = _row(s)
                read_ref = _bind(s, 'r:p', lookup_body('resp_t'))
                cancel_ref = _bind(s, 'c:p', cancel_body('resp_t'))
                for surface, call in (
                        ('read', lambda: gateway.read('resp_t', read_ref)),
                        ('cancel', lambda: gateway.cancel('resp_t',
                                                          cancel_ref)),
                        ('project', lambda: gateway.project('run'))):
                    with self.subTest(surface=surface):
                        with self.assertRaises(IntegrityViolation):
                            call()
                self.assertEqual(_row(s), row)   # never rewritten

    def test_persisted_cancelled_row_is_monotonic(self):
        s = output_run(self.dir / 'cancelled')
        self.addCleanup(s.close)
        s.drive(lambda p: p.reason == 'execute_receipt')
        authenticate_stop(s, 'stop:x')
        s.store.intake().record_stop_request('run', 'stop:x')
        final = s.drive()
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'human_stop'))
        gateway = _attach(s)
        first = gateway.project('run')
        self.assertEqual((first.status, first.decided), ('cancelled', True))
        row = _row(s)
        # A later committed fatal latch and aggregate contradiction cannot
        # rewrite the decisive cancelled row.
        s.state.save_checkpoint('run', ControllerCheckpoint(
            None, None, None, (), (), (), None, 'integrity_violation',
            (), 0, None), s.state.get_run('run').revision)
        attempt = s.state.attempts('run')[0]
        key = _attempt_key(attempt.ref)
        _tamper(s, lambda data: data['writes'].__delitem__('attempt:' + key))
        again = gateway.project('run')
        self.assertEqual((again.status, again.decided, again.output),
                         ('cancelled', True, None))
        read = gateway.read('resp_t', _bind(s, 'r:c', lookup_body('resp_t')))
        self.assertEqual((read.status, read.output), ('cancelled', None))
        self.assertEqual(_row(s), row)

    def test_committed_run_goal_digest_is_authority_not_recomputed(self):
        # The stored RunGoal request_digest is not recomputed at projection:
        # its binding was enforced by record_run_goal at commit time.
        # Tampering the stored digest alone must not alter a valid selection.
        s, gateway = self.completed('digest-authority')

        def forge(data):
            goals = list(data.get('run_goals', []))
            goals[-1] = replace(goals[-1], request_digest='0' * 64)
            data['run_goals'] = goals
        _tamper(s, forge)
        projection = gateway.project('run')
        self.assertEqual((projection.status, projection.decided),
                         ('completed', True))


if __name__ == '__main__':
    unittest.main()
