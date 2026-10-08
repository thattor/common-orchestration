"""#190 M3 profile AC verifier: real state, real store, real registry.

ControllerState, OutputStore and ProfileRegistry are production objects;
ProfileVerifier runs inside a real Acceptance. The registry entry here is
constructed directly (wire-load validation is covered elsewhere); no
provider qualification is claimed.
"""
import hashlib
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckRequest, JobGoal
from co_v4.judgment import JudgmentRequest
from co_v4.output_store import IntegrityError, OutputStore
from co_v4.profile_acceptance import ProfileVerifier
from co_v4.profile_registry import (ACDeclaration, ProfileRegistry,
                                    RegistryEntry, canonical)
from co_v4.state import IngressReceipt, body_digest, create_run_body
from test_state import Harness
from test_output_pipeline import SYNTHETIC, drive_until, output_run

BASE = ('ac:media_types', 'ac:max_bytes', 'ac:non_whitespace',
        'ac:no_forbidden_literals')
DIG, DIG2 = 'sha256:' + 'ab' * 32, 'sha256:' + 'cd' * 32
ROUTES = (('m', 'openai.responses', 'env:x'),)
SCEN_ROUTES = (('fixture-a', SYNTHETIC, 'fixture:environment'),
               ('fixture-b', SYNTHETIC, 'fixture:environment'))


def entry(digest=DIG, criteria=BASE, routes=ROUTES, **ac):
    decl = {'media_types': ('text/plain',), 'max_bytes': 4096,
            'forbidden_literals': ('</think>', '<think>'),
            'exact_any': None}
    decl.update(ac)
    return RegistryEntry('fixture-task', digest, 'pure', True, routes,
        ((120, 30),) * len(routes), 180, 'general',
        'Produce the answer text.', tuple(criteria),
        ACDeclaration(tuple(decl['media_types']), decl['max_bytes'],
                      tuple(decl['forbidden_literals']), decl['exact_any']))


def pinned(digest=DIG, routes=ROUTES):
    return c.TaskProfile('fixture-task', digest, 'pure', True, routes)


class ProfileAcceptanceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.h = Harness(tmp.name)
        self.addCleanup(self.h.store.close)
        self.out = OutputStore(Path(tmp.name) / 'outputs')
        self.registry = ProfileRegistry({
            ('fixture-task', DIG): entry(),
            ('fixture-task', DIG2): entry(DIG2, BASE + ('ac:exact',),
                                          exact_any=('4',))}, {})
        self.state = self.h.ctrl
        self.verify = ProfileVerifier(self.registry, self.state, self.out)
        self.accept = Acceptance(self.verify)
        self.add_run('p', pinned())
        self.add_run('q', pinned(DIG2))
        self.job = self.add_job('p', 'j')
        self.jobq = self.add_job('q', 'jq', BASE + ('ac:exact',))
        self.n = 0

    def add_run(self, run_id, profile):
        self.h.authenticate('origin:' + run_id,
                            create_run_body(run_id, 'intent'))
        self.h.intake.create_run(run_id, 'intent', 'origin:' + run_id,
                                 profile=profile)

    def judge(self, run_id, job_id, attempt=None, proposed=None,
              conditions=None):
        return self.h.judgment.judge(JudgmentRequest(
            c.QuestionRef(run_id, job_id, attempt), self.h.action,
            'write-output', conditions or self.h.conditions, None,
            proposed))

    def add_job(self, run_id, name, criteria=BASE):
        job = c.Job(run_id, name, 'create output', tuple(criteria),
                    output_candidate=True)
        d = self.judge(run_id, name, proposed=job)
        return self.h.ctrl.add_job(job, d.decision_id,
                                 self.h.ctrl.get_run(run_id).revision)

    def begin(self, run_id, job_id, name, model='m'):
        request = c.ExecuteRequest(c.AttemptRef(run_id, job_id, name),
            self.h.ctrl.get_job(run_id, job_id),
            replace(self.h.conditions, model=model))
        d = self.judge(run_id, job_id, name,
                       conditions=request.conditions)
        return self.h.ctrl.begin_attempt(request, d.decision_id,
            self.h.ctrl.get_run(run_id).revision)

    def ceased(self, run_id, job_id, texts, media='text/plain', model=None):
        # Manual StopReply is unit-level contract-fixture plumbing only, as
        # in test_state; the Controller tests below use the adapter's real
        # stop path.
        self.n += 1
        attempt = self.begin(run_id, job_id, 'a%d' % self.n,
                             model or 'm%d' % self.n)
        attempt = self.h.event(c.ResultEvent(
            attempt.ref, 'result:%d' % self.n,
            c.Result(attempt.ref, c.State.COMPLETED)))
        attempt = self.h.ctrl.record_stop(c.StopReply(
            attempt.ref, c.StopStatus.CONFIRMED, 'fixture',
            'ev:%d' % self.n), attempt.revision)
        items = tuple(c.OutputItem(i, media, t)
                      for i, t in enumerate(texts))
        out = self.out.put(attempt.ref, items)
        return self.h.ctrl.record_attempt_output(
            attempt.ref, out, attempt.revision)

    def request(self, run_id='p', job_id='j', **kw):
        run = self.state.get_run(run_id)
        return CheckRequest('job', run, self.h.ctrl.get_job(run_id, job_id),
                            kw.pop('result'), **kw)

    def evaluate(self, texts, media='text/plain', run_id='p', job_id='j'):
        attempt = self.ceased(run_id, job_id, texts, media)
        return self.verify(self.request(
            run_id, job_id, result=attempt.result,
            output=c.OutputRef(attempt.ref, attempt.output.digest))), attempt

    def test_each_predicate_fails_only_named(self):
        cases = [('ok text', 'text/plain', None),          # clean co-text
                 ('ok', 'text/markdown', 'ac:media_types'),
                 ('é' * 2049, 'text/plain', 'ac:max_bytes'),
                 (' \t\n', 'text/plain', 'ac:non_whitespace'),
                 ('a <think> b', 'text/plain',
                  'ac:no_forbidden_literals')]
        for text, media, failed in cases:
            with self.subTest(failed=failed):
                evidence, _ = self.evaluate((text,), media)
                expected = ['fail' if p == failed else 'pass'
                            for p in BASE]
                self.assertEqual([f.verdict for f in evidence.criteria],
                                 expected)
                self.assertEqual(evidence.goal.verdict,
                                 'fail' if failed else 'pass')

    def test_exact_full_text_no_normalization(self):
        for text, ok in (('4', True), ('4\n', False), (' 4', False),
                         ('four', False)):
            with self.subTest(text=repr(text)):
                evidence, _ = self.evaluate((text,), run_id='q',
                                            job_id='jq')
                self.assertEqual([f.verdict for f in evidence.criteria],
                                 ['pass'] * 4 + ['pass' if ok else 'fail'])
        evidence, _ = self.evaluate(('4', '4'), run_id='q', job_id='jq')
        self.assertEqual(evidence.criteria[-1].verdict, 'fail')  # two items
        self.assertEqual(evidence.goal.verdict, 'fail')

    def test_binding_mismatches_fail_never_pass(self):
        baseline, attempt = self.evaluate(('ok',))
        self.assertEqual(baseline.goal.verdict, 'pass')
        run = self.state.get_run('p')
        out = c.OutputRef(attempt.ref, attempt.output.digest)
        good = self.request(result=attempt.result, output=out)
        negatives = (
            replace(good, output=c.OutputRef(                 # wrong digest
                attempt.ref, 'sha256:' + '9' * 64)),
            replace(good, result=c.Result(attempt.ref,        # tampered result
                c.State.COMPLETED, detail='x')),
            replace(good, result=c.Result(attempt.ref,        # forged failure
                c.State.FAILED, 'forged')),
            replace(good, job=c.Job('p', 'j', 'altered', BASE)),
            replace(good, output=None),                       # missing output
        )
        for request in negatives:
            self.assertEqual(self.verify(request).goal.verdict, 'fail')
        self.assertEqual(self.verify(good).goal.verdict, 'pass')
        forged = c.Job('p', 'j', 'i', ('ac:media_types', 'ac:max_bytes',
                       'ac:non_whitespace', 'bogus'))
        self.assertEqual(self.verify(CheckRequest(              # unknown AC
            'job', run, forged, attempt.result,
            output=out)).criteria[-1].verdict, 'fail')
        with self.assertRaises(ValueError):                     # schema pin
            CheckRequest('job', run, self.h.ctrl.get_job('p', 'j'),
                         attempt.result, schema='bogus', output=out)
        self.add_run('b', pinned(routes=(('m', 'openai.responses',
                                         'env:other'),)))       # pinned fields
        self.add_job('b', 'jb')
        wrong = self.ceased('b', 'jb', ('ok',))
        self.assertEqual(self.verify(self.request(
            'b', 'jb', result=wrong.result,
            output=c.OutputRef(wrong.ref, wrong.output.digest))
            ).goal.verdict, 'fail')
        self.h.authenticate('stop:p', {'operation': 'stop_run',
                                       'run_id': 'p'})
        self.h.intake.record_stop_request('p', 'stop:p')
        self.assertEqual(self.verify(self.request(
            result=attempt.result, output=out)).goal.verdict, 'fail')

    def test_rehash_integrity_propagates_never_verdict(self):
        _, attempt = self.evaluate(('ok',))
        (self.out.root / 'blobs'
         / attempt.output.items[0].blob_digest[7:]).write_bytes(b'tampered')
        with self.assertRaises(IntegrityError):
            self.verify(self.request(
                result=attempt.result,
                output=c.OutputRef(attempt.ref, attempt.output.digest)))
        _, attempt2 = self.evaluate(('ok2',))
        (self.out.root / 'manifests'
         / attempt2.output.digest[7:]).write_bytes(b'[]')
        with self.assertRaises(IntegrityError):
            self.verify(self.request(
                result=attempt2.result,
                output=c.OutputRef(attempt2.ref, attempt2.output.digest)))

    def test_evidence_refs_deterministic_hex_no_text(self):
        evidence, attempt = self.evaluate(('ok',))
        request = self.request(
            result=attempt.result,
            output=c.OutputRef(attempt.ref, attempt.output.digest))
        for predicate, finding in zip(BASE, evidence.criteria):
            expected = 'ac:sha256:' + hashlib.sha256(canonical({
                'request_digest': body_digest(request),
                'output_digest': attempt.output.digest,
                'predicate_id': predicate,
                'passed': True})).hexdigest()
            self.assertEqual(finding.evidence_refs, (expected,))
        self.assertEqual(self.verify(request), evidence)   # stable rerun
        self.assertEqual(evidence.request_digest, body_digest(request))

    def test_run_goal_malformed_request_fails_closed(self):
        attempt = self.ceased('p', 'j', ('ok',))
        run = self.state.get_run('p')
        goal = self.accept.job(run, self.h.ctrl.get_job('p', 'j'),
            attempt.result,
            output=c.OutputRef(attempt.ref, attempt.output.digest))
        self.h.ctrl.record_ac(goal.ac, attempt.revision)
        self.h.ctrl.record_job_goal(goal,
                                    self.h.ctrl.get_run('p').revision)
        run = self.state.get_run('p')
        self.assertEqual(self.verify(CheckRequest(
            'run', run, jobs=(goal,))).goal.verdict, 'pass')
        # run=None / non-tuple jobs / malformed JobGoal fields fail
        # closed as verdicts; no AttributeError may escape.
        for request in (CheckRequest('run', None, jobs=(goal,)),
                        CheckRequest('run', run, jobs=[goal]),
                        CheckRequest('run', run, jobs=('x',)),
                        CheckRequest('run', run,
                                     jobs=(JobGoal('a', 'b', 'c', 'd'),))):
            self.assertEqual(self.verify(request).goal.verdict, 'fail')
        # Mutable snapshot copies diverge job_ids/derived_interpretation
        # from the goal set — no DB tampering needed.
        diverged = replace(run, job_ids=tuple(run.job_ids) + ('ghost',))
        self.assertEqual(self.verify(CheckRequest(
            'run', diverged, jobs=(goal,))).goal.verdict, 'fail')
        dropped = replace(run, derived_interpretation=())
        self.assertEqual(self.verify(CheckRequest(
            'run', dropped, jobs=(goal,))).goal.verdict, 'fail')

    def test_run_goal_real_bindings_and_latest_attempt(self):
        attempt = self.ceased('p', 'j', ('ok',))
        run = self.state.get_run('p')
        goal = self.accept.job(run, self.h.ctrl.get_job('p', 'j'),
            attempt.result,
            output=c.OutputRef(attempt.ref, attempt.output.digest))
        self.assertTrue(goal.completed)
        self.h.ctrl.record_ac(goal.ac, attempt.revision)
        # record_ac bumps the Run revision; re-read before the goal write.
        self.h.ctrl.record_job_goal(goal,
                                    self.h.ctrl.get_run('p').revision)
        attempt = self.state.get_attempt(attempt.ref)
        self.assertEqual(attempt.ac.output_digest, attempt.output.digest)
        run = self.state.get_run('p')
        self.assertEqual(self.accept.run(run, (goal,)).finding.verdict,
                         'pass')
        self.assertEqual(self.accept.run(run, ()).finding.verdict,
                         'incomplete')
        # A passed JobGoal for a superseded Attempt can never pass.
        self.begin('p', 'j', 'pending', model='m-new')
        run = self.state.get_run('p')
        self.assertEqual(self.accept.run(run, (goal,)).finding.verdict,
                         'fail')
        for forged in (JobGoal(replace(goal.job, instructions='x'),
                               goal.result, goal.ac, goal.goal),
                       JobGoal(goal.job, goal.result,
                               replace(goal.ac,
                                       output_digest='sha256:' + '1' * 64),
                               goal.goal),
                       JobGoal(goal.job,
                               replace(goal.result, ref=c.AttemptRef(
                                   'p', 'j', 'ghost')),
                               goal.ac, goal.goal)):
            self.assertEqual(self.verify(CheckRequest(
                'run', run, jobs=(forged,))).goal.verdict, 'fail')
        self.h.authenticate('stop:p', {'operation': 'stop_run',
                                       'run_id': 'p'})
        self.h.intake.record_stop_request('p', 'stop:p')
        stopped = self.state.get_run('p')
        self.assertEqual(self.verify(CheckRequest(
            'run', stopped, jobs=(goal,))).goal.verdict, 'fail')
        self.assertEqual(self.accept.run(stopped, (goal,)).finding.verdict,
                         'incomplete')


class ControllerIntegrityTests(unittest.TestCase):
    """Real Controller drive: verifier IntegrityError ends the Run."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def scenario(self, name):
        profile = c.TaskProfile('fixture-task', DIG, 'pure', True,
                                SCEN_ROUTES)
        s = output_run(self.dir / name, profile=profile,
                       scripts={'squares': ['good']})
        # Single-Job fixture: wrap the Scenario planner before the first
        # step so only 'squares' exists, carrying the pinned BASE criteria
        # and the output-candidate flag — never an arbitrary criterion.
        original = s.plan
        def plan(run, completed, goal):
            if completed:
                return None
            planned = original(run, completed, goal)
            return replace(planned, job=replace(
                planned.job, acceptance_criteria=BASE,
                output_candidate=True))
        s.plan = plan
        s.verify = ProfileVerifier(
            ProfileRegistry({('fixture-task', DIG): entry(
                routes=SCEN_ROUTES)}, {}), s.state, s.output_store)
        s.controller = s.build()
        return s

    def test_clean_output_passes_and_selection_binds_digest(self):
        s = self.scenario('clean')
        try:
            final = s.drive()
            self.assertEqual(final.state, c.State.COMPLETED)
            run = s.state.get_run('run')
            attempt = s.state.get_attempt(
                run.output_selection.attempt_ref)
            self.assertEqual(run.output_selection.output_digest,
                             attempt.output.digest)
            self.assertEqual(attempt.ac.output_digest,
                             attempt.output.digest)
        finally:
            s.close()

    def test_corrupted_blob_is_output_integrity_failure(self):
        s = self.scenario('corrupt')
        try:
            # Corrupt after the persisted-output boundary, before the AC
            # phase reads it; the verifier's mandatory rehash must raise.
            drive_until(s, 'output_persisted')
            attempt = s.state.get_attempt(s.controller._active)
            (s.output_store.root / 'blobs'
             / attempt.output.items[0].blob_digest[7:]
             ).write_bytes(b'tampered bytes')
            final = s.drive()
            self.assertEqual((final.state, final.reason),
                             (c.State.FAILED, 'output_integrity_failure'))
            self.assertIsNone(
                s.state.get_run('run').output_selection)
        finally:
            s.close()


if __name__ == '__main__':
    unittest.main()
