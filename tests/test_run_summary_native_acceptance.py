"""Offline harness tests. Synthetic observations never qualify a live Native."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4.catalog import Catalog, CatalogEntry, Verification
from co_v4.judgment import TrustedEvidence
from co_v4.state import IngressReceipt, body_digest, create_run_body
from probes import run_summary_native_acceptance as probe


# Independent offline fixture, not the Native contribution and never integrated
# as that contribution. Live source must come from the bound original stream.
FIXTURE = b'''import unittest
import copy
import tempfile
from test_state import Harness
from co_v4 import contracts as c
from co_v4.summary import render_run_summary

class CessationTests(unittest.TestCase):
    def check_flag(self, flag):
        with tempfile.TemporaryDirectory() as d:
            h = Harness(d)
            try:
                h.ctrl.finalize_run('r', c.State.ERROR, 'controller_error', h.rev(), cessation=flag)
                before = copy.deepcopy(h.ctrl.get_run('r'))
                text = render_run_summary(h.ctrl, 'r')
                self.assertEqual(len(text.splitlines()), 5)
                self.assertEqual(h.ctrl.get_run('r'), before)
                self.assertEqual('cessation unconfirmed' in text, not flag)
            finally:
                h.store.close()
    def test_unconfirmed(self):
        self.check_flag(False)
    def test_confirmed(self):
        self.check_flag(True)
'''


class NativeSummaryHarnessTests(unittest.TestCase):
    def wire(self):
        return SimpleNamespace(texts={'answer': FIXTURE.decode()}, turn_submissions=1,
            turn_rpc_confirmed=True, terminal='completed', error=None,
            eof_validated=True, wait_exit=0, cleanup_terminated=False,
            started={'answer'}, finished={'answer'}, terminal_inventory={'view': 'summary'},
            _process=SimpleNamespace(poll=lambda: 0))

    def test_structural_completion_does_not_require_canned_answer(self):
        result = probe.structural_evidence(self.wire())
        self.assertTrue(result['scoped_completion_evidence_complete'])
        self.assertEqual(result['observed_sha256'], probe.sha(FIXTURE))
        self.assertFalse(result['generic_cessation_capability_granted'])

    def test_incomplete_native_execution_is_never_promoted(self):
        changes = ({'turn_submissions': 2}, {'turn_rpc_confirmed': False},
            {'terminal': None}, {'error': 'unmapped_native_notification'},
            {'eof_validated': False}, {'wait_exit': 1}, {'cleanup_terminated': True},
            {'finished': set()}, {'texts': {}}, {'texts': {'a': 'x', 'b': 'y'}},
            {'texts': {'a': 'x' * 2049}}, {'terminal_inventory': None},
            {'_process': SimpleNamespace(poll=lambda: None)})
        for change in changes:
            with self.subTest(change=change):
                wire = self.wire()
                vars(wire).update(change)
                self.assertFalse(probe.structural_evidence(wire)['scoped_completion_evidence_complete'])

    def test_python_and_import_limits(self):
        self.assertEqual(probe.validate_artifact(FIXTURE), probe.sha(FIXTURE))
        for bad in (b'', b'x' * 2049, b'import subprocess\n', b'from os import system\n', b'```python\npass\n```'):
            with self.subTest(bad=bad[:20]), self.assertRaises((ValueError, SyntaxError)):
                probe.validate_artifact(bad)

    def test_diagnostics_never_export_arbitrary_error_text(self):
        self.assertEqual(probe.failure_code(ValueError('unexpected artifact import')), 'artifact_import_unsupported')
        self.assertEqual(probe.failure_code(SyntaxError('private source')), 'artifact_python_invalid')
        self.assertEqual(probe.failure_code(ValueError('secret=DO_NOT_EXPORT')), 'unclassified_failure')

    def test_actual_code_passes_and_detects_targeted_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            artifact = Path(d) / probe.ARTIFACT
            artifact.write_bytes(FIXTURE)
            reviews = []
            def review(request, raw):
                self.assertEqual(request, 'fixture-attempt')
                self.assertEqual(raw, FIXTURE)
                reviews.append(probe.sha(raw))
                return 'fixture:reviewed-static-test-source'
            result = probe.check_artifact(artifact, d, review_artifact=review, request='fixture-attempt')
            self.assertTrue(result['passed'])
            self.assertEqual(result['normal']['tests'], 2)
            self.assertEqual(result['mutation']['failures'], 1)
            self.assertEqual(result['mutation']['errors'], 0)
            self.assertEqual(artifact.read_bytes(), FIXTURE)
            self.assertEqual(reviews, [probe.sha(FIXTURE)])

    def test_empty_tests_fail_mutation_acceptance(self):
        raw = b'import unittest\nclass T(unittest.TestCase):\n def test_a(self): pass\n def test_b(self): pass\n'
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / probe.ARTIFACT
            path.write_bytes(raw)
            result = probe.check_artifact(path, d, review_artifact=lambda *_: 'fixture:review', request=None)
            self.assertFalse(result['passed'])
            self.assertEqual(result['mutation']['failures'], 0)

    def test_review_is_required_before_any_test_execution(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / probe.ARTIFACT
            path.write_bytes(FIXTURE)
            with patch.object(probe.subprocess, 'run') as execute:
                with self.assertRaisesRegex(ValueError, 'review evidence'):
                    probe.check_artifact(path, d, review_artifact=lambda *_: None, request=None)
                execute.assert_not_called()

    def test_job_contains_real_source_no_answer_or_runtime_authority(self):
        job = probe.job_for('fixture-run')
        self.assertEqual(job.job_id, 'summary-native-contribution')
        self.assertIn('cessation=False', job.instructions)
        self.assertIn('render_run_summary', job.context_json)
        self.assertNotIn('CO03_ACCEPTANCE_OK', job.instructions + job.context_json)
        self.assertNotIn('auth.json', job.context_json)
        self.assertEqual(len(job.acceptance_criteria), 3)
        for name in probe._ALLOWED_IMPORTS:
            self.assertIn(name, job.instructions)

    def test_no_default_live_authority(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaisesRegex(ValueError, 'actual host callbacks'):
            probe.qualify(Path(d) / 'not-created', run_id='r', human_intent='fixture', human_intent_ref='fixture',
                origin_verifier=None, evidence_resolver=None, executable='/not-used', check_source=None,
                review_artifact=None, environment_ref='unverified')
        self.assertNotEqual(probe.USE.other, 'fixed-response text')

    def test_qualification_then_controller_with_synthetic_native_only(self):
        # Exercise real state/Controller/Command/artifact/AC integration. All
        # Native/authority fixtures below are test-only, never live evidence.
        class Session:
            def __init__(self, request, config, *, check_source, service_tier):
                self.request = request
                self.stopped = False
            def execute(self, request):
                return c.OperationReply(request.ref, c.OperationStatus.ACCEPTED, 'fixture receipt')
            def events(self, ref, after=None):
                return () if after else (c.ResultEvent(ref, 'fixture-result', c.Result(ref, c.State.COMPLETED)),)
            def stop(self, ref):
                self.stopped = True
                return c.StopReply(ref, c.StopStatus.CONFIRMED, 'fixture only', 'fixture:stop')
            def artifact_bytes(self): return FIXTURE
            def observation(self):
                return {'ref': self.request.ref.__dict__,
                    'environment_ref': self.request.conditions.environment_ref,
                    'host': {'native_handoff_verified': True},
                    'native': {'observed_sha256': probe.sha(FIXTURE), 'scoped_completion_evidence_complete': self.stopped}}
            def close(self): pass
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d).resolve()
            (directory / '.codex').mkdir()
            (directory / '.codex/auth.json').write_text('fixture-metadata-only')
            executable = directory / 'fake-not-executed'
            executable.write_text('fixture')
            environment, _ = probe.environment_definition(executable)
            def evidence(snapshot, request, admission):
                refs = ('fixture:policy',) + ((admission.evidence_ref,) if admission else ())
                return TrustedEvidence(body_digest(request), 'fixture:policy', refs,
                    'fixture:operation', intent_contained=True, intent_authorizes=True,
                    conditions_verified=True, protection_verified=True)
            def inputs(run_id):
                intent, origin = 'fixture scoped Goal', 'fixture-origin:' + run_id
                receipt = IngressReceipt('fixture-human', origin,
                    body_digest(create_run_body(run_id, intent)), '2026-10-03T00:00:00Z')
                return dict(run_id=run_id, human_intent=intent, human_intent_ref=origin,
                    origin_verifier=lambda ref: receipt if ref == origin else None,
                    evidence_resolver=evidence, executable=executable, check_source=lambda: None,
                    review_artifact=lambda request, raw: 'fixture:review', environment_ref=environment)
            with patch.object(probe.Path, 'home', return_value=directory), \
                 patch.object(probe, 'configured_launch_inventory', return_value=((), ())), \
                 patch.object(probe.CodexReadOnlyHost, 'verify'), \
                 patch.object(probe, 'CodeSession', Session):
                qualified = probe.qualify(directory / 'qualification', **inputs('fixture-q'))
                self.assertTrue(qualified['accepted'], qualified)
                self.assertFalse(qualified['controller_exercised'])
                self.assertEqual(qualified['job_goal_count'], 1)
                self.assertEqual(qualified['run_goal_count'], 0)
                verification = Verification(probe.MODEL, probe.ADAPTER, probe.USE, environment,
                    'fixture:official', 'fixture:implementation', 'fixture:measurement', 'fixture:AC')
                catalog = Catalog((CatalogEntry(probe.MODEL, probe.ADAPTER,
                    {probe.USE: 1}, (verification,)),))
                actual = probe.run(directory / 'controller', **inputs('fixture-c'), catalog=catalog)
                self.assertTrue(actual['accepted'], actual)
                self.assertTrue(actual['controller_exercised'])
                self.assertEqual(actual['run_goal_count'], 1)
                self.assertEqual(actual['check_verdicts'], ['pass', 'pass'])
                self.assertEqual((directory / 'controller/worker' / probe.ARTIFACT).read_bytes(), FIXTURE)


if __name__ == '__main__':
    unittest.main()
