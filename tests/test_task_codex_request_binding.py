"""Focused stdlib unittest for codex_route._validate_request_binding.

Uses the real co_v4 contracts and the real pure validators. All paths and
digests are synthetic strings that need not exist; no fixture, ledger, HOME,
Native call, or qualification claim is involved. Purity is observed after
real module imports only.
"""
import contextlib
import types
import unittest
from pathlib import Path
from unittest import mock

from co_v4 import contracts as c
from co_v4.task import codex_route
from co_v4.task.common import TaskError


MODEL = 'gpt-5.2-codex'
OTHER_MODEL = 'gpt-5.1'
CWD = '/nonexistent/co04-binding-cwd-9f3d2a1b'
OTHER_CWD = '/nonexistent/co04-binding-other-5e7b'
DIGEST = 'sha256:' + 'a' * 64
OTHER_DIGEST = 'sha256:' + 'b' * 64
ADAPTER = 'codex.app-server'
ENV_REF = 'native:' + DIGEST
HUMAN_REF = 'human-intent-ref-7'
EVIDENCE = ('control-evidence-1', 'freeform ref without any prefix')


class RefSub(c.AttemptRef):
    pass


class JobSub(c.Job):
    pass


class ConditionsSub(c.ExecutionConditions):
    pass


class RequestSub(c.ExecuteRequest):
    pass


class StrSub(str):
    pass


class TupleSub(tuple):
    pass


def make_request():
    ref = c.AttemptRef(run_id='run-1', job_id='job-1', attempt_id='att-1')
    job = c.Job(run_id='run-1', job_id='job-1', instructions='do the thing',
                acceptance_criteria=('it is done',))
    conditions = c.ExecutionConditions(
        model=MODEL, adapter=ADAPTER, workspace=CWD,
        environment_ref=ENV_REF, control_evidence_refs=EVIDENCE)
    return c.ExecuteRequest(ref=ref, job=job, conditions=conditions)


def call(request=None, human_intent_ref=HUMAN_REF, **expected):
    if request is None:
        request = make_request()
    expected.setdefault('model', MODEL)
    expected.setdefault('cwd', CWD)
    expected.setdefault('measurement_digest', DIGEST)
    return codex_route._validate_request_binding(
        request, human_intent_ref, **expected)


class ValidateRequestBindingTests(unittest.TestCase):

    def assert_refused(self, thunk):
        try:
            thunk()
        except TaskError as exc:
            self.assertIs(type(exc), TaskError)
            self.assertEqual(exc.code, 'route_unmeasured')
            self.assertEqual(exc.detail, '')
            self.assertEqual(str(exc), 'route_unmeasured')
            self.assertIsNone(exc.__cause__)
            self.assertTrue(exc.__suppress_context__)
        else:
            self.fail('expected fixed TaskError route_unmeasured')

    def test_valid_binding_returns_none_and_preserves_request(self):
        request = make_request()
        ref, job, conditions = request.ref, request.job, request.conditions
        self.assertIsNone(call(request, '  ' + HUMAN_REF + '  '))
        self.assertIs(request.ref, ref)
        self.assertIs(request.job, job)
        self.assertIs(request.conditions, conditions)
        self.assertEqual((ref.run_id, ref.job_id, ref.attempt_id),
                         ('run-1', 'job-1', 'att-1'))
        self.assertEqual((job.run_id, job.job_id), ('run-1', 'job-1'))
        self.assertEqual(job.instructions, 'do the thing')
        self.assertEqual(job.acceptance_criteria, ('it is done',))
        self.assertEqual(job.context_json, '{}')
        self.assertIs(job.output_candidate, False)
        self.assertEqual(conditions.model, MODEL)
        self.assertEqual(conditions.adapter, ADAPTER)
        self.assertEqual(conditions.workspace, CWD)
        self.assertEqual(conditions.environment_ref, ENV_REF)
        self.assertIs(conditions.control_evidence_refs, EVIDENCE)

    def test_valid_binding_is_pure(self):
        request = make_request()
        boom = mock.MagicMock(
            side_effect=AssertionError('forbidden impure call'))
        helpers = ('_canonical_path', '_require_private_dir', '_expected_home',
                   '_hash_path', '_read_path', '_read_private_config',
                   '_capture_sources', '_capture_credentials',
                   '_validate_protected_state', '_lstat', '_consume_fd',
                   '_open_readonly', '_close_quietly',
                   '_current_auth_identity', 'read_config', 'validate_entry',
                   'capture_binding', 'measurement_digest')
        targets = ('os.stat', 'os.lstat', 'os.open', 'os.read',
                   'os.path.realpath', 'os.getcwd', 'os.getuid',
                   'os.geteuid', 'pwd.getpwuid', 'builtins.open',
                   'socket.socket', 'subprocess.Popen', 'hashlib.sha256')
        with contextlib.ExitStack() as stack:
            for name in helpers:
                stack.enter_context(mock.patch.object(codex_route, name, boom))
            for target in targets:
                stack.enter_context(mock.patch(target, boom))
            self.assertIsNone(call(request))
        boom.assert_not_called()

    def test_rejects_wrong_request_types(self):
        good = make_request()
        cases = [
            {}, object(), 'request', good.ref,
            types.SimpleNamespace(ref=good.ref, job=good.job,
                                  conditions=good.conditions),
            RequestSub(ref=good.ref, job=good.job,
                       conditions=good.conditions),
        ]
        for bad in cases:
            self.assert_refused(lambda b=bad: call(b))

    def test_rejects_subclassed_members(self):
        good = make_request()
        cases = [
            c.ExecuteRequest(
                ref=RefSub('run-1', 'job-1', 'att-1'),
                job=good.job, conditions=good.conditions),
            c.ExecuteRequest(
                ref=good.ref,
                job=JobSub('run-1', 'job-1', 'do the thing',
                           ('it is done',)),
                conditions=good.conditions),
            c.ExecuteRequest(
                ref=good.ref, job=good.job,
                conditions=ConditionsSub(MODEL, ADAPTER, CWD, ENV_REF,
                                         EVIDENCE)),
        ]
        for bad in cases:
            self.assert_refused(lambda b=bad: call(b))

    def test_rejects_invalid_or_mismatched_ids(self):
        corruptions = [
            ('ref', 'run_id', ''), ('ref', 'job_id', ''),
            ('ref', 'attempt_id', ''), ('job', 'run_id', ''),
            ('job', 'job_id', ''), ('ref', 'run_id', 1),
            ('ref', 'attempt_id', None), ('job', 'job_id', b'job-1'),
            ('ref', 'run_id', 'other-run'),
            ('job', 'job_id', 'other-job'),
        ]
        for attr, field, value in corruptions:
            request = make_request()
            object.__setattr__(getattr(request, attr), field, value)
            self.assert_refused(lambda r=request: call(r))
            self.assertIsNone(call(make_request()))

    def test_rejects_bad_human_intent_ref(self):
        for bad in ('', '   ', '\t\n', None, 0, StrSub('ok'), b'ok'):
            self.assert_refused(lambda b=bad: call(make_request(), b))

    def test_rejects_bad_evidence_refs(self):
        for bad in ((), [], ['ok'], TupleSub(('ok',)), ('',), (None,),
                    ('ok', ''), ('ok', 1)):
            request = make_request()
            object.__setattr__(request.conditions,
                               'control_evidence_refs', bad)
            self.assert_refused(lambda r=request: call(r))

    def test_rejects_bad_expected_scalars(self):
        cases = [
            {'model': True}, {'model': 7}, {'model': Path('/x')},
            {'model': StrSub(MODEL)}, {'model': 'auto'},
            {'model': 'default'}, {'model': 'gpt-'}, {'model': 'GPT-5'},
            {'model': 'gpt-5/x'}, {'model': 'gpt-5 x'},
            {'model': OTHER_MODEL},
            {'cwd': Path(CWD)}, {'cwd': StrSub(CWD)}, {'cwd': ''},
            {'cwd': 'relative/dir'}, {'cwd': '//double'},
            {'cwd': '/a/../b'}, {'cwd': '/a/./b'}, {'cwd': '/a//b'},
            {'cwd': '/' + 'x' * 4096}, {'cwd': OTHER_CWD},
            {'measurement_digest': 'sha256:' + 'A' * 64},
            {'measurement_digest': 'sha256:' + 'a' * 63},
            {'measurement_digest': 'a' * 64},
            {'measurement_digest': 'sha512:' + 'a' * 64},
            {'measurement_digest': StrSub(DIGEST)},
            {'measurement_digest': codex_route.measurement_digest},
            {'measurement_digest': OTHER_DIGEST},
        ]
        for kwargs in cases:
            self.assert_refused(lambda k=kwargs: call(**k))

    def test_rejects_mismatched_conditions(self):
        corruptions = [
            ('model', OTHER_MODEL), ('model', True),
            ('adapter', 'other.adapter'), ('adapter', StrSub(ADAPTER)),
            ('workspace', OTHER_CWD), ('workspace', StrSub(CWD)),
            ('environment_ref', 'native:' + OTHER_DIGEST),
            ('environment_ref', DIGEST),
            ('environment_ref', 'native:' + DIGEST + 'x'),
            ('environment_ref', None),
        ]
        for field, value in corruptions:
            request = make_request()
            object.__setattr__(request.conditions, field, value)
            self.assert_refused(lambda r=request: call(r))

    def test_helper_fault_becomes_fixed_refusal(self):
        request = make_request()
        with mock.patch.object(codex_route, '_validate_model',
                               side_effect=RuntimeError('inner boom')):
            self.assert_refused(lambda: call(request))
        self.assertEqual(request.conditions.model, MODEL)
        self.assertIsNone(call(request))

    def test_interrupts_propagate_same_instance(self):
        for exc in (KeyboardInterrupt(), SystemExit(3)):
            request = make_request()
            with mock.patch.object(codex_route, '_lexical_path',
                                   side_effect=exc):
                try:
                    call(request)
                except BaseException as caught:
                    self.assertIs(caught, exc)
                else:
                    self.fail('interrupt was swallowed')
            self.assertEqual(request.conditions.model, MODEL)
            self.assertIsNone(call(request))


if __name__ == '__main__':
    unittest.main()
