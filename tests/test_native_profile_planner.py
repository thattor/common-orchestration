import tempfile
import unittest
from pathlib import Path

from co_v4 import contracts as c
from co_v4.controller import JobPlan
from co_v4.openai_transport import Deadlines
from co_v4.profile_planner import ProfilePlanner
from co_v4.profile_registry import (
    ACDeclaration, NativeRouteConfig, ProfileRegistry, RegistryEntry,
    RouteConfig, canonical, environment_ref)
from co_v4.protocol_profile import RouteProtocolProfile
from co_v4.responses_input import parse
from co_v4.state import IntegrityViolation, RunSnapshot

REV = 'sha256:' + '12' * 32
DIGEST = 'sha256:' + 'ab' * 32
NMODEL, NADAPTER, NENV = 'm', 'codex.app-server', 'native:' + DIGEST
WMODEL, WADAPTER = 'w', 'openai.responses'
ENDPOINT, AUTH_REF = 'https://provider.test/v1', 'cred-main'
WORKSPACE = 'co:text-profile'
INTENT = parse(canonical({'input': 'hi', 'instructions': 'pin',
                         'model': NMODEL})).canonical_body.decode('utf-8')
CONTEXT = canonical({'input': 'hi', 'instructions': 'pin'}).decode('utf-8')


class NativeProfilePlanner(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        self.state, self.cwd = (str(root / d) for d in ('state', 'cwd'))
        Path(self.state).mkdir()
        Path(self.cwd).mkdir()
        self.ncfg = NativeRouteConfig(**self.native_kwargs())
        self.wprof = RouteProtocolProfile('responses', 'present', 'present',
                                        {}, WMODEL, 'cd' * 32)
        self.wenv = environment_ref(ENDPOINT, AUTH_REF,
                                    self.wprof.profile_digest)
        self.wcfg = RouteConfig(WMODEL, WADAPTER, self.wenv, ENDPOINT,
                                AUTH_REF, Deadlines(), 5, self.wprof)

    def native_kwargs(self):
        return dict(
            model=NMODEL, adapter=NADAPTER, environment_ref=NENV,
            measurement_state_dir=self.state, native_cwd=self.cwd,
            measurement_key='codex/' + NMODEL, measurement_digest=DIGEST,
            effort='high', total_s=900, max_drain_s=5, max_output_bytes=1024)

    def entry(self, routes):
        ac = ACDeclaration(('t',), 1024, ('</think>', '<think>'))
        return RegistryEntry('p', REV, 'effectful', True, tuple(routes),
                             ((900, 5),) * len(routes), 960, 'general',
                             'i', ('crit',), ac)

    def planner(self, entry, configs):
        key = (entry.profile_id, entry.revision_digest)
        return ProfilePlanner(ProfileRegistry({key: entry}, {}),
                              list(configs), WORKSPACE)

    def snapshot(self, entry, **over):
        profile = c.TaskProfile(entry.profile_id, entry.revision_digest,
                                entry.effect_class, entry.requires_output,
                                entry.routes)
        args = dict(run_id='r', original_intent=INTENT,
                    authenticated_origin_ref='o', profile=profile)
        args.update(over)
        return RunSnapshot(**args)

    def test_native_conditions(self):
        entry = self.entry([(NMODEL, NADAPTER, NENV)])
        planner = self.planner(entry, [self.ncfg])
        plan = planner(self.snapshot(entry), (), 'goal')
        self.assertIsInstance(plan, JobPlan)
        cond, = plan.conditions
        self.assertEqual(
            (cond.model, cond.adapter, cond.workspace,
             cond.environment_ref, cond.control_evidence_refs),
            (NMODEL, NADAPTER, self.cwd, NENV,
             ('native-measurement:' + DIGEST,)))
        self.assertEqual(
            (plan.action.name, plan.method, plan.job.acceptance_criteria,
             plan.job.context_json, plan.job.output_candidate,
             dict(plan.action.scope.dimensions)['workspace']),
            ('text.generate', 'text.generate', ('crit',), CONTEXT, True,
             WORKSPACE))
        self.assertIsNone(planner(
            self.snapshot(entry, job_ids=('job-1',)), (), 'g'))

    def test_wire_and_mixed(self):
        routes = [(NMODEL, NADAPTER, NENV), (WMODEL, WADAPTER, self.wenv)]
        entry = self.entry(routes)
        plan = self.planner(entry, [self.wcfg, self.ncfg])(
            self.snapshot(entry), (), 'g')
        self.assertEqual(
            [(x.workspace, x.environment_ref, x.control_evidence_refs)
             for x in plan.conditions],
            [(self.cwd, NENV, ('native-measurement:' + DIGEST,)),
             (WORKSPACE, self.wenv,
              ('route-profile:' + self.wprof.profile_digest,))])

    def test_integrity(self):
        entry = self.entry([(NMODEL, NADAPTER, NENV)])
        planner = self.planner(entry, [self.ncfg])
        runs = ([self.snapshot(entry, profile=c.TaskProfile(
                    'p', d, 'effectful', rq, entry.routes))
                 for d, rq in (('sha256:' + '56' * 32, True), (REV, False))] +
                [self.snapshot(entry, original_intent='garbage'),
                 self.snapshot(entry, job_ids=('job-1', 'job-2'))])
        for run in runs:
            with self.assertRaises(IntegrityViolation):
                planner(run, (), 'g')
        for extra in [('x', 'o', 'e'), (NMODEL, NADAPTER, 'e2')]:
            bad = self.entry([(NMODEL, NADAPTER, NENV), extra])
            with self.assertRaises(IntegrityViolation):
                self.planner(bad, [self.ncfg])(self.snapshot(bad), (), 'g')

    def test_constructor(self):
        class Sub(NativeRouteConfig):
            pass
        for routes in ([object()], [Sub(**self.native_kwargs())],
                       [self.ncfg, self.ncfg]):
            with self.assertRaises(ValueError):
                ProfilePlanner(ProfileRegistry({}, {}), routes, WORKSPACE)
