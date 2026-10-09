import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from co_v4 import contracts as c
from co_v4.host_policy import make_evidence
from co_v4.host_routes import RouteBundle, RouteContext, TEXT_WORKSPACE
from co_v4.judgment import JudgmentRequest
from co_v4.openai_transport import Deadlines
from co_v4.profile_planner import ProfilePlanner
from co_v4.profile_registry import (ACDeclaration, NativeRouteConfig,
                                    ProfileRegistry, RegistryEntry,
                                    RouteConfig)
from co_v4.protocol_profile import RouteProtocolProfile
from co_v4.responses_input import parse
from co_v4.state import JudgmentView, RunSnapshot

DIGEST = 'sha256:' + 'ab' * 32
NKEY = ('m', 'codex.app-server', 'native:' + DIGEST)


class _Store:
    def __init__(self, view):
        self._view = view

    def judgment_view(self, *args):
        return self._view


class NativeHostPolicy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        for d in ('s', 'c', 'c2'):
            (root / d).mkdir()
        self.state, self.cwd, self.cwd2 = map(
            str, (root / 's', root / 'c', root / 'c2'))

    def ncfg(self, **over):
        base = dict(model='m', adapter='codex.app-server',
                    environment_ref=NKEY[2],
                    measurement_state_dir=self.state, native_cwd=self.cwd,
                    measurement_key='codex/m', measurement_digest=DIGEST,
                    effort='high', total_s=900, max_drain_s=5,
                    max_output_bytes=1024)
        return NativeRouteConfig(**{**base, **over})

    def registry(self, route):
        entry = RegistryEntry(
            profile_id='co-native', revision_digest='sha256:' + 'cd' * 32,
            effect_class='effectful', requires_output=True,
            routes=(route,), route_bounds=((900, 5),),
            unconfirmed_after_seconds=935, use_case='general',
            job_instructions='do', job_criteria=('ok',),
            ac=ACDeclaration(('text/plain',), 1024,
                             ('</think>', '<think>')))
        key = (entry.profile_id, entry.revision_digest)
        return (ProfileRegistry({key: entry}, {'co-native': key}),
                entry.task_profile())

    def fixture(self, cfg, contexts, store=None):
        reg, tprofile = self.registry(
            (cfg.model, cfg.adapter, cfg.environment_ref))
        body = parse(b'{"model":"co-native","input":"x"}')
        snap = RunSnapshot(
            run_id='r', profile=tprofile,
            original_intent=body.canonical_body.decode('utf-8'),
            authenticated_origin_ref='origin:test')
        plan = ProfilePlanner(reg, (cfg,), TEXT_WORKSPACE)(snap, (), None)
        snap = replace(snap, job_ids=(plan.job.job_id,))
        if store is None:
            store = _Store(JudgmentView(
                (body.body_hash, 'co-native', 1), (plan.job,)))
        ev = make_evidence(store, reg,
                           RouteBundle(None, (cfg,), contexts, {}))
        return ev, snap, plan, reg

    def request(self, snap, plan, **over):
        return replace(JudgmentRequest(
            c.QuestionRef(snap.run_id, plan.job.job_id), plan.action,
            plan.method, plan.conditions[0]), **over)

    def wire(self):
        proto = RouteProtocolProfile(
            protocol='responses', index_mode='present',
            sequence_mode='present', inert_fields={}, model='m',
            provider_manifest_sha256='ab' * 32)
        cfg = RouteConfig(model='m', adapter='openai.responses',
                          environment_ref='env:w', endpoint='https://e',
                          auth_ref='a', deadlines=Deadlines(),
                          max_drain_s=5, profile=proto)
        ctx = RouteContext('m', 'openai.responses', 'https://e', 'a',
                           'env:w', proto, 'ab' * 32, 'p', Deadlines(), 5,
                           ('u',) * 5, *([None] * 5))
        return ('m', 'openai.responses', 'env:w'), cfg, ctx

    def test_native_ok(self):
        cfg = self.ncfg()
        ev, snap, plan, reg = self.fixture(cfg, {NKEY: cfg})
        got = ev(snap, self.request(snap, plan))
        self.assertEqual(('registry:' + snap.profile.revision_digest,
                          'native-measurement:' + DIGEST, NKEY[2]),
                         got.evidence_refs)
        self.assertTrue(got.operation_key.endswith('|' + TEXT_WORKSPACE))
        self.assertTrue(got.intent_authorizes)
        got = ev(snap, self.request(snap, plan, proposed_job=plan.job))
        self.assertTrue(got.intent_contained)
        callback = c.Confirmation(
            c.AttemptRef(snap.run_id, plan.job.job_id, 'a'), 'cb',
            c.Decision.CONFIRM, plan.action, 'ask', 'fixture', True)
        self.assertTrue(ev(snap, self.request(
            snap, plan,
            ref=c.QuestionRef(snap.run_id, plan.job.job_id, 'a'),
            confirmation=callback)).hard_deny)

    def test_native_denies(self):
        cfg = self.ncfg()
        ev, snap, plan, reg = self.fixture(cfg, {NKEY: cfg})
        cond = plan.conditions[0]
        reqs = [self.request(snap, plan, conditions=x) for x in (
                replace(cond, workspace=self.cwd2),
                replace(cond, environment_ref='native:x'),
                replace(cond, control_evidence_refs=()),
                replace(cond, model='z'))]
        reqs += [self.request(snap, plan, method='x'),
                 self.request(snap, plan,
                              ref=c.QuestionRef('r', 'absent')),
                 self.request(snap, plan, action=replace(
                     plan.action, scope=c.Scope(
                         (('workspace', self.cwd),), True)))]
        for req in reqs:
            self.assertTrue(ev(snap, req).hard_deny)

    def test_composition_and_rebind(self):
        cfg = self.ncfg()
        reg, tprofile = self.registry(NKEY)
        bad = ({}, {NKEY: object()}, {NKEY: self.ncfg(effort='low')},
               {NKEY: self.ncfg(native_cwd=self.cwd2)})
        for contexts in bad:
            with self.assertRaises(ValueError):
                make_evidence(_Store(None), reg,
                              RouteBundle(None, (cfg,), contexts, {}))
        contexts = {NKEY: self.ncfg()}
        ev, snap, plan, reg = self.fixture(cfg, contexts)
        self.assertFalse(ev(snap, self.request(snap, plan)).hard_deny)
        contexts[NKEY] = self.ncfg(effort='low')
        with self.assertRaises(TypeError):
            ev(snap, self.request(snap, plan))
        del contexts[NKEY]
        with self.assertRaises(TypeError):
            ev(snap, self.request(snap, plan))

    def test_wire_and_fault(self):
        key, cfg, ctx = self.wire()
        ev, snap, plan, reg = self.fixture(cfg, {key: ctx})
        got = ev(snap, self.request(snap, plan))
        self.assertEqual('manifest:' + 'ab' * 32, got.evidence_refs[3])

        class Boom:
            def judgment_view(self, *a):
                raise RuntimeError('x')

        ev = make_evidence(Boom(), reg,
                           RouteBundle(None, (cfg,), {key: ctx}, {}))
        with self.assertRaises(RuntimeError):
            ev(snap, self.request(snap, plan))


if __name__ == '__main__':
    unittest.main()
