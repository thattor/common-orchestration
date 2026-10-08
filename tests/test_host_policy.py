"""host_policy resolver: real RouteBundle/registry/store/Controller paths.

Real protected manifest/captures/credential files drive build_routes; the
registry loads over the bundle's real catalog and RouteConfigs; every
judgment runs inside a real judge() transaction with the actual
make_evidence closure — never a fixture boolean or a mock view. Provider
transport is trapped and must never be called. Tampering uses the measured
store seams only; production code never touches _db.

Explicit followup, not covered here: live-callback hard_deny with a real
PooledAdapter contract child (barrier + real stop + zero respond()); the
structural global-latch behavior (503/driver/owner/SIGTERM) lives in the
HTTP/ServiceDriver suite per the Opus ruling.
"""
import json
import secrets
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4 import host_routes as hr
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.adapter_capacity import CapacityLedger, PooledAdapter
from co_v4.controller import Controller
from co_v4.gateway_store import submit_body
from co_v4.host_policy import make_evidence
from co_v4.http_auth import IngressBroker
from co_v4.judgment import JudgmentRequest
from co_v4.profile_planner import ProfilePlanner
from co_v4.profile_registry import load_registry, revision_digest
from co_v4.responses_input import parse
from co_v4.state import ControlStore, StoreUnavailable, body_digest
from co_v4.usage import UsageStore
import test_host_routes as thr
import test_profile_registry as tpr

NOW = '2026-10-06T00:00:00Z'
NOW_DT = datetime(2026, 10, 6, tzinfo=timezone.utc)   # Controller clock
ALIAS = 'co-text'
MODEL, RESPONSES = thr.MODEL, thr.RESPONSES


class HostPolicyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name).resolve()
        tmp = Path(tempfile.mkdtemp(dir=str(base)))
        cred = thr.write(tmp / 'cred', secrets.token_hex(32).encode())
        mpath = thr.write(tmp / 'manifest.json',
                          thr.manifest_dict(tmp, cred))
        helper = thr.HostRoutesTests()
        spec = helper.spec_for(tmp, cred, mpath)
        self.bundle = hr.build_routes(helper.config(tmp, (spec,), cred))
        self.env = spec.environment_ref
        wire = tpr.wire_entry(
            env=self.env,
            routes=[[MODEL, RESPONSES, self.env]],
            route_bounds=[{'route': [MODEL, RESPONSES, self.env],
                           'total_s': 120, 'max_drain_s': 30}])
        doc = tpr.registry_doc([wire], [{
            'alias': ALIAS, 'profile_id': 'co-text',
            'revision_digest': revision_digest(wire)}])
        self.registry = load_registry(
            json.dumps(doc), catalog=self.bundle.catalog,
            routes=self.bundle.route_configs)
        self.broker = None
        self.store = ControlStore(
            base / 'control.sqlite',
            verifier=lambda ref: self.broker.verifier(ref),
            evidence=lambda run, req: self._resolver(run, req),
            clock=lambda: NOW,
            profile_resolver=self.registry.resolve)
        self.addCleanup(self.store.close)
        self.broker = IngressBroker(self.store.now)
        self._resolver = make_evidence(self.store, self.registry,
                                       self.bundle)
        self.gateway = self.store.gateway()
        self.ctrl = self.store.controller()
        self.judge = self.store.judgment()
        self.planner = ProfilePlanner(self.registry,
                                      self.bundle.route_configs,
                                      hr.TEXT_WORKSPACE)
        self.ledger = CapacityLedger(base / 'cap.sqlite')
        self.pool = PooledAdapter(RESPONSES, ledger=self.ledger,
            canonical_ledger=self.ledger.path,
            factory=self.bundle.factories[RESPONSES])
        trap = patch.object(hr, 'HttpSseTransport')
        self.transport = trap.start()
        self.addCleanup(trap.stop)
        self.verified = []
        self._key = 0

    def submit(self):
        """Real Gateway.submit through the real IngressBroker verifier."""
        self._key += 1
        key = 'k%d' % self._key
        intent = parse(json.dumps(
            {'model': ALIAS, 'input': 'x'}).encode())
        with self.broker.receipt_ref(
                'p1', submit_body(intent.body_hash, key)) as ref:
            sub = self.gateway.submit(intent, key, ref)
        run = self.ctrl.get_run(sub.run_id)
        return sub.run_id, self.planner(replace(run, job_ids=()), (), None)

    def request(self, run_id, plan, **kw):
        base = dict(ref=c.QuestionRef(run_id, 'job-1'),
                    action=plan.action, method=plan.method,
                    conditions=plan.conditions[0])
        base.update(kw)
        return JudgmentRequest(**base)

    def verify(self, request):
        self.verified.append(request)
        return CheckEvidence(body_digest(request),
            Finding('pass', ('x',)),
            tuple(Finding('pass', ('y',))
                  for _ in (request.job.acceptance_criteria
                            if request.job else ())))

    def controller(self, run_id):
        return Controller(run_id, state=self.ctrl, judgment=self.judge,
            catalog=self.bundle.catalog, usage=UsageStore(),
            adapters={RESPONSES: self.pool},
            acceptance=Acceptance(self.verify), planner=self.planner,
            clock=lambda: NOW_DT)

    def test_plan_and_execution_judgments_normal(self):
        run_id, plan = self.submit()
        record = self.judge.judge(self.request(
            run_id, plan, proposed_job=plan.job))
        self.assertEqual((record.decision, record.reason),
                         (c.Decision.NORMAL, 'job_contained'))
        self.ctrl.add_job(plan.job, record.decision_id,
                          self.ctrl.get_run(run_id).revision)
        record = self.judge.judge(self.request(run_id, plan))
        self.assertEqual((record.decision, record.reason),
                         (c.Decision.NORMAL, 'authenticated_intent'))
        self.assertTrue(record.evidence_refs)
        self.transport.assert_not_called()

    def test_proposed_single_field_mismatches_deny(self):
        run_id, plan = self.submit()
        cases = (
            dict(proposed_job=replace(plan.job, instructions='other')),
            dict(action=c.Action('other.name', plan.action.scope)),
            dict(method='other.method'),
            dict(conditions=replace(plan.conditions[0], workspace='/x')),
            dict(conditions=replace(plan.conditions[0],
                                    control_evidence_refs=())),
            dict(conditions=replace(plan.conditions[0],
                    environment_ref='env:sha256:' + '1' * 64)),
        )
        for i, kw in enumerate(cases):
            with self.subTest(case=i):
                self.assertEqual(self.judge.judge(self.request(
                    run_id, plan,
                    **{'proposed_job': plan.job, **kw})).decision,
                    c.Decision.DENY)
        # A second Run proceeds normally: per-Run deny never latches.
        run2, plan2 = self.submit()
        self.assertEqual(self.judge.judge(self.request(
            run2, plan2, proposed_job=plan2.job)).decision,
            c.Decision.NORMAL)

    def test_execution_mismatches_deny(self):
        run_id, plan = self.submit()
        record = self.judge.judge(self.request(
            run_id, plan, proposed_job=plan.job))
        self.ctrl.add_job(plan.job, record.decision_id,
                          self.ctrl.get_run(run_id).revision)
        cond = plan.conditions[0]
        cases = (
            dict(ref=c.QuestionRef(run_id, 'job-2')),   # no committed Job
            dict(action=c.Action('other', plan.action.scope)),
            dict(method='other'),
            dict(conditions=replace(cond, control_evidence_refs=())),
            dict(conditions=replace(cond, workspace='/x')),
            dict(conditions=replace(cond,
                    environment_ref='env:sha256:' + '2' * 64)),
            dict(conditions=replace(cond, adapter='codex.app-server')),
        )
        for i, kw in enumerate(cases):
            with self.subTest(case=i):
                self.assertEqual(self.judge.judge(
                    self.request(run_id, plan, **kw)).decision,
                    c.Decision.DENY)

    def test_semantic_plan_mutation_fails_real_controller(self):
        mutations = (
            lambda p: replace(p, job=replace(p.job, instructions='o')),
            lambda p: replace(p, action=c.Action('o', p.action.scope)),
            lambda p: replace(p, method='other.method'),
            lambda p: replace(p, conditions=(
                replace(p.conditions[0], workspace='/x'),)),
            lambda p: replace(p, conditions=(
                replace(p.conditions[0], control_evidence_refs=()),)),
        )
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                run_id, _plan = self.submit()           # fresh valid Run
                controller = Controller(run_id, state=self.ctrl,
                    judgment=self.judge, catalog=self.bundle.catalog,
                    usage=UsageStore(), adapters={RESPONSES: self.pool},
                    acceptance=Acceptance(self.verify),
                    planner=lambda r, j, g, _m=mutate: _m(
                        self.planner(r, j, g)),          # wrap, not fake
                    clock=lambda: NOW_DT)
                final = controller.step()
                self.assertEqual((final.state, final.reason),
                                 (c.State.FAILED, 'approval_required'))
                self.assertEqual(self.ctrl.waits(run_id), ())
                self.assertEqual(self.ctrl.attempts(run_id), ())
        run2, _ = self.submit()
        progress = self.controller(run2).step()
        self.assertEqual((progress.state, progress.reason),
                         (c.State.PENDING, 'next_job'))
        self.transport.assert_not_called()               # zero POST
        self.assertEqual(self.verified, [])              # no AC ran

    def test_gateway_membership_denies_via_real_controller(self):
        cases = (
            ('DELETE FROM gateway_responses WHERE run_id=?', ()),
            ('UPDATE gateway_responses SET request_digest=? WHERE run_id=?',
             ('0' * 64,)),
            ('UPDATE gateway_responses SET alias=? WHERE run_id=?',
             ('bad alias',)),
            ('UPDATE gateway_responses SET created_at=? WHERE run_id=?',
             ('not-a-time',)),
        )
        for i, (sql, args) in enumerate(cases):
            with self.subTest(case=i):
                run_id, _plan = self.submit()
                self.assertEqual(self.store._db.execute(
                    sql, args + (run_id,)).rowcount, 1)   # exactly one row
                final = self.controller(run_id).step()
                self.assertEqual((final.state, final.reason),
                                 (c.State.FAILED, 'approval_required'))
                self.assertEqual(self.ctrl.waits(run_id), ())
                self.assertEqual(self.ctrl.attempts(run_id), ())
        self.transport.assert_not_called()

    def test_profile_missing_or_field_mismatch_denies(self):
        for i, mutate in enumerate((
                lambda p: None,
                lambda p: replace(p, requires_output=False),
                lambda p: replace(p, routes=()))):
            with self.subTest(case=i):
                run_id, plan = self.submit()
                with self.store._tx(run_id) as data:
                    data['run'] = replace(data['run'],
                        profile=mutate(data['run'].profile))
                self.assertEqual(self.judge.judge(self.request(
                    run_id, plan, proposed_job=plan.job)).decision,
                    c.Decision.DENY)

    def test_structural_failures_propagate_to_global(self):
        # evaluate-level propagation only: Controller.step() catches
        # exceptions itself (ERROR/controller_error) before any driver
        # latch — the 503/owner-held surface is NOT asserted here.
        run_id, plan = self.submit()
        request = self.request(run_id, plan, proposed_job=plan.job)
        real = self.store.judgment_view
        for exc in (TypeError('code bug'), sqlite3.Error('db'),
                    StoreUnavailable('facade misuse')):
            with self.subTest(exc=type(exc).__name__):
                def broken(_rid, _e=exc):
                    raise _e
                self.store.judgment_view = broken
                try:
                    with self.assertRaises(StoreUnavailable):
                        self.judge.judge(request)
                finally:
                    self.store.judgment_view = real
        self.assertEqual(self.judge.judge(request).decision,
                         c.Decision.NORMAL)


if __name__ == '__main__':
    unittest.main()
