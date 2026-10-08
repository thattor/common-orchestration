"""#190 M3 runtime pin tampering: committed corruption -> integrity latch.

A real committed Run aggregate is tampered through the store's own
transaction AFTER a valid startup; the real Controller.step then hits the
planner's IntegrityViolation -> fatal latch -> FAILED/integrity_violation
with zero Attempts, zero waits and zero judgments. The untampered sibling
Run plans and dispatches normally through the same stack. Only
persistable committed tamper is modeled here (str-typed Run fields); the
unpersistable bytes/surrogate and non-(job-1,) job_ids shapes are covered
as direct planner cases in test_profile_planner.py. Startup check_store
semantics are asserted unchanged. No provider contact, no AC fabrication
-- Acceptance is armed to explode if it is ever invoked on these paths.
"""
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.ac import Acceptance
from co_v4.adapter_capacity import CapacityLedger, PooledAdapter
from co_v4.controller import Controller
from co_v4.gateway_store import submit_body
from co_v4.judgment import TrustedEvidence
from co_v4.output_store import OutputStore
from co_v4.profile_planner import ProfilePlanner
from co_v4.profile_registry import (ProfileRegistryMismatch, check_store)
from co_v4.responses_input import parse
from co_v4.state import (ControlStore, IngressReceipt, body_digest)
from co_v4.trace import canonical
from co_v4.usage import UsageStore
from test_adapter_capacity import Child
from test_profile_planner import ADAPTER, MODEL, WORKSPACE
import test_profile_planner as tpp        # fixture module, not the class

NOW = '2026-10-06T00:00:00Z'
NOW_DT = datetime(2026, 10, 6, tzinfo=timezone.utc)


class CollectingChild(Child, c.OutputCollector):
    """Real OutputCollector contract qualification for the dispatch
    admission guard; collect_output itself is never invoked on this
    suite's paths (the Attempt is only admitted, never polled)."""
    def collect_output(self, ref):
        return ()


class PinIntegrityTests(unittest.TestCase):
    """Composition over the real planner fixture (registry, catalog,
    route) plus an OWN ControlStore whose evidence seam is the bound
    test resolver below -- the planner fixture's evidence is the inert
    lambda, so nothing here shares its store, gateway or receipts."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        self.fx = tpp.ProfilePlannerTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)        # closes its own store
        self.registry, self.route = self.fx.registry, self.fx.route
        self.catalog = self.fx.catalog
        self.planner = ProfilePlanner(self.registry, (self.route,),
                                      WORKSPACE)
        self.receipts, self.evidence_calls = {}, []
        self.store = ControlStore(self.dir / 'control.sqlite',
            verifier=self.receipts.__getitem__, evidence=self._evidence,
            clock=lambda: NOW,
            profile_resolver=self.registry.resolve)
        self.addCleanup(self.store.close)
        self.gateway = self.store.gateway()
        self.state = self.store.controller()
        self.ledger = CapacityLedger(self.dir / 'cap.sqlite')
        self.out = OutputStore(self.dir / 'outputs')
        self.pool = PooledAdapter(ADAPTER, ledger=self.ledger,
            canonical_ledger=self.ledger.path,
            factory=lambda req: CollectingChild())
        self.addCleanup(self.pool.close)

    def _evidence(self, run, request):
        """Bound trusted resolver: real field-shaped TrustedEvidence for
        plan containment and execution admission; never a bare bool."""
        self.evidence_calls.append(request)
        return TrustedEvidence(body_digest(request), 'f:policy',
            ('f:controls',), canonical([request.action.name]),
            False, False, True, True, True, True)

    def submit(self, **request):
        """Real Gateway.submit on THIS store; committed RunSnapshot."""
        request.setdefault('model', 'co-text')
        intent = parse(json.dumps(request, ensure_ascii=False,
                                  separators=(',', ':')).encode('utf-8'))
        event = 'e%d' % len(self.receipts)
        self.receipts[event] = IngressReceipt(
            'p', event, body_digest(submit_body(intent.body_hash, None)),
            NOW)
        sub = self.gateway.submit(intent, None, event)
        return self.state.get_run(sub.run_id)

    def tamper(self, run_id, **fields):
        """Committed aggregate mutation inside the store's own _tx."""
        with self.store._tx(run_id) as data:
            data['run'] = replace(data['run'], **fields)

    def controller(self, run_id, planner=None):
        return Controller(run_id, state=self.state,
            judgment=self.store.judgment(), catalog=self.catalog,
            usage=UsageStore(), adapters={ADAPTER: self.pool},
            acceptance=Acceptance(lambda req: (_ for _ in ()).throw(
                AssertionError('AC must not run'))),
            planner=planner or self.planner, clock=lambda: NOW_DT,
            output_store=self.out)

    def assert_integrity_failure(self, run_id):
        view = self.controller(run_id).step()
        self.assertEqual((view.state, view.reason),
                         (c.State.FAILED, 'integrity_violation'))
        run = self.state.get_run(run_id)
        self.assertEqual((run.state, run.final_reason),
                         (c.State.FAILED, 'integrity_violation'))
        # Zero judgments: the planner raised before any judge() call.
        self.assertEqual(self.evidence_calls, [])
        # Zero Attempts, zero waits, zero Jobs, all committed.
        self.assertEqual(self.state.attempts(run_id), ())
        self.assertEqual(self.state.waits(run_id), ())
        self.assertEqual(run.job_ids, ())
        self.assertEqual(self.state.history(run_id, 'execute_history'),
                         ())
        projected = self.gateway.project(run_id)
        self.assertEqual((projected.status, projected.code,
                          projected.decided),
                         ('failed', 'integrity_violation', True))

    def test_pinned_field_tamper_fails_integrity(self):
        for fields in ({'routes': ((MODEL, ADAPTER, 'env:x'),)},
                       {'effect_class': 'effectful'},
                       {'requires_output': False}):
            run = self.submit(input='x')
            self.tamper(run.run_id, profile=replace(run.profile,
                                                    **fields))
            with self.subTest(fields=fields):
                self.assert_integrity_failure(run.run_id)

    def test_profile_none_and_missing_revision(self):
        run = self.submit(input='x')
        self.tamper(run.run_id, profile=None)
        self.assert_integrity_failure(run.run_id)
        run = self.submit(input='x')
        self.tamper(run.run_id, profile=replace(
            run.profile, revision_digest='sha256:' + '9' * 64))
        self.assert_integrity_failure(run.run_id)

    def test_persistable_intent_tamper_fails_integrity(self):
        # Only str-typed committed mutations can persist; bytes/surrogate
        # shapes cannot be stored and stay direct-planner coverage.
        run = self.submit(input='x')
        self.tamper(run.run_id, original_intent='not json')
        self.assert_integrity_failure(run.run_id)
        run = self.submit(input='x')
        reserialized = json.dumps(json.loads(run.original_intent),
                                  indent=1)
        self.tamper(run.run_id, original_intent=reserialized)
        self.assert_integrity_failure(run.run_id)

    def test_pinned_route_missing_host_config(self):
        run = self.submit(input='x')
        empty = ProfilePlanner(self.registry, (), WORKSPACE)
        view = self.controller(run.run_id, planner=empty).step()
        self.assertEqual((view.state, view.reason),
                         (c.State.FAILED, 'integrity_violation'))
        self.assertEqual(self.state.attempts(run.run_id), ())

    def test_untampered_sibling_progresses(self):
        run = self.submit(input='x')
        self.tamper(run.run_id, profile=None)
        self.assert_integrity_failure(run.run_id)
        good = self.submit(input='x')
        ctl = self.controller(good.run_id)
        self.assertEqual(ctl.step().reason, 'next_job')
        self.assertEqual(self.state.get_run(good.run_id).job_ids,
                         ('job-1',))
        ctl.step()
        self.assertEqual(len(self.state.attempts(good.run_id)), 1)
        self.assertNotEqual(
            self.state.get_run(good.run_id).final_reason,
            'integrity_violation')

    def test_startup_check_store_semantics_unchanged(self):
        # Tamper after a valid startup: check_store still quarantines a
        # drifted pin and still refuses a missing revision outright.
        drifted = self.submit(input='x')
        self.tamper(drifted.run_id, profile=replace(
            drifted.profile, requires_output=False))
        self.assertEqual(
            check_store(self.registry, self.gateway, self.state),
            frozenset({drifted.run_id}))
        ghosted = self.submit(input='x')
        self.tamper(ghosted.run_id, profile=replace(
            ghosted.profile, revision_digest='sha256:' + '9' * 64))
        with self.assertRaises(ProfileRegistryMismatch):
            check_store(self.registry, self.gateway, self.state)


if __name__ == '__main__':
    unittest.main()
