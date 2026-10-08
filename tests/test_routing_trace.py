"""Durable product Controller routing evidence; synthetic Native, no live claims."""
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.catalog import Catalog
from co_v4.state import Conflict, InvalidTransition, Limits
from co_v4.trace import PublicationBlocked, PublicationPolicy, Trace, canonical
from co_v4.usage import UsageStore
import test_controller as fixture
from test_controller import NativeFixture, NOW, catalog
from test_state import Harness


class RoutingTraceTests(unittest.TestCase):
    # Reuse fixture construction without inheriting unrelated test cases.
    plan = fixture.ControllerTests.plan
    verify = fixture.ControllerTests.verify
    build = fixture.ControllerTests.build
    drive = fixture.ControllerTests.drive
    start = fixture.ControllerTests.start

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Harness(self.tmp.name)
        self.addCleanup(lambda: self.h.store.close())
        self.native = NativeFixture()
        self.verdicts, self.run_verdicts = [], []
        self.plans = [self.plan()]
        self.usage = UsageStore()
        self.controller = self.build()

    def history(self):
        return self.h.ctrl.history('r', 'routing_history')

    def reopen(self):
        self.h.store.close()
        self.h.store = self.h.connect()
        self.h.refresh()
        self.controller = self.build()

    def trace(self, release=lambda _: True):
        trace = Trace(Path(self.tmp.name) / 'trace.sqlite', PublicationPolicy(release))
        self.addCleanup(trace.close)
        return trace

    def test_before_native_io_and_restart_before_projection_preserve_exact_rationale(self):
        self.controller = self.build(catalog=catalog(('a', 'b', 'unassessed')))
        for model, percent in (('a', 10.25), ('b', 80.5)):
            self.usage.update(c.Usage(model, 'adapter', percent, NOW.isoformat(),
                'fixture:usage', 'comparable-fixture-window'))
        execute = self.native.execute
        evidence = []
        def inspect_then_execute(request):
            records = self.history()
            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertEqual((record.ref.run_id, record.ref.job_id, record.ref.attempt_id),
                (request.ref.run_id, request.ref.job_id, request.ref.attempt_id))
            self.assertEqual(record.state_revision + 1, self.h.ctrl.get_attempt(request.ref).revision)
            evidence.append(record)
            return execute(request)
        self.native.execute = inspect_then_execute
        ref = self.start()
        self.reopen()
        self.assertEqual(self.controller.records, ())
        self.assertEqual(self.history(), tuple(evidence))
        # Recovery must use retained observation, even if dynamic inputs disappear.
        self.usage.invalidate('b', 'adapter', 'comparable-fixture-window')
        trace = self.trace()
        projected = trace.record_routing(self.history()[0])
        self.assertEqual(trace.record_routing(self.history()[0]), projected)
        self.assertEqual(len(trace.records()), 1)
        summary = projected['summary']
        self.assertEqual(summary['selected'], {'model': 'b', 'adapter': 'adapter'})
        self.assertEqual(summary['reason'], 'comparable_usage')
        self.assertEqual(summary['use_case']['category'], 'coding')
        self.assertEqual(summary['excluded'], [{'model': 'unassessed', 'adapter': 'adapter',
            'reason': 'missing_current_job_assessment'}])
        self.assertEqual(summary['eligible'][1]['usage']['remaining_percent'], 80.5)
        self.assertEqual(summary['eligible'][1]['catalog_verification']['measurement_ref'],
            'fixture:measurement')
        self.assertIn({'kind': 'judgment', 'record_id': evidence[0].execution_decision_ref}, projected['links'])
        self.assertIn({'kind': 'attempt', 'record_id': ref.attempt_id}, projected['links'])
        self.assertEqual(self.drive().state, c.State.COMPLETED)
        self.assertEqual(len(self.native.requests), 1)

    def test_crash_after_actual_dispatch_before_receipt_or_projection_keeps_evidence(self):
        execute = self.native.execute
        def crash(request):
            execute(request)
            raise KeyboardInterrupt('fixture host crash')
        self.native.execute = crash
        self.controller.step()
        with self.assertRaises(KeyboardInterrupt):
            self.controller.step()
        retained = self.history()
        self.assertEqual(len(retained), 1)
        ref = self.native.requests[0].ref
        self.assertIsNone(self.h.ctrl.execute_receipt(ref))
        self.reopen()
        self.assertEqual(self.history(), retained)
        self.assertEqual(self.trace().record_routing(retained[0])['attempt_id'], ref.attempt_id)
        self.controller.step()
        self.assertEqual(len(self.native.requests), 1)
        self.assertEqual(self.native.stops, [ref])

    def test_crash_after_reservation_before_execute_is_atomic_and_recoverable(self):
        begin = self.h.ctrl.begin_attempt
        def crash(*args, **kwargs):
            begin(*args, **kwargs)
            raise KeyboardInterrupt('fixture crash before execute')
        self.h.ctrl.begin_attempt = crash
        self.controller.step()
        with self.assertRaises(KeyboardInterrupt):
            self.controller.step()
        self.assertEqual(self.native.requests, [])
        self.reopen()
        record, = self.history()
        attempt, = self.h.ctrl.attempts('r')
        self.assertEqual(record.ref.attempt_id, attempt.ref.attempt_id)
        self.assertEqual(self.trace().record_routing(record)['kind'], 'routing')
        # Recovery requests cessation instead of treating a reserved slot as unsent.
        self.controller.step()
        self.assertEqual(self.native.requests, [])
        self.assertEqual(self.native.stops, [attempt.ref])

    def test_no_eligible_route_retains_exclusion_and_assessment_before_terminal(self):
        self.controller = self.build(catalog=catalog(('unassessed',)))
        self.assertEqual(self.drive().state, c.State.FAILED)
        self.reopen()
        record, = self.history()
        self.assertIsNone(record.ref.attempt_id)
        summary = self.trace().record_routing(record)['summary']
        self.assertIsNone(summary['selected'])
        self.assertEqual(summary['reason'], 'no_eligible_route')
        self.assertEqual(summary['excluded'][0]['reason'], 'missing_current_job_assessment')
        self.assertEqual(len(summary['assessments']), 2)
        self.assertEqual(self.native.requests, [])

    def test_stale_and_missing_usage_remain_distinguishable_after_restart(self):
        self.usage.update(c.Usage('a', 'adapter', 42.5, (NOW-timedelta(days=1)).isoformat(),
            'fixture:old', 'comparable-fixture-window'))
        self.start()
        self.reopen()
        summary = json.loads(self.history()[0].summary_json)
        first, second = [o['usage'] for o in summary['eligible']]
        self.assertEqual((first['reason'], first['remaining_percent']), ('stale', None))
        self.assertEqual(first['sample']['remaining_percent'], 42.5)
        self.assertEqual((second['reason'], second['sample']), ('missing', None))
        self.assertEqual(summary['selected']['model'], 'a')

    def test_revision_change_during_final_judgment_requires_fresh_selection(self):
        self.controller.step()
        judge = self.h.judgment.judge
        def changed(request):
            if request.ref.attempt_id:
                self.h.ctrl.set_limits('r', Limits(jobs=19), self.h.rev())
            return judge(request)
        self.h.judgment.judge = changed
        self.assertEqual(self.controller.step().reason, 'routing_snapshot_changed')
        self.assertEqual(self.native.requests, [])
        self.assertEqual(self.history(), ())
        self.assertEqual(self.h.ctrl.attempts('r'), ())
        self.h.judgment.judge = judge
        fresh_revision = self.h.rev()
        self.assertEqual(self.controller.step().reason, 'execute_receipt')
        self.assertEqual(self.history()[0].state_revision, fresh_revision)

    def test_revision_change_during_candidate_assessment_never_dispatches(self):
        self.controller.step()
        judge = self.h.judgment.judge
        def changed(request):
            if request.conditions.model == 'b':
                self.h.ctrl.set_limits('r', Limits(jobs=19), self.h.rev())
            return judge(request)
        self.h.judgment.judge = changed
        self.assertEqual(self.controller.step().reason, 'routing_snapshot_changed')
        self.assertEqual(self.native.requests, [])
        self.assertEqual(self.history(), ())

    def test_failed_rejudgment_is_retained_without_an_attempt(self):
        self.controller.step()
        judge = self.h.judgment.judge
        def changed(request):
            if request.ref.attempt_id:
                self.h.protection = False
            return judge(request)
        self.h.judgment.judge = changed
        self.assertEqual(self.controller.step().reason, 'dispatch_rejudgment_not_normal')
        self.reopen()
        record, = self.history()
        self.assertIsNone(record.ref.attempt_id)
        self.assertIsNotNone(record.execution_decision_ref)
        self.assertEqual(self.h.ctrl.attempts('r'), ())
        self.assertEqual(self.native.requests, [])

    def test_wrong_attempt_selection_revision_or_judgment_cannot_be_reserved(self):
        begin = self.h.ctrl.begin_attempt
        captures = []
        def capture(request, decision_ref, revision, **kwargs):
            captures.append((request, decision_ref, revision, kwargs['routing']))
            raise KeyboardInterrupt('fixture pause')
        self.h.ctrl.begin_attempt = capture
        self.controller.step()
        with self.assertRaises(KeyboardInterrupt):
            self.controller.step()
        request, decision_ref, revision, record = captures[0]
        summary = json.loads(record.summary_json)
        summary['selected']['model'] = 'b'
        variants = [replace(record, ref=replace(record.ref, attempt_id='wrong')),
                    replace(record, state_revision=revision+1),
                    replace(record, execution_decision_ref='wrong'),
                    replace(record, summary_json=canonical(summary))]
        for forged in variants:
            with self.subTest(record=forged), self.assertRaises(InvalidTransition):
                begin(request, decision_ref, revision, routing=forged)
            self.assertEqual(self.history(), ())
            self.assertEqual(self.h.ctrl.attempts('r'), ())
        attempt = begin(request, decision_ref, revision, routing=record)
        self.assertEqual(begin(request, decision_ref, revision, routing=record), attempt)
        with self.assertRaises(Conflict):
            begin(request, 'different-judgment', revision, routing=record)
        with self.assertRaises(Conflict):
            begin(request, decision_ref, revision, routing=replace(record, record_id='changed'))
        self.assertEqual(self.history(), (record,))

    def test_private_extras_and_workspace_never_enter_routing_evidence(self):
        entries = catalog().entries
        private_catalog = Catalog(tuple(replace(e, extra={'private': 'token=do-not-retain'}) for e in entries))
        self.controller = self.build(catalog=private_catalog)
        self.start()
        retained = self.history()[0].summary_json
        self.assertNotIn('do-not-retain', retained)
        self.assertNotIn('/fixture', retained)
        self.assertNotIn('create tested output', retained)
        with self.assertRaises(PublicationBlocked):
            self.trace(release=lambda _: False).record_routing(self.history()[0])
        self.assertEqual(len(self.history()), 1)

    def test_sensitive_usage_reference_fails_closed_before_reservation_and_execute(self):
        self.usage.update(c.Usage('a', 'adapter', 20.0, NOW.isoformat(),
            'token=do-not-retain', 'comparable-fixture-window'))
        self.controller.step()
        self.assertEqual(self.controller.step().reason, 'controller_error')
        self.assertEqual(self.native.requests, [])
        self.assertEqual(self.history(), ())
        self.assertEqual(self.h.ctrl.attempts('r'), ())


if __name__ == '__main__':
    unittest.main()
