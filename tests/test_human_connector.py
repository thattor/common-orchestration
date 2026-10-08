"""Synthetic host connector calls; no real publication or positive host guard."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
import unittest

from co_v4.human_connector import ConnectorGitHub, LIMIT
from co_v4.human_gateway import ConnectorUnavailable, DeliveryUncertain, IssueTarget
from co_v4.state import Conflict, UntrustedInput
from co_v4.waiting import wait_link
import test_human_gateway as gateway_fixture


class ConnectorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = gateway_fixture.GatewayTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.target = self.fixture.http.target
        self.reads = []
        self.bridge = ConnectorGitHub(self.target, self.raw_fetch)
        self.fixture.gateway.github = self.bridge

    def raw_fetch(self, url):
        """Fixture-only trusted host callback; never authenticates a live source."""
        self.reads.append(url)
        if url == self.target.api_url:
            return json.dumps(self.fixture.http.issue)
        source = deepcopy(self.fixture.http.comments[int(url.rsplit('/', 1)[1])])
        source['url'] = url
        source['user']['email'] = 'unrelated@example.invalid'
        return json.dumps(source)

    def stage(self):
        wait = self.fixture.h.wait()
        with self.assertRaises(DeliveryUncertain):
            self.fixture.gateway.publish(wait.ref, wait.request_id, self.fixture.context)
        return wait

    def test_generated_question_once_then_authenticated_readback_and_receive(self):
        wait = self.stage()
        action = self.bridge.take_question()
        self.assertEqual(action.target, self.target)
        with self.assertRaises(FrozenInstanceError): action.body = 'different'
        self.assertIsNone(self.bridge.take_question())
        self.assertEqual(self.fixture.http.calls, [])  # No token-bearing HTTP client used.
        self.assertEqual(self.fixture.h.ctrl.history('r', 'approvals'), ())
        # Fixture host executes only the exact question action. This is not a
        # Worker capability and cannot generate the separately supplied answer.
        self.fixture.http.add(10, action.body, user=202)
        self.fixture.gateway.reconcile(wait.ref, wait.request_id, 10)
        self.fixture.comment(wait)
        self.assertEqual(self.fixture.receive(wait).disposition, 'applied')
        self.assertEqual(self.fixture.receive(wait).disposition, 'applied')
        self.assertEqual(len(self.fixture.h.ctrl.history('r', 'approvals')), 1)
        self.assertNotIn('email', self.bridge.comment(self.target, 42)['user'])

    def test_restart_lost_action_and_uncertain_post_never_recreate_action(self):
        wait = self.stage()
        action = self.bridge.take_question()
        restarted = ConnectorGitHub(self.target, self.raw_fetch)
        self.fixture.gateway.github = restarted
        with self.assertRaises(DeliveryUncertain):
            self.fixture.gateway.publish(wait.ref, wait.request_id, self.fixture.context)
        self.assertIsNone(restarted.take_question())
        self.assertEqual(self.fixture.journal.publication(wait_link(wait.ref, wait.request_id))['status'], 'sending')
        # An uncertain successful external POST is resolved by GET, not another POST.
        self.fixture.http.add(10, action.body, user=202)
        self.fixture.gateway.reconcile(wait.ref, wait.request_id, 10)
        self.assertIsNone(restarted.take_question())

    def test_distinct_questions_work_after_reconciliation_and_queue_in_order(self):
        first = self.stage()
        first_action = self.bridge.take_question()
        self.fixture.http.add(10, first_action.body, user=202)
        self.fixture.gateway.reconcile(first.ref, first.request_id, 10)
        for name in ('second', 'third'):
            wait = self.fixture.h.wait(name=name)
            with self.assertRaises(DeliveryUncertain):
                self.fixture.gateway.publish(wait.ref, wait.request_id, self.fixture.context)
        second, third = self.bridge.take_question(), self.bridge.take_question()
        self.assertIn('"request_id":"second"', second.body)
        self.assertIn('"request_id":"third"', third.body)
        self.assertIsNone(self.bridge.take_question())
        with self.assertRaises(DeliveryUncertain):
            self.bridge.post_question(self.target, first_action.body)
        self.assertIsNone(self.bridge.take_question())

    def test_guard_blocks_before_broker_fetch_or_action(self):
        self.fixture.isolated = False
        wait = self.fixture.h.wait()
        with self.assertRaises(UntrustedInput):
            self.fixture.gateway.publish(wait.ref, wait.request_id, self.fixture.context)
        self.assertEqual(self.reads, [])
        self.assertIsNone(self.bridge.take_question())
        self.assertIsNone(self.fixture.journal.publication(wait_link(wait.ref, wait.request_id)))

    def test_fresh_answer_rechecks_source_and_does_not_infer_missing_metadata(self):
        wait = self.stage()
        self.fixture.http.add(10, self.bridge.take_question().body, user=202)
        self.fixture.gateway.reconcile(wait.ref, wait.request_id, 10)
        self.fixture.comment(wait)
        original = deepcopy(self.fixture.http.comments[42])
        for key in ('created_at', 'updated_at', 'issue_url'):
            self.fixture.http.comments[42] = deepcopy(original)
            del self.fixture.http.comments[42][key]
            with self.assertRaises(UntrustedInput): self.fixture.receive(wait)
        self.fixture.http.comments[42] = deepcopy(original)
        self.fixture.http.comments[42]['user']['type'] = 'Bot'
        with self.assertRaises(UntrustedInput): self.fixture.receive(wait)
        self.assertEqual(self.fixture.h.ctrl.history('r', 'approvals'), ())

    def test_cross_target_source_mismatch_duplicate_fields_and_bounds_fail_closed(self):
        with self.assertRaises(UntrustedInput): self.bridge.issue(IssueTarget('other/repo', 160))
        self.assertEqual(self.reads, [])
        invalid = ('{}', '[]', '{"url":"x","url":"y"}',
                   json.dumps({'url': 'https://api.github.com/repos/other/repo/issues/160'}),
                   '{"url":NaN}', ' ' * (LIMIT + 1))
        for raw in invalid:
            with self.subTest(raw=raw[:60]):
                bridge = ConnectorGitHub(self.target, lambda _: raw)
                with self.assertRaises(UntrustedInput): bridge.issue(self.target)
        for value in (True, 0, '42'):
            with self.assertRaises(ValueError): self.bridge.comment(self.target, value)

    def test_transport_error_sanitized_and_no_arbitrary_answer_post(self):
        def failed(_): raise OSError('private provider detail')
        bridge = ConnectorGitHub(self.target, failed)
        with self.assertRaises(ConnectorUnavailable) as failure: bridge.issue(self.target)
        self.assertNotIn('private provider detail', str(failure.exception))
        for body in ('approve', '{"schema":"co.human-response.v1","answer":"approve"}'):
            with self.assertRaises(UntrustedInput): bridge.post_question(self.target, body)
        self.assertIsNone(bridge.take_question())

    def test_question_readback_change_remains_conflict(self):
        wait = self.stage()
        action = self.bridge.take_question()
        with self.assertRaises(DeliveryUncertain): self.bridge.post_question(self.target, action.body)
        self.fixture.http.add(10, action.body + '\nchanged', user=202)
        with self.assertRaises(Conflict): self.fixture.gateway.reconcile(wait.ref, wait.request_id, 10)
        self.assertEqual(self.fixture.h.ctrl.history('r', 'approvals'), ())


if __name__ == '__main__': unittest.main()
