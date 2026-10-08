"""Real local state/lock/marker; synthetic source and Native, no live approval."""
from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4.human_gateway import DeliveryUncertain, IssueTarget, QuestionContext
from co_v4.judgment import JudgmentRequest, TrustedEvidence
from co_v4.preexecution_human import PreExecutionHumanDriver
from co_v4.state import IngressReceipt, InvalidTransition, UntrustedInput, body_digest, create_run_body
from co_v4.trace import canonical, digest
from co_v4.waiting import wait_link
from probes.preexecution_human_candidate import prepare


class PreExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / 'candidate'
        self.now = '2026-10-01T00:00:00Z'
        self.intent = 'Request a fixture text response after a genuine fixture Human answer.'
        self.origin_ref = 'github:fixture/co:comment:1'
        self.target = IssueTarget('fixture/co', 161)
        self.approvers = frozenset({101})
        self.conditions = c.ExecutionConditions('fixture-model', 'devin.acp', '/fixture/worker',
            'fixture:preexecution', ('fixture:independent-execution-controls',))
        self.action = c.Action('native.text.response', c.Scope((('response_sha256', 'fixture-digest'),), True))
        self.execution_verified = False  # Synthetic independent route evidence, never driver.guard.
        self.job = c.Job('r', 'j', 'Return fixture text without tools.', ('verify exact fixture text',))
        self.sources = {self.target.api_url: {'url': self.target.api_url, 'number': 161, 'state': 'open'}}
        self.calls = []
        self.launches = []
        self.factory_failure = False
        self.native_closes = 0
        self.cleanup_failure = False
        self.addCleanup(patch.stopall)
        patch('socket.socket', side_effect=AssertionError('test forbids sockets')).start()
        patch('subprocess.Popen', side_effect=AssertionError('no Native process expected')).start()
        self.driver = None
        self.driver = self.create()
        self.addCleanup(lambda: self.driver.close())

    def origin(self, source):
        if source != self.origin_ref: raise UntrustedInput('unknown fixture source')
        return IngressReceipt('fixture-human', source,
            body_digest(create_run_body('r', self.intent)), self.now)

    def evidence(self, run, request):
        if request.action != self.action or request.conditions != self.conditions:
            raise UntrustedInput('different fixture request')
        return TrustedEvidence(body_digest(request), 'fixture:policy', ('fixture:controls',),
            body_digest(self.action), requires_confirmation=True, intent_contained=True,
            intent_authorizes=False, conditions_verified=self.execution_verified,
            protection_verified=self.execution_verified)

    def fetch(self, url):
        self.calls.append(url)
        return json.dumps(self.sources[url])

    def factory(self, request):
        # This is a fixture Native, not a production attestation. The factory is
        # invoked only after durable launch closure and receives only Job data.
        self.assertFalse(self.driver.guard(self.approvers))
        self.assertEqual(json.loads((self.root / 'driver.json').read_text())['phase'], 'launch_claimed')
        self.assertEqual(request, self.request())
        self.assertNotIn('fetch', canonical(asdict(request)))
        self.assertNotIn(str(self.root), canonical(asdict(request)))
        self.launches.append(request)
        if self.factory_failure:
            raise OSError('fixture factory outcome uncertain')
        owner = self
        class Native:
            def execute(self, bound):
                return c.OperationReply(bound.ref, c.OperationStatus.ACCEPTED, 'fixture_started')
            def stop(self, ref):
                return c.StopReply(ref, c.StopStatus.UNCONFIRMED, 'fixture_unconfirmed')
            def close(self):
                owner.native_closes += 1
                if owner.cleanup_failure: raise OSError('fixture private cleanup detail')
        return Native()

    def options(self):
        class NoNotification:
            def send(self, **_): raise AssertionError('not exercised')
        return dict(run_id='r', origin_verifier=self.origin, evidence=self.evidence,
            target=self.target, approver_ids=self.approvers, publisher_id=202,
            fetch_raw=self.fetch, notifier=NoNotification(), release_check=lambda _: True,
            clock=lambda: self.now, native_factory=self.factory)

    def create(self):
        return PreExecutionHumanDriver.create(self.root, intent=self.intent,
            origin_ref=self.origin_ref, **self.options())

    def wait(self):
        ref = c.QuestionRef('r', 'j')
        decision = self.driver.judgment.judge(JudgmentRequest(ref, self.action, 'text',
            self.conditions, proposed_job=self.job))
        self.driver.state.add_job(self.job, decision.decision_id, self.driver.state.get_run('r').revision)
        decision = self.driver.judgment.judge(JudgmentRequest(ref, self.action, 'text', self.conditions))
        wait = c.WaitingHuman(ref, 'question', self.action, decision.decision, decision.reason,
            '2026-10-02T00:00:00Z')
        return self.driver.state.open_wait(wait, 'text', decision.state_revision, decision.decision_id)

    def context(self):
        return QuestionContext('Fixture background', 'Review fixture scope',
                               'Human decides', 'Only the bound fixture text')

    def comment(self, comment_id, body, actor):
        url = f'https://api.github.com/repos/{self.target.repository}/issues/comments/{comment_id}'
        self.sources[url] = dict(url=url, id=comment_id, issue_url=self.target.api_url,
            user={'id': actor, 'type': 'User'}, created_at=self.now, updated_at=self.now, body=body)

    def approve(self, wait):
        action = self.driver.stage_question(wait.ref, wait.request_id, self.context())
        self.comment(10, action.body, 202)
        self.driver.reconcile(wait.ref, wait.request_id, 10)
        presentation = self.driver.journal.publication(wait_link(wait.ref, wait.request_id))['presentation']
        self.comment(42, canonical(dict(schema='co.human-response.v1', request_id=wait.request_id,
            presentation_digest=digest(presentation), answer='approve', detail='')), 101)
        return self.driver.receive(wait.ref, wait.request_id, 42,
            expected_revision=self.driver.state.get_run('r').revision)

    def request(self):
        return c.ExecuteRequest(c.AttemptRef('r', 'j', 'a'), self.job, self.conditions)

    def reserve(self):
        self.execution_verified = True
        request = self.request()
        decision = self.driver.judgment.judge(JudgmentRequest(c.QuestionRef('r', 'j', 'a'),
            self.action, 'text', self.conditions))
        self.assertEqual(decision.decision, c.Decision.NORMAL)
        self.driver.state.begin_attempt(request, decision.decision_id, decision.state_revision)
        return request

    def test_preexecution_source_cycle_has_zero_native_and_approval_is_not_execution_proof(self):
        self.assertTrue(self.driver.guard(self.approvers))
        self.assertFalse(self.driver.guard(frozenset({999})))
        wait = self.wait()
        receipt = self.approve(wait)
        self.assertIsNotNone(receipt.approval_id)
        self.assertEqual(self.launches, [])
        self.assertEqual(self.driver.state.attempts('r'), ())
        decision = self.driver.judgment.judge(JudgmentRequest(wait.ref, self.action, 'text', self.conditions))
        self.assertEqual(decision.decision, c.Decision.UNDETERMINED)
        self.assertEqual(decision.reason, 'environment_or_protection_unproven')

    def test_programmatic_probe_returns_exact_durable_question_without_native_launch(self):
        wait, post = prepare(self.driver, job=self.job, action=self.action,
            conditions=self.conditions, method='text', request_id='probe-question', context=self.context())
        self.assertEqual(wait.deadline, '2026-10-02T00:00:00Z')
        self.assertEqual(self.driver.state.get_wait(wait.ref, wait.request_id), wait)
        self.assertEqual(post.target, self.target)
        self.assertIn('"request_id":"probe-question"', post.body)
        self.assertIn('"answer":"CHOOSE_ONE"', post.body)
        self.assertEqual(self.driver.state.history('r', 'approvals'), ())
        self.assertEqual(self.driver.state.attempts('r'), ())
        self.assertEqual(self.launches, [])

    def test_reopen_preserves_wait_and_never_recreates_outbound_action(self):
        wait = self.wait()
        action = self.driver.stage_question(wait.ref, wait.request_id, self.context())
        self.driver.close()
        self.driver = PreExecutionHumanDriver.open(self.root, **self.options())
        self.assertTrue(self.driver.guard(self.approvers))
        with self.assertRaises(DeliveryUncertain):
            self.driver.stage_question(wait.ref, wait.request_id, self.context())
        self.comment(10, action.body, 202)
        self.assertEqual(self.driver.reconcile(wait.ref, wait.request_id, 10)['status'], 'posted')
        self.assertEqual(self.launches, [])

    def test_actual_launch_claim_precedes_factory_and_never_reopens_human_ingress(self):
        wait = self.wait(); self.approve(wait)
        request = self.reserve()
        self.assertFalse(self.driver.guard(self.approvers))  # Reservation itself closes intake.
        self.assertEqual(self.driver.execute(request).status, c.OperationStatus.ACCEPTED)
        self.assertEqual(self.driver.stop(request.ref).status, c.StopStatus.UNCONFIRMED)
        with self.assertRaises(UntrustedInput):
            self.driver.receive(wait.ref, wait.request_id, 42, expected_revision=0)
        with self.assertRaises(InvalidTransition): self.driver.execute(request)
        self.assertEqual(len(self.launches), 1)
        self.driver.close()
        self.assertEqual(self.native_closes, 1)
        with self.assertRaises(UntrustedInput): PreExecutionHumanDriver.open(self.root, **self.options())

    def test_close_failure_attempts_native_cleanup_and_never_confirms_cessation(self):
        wait = self.wait(); self.approve(wait)
        request = self.reserve(); self.driver.execute(request)
        self.assertIsNone(self.driver.state.get_attempt(request.ref).stop_reply)
        self.cleanup_failure = True
        with self.assertRaises(RuntimeError) as failure: self.driver.close()
        self.assertNotIn('fixture private cleanup detail', str(failure.exception))
        self.assertEqual(self.native_closes, 1)
        self.assertEqual(json.loads((self.root / 'driver.json').read_text())['phase'], 'launch_claimed')
        with self.assertRaises(UntrustedInput): PreExecutionHumanDriver.open(self.root, **self.options())

    def test_factory_failure_remains_durably_closed_without_fake_cessation(self):
        wait = self.wait(); self.approve(wait)
        request = self.reserve(); self.factory_failure = True
        with self.assertRaises(OSError): self.driver.execute(request)
        self.assertFalse(self.driver.guard(self.approvers))
        self.assertIsNone(self.driver.state.get_attempt(request.ref).stop_reply)
        self.driver.close()
        with self.assertRaises(UntrustedInput): PreExecutionHumanDriver.open(self.root, **self.options())

    def test_existing_attempt_blocks_reopen_even_if_launch_marker_not_claimed(self):
        wait = self.wait(); self.approve(wait); self.reserve()
        self.driver.close()
        with self.assertRaises(UntrustedInput): PreExecutionHumanDriver.open(self.root, **self.options())
        self.assertEqual(self.launches, [])

    def test_preobserved_native_activity_cannot_be_adopted_as_fresh_launch(self):
        wait = self.wait(); self.approve(wait)
        request = self.reserve()
        attempt = self.driver.state.get_attempt(request.ref)
        self.driver.state.record_event(c.StatusEvent(request.ref, 'outside-native', c.State.RUNNING), attempt.revision)
        with self.assertRaises(InvalidTransition): self.driver.execute(request)
        self.assertEqual(self.launches, [])
        self.assertFalse(self.driver.guard(self.approvers))

    def test_lock_marker_and_changed_files_fail_closed(self):
        with self.assertRaises(UntrustedInput): PreExecutionHumanDriver.open(self.root, **self.options())
        (self.root / 'driver.next').write_text('interrupted')
        self.assertFalse(self.driver.guard(self.approvers))
        (self.root / 'driver.next').unlink()
        (self.root / 'driver.json').write_text('{"phase":"never_launched"}')
        self.assertFalse(self.driver.guard(self.approvers))
        self.driver.close()
        with self.assertRaises(UntrustedInput): PreExecutionHumanDriver.open(self.root, **self.options())

    def test_unknown_origin_cannot_create_fresh_guard_or_run(self):
        other = self.root.parent / 'invalid'
        with self.assertRaises(UntrustedInput):
            PreExecutionHumanDriver.create(other, intent=self.intent, origin_ref='worker-claim', **self.options())
        with self.assertRaises(UntrustedInput): PreExecutionHumanDriver.open(other, **self.options())
        self.assertEqual(self.launches, [])


if __name__ == '__main__': unittest.main()
