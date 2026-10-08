"""Synthetic HTTP/SMTP fixtures + real local ControlStore; no live delivery."""
from copy import deepcopy
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import sqlite3
import unittest

from co_v4 import contracts as c
from co_v4.human_gateway import (ConnectorUnavailable, DeliveryUncertain, GatewayJournal,
    GitHubREST, HumanGateway, IssueTarget, QuestionContext, SMTPNotification, question_body)
from co_v4.state import Conflict, ControlStore, InvalidTransition, UntrustedInput
from co_v4.trace import PublicationBlocked, PublicationPolicy, Trace, Link, canonical, digest
from co_v4.waiting import WaitingService, wait_link
from test_state import Harness


class Response(io.BytesIO):
    def __init__(self, value, status=200):
        super().__init__(canonical(value).encode()); self.status = status


class FixtureHTTP:
    """Exercises actual Request method/path/JSON handling in GitHubREST."""
    def __init__(self):
        self.comments = {}
        self.calls = []
        self.fail_post = False
        self.next_question = 10
        self.fail_read = False
        self.target = IssueTarget('fixture/co', 160)
        self.issue = {'number': 160, 'url': self.target.api_url, 'state': 'open'}
        self.template = json.loads((Path(__file__).parent / 'fixtures/human_comment.json').read_text())

    def add(self, comment_id, body, user=101, **changes):
        value = deepcopy(self.template)
        value.update(id=comment_id, body=body, **changes)
        value['user']['id'] = user
        self.comments[comment_id] = value
        return value

    def open(self, request, timeout):
        self.calls.append((request.method, request.full_url))
        if request.full_url == self.target.api_url and request.method == 'GET':
            return Response(self.issue)
        if request.full_url == self.target.api_url + '/comments' and request.method == 'POST':
            assert request.get_header('Authorization') == 'Bearer fixture-transport-only'
            value = self.add(self.next_question, json.loads(request.data)['body'], user=202)
            self.next_question += 1
            if self.fail_post:
                raise OSError('simulated lost response: secret=do-not-log')
            return Response(value, 201)
        if '/issues/comments/' in request.full_url and request.method == 'GET':
            if self.fail_read: raise OSError('secret=transport-error')
            return Response(self.comments[int(request.full_url.rsplit('/', 1)[1])])
        raise AssertionError('unexpected fixture request')


class FixtureSMTP:
    debuglevel = 0
    def __init__(self):
        self.messages = []; self.fail = False; self.refused = {}
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def send_message(self, message, **envelope):
        self.messages.append((message, envelope))
        if self.fail: raise OSError('secret=mail-error')
        return self.refused


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.h = Harness(self.tmp.name); self.h.job()
        self.policy = PublicationPolicy(lambda value: True)  # Synthetic release authority.
        self.trace = Trace(Path(self.tmp.name) / 'trace.sqlite', self.policy)
        self.journal = GatewayJournal(Path(self.tmp.name) / 'gateway.sqlite')
        self.http = FixtureHTTP(); self.smtp = FixtureSMTP()
        self.rest = GitHubREST(lambda: 'fixture-transport-only', opener=self.http)
        self.mail = SMTPNotification(lambda: self.smtp, sender='sender@example.invalid',
                                     self_recipient='self@example.invalid')
        self.isolated = True  # Synthetic fixture; never a host-isolation claim.
        # Composition uses separate existing initial-intake and GitHub resolvers.
        # Reopen state through the public constructor, never patch its internals.
        self.h.store.close()
        self.h.store = ControlStore(self.h.path, verifier=self.verify,
            evidence=self.h.evidence, clock=lambda: self.h.now)
        self.h.refresh()
        self.build()
        self.context = QuestionContext('Fixture write requested', 'Review exact target',
                                       'Write requires confirmation', 'Creates fixture output')

    def verify(self, source):
        if source.startswith('github:'): return self.journal.verifier(source)
        return self.h.receipts[source]

    def build(self, guard=None):
        self.gateway = HumanGateway(self.h.ctrl, self.h.intake, self.journal,
            self.rest, self.mail, self.trace, target=self.http.target,
            approver_ids=frozenset({101}), publisher_id=202,
            isolation_guard=(guard if guard is not None else
                             lambda approvers: self.isolated and approvers == frozenset({101})),
            clock=lambda: self.h.now)
        self.waiting = WaitingService(self.h.ctrl, self.h.store.scheduler(),
                                     clock=lambda: self.h.now, trace=self.trace)

    def tearDown(self):
        self.h.store.close(); self.trace.close(); self.journal.close(); self.tmp.cleanup()

    def publish(self, attempt=None, name='q', action=None):
        wait = self.h.wait(name, attempt, action)
        self.gateway.publish(wait.ref, wait.request_id, self.context)
        return wait

    def comment(self, wait, answer='approve', comment_id=42, **changes):
        publication = self.journal.publication(wait_link(wait.ref, wait.request_id))
        value = dict(schema='co.human-response.v1', request_id=wait.request_id,
                     presentation_digest=digest(publication['presentation']), answer=answer,
                     detail='Use a different approach' if answer == 'instruct' else '')
        value.update(changes)
        return self.http.add(comment_id, canonical(value))

    def receive(self, wait, comment_id=42, revision=None):
        return self.gateway.receive(wait.ref, wait.request_id, comment_id,
                expected_revision=self.h.rev() if revision is None else revision)

    def test_exact_presentation_and_outbound_only_mail(self):
        w = self.publish()
        presentation = self.journal.publication(wait_link(w.ref, w.request_id))['presentation']
        self.assertEqual(presentation['target'], c.approval_target('r', self.h.action))
        self.assertIsNone(presentation['attempt_id'])
        for field in ('background','rationale','recommendation','expected_effect','deadline','reply_to'):
            self.assertTrue(presentation[field])
        self.assertIn('equal execution conditions', presentation['reuse_conditions'])
        self.assertEqual(self.gateway.notify(w.ref, w.request_id), 'transport_accepted')
        self.assertEqual(len(self.smtp.messages), 1)
        message, envelope = self.smtp.messages[0]
        self.assertEqual(envelope['to_addrs'], ['self@example.invalid'])
        self.assertIn('Notification only', message.get_content())
        self.assertIn(w.deadline, message.get_content())
        self.assertFalse(hasattr(self.mail, 'receive'))
        self.assertEqual(self.h.ctrl.history('r','approvals'), ())
        self.assertNotIn('example.invalid', self.trace.jsonl())

    def test_approve_is_recorded_and_requires_new_judgment(self):
        w = self.publish(); self.comment(w)
        receipt = self.receive(w)
        self.assertEqual(receipt.disposition, 'applied')
        self.assertIsNotNone(receipt.approval_id)
        self.assertEqual(self.h.ctrl.get_run('r').state, c.State.PENDING)
        self.assertEqual(self.h.judgment.judge(self.h.request()).decision, c.Decision.NORMAL)
        changed = replace(self.h.conditions, environment_ref='different')
        self.assertNotEqual(self.h.judgment.judge(self.h.request(conditions=changed)).decision, c.Decision.NORMAL)

    def test_reject_instruct_stop_remain_distinct(self):
        for answer in ('reject','instruct','stop_run'):
            with self.subTest(answer=answer):
                # Independent fresh runs prevent old refusals affecting a later case.
                if answer != 'reject':
                    self.tearDown(); self.setUp()
                w = self.publish(); self.comment(w, answer)
                result = self.receive(w)
                self.assertIsNone(result.approval_id)
                run = self.h.ctrl.get_run('r')
                self.assertEqual(run.stop_requested, answer == 'stop_run')
                self.assertEqual(bool(run.human_instructions), answer == 'instruct')
                self.assertEqual(bool(self.h.ctrl.history('r','rejections')), answer == 'reject')

    def test_stop_run_latches_without_inventing_native_cessation(self):
        self.h.begin(); w=self.publish('a'); self.comment(w,'stop_run')
        self.receive(w)
        attempt=self.h.ctrl.get_attempt(c.AttemptRef('r','j','a'))
        self.assertTrue(self.h.ctrl.get_run('r').stop_requested)
        self.assertIsNone(attempt.result); self.assertIsNone(attempt.stop_reply)
        self.assertEqual(self.h.ctrl.history('r','approvals'),())
        answer=next(r for r in self.trace.records() if r['kind']=='human_response')
        self.assertEqual(answer['summary']['next_step'],'request_native_stop_and_verify_cessation')

    def test_response_replay_restart_and_edited_comment(self):
        w = self.publish(); self.comment(w); first = self.receive(w)
        self.journal.close(); self.journal = GatewayJournal(Path(self.tmp.name) / 'gateway.sqlite')
        self.h.store.close()
        self.h.store = ControlStore(self.h.path, verifier=self.verify,
            evidence=self.h.evidence, clock=lambda: self.h.now)
        self.h.refresh(); self.build()
        self.assertEqual(self.receive(w, revision=-1), first)
        self.assertEqual(len(self.h.ctrl.history('r','answers')), 1)
        self.http.comments[42]['body'] = self.http.comments[42]['body'].replace('approve','reject')
        with self.assertRaises(Conflict): self.receive(w)
        self.assertEqual(len(self.h.ctrl.history('r','approvals')), 1)

    def test_multiple_questions_in_same_attempt_cannot_cross_answer(self):
        self.h.begin(); first=self.publish('a')
        other=c.Action('filesystem.write', c.Scope((('path','/fixture/other'),),True))
        second=self.publish('a',name='q2',action=other)
        self.comment(first)
        with self.assertRaises(Conflict): self.receive(second)
        self.assertEqual(self.receive(first).disposition,'applied')
        self.comment(second,comment_id=43)
        self.assertEqual(self.receive(second,43).disposition,'applied')
        self.assertEqual(len(self.h.ctrl.history('r','approvals')),2)

    def test_fixture_resume_relay_result_and_separate_ac(self):
        from fixture_adapter import FixtureAdapter
        from co_v4.trace import Link
        native=FixtureAdapter(self.h.action)
        attempt=self.h.begin()
        request=c.ExecuteRequest(attempt.ref,self.h.ctrl.get_job('r','j'),self.h.conditions)
        started=native.execute(request)
        for event in native.events(attempt.ref): self.h.event(event)
        callback=native.confirmation
        self.h.confirm=True
        judgment_request=self.h.request(attempt='a',confirmation=callback)
        decision=self.h.judgment.judge(judgment_request)
        self.trace.record_judgment(decision,at=self.h.now,links=(Link('native','fixture:callback'),))
        w=self.waiting.open(judgment_request.ref,callback.request_id,self.h.action,
            decision.decision,decision.reason,judgment_request.method,
            expected_revision=self.h.rev(),judgment_ref=decision.decision_id)
        self.gateway.publish(w.ref,w.request_id,self.context)
        self.comment(w); self.receive(w)
        self.assertEqual(native.effects,[])  # Gateway does not execute or resume.
        decision=self.h.judgment.judge(judgment_request)
        self.assertEqual(decision.decision,c.Decision.NORMAL)
        relay=c.ConfirmationResponse(attempt.ref,w.request_id,w.action,c.Resolution.ALLOW,decision.decision_id)
        self.h.ctrl.validate_relay(relay)
        self.assertEqual(native.resume(started.resume_state).status,c.OperationStatus.ACCEPTED)
        self.assertEqual(native.respond(relay).status,c.OperationStatus.ACCEPTED)
        # Only new Native events are collected; state keeps the original wait.
        for event in native.events(attempt.ref,after='2'): self.h.event(event)
        completed=self.h.ctrl.get_attempt(attempt.ref)
        ac=c.ACRecord(attempt.ref,'fail',('fixture:independent-check',))
        self.h.ctrl.record_ac(ac,completed.revision)
        self.trace.record_result('fixture:result',completed.result,at=self.h.now,
            links=(Link('judgment',decision.decision_id),))
        self.trace.record_ac('fixture:ac',ac,at=self.h.now,result_ref='fixture:result')
        self.assertEqual(self.h.ctrl.get_attempt(attempt.ref).result.status,c.State.COMPLETED)
        self.assertEqual(len(native.effects),1)
        self.assertNotIn('fixture-secret',self.trace.jsonl())

    def test_other_comment_cannot_answer_closed_question(self):
        w = self.publish(); self.comment(w); self.receive(w)
        self.comment(w, comment_id=43)
        with self.assertRaises(Conflict): self.receive(w, 43)
        self.assertEqual(len(self.h.ctrl.history('r','answers')), 1)

    def test_late_response_and_timeout_do_not_resurrect_attempt(self):
        self.h.begin(); w = self.publish('a'); self.comment(w)
        self.h.now = '2026-09-29T00:00:00.000001Z'
        result = self.receive(w)
        self.assertEqual(result.disposition, 'late'); self.assertIsNone(result.approval_id)
        attempt = self.h.ctrl.get_attempt(c.AttemptRef('r','j','a'))
        # The timeout is a wait fact, never a fabricated Result: no Result,
        # StopReply or ended_at appears and the Attempt is not resurrected.
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.stop_reply)
        self.assertIsNone(attempt.ended_at)
        self.assertEqual(self.h.ctrl.history('r','rejections'), ())
        self.assertEqual(len(self.h.ctrl.history('r','timeouts')), 1)
        self.assertNotEqual(self.h.judgment.judge(self.h.request()).decision, c.Decision.NORMAL)

    def test_late_stop_trace_requests_native_stop(self):
        self.h.begin(); wait = self.publish('a')
        self.comment(wait, answer='stop_run')
        self.h.now = '2026-09-29T00:00:00.000001Z'
        receipt = self.receive(wait)
        self.assertEqual(receipt.disposition, 'late')
        self.assertTrue(self.h.ctrl.get_run('r').stop_requested)
        record = next(r for r in self.trace.records() if r['kind'] == 'human_response')
        self.assertEqual(record['summary']['next_step'], 'request_native_stop_and_verify_cessation')
        self.assertIsNone(receipt.approval_id)
        self.assertEqual(self.receive(wait, revision=-1), receipt)

    def test_committed_receipt_survives_cas_conflict_past_deadline(self):
        w = self.publish(); self.comment(w)
        self.h.now = '2026-09-28T23:59:59.999999Z'
        with self.assertRaises(Conflict): self.receive(w, revision=-1)
        self.journal.close(); self.journal = GatewayJournal(Path(self.tmp.name) / 'gateway.sqlite')
        self.h.store.close()
        self.h.store = ControlStore(self.h.path, verifier=self.verify,
            evidence=self.h.evidence, clock=lambda: self.h.now)
        self.h.refresh(); self.build()
        self.h.now = '2026-09-29T01:00:00Z'
        self.assertIsNone(self.waiting.expire(w.ref, w.request_id, expected_revision=self.h.rev()))
        self.assertEqual(self.receive(w).disposition, 'applied')
        self.assertEqual(len(self.h.ctrl.history('r', 'approvals')), 1)
        self.assertEqual(self.receive(w, revision=-1).disposition, 'applied')
        records = [r for r in self.trace.records() if r['kind'] == 'human_response']
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['summary']['response_at'], self.http.comments[42]['created_at'])
        self.assertEqual(records[0]['summary']['received_at'], '2026-09-28T23:59:59.999999Z')
        self.assertEqual(records[0]['summary']['deadline_at'], w.deadline)

    def test_source_evidence_without_control_receipt_cannot_hold_deadline(self):
        w = self.publish(); self.comment(w)
        original = self.h.intake.record_receipt
        def unavailable(*args):
            raise OSError('fixture control receipt unavailable')
        self.h.intake.record_receipt = unavailable
        with self.assertRaises(OSError): self.receive(w)
        self.h.intake.record_receipt = original
        self.assertEqual(self.h.ctrl.history('r', 'human_receipts'), ())
        self.h.now = w.deadline
        self.waiting.expire(w.ref, w.request_id, expected_revision=self.h.rev())
        self.h.now = '2026-09-29T00:00:00.000001Z'
        self.assertEqual(self.receive(w).disposition, 'late')
        record = next(r for r in self.trace.records() if r['kind'] == 'human_response')
        self.assertEqual(record['summary']['received_at'], self.h.now)
        self.assertLess(record['summary']['response_at'], w.deadline)
        self.assertEqual(self.h.ctrl.history('r', 'approvals'), ())

    def test_wrong_actor_issue_request_scope_and_question_edit(self):
        w = self.publish(); original = deepcopy(self.comment(w))
        variants = [dict(user={'id':999,'login':'fixture-human','type':'User'}),
                    dict(issue_url='https://api.github.com/repos/other/repo/issues/160'),
                    dict(updated_at='2026-09-28T00:00:01Z'),
                    dict(user={'id':101,'type':'Bot'}),
                    dict(created_at='2026-09-29T00:00:00Z',updated_at='2026-09-29T00:00:00Z')]
        for change in variants:
            self.http.comments[42] = dict(deepcopy(original), **change)
            with self.assertRaises(UntrustedInput): self.receive(w)
        for field, value in [('request_id','other'),('presentation_digest','different')]:
            self.comment(w, **{field:value})
            with self.assertRaises(Conflict): self.receive(w)
        self.comment(w)
        self.http.comments[10]['body'] += '\nchanged target'
        with self.assertRaises(Conflict): self.receive(w)
        self.assertEqual(self.h.ctrl.history('r','answers'), ())

    def test_unverified_isolation_fails_closed(self):
        w = self.h.wait(); self.isolated = False
        with self.assertRaises(UntrustedInput): self.gateway.publish(w.ref,w.request_id,self.context)
        self.assertEqual(self.http.calls, [])
        self.isolated = True; self.gateway.publish(w.ref,w.request_id,self.context); self.comment(w)
        self.isolated = False
        with self.assertRaises(UntrustedInput): self.receive(w)
        with self.assertRaises(UntrustedInput): self.gateway.notify(w.ref,w.request_id)

    def test_guard_rejects_truthy_claims_before_any_operation(self):
        w = self.h.wait()
        for value in (False, None, 1, 'true', {'verified': True}):
            with self.subTest(value=value):
                calls = []
                def guard(approvers):
                    calls.append(approvers)
                    return value
                self.build(guard)
                operations = (
                    lambda: self.gateway.publish(w.ref, w.request_id, self.context),
                    lambda: self.gateway.reconcile(w.ref, w.request_id, 10),
                    lambda: self.gateway.notify(w.ref, w.request_id),
                    lambda: self.receive(w),
                )
                for operation in operations:
                    with self.assertRaises(UntrustedInput): operation()
                self.assertEqual(calls, [frozenset({101})] * 4)
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.smtp.messages, [])
        self.assertIsNone(self.journal.publication(wait_link(w.ref, w.request_id)))
        self.assertEqual(self.h.ctrl.history('r', 'answers'), ())
        self.assertEqual(self.trace.records(), ())

    def test_guard_failure_after_publication_is_rechecked_without_side_effects(self):
        calls = []
        def guard(approvers):
            calls.append(approvers)
            if not self.isolated:
                raise RuntimeError('private host diagnostic')
            return approvers == frozenset({101})
        self.build(guard)
        w = self.publish(); self.comment(w)
        before_http, before_trace = list(self.http.calls), self.trace.records()
        before_publication = self.journal.publication(wait_link(w.ref, w.request_id))
        calls.clear()
        self.isolated = False
        for operation in (
            lambda: self.gateway.publish(w.ref, w.request_id, self.context),
            lambda: self.gateway.reconcile(w.ref, w.request_id, 10),
            lambda: self.gateway.notify(w.ref, w.request_id),
            lambda: self.receive(w),
        ):
            with self.assertRaises(UntrustedInput) as failure: operation()
            self.assertNotIn('private host diagnostic', str(failure.exception))
        self.assertEqual(calls, [frozenset({101})] * 4)
        self.assertEqual(self.http.calls, before_http)
        self.assertEqual(self.trace.records(), before_trace)
        self.assertEqual(self.journal.publication(wait_link(w.ref, w.request_id)), before_publication)
        self.assertEqual(self.smtp.messages, [])
        self.assertEqual(self.h.ctrl.history('r', 'answers'), ())

    def test_strict_response_schema(self):
        w = self.publish(); self.comment(w)
        valid = self.http.comments[42]['body']
        invalid = ['approve', '```json\n'+valid+'\n```', valid[:-1]+',"answer":"reject"}',
                   valid[:-1]+',"origin":"human"}', valid.replace('"detail":""','"detail":null'),
                   valid.replace('"approve"','"instruct"')]
        for raw in invalid:
            self.http.comments[42]['body'] = raw
            with self.assertRaises(UntrustedInput): self.receive(w)
        self.assertEqual(self.h.ctrl.history('r','approvals'), ())

    def test_unknown_scope_can_be_asked_but_never_approved(self):
        action = c.Action('filesystem.write', c.Scope((('path',None),)))
        w = self.publish(action=action); self.comment(w)
        with self.assertRaises(UntrustedInput): self.receive(w)
        self.assertIsNone(self.journal.publication(wait_link(w.ref,w.request_id))['presentation']['target']['scope']['path'])

    def test_duplicate_publication_and_notification_never_resend(self):
        w = self.publish(); self.gateway.notify(w.ref,w.request_id)
        self.gateway.publish(w.ref,w.request_id,self.context)
        self.gateway.notify(w.ref,w.request_id)
        self.assertEqual(sum(method == 'POST' for method, _ in self.http.calls),1)
        self.assertEqual(len(self.smtp.messages),1)
        with self.assertRaises(Conflict):
            self.gateway.publish(w.ref,w.request_id,replace(self.context,background='changed'))

    def test_non_smtp_transport_acceptance_survives_restart_without_resend(self):
        class OfficialTransportFixture:
            def __init__(self): self.messages = []
            def send(self, *, body, message_key):
                self.messages.append((body, message_key))
        self.mail = OfficialTransportFixture()
        self.build()
        w = self.publish()
        key = wait_link(w.ref, w.request_id)
        self.assertEqual(self.gateway.notify(w.ref, w.request_id), 'transport_accepted')
        self.assertEqual(self.mail.messages, [(question_body(self.journal.publication(key)['presentation']), key)])
        self.journal.close()
        self.journal = GatewayJournal(Path(self.tmp.name) / 'gateway.sqlite')
        self.build()
        before = self.trace.records()
        self.assertEqual(self.gateway.notify(w.ref, w.request_id), 'transport_accepted')
        self.assertEqual(len(self.mail.messages), 1)
        self.assertEqual(self.trace.records(), before)
        self.assertEqual(before[-1]['summary'],
                         {'email': 'transport_accepted', 'inbox_delivery': 'unverified'})
        self.comment(w)
        self.assertEqual(self.receive(w).disposition, 'applied')

    def test_legacy_smtp_receipt_replays_without_rewriting_trace_or_resending(self):
        w = self.publish()
        key = wait_link(w.ref, w.request_id)
        # Construct an on-disk journal and trace produced by the old release.
        at = '2026-01-01T00:00:00Z'
        with sqlite3.connect(Path(self.tmp.name) / 'gateway.sqlite') as db:
            db.execute("UPDATE publications SET email_status='smtp_accepted',email_at=? WHERE id=?", (at, key))
        self.trace.append('email:' + key, 'notification', w.ref, at=at,
            summary={'email': 'smtp_accepted', 'inbox_delivery': 'unverified'},
            links=(Link('notification', 'notification:' + key),))
        before = self.trace.records()
        self.assertEqual(self.gateway.notify(w.ref, w.request_id), 'smtp_accepted')
        self.assertEqual(self.trace.records(), before)
        self.assertEqual(self.smtp.messages, [])
        self.assertEqual(self.journal.publication(key)['email_status'], 'smtp_accepted')

    def test_lost_post_response_requires_reconciliation(self):
        w = self.h.wait(); self.http.fail_post = True
        with self.assertRaises(DeliveryUncertain): self.gateway.publish(w.ref,w.request_id,self.context)
        with self.assertRaises(DeliveryUncertain): self.gateway.publish(w.ref,w.request_id,self.context)
        self.assertEqual(sum(method == 'POST' for method, _ in self.http.calls),1)
        self.assertEqual(self.gateway.reconcile(w.ref,w.request_id,10)['status'],'posted')
        self.comment(w); self.assertEqual(self.receive(w).disposition,'applied')

    def test_uncertain_mail_is_not_resent_or_used_for_approval(self):
        w = self.publish(); self.smtp.fail = True
        with self.assertRaises(DeliveryUncertain) as failure: self.gateway.notify(w.ref,w.request_id)
        self.assertNotIn('mail-error',str(failure.exception))
        with self.assertRaises(DeliveryUncertain): self.gateway.notify(w.ref,w.request_id)
        self.assertEqual(len(self.smtp.messages),1)
        self.comment(w); self.assertEqual(self.receive(w).disposition,'applied')

    def test_secret_target_context_detail_and_transport_errors_never_publish(self):
        action = c.Action('filesystem.write',c.Scope((('path','/tmp/token=hidden'),),True))
        w = self.h.wait(action=action)
        with self.assertRaises(PublicationBlocked): self.gateway.publish(w.ref,w.request_id,self.context)
        self.assertEqual(self.http.calls,[])
        # Use a new question, preserving the rejected target's authoritative state.
        w = self.publish(name='safe')
        self.comment(w,detail='password=hidden')
        with self.assertRaises(PublicationBlocked): self.receive(w)
        self.http.fail_read=True
        with self.assertRaises(ConnectorUnavailable) as failure: self.receive(w)
        self.assertNotIn('transport-error',str(failure.exception))
        self.assertNotIn('hidden',self.trace.jsonl())
        self.assertEqual(self.h.ctrl.history('r','answers'),())

    def test_closed_or_expired_question_does_not_send_new_notification(self):
        w = self.publish(); self.comment(w); self.receive(w)
        with self.assertRaises(Conflict): self.gateway.notify(w.ref,w.request_id)
        self.assertEqual(self.smtp.messages,[])

    def test_dedicated_target_validation_and_pr_rejection(self):
        for repository in ('../escape/repo','repo','a/b?token=x'):
            with self.assertRaises(ValueError): IssueTarget(repository,160)
        for number in (True,0,'160'):
            with self.assertRaises(ValueError): IssueTarget('fixture/co',number)
        w=self.h.wait(); self.http.issue['pull_request']={}
        with self.assertRaises(UntrustedInput): self.gateway.publish(w.ref,w.request_id,self.context)
        self.assertFalse(any(method == 'POST' for method,_ in self.http.calls))

    def test_independent_journal_connections_claim_once_and_bind_immutable_source(self):
        second=GatewayJournal(Path(self.tmp.name)/'gateway.sqlite')
        try:
            self.assertTrue(self.journal.claim('key',{'fixture':1}))
            self.assertFalse(second.claim('key',{'fixture':1}))
            with self.assertRaises(Conflict): second.claim('key',{'fixture':2})
            self.journal.posted('key',10)
            with self.assertRaises(Conflict): second.posted('key',11)
            self.assertEqual(second.publication('key')['comment_id'],10)
            self.assertTrue(second.claim_email('key',self.h.now))
            self.assertFalse(self.journal.claim_email('key',self.h.now))
        finally:
            second.close()

    def test_response_committed_before_trace_failure_recovers_without_reapplication(self):
        w=self.publish(); self.comment(w)
        original=self.trace.append
        def fail(*args,**kwargs): raise OSError('fixture trace unavailable')
        self.trace.append=fail
        with self.assertRaises(OSError): self.receive(w)
        self.assertEqual(len(self.h.ctrl.history('r','answers')),1)
        self.trace.append=original
        self.assertEqual(self.receive(w,revision=-1).disposition,'applied')
        self.assertEqual(len(self.h.ctrl.history('r','answers')),1)
        self.assertEqual(len([r for r in self.trace.records() if r['kind']=='human_response']),1)

    def test_question_markdown_cannot_replace_exact_scope(self):
        action=c.Action('filesystem.write',c.Scope((('path','/fixture/```<details>'),),True))
        w=self.publish(action=action)
        body=self.http.comments[10]['body']
        encoded=body.split('```json\n',1)[1].split('\n```',1)[0]
        self.assertEqual(json.loads(encoded)['target'],c.approval_target('r',action))
        self.assertNotIn('<details>',body)
        self.assertEqual(body.count('```'),2)

    def test_smtp_debug_and_refusal_are_sanitized(self):
        self.smtp.debuglevel=1
        with self.assertRaises(ConnectorUnavailable): self.mail.send(body='fixture',message_key='one')
        self.assertEqual(self.smtp.messages,[])
        self.smtp.debuglevel=0; self.smtp.refused={'self@example.invalid':(550,b'secret=hidden')}
        with self.assertRaises(ConnectorUnavailable) as failure: self.mail.send(body='fixture',message_key='one')
        self.assertNotIn('example.invalid',str(failure.exception))


if __name__ == '__main__': unittest.main()
