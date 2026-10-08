"""GitHub decision channel and outbound-only notification boundary.

Only trusted host composition may construct this gateway, its journal, connector,
release checker and isolation guard. A Worker/model must never receive these
handles or credentials. No environment credentials are discovered here. Network
IO occurs only on explicit publish/notify/receive calls, never at construction.
"""
from dataclasses import dataclass
from email.message import EmailMessage
import json
import re
import sqlite3
from typing import Protocol
from urllib.request import Request, build_opener, HTTPRedirectHandler

from . import contracts as c
from .state import Conflict, IngressReceipt, UntrustedInput, body_digest
from .trace import Link, canonical, digest
from .waiting import utc, timestamp, wait_link


class ConnectorUnavailable(Exception): pass
class DeliveryUncertain(Exception): pass


@dataclass(frozen=True)
class IssueTarget:
    repository: str
    number: int

    def __post_init__(self):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', self.repository):
            raise ValueError('exact GitHub repository required')
        if type(self.number) is not int or self.number < 1:
            raise ValueError('dedicated Issue number required')

    @property
    def api_url(self):
        return f'https://api.github.com/repos/{self.repository}/issues/{self.number}'

    @property
    def url(self):
        return f'https://github.com/{self.repository}/issues/{self.number}'


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ConnectorUnavailable('GitHub redirect refused')


class GitHubREST:
    """Real bounded REST client. Token callback belongs to the existing host auth.

    The optional opener is a test/host transport boundary, not untrusted input.
    No retries of POSTs, redirects, error-body logging or auth/provider changes.
    """
    def __init__(self, token, *, opener=None, timeout=20):
        self._token = token
        self._opener = opener or build_opener(_NoRedirect())
        self._timeout = timeout

    def _request(self, method, path, payload=None):
        try:
            request = Request('https://api.github.com' + path, method=method,
                data=None if payload is None else canonical(payload).encode(),
                headers={'Authorization': 'Bearer ' + self._token(),
                         'Accept': 'application/vnd.github+json',
                         'Content-Type': 'application/json',
                         'X-GitHub-Api-Version': '2022-11-28'})
            with self._opener.open(request, timeout=self._timeout) as response:
                if response.status != (201 if method == 'POST' else 200):
                    raise ValueError('unexpected status')
                raw = response.read(262145)
                if len(raw) > 262144:
                    raise ValueError('response too large')
                result = json.loads(raw)
                if type(result) is not dict:
                    raise ValueError('object required')
                return result
        except Exception:
            raise ConnectorUnavailable('GitHub request failed; reconcile writes before retry') from None

    def issue(self, target: IssueTarget):
        return self._request('GET', f'/repos/{target.repository}/issues/{target.number}')

    def post_question(self, target: IssueTarget, body: str):
        return self._request('POST', f'/repos/{target.repository}/issues/{target.number}/comments', {'body': body})

    def comment(self, target: IssueTarget, comment_id: int):
        if type(comment_id) is not int or comment_id < 1:
            raise ValueError('comment ID required')
        return self._request('GET', f'/repos/{target.repository}/issues/comments/{comment_id}')


class NotificationTransport(Protocol):
    """Replaceable outbound transport supplied by trusted host composition.

    Use an already authorized official connection; account and recipient belong
    to host configuration, never Worker input. Return normally only after the
    transport accepts the message, not to assert inbox delivery. Failures raise;
    implementations must not retry or expose raw provider errors. message_key is
    a correlation hint, not a provider idempotency guarantee. The gateway owns
    publication checks and its durable send claim. There is no reply/approval API.
    """
    def send(self, *, body: str, message_key: str) -> None: ...


class SMTPNotification:
    """Uses an already authorized SMTP connection factory; never receives replies.

    The factory must return an authenticated TLS SMTP context manager with debug
    output disabled. Sender/recipient are trusted envelope configuration, excluded
    from trace and exceptions. SMTP acceptance is not inbox delivery evidence.
    """
    def __init__(self, connection, *, sender: str, self_recipient: str):
        for address in (sender, self_recipient):
            if not re.fullmatch(r'[^\s<>@,;]+@[^\s<>@,;]+', address):
                raise ValueError('single envelope address required')
        self._connection, self._sender, self._recipient = connection, sender, self_recipient

    def send(self, *, body: str, message_key: str):
        try:
            message = EmailMessage()
            message['From'], message['To'] = self._sender, self._recipient
            message['Subject'] = 'CO human decision requested'
            message['Message-ID'] = f'<{digest(message_key)}@co.local>'
            message.set_content(body + '\n\nNotification only. Respond on the linked GitHub Issue.\n')
            with self._connection() as smtp:
                if getattr(smtp, 'debuglevel', 0):
                    raise ValueError('SMTP debug logging is forbidden')
                refused = smtp.send_message(message, from_addr=self._sender, to_addrs=[self._recipient])
                if refused:
                    raise ValueError('SMTP recipient refused')
        except Exception:
            raise ConnectorUnavailable('SMTP outcome unconfirmed; reconcile before retry') from None


class GatewayJournal:
    """Protected local transport bookkeeping; never exports source receipts.

    State remains the decision and received_at authority. This journal stores
    presentation, delivery claims and authenticated source projections for recovery.
    Its legacy IngressReceipt.received_at is a transport authentication observation,
    not the committed CO receipt used by deadline scheduling.
    Use a protected path, distinct from Worker-visible fixtures and trace exports.
    """
    def __init__(self, path):
        self._db = sqlite3.connect(path, isolation_level=None)
        self._db.executescript('''
            CREATE TABLE IF NOT EXISTS publications (
                id TEXT PRIMARY KEY, body TEXT NOT NULL, status TEXT NOT NULL,
                comment_id INTEGER, email_status TEXT NOT NULL DEFAULT 'pending', email_at TEXT);
            CREATE TABLE IF NOT EXISTS ingress (
                id TEXT PRIMARY KEY, evidence TEXT NOT NULL, receipt TEXT NOT NULL);
        ''')

    def close(self):
        self._db.close()

    def publication(self, key):
        row = self._db.execute('SELECT body,status,comment_id,email_status,email_at FROM publications WHERE id=?', (key,)).fetchone()
        if row is None:
            return None
        return {'presentation': json.loads(row[0]), 'status': row[1],
                'comment_id': row[2], 'email_status': row[3], 'email_at': row[4]}

    def claim(self, key, presentation):
        self._db.execute('BEGIN IMMEDIATE')
        try:
            previous = self.publication(key)
            if previous:
                if previous['presentation'] != presentation:
                    raise Conflict('published question cannot change')
                result = False
            else:
                self._db.execute('INSERT INTO publications (id,body,status) VALUES (?,?,?)',
                                 (key, canonical(presentation), 'sending'))
                result = True
            self._db.execute('COMMIT')
            return result
        except BaseException:
            self._db.execute('ROLLBACK')
            raise

    def posted(self, key, comment_id):
        changed = self._db.execute(
            "UPDATE publications SET status='posted',comment_id=? "
            "WHERE id=? AND (comment_id IS NULL OR comment_id=?)",
            (comment_id, key, comment_id)).rowcount
        if changed != 1:
            raise Conflict('publication receipt mismatch')

    def claim_email(self, key, at):
        return self._db.execute("UPDATE publications SET email_status='sending',email_at=? WHERE id=? AND status='posted' AND email_status='pending'", (at, key)).rowcount == 1

    def email_accepted(self, key):
        self._db.execute("UPDATE publications SET email_status='transport_accepted' WHERE id=? AND email_status='sending'", (key,))

    def bind(self, source, evidence, receipt: IngressReceipt):
        value = canonical({'principal': receipt.principal, 'source_event': receipt.source_event,
                           'body_digest': receipt.body_digest, 'received_at': receipt.received_at})
        self._db.execute('BEGIN IMMEDIATE')
        try:
            row = self._db.execute('SELECT evidence,receipt FROM ingress WHERE id=?', (source,)).fetchone()
            if row and row[0] != canonical(evidence):
                raise Conflict('source comment changed after authentication')
            if not row:
                self._db.execute('INSERT INTO ingress VALUES (?,?,?)', (source, canonical(evidence), value))
            self._db.execute('COMMIT')
        except BaseException:
            self._db.execute('ROLLBACK')
            raise
        return self.verifier(source)

    def verifier(self, source) -> IngressReceipt:
        row = self._db.execute('SELECT receipt FROM ingress WHERE id=?', (source,)).fetchone()
        if row is None:
            raise UntrustedInput('authenticated GitHub source not found')
        return IngressReceipt(**json.loads(row[0]))


@dataclass(frozen=True)
class QuestionContext:
    background: str
    recommendation: str
    rationale: str
    expected_effect: str


def _question(wait, context, target, binding):
    return {'schema': 'co.human-question.v1', 'run_id': wait.ref.run_id,
            'job_id': wait.ref.job_id, 'attempt_id': wait.ref.attempt_id,
            'request_id': wait.request_id, 'target': c.approval_target(wait.ref.run_id, wait.action),
            'decision': wait.decision.value, 'reason': wait.reason, 'deadline': wait.deadline,
            'deadline_semantics': 'CO must authenticate, match and durably receive the answer '
                'by this deadline (inclusive). Posting time alone does not qualify. '
                'A received answer may be applied later; an ended Attempt is never revived.',
            'background': context.background, 'recommendation': context.recommendation,
            'rationale': context.rationale, 'expected_effect': context.expected_effect,
            'judgment_ref': binding.judgment_ref,
            'execution_conditions': {
                'model': binding.conditions.model, 'adapter': binding.conditions.adapter,
                'workspace': binding.conditions.workspace,
                'environment_ref': binding.conditions.environment_ref,
                'control_evidence_refs': list(binding.conditions.control_evidence_refs)},
            'reuse_conditions': 'Reuse requires equal execution conditions shown above and fresh protection evidence.',
            'reply_to': target.url}


def question_body(presentation):
    fingerprint = digest(presentation)
    # JSON escapes keep scope values exact and prevent Markdown injection.
    encoded = canonical(presentation).replace('<', '\\u003c').replace('>', '\\u003e').replace('`', '\\u0060')
    example = canonical({'schema': 'co.human-response.v1', 'request_id': presentation['request_id'],
                         'presentation_digest': fingerprint, 'answer': 'CHOOSE_ONE', 'detail': ''})
    example = example.replace('<', '\\u003c').replace('>', '\\u003e').replace('`', '\\u0060')
    return ('CO human decision requested\n\nExact target and context:\n```json\n' + encoded +
            '\n```\n\nReply with a plain JSON object (no code fence). Choose exactly one of '
            'approve, reject, instruct, stop_run. instruct requires detail. '
            'Approval always requires current rejudgment; stop_run requests cessation, '
            'it does not certify that Native stopped. Email replies have no effect.\n\n' + example)


def _parse_response(body):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate field')
            result[key] = value
        return result
    try:
        if type(body) is not str or len(body) > 16000:
            raise ValueError('invalid body')
        value = json.loads(body, object_pairs_hook=unique)
        if type(value) is not dict or set(value) != {'schema','request_id','presentation_digest','answer','detail'}:
            raise ValueError('unexpected fields')
        if not all(type(item) is str for item in value.values()) or value['schema'] != 'co.human-response.v1':
            raise ValueError('invalid response schema')
        answer = c.HumanAnswer(value['answer'])
        if answer == c.HumanAnswer.INSTRUCT and not value['detail'].strip():
            raise ValueError('instruction required')
        return value
    except Exception:
        raise UntrustedInput('invalid human response; use the displayed JSON format') from None


class HumanGateway:
    """Trusted host component. No execute/resume/stop or email response API.

    New notification receipts are transport_accepted, never proof of delivery.
    Legacy smtp_accepted receipts and their trace identities remain replayable.

    isolation_guard must freshly verify the actual delegated Worker route cannot
    impersonate the configured GitHub approvers or mutate the host-owned intake.
    Its trusted composition must account for that route's credentials, connector
    capabilities and CO state access. Native login reachability alone neither
    proves nor disproves Human GitHub impersonation. NATIVE-HANDOFF.md defines
    this route boundary; no global credential inventory or separate UID is implied.
    The callback is trusted code backed by current host evidence, never a model
    boolean or caller-provided receipt. Only exact True permits an operation;
    missing/ambiguous evidence, truthy substitutes and exceptions fail closed.
    """
    def __init__(self, controller, intake, journal, github, notifier: NotificationTransport, trace, *,
                 target: IssueTarget, approver_ids: frozenset[int], publisher_id: int,
                 isolation_guard, clock):
        if (type(approver_ids) is not frozenset or not approver_ids or any(type(i) is not int or i < 1 for i in approver_ids)
                or type(publisher_id) is not int or publisher_id < 1):
            raise ValueError('stable GitHub numeric identities required')
        self.controller, self.intake, self.journal = controller, intake, journal
        self.github, self.notifier, self.trace = github, notifier, trace
        self.target, self._approvers, self._publisher = target, approver_ids, publisher_id
        self._guard, self.clock = isolation_guard, clock

    def _isolated(self):
        try:
            verified = self._guard(self._approvers) is True
        except Exception:
            verified = False
        if not verified:
            raise UntrustedInput('Worker and human approval path isolation is unverified')

    def _issue(self):
        issue = self.github.issue(self.target)
        if (issue.get('number') != self.target.number or issue.get('url') != self.target.api_url
                or 'pull_request' in issue or issue.get('state') != 'open'):
            raise UntrustedInput('dedicated open Issue required')

    def _comment(self, comment, comment_id, *, user_ids):
        try:
            if (type(comment['id']) is not int or comment['id'] != comment_id
                    or comment['issue_url'] != self.target.api_url
                    or type(comment['user']['id']) is not int or comment['user']['id'] not in user_ids
                    or comment['user']['type'] not in ('User', 'Bot')
                    or comment['created_at'] != comment['updated_at']
                    or type(comment['body']) is not str):
                raise ValueError('comment binding')
            created = utc(comment['created_at'])
            if created > utc(self.clock()):
                raise ValueError('future comment')
            return comment
        except Exception:
            raise UntrustedInput('comment identity, Issue, or immutable source check failed') from None

    def _active(self, wait):
        if utc(self.clock()) >= utc(wait.deadline) or self.controller.get_run(wait.ref.run_id).stop_requested:
            raise Conflict('question is no longer active')
        if any(response.ref == wait.ref and response.request_id == wait.request_id
               for response, _, _ in self.controller.history(wait.ref.run_id, 'answers')):
            raise Conflict('question already has a response')
        if wait.ref.attempt_id is not None:
            ref = c.AttemptRef(wait.ref.run_id, wait.ref.job_id, wait.ref.attempt_id)
            if self.controller.get_attempt(ref).result is not None:
                raise Conflict('question Attempt is terminal')

    def publish(self, ref, request_id, context: QuestionContext):
        self._isolated()
        wait = self.controller.get_wait(ref, request_id)
        presentation = _question(wait, context, self.target,
                                 self.controller.wait_details(ref, request_id))
        self.trace.policy.check(presentation)
        key = wait_link(ref, request_id)
        old = self.journal.publication(key)
        if old and old['presentation'] != presentation:
            raise Conflict('published question cannot change')
        if old and old['status'] == 'posted':
            return self.reconcile(ref, request_id, old['comment_id'])
        self._active(wait)
        self._issue()
        if not self.journal.claim(key, presentation):
            raise DeliveryUncertain('GitHub publication needs reconciliation; do not repost')
        try:
            comment = self.github.post_question(self.target, question_body(presentation))
            return self.reconcile(ref, request_id, comment['id'])
        except Exception:
            raise DeliveryUncertain('GitHub publication needs reconciliation; do not repost') from None

    def reconcile(self, ref, request_id, comment_id):
        """After uncertain POST, a host operator supplies the observed comment ID."""
        self._isolated()
        key = wait_link(ref, request_id)
        publication = self.journal.publication(key)
        if publication is None:
            raise Conflict('no publication intent to reconcile')
        comment = self._comment(self.github.comment(self.target, comment_id), comment_id,
                                user_ids={self._publisher})
        if comment['body'] != question_body(publication['presentation']):
            raise Conflict('published question body changed')
        self.journal.posted(key, comment_id)
        self.trace.append('notification:' + key, 'notification', ref, at=comment['created_at'],
            summary={'github': 'posted', 'request_id': request_id, 'reply_to': self.target.url + f'#issuecomment-{comment_id}'},
            links=(Link('waiting', key),))
        return self.journal.publication(key)

    def notify(self, ref, request_id):
        self._isolated()
        key = wait_link(ref, request_id)
        publication = self.journal.publication(key)
        if publication is None or publication['status'] != 'posted':
            raise Conflict('publish GitHub question before notification')
        if publication['presentation']['reply_to'] != self.target.url:
            raise Conflict('notification belongs to a different target')
        if publication['email_status'] in ('smtp_accepted', 'transport_accepted'):
            self._email_trace(ref, key)
            return publication['email_status']
        self._active(self.controller.get_wait(ref, request_id))
        self.trace.policy.check(publication['presentation'])
        if not self.journal.claim_email(key, timestamp(utc(self.clock()))):
            raise DeliveryUncertain('email outcome unconfirmed; no automatic resend')
        try:
            self.notifier.send(body=question_body(publication['presentation']), message_key=key)
        except Exception:
            raise DeliveryUncertain('email outcome unconfirmed; no automatic resend') from None
        self.journal.email_accepted(key)
        self._email_trace(ref, key)
        return 'transport_accepted'

    def _email_trace(self, ref, key):
        publication = self.journal.publication(key)
        self.trace.append('email:' + key, 'notification', ref, at=publication['email_at'],
            summary={'email': publication['email_status'], 'inbox_delivery': 'unverified'},
            links=(Link('notification', 'notification:' + key),))

    def receive(self, ref, request_id, comment_id, *, expected_revision):
        self._isolated()
        wait = self.controller.get_wait(ref, request_id)
        key = wait_link(ref, request_id)
        publication = self.journal.publication(key)
        if publication is None or publication['status'] != 'posted':
            raise UntrustedInput('question has no verified GitHub publication')
        presentation = publication['presentation']
        if (presentation['target'] != c.approval_target(ref.run_id, wait.action)
                or presentation['deadline'] != wait.deadline or presentation['reply_to'] != self.target.url):
            raise Conflict('local question no longer matches published target')
        question = self._comment(self.github.comment(self.target, publication['comment_id']),
                                 publication['comment_id'], user_ids={self._publisher})
        if question['body'] != question_body(presentation):
            raise Conflict('published question changed; issue a fresh request')
        comment = self._comment(self.github.comment(self.target, comment_id), comment_id,
                                user_ids=self._approvers)
        if (comment['user']['type'] != 'User'
                or utc(comment['created_at']) < utc(question['created_at'])):
            raise UntrustedInput('human response must follow the question')
        value = _parse_response(comment['body'])
        if value['request_id'] != request_id or value['presentation_digest'] != digest(presentation):
            raise Conflict('response does not match the exact presented question')
        # Free text is never reflected into logs/notifications. Reject known
        # secret-bearing input even for the protected source evidence journal.
        self.trace.policy.check(value)
        source = f'github:{self.target.repository}:comment:{comment_id}'
        response = c.HumanResponse('response:' + digest(source), ref, request_id, wait.action,
                                   c.HumanAnswer(value['answer']), source, value['detail'])
        evidence = {'issue': self.target.api_url, 'comment_id': comment_id,
                    'principal_id': comment['user']['id'], 'created_at': comment['created_at'],
                    'updated_at': comment['updated_at'], 'response': value,
                    'source_body_digest': digest(comment['body'])}
        self.journal.bind(source, evidence,
            IngressReceipt('github:' + str(comment['user']['id']), source,
                           body_digest(response), timestamp(utc(self.clock()))))
        # The transport journal authenticates the source. Only the control-store
        # receipt is serialized with expiry and establishes CO received_at.
        receipt = self.intake.record_receipt(response, source)
        answer = self.intake.record_answer(response, source, expected_revision)
        links = [Link('waiting', key)]
        if answer.approval_id:
            links.append(Link('approval', answer.approval_id))
        self.trace.append(response.response_id, 'human_response', ref, at=receipt.received_at,
            summary={'answer': response.answer.value, 'disposition': answer.disposition,
                     'response_at': comment['created_at'], 'received_at': receipt.received_at,
                     'deadline_at': wait.deadline,
                     'request_id': request_id, 'next_step': ('request_native_stop_and_verify_cessation'
                         if response.answer == c.HumanAnswer.STOP_RUN else
                         'review_late_response' if answer.disposition == 'late' else {
                         c.HumanAnswer.APPROVE: 'rejudge_before_resume',
                         c.HumanAnswer.REJECT: 'replan_without_rejected_operation',
                         c.HumanAnswer.INSTRUCT: 'replan_with_instruction',
                         c.HumanAnswer.STOP_RUN: 'request_native_stop_and_verify_cessation',
                     }[response.answer])},
            links=tuple(links))
        return answer
