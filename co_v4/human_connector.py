"""Token-free bridge for an existing host-owned GitHub connector.

fetch_raw(url) is trusted transport code: it must check a successful authorized
connector invocation and return its raw REST JSON from that exact URL. A file,
model assertion, digest or this parser cannot establish acquisition provenance.
Keep this callback and bridge outside the delegated Native/Worker capabilities.
The bridge neither implements nor supplies HumanGateway's isolation_guard.

Publication is deliberately deferred. The gateway durably claims its generated
question first; the host takes the one-shot action, performs the external POST,
then acquires the posted comment through GET and calls gateway.reconcile.
Lost actions or ambiguous POST outcomes require reconciliation, never replay.
"""
from dataclasses import dataclass, field
from collections import deque
import json
from typing import Callable

from .human_gateway import ConnectorUnavailable, DeliveryUncertain, IssueTarget, question_body
from .state import UntrustedInput


LIMIT = 262144


@dataclass(frozen=True)
class QuestionPost:
    """Exact generated question for one host connector call; not an approval."""
    target: IssueTarget
    body: str = field(repr=False)


class ConnectorGitHub:
    """Same in-process issue/comment/post_question seam as GitHubREST.

    No credentials, network client, arbitrary POST, answer-construction method,
    background work or persistent outbox. GatewayJournal owns durable delivery
    claims. A reconstructed bridge never recreates an unconsumed action from a
    journal's uncertain 'sending' status. Only trusted host code may take it.
    """
    def __init__(self, target: IssueTarget, fetch_raw: Callable[[str], str]):
        if type(target) is not IssueTarget or not callable(fetch_raw):
            raise ValueError('fixed Issue target and trusted fetch callback required')
        self._target, self._fetch = target, fetch_raw
        self._deferred = set()
        self._questions = deque()

    def _target_matches(self, target):
        if target != self._target:
            raise UntrustedInput('connector Issue target mismatch')

    def _read(self, url):
        try:
            raw = self._fetch(url)
        except Exception:
            raise ConnectorUnavailable('host GitHub acquisition failed') from None
        try:
            if type(raw) is not str or len(raw.encode('utf-8')) > LIMIT:
                raise ValueError('bounded raw JSON required')
            def unique(pairs):
                value = {}
                for key, child in pairs:
                    if key in value:
                        raise ValueError('duplicate source field')
                    value[key] = child
                return value
            def invalid_constant(_):
                raise ValueError('invalid JSON constant')
            value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
            if type(value) is not dict or value.get('url') != url:
                raise ValueError('exact REST source URL required')
            return value
        except Exception:
            raise UntrustedInput('invalid raw GitHub source') from None

    def issue(self, target):
        self._target_matches(target)
        source = self._read(target.api_url)
        try:
            value = {key: source[key] for key in ('number', 'url', 'state')}
            if 'pull_request' in source:
                value['pull_request'] = {}  # Preserve PR detection, omit unrelated metadata.
            return value
        except KeyError:
            raise UntrustedInput('incomplete GitHub Issue source') from None

    def comment(self, target, comment_id):
        self._target_matches(target)
        if type(comment_id) is not int or comment_id < 1:
            raise ValueError('exact comment ID required')
        url = f'https://api.github.com/repos/{target.repository}/issues/comments/{comment_id}'
        source = self._read(url)
        try:
            # Preserve exact source values; Gateway owns identity/time/body checks.
            value = {key: source[key] for key in
                     ('id', 'issue_url', 'created_at', 'updated_at', 'body')}
            value['user'] = {key: source['user'][key] for key in ('id', 'type')}
            return value
        except (KeyError, TypeError):
            raise UntrustedInput('incomplete GitHub comment source') from None

    def post_question(self, target, body):
        self._target_matches(target)
        try:
            if type(body) is not str or len(body.encode('utf-8')) > LIMIT:
                raise ValueError('bounded generated question required')
            presentation = json.loads(body.split('```json\n', 1)[1].split('\n```', 1)[0])
            if (presentation['schema'] != 'co.human-question.v1'
                    or presentation['reply_to'] != target.url
                    or not isinstance(presentation['request_id'], str)
                    or not presentation['request_id']
                    or question_body(presentation) != body):
                raise ValueError('generated question mismatch')
            identity = tuple(presentation[key] for key in
                             ('run_id', 'job_id', 'attempt_id', 'request_id'))
            if (any(type(value) is not str or not value for value in
                    (identity[0], identity[1], identity[3]))
                    or (identity[2] is not None and
                        (type(identity[2]) is not str or not identity[2]))):
                raise ValueError('exact question identity required')
        except Exception:
            raise UntrustedInput('only an exact generated Human question may be deferred') from None
        if identity in self._deferred:
            raise DeliveryUncertain('question already deferred; reconcile before retry')
        self._questions.append(QuestionPost(target, body))
        self._deferred.add(identity)
        raise DeliveryUncertain('question deferred to host connector; readback required')

    def take_question(self) -> QuestionPost | None:
        """Consume once; this does not assert publication or permit a retry.

        The host must serialize this with gateway/state operations, recheck the
        actual guard and question validity before dispatch, send exactly this
        body, then reconcile the authenticated readback. Do not pass to Worker.
        """
        return self._questions.popleft() if self._questions else None
