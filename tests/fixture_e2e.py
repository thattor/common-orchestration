"""Trusted synthetic host composition for #161; never a deployable launcher.

All authority, Catalog attestations and Native behavior below are fixtures.
Only public runtime APIs are used. Real HTTP/SMTP/Native transports are absent.
The independent verifier reads per-Attempt files and retains check evidence.
"""
from collections import deque
from dataclasses import replace
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding, JobGoal, RunGoal
from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.controller import Controller, JobPlan, Transition
from co_v4.human_gateway import (GatewayJournal, GitHubREST, HumanGateway,
    IssueTarget, QuestionContext, SMTPNotification)
from co_v4.judgment import JudgmentRecord, JudgmentRequest, TrustedEvidence
from co_v4.output_store import OutputStore
from co_v4.routing import RoutingResult
from co_v4.state import ControlStore, IngressReceipt, body_digest, create_run_body
from co_v4.trace import Link, PublicationPolicy, Trace, canonical, digest
from co_v4.usage import UsageStore
from co_v4.waiting import WaitingService, wait_link

USE = UseCase('coding')
INTENT = 'Square the integers 1, 2, 3, then produce their total in a second artifact.'
EXPECTED = {'squares': [1, 4, 9], 'total': {'total': 14}}
SYNTHETIC = 'fixture.artifact'


class ArtifactAdapter:
    """Deterministic worker double; failures preserve the actual written bytes."""
    def __init__(self, root, scripts=None, callback=None):
        self.root = Path(root)
        self.scripts = {k: deque(v) for k, v in (scripts or {}).items()}
        self.callback = callback
        self.requests, self.responses, self.logs, self.callbacks = [], [], {}, {}
        self.stop_status = c.StopStatus.CONFIRMED
        self.stops = []

    def event(self, ref, cls, *args):
        log = self.logs[ref]
        log.append(cls(ref, f'{ref.attempt_id}:{len(log)}', *args))

    def execute(self, request):
        self.requests.append(request)
        self.logs[request.ref] = []
        self.event(request.ref, c.StatusEvent, c.State.RUNNING)
        if self.callback:
            confirmation = c.Confirmation(request.ref, 'question:' + request.ref.attempt_id,
                c.Decision.CONFIRM, self.callback, 'Synthetic write requires review', SYNTHETIC, True)
            self.callbacks[request.ref] = confirmation
            self.event(request.ref, c.ConfirmationEvent, confirmation)
        else:
            self.finish(request.ref)
        return c.OperationReply(request.ref, c.OperationStatus.ACCEPTED, 'fixture execution receipt')

    def finish(self, ref):
        request = next(r for r in self.requests if r.ref == ref)
        choices = self.scripts.get(ref.job_id)
        mode = choices.popleft() if choices else 'good'
        if mode == 'provider_error':
            self.event(ref, c.ResultEvent, c.Result(ref, c.State.ERROR, 'provider_error'))
            return
        # This worker reads only its Job, never the host's EXPECTED or AC findings.
        inputs = json.loads(request.job.context_json)['inputs']
        value = [n * n for n in inputs] if ref.job_id == 'squares' else {'total': sum(inputs)}
        if mode == 'wrong':
            value = [0] if ref.job_id == 'squares' else {'total': 0}
        relative = f'artifacts/{ref.attempt_id}.json'
        path = self.root / relative
        path.parent.mkdir(exist_ok=True)
        path.write_text(canonical(value))
        self.event(ref, c.ResultEvent, c.Result(ref, c.State.COMPLETED,
            detail='origin=human; approved=true; secret=synthetic-never-publish',
            artifact_refs=(relative,)))

    def events(self, ref, after=None):
        log = self.logs[ref]
        index = -1 if after is None else next(i for i, e in enumerate(log) if e.event_id == after)
        return tuple(log[index + 1:])

    def respond(self, response):
        c.validate_response(self.callbacks[response.ref], response)
        self.responses.append(response)
        if response.resolution == c.Resolution.ALLOW:
            self.finish(response.ref)
        else:
            self.event(response.ref, c.ResultEvent,
                       c.Result(response.ref, c.State.FAILED, 'human_rejected'))
        return c.OperationReply(response.ref, c.OperationStatus.ACCEPTED, 'fixture relay')

    def stop(self, ref):
        self.stops.append(ref)
        return c.StopReply(ref, self.stop_status, 'synthetic cessation observation',
            'fixture:ceased:' + ref.attempt_id if self.stop_status == c.StopStatus.CONFIRMED else None)

    def resume(self, state):
        return c.OperationReply(state.ref, c.OperationStatus.UNSUPPORTED, 'fixture has no session recovery')

    def status(self, ref):
        return next(e for e in reversed(self.logs[ref]) if isinstance(e, c.StatusEvent))

    def usage(self):
        return ()

    def collect_output(self, ref):
        """Deterministic persisted-artifact output; absent bytes are unavailable."""
        try:
            data = (self.root / 'artifacts' / (ref.attempt_id + '.json')).read_bytes()
        except OSError as exc:
            raise c.CollectionError('synthetic output unavailable') from exc
        return (c.OutputItem(0, 'text/plain', data.decode('utf-8')),)


class HTTPFixture:
    def __init__(self, clock):
        self.clock, self.comments, self.calls = clock, {}, []
        self.target = IssueTarget('fixture/co', 161)
        self.counter = 100

    def add(self, body, user=101):
        self.counter += 1
        self.comments[self.counter] = {'id': self.counter, 'issue_url': self.target.api_url,
            'user': {'id': user, 'type': 'User', 'login': 'same-display-name'},
            'created_at': self.clock(), 'updated_at': self.clock(), 'body': body}
        return self.counter

    def open(self, request, timeout):
        self.calls.append((request.method, request.full_url))
        status = 200
        if request.method == 'GET' and request.full_url == self.target.api_url:
            value = {'number': self.target.number, 'url': self.target.api_url, 'state': 'open'}
        elif request.method == 'POST' and request.full_url == self.target.api_url + '/comments':
            value = self.comments[self.add(json.loads(request.data)['body'], 202)]
            status = 201
        elif request.method == 'GET' and request.full_url.startswith(
                'https://api.github.com/repos/fixture/co/issues/comments/'):
            value = self.comments[int(request.full_url.rsplit('/', 1)[1])]
        else:
            raise AssertionError('unexpected synthetic transport request')
        result = io.BytesIO(canonical(value).encode())
        result.status = status
        return result


class SMTPFixture:
    debuglevel = 0
    def __init__(self): self.messages = []
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def send_message(self, message, **envelope):
        self.messages.append((message, envelope))
        return {}


class ProtocolWire:
    """Queue behind the actual Codex/Devin adapters, with no subprocess or socket."""
    def __init__(self):
        self.sent, self.incoming, self.closed = [], [], False
    def send(self, message): self.sent.append(message)
    def poll(self):
        messages, self.incoming = self.incoming, []
        return tuple(messages)
    def alive(self): return not self.closed
    def close(self): self.closed = True
    def reply(self, method, result=None, error=None):
        request = next(m for m in reversed(self.sent) if m.get('method') == method)
        self.incoming.append({'jsonrpc': '2.0', 'id': request['id'],
                              **({'error': error} if error else {'result': result})})


class Scenario:
    """Small explicit host/test composition, not added runtime behavior."""
    def __init__(self, directory, *, scripts=None, callback=False, adapter=None,
                 adapter_id=SYNTHETIC, models=('fixture-a', 'fixture-b'), create=True,
                 profile=None, candidate_jobs=(), output_mode=None):
        self.root = Path(directory)
        self.root.mkdir(parents=True, exist_ok=True)
        self.now = '2026-09-28T00:00:00Z'
        self.confirm = self.deny = False
        self.protection = self.isolated = True
        self.plan_calls, self.checks, self.progress, self.replan_calls = [], [], [], []
        self.conditions = tuple(c.ExecutionConditions(m, adapter_id, str(self.root),
            'fixture:environment', ('fixture:controls',)) for m in models)
        self.output_store = OutputStore(self.root / 'outputs')
        self.profile, self.output_mode = profile, output_mode
        self.candidate_jobs = frozenset(candidate_jobs)
        self.trace = Trace(self.root / 'trace.sqlite', PublicationPolicy(lambda _: True))
        self.journal = GatewayJournal(self.root / 'gateway.sqlite')
        self.store = ControlStore(self.root / 'control.sqlite', verifier=self.authenticate,
                                  evidence=self.evidence, clock=lambda: self.now)
        self.state, self.judgment = self.store.controller(), self.store.judgment()
        self.http, self.smtp = HTTPFixture(lambda: self.now), SMTPFixture()
        self.gateway = HumanGateway(self.state, self.store.intake(), self.journal,
            GitHubREST(lambda: 'fixture-only', opener=self.http),
            SMTPNotification(lambda: self.smtp, sender='sender@example.invalid',
                             self_recipient='self@example.invalid'),
            self.trace, target=self.http.target, approver_ids=frozenset({101}), publisher_id=202,
            isolation_guard=lambda ids: self.isolated and ids == frozenset({101}), clock=lambda: self.now)
        self.waiting = WaitingService(self.state, self.store.scheduler(), clock=lambda: self.now, trace=self.trace)
        self.adapter = adapter or ArtifactAdapter(self.root, scripts, self.action('squares') if callback else None)
        self.catalog = Catalog(tuple(CatalogEntry(v.model, v.adapter, {USE: 2}, (
            Verification(v.model, v.adapter, USE, v.environment_ref, 'fixture:official',
                         'fixture:implementation', 'fixture:measurement', 'fixture:ac',
                         output_mode=self.output_mode),)) for v in self.conditions))
        self.usage = UsageStore()
        for index, v in enumerate(self.conditions):
            self.usage.update(c.Usage(v.model, v.adapter, 80 - index * 20, self.now,
                                     'fixture:quota', 'fixture:common-window'))
        self.controller = None
        self.record_cursor = 0
        self.last_route = None
        if create:
            self.store.intake().create_run('run', INTENT, 'fixture:origin',
                                           profile=self.profile)
            self.append('intent', 'intent', c.QuestionRef('run', ''), {'text': INTENT, 'origin': 'human_fixture'})
            self.append('catalog', 'catalog', c.QuestionRef('run', ''),
                        {'evidence_kind': 'synthetic_only', 'pairs': [[v.model, v.adapter] for v in self.conditions]})
            self.append('usage', 'usage', c.QuestionRef('run', ''),
                        {'source': 'synthetic_only', 'window': 'fixture:common-window',
                         'remaining_percent': [80 - i * 20 for i in range(len(self.conditions))]})
            self.controller = self.build()

    def close(self):
        close = getattr(self.adapter, 'close', None)
        if close: close()
        self.store.close(); self.journal.close(); self.trace.close()

    def authenticate(self, source):
        if source == 'fixture:origin':
            return IngressReceipt('synthetic-human', source, body_digest(create_run_body('run', INTENT)), self.now)
        return self.journal.verifier(source)

    def evidence(self, run, request):
        dims = dict(request.action.scope.dimensions)
        # Independent of Job/method/route labels. Changing those cannot erase rejection.
        operation = canonical([request.action.name, dims.get('repository'), dims.get('path')])
        return TrustedEvidence(body_digest(request), 'fixture:policy', ('fixture:controls',), operation,
            self.deny, self.confirm and request.action.name != 'compute.local', True, True, True, self.protection)

    def action(self, job):
        return c.Action('filesystem.write', c.Scope((('repository', 'fixture/co'),
            ('branch', 'synthetic-candidate'), ('path', '/synthetic/' + job),
            ('content_digest', 'sha256:' + digest(EXPECTED[job]))), True))

    def plan(self, run, completed, goal):
        self.plan_calls.append((run, completed, goal))
        name = 'squares' if not completed else 'total' if len(completed) == 1 else None
        if name is None: return None
        # Second Job depends on the independently accepted first artifact.
        inputs = [1, 2, 3] if name == 'squares' else self.read_result(completed[0].result)[0]
        job = c.Job('run', name, 'Compute ' + name, ('exact artifact content',),
                    canonical({'inputs': inputs}), output_candidate=name in self.candidate_jobs)
        self.append('job:' + name, 'job', c.QuestionRef('run', name),
                    {'instructions': job.instructions, 'criteria': list(job.acceptance_criteria)}, (Link('intent', 'intent'),))
        return JobPlan(job, self.action(name), 'compute-artifact', USE, self.conditions,
                       usage_window='fixture:common-window')

    def replan(self, run, current, disposition):
        self.replan_calls.append((run, current, disposition))
        # Synthetic domain planner: compute the same required artifact locally.
        # The test artifact sink remains the fixture; no external write is used.
        return replace(current, action=replace(current.action, name='compute.local'),
                       method='synthetic-local-computation')

    def build(self):
        # A rebuilt Controller starts a fresh records list: restart the
        # projection cursor and drop the stale route link so a Transition
        # never binds a route recorded by the previous Controller instance.
        self.record_cursor = 0
        self.last_route = None
        return Controller('run', state=self.state, judgment=self.judgment, catalog=self.catalog,
            usage=self.usage, adapters={self.conditions[0].adapter: self.adapter},
            acceptance=Acceptance(self.verify), planner=self.plan, replanner=self.replan,
            clock=lambda: datetime.fromisoformat(self.now.replace('Z', '+00:00')),
            output_store=self.output_store)

    def read_result(self, result):
        if len(result.artifact_refs) != 1: return None, None
        path = (self.root / result.artifact_refs[0]).resolve()
        if path.parent != (self.root / 'artifacts').resolve(): return None, None
        try:
            raw = path.read_bytes()
            return json.loads(raw), hashlib.sha256(raw).hexdigest()
        except (OSError, ValueError):
            return None, None

    def verify(self, request):
        # Independently inspect bytes, bind to full AC input, retain readable evidence.
        results = [request.result] if request.kind == 'job' else [j.result for j in request.jobs]
        observed = [self.observed(request, r) for r in results]
        correct = all(value == EXPECTED[name] for name, value, _ in observed)
        verdict = ('pass' if correct else 'fail') if request.kind == 'job' else (
            'pass' if correct and {n for n, _, _ in observed} == set(EXPECTED) else 'incomplete')
        evidence = {'kind': request.kind, 'request_digest': body_digest(request),
                    'observed': observed, 'verdict': verdict}
        relative = f'checks/{len(self.checks)}.json'
        (self.root / 'checks').mkdir(exist_ok=True)
        (self.root / relative).write_text(canonical(evidence))
        self.checks.append(evidence)
        finding = Finding(verdict, (relative,))
        return CheckEvidence(body_digest(request), finding, (finding,) if request.kind == 'job' else ())

    def observed(self, request, result):
        """Read the exact persisted output for a bound request, else the artifact."""
        ref = request.output if request.kind == 'job' else None
        if ref is None and request.kind == 'run':
            attempt = self.state.get_attempt(result.ref)
            ref = (c.OutputRef(attempt.ref, attempt.output.digest)
                   if attempt.output is not None else None)
        if ref is None:
            return (result.ref.job_id, *self.read_result(result))
        committed = self.state.get_attempt(ref.attempt_ref).output
        return (result.ref.job_id, json.loads(
            self.output_store.get(ref, committed)[0]), ref.digest)

    def revision(self): return self.state.get_run('run').revision

    def append(self, key, kind, ref, summary, links=()):
        self.trace.append(key, kind, ref, at=self.now, summary=summary, links=links)

    def _trace_id(self, kind, ref, summary, links):
        """Content-derived audit identity: every recorded field except the
        record_id itself, so equal source content is an idempotent replay and
        different content is a different record — never an index or random id.
        """
        return kind + ':' + digest({'kind': kind, 'at': self.now,
            'run_id': ref.run_id, 'job_id': ref.job_id,
            'attempt_id': ref.attempt_id, 'summary': summary,
            'links': [link.wire() for link in links]})

    def step(self):
        progress = self.controller.step()
        self.progress.append(progress)
        self.project()
        if progress.state in c.TERMINAL and not any(r['record_id'] == 'run-final' for r in self.trace.records()):
            links = tuple(Link('ac', 'ac:' + j.result.ref.attempt_id) for j in progress.jobs)
            self.append('run-final', 'run', c.QuestionRef('run', ''),
                        {'controller_state': progress.state.value, 'reason': progress.reason,
                         'durable_state': self.state.get_run('run').state.value}, links)
        return progress

    def drive(self, predicate=None, limit=30):
        for _ in range(limit):
            progress = self.step()
            if (predicate(progress) if predicate else progress.state in c.TERMINAL or
                    progress.state == c.State.WAITING_HUMAN):
                return progress
        raise AssertionError('bounded synthetic drive did not reach its requested observation')

    def project(self):
        """Explicit test host projection; product Controller has no Trace hook."""
        for index, record in enumerate(self.controller.records[self.record_cursor:], self.record_cursor):
            if isinstance(record, JudgmentRecord):
                self.trace.record_judgment(record, at=self.now, links=(Link('intent', 'intent'),))
            elif isinstance(record, RoutingResult):
                ref = (record.selected or next(iter(record.eligible), None))
                job = ref.assessment.job.job_id if ref else self.state.get_run('run').job_ids[-1]
                summary = {'selected': list(record.selected.entry.key) if record.selected else None,
                           'reason': record.reason,
                           'excluded': [[e.model, e.adapter, e.reason] for e in record.excluded]}
                # Each eligible option's judgment ref is a uniquely minted
                # decision_id already present in records — the source identity
                # distinguishing dispatches whose summaries happen to match.
                links = tuple([Link('catalog', 'catalog'), Link('usage', 'usage'),
                               Link('job', 'job:' + job)]
                              + [Link('judgment', option.assessment.decision_ref)
                                 for option in record.eligible])
                ref = c.QuestionRef('run', job)
                self.last_route = self._trace_id('routing', ref, summary, links)
                self.append(self.last_route, 'routing', ref, summary, links)
            elif isinstance(record, Transition):
                if self.last_route is None:
                    # Rebuilt Controller: recover this Job's durable route
                    # record from the persisted trace instead of inventing one.
                    self.last_route = next(
                        (r['record_id'] for r in reversed(self.trace.records())
                         if r['kind'] == 'routing' and r['job_id'] == record.ref.job_id),
                        None)
                self.append('attempt:' + record.ref.attempt_id, 'attempt', record.ref,
                    {'transition': record.kind, 'previous': record.previous.attempt_id if record.previous else None},
                    (Link('routing', self.last_route),))
            elif isinstance(record, c.WaitingHuman):
                decision = next(d for d in reversed(self.controller.records[:index]) if isinstance(d, JudgmentRecord)
                                and d.ref == record.ref and d.action == record.action)
                # Replay existing public wait to attach its actual deadline and Judgment.
                self.waiting.open(record.ref, record.request_id, record.action, record.decision,
                    record.reason, decision.method, expected_revision=self.revision(),
                    deadline=record.deadline, judgment_ref=decision.decision_id)
            elif isinstance(record, JobGoal):
                self.append('goal:' + record.result.ref.attempt_id, 'job', record.result.ref,
                    {'goal': record.goal.verdict, 'completed': record.completed},
                    (Link('ac', 'ac:' + record.result.ref.attempt_id),))
            elif isinstance(record, RunGoal):
                # request_digest/revision are the Goal's immutable source
                # identity; a Goal evaluated at a different snapshot differs.
                summary = {'goal': record.finding.verdict,
                           'evidence_refs': list(record.finding.evidence_refs),
                           'request_digest': record.request_digest,
                           'revision': record.revision}
                links = (Link('intent', 'intent'),)
                ref = c.QuestionRef('run', '')
                self.append(self._trace_id('run', ref, summary, links), 'run',
                            ref, summary, links)
        self.record_cursor = len(self.controller.records)
        # Read actual reserved Attempt identities, never invent them for preflight waits.
        for transition in (v for v in self.controller.records if isinstance(v, Transition)):
            attempt = self.state.get_attempt(transition.ref)
            key = transition.ref.attempt_id
            known = {r['record_id'] for r in self.trace.records()}
            if attempt.result and 'result:' + key not in known:
                self.trace.record_result('result:' + key, attempt.result, at=self.now,
                                         links=(Link('attempt', 'attempt:' + key),))
            if attempt.ac:
                ac_id = 'ac:' + key if attempt.ac.verdict != 'blocked' else 'ac-blocked:' + key
                if ac_id not in known:
                    self.trace.record_ac(ac_id, attempt.ac, at=self.now, result_ref='result:' + key)
        for approval, _ in self.state.history('run', 'approvals'):
            if approval.approval_id not in {r['record_id'] for r in self.trace.records()}:
                self.append(approval.approval_id, 'approval', c.QuestionRef('run', ''),
                    {'target': c.approval_target('run', approval.action)},
                    (Link('human_response', approval.human_response_ref),))

    def current_wait(self):
        return next(v for v in reversed(self.controller.records) if isinstance(v, c.WaitingHuman))

    def publish(self, wait):
        return self.gateway.publish(wait.ref, wait.request_id, QuestionContext(
            'Synthetic artifact computation', 'Review the exact target',
            'Fixture policy requires a human response', 'Writes only a synthetic artifact'))

    def comment(self, wait, answer='approve', *, user=101, **changes):
        publication = self.journal.publication(wait_link(wait.ref, wait.request_id))
        value = {'schema': 'co.human-response.v1', 'request_id': wait.request_id,
                 'presentation_digest': digest(publication['presentation']), 'answer': answer,
                 'detail': 'Use a read-only alternative' if answer == 'instruct' else ''}
        value.update(changes)
        return self.http.add(canonical(value), user)

    def receive(self, wait, comment):
        receipt = self.gateway.receive(wait.ref, wait.request_id, comment, expected_revision=self.revision())
        self.project()
        return receipt

    def request(self, wait, *, action=None, conditions=None, job=None, method='compute-artifact'):
        return JudgmentRequest(c.QuestionRef('run', job or wait.ref.job_id), action or wait.action,
                               method, conditions or self.conditions[0])
