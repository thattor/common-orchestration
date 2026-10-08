"""Injected transports only; no socket, provider, credential or network.

Every positive wire frame is an actual openai==3.24.0 SDK event model
instantiated and serialized in-process via model_dump_json(); the canonical
nested `response` envelope and required fields come from the pinned models,
never a hand-built envelope dict. Deliberately malformed or off-vocabulary
fixtures (unknown finish values, foreign item types, non-JSON payloads) are
built raw and marked as such. The SDK import is intentionally hard: this
file does not run without the pinned dependency. Collection failures assert
the canonical contracts.CollectionError, never a transport-local alias.
No real-provider acceptance is claimed here.
"""
import json
import unittest

import openai.types.responses as R
from openai.types.responses.response import IncompleteDetails
from openai.types.chat.chat_completion_chunk import (ChatCompletionChunk,
    Choice, ChoiceDelta, ChoiceDeltaToolCall)
from openai.types.completion_usage import CompletionUsage

from co_v4.adapters.openai_chat import ADAPTER as CHAT, OpenAIChatAdapter
from co_v4.adapters.openai_responses import (ADAPTER as RESPONSES,
    MAX_CONTENT_PARTS, MAX_OUTPUT_ITEMS, MAX_TEXT, OpenAIResponsesAdapter)
from co_v4.contracts import (AttemptRef, CollectionError, ExecutionConditions,
    ExecuteRequest, Job, OperationStatus, OutputItem, ResultEvent,
    ResumeState, State, StopStatus)
from co_v4.openai_transport import (OpenAIRoute, SseMessage, StreamEnded,
    StreamFailed, StreamStarted, TransportOpenError, payload_digest)

from co_v4.protocol_profile import RouteProtocolProfile
from co_v4.qualified_route import QualifiedBinding, QualifiedRouteGate

TERMINAL = (State.COMPLETED, State.FAILED, State.ERROR)


def request(adapter):
    ref = AttemptRef('run-1', 'job-1', 'attempt-1')
    return ExecuteRequest(ref, Job(ref.run_id, ref.job_id, 'Produce the text',
        ('acriterion',), '{"ctx":"v"}'),
        ExecutionConditions('test-model', adapter, '/unused-workspace',
                            'env:fixture'))


def route(req, store='send_false', confirmed=(), sequence='required',
          allow_done=False):
    return OpenAIRoute(request=req, endpoint='https://provider.example/v1/x',
        model=req.conditions.model, store_param=store,
        payload_sha256=payload_digest(req), confirmed_statuses=confirmed,
        sequence=sequence, allow_terminal_done=allow_done)


def ev(model, name=None):
    """One pinned SDK event model serialized to its SSE frame. Responses
    frames carry the envelope type as the SSE event name, like the wire."""
    return SseMessage(name if name is not None
                      else getattr(model, 'type', 'message'),
                      model.model_dump_json())


def ev_noseq(model):
    """SDK envelope with sequence_number dropped: lawful only on a route whose
    evidence records the field wholly absent; a violation anywhere else."""
    data = model.model_dump()
    del data['sequence_number']
    return SseMessage(model.type, json.dumps(data, sort_keys=True))


def raw(name, data):
    """Deliberately off-model wire bytes: negative/malformed fixtures only."""
    return SseMessage(name, data if type(data) is str
                      else json.dumps(data, sort_keys=True))


def resp(status, rid='resp_1', output=(), model='test-model',
         incomplete=None):
    return R.Response(id=rid, object='response', created_at=1728000000.0,
        model=model, status=status, output=list(output),
        incomplete_details=incomplete, parallel_tool_calls=False,
        tool_choice='none', tools=[])


def message(content, iid='m1', status='completed'):
    return R.ResponseOutputMessage(id=iid, type='message', role='assistant',
        status=status, content=list(content))


def text_part(text):
    return R.ResponseOutputText(type='output_text', annotations=[], text=text)


def refusal_part(text):
    return R.ResponseOutputRefusal(type='refusal', refusal=text)


class Script:
    """Strictly increasing sequence_number source for SDK envelopes."""
    def __init__(self):
        self.seq = 0

    def n(self, override=None):
        self.seq = self.seq + 1 if override is None else override
        return self.seq

    def created(self, seq=None):
        return ev(R.ResponseCreatedEvent(response=resp('in_progress'),
            sequence_number=self.n(seq), type='response.created'))

    def completed(self, output=(), seq=None, **kw):
        return ev(R.ResponseCompletedEvent(
            response=resp('completed', output=output, **kw),
            sequence_number=self.n(seq), type='response.completed'))

    def incomplete(self, reason=None, seq=None):
        details = (None if reason is None
                   else IncompleteDetails(reason=reason))
        return ev(R.ResponseIncompleteEvent(
            response=resp('incomplete', incomplete=details),
            sequence_number=self.n(seq), type='response.incomplete'))

    def failed(self, seq=None):
        return ev(R.ResponseFailedEvent(response=resp('failed'),
            sequence_number=self.n(seq), type='response.failed'))

    def error(self, seq=None, code=None):
        return ev(R.ResponseErrorEvent(code=code, message='PRIVATE_CANARY',
            sequence_number=self.n(seq), type='error'))

    def delta(self, delta, item_id='m1', output_index=0, content_index=0,
              seq=None):
        return ev(R.ResponseTextDeltaEvent(content_index=content_index,
            delta=delta, item_id=item_id, logprobs=[], output_index=output_index,
            sequence_number=self.n(seq), type='response.output_text.delta'))

    def text_done(self, text, item_id='m1', output_index=0, content_index=0,
                  seq=None):
        return ev(R.ResponseTextDoneEvent(content_index=content_index,
            item_id=item_id, logprobs=[], output_index=output_index,
            sequence_number=self.n(seq), text=text,
            type='response.output_text.done'))

    def refusal_done(self, refusal='PRIVATE_CANARY', item_id='m1', seq=None):
        return ev(R.ResponseRefusalDoneEvent(content_index=0, item_id=item_id,
            output_index=0, refusal=refusal, sequence_number=self.n(seq),
            type='response.refusal.done'))

    def item_added(self, item=None, output_index=0, seq=None):
        return ev(R.ResponseOutputItemAddedEvent(
            item=item if item is not None else message([text_part('')]),
            output_index=output_index, sequence_number=self.n(seq),
            type='response.output_item.added'))


def chunk(delta=None, finish=None, cid='chatcmpl-1', model='test-model'):
    return ev(ChatCompletionChunk(id=cid, created=1728000000, model=model,
        object='chat.completion.chunk',
        choices=[Choice(index=0, delta=ChoiceDelta(**(delta or {})),
                        finish_reason=finish)]))


def usage_chunk(cid='chatcmpl-1'):
    return ev(ChatCompletionChunk(id=cid, created=1728000000,
        model='test-model', object='chat.completion.chunk', choices=[],
        usage=CompletionUsage(completion_tokens=1, prompt_tokens=1,
                              total_tokens=2)))


class FakeTransport:
    """Implements the transport API: open/poll/close/cancel/deadline."""
    def __init__(self, script, open_error=None, pre_connect=True):
        self.script = [tuple(b) for b in script]
        self.open_error = open_error
        self.pre_connect = pre_connect    # cancel() wins only before connect
        self.sent_state = 'not_sent'
        self.responded = self.closed = self.done = False
        self.dropped_terminal = False
        self.open_calls = self.cancel_calls = 0
        self.deadline = 10 ** 9

    def open(self):
        self.open_calls += 1
        if self.open_error is not None:
            raise self.open_error
        self.sent_state, self.responded = 'sent', True

    def cancel(self):
        self.cancel_calls += 1
        if not self.pre_connect:
            return False
        self.script.insert(0, (StreamFailed('aborted', 'not_sent'),))
        return True

    def poll(self):
        if self.script:
            return self.script.pop(0)
        return (StreamFailed('total_timeout', self.sent_state),)

    def close(self):
        self.closed = True


def build(cls, script, store='send_false', confirmed=(), open_error=None,
          pre_connect=True, sequence='required', allow_done=False):
    req = request(cls.ADAPTER_ID)
    transport = FakeTransport(script, open_error, pre_connect)
    captured = {}

    def factory(r, body, rt):
        captured['body'] = json.loads(body)
        return transport

    adapter = cls(verify_host=lambda *a: None, transport_factory=factory,
                  route=route(req, store, confirmed, sequence, allow_done))
    return adapter, req, transport, captured


def finish(adapter, ref):
    for _ in range(50):
        state = adapter.status(ref).state
        if state in TERMINAL:
            return state
    raise AssertionError('no terminal state')


def result(adapter, ref):
    return next(e.result for e in adapter.events(ref)
                if type(e) is ResultEvent)


def results(adapter, ref):
    return [e.result for e in adapter.events(ref) if type(e) is ResultEvent]


def succeeded(s, text='hello', parts=None, items=None):
    content = (parts if parts is not None else [text_part(text)])
    output = items if items is not None else [message(content)]
    return [[StreamStarted(200), s.created(),
             s.completed(output=output), StreamEnded()]]


class ResponsesAdapterTests(unittest.TestCase):
    def test_error_param_missing_vs_null_generic_and_strict(self):
        """Q5: typed 'error' aux terminal — 'param' key missing is a
        protocol violation (UNCONFIRMED); explicit 'param': null is lawful
        provider_error (CONFIRMED). Generic route first, then the strict
        absent-single-part profile on the production adapter."""
        s = Script()
        created = s.created()
        missing = raw('error', {'type': 'error', 'code': 'x',
            'message': 'PRIVATE_CANARY', 'sequence_number': s.n()})
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), created, missing, StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        s = Script()
        created = s.created()
        explicit = raw('error', {'type': 'error', 'code': 'x',
            'message': 'PRIVATE_CANARY', 'param': None,
            'sequence_number': s.n()})
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), created, explicit, StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'provider_error')
        self.assertNotIn('PRIVATE_CANARY', repr(adapter.events(req.ref)))
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        # Strict absent-single-part profile on the production adapter. The
        # declared stub returns a typed QualifiedBinding (same seam as
        # ChatAdapterTests._qualified); the real gate object exists, and the
        # real _sse/_checker/_outcome path processes the actual frames.
        prof = RouteProtocolProfile(protocol='responses',
            index_mode='absent_single_part', sequence_mode='absent',
            inert_fields={}, model='test-model',
            provider_manifest_sha256='0' * 64)

        class Supplier:
            credential_ref = 'fixture-ref'

        def strict_adapter(script):
            req = request(RESPONSES)
            rt = OpenAIRoute(request=req,
                endpoint='https://provider.example/v1/x', model='test-model',
                store_param='send_false', payload_sha256=payload_digest(req),
                sequence='absent', profile=prof, auth_ref='fixture-ref')
            transport = FakeTransport(script)
            supplier = Supplier()
            transport.auth_supplier = supplier      # exact bound identity
            adapter = OpenAIResponsesAdapter(verify_host=lambda *a: None,
                transport_factory=lambda r, b, route_: transport, route=rt,
                qualification_gate=QualifiedRouteGate(
                    read_evidence=lambda path: b'',
                    probe_identity=lambda: {'model': 'test-model'},
                    launch_attested=lambda *a: True),
                manifest_loader=lambda digest: {}, auth_supplier=supplier)
            adapter._preflight = lambda r: (QualifiedBinding(
                endpoint=rt.endpoint, auth_ref='fixture-ref',
                model='test-model', environment_ref='env:fixture',
                profile=prof, manifest_sha256='0' * 64), None)
            return adapter, req, transport

        created = raw('response.created', {'type': 'response.created',
            'response': {'id': 'resp_1', 'object': 'response',
                         'status': 'in_progress'}})
        adapter, req, transport = strict_adapter(
            [[StreamStarted(200), created,
              raw('error', {'type': 'error', 'code': 'x',
                            'message': 'PRIVATE_CANARY'}), StreamEnded()]])
        reply = adapter.execute(req)
        self.assertEqual(reply.status, OperationStatus.ACCEPTED)
        self.assertEqual(transport.open_calls, 1)  # wire reached — not a refusal
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        adapter, req, transport = strict_adapter(
            [[StreamStarted(200), created,
              raw('error', {'type': 'error', 'code': 'x',
                            'message': 'PRIVATE_CANARY', 'param': None}),
              StreamEnded()]])
        reply = adapter.execute(req)
        self.assertEqual(reply.status, OperationStatus.ACCEPTED)
        self.assertEqual(transport.open_calls, 1)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'provider_error')
        self.assertNotIn('PRIVATE_CANARY', repr(adapter.events(req.ref)))
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_partially_streamed_and_foreign_key_reconcile_violation(self):
        # Deltas covering only part of the terminal content: marked, drained
        # to the valid terminal, CONFIRMED — never collected.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.delta('hel'),
              s.completed(output=[message([text_part('hello'),
                                           text_part('extra')])]),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        with self.assertRaises(CollectionError):
            adapter.collect_output(req.ref)
        # Streamed surfaces keyed to an item_id the terminal never carries.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.delta('hello', item_id='alien'),
              s.text_done('hello', item_id='alien'),
              s.completed(output=[message([text_part('hello')])]),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        with self.assertRaises(CollectionError):
            adapter.collect_output(req.ref)


    def test_completed_collect_body_and_confirmed_stop(self):
        s = Script()
        adapter, req, transport, captured = build(
            OpenAIResponsesAdapter, succeeded(s))
        self.assertEqual(adapter.execute(req).status, OperationStatus.ACCEPTED)
        self.assertEqual(transport.open_calls, 1)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        body = captured['body']
        self.assertEqual((body['model'], body['stream'], body['store']),
                         ('test-model', True, False))
        part = body['input'][0]['content'][0]
        self.assertEqual(part['type'], 'input_text')
        self.assertEqual(json.loads(part['text'])['context'], {'ctx': 'v'})
        self.assertNotIn('previous_response_id', body)
        self.assertNotIn('tools', body)
        items = adapter.collect_output(req.ref)
        self.assertEqual([(i.index, i.media_type, i.text) for i in items],
                         [(0, 'text/plain', 'hello')])
        self.assertTrue(transport.closed)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        self.assertEqual(adapter.execute(req).status,
                         OperationStatus.INVALID_STATE)

    def test_store_omit_and_idempotent_events(self):
        s = Script()
        adapter, req, _, captured = build(OpenAIResponsesAdapter,
                                          succeeded(s), store='omit')
        adapter.execute(req)
        self.assertNotIn('store', captured['body'])
        first = [e.event_id for e in adapter.events(req.ref)]
        second = [e.event_id for e in adapter.events(req.ref)]
        self.assertEqual(first, second)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)

    def test_multipart_ordered_collect_and_reconciliation(self):
        s = Script()
        parts = [text_part('hello'), text_part('world')]
        script = [[StreamStarted(200),
            s.delta('hel', content_index=0),
            s.delta('wor', content_index=1),
            s.delta('lo', content_index=0),
            s.text_done('hello', content_index=0),
            s.delta('ld', content_index=1),
            s.completed(output=[message(parts)]),
            StreamEnded()]]
        adapter, req, _, _ = build(OpenAIResponsesAdapter, script)
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        self.assertEqual([i.text for i in adapter.collect_output(req.ref)],
                         ['hello', 'world'])
        # A terminal whose output disagrees with the streamed deltas is a
        # semantic violation inside valid framing: the terminal still counts.
        s = Script()
        script = [[StreamStarted(200),
            s.delta('hel', content_index=0),
            s.delta('wor', content_index=1),
            s.delta('lo', content_index=0),
            s.text_done('hello', content_index=0),
            s.delta('ld', content_index=1),
            s.completed(output=[message([text_part('hello'),
                                         text_part('other')])]),
            StreamEnded()]]
        adapter, req, _, _ = build(OpenAIResponsesAdapter, script)
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        with self.assertRaises(CollectionError):
            adapter.collect_output(req.ref)

    def test_eof_before_terminal_never_success(self):
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.delta('part'), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.ERROR)
        self.assertEqual(result(adapter, req.ref).reason, 'transport_eof')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        with self.assertRaises(CollectionError):
            adapter.collect_output(req.ref)

    def test_incomplete_details_content_filter_is_policy(self):
        # Exact typed SDK field: content_filter maps to canonical policy,
        # CONFIRMED via the valid incomplete terminal.
        for reason, expected in (('content_filter', 'content_filter'),
                                 ('max_output_tokens', 'output_truncated'),
                                 ('steered', 'output_truncated'),
                                 (None, 'output_truncated')):
            s = Script()
            adapter, req, _, _ = build(OpenAIResponsesAdapter,
                [[StreamStarted(200), s.incomplete(reason), StreamEnded()]])
            adapter.execute(req)
            self.assertEqual(finish(adapter, req.ref), State.FAILED)
            self.assertEqual(result(adapter, req.ref).reason, expected)
            self.assertEqual(adapter.stop(req.ref).status,
                             StopStatus.CONFIRMED)
        # First policy wins: an earlier refusal beats a later filter terminal.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.refusal_done(),
              s.incomplete('content_filter'), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'provider_refusal')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_failed_error_refusal_terminals_confirmed(self):
        cases = [
            (lambda s: [s.failed()], 'provider_failed'),
            (lambda s: [s.error()], 'provider_error'),
            (lambda s: [s.completed(output=[message([refusal_part('no')])])],
             'provider_refusal'),
        ]
        for build_events, reason in cases:
            with self.subTest(reason=reason):
                s = Script()
                adapter, req, _, _ = build(OpenAIResponsesAdapter,
                    [[StreamStarted(200)] + build_events(s) + [StreamEnded()]])
                adapter.execute(req)
                self.assertEqual(finish(adapter, req.ref), State.FAILED)
                self.assertEqual(result(adapter, req.ref).reason, reason)
                self.assertNotIn('PRIVATE_CANARY', repr(adapter.events(req.ref)))
                with self.assertRaises(CollectionError):
                    adapter.collect_output(req.ref)
                self.assertEqual(adapter.stop(req.ref).status,
                                 StopStatus.CONFIRMED)

    def test_first_policy_dominates_eof_timeout_and_terminal(self):
        # Refusal parsed first, then every non-policy outcome loses the reason.
        for tail in ([StreamEnded()],
                     [StreamFailed('idle_timeout', 'sent')],
                     [StreamFailed('total_timeout', 'sent')],
                     [StreamFailed('aborted', 'sent')]):
            s = Script()
            adapter, req, _, _ = build(OpenAIResponsesAdapter,
                [[StreamStarted(200), s.refusal_done()] + list(tail)])
            adapter.execute(req)
            self.assertEqual(finish(adapter, req.ref), State.FAILED)
            self.assertEqual(result(adapter, req.ref).reason,
                             'provider_refusal')
            self.assertEqual(adapter.stop(req.ref).status,
                             StopStatus.UNCONFIRMED)
        # Refusal dominates a later non-policy provider terminal too.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.refusal_done(), s.failed(),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'provider_refusal')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_policy_first_then_postterminal_violation_keeps_reason(self):
        # Corrected ordering: the violation invalidates the proof but the
        # first policy reason stands.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.refusal_done(),
              s.completed(output=[message([text_part('x')])]),
              s.delta('late'), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'provider_refusal')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_semantic_violation_marks_and_drains_to_terminal(self):
        # Foreign item type inside valid framing: marked, then the stream is
        # parse-discard drained to a valid terminal (CONFIRMED) or deadline
        # (UNCONFIRMED) — never an immediate finish.
        tool_item = {'type': 'function_call', 'id': 'fc1', 'call_id': 'c1',
                     'name': 'PRIVATE_CANARY', 'arguments': '{}',
                     'status': 'completed'}
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200),
              raw('response.output_item.added',
                  {'type': 'response.output_item.added',
                   'sequence_number': s.n(), 'output_index': 0,
                   'item': tool_item}),
              s.completed(output=[message([text_part('x')])]),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        self.assertNotIn('PRIVATE_CANARY', repr(adapter.events(req.ref)))
        with self.assertRaises(CollectionError):
            adapter.collect_output(req.ref)
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200),
              raw('response.output_item.added',
                  {'type': 'response.output_item.added',
                   'sequence_number': s.n(), 'output_index': 0,
                   'item': tool_item}),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_malformed_json_closes_unconfirmed(self):
        s = Script()
        adapter, req, transport, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.created(),
              raw('response.output_text.delta', '{not json'),
              s.completed(output=[message([text_part('x')])]),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertTrue(transport.closed)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_each_accumulation_cap_is_nonpolicy_drain(self):
        big = 'x' * (MAX_TEXT + 1)
        # Text cap then a valid terminal: non-policy reason, confirmed drain.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.delta(big),
              s.completed(output=[message([text_part('x')])]),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason,
                         'output_limit_exceeded')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        with self.assertRaises(CollectionError):
            adapter.collect_output(req.ref)
        # Same cap reaching the deadline instead: UNCONFIRMED, same reason.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.delta(big)]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason,
                         'output_limit_exceeded')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        # Item cap inside the completed terminal.
        s = Script()
        items = [message([text_part('x')], iid='m%d' % i) for i in
                 range(MAX_OUTPUT_ITEMS + 1)]
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.completed(output=items), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason,
                         'output_limit_exceeded')
        # Part cap inside the completed terminal.
        s = Script()
        items = [message([text_part('x')
                          for _ in range(MAX_CONTENT_PARTS + 1)])]
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.completed(output=items), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason,
                         'output_limit_exceeded')

    def test_policy_after_cap_still_detected_first_wins(self):
        big = 'x' * (MAX_TEXT + 1)
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.delta(big), s.refusal_done(),
              s.completed(output=[message([text_part('x')])]),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'provider_refusal')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_sequence_rules(self):
        # Gaps are allowed; strictly increasing holds.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.created(seq=1), s.delta('x', seq=7),
              s.completed(output=[message([text_part('x')])], seq=19),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        # Non-increasing on a non-terminal frame: marked, drained, terminal
        # still confirms.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.created(seq=1), s.delta('x', seq=7),
              s.delta('y', seq=3),
              s.completed(output=[message([text_part('x')])], seq=19),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        # Missing on a default 'required' route: violation.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), s.created(),
              ev_noseq(R.ResponseTextDeltaEvent(content_index=0, delta='x',
                  item_id='m1', logprobs=[], output_index=0,
                  sequence_number=0, type='response.output_text.delta')),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        # Wholly absent only on a route whose evidence records it.
        s = Script()
        noseq_completed = ev_noseq(R.ResponseCompletedEvent(
            response=resp('completed',
                          output=[message([text_part('x')])]),
            sequence_number=0, type='response.completed'))
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200),
              ev_noseq(R.ResponseCreatedEvent(response=resp('in_progress'),
                  sequence_number=0, type='response.created')),
              noseq_completed, StreamEnded()]],
            sequence='absent')
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        # Mixed presence is a violation on either route choice.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200),
              ev_noseq(R.ResponseCreatedEvent(response=resp('in_progress'),
                  sequence_number=0, type='response.created')),
              s.completed(output=[message([text_part('x')])]),
              StreamEnded()]],
            sequence='absent')
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')

    def test_done_post_terminal_needs_route_evidence(self):
        s = Script()
        done_frame = s.completed(output=[message([text_part('x')])])
        # Default route: a single post-terminal [DONE] invalidates the proof.
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), done_frame,
              raw('message', '[DONE]'), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        # Route-evidenced single [DONE] after the terminal: permitted.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200),
              s.completed(output=[message([text_part('x')])]),
              raw('message', '[DONE]'), StreamEnded()]],
            allow_done=True)
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        # A second [DONE] is never accepted.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200),
              s.completed(output=[message([text_part('x')])]),
              raw('message', '[DONE]'), raw('message', '[DONE]'),
              StreamEnded()]],
            allow_done=True)
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        # [DONE] before the terminal is never accepted, on any route.
        s = Script()
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), raw('message', '[DONE]'),
              s.completed(output=[message([text_part('x')])]),
              StreamEnded()]],
            allow_done=True)
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_post_terminal_identical_repeat_and_violations(self):
        s = Script()
        done = s.completed(output=[message([text_part('hello')])])
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), done, done, StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        # Altered terminal payload after completed: invalidates proof.
        s = Script()
        altered = s.completed(output=[message([text_part('hello')])],
                              rid='resp_other')
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), done, altered, StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        # Content delta after terminal: same failure.
        s = Script()
        late = s.delta('x')
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200), done, late, StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_envelope_violations_mark_and_drain(self):
        scripts = []
        # Envelope type disagrees with the SSE event name.
        scripts.append([[StreamStarted(200),
            raw('response.completed', {'type': 'response.failed',
                'sequence_number': 1, 'response': resp('failed').model_dump()}),
            StreamEnded()]])
        # Missing response payload.
        scripts.append([[StreamStarted(200),
            raw('response.completed', {'type': 'response.completed',
                'sequence_number': 1}), StreamEnded()]])
        # Unknown event type.
        scripts.append([[StreamStarted(200),
            raw('response.alien', {'type': 'response.alien',
                                   'sequence_number': 1}),
            StreamEnded()]])
        for script in scripts:
            with self.subTest(script=script):
                adapter, req, _, _ = build(OpenAIResponsesAdapter, script)
                adapter.execute(req)
                self.assertEqual(finish(adapter, req.ref), State.FAILED)
                self.assertEqual(result(adapter, req.ref).reason,
                                 'protocol_violation')
                self.assertEqual(adapter.stop(req.ref).status,
                                 StopStatus.UNCONFIRMED)

    def test_http_status_unconfirmed_unless_route_evidence(self):
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(500), StreamFailed('http_status', 'sent')]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.ERROR)
        self.assertEqual(result(adapter, req.ref).reason, 'http_status')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(429), StreamFailed('http_status', 'sent')]],
            confirmed=(429,))
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'http_status')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_stop_timings_exactly_one_evidence(self):
        # Timing 1: stop observed inside execute before open() — a NeverStarted
        # receipt only; the Attempt never carries a Result.
        req = request(RESPONSES)
        adapter = OpenAIResponsesAdapter(verify_host=lambda *a: None,
            route=route(req),
            transport_factory=lambda r, b, rt: (
                setattr(adapter._attempts[r.ref], 'stop_requested', True)
                or FakeTransport([])))
        reply = adapter.execute(req)
        self.assertIsNotNone(reply.never_started)
        self.assertEqual(reply.never_started.request, req)
        self.assertEqual(results(adapter, req.ref), [])
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        # Timing 2: accepted, then stop lands before connect — one Result,
        # no NeverStarted on the accepted reply.
        s = Script()
        adapter, req, transport, _ = build(OpenAIResponsesAdapter,
                                           succeeded(s))
        reply = adapter.execute(req)
        self.assertEqual(reply.status, OperationStatus.ACCEPTED)
        self.assertIsNone(reply.never_started)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        self.assertEqual(transport.cancel_calls, 1)
        self.assertEqual(len(results(adapter, req.ref)), 1)
        self.assertEqual(result(adapter, req.ref).reason,
                         'stopped_before_transmit')
        # Timing 3: connect already began — drain to the provider terminal.
        s = Script()
        adapter, req, transport, _ = build(OpenAIResponsesAdapter,
            succeeded(s), pre_connect=False)
        adapter.execute(req)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        self.assertEqual(len(results(adapter, req.ref)), 1)
        self.assertEqual(result(adapter, req.ref).reason, 'stopped_midrequest')
        with self.assertRaises(CollectionError):
            adapter.collect_output(req.ref)
        # Drain deadline: UNCONFIRMED, still exactly one Result.
        adapter, req, _, _ = build(OpenAIResponsesAdapter,
            [[StreamStarted(200)]], pre_connect=False)
        adapter.execute(req)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        self.assertEqual(result(adapter, req.ref).reason,
                         'transport_total_timeout')
        # Unknown Attempt: UNCONFIRMED, no queue or acknowledgement.
        self.assertEqual(adapter.stop(AttemptRef('r', 'j', 'x')).status,
                         StopStatus.UNCONFIRMED)

    def test_open_failure_classification(self):
        adapter, req, _, _ = build(OpenAIResponsesAdapter, [],
            open_error=TransportOpenError('connect_failed', 'not_sent'))
        self.assertEqual(adapter.execute(req).status, OperationStatus.ERROR)
        self.assertEqual(result(adapter, req.ref).reason,
                         'transport_connect_failed')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        adapter, req, _, _ = build(OpenAIResponsesAdapter, [],
            open_error=RuntimeError('PRIVATE_CANARY'))
        self.assertEqual(adapter.execute(req).status, OperationStatus.ERROR)
        self.assertEqual(result(adapter, req.ref).reason,
                         'provider_submission_unknown')
        self.assertNotIn('PRIVATE_CANARY', repr(adapter.events(req.ref)))
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_default_refuses_and_resume_unsupported(self):
        req = request(RESPONSES)
        adapter = OpenAIResponsesAdapter(route=route(req))
        reply = adapter.execute(req)
        self.assertEqual(reply.status, OperationStatus.UNSUPPORTED)
        self.assertIsNotNone(reply.never_started)
        self.assertEqual(adapter.resume(
            ResumeState(RESPONSES, req.ref, b'opaque')).status,
            OperationStatus.INVALID_STATE)


class ChatAdapterTests(unittest.TestCase):
    def test_usage_after_done_is_activity_after_terminal(self):
        # Q2 ruling: [DONE] ends the Chat stream. Capture order is
        # terminal -> [DONE]; a usage chunk after [DONE] is post-terminal
        # traffic and invalidates the proof.
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'content': 'x'}, 'stop'),
              raw('message', '[DONE]'), usage_chunk(), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_usage_before_done_and_allowances_pinned(self):
        # stop -> usage -> [DONE] remains the single permitted post-terminal
        # usage allowance.
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'content': 'x'}, 'stop'),
              usage_chunk(), raw('message', '[DONE]'), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        # A second usage chunk is still rejected.
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'content': 'x'}, 'stop'),
              usage_chunk(), usage_chunk(), raw('message', '[DONE]'),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        # Pre-terminal usage behavior is unchanged.
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'content': 'x'}), usage_chunk(),
              chunk({}, 'stop'), raw('message', '[DONE]'), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        self.assertEqual([i.text for i in adapter.collect_output(req.ref)],
                         ['x'])

    def test_terminal_repeat_capped_once_before_done(self):
        # Opus F1+F4: at most one byte-identical terminal repeat, and only
        # before [DONE]; [DONE] ends the stream for every kind of data.
        stop = chunk({'content': 'x'}, 'stop')
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), stop, stop, raw('message', '[DONE]'),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        # Repeat + usage in either order, both before [DONE]: permitted.
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), stop, stop, usage_chunk(),
              raw('message', '[DONE]'), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), stop, usage_chunk(), stop,
              raw('message', '[DONE]'), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        # A second identical repeat is activity_after_terminal.
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), stop, stop, stop,
              raw('message', '[DONE]'), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason,
                         'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status,
                         StopStatus.UNCONFIRMED)
        # Identical repeat after [DONE]: the stream already ended.
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), stop, raw('message', '[DONE]'), stop,
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason,
                         'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status,
                         StopStatus.UNCONFIRMED)

    def _qualified(self, initial_sent, rewrite_to=None, close_raises=False):
        """Q7 fixture: real gate, stubbed post-binding _preflight.

        The stub isolates the auth-supplier identity-mismatch path; the gate
        is a genuine QualifiedRouteGate so the env exclusion latch is
        observed for real. Transport is never opened: sent_state is only the
        snapshot input."""
        req = request(CHAT)
        profile = RouteProtocolProfile(protocol='chat', index_mode='present',
            sequence_mode='present', inert_fields={}, model='test-model',
            provider_manifest_sha256='0' * 64)
        rt = OpenAIRoute(request=req,
            endpoint='https://provider.example/v1/x', model='test-model',
            store_param='send_false', payload_sha256=payload_digest(req),
            profile=profile, auth_ref='fixture-ref')
        gate = QualifiedRouteGate(read_evidence=lambda path: b'',
            probe_identity=lambda: {'model': 'test-model'},
            launch_attested=lambda *a: True)

        class Supplier:
            credential_ref = 'fixture-ref'

        class RewritingTransport(FakeTransport):
            def __init__(self):
                super().__init__([])
                self.sent_state = initial_sent

            def close(self):
                self.closed = True
                if close_raises:
                    raise RuntimeError('PRIVATE_CANARY')
                if rewrite_to is not None:
                    self.sent_state = rewrite_to

        transport = RewritingTransport()
        adapter = OpenAIChatAdapter(verify_host=lambda *a: None,
            transport_factory=lambda r, b, route_: transport, route=rt,
            qualification_gate=gate, manifest_loader=lambda digest: {},
            auth_supplier=Supplier())
        adapter._preflight = lambda r: (QualifiedBinding(
            endpoint=rt.endpoint, auth_ref='fixture-ref', model='test-model',
            environment_ref='env:fixture', profile=profile,
            manifest_sha256='0' * 64), None)
        return adapter, req, transport, gate

    def test_sent_state_snapshot_survives_close_rewrite(self):
        # Q7: sent_state is read BEFORE close(). A close() rewriting
        # 'unknown' -> 'not_sent' must never mint a NeverStarted.
        adapter, req, transport, gate = self._qualified(
            'unknown', rewrite_to='not_sent')
        reply = adapter.execute(req)
        self.assertEqual(reply.status, OperationStatus.ERROR)
        self.assertIsNone(reply.never_started)
        self.assertEqual(transport.sent_state, 'not_sent')   # close() ran
        self.assertIn(req.ref, adapter._attempts)            # retained
        self.assertIn('env:fixture', gate._excluded)
        self.assertEqual(result(adapter, req.ref).reason,
                         'provider_submission_unknown')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        # Reverse rewrite: 'not_sent' observed before close is genuine proof;
        # NeverStarted stands even after close() falsifies the field.
        adapter, req, transport, gate = self._qualified(
            'not_sent', rewrite_to='unknown')
        reply = adapter.execute(req)
        self.assertEqual(reply.status, OperationStatus.UNSUPPORTED)
        self.assertIsNotNone(reply.never_started)
        self.assertNotIn(req.ref, adapter._attempts)
        self.assertIn('env:fixture', gate._excluded)
        # A close() that raises changes neither outcome.
        adapter, req, transport, gate = self._qualified(
            'not_sent', close_raises=True)
        reply = adapter.execute(req)
        self.assertEqual(reply.status, OperationStatus.UNSUPPORTED)
        self.assertIsNotNone(reply.never_started)
        self.assertIn('env:fixture', gate._excluded)
        adapter, req, transport, gate = self._qualified(
            'unknown', close_raises=True)
        reply = adapter.execute(req)
        self.assertEqual(reply.status, OperationStatus.ERROR)
        self.assertEqual(result(adapter, req.ref).reason,
                         'provider_submission_unknown')
        self.assertIn('env:fixture', gate._excluded)

    def test_stop_finish_collect_body_and_confirmed(self):
        script = [[StreamStarted(200), chunk({'content': 'hel'}),
                   chunk({'content': 'lo'}, 'stop'),
                   raw('message', '[DONE]'), StreamEnded()]]
        adapter, req, _, captured = build(OpenAIChatAdapter, script)
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        body = captured['body']
        self.assertEqual([m['role'] for m in body['messages']],
                         ['system', 'user'])
        self.assertEqual(body['store'], False)
        self.assertNotIn('tools', body)
        items = adapter.collect_output(req.ref)
        self.assertEqual([(i.index, i.text) for i in items], [(0, 'hello')])
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_finish_vocabulary_and_confirmed_tool_terminal(self):
        cases = [
            (chunk({'content': 'x'}, 'length'), 'output_truncated',
             StopStatus.CONFIRMED),
            (chunk({'content': 'x'}, 'content_filter'), 'content_filter',
             StopStatus.CONFIRMED),
            (chunk({'content': 'x'}, 'tool_calls'), 'protocol_violation',
             StopStatus.CONFIRMED),
            (chunk({'content': 'x'}, 'function_call'), 'protocol_violation',
             StopStatus.CONFIRMED),
        ]
        for frame, reason, expected_stop in cases:
            with self.subTest(reason=reason):
                adapter, req, _, _ = build(OpenAIChatAdapter,
                    [[StreamStarted(200), frame, raw('message', '[DONE]'),
                      StreamEnded()]])
                adapter.execute(req)
                self.assertEqual(finish(adapter, req.ref), State.FAILED)
                self.assertEqual(result(adapter, req.ref).reason, reason)
                self.assertEqual(adapter.stop(req.ref).status, expected_stop)
                # Tool content is never collected, published or executed.
                with self.assertRaises(CollectionError):
                    adapter.collect_output(req.ref)

    def test_unknown_finish_closes_unconfirmed_no_resurrection(self):
        # Unrecognized terminal vocabulary closes immediately; a later valid
        # finish in the same stream can never confirm it.
        alien = raw('message', {'id': 'c', 'object': 'chat.completion.chunk',
            'model': 'test-model', 'created': 1,
            'choices': [{'index': 0, 'delta': {},
                         'finish_reason': 'alien'}]})
        adapter, req, transport, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), alien],
             [chunk({'content': 'x'}, 'stop'), raw('message', '[DONE]'),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertTrue(transport.closed)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_tool_delta_marks_then_drains(self):
        # A tool-call delta inside valid framing is a semantic violation:
        # marked, drained, confirmed by the real finish terminal; the tool
        # payload is never collected.
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200),
              chunk({'tool_calls': [{'index': 0, 'id': 'c',
                                     'function': {'name': 'PRIVATE_CANARY',
                                                  'arguments': '{}'}}]}),
              chunk({'content': 'x'}, 'stop'), raw('message', '[DONE]'),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        self.assertNotIn('PRIVATE_CANARY', repr(adapter.events(req.ref)))
        with self.assertRaises(CollectionError):
            adapter.collect_output(req.ref)

    def test_chat_first_policy_wins(self):
        # Refusal then filter finish: first policy reason in stream order.
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'refusal': 'PRIVATE_CANARY'}),
              chunk({}, 'content_filter'), raw('message', '[DONE]'),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'provider_refusal')
        self.assertNotIn('PRIVATE_CANARY', repr(adapter.events(req.ref)))
        # Refusal then EOF: same reason, UNCONFIRMED.
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'refusal': 'x'}), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'provider_refusal')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        # Refusal then a mid-wire transport failure: policy still dominates.
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'refusal': 'x'}),
              StreamFailed('idle_timeout', 'sent')]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'provider_refusal')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_empty_refusal_is_not_refusal(self):
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'refusal': ''}),
              chunk({'content': 'ok'}, 'stop'), raw('message', '[DONE]'),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        self.assertEqual([i.text for i in adapter.collect_output(req.ref)],
                         ['ok'])

    def test_done_before_finish_and_eof_unconfirmed(self):
        for tail in ([raw('message', '[DONE]'), StreamEnded()],
                     [StreamEnded()]):
            adapter, req, _, _ = build(OpenAIChatAdapter,
                [[StreamStarted(200), chunk({'content': 'x'})] + tail])
            adapter.execute(req)
            self.assertEqual(finish(adapter, req.ref), State.ERROR)
            self.assertEqual(result(adapter, req.ref).reason, 'transport_eof')
            self.assertEqual(adapter.stop(req.ref).status,
                             StopStatus.UNCONFIRMED)

    def test_second_done_and_post_terminal_content_violate(self):
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'content': 'x'}, 'stop'),
              raw('message', '[DONE]'), raw('message', '[DONE]'),
              StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'content': 'x'}, 'stop'),
              chunk({'content': 'y'}), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')

    def test_usage_chunk_once_and_post_terminal_once(self):
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'content': 'x'}), usage_chunk(),
              chunk({}, 'stop'), raw('message', '[DONE]'), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.COMPLETED)
        self.assertEqual(adapter.usage(), ())
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'content': 'x'}, 'stop'),
              usage_chunk(), usage_chunk(), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'protocol_violation')

    def test_error_object_terminal(self):
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'content': 'x'}),
              raw('message', {'error': {'message': 'PRIVATE_CANARY'}}),
              raw('message', '[DONE]'), StreamEnded()]])
        adapter.execute(req)
        self.assertEqual(finish(adapter, req.ref), State.FAILED)
        self.assertEqual(result(adapter, req.ref).reason, 'provider_error')
        self.assertNotIn('PRIVATE_CANARY', repr(adapter.events(req.ref)))
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_chat_midrequest_stop_drains_terminal(self):
        adapter, req, _, _ = build(OpenAIChatAdapter,
            [[StreamStarted(200), chunk({'content': 'x'})],
             [chunk({}, 'stop'), raw('message', '[DONE]'), StreamEnded()]],
            pre_connect=False)
        adapter.execute(req)
        adapter.events(req.ref)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        outcome = result(adapter, req.ref)
        self.assertEqual((outcome.status, outcome.reason),
                         (State.FAILED, 'stopped_midrequest'))
        with self.assertRaises(CollectionError):
            adapter.collect_output(req.ref)

    def test_route_model_mismatch_refused(self):
        req = request(CHAT)
        with self.assertRaises(ValueError):
            OpenAIRoute(request=req, endpoint='https://provider.example/v1/x',
                model='other-model', store_param='send_false',
                payload_sha256=payload_digest(req),
                sequence='required', allow_terminal_done=False)


if __name__ == '__main__':
    unittest.main()
