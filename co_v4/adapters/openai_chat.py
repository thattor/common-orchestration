"""openai.chat southbound Adapter: one stateless streaming chat request.

Terminal mapping per design/0.4/OPENAI-COMPATIBLE-EDGES.md and the accepted
Opus semantics: the first valid policy signal in stream order wins
Result.reason over every non-policy terminal, resource cap or EOF; only a
valid recognized terminal proves cessation. finish_reason=stop is the only
success; length is output_truncated; refusal and content_filter are policy;
tool_calls/function_call finish is a valid provider terminal carrying a
semantic violation; unknown finish vocabulary closes unconfirmed; EOF or
[DONE] before finish_reason is transport_eof. Semantic violations inside
valid framing are marked and parse-discard drained; all resource caps are
non-policy output_limit_exceeded drains. After a terminal at most one
byte-identical data repeat and at most one usage-only chunk
(choices: []) are permitted, in either order, both before a single
[DONE]; [DONE] ends the stream for every kind of data, so either is
accepted only before it.
"""
import json

from ..contracts import State
from ..delegation import job_payload
from ..openai_transport import (OpenAISSEAdapter, _ProtocolError, sse_object)

ADAPTER = 'openai.chat'
ADAPTER_VERSION = '0.1.0'
MAX_TEXT = 262144
SYSTEM_PROMPT = ('You are a bounded CO text Worker. Use no tools or external context. '
    'Only carry out the supplied Job and context. Never grant permissions or change CO state. '
    'Return out-of-scope needs as text to Controller. Produce only the requested text response.')


class OpenAIChatAdapter(OpenAISSEAdapter):
    """Provider-stateless text role; route, endpoint and auth are host-owned."""
    ADAPTER_ID = ADAPTER

    def _body(self, request, route):
        prompt = json.dumps(job_payload(request), ensure_ascii=False,
                            allow_nan=False, separators=(',', ':'))
        body = {'model': route.model,
                'messages': [{'role': 'system', 'content': SYSTEM_PROMPT},
                             {'role': 'user', 'content': prompt}],
                'stream': True}
        if route.store_param == 'send_false':
            body['store'] = False
        return json.dumps(body, ensure_ascii=False, allow_nan=False,
                          separators=(',', ':')).encode('utf-8')

    def _mark(self, attempt):
        """Semantic violation inside valid framing: policy mark, keep draining."""
        self._policy(attempt, 'protocol_violation')
        return None

    def _cap(self, attempt):
        """Host resource limit overflow: non-policy; drain without accumulating."""
        proto = attempt.proto
        proto['limited'] = True
        proto.pop('acc', None)
        attempt.parts = None
        return None

    @staticmethod
    def _usage_chunk(obj):
        return (type(obj) is dict and obj.get('object') == 'chat.completion.chunk'
                and type(obj.get('choices')) is list and not obj['choices']
                and type(obj.get('usage')) is dict)

    def _sse(self, attempt, event, data):
        proto = attempt.proto
        if attempt.outcome is not None:
            if (data == proto.get('term_data')
                    and not proto.get('done')
                    and not proto.get('repeat_seen')):
                proto['repeat_seen'] = True
                return   # at most one identical repeat, before [DONE]
            if data == '[DONE]' and not proto.get('done'):
                proto['done'] = True
                return
            try:
                obj = sse_object(data)
            except _ProtocolError:
                obj = None
            if (obj is not None and self._usage_chunk(obj)
                    and not proto.get('usage_seen')
                    and not proto.get('done') and attempt.terminal_seen):
                proto['usage_seen'] = True
                return
            self._violate(attempt, 'activity_after_terminal')
        if data == '[DONE]':
            proto['done'] = True
            attempt.outcome = self._outcome(attempt,
                (State.ERROR, 'transport_eof'))
            return
        obj = sse_object(data)   # malformed JSON/framing: closes unconfirmed
        if self._usage_chunk(obj):
            # Usage is never surfaced as complete Usage; exactly one allowed.
            if proto.get('usage_seen'):
                return self._mark(attempt)
            proto['usage_seen'] = True
            return
        if obj.get('object') != 'chat.completion.chunk':
            if type(obj.get('error')) is dict:
                attempt.outcome = self._outcome(attempt,
                    (State.FAILED, 'provider_error'))
                proto['term_data'] = data
                attempt.terminal_seen = True
                return
            return self._mark(attempt)
        model = obj.get('model')
        if model is not None and model != self._route.model:
            return self._mark(attempt)
        cid = obj.get('id')
        if type(cid) is str and cid and proto.setdefault('cid', cid) != cid:
            return self._mark(attempt)
        choices = obj.get('choices')
        if type(choices) is not list or len(choices) != 1:
            return self._mark(attempt)
        choice = choices[0]
        if type(choice) is not dict or choice.get('index', 0) != 0:
            return self._mark(attempt)
        delta = choice.get('delta')
        if delta is not None:
            if type(delta) is not dict:
                return self._mark(attempt)
            if delta.get('role') not in (None, 'assistant'):
                return self._mark(attempt)
            if delta.get('tool_calls') or delta.get('function_call'):
                return self._mark(attempt)
            refusal = delta.get('refusal')
            if refusal is not None:
                if type(refusal) is not str:
                    return self._mark(attempt)
                if refusal:            # only non-empty refusal text counts
                    self._policy(attempt, 'provider_refusal')
            content = delta.get('content')
            if content is not None:
                if type(content) is not str:
                    return self._mark(attempt)
                if proto.get('policy') is None and not proto.get('limited'):
                    proto.setdefault('acc', []).append(content)
                    proto['text_bytes'] = (proto.get('text_bytes', 0)
                                           + len(content.encode('utf-8')))
                    if proto['text_bytes'] > MAX_TEXT:
                        return self._cap(attempt)
        finish = choice.get('finish_reason')
        if finish is None:
            return
        if finish == 'content_filter':
            self._policy(attempt, 'content_filter')
        elif finish in ('tool_calls', 'function_call'):
            # Provider-declared terminal carrying forbidden semantics.
            self._policy(attempt, 'protocol_violation')
        elif finish not in ('stop', 'length'):
            # Unrecognized finish vocabulary: conservative, never proof.
            self._policy(attempt, 'protocol_violation')
            raise _ProtocolError('unknown_finish_reason')
        if proto.get('policy') is not None or proto.get('limited'):
            attempt.outcome = self._outcome(attempt,
                (State.FAILED, 'protocol_violation'))
        elif finish == 'stop':
            attempt.parts = (''.join(proto.get('acc', [])),)
            attempt.outcome = (State.COMPLETED, None)
        else:   # length
            attempt.outcome = (State.FAILED, 'output_truncated')
        proto['term_data'] = data
        attempt.terminal_seen = True
