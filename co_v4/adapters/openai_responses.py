"""openai.responses southbound Adapter: one stateless streaming text request.

Wire shape verified against installed openai==3.24.0 types: every SSE data
payload is an event envelope carrying type, sequence_number and its payload
(response/item/part/item_id...), never a bare Response. Terminal mapping per
design/0.4/OPENAI-COMPATIBLE-EDGES.md and the accepted Opus semantics: a
frame confirms cessation only when the shared _terminal_shape core proof
validates; sequence/order/index and checker errors are semantic marks that
keep draining to a recognized terminal. The first valid policy signal in
stream order wins Result.reason over every non-policy outcome; a policy
value inside a malformed terminal is not a valid signal, and strict UTF-8
in failure content strings is semantic, never shape. After a terminal only
a byte-identical data repeat under a consistent SSE event name (empty,
message, or the terminal's own type) or, on routes whose evidence records
it, a single message-named [DONE] is permitted.
"""
import json

from ..contracts import State
from ..delegation import job_payload
from ..openai_transport import OpenAISSEAdapter, sse_object

ADAPTER = 'openai.responses'
ADAPTER_VERSION = '0.1.0'
MAX_TEXT = 262144
MAX_OUTPUT_ITEMS = 64
MAX_CONTENT_PARTS = 64
SYSTEM_PROMPT = ('You are a bounded CO text Worker. Use no tools or external context. '
    'Only carry out the supplied Job and context. Never grant permissions or change CO state. '
    'Return out-of-scope needs as text to Controller. Produce only the requested text response.')
LIFECYCLE = frozenset({'response.created', 'response.queued', 'response.in_progress'})
TERMINALS = frozenset({'response.completed', 'response.incomplete', 'response.failed'})
ITEM_EVENTS = frozenset({'response.output_item.added', 'response.output_item.done'})
PART_EVENTS = frozenset({'response.content_part.added', 'response.content_part.done'})
TEXT_EVENTS = frozenset({'response.output_text.delta', 'response.output_text.done'})
REFUSAL_EVENTS = frozenset({'response.refusal.delta', 'response.refusal.done'})
KNOWN_EVENTS = (LIFECYCLE | TERMINALS | ITEM_EVENTS | PART_EVENTS
                | TEXT_EVENTS | REFUSAL_EVENTS | {'error'})


def _key(obj):
    """(item_id, output_index, content_index) binding for one text part."""
    item_id, output_index, content_index = (obj.get('item_id'),
        obj.get('output_index'), obj.get('content_index'))
    if (type(item_id) is not str or not item_id or len(item_id) > 256
            or type(output_index) is not int or output_index < 0
            or type(content_index) is not int or content_index < 0):
        return None
    return (item_id, output_index, content_index)


def _utf8_ok(value):
    """Strict UTF-8 encodability of one content string; never raises."""
    try:
        value.encode('utf-8')
        return True
    except (AttributeError, UnicodeEncodeError):
        return False


class OpenAIResponsesAdapter(OpenAISSEAdapter):
    """Provider-stateless text role; route, endpoint and auth are host-owned."""
    ADAPTER_ID = ADAPTER

    def _body(self, request, route):
        prompt = json.dumps(job_payload(request), ensure_ascii=False,
                            allow_nan=False, separators=(',', ':'))
        body = {'model': route.model, 'instructions': SYSTEM_PROMPT,
                'input': [{'role': 'user', 'content': [
                    {'type': 'input_text', 'text': prompt}]}],
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
        for name in ('acc', 'done_text', 'strict_parts'):
            proto.pop(name, None)
        attempt.parts = None
        return None

    def _seq(self, attempt, obj):
        """sequence_number: present and strictly increasing by default (gaps
        allowed); wholly absent only on a route-evidenced 'absent' route.
        Mixed presence is always a violation. Returns False on violation."""
        proto = attempt.proto
        if self._route.sequence == 'absent':
            if 'sequence_number' in obj:
                self._mark(attempt)
                return False
            return True
        seq = obj.get('sequence_number')
        if type(seq) is not int or seq < 0 or seq <= proto.get('seq', -1):
            self._mark(attempt)
            return False
        proto['seq'] = seq
        return True

    def _bind(self, attempt, resp):
        """Response identity and model stay pinned across the stream."""
        rid = resp.get('id')
        if type(rid) is not str or not rid:
            return self._mark(attempt)
        try:
            if len(rid.encode('utf-8')) > 256:
                return self._mark(attempt)
        except UnicodeEncodeError:
            return self._mark(attempt)
        if attempt.proto.setdefault('rid', rid) != rid:
            return self._mark(attempt)
        model = resp.get('model')
        if model is not None and model != self._route.model:
            return self._mark(attempt)
        return resp

    def _response(self, attempt, obj):
        resp = obj.get('response')
        if type(resp) is not dict or ('object' in resp and resp['object'] != 'response'):
            return self._mark(attempt)
        return self._bind(attempt, resp)

    def _strict_policy(self, attempt, etype, obj):
        """Policy signals evaluated before the checker marks: refusal
        events and refusal parts plus the typed content_filter reason.
        Terminal frames reach here only after a valid shape, so a
        malformed terminal cannot mint a valid policy signal."""
        if etype in REFUSAL_EVENTS:
            value = obj.get('delta' if etype.endswith('.delta')
                            else 'refusal')
            if type(value) is str and value and _utf8_ok(value):
                self._policy(attempt, 'provider_refusal')
            return
        parts = []
        if etype in PART_EVENTS:
            parts.append(obj.get('part'))
        elif etype in ITEM_EVENTS:
            item = obj.get('item')
            if type(item) is dict and type(item.get('content')) is list:
                parts += item['content']
        elif etype in TERMINALS:
            resp = obj['response']              # shape-checked dict
            if type(resp.get('output')) is list:
                for item in resp['output']:
                    if (type(item) is dict
                            and type(item.get('content')) is list):
                        parts += item['content']
            details = resp.get('incomplete_details')
            # Exact typed SDK field: content_filter is canonical policy;
            # every other reason stays output_truncated.
            if (etype == 'response.incomplete' and type(details) is dict
                    and details.get('reason') == 'content_filter'):
                self._policy(attempt, 'content_filter')
        for part in parts:
            if (type(part) is dict and part.get('type') == 'refusal'
                    and type(part.get('refusal')) is str
                    and part['refusal'] and _utf8_ok(part['refusal'])):
                self._policy(attempt, 'provider_refusal')

    def _sse_strict(self, attempt, event, etype, obj, data):
        """Issued-binding strict stream: shape gate, then policy detection
        before the checker marks, then the checker itself."""
        proto = attempt.proto
        terminalish = etype in TERMINALS or etype == 'error'
        if (terminalish
                and not self._terminal_shape(attempt, event, etype, obj)):
            return self._mark(attempt)      # shape failure: not a terminal
        self._strict_policy(attempt, etype, obj)
        if etype in LIFECYCLE and self._response(attempt, obj) is None:
            return
        parts = self._strict_feed(attempt, obj)
        if parts is not None:
            proto['strict_parts'] = parts
        if not terminalish:
            return
        if not self._failure_text(obj):
            self._mark(attempt)             # content UTF-8: semantic mark
        if etype == 'error':
            attempt.outcome = self._outcome(attempt,
                (State.FAILED, 'provider_error'))
        elif etype == 'response.completed':
            if (proto.get('policy') is None and not proto.get('limited')
                    and proto.get('strict_parts') is not None):
                attempt.parts = proto['strict_parts']
            attempt.outcome = self._outcome(attempt,
                (State.COMPLETED, None))
        elif etype == 'response.incomplete':
            attempt.outcome = self._outcome(attempt,
                (State.FAILED, 'output_truncated'))
        else:
            attempt.outcome = self._outcome(attempt,
                (State.FAILED, 'provider_failed'))
        proto['term_data'] = data
        proto['term_type'] = etype
        attempt.terminal_seen = True

    def _completed(self, attempt, resp):
        """Validate completed-terminal output; marks first-wins, never raises."""
        proto = attempt.proto
        output = resp.get('output')
        if type(output) is not list:
            return self._mark(attempt)
        if len(output) > MAX_OUTPUT_ITEMS:
            return self._cap(attempt)
        acc, done = proto.get('acc', {}), proto.get('done_text', {})
        parts, keys = [], set()
        clean = proto.get('policy') is None and not proto.get('limited')
        for output_index, item in enumerate(output):
            # Non-message items (tools, reasoning, searches) are outside the
            # verified text role and are never silently dropped.
            if (type(item) is not dict or item.get('type') != 'message'
                    or item.get('role') != 'assistant'
                    or type(item.get('id')) is not str
                    or ('status' in item and item['status'] != 'completed')):
                return self._mark(attempt)
            content = item.get('content')
            if type(content) is not list:
                return self._mark(attempt)
            if len(content) > MAX_CONTENT_PARTS:
                return self._cap(attempt)
            for content_index, part in enumerate(content):
                if type(part) is not dict:
                    return self._mark(attempt)
                kind = part.get('type')
                if kind == 'output_text':
                    if (type(part.get('text')) is not str
                            or not _utf8_ok(part['text'])):
                        return self._mark(attempt)
                    if not clean:
                        continue
                    key = (item.get('id'), output_index, content_index)
                    if key in acc or key in done:
                        expected = done.get(key)
                        if expected is None:
                            expected = ''.join(acc.get(key, []))
                        if expected != part['text']:
                            return self._mark(attempt)
                    keys.add(key)
                    parts.append(part['text'])
                elif kind == 'refusal':
                    value = part.get('refusal')
                    if (value is not None
                            and (type(value) is not str
                                 or not _utf8_ok(value))):
                        return self._mark(attempt)
                    if value:
                        self._policy(attempt, 'provider_refusal')
                        clean = False
                else:
                    return self._mark(attempt)
        if clean:
            streamed = set(acc) | set(done)
            if streamed and streamed != keys:
                return self._mark(attempt)
            if len(''.join(parts).encode('utf-8')) > MAX_TEXT:
                return self._cap(attempt)
            attempt.parts = tuple(parts)
        attempt.outcome = self._outcome(attempt, (State.COMPLETED, None))

    def _sse(self, attempt, event, data):
        proto = attempt.proto
        if attempt.outcome is not None:
            if (data == proto.get('term_data')
                    and event in ('', 'message', proto.get('term_type'))):
                return   # permitted repeat: identical data, agreeing name
            if (data == '[DONE]' and event in ('', 'message')
                    and not proto.get('done')
                    and self._route.allow_terminal_done):
                proto['done'] = True
                return
            self._violate(attempt, 'activity_after_terminal')
        if data == '[DONE]':
            # Undocumented on Responses routes and never a terminal or proof:
            # a violation inside valid SSE framing; mark and keep draining.
            return self._mark(attempt)
        obj = sse_object(data)   # malformed JSON/framing: closes unconfirmed
        etype = obj.get('type')
        if type(etype) is not str or etype not in KNOWN_EVENTS:
            return self._mark(attempt)
        if event not in ('', 'message') and event != etype:
            return self._mark(attempt)   # name contradiction: shape failure
        if self._strict_checker(attempt) is not None:
            return self._sse_strict(attempt, event, etype, obj, data)
        if (not self._seq(attempt, obj)
                and etype not in TERMINALS and etype != 'error'):
            return   # a semantic violation still reaches terminal shape
        if etype in LIFECYCLE:
            resp = self._response(attempt, obj)
            if resp is None:
                return
            if resp.get('status') not in ('queued', 'in_progress'):
                return self._mark(attempt)
            return
        if etype in ITEM_EVENTS:
            item = obj.get('item')
            if (type(item) is not dict or item.get('type') != 'message'
                    or ('role' in item and item['role'] is not None
                        and item['role'] != 'assistant')):
                return self._mark(attempt)
            return
        if etype in PART_EVENTS:
            part = obj.get('part')
            if (type(part) is not dict
                    or part.get('type') not in ('output_text', 'refusal')):
                return self._mark(attempt)
            text = part.get('text')
            if (part['type'] == 'output_text' and text is not None
                    and (type(text) is not str or not _utf8_ok(text))):
                return self._mark(attempt)
            if part['type'] == 'refusal' and part.get('refusal'):
                if (type(part['refusal']) is not str
                        or not _utf8_ok(part['refusal'])):
                    return self._mark(attempt)
                self._policy(attempt, 'provider_refusal')
            return
        if etype in TEXT_EVENTS:
            key = _key(obj)
            value = obj.get('delta' if etype.endswith('.delta') else 'text')
            if (key is None or type(value) is not str
                    or not _utf8_ok(value)):
                return self._mark(attempt)
            if proto.get('policy') is not None or proto.get('limited'):
                return   # parse-discard: still detected, never accumulated
            acc = proto.setdefault('acc', {})
            if etype.endswith('.delta'):
                acc.setdefault(key, []).append(value)
                proto['text_bytes'] = proto.get('text_bytes', 0) + len(value.encode('utf-8'))
            else:
                prior = acc.get(key)
                if prior is not None and value != ''.join(prior):
                    return self._mark(attempt)
                if prior is None:
                    proto['text_bytes'] = proto.get('text_bytes', 0) + len(value.encode('utf-8'))
                acc[key] = [value]
                proto.setdefault('done_text', {})[key] = value
            if proto['text_bytes'] > MAX_TEXT:
                return self._cap(attempt)
            return
        if etype in REFUSAL_EVENTS:
            value = obj.get('delta' if etype.endswith('.delta') else 'refusal')
            if type(value) is not str or not _utf8_ok(value):
                return self._mark(attempt)
            if value:
                self._policy(attempt, 'provider_refusal')
            return
        # Terminals and the error event: the shared typed core shape is the
        # only recognition gate — semantic marks never retract it.
        if not self._terminal_shape(attempt, event, etype, obj):
            return self._mark(attempt)      # not a terminal; keep draining
        if not self._failure_text(obj):
            self._mark(attempt)             # content UTF-8 stays semantic
        if etype == 'error':
            attempt.outcome = self._outcome(attempt,
                (State.FAILED, 'provider_error'))
        else:
            resp = obj['response']
            if etype == 'response.completed':
                self._completed(attempt, resp)
                if attempt.outcome is None:
                    attempt.outcome = self._outcome(attempt,
                        (State.FAILED, 'protocol_violation'))
            elif etype == 'response.incomplete':
                details = resp.get('incomplete_details')
                if (type(details) is dict
                        and details.get('reason') == 'content_filter'):
                    # Exact typed SDK field; every other reason stays
                    # output_truncated — no text search, no vendor keys.
                    self._policy(attempt, 'content_filter')
                attempt.outcome = self._outcome(attempt,
                    (State.FAILED, 'output_truncated'))
            else:
                attempt.outcome = self._outcome(attempt,
                    (State.FAILED, 'provider_failed'))
        proto['term_data'] = data
        proto['term_type'] = etype
        attempt.terminal_seen = True
