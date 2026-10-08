"""Strict absent_single_part stream checker for a host-qualified route.

For future adapter integration only: construction requires a
RouteProtocolProfile with protocol 'responses',
index_mode 'absent_single_part' and sequence_mode 'absent'; constructing
one is never provider qualification. feed() consumes one parsed event
envelope per call in the exact ruled order — created, optional
in_progress (once), one output_item.added, one content_part.added, zero
or more output_text.delta, one output_text.done, one content_part.done,
one output_item.done, response.completed. Structural keys
sequence_number/output_index/content_index are forbidden outright, never
defaulted; required keys must be present exactly, and only the profile's
per-event inert allowlist may add keys. Nested shapes are typed against
closed field tables — ordinary-text slice only, no unchecked arbitrary
fields. Concatenated deltas must equal output_text.done, part.done,
item.done and completed text byte-for-byte.

feed(obj, discard=True) permanently latches discard: the accumulator is
cleared, no output is produced and byte equality is skipped, while
strict UTF-8 on every text field, phase order, identity binding,
required-key and forbidden-key checks all still run.

mark_unverifiable() latches the transport-gap mode: the accumulator is
dropped permanently, missing phases alone are not violations, an event
from an already-observed earlier phase still is, and the first observed
rid/iid is adopted only in this mode.

response.failed, response.incomplete and error are auxiliary terminal
events accepted at phase >= 1, or at any phase once unverifiable; they
validate closed typed shapes, produce no output and set terminal only
when fully accepted. ProfileError means a semantic violation;
ProfileCap is a separate non-policy host cap raised atomically before
any state change. Recognition, policy and cessation stay at the adapter
layer — this checker never decides terminal recognition, and refusal or
other off-vocabulary frames simply raise ProfileError.
"""
import math

from .protocol_profile import ProfileError, RouteProtocolProfile

MAX_TEXT = 262144
FORBIDDEN = frozenset({'sequence_number', 'output_index', 'content_index'})
ENVELOPE_KEYS = {
    'response.created': frozenset({'type', 'response'}),
    'response.in_progress': frozenset({'type', 'response'}),
    'response.output_item.added': frozenset({'type', 'item'}),
    'response.output_item.done': frozenset({'type', 'item'}),
    'response.content_part.added': frozenset({'type', 'item_id', 'part'}),
    'response.content_part.done': frozenset({'type', 'item_id', 'part'}),
    'response.output_text.delta': frozenset({'type', 'item_id', 'delta'}),
    'response.output_text.done': frozenset({'type', 'item_id', 'text'}),
    'response.completed': frozenset({'type', 'response'}),
    'response.failed': frozenset({'type', 'response'}),
    'response.incomplete': frozenset({'type', 'response'}),
    'error': frozenset({'type', 'code', 'message', 'param'}),
}
# Canonical required phase per ordinary event, used for the monotone
# order check once the unverifiable latch is set.
_PHASE_REQ = {
    'response.created': 0,
    'response.in_progress': 1,
    'response.output_item.added': 1,
    'response.content_part.added': 2,
    'response.output_text.delta': 3,
    'response.output_text.done': 3,
    'response.content_part.done': 4,
    'response.output_item.done': 5,
    'response.completed': 6,
}
_AUX_EVENTS = frozenset(
    {'response.failed', 'response.incomplete', 'error'})
_INCOMPLETE_REASONS = frozenset(
    {'content_filter', 'max_output_tokens', 'max_tool_calls'})
_REFUSAL_PART_FIELDS = frozenset({'type', 'refusal'})
# Closed SDK tables: ordinary text slice only. Fields carrying non-text
# semantics must be absent or null; standard fields keep typed values.
RESPONSE_FIELDS = frozenset({
    'id', 'object', 'created_at', 'model', 'status', 'output', 'error',
    'incomplete_details', 'instructions', 'metadata', 'parallel_tool_calls',
    'temperature', 'tool_choice', 'tools', 'top_p', 'usage',
    'access_programs', 'background', 'completed_at', 'conversation',
    'max_output_tokens', 'max_tool_calls', 'moderation',
    'previous_response_id', 'prompt', 'prompt_cache_diagnostics',
    'prompt_cache_key', 'prompt_cache_options', 'prompt_cache_retention',
    'reasoning', 'safety_identifier', 'service_tier', 'text', 'top_logprobs',
    'truncation', 'user'})
_NULL_ONLY = (RESPONSE_FIELDS - {
    'id', 'object', 'status', 'model', 'output', 'usage', 'tools',
    'tool_choice', 'metadata', 'created_at', 'completed_at', 'temperature',
    'top_p', 'top_logprobs', 'parallel_tool_calls', 'max_output_tokens',
    'max_tool_calls', 'error', 'incomplete_details'})
ITEM_FIELDS = frozenset({'content', 'id', 'role', 'status', 'type'})
PART_FIELDS = frozenset({'annotations', 'logprobs', 'text', 'type'})
USAGE_FIELDS = frozenset({'input_tokens', 'output_tokens', 'total_tokens',
    'input_tokens_details', 'output_tokens_details'})
DETAIL_FIELDS = frozenset({'cached_tokens', 'reasoning_tokens',
    'audio_tokens', 'accepted_prediction_tokens',
    'rejected_prediction_tokens'})


class ProfileCap(Exception):
    """Host resource limit during checking; non-policy drain upstream."""


def _utf8(value):
    try:
        return value.encode('utf-8')
    except UnicodeEncodeError:
        raise ProfileError('text invalid') from None


def _usage(value):
    if type(value) is not dict or not set(value) <= USAGE_FIELDS:
        return False
    for key, val in value.items():
        if key.endswith('_details'):
            if (type(val) is not dict or not set(val) <= DETAIL_FIELDS
                    or any(type(n) is not int or n < 0
                           for n in val.values())):
                return False
        elif type(val) is not int or val < 0:
            return False
    return True


def _response_value(key, value):
    if key in ('id', 'status', 'object'):
        return type(value) is str
    if key == 'model':
        return value is None or type(value) is str
    if key == 'error':
        return (value is None or type(value) is dict
                and set(value) <= {'code', 'message'}
                and type(value.get('message')) is str
                and (value.get('code') is None
                     or type(value.get('code')) is str))
    if key == 'incomplete_details':
        return (value is None or type(value) is dict
                and set(value) <= {'reason'}
                and value.get('reason') in _INCOMPLETE_REASONS)
    if key in _NULL_ONLY:
        return value is None
    if key in ('created_at', 'completed_at', 'temperature', 'top_p',
               'top_logprobs'):
        if value is None:
            return True
        if type(value) is int:
            return value >= 0
        return (type(value) is float and math.isfinite(value)
                and value >= 0)
    if key in ('max_output_tokens', 'max_tool_calls'):
        return value is None or type(value) is int and value >= 0
    if key == 'parallel_tool_calls':
        return value is None or type(value) is bool
    if key == 'output':
        return type(value) is list
    if key == 'usage':
        return value is None or _usage(value)
    if key == 'tools':
        return value is None or value == []
    if key == 'tool_choice':
        return value is None or value in ('none', 'auto')
    if key == 'metadata':
        return (value is None or type(value) is dict and len(value) <= 16
                and all(type(k) is str and type(v) is str
                        for k, v in value.items()))
    return False


class SinglePartChecker:
    """Stateful strict checker; ordinary successful text slice only."""

    def __init__(self, profile):
        if (type(profile) is not RouteProtocolProfile
                or profile.protocol != 'responses'
                or profile.index_mode != 'absent_single_part'
                or profile.sequence_mode != 'absent'):
            raise ProfileError('route not qualified for single-part')
        self._profile = profile
        self.terminal = False
        self._phase = 0
        self._in_progress = False
        self._rid = self._iid = None
        self._acc = bytearray()
        self._discard = self._unverifiable = False

    def mark_unverifiable(self):
        """Latch the transport-gap mode: accumulator dropped permanently,
        missing phases stop being violations, first observed ids adopt."""
        self._unverifiable = True
        self._acc = bytearray()

    def _draining(self):
        return self._discard or self._unverifiable

    def feed(self, obj, discard=False):
        """Validate one parsed envelope; returns ('text',) only on a fully
        verified response.completed, None for every other accepted event.
        discard=True permanently latches drain mode (no accumulation, no
        byte equality, no output) while every structural check still runs."""
        if discard:
            self._discard = True
            self._acc = bytearray()
        if self.terminal or type(obj) is not dict:
            raise ProfileError('stream after terminal')
        etype = obj.get('type')
        if type(etype) is not str:
            raise ProfileError('unexpected event type')
        allowed = ENVELOPE_KEYS.get(etype)
        if allowed is None or set(obj) & FORBIDDEN:
            raise ProfileError('unexpected event type')
        inert = set(self._profile.inert_fields.get(etype, ()))
        if set(obj) - inert != allowed:
            raise ProfileError('event keys invalid')
        phase = self._phase
        if etype in _AUX_EVENTS:
            if phase < 1 and not self._unverifiable:
                raise ProfileError('event out of order')
        elif self._unverifiable:
            req = _PHASE_REQ[etype]
            if req < phase:
                raise ProfileError('event out of order')
            if etype == 'response.in_progress':
                if self._in_progress:
                    raise ProfileError('event out of order')
                self._in_progress = True
            self._phase = req
        elif etype == 'response.created':
            if phase != 0:
                raise ProfileError('event out of order')
        elif etype == 'response.in_progress':
            if phase != 1 or self._in_progress:
                raise ProfileError('event out of order')
            self._in_progress = True
        elif etype == 'response.output_item.added':
            if phase != 1:
                raise ProfileError('event out of order')
        elif etype == 'response.content_part.added':
            if phase != 2:
                raise ProfileError('event out of order')
        elif etype in ('response.output_text.delta',
                       'response.output_text.done'):
            if phase != 3:
                raise ProfileError('event out of order')
        elif etype == 'response.content_part.done':
            if phase != 4:
                raise ProfileError('event out of order')
        elif etype == 'response.output_item.done':
            if phase != 5:
                raise ProfileError('event out of order')
        elif phase != 6:
            raise ProfileError('event out of order')
        return getattr(self, '_on_' + etype.replace('.', '_'))(obj)

    def _response(self, obj):
        resp = obj.get('response')
        if (type(resp) is not dict or not set(resp) <= RESPONSE_FIELDS
                or not all(_response_value(k, v)
                           for k, v in resp.items())
                or ('object' in resp and resp['object'] != 'response')
                or type(resp.get('id')) is not str or not resp['id']
                or type(resp.get('status')) is not str):
            raise ProfileError('response invalid')
        err = resp.get('error')
        if err is not None:
            _utf8(err['message'])
        if self._rid is None:
            self._rid = resp['id']
        if resp['id'] != self._rid:
            raise ProfileError('response id mismatch')
        model = resp.get('model')
        if model is not None and model != self._profile.model:
            raise ProfileError('served model mismatch')
        return resp

    def _item_id(self, obj):
        iid = obj.get('item_id')
        if type(iid) is not str:
            raise ProfileError('item id mismatch')
        if self._iid is None and self._unverifiable:
            self._iid = iid
        if iid != self._iid:
            raise ProfileError('item id mismatch')

    def _bind_item_id(self, iid, exc):
        if type(iid) is not str or not iid:
            raise ProfileError(exc)
        if self._iid is None and self._unverifiable:
            self._iid = iid
        if iid != self._iid:
            raise ProfileError(exc)

    def _part(self, part, need_text):
        if (type(part) is not dict or not set(part) <= PART_FIELDS
                or part.get('type') != 'output_text'
                or part.get('annotations', []) != []
                or part.get('logprobs', []) != []
                or (need_text and type(part.get('text')) is not str)
                or ('text' in part and type(part['text']) is not str)):
            raise ProfileError('part invalid')
        return part

    def _output_item(self, item):
        if (type(item) is not dict or not set(item) <= ITEM_FIELDS
                or item.get('type') != 'message'
                or item.get('role') != 'assistant'
                or item.get('status') != 'completed'):
            raise ProfileError('output item invalid')
        self._bind_item_id(item.get('id'), 'output item invalid')
        content = item.get('content')
        if type(content) is not list or len(content) != 1:
            raise ProfileError('item content invalid')
        part = self._part(content[0], need_text=True)
        data = _utf8(part['text'])
        if not self._draining() and data != bytes(self._acc):
            raise ProfileError('text agreement mismatch')

    def _on_response_created(self, obj):
        if self._response(obj).get('status') != 'in_progress':
            raise ProfileError('response invalid')
        self._phase = 1

    def _on_response_in_progress(self, obj):
        if self._response(obj).get('status') != 'in_progress':
            raise ProfileError('response invalid')

    def _on_response_output_item_added(self, obj):
        item = obj.get('item')
        if (type(item) is not dict or not set(item) <= ITEM_FIELDS
                or item.get('type') != 'message'
                or item.get('role') != 'assistant'
                or item.get('status') != 'in_progress'
                or type(item.get('id')) is not str or not item['id']
                or item.get('content') != []):
            raise ProfileError('item invalid')
        if self._iid is not None and item['id'] != self._iid:
            raise ProfileError('item invalid')
        self._iid = item['id']
        self._phase = 2

    def _on_response_content_part_added(self, obj):
        self._item_id(obj)
        part = self._part(obj.get('part'), need_text=False)
        if part.get('text', '') != '':
            raise ProfileError('part invalid')
        self._phase = 3

    def _on_response_output_text_delta(self, obj):
        self._item_id(obj)
        delta = obj.get('delta')
        if type(delta) is not str:
            raise ProfileError('delta invalid')
        data = _utf8(delta)
        if self._draining():
            return
        if len(self._acc) + len(data) > MAX_TEXT:
            raise ProfileCap('output limit exceeded')
        self._acc += data

    def _on_response_output_text_done(self, obj):
        self._item_id(obj)
        text = obj.get('text')
        if type(text) is not str:
            raise ProfileError('text agreement mismatch')
        data = _utf8(text)
        if not self._draining() and data != bytes(self._acc):
            raise ProfileError('text agreement mismatch')
        self._phase = 4

    def _on_response_content_part_done(self, obj):
        self._item_id(obj)
        part = self._part(obj.get('part'), need_text=True)
        data = _utf8(part['text'])
        if not self._draining() and data != bytes(self._acc):
            raise ProfileError('text agreement mismatch')
        self._phase = 5

    def _on_response_output_item_done(self, obj):
        self._output_item(obj.get('item'))
        self._phase = 6

    def _on_response_completed(self, obj):
        resp = self._response(obj)
        if resp.get('status') != 'completed':
            raise ProfileError('response invalid')
        if resp.get('model') != self._profile.model:
            raise ProfileError('served model mismatch')
        output = resp.get('output')
        if type(output) is not list or len(output) != 1:
            raise ProfileError('terminal output invalid')
        self._output_item(output[0])
        self.terminal = True
        if self._draining():
            return None
        return (bytes(self._acc).decode('utf-8'),)

    def _aux_part(self, part):
        if type(part) is not dict:
            raise ProfileError('part invalid')
        ptype = part.get('type')
        if ptype == 'output_text':
            if not set(part) <= PART_FIELDS:
                raise ProfileError('part invalid')
            for key in ('annotations', 'logprobs'):
                if key in part and type(part[key]) is not list:
                    raise ProfileError('part invalid')
            if 'text' in part:
                if type(part['text']) is not str:
                    raise ProfileError('part invalid')
                _utf8(part['text'])
        elif ptype == 'refusal':
            if (not set(part) <= _REFUSAL_PART_FIELDS
                    or type(part.get('refusal')) is not str):
                raise ProfileError('part invalid')
            _utf8(part['refusal'])
        else:
            raise ProfileError('part invalid')

    def _aux_output_item(self, item):
        if (type(item) is not dict or not set(item) <= ITEM_FIELDS
                or item.get('type') != 'message'
                or item.get('role') != 'assistant'
                or item.get('status') not in ('completed', 'incomplete',
                                              'in_progress')):
            raise ProfileError('output item invalid')
        if 'id' in item:
            self._bind_item_id(item['id'], 'output item invalid')
        content = item.get('content')
        if content is None:
            return
        if type(content) is not list or len(content) > 1:
            raise ProfileError('item content invalid')
        for part in content:
            self._aux_part(part)

    def _aux_response(self, obj, status):
        resp = self._response(obj)
        if resp.get('status') != status:
            raise ProfileError('response invalid')
        output = resp.get('output')
        if type(output) is not list or len(output) > 1:
            raise ProfileError('terminal output invalid')
        for item in output:
            self._aux_output_item(item)
        return resp

    def _on_response_failed(self, obj):
        self._aux_response(obj, 'failed')
        self.terminal = True

    def _on_response_incomplete(self, obj):
        self._aux_response(obj, 'incomplete')
        self.terminal = True

    def _on_error(self, obj):
        code = obj.get('code')
        param = obj.get('param')
        message = obj.get('message')
        if (not (code is None or type(code) is str)
                or not (param is None or type(param) is str)
                or type(message) is not str):
            raise ProfileError('error event invalid')
        _utf8(message)
        self.terminal = True
