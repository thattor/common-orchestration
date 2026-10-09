"""Pure value/shape validation for codex-cli 0.160.1 experimental text frames.

In-memory checks only: no transport, session, process, clock, lifecycle or
RPC-binding logic lives here. Importing this module launches nothing.
"""

import math
import re

from co_v4.adapters.codex import MAX_BYTES, NativeError

INT64_MIN = -9223372036854775808
INT64_MAX = 9223372036854775807

E_RPC_ID = 'rpc_id_invalid'
E_NATIVE_REQUEST = 'text_job_native_request'
E_RPC_ERROR = 'native_rpc_error'
E_FRAME = 'frame_invalid'
E_TEXT = 'text_output_invalid'
E_ITEM = 'item_invalid'
E_TERMINAL = 'terminal_invalid'


class ValidationError(NativeError):
    """Fixed-code validation failure; never carries input data or payloads."""


TURN_SCHEMA = {'properties': {'completedAt': {'type': ['integer', 'null'], 'minimum': -9223372036854775808, 'maximum': 9223372036854775807}, 'durationMs': {'type': ['integer', 'null'], 'minimum': -9223372036854775808, 'maximum': 9223372036854775807}, 'error': {'type': 'null'}, 'id': {'type': 'string', 'minLength': 1, 'maxUtf8Bytes': 1024}, 'items': {'items': {'$ref': '#/definitions/ThreadItem'}, 'type': 'array'}, 'itemsView': {'allOf': [{'$ref': '#/definitions/TurnItemsView'}]}, 'startedAt': {'type': ['integer', 'null'], 'minimum': -9223372036854775808, 'maximum': 9223372036854775807}, 'status': {'$ref': '#/definitions/TurnStatus'}}, 'required': ['id', 'items', 'status'], 'type': 'object', 'additionalProperties': False}

DEFINITIONS = {
    'ThreadItem': {'oneOf': [{'properties': {'clientId': {'type': ['string', 'null']}, 'content': {'items': {'$ref': '#/definitions/UserInput'}, 'type': 'array'}, 'id': {'type': 'string', 'minLength': 1, 'maxUtf8Bytes': 1024}, 'type': {'enum': ['userMessage'], 'type': 'string'}}, 'required': ['content', 'id', 'type'], 'type': 'object', 'additionalProperties': False}, {'properties': {'delivery': {'type': 'null'}, 'id': {'type': 'string', 'minLength': 1, 'maxUtf8Bytes': 1024}, 'memoryCitation': {'type': 'null'}, 'phase': {'anyOf': [{'$ref': '#/definitions/MessagePhase'}, {'type': 'null'}]}, 'questions': {'type': ['array', 'null'], 'items': False, 'maxItems': 0}, 'text': {'type': 'string', 'maxUtf8Bytes': 1048576}, 'type': {'enum': ['agentMessage'], 'type': 'string'}}, 'required': ['id', 'text', 'type'], 'type': 'object', 'additionalProperties': False}, {'properties': {'content': {'items': {'type': 'string'}, 'type': 'array'}, 'id': {'type': 'string', 'minLength': 1, 'maxUtf8Bytes': 1024}, 'summary': {'items': {'type': 'string'}, 'type': 'array'}, 'type': {'enum': ['reasoning'], 'type': 'string'}}, 'required': ['id', 'type'], 'type': 'object', 'additionalProperties': False}]},
    'UserInput': {'oneOf': [{'properties': {'text': {'type': 'string', 'maxUtf8Bytes': 1048576}, 'text_elements': {'type': 'array', 'items': False, 'maxItems': 0}, 'type': {'enum': ['text'], 'type': 'string'}}, 'required': ['text', 'type'], 'type': 'object', 'additionalProperties': False}]},
    'MessagePhase': {'oneOf': [{'enum': ['commentary'], 'type': 'string'}, {'enum': ['final_answer'], 'type': 'string'}]},
    'TurnItemsView': {'oneOf': [{'enum': ['notLoaded'], 'type': 'string'}, {'enum': ['summary'], 'type': 'string'}, {'enum': ['full'], 'type': 'string'}]},
    'TurnStatus': {'enum': ['completed', 'interrupted', 'failed', 'inProgress'], 'type': 'string'}
}

_THREAD_ITEM = DEFINITIONS['ThreadItem']
_ITEM_KINDS = ('userMessage', 'reasoning', 'agentMessage')
_NOTIFICATION_METHODS = frozenset({
    'account/updated', 'account/rateLimits/updated', 'thread/started',
    'thread/status/changed', 'thread/tokenUsage/updated', 'turn/started',
    'turn/completed', 'item/started', 'item/completed',
    'item/agentMessage/delta', 'item/reasoning/summaryTextDelta',
    'item/reasoning/textDelta', 'item/reasoning/summaryPartAdded',
    'warning', 'remoteControl/status/changed',
})


def _schema_valid(value, schema, definitions=None, depth=0):
    """Bounded validator for the fixed local schema subset; unknown keys deny."""
    if depth > 32 or type(schema) not in (dict, bool):
        return False
    if type(schema) is bool:
        return schema
    definitions = schema.get('definitions', {}) if definitions is None else definitions
    if '$ref' in schema:
        ref = schema['$ref']
        refs = {'#/definitions/' + name: spec for name, spec in DEFINITIONS.items()}
        if type(ref) is not str or ref not in refs:
            return False
        return _schema_valid(value, refs[ref], DEFINITIONS, depth + 1)
    for key, predicate in (('anyOf', any), ('allOf', all)):
        if key in schema and not predicate(_schema_valid(value, s, definitions, depth + 1) for s in schema[key]):
            return False
    if 'oneOf' in schema and sum(1 for s in schema['oneOf'] if _schema_valid(value, s, definitions, depth + 1)) != 1:
        return False
    if 'enum' in schema and value not in schema['enum']:
        return False
    if 'const' in schema and value != schema['const']:
        return False
    types = schema.get('type')
    types = [types] if type(types) is str else types
    matches = {'null': value is None, 'string': type(value) is str,
               'integer': type(value) is int, 'boolean': type(value) is bool,
               'number': type(value) is int or (type(value) is float and math.isfinite(value)),
               'object': type(value) is dict, 'array': type(value) is list}
    if types and not any(matches.get(t, False) for t in types):
        return False
    if type(value) is dict and (schema.get('type') == 'object' or 'properties' in schema):
        props = schema.get('properties', {})
        if not set(schema.get('required', ())) <= set(value):
            return False
        for key, item in value.items():
            if not _schema_valid(item, props.get(key, schema.get('additionalProperties', False)), definitions, depth + 1):
                return False
    if type(value) is list:
        if not schema.get('minItems', 0) <= len(value) <= min(schema.get('maxItems', 128), 128):
            return False
        if 'items' in schema and not all(_schema_valid(v, schema['items'], definitions, depth + 1) for v in value):
            return False
    if type(value) is str:
        try:
            size = len(value.encode('utf-8'))
        except UnicodeEncodeError:
            return False
        if size > schema.get('maxUtf8Bytes', 65536):
            return False
        char_limit = schema.get('maxLength', schema.get('maxUtf8Bytes', 65536))
        if not schema.get('minLength', 0) <= len(value) <= char_limit:
            return False
        if 'pattern' in schema and re.search(schema['pattern'], value) is None:
            return False
    if type(value) in (int, float) and not schema.get('minimum', -math.inf) <= value <= schema.get('maximum', math.inf):
        return False
    return True


def _check_cap(max_output_bytes):
    if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= MAX_BYTES:
        raise ValidationError(E_TEXT)


def rpc_key(value):
    """Return a typed ('int'|'str', value) key for a JSON-RPC request id."""
    if type(value) is int and INT64_MIN <= value <= INT64_MAX:
        return ('int', value)
    if type(value) is str and value:
        try:
            if len(value.encode('utf-8')) <= 1024:
                return ('str', value)
        except UnicodeEncodeError:
            pass
    raise ValidationError(E_RPC_ID)


def frame_kind(frame):
    """Classify a decoded frame as 'response' or 'notification'; deny the rest."""
    if type(frame) is not dict:
        raise ValidationError(E_FRAME)
    if 'id' in frame and 'method' in frame:
        raise ValidationError(E_NATIVE_REQUEST)
    if 'method' in frame:
        if 'params' not in frame or not set(frame) <= {'method', 'params', 'jsonrpc', 'emittedAtMs'}:
            raise ValidationError(E_FRAME)
        if type(frame['method']) is not str or frame['method'] not in _NOTIFICATION_METHODS:
            raise ValidationError(E_FRAME)
        if type(frame['params']) is not dict:
            raise ValidationError(E_FRAME)
        if frame.get('jsonrpc', '2.0') != '2.0':
            raise ValidationError(E_FRAME)
        if 'emittedAtMs' in frame:
            emitted = frame['emittedAtMs']
            if type(emitted) is not int or not INT64_MIN <= emitted <= INT64_MAX:
                raise ValidationError(E_FRAME)
        return 'notification'
    if 'id' not in frame or not set(frame) <= {'id', 'result', 'error', 'jsonrpc'}:
        raise ValidationError(E_FRAME)
    if frame.get('jsonrpc', '2.0') != '2.0':
        raise ValidationError(E_FRAME)
    rpc_key(frame['id'])
    if ('result' in frame) == ('error' in frame):
        raise ValidationError(E_FRAME)
    if 'error' in frame:
        raise ValidationError(E_RPC_ERROR)
    return 'response'


def text_bytes(value, max_output_bytes):
    """Return UTF-8 byte length of a string within the caller byte cap."""
    _check_cap(max_output_bytes)
    if type(value) is not str:
        raise ValidationError(E_TEXT)
    try:
        size = len(value.encode('utf-8'))
    except UnicodeEncodeError:
        raise ValidationError(E_TEXT) from None
    if size > max_output_bytes:
        raise ValidationError(E_TEXT)
    return size


def checked_item(item, *, max_output_bytes, completed=True):
    """Shape-validate a ThreadItem and return a fresh canonical dict."""
    _check_cap(max_output_bytes)
    if type(completed) is not bool:
        raise ValidationError(E_ITEM)
    if type(item) is not dict or item.get('type') not in _ITEM_KINDS:
        raise ValidationError(E_ITEM)
    if not _schema_valid(item, _THREAD_ITEM, DEFINITIONS):
        raise ValidationError(E_ITEM)
    kind = item['type']
    if kind == 'userMessage':
        client_id = item.get('clientId')
        if client_id is not None:
            try:
                if len(client_id.encode('utf-8')) > 1024:
                    raise ValidationError(E_ITEM)
            except UnicodeEncodeError:
                raise ValidationError(E_ITEM) from None
        return {'id': item['id'], 'type': kind, 'clientId': client_id,
                'content': [{'type': 'text', 'text': u['text'],
                             'text_elements': list(u.get('text_elements') or [])}
                            for u in item['content']]}
    if kind == 'reasoning':
        return {'id': item['id'], 'type': kind,
                'content': list(item.get('content') or []),
                'summary': list(item.get('summary') or [])}
    text_bytes(item['text'], max_output_bytes)
    phase = item.get('phase')
    ok = phase == 'final_answer' if completed else phase in (None, 'final_answer')
    if not ok:
        raise ValidationError(E_ITEM)
    return {'id': item['id'], 'type': kind, 'text': item['text'], 'phase': phase,
            'delivery': None, 'memoryCitation': None, 'questions': None}


def _type_counts(items):
    return {k: sum(1 for i in items if i['type'] == k) for k in _ITEM_KINDS}


def checked_terminal(turn, completed_items, *, max_output_bytes):
    """Return a counts-only inventory for a completed turn vs. observed items."""
    _check_cap(max_output_bytes)
    if not _schema_valid(turn, TURN_SCHEMA, DEFINITIONS):
        raise ValidationError(E_TERMINAL)
    if turn['status'] != 'completed' or turn.get('error') is not None:
        raise ValidationError(E_TERMINAL)
    if type(completed_items) is not dict or len(completed_items) > 128:
        raise ValidationError(E_TERMINAL)
    canonical = {}
    for key, item in completed_items.items():
        if type(item) is not dict or item.get('id') != key:
            raise ValidationError(E_TERMINAL)
        try:
            canonical[key] = checked_item(item, max_output_bytes=max_output_bytes, completed=True)
        except ValidationError:
            raise ValidationError(E_TERMINAL) from None
    finals = [k for k, v in canonical.items()
              if v['type'] == 'agentMessage' and v['phase'] == 'final_answer']
    if len(finals) != 1:
        raise ValidationError(E_TERMINAL)
    view = turn.get('itemsView', 'full')
    if view not in ('full', 'summary', 'notLoaded'):
        raise ValidationError(E_TERMINAL)
    terminal = []
    for raw in turn['items']:
        try:
            terminal.append(checked_item(raw, max_output_bytes=max_output_bytes, completed=False))
        except ValidationError:
            raise ValidationError(E_TERMINAL) from None
    if view == 'full':
        ids = [i['id'] for i in terminal]
        if len(ids) != len(set(ids)) or set(ids) != set(canonical):
            raise ValidationError(E_TERMINAL)
        if any(i != canonical[i['id']] for i in terminal):
            raise ValidationError(E_TERMINAL)
        matched = len(ids)
    elif view == 'summary':
        if len(terminal) != 1 or terminal[0] != canonical[finals[0]]:
            raise ValidationError(E_TERMINAL)
        matched = 1
    elif terminal:
        raise ValidationError(E_TERMINAL)
    else:
        matched = 0
    return {'view': view, 'terminal_count': len(terminal),
            'completed_count': len(canonical),
            'terminal_types': _type_counts(terminal),
            'completed_types': _type_counts(canonical.values()),
            'matched_id_count': matched, 'unique_ids': True,
            'agent_texts_match_observed': True}
