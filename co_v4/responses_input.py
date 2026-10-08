"""Strict Responses-subset northbound request parsing (#190 M3).

Pure input validation only. No endpoint, auth, credential, or provider
configuration is admitted here; nothing is interpreted, executed, or sent.

- Accepted fields: model, input, instructions, background, stream, metadata,
  store, tools, tool_choice, text. KNOWN_UNSUPPORTED names every remaining
  SDK 3.24.0 ResponseCreateParams key: null (and include:[]) is absent,
  any other value is unsupported_field. Truly unknown keys fail as
  unknown_field.
- Optional null equals absent. Ordered system/developer/user/assistant text
  roles, string-vs-fragment content shape, and distinct instructions are
  preserved exactly; no normalization or trimming of text bytes.
- Canonical body/hash cover the normalized schema-validated request including
  the alias string, for the gateway's (principal, key) idempotency compare
  BEFORE mutable alias resolution. Client fields never carry effect_class,
  output, AC, or authority.
- MAX_BODY_BYTES is an explicit conservative host resource limit (gateway
  maps it to 413), not a silently unsupported field choice.
"""
from dataclasses import dataclass
import hashlib
import json
import re


MAX_BODY_BYTES = 256 * 1024      # host resource limit; documented route cap
MAX_ALIAS_CHARS = 128            # bounded task-profile alias string
MAX_INPUT_ITEMS = 64             # ordered message items per request
MAX_CONTENT_PARTS = 64           # text fragments per message item
MAX_METADATA_PAIRS = 16
MAX_METADATA_KEY = 64
MAX_METADATA_VALUE = 512

ROLES = frozenset({'system', 'developer', 'user', 'assistant'})
FIELDS = frozenset({'model', 'input', 'instructions', 'background', 'stream',
                    'metadata', 'store', 'tools', 'tool_choice', 'text'})
# Installed SDK 3.24.0 ResponseCreateParams{,NonStreaming} top-level keys
# minus FIELDS; pinned by test_responses_input against a literal table.
KNOWN_UNSUPPORTED = frozenset({
    'access_programs', 'context_management', 'conversation', 'include',
    'max_output_tokens', 'max_tool_calls', 'moderation', 'parallel_tool_calls',
    'previous_response_id', 'prompt', 'prompt_cache_key',
    'prompt_cache_options', 'prompt_cache_retention', 'reasoning',
    'safety_identifier', 'service_tier', 'stream_options', 'temperature',
    'top_logprobs', 'top_p', 'truncation', 'user'})
ITEM_KEYS = frozenset({'type', 'role', 'content', 'phase'})
# Per-part key tables, pinned by tests to the installed SDK 3.24.0
# ResponseInputTextParam / ResponseOutputTextParam. Keys outside the table
# are rejected whatever their value; inert optional keys accept null or []
# as absent and are dropped from the canonical form.
PART_KEYS = {
    'input_text': frozenset({'type', 'text', 'prompt_cache_breakpoint'}),
    'output_text': frozenset({'type', 'text', 'annotations', 'logprobs'}),
}
PART_INERT = {
    'input_text': frozenset(),
    'output_text': frozenset({'annotations', 'logprobs'}),
}
TEXT_FORMAT = {'format': {'type': 'text'}}
DOMAIN = b'co.responses.request/1\n'
_SAFE_PARAM = re.compile(r'[A-Za-z0-9_.\-]{1,64}\Z')

MESSAGES = {
    'body_too_large': 'request body exceeds the host byte limit',
    'invalid_utf8': 'request body is not valid UTF-8',
    'invalid_json': 'request body is not well-formed strict JSON',
    'duplicate_key': 'request body contains a duplicate object key',
    'invalid_request_body': 'request body must be a JSON object',
    'missing_required_field': 'a required field is missing',
    'unknown_field': 'an unsupported field was provided',
    'unsupported_field': 'field semantics are unsupported by this subset',
    'invalid_field_type': 'field has an invalid type for this subset',
    'invalid_field_value': 'field has an invalid value for this subset',
}


class RequestRejected(Exception):
    """invalid_request_error. Fixed codes/messages; no client bytes echoed."""
    def __init__(self, code, param=None):
        self.code, self.param = code, param
        super().__init__(MESSAGES[code])


@dataclass(frozen=True)
class Fragment:
    kind: str                            # 'input_text' or assistant 'output_text'
    text: str


@dataclass(frozen=True)
class Item:
    role: str                            # system|developer|user|assistant
    content: 'str | tuple[Fragment, ...]'


@dataclass(frozen=True)
class TaskIntent:
    """Schema-validated subset intent; carries echo fields, not authority."""
    model: str
    input: 'str | tuple[Item, ...]'
    instructions: str | None
    background: bool
    store: bool
    metadata: tuple[tuple[str, str], ...]
    canonical_body: bytes
    body_hash: str


def _param(name):
    return name if isinstance(name, str) and _SAFE_PARAM.match(name) else None


def _reject_constant(value):
    raise ValueError('non-finite number is not strict JSON')


def _object(pairs):
    seen, out = set(), {}
    for key, value in pairs:
        if key in seen:
            raise RequestRejected('duplicate_key', _param(key))
        seen.add(key)
        out[key] = value
    return out


def _text(value, param, limit=None):
    if type(value) is not str:
        raise RequestRejected('invalid_field_type', param)
    if (limit is not None and len(value) > limit) or any(
            0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise RequestRejected('invalid_field_value', param)
    return value


def _fragment(value, role):
    if type(value) is not dict:
        raise RequestRejected('invalid_field_type', 'input')
    kind = value.get('type')
    if type(kind) is not str:
        raise RequestRejected('invalid_field_type', 'input')
    if kind != 'input_text' and not (kind == 'output_text' and role == 'assistant'):
        raise RequestRejected('invalid_field_value', 'input')
    if set(value) - PART_KEYS[kind]:
        # Part keys outside the SDK param type fail whatever their value.
        raise RequestRejected('unsupported_field', 'input')
    for key in PART_KEYS[kind] - {'type', 'text'}:
        present = value.get(key)
        if present is None:
            continue
        if key not in PART_INERT[kind] or present != []:
            raise RequestRejected('unsupported_field', 'input')
    return Fragment(kind, _text(value.get('text'), 'input'))


def _item(value):
    if type(value) is not dict:
        raise RequestRejected('invalid_field_type', 'input')
    if set(value) - ITEM_KEYS:
        raise RequestRejected('unsupported_field', 'input')
    if value.get('phase') is not None:
        # phase carries real assistant semantics; only null is absent.
        raise RequestRejected('unsupported_field', 'input')
    kind = value.get('type')
    if kind is not None:
        # The easy-message form omits type; canonical emits "message" always.
        if type(kind) is not str:
            raise RequestRejected('invalid_field_type', 'input')
        if kind != 'message':
            raise RequestRejected('unsupported_field', 'input')
    role = value.get('role')
    if type(role) is not str:
        raise RequestRejected('invalid_field_type', 'input')
    if role not in ROLES:
        raise RequestRejected('invalid_field_value', 'input')
    content = value.get('content')
    if type(content) is str:
        return Item(role, _text(content, 'input'))
    if type(content) is not list:
        raise RequestRejected('invalid_field_type', 'input')
    if len(content) > MAX_CONTENT_PARTS:
        raise RequestRejected('invalid_field_value', 'input')
    return Item(role, tuple(_fragment(part, role) for part in content))


def _input(value):
    if type(value) is str:
        return _text(value, 'input')
    if type(value) is not list:
        raise RequestRejected('invalid_field_type', 'input')
    if not value or len(value) > MAX_INPUT_ITEMS:
        raise RequestRejected('invalid_field_value', 'input')
    return tuple(_item(item) for item in value)


def _text_total(items):
    if type(items) is str:
        return len(items)
    return sum(len(item.content) if type(item.content) is str
               else sum(len(f.text) for f in item.content)
               for item in items)


def _wire(value):
    if type(value) is str:
        return value
    return [{'type': 'message', 'role': item.role,
             'content': item.content if type(item.content) is str else
                 [{'type': f.kind, 'text': f.text} for f in item.content]}
            for item in value]


def _validate(raw) -> TaskIntent:
    if type(raw) is not dict:
        raise RequestRejected('invalid_request_body')
    # Truly unknown keys are rejected whatever their value, including null:
    # classify them on the raw keys before any null stripping can erase them.
    for key in sorted(set(raw) - FIELDS - KNOWN_UNSUPPORTED):
        raise RequestRejected('unknown_field', _param(key))
    # Optional null equals absent, but only for known fields.
    given = {k: v for k, v in raw.items() if v is not None}
    for key in sorted(set(given) - FIELDS):
        if not (key == 'include' and given[key] == []):
            raise RequestRejected('unsupported_field', _param(key))
    model = given.get('model')
    if model is None:
        raise RequestRejected('missing_required_field', 'model')
    model = _text(model, 'model', MAX_ALIAS_CHARS)
    if not model or not all(0x21 <= ord(ch) <= 0x7E for ch in model):
        raise RequestRejected('invalid_field_value', 'model')
    value = given.get('input')
    if value is None:
        raise RequestRejected('missing_required_field', 'input')
    items = _input(value)
    if not _text_total(items):
        raise RequestRejected('invalid_field_value', 'input')
    instructions = given.get('instructions')
    if instructions is not None:
        instructions = _text(instructions, 'instructions')
    background = given.get('background', False)
    if type(background) is not bool:
        raise RequestRejected('invalid_field_type', 'background')
    stream = given.get('stream')
    if stream is not None and stream is not False:
        raise RequestRejected('invalid_field_value', 'stream')
    if 'store' in given and given['store'] is not True:
        # CO persists; store:false cannot mean zero-retention here.
        raise RequestRejected('invalid_field_value', 'store')
    if 'tools' in given and (type(given['tools']) is not list
                             or given['tools'] != []):
        raise RequestRejected('unsupported_field', 'tools')
    if 'tool_choice' in given:
        raise RequestRejected('unsupported_field', 'tool_choice')
    if 'text' in given:
        if type(given['text']) is not dict:
            raise RequestRejected('invalid_field_type', 'text')
        if given['text'] != TEXT_FORMAT:
            raise RequestRejected('unsupported_field', 'text')
    metadata = given.get('metadata')
    if metadata is None:
        metadata = ()
    else:
        if type(metadata) is not dict:
            raise RequestRejected('invalid_field_type', 'metadata')
        if len(metadata) > MAX_METADATA_PAIRS:
            raise RequestRejected('invalid_field_value', 'metadata')
        pairs = []
        for mkey, mval in metadata.items():
            _text(mkey, 'metadata')
            _text(mval, 'metadata')
            if (not mkey or len(mkey) > MAX_METADATA_KEY
                    or len(mval) > MAX_METADATA_VALUE):
                raise RequestRejected('invalid_field_value', 'metadata')
            pairs.append((mkey, mval))
        metadata = tuple(sorted(pairs))
    normalized = {'model': model, 'input': _wire(items),
                  'background': background, 'store': True}
    if instructions is not None:
        normalized['instructions'] = instructions
    if metadata:
        normalized['metadata'] = dict(metadata)
    canonical_body = json.dumps(normalized, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode('utf-8')
    return TaskIntent(model, items, instructions, background, True, metadata,
                      canonical_body,
                      hashlib.sha256(DOMAIN + canonical_body).hexdigest())


def parse(body: bytes, *, limit: int = MAX_BODY_BYTES) -> TaskIntent:
    """Validate strict-subset bytes. Raises only RequestRejected."""
    if type(body) is not bytes:
        raise RequestRejected('invalid_field_type')
    if len(body) > limit:
        raise RequestRejected('body_too_large')
    try:
        text = body.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        raise RequestRejected('invalid_utf8') from None
    try:
        raw = json.loads(text, parse_constant=_reject_constant,
                         object_pairs_hook=_object)
    except (ValueError, RecursionError):
        raise RequestRejected('invalid_json') from None
    try:
        return _validate(raw)
    except RecursionError:
        raise RequestRejected('invalid_json') from None
