"""Frozen TaskSpec and structured worker-output validators. Stdlib only.

Exact wire payloads, no extra keys accepted:
  spec    {"schema":"co.task/1"|"co.task/2"|"co.task/3", ...}; v2 adds optional
          selection, announcement, and focus keys
  plan    {"schema":"co.task-plan/1","steps":[{"id","role","instructions","inputs"}]}
          co.task-plan/2 adds a required per-step "focus" enum member
  changes {"files":[{"path":p,"content":c}],"summary":str}
  review  {"verdict":"approve|request_changes","findings":[str]}

All failures raise common.TaskError: spec_invalid, plan_invalid,
changes_invalid, review_invalid. Worker text never supplies routes, scope, or
verifier argv. Error details never echo raw worker payload values.
"""
import re
import unicodedata

from ..catalog import CATEGORIES
from .common import TaskError, parse_json

SCHEMA = 'co.task/1'
PLAN_SCHEMA = 'co.task-plan/1'
SCHEMA_V2 = 'co.task/2'
PLAN_SCHEMA_V2 = 'co.task-plan/2'
SCHEMA_V3 = 'co.task/3'

ROLES = frozenset({'design', 'implement', 'review'})
ROLES_V2 = frozenset({'planner', 'design', 'implement', 'review'})
SELECTION_MODES = frozenset({'suitability', 'usage', 'fixed'})
ROUTES = frozenset({'claude', 'devin'})
ANNOUNCEMENTS = frozenset({'standard', 'quiet'})
FOCI = CATEGORIES - {'other'}
DEFAULT_FOCUS = 'architecture_planning'
VERDICTS = frozenset({'approve', 'request_changes'})
RESERVED = frozenset({'.git', '.co-verify-tmp'})
MAX_FILE_BYTES = 65536
_MAX_MODEL_BYTES = 128
_MAX_GOAL_BYTES = 20000
_MAX_INSTRUCTIONS_BYTES = 4096
_MAX_FINDING_BYTES = 2000
_MAX_SUMMARY_BYTES = 4096
_MAX_PATH_BYTES = 512
_MAX_ARG_BYTES = 512
_MAX_BASE_BYTES = 256
_MAX_PATHS = 256
_MAX_ARGV = 16
_MAX_FINDINGS = 64
_SHA_RE = re.compile(r'[0-9a-f]{40}')


def _err(code: str, detail: str):
    raise TaskError(code, detail)


def _size(value):
    """UTF-8 byte length, or None when not a strict-UTF-8 string."""
    if not isinstance(value, str):
        return None
    try:
        return len(value.encode('utf-8'))
    except UnicodeEncodeError:
        return None


def _bstr(value, limit: int, code: str, what: str, empty_ok: bool = False):
    n = _size(value)
    if n is None or n > limit or (not empty_ok and not value.strip()):
        _err(code, f'{what} must be strict-UTF-8 str within {limit} bytes')
    return value


def _rel(path, what: str) -> str:
    if _size(path) is None or not path or _size(path) > _MAX_PATH_BYTES:
        _err('spec_invalid', f'{what} must be a bounded UTF-8 path string')
    if (path.startswith('/') or '\\' in path or '\x00' in path
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in path)):
        _err('spec_invalid', f'{what} must be a clean relative POSIX path')
    parts = path.split('/')
    if any(p in ('', '.', '..') for p in parts):
        _err('spec_invalid', f'{what} must be normalized without . or ..')
    if any(p.casefold() == '.git' or p.casefold().startswith('.co-verify-tmp')
           for p in parts):
        _err('spec_invalid', f'{what} may not address reserved names')
    return path


def _pathlist(value, what: str) -> list:
    if not isinstance(value, list) or len(value) > _MAX_PATHS:
        _err('spec_invalid', f'{what} must be a list of at most {_MAX_PATHS}')
    out = [_rel(p, what) for p in value]
    if len(set(out)) != len(out):
        _err('spec_invalid', f'{what} contains duplicates')
    return out


def _no_ancestor(paths: list):
    """Reject 'a' plus 'a/b': a listed file cannot be another's ancestor dir."""
    aliases = {}
    for p in paths:
        key = unicodedata.normalize('NFC', p).casefold()
        if key in aliases and aliases[key] != p:
            _err('spec_invalid', 'scope paths alias on supported filesystems')
        aliases[key] = p
    pts = sorted(p.split('/') for p in aliases)
    for a, b in zip(pts, pts[1:]):
        if len(a) < len(b) and b[:len(a)] == a:
            _err('spec_invalid', 'path listed both as file and as ancestor')


def _bounded_int(value, lo: int, hi: int, default: int, what: str) -> int:
    if value is None:
        return default
    if type(value) is not int or not lo <= value <= hi:
        _err('spec_invalid', f'{what} must be int {lo}..{hi}')
    return value


def validate_spec(spec: dict) -> dict:
    """Return a deep-copied, fully validated TaskSpec (base_sha resolved).

    Dispatches on spec['schema']: co.task/1 keeps the frozen v1 contract;
    co.task/2 additionally accepts selection, announcement, and focus keys;
    co.task/3 uses the same fields and defaults as co.task/2.
    """
    if not isinstance(spec, dict):
        _err('spec_invalid', 'spec must be a dict')
    if spec.get('schema') == SCHEMA_V2:
        return _validate_spec_v2(spec)
    if spec.get('schema') == SCHEMA_V3:
        return _validate_spec_v3(spec)
    return _spec_fields(spec, SCHEMA, ())


def _spec_fields(spec: dict, schema: str, extra: tuple) -> dict:
    """Shared TaskSpec field checks; `extra` lists version-specific keys."""
    allowed = {'schema', 'goal', 'repo', 'base', 'base_sha', 'readable',
               'writable', 'verify', 'max_steps', 'max_repairs',
               'call_timeout'} | set(extra)
    unknown = set(spec) - allowed
    missing = {'schema', 'goal', 'repo', 'base_sha', 'readable', 'writable',
               'verify'} - set(spec)
    if unknown:
        _err('spec_invalid', 'unknown spec keys')
    if missing:
        _err('spec_invalid', 'missing spec keys')
    if spec['schema'] != schema:
        _err('spec_invalid', f'schema must be {schema}')
    _bstr(spec['goal'], _MAX_GOAL_BYTES, 'spec_invalid', 'goal')
    repo = spec['repo']
    if (not isinstance(repo, str) or not repo.startswith('/')
            or '\x00' in repo or _size(repo) is None or _size(repo) > 1024):
        _err('spec_invalid', 'repo must be an absolute UTF-8 path string')
    base_sha = spec['base_sha']
    if not isinstance(base_sha, str) or not _SHA_RE.fullmatch(base_sha):
        _err('spec_invalid', 'base_sha must be exact 40 lowercase hex')
    readable = _pathlist(spec['readable'], 'readable')
    writable = _pathlist(spec['writable'], 'writable')
    if not writable:
        _err('spec_invalid', 'writable must list at least one path')
    _no_ancestor(readable + writable)
    verify = spec['verify']
    if not isinstance(verify, list) or not 1 <= len(verify) <= _MAX_ARGV:
        _err('spec_invalid', f'verify must be argv of 1..{_MAX_ARGV}')
    for arg in verify:
        _bstr(arg, _MAX_ARG_BYTES, 'spec_invalid', 'verify arg')
    if not verify[0].startswith('/') or verify[0].endswith('/'):
        _err('spec_invalid', 'verify argv[0] must be an absolute executable')
    out = {'schema': schema, 'goal': spec['goal'], 'repo': repo,
           'base_sha': base_sha, 'readable': readable, 'writable': writable,
           'verify': list(verify),
           'max_steps': _bounded_int(spec.get('max_steps'), 1, 6, 6, 'max_steps'),
           'max_repairs': _bounded_int(spec.get('max_repairs'), 0, 1, 1,
                                       'max_repairs'),
           'call_timeout': _bounded_int(spec.get('call_timeout'), 1, 900, 900,
                                        'call_timeout')}
    if 'base' in spec:
        _bstr(spec['base'], _MAX_BASE_BYTES, 'spec_invalid', 'base')
        out['base'] = spec['base']
    return out


def _target(value) -> dict:
    if not isinstance(value, dict) or set(value) != {'route', 'model'}:
        _err('spec_invalid', 'selection target must be exactly route+model')
    route = value['route']
    if not isinstance(route, str) or route not in ROUTES:
        _err('spec_invalid', 'selection route must be claude or devin')
    model = value['model']
    if (not isinstance(model, str) or not model or _size(model) is None
            or _size(model) > _MAX_MODEL_BYTES
            or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7f
                   for ch in model)):
        _err('spec_invalid',
             f'selection model must be a token within {_MAX_MODEL_BYTES} bytes')
    return {'route': route, 'model': model}


def _selection(value) -> dict:
    if not isinstance(value, dict):
        _err('spec_invalid', 'selection must be a dict')
    if set(value) - {'mode', 'targets'}:
        _err('spec_invalid', 'unknown selection keys')
    mode = value.get('mode', 'suitability')
    if not isinstance(mode, str) or mode not in SELECTION_MODES:
        _err('spec_invalid',
             'selection mode must be suitability, usage, or fixed')
    targets = value.get('targets', {})
    if not isinstance(targets, dict):
        _err('spec_invalid', 'selection targets must be a dict')
    out = {}
    for role, target in targets.items():
        if not isinstance(role, str) or role not in ROLES_V2:
            _err('spec_invalid', 'selection targets key must be a known role')
        out[role] = _target(target)
    if mode == 'fixed' and not {'planner', 'implement'} <= set(out):
        _err('spec_invalid',
             'fixed mode requires planner and implement targets')
    return {'mode': mode, 'targets': out}


def _validate_spec_v2(spec: dict) -> dict:
    return _validate_spec_v23(spec, SCHEMA_V2)


def _validate_spec_v3(spec: dict) -> dict:
    return _validate_spec_v23(spec, SCHEMA_V3)


def _validate_spec_v23(spec: dict, schema: str) -> dict:
    out = _spec_fields(spec, schema, ('selection', 'announcement', 'focus'))
    out['selection'] = (_selection(spec['selection']) if 'selection' in spec
                        else {'mode': 'suitability', 'targets': {}})
    announcement = spec.get('announcement', 'standard')
    if not isinstance(announcement, str) or announcement not in ANNOUNCEMENTS:
        _err('spec_invalid', 'announcement must be standard or quiet')
    out['announcement'] = announcement
    focus = spec.get('focus', DEFAULT_FOCUS)
    if not isinstance(focus, str) or focus not in FOCI:
        _err('spec_invalid', 'focus must be a known focus name')
    out['focus'] = focus
    return out


def validate_plan(obj: dict, spec: dict) -> dict:
    """Validated plan: s1..sN ordered steps, inputs reference earlier ids only.

    Dispatches on obj['schema']: co.task-plan/1 keeps the frozen v1 contract;
    co.task-plan/2 adds a required per-step focus and validates against a
    co.task/2 or co.task/3 spec including fixed-mode target coverage.
    """
    if isinstance(obj, dict) and obj.get('schema') == PLAN_SCHEMA_V2:
        return _validate_plan_v2(obj, spec)
    if isinstance(spec, dict) and spec.get('schema') == SCHEMA_V2:
        _err('plan_invalid', 'co.task/2 requires a co.task-plan/2 plan')
    if isinstance(spec, dict) and spec.get('schema') == SCHEMA_V3:
        _err('plan_invalid', 'co.task/3 requires a co.task-plan/2 plan')
    return _validate_plan_v1(obj, spec)


def _validate_plan_v1(obj: dict, spec: dict) -> dict:
    """Shape invariant: design/implement steps may precede the first review;
    once a review appears no implement step may follow (stale approval); a
    review may never precede the first implement; the last step must be
    implement or review.
    """
    if (not isinstance(obj, dict) or set(obj) != {'schema', 'steps'}
            or obj['schema'] != PLAN_SCHEMA):
        _err('plan_invalid', 'exact plan schema with steps required')
    steps = obj['steps']
    limit = spec.get('max_steps') if isinstance(spec, dict) else None
    if type(limit) is not int or not 1 <= limit <= 6:
        _err('plan_invalid', 'spec max_steps invalid')
    if not isinstance(steps, list) or not 1 <= len(steps) <= limit:
        _err('plan_invalid', f'1..{limit} steps required')
    out, seen = [], set()
    seen_impl = seen_review = False
    for i, raw in enumerate(steps, 1):
        sid = f's{i}'
        if (not isinstance(raw, dict)
                or set(raw) != {'id', 'role', 'instructions', 'inputs'}):
            _err('plan_invalid', f'step {sid} keys must be id/role/instructions/inputs')
        if raw['id'] != sid:
            _err('plan_invalid', f'step {sid} id must be {sid}')
        role = raw['role']
        if not isinstance(role, str) or role not in ROLES:
            _err('plan_invalid', f'step {sid} has unknown role')
        if role == 'review':
            if not seen_impl:
                _err('plan_invalid', 'review before any implement step')
            if seen_review:
                _err('plan_invalid', 'at most one review step is supported')
            seen_review = True
        elif role == 'implement':
            if seen_review:
                _err('plan_invalid', 'implement after first review step')
            seen_impl = True
        _bstr(raw['instructions'], _MAX_INSTRUCTIONS_BYTES, 'plan_invalid',
              f'step {sid} instructions')
        inputs = raw['inputs']
        if (not isinstance(inputs, list)
                or any(not isinstance(x, str) or x not in seen for x in inputs)
                or len(set(inputs)) != len(inputs)):
            _err('plan_invalid', f'step {sid} inputs must be unique earlier ids')
        out.append({'id': sid, 'role': role,
                    'instructions': raw['instructions'],
                    'inputs': list(inputs)})
        seen.add(sid)
    if not seen_impl:
        _err('plan_invalid', 'at least one implement step required')
    if out[-1]['role'] not in ('implement', 'review'):
        _err('plan_invalid', 'last step must be implement or review')
    consumed = {sid for step in out for sid in step['inputs']}
    if any(step['role'] == 'design' and step['id'] not in consumed for step in out):
        _err('plan_invalid', 'design output requires a later consumer')
    return {'schema': PLAN_SCHEMA, 'steps': out}


def _validate_plan_v2(obj: dict, spec: dict) -> dict:
    """co.task-plan/2: v1 step rules plus a required per-step focus.

    The plan schema must pair with a co.task/2 or co.task/3 spec. Under
    selection mode 'fixed' every role used by the plan must have a
    configured target; unused roles need none.
    """
    if set(obj) != {'schema', 'steps'}:
        _err('plan_invalid', 'exact plan schema with steps required')
    if not isinstance(spec, dict) or spec.get('schema') not in (SCHEMA_V2, SCHEMA_V3):
        _err('plan_invalid', 'co.task-plan/2 requires a co.task/2 or co.task/3 spec')
    steps = obj['steps']
    limit = spec.get('max_steps')
    if type(limit) is not int or not 1 <= limit <= 6:
        _err('plan_invalid', 'spec max_steps invalid')
    if not isinstance(steps, list) or not 1 <= len(steps) <= limit:
        _err('plan_invalid', f'1..{limit} steps required')
    out, seen = [], set()
    seen_impl = seen_review = False
    used_roles = set()
    for i, raw in enumerate(steps, 1):
        sid = f's{i}'
        if (not isinstance(raw, dict) or set(raw)
                != {'id', 'role', 'instructions', 'inputs', 'focus'}):
            _err('plan_invalid',
                 f'step {sid} keys must be id/role/instructions/inputs/focus')
        if raw['id'] != sid:
            _err('plan_invalid', f'step {sid} id must be {sid}')
        role = raw['role']
        if not isinstance(role, str) or role not in ROLES:
            _err('plan_invalid', f'step {sid} has unknown role')
        if role == 'review':
            if not seen_impl:
                _err('plan_invalid', 'review before any implement step')
            if seen_review:
                _err('plan_invalid', 'at most one review step is supported')
            seen_review = True
        elif role == 'implement':
            if seen_review:
                _err('plan_invalid', 'implement after first review step')
            seen_impl = True
        _bstr(raw['instructions'], _MAX_INSTRUCTIONS_BYTES, 'plan_invalid',
              f'step {sid} instructions')
        focus = raw['focus']
        if not isinstance(focus, str) or focus not in FOCI:
            _err('plan_invalid', f'step {sid} has unknown focus')
        inputs = raw['inputs']
        if (not isinstance(inputs, list)
                or any(not isinstance(x, str) or x not in seen for x in inputs)
                or len(set(inputs)) != len(inputs)):
            _err('plan_invalid', f'step {sid} inputs must be unique earlier ids')
        out.append({'id': sid, 'role': role,
                    'instructions': raw['instructions'],
                    'inputs': list(inputs), 'focus': focus})
        seen.add(sid)
        used_roles.add(role)
    if not seen_impl:
        _err('plan_invalid', 'at least one implement step required')
    if out[-1]['role'] not in ('implement', 'review'):
        _err('plan_invalid', 'last step must be implement or review')
    consumed = {sid for step in out for sid in step['inputs']}
    if any(step['role'] == 'design' and step['id'] not in consumed
           for step in out):
        _err('plan_invalid',
             'design output requires a later consumer')
    selection = spec.get('selection')
    if isinstance(selection, dict) and selection.get('mode') == 'fixed':
        targets = selection.get('targets')
        named = set(targets) if isinstance(targets, dict) else set()
        if used_roles - named:
            _err('plan_invalid',
                 'fixed selection lacks a target for a used role')
    return {'schema': PLAN_SCHEMA_V2, 'steps': out}


def validate_changes(text: str, spec: dict) -> list:
    """Worker change payload -> [{'path','content'}] strictly inside writable."""
    try:
        obj = parse_json(text)
    except TaskError as exc:
        raise TaskError('changes_invalid', 'payload is not strict JSON') from exc
    if not isinstance(obj, dict) or set(obj) != {'files', 'summary'}:
        _err('changes_invalid', 'payload must be exactly files+summary')
    if not isinstance(obj['summary'], str) \
            or (_size(obj['summary']) or _MAX_SUMMARY_BYTES + 1) > _MAX_SUMMARY_BYTES:
        _err('changes_invalid', 'summary must be a bounded str')
    files = obj['files']
    writable = set(spec['writable']) if isinstance(spec, dict) else set()
    if not isinstance(files, list) or not 1 <= len(files) <= len(writable):
        _err('changes_invalid', 'files must be nonempty within writable scope')
    out, seen = [], set()
    for raw in files:
        if not isinstance(raw, dict) or set(raw) != {'path', 'content'}:
            _err('changes_invalid', 'file keys must be exactly path/content')
        path, content = raw['path'], raw['content']
        if not isinstance(path, str):
            _err('changes_invalid', 'file path must be str')
        if path in seen:
            _err('changes_invalid', 'duplicate change for one path')
        if path not in writable:
            _err('changes_invalid', 'change path outside writable scope')
        n = _size(content)
        if n is None:
            _err('changes_invalid', 'content must be strict-UTF-8 str')
        if n > MAX_FILE_BYTES:
            _err('changes_invalid', 'content exceeds max file size')
        seen.add(path)
        out.append({'path': path, 'content': content})
    return out


def validate_review(text: str) -> dict:
    """Worker review payload -> {'verdict','findings'} exactly."""
    try:
        obj = parse_json(text)
    except TaskError as exc:
        raise TaskError('review_invalid', 'payload is not strict JSON') from exc
    if not isinstance(obj, dict) or set(obj) != {'verdict', 'findings'}:
        _err('review_invalid', 'payload must be exactly verdict+findings')
    verdict = obj['verdict']
    if not isinstance(verdict, str) or verdict not in VERDICTS:
        _err('review_invalid', 'verdict must be approve or request_changes')
    findings = obj['findings']
    if (not isinstance(findings, list) or len(findings) > _MAX_FINDINGS
            or any(not isinstance(f, str) or not f.strip()
                   or _size(f) is None or _size(f) > _MAX_FINDING_BYTES
                   for f in findings)):
        _err('review_invalid', 'findings must be bounded nonempty UTF-8 strs')
    return {'verdict': verdict, 'findings': list(findings)}
