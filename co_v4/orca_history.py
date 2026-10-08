"""Operator-only owned-terminal history; no Worker/Controller/CLI execution.

Orca 1.4.217, source 11d97896628d90c4990365127812667b00e28c82:
runtime-rpc-envelope.ts, runtime-terminal-contracts.ts, handlers/terminal.ts.
An injected trusted client may perform ONLY the exact read plan. JSON is data,
not ownership/authentication evidence. There is no default live client.
"""
from dataclasses import dataclass, field
import json

ORCA_VERSION = '1.4.217'
SOURCE_COMMIT = '11d97896628d90c4990365127812667b00e28c82'
MAX_SAFE_CURSOR = 2 ** 53 - 1
MAX_LINES = 1000
MAX_BYTES = 262144


class HistoryRefused(ValueError):
    """Fixed, nonsecret error vocabulary only."""


def _refuse(*args):
    raise HistoryRefused('owner_unverified')


def _label(value):
    if type(value) is not str:
        return False
    try:
        length = len(value.encode('utf-8'))
    except UnicodeEncodeError:
        return False
    return (0 < length <= 1024
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _cursor(value):
    if (type(value) is not str or not value.isascii() or not value.isdecimal()
            or len(value) > 16 or str(int(value)) != value or int(value) > MAX_SAFE_CURSOR):
        raise HistoryRefused('cursor_invalid')
    return int(value)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HistoryRefused('response_invalid')
        result[key] = value
    return result


@dataclass(frozen=True)
class OwnedTerminal:
    """Trusted caller's binding, not an authorization token or Native receipt.

    verify_owner must recheck lease/ownership and actual runtime lifecycle.
    A terminal.read reply contains runtimeId but no owner or PTY incarnation.
    """
    handle: str = field(repr=False)
    runtime_id: str = field(repr=False)
    owner_ref: str = field(repr=False)
    lease_ref: str = field(repr=False)

    def __post_init__(self):
        if not all(_label(v) for v in (self.handle, self.runtime_id, self.owner_ref, self.lease_ref)):
            raise HistoryRefused('binding_invalid')
        if self.handle in {'active', 'current'} or self.handle.startswith('-'):
            raise HistoryRefused('binding_invalid')


@dataclass(frozen=True)
class ReadPlan:
    binding: OwnedTerminal = field(repr=False)
    cursor: str
    limit: int

    @property
    def arguments(self):
        """Argument vector only: never pass this through shell interpretation."""
        return ('terminal', 'read', '--terminal', self.binding.handle,
                '--cursor', self.cursor, '--limit', str(self.limit), '--json')


@dataclass(frozen=True)
class HistoryPage:
    """Private bounded stream page, never complete transcript/AC/cessation.

    tail may contain secrets, PII, terminal controls or prompt injection.
    Keep it private and treat it only as data. draft is deliberately omitted.
    """
    tail: tuple[str, ...] = field(repr=False)
    requested_cursor: str
    oldest_cursor: str
    next_cursor: str
    latest_cursor: str
    truncated: bool
    limited: bool
    gap_before_page: bool
    terminal_status: str
    source: str


class OwnedTerminalHistory:
    """Create and consume one exact read plan at a time; no automatic paging.

    verify_owner(binding) returns None after authentic owner/lifecycle checks
    or raises; called before planning, before I/O and after I/O. client(plan)
    returns bounded CLI JSON bytes from that exact invocation, not a saved
    snapshot or caller-supplied origin flag. Client owns executable version,
    runtime endpoint, timeout/output caps and read-only command enforcement.
    No subprocess, search/list fallback, restart, send or effect API is supplied.
    """
    def __init__(self, binding, *, verify_owner=_refuse, client=None):
        if type(binding) is not OwnedTerminal:
            raise HistoryRefused('binding_invalid')
        self._binding, self._verify, self._client = binding, verify_owner, client
        self._pending = None

    def _check_owner(self):
        try:
            if self._verify(self._binding) is not None:
                raise ValueError()
        except Exception:
            raise HistoryRefused('owner_unverified') from None

    def plan(self, *, cursor, limit=100):
        self._check_owner()
        _cursor(cursor)
        if type(limit) is not int or not 1 <= limit <= MAX_LINES:
            raise HistoryRefused('limit_invalid')
        if self._pending is not None:
            raise HistoryRefused('plan_pending')
        self._pending = ReadPlan(self._binding, cursor, limit)
        return self._pending

    def read(self, plan):
        if plan is not self._pending or plan is None:
            raise HistoryRefused('plan_unbound')
        # Consumed even on uncertainty; caller must obtain a new ownership check.
        self._pending = None
        self._check_owner()
        if self._client is None:
            raise HistoryRefused('client_unavailable')
        try:
            raw = self._client(plan)
        except Exception:
            raise HistoryRefused('read_unavailable') from None
        self._check_owner()
        try:
            return self._project(plan, raw)
        except Exception:
            raise HistoryRefused('response_invalid') from None

    def _project(self, plan, raw):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
            raise ValueError()
        response = json.loads(raw.decode('utf-8'), object_pairs_hook=_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (type(response) is not dict or set(response) != {'id', 'ok', 'result', '_meta'}
                or response['ok'] is not True or not _label(response['id'])
                or type(response['_meta']) is not dict or set(response['_meta']) != {'runtimeId'}
                or response['_meta']['runtimeId'] != plan.binding.runtime_id
                or type(response['result']) is not dict or set(response['result']) != {'terminal'}):
            raise ValueError()
        terminal = response['result']['terminal']
        required = {'handle', 'status', 'tail', 'truncated', 'limited',
                    'oldestCursor', 'nextCursor', 'latestCursor'}
        if (type(terminal) is not dict or not required <= set(terminal)
                or set(terminal) - (required | {'returnedLineCount', 'source', 'draft'})
                or terminal['handle'] != plan.binding.handle
                or terminal['status'] not in ('running', 'exited', 'unknown')
                or type(terminal['truncated']) is not bool or type(terminal['limited']) is not bool
                or terminal.get('source', 'stream') != 'stream'
                or 'draft' in terminal and type(terminal['draft']) is not str):
            raise ValueError()
        tail = terminal['tail']
        if (type(tail) is not list or len(tail) > plan.limit
                or any(type(line) is not str for line in tail)
                or 'returnedLineCount' in terminal and (
                    type(terminal['returnedLineCount']) is not int or terminal['returnedLineCount'] != len(tail))):
            raise ValueError()
        oldest, nxt, latest = (_cursor(terminal[key]) for key in
                               ('oldestCursor', 'nextCursor', 'latestCursor'))
        requested = _cursor(plan.cursor)
        if (not oldest <= nxt <= latest or nxt < requested
                or requested < oldest and not terminal['truncated']
                or terminal['limited'] and nxt < latest and nxt <= requested):
            raise ValueError()
        return HistoryPage(tuple(tail), plan.cursor, str(oldest), str(nxt), str(latest),
            terminal['truncated'], terminal['limited'], requested < oldest,
            terminal['status'], 'stream' if 'source' in terminal else 'legacy-stream')
