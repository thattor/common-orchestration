"""Bounded text mapping for the pinned AGY CLI; defaults refuse unverified hosts.

Uses the existing Adapter Protocol; fixtures are not Native qualification.
See design/0.3/ANTIGRAVITY-FIXED-TEXT.md for the bounded contract.
"""
from dataclasses import dataclass, field
import json
import hashlib
import math
import re
import time
from uuid import uuid4

from ..contracts import (CollectionError, ExecuteRequest, NeverStarted, OperationReply, OperationStatus, State,
    StatusEvent, ResultEvent, Result, StopReply, StopStatus, OutputItem)
from ..delegation import job_payload

ADAPTER = 'antigravity.text.only'
# Minor bump marks the co.controller/4 compatibility change; v3 baseline
# was 0.1.0-dev. The -dev suffix honestly marks this adapter unqualified.
ADAPTER_VERSION = '0.2.0-dev'
CLI_VERSION = '1.2.15'
SOURCE_DOC = 'https://antigravity.google/docs/cli/headless/'
MAX_BYTES = 1048576
MAX_LINE = 262144
MAX_TEXT = 262144
MAX_FRAMES = 256
MAX_BATCH = 64


def _refuse(*args):
    raise ValueError('unverified host')


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _string(value, maximum=256):
    return type(value) is str and 0 < len(value.encode('utf-8')) <= maximum


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _usage(value):
    allowed = {'input_tokens', 'output_tokens', 'thinking_tokens', 'cache_read_tokens', 'total_tokens'}
    if (type(value) is not dict or set(value) != allowed
            or any(type(n) is not int or n < 0 for n in value.values())):
        raise ValueError('invalid usage metadata')


def payload_digest(request):
    return hashlib.sha256(json.dumps(job_payload(request), sort_keys=True,
        ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class TextProfile:
    """Trusted request pin, not authorization or evidence that a guard exists.

    Live authorization, fee and context conditions must be verified by verify_host.
    tools optionally pins inventory; None accepts a bounded Native inventory.
    Inventory is not a grant. The Job delegates no tools or skill actions.
    """
    request: ExecuteRequest
    payload_sha256: str
    tools: tuple[str, ...] | None = None
    effort: str = 'high'
    plan_expansion: bool = False
    native_done_lf: bool = False

    def __post_init__(self):
        if (type(self.request) is not ExecuteRequest
                or type(self.payload_sha256) is not str
                or re.fullmatch('[0-9a-f]{64}', self.payload_sha256) is None
                or (self.tools is not None and (type(self.tools) is not tuple or len(self.tools) > 128
                    or any(type(t) is not str or re.fullmatch('[a-z][a-z0-9_]{0,79}',t) is None for t in self.tools)
                    or len(set(self.tools)) != len(self.tools)))
                or type(self.plan_expansion) is not bool or type(self.native_done_lf) is not bool
                or self.effort not in ('low', 'medium', 'high', 'max')):
            raise ValueError('invalid trusted public-text profile')


@dataclass
class _Attempt:
    request: object
    started: float
    transport: object = None
    events: list = field(default_factory=list)
    buffer: bytes = b''
    received: int = 0
    frames: int = 0
    session: str | None = None
    message: tuple | None = None
    parts: set = field(default_factory=set)
    text: str = ''
    raw_text: str = ''
    formatting_lfs: int = 0
    finish: dict | None = None
    proof: str | None = None
    terminal: bool = False
    closed: bool = False
    phase: str = 'before_init'
    failed: bool = False


class AntigravityTextAdapter:
    """Role-specific stream mapping; Native launch belongs to AntigravityTextHost.

    verify_host(request, profile) attests the exact public-only request and pre-send
    invocation/context/fee conditions, returning None or raising. Factory
    receives the full job_payload, owns one process and bounded cleanup.
    Completion verifier binds actual owned transport/session/result and normal
    cessation to the admitted request, returning a nonsecret evidence reference.
    Defaults refuse; fixture callbacks never qualify a real host.
    """
    def __init__(self, *, verify_host=_refuse, transport_factory=None,
                 verify_completion=_refuse, profile=None, clock=time.monotonic, timeout=120):
        if not _number(timeout) or not 0 < timeout <= 600:
            raise ValueError('bounded timeout required')
        self._verify, self._factory = verify_host, transport_factory
        self._completion, self._clock, self._timeout = verify_completion, clock, timeout
        self._profile = profile
        self._attempts = {}
        self._closed = False

    def execute(self, request):
        ref = request.ref
        if self._closed or ref in self._attempts:
            return OperationReply(ref, OperationStatus.INVALID_STATE, 'Adapter closed or Attempt used')
        try:
            if (request.conditions.adapter != ADAPTER or self._factory is None
                    or type(self._profile) is not TextProfile
                    or self._profile.request != request
                    or self._profile.payload_sha256 != payload_digest(request)):
                raise ValueError('route unavailable')
            payload = job_payload(request)
            if self._verify(request, self._profile) is not None:
                raise ValueError('host verifier must attest or raise, not return a flag')
        except Exception:
            return OperationReply(ref, OperationStatus.UNSUPPORTED, 'Antigravity public-text host preflight refused',
                never_started=NeverStarted(request, ADAPTER + ':never-started:' + uuid4().hex))
        attempt = _Attempt(request, self._clock())
        # Reservation precedes factory: failed creation/submission is ambiguous.
        self._attempts[ref] = attempt
        self._status(attempt, State.PENDING)
        try:
            attempt.transport = self._factory(request, payload, self._profile)
            if attempt.transport is None:
                raise ValueError('missing transport')
        except Exception:
            self._finish(attempt, State.ERROR, 'native_launch_or_submission_unknown')
            return OperationReply(ref, OperationStatus.ERROR, 'Native submission outcome unknown')
        return OperationReply(ref, OperationStatus.ACCEPTED, 'submission attempted; outcome unverified')

    def _status(self, attempt, state):
        attempt.events.append(StatusEvent(attempt.request.ref, uuid4().hex, state))

    def _finish(self, attempt, state, reason=None):
        if attempt.terminal:
            return
        attempt.terminal = True
        attempt.buffer = b''
        if state != State.COMPLETED:
            attempt.text, attempt.raw_text, attempt.proof = '', '', None
        self._status(attempt, state)
        attempt.events.append(ResultEvent(attempt.request.ref, uuid4().hex,
            Result(attempt.request.ref, state, reason)))
        if not attempt.closed:
            attempt.closed = True
            if attempt.transport is not None:
                try:
                    attempt.transport.close()
                except Exception:
                    pass

    def _frame(self, attempt, frame):
        attempt.frames += 1
        if (attempt.frames > MAX_FRAMES or type(frame) is not dict
                or attempt.finish is not None):
            raise ValueError('invalid frame or activity after result')
        kind = frame.get('event')
        attempt.phase = kind if kind in ('init', 'step_update', 'result') else 'unknown_event'
        if kind == 'init':
            if (attempt.session is not None
                    or set(frame) != {'event', 'conversation_id', 'init'}):
                raise ValueError('invalid init')
            session, info = frame['conversation_id'], frame['init']
            if (not _string(session) or type(info) is not dict
                    or not {'cwd', 'permission_mode', 'model'} <= set(info)
                    or set(info) - {'cwd', 'tools', 'permission_mode', 'model', 'agent', 'expanded_commands', 'json_schema'}
                    or ('json_schema' in info and info['json_schema'] is not None)
                    or ('expanded_commands' in info and (type(info['expanded_commands']) is not list
                        or info['expanded_commands'] not in ([], [{'name': 'plan', 'type': 'system'}])
                        or (info['expanded_commands'] and not self._profile.plan_expansion)))
                    or info['cwd'] != attempt.request.conditions.workspace
                    or info['model'] != attempt.request.conditions.model
                    or type(info.get('tools', [])) is not list
                    or len(info.get('tools', [])) > 128
                    or any(not _string(t, 128) for t in info.get('tools', []))
                    or len(set(info.get('tools', []))) != len(info.get('tools', []))
                    or (self._profile.tools is not None and tuple(info.get('tools', [])) != self._profile.tools)
                    or ('agent' in info and not _string(info['agent'], 256))
                    or info['permission_mode'] != 'request-review'):
                raise ValueError('unverified init')
            attempt.session = session
            self._status(attempt, State.RUNNING)
            return
        if attempt.session is None:
            raise ValueError('init required')
        if kind == 'step_update':
            if set(frame) != {'event', 'step_update'}:
                raise ValueError('invalid update')
            item = frame['step_update']
            required = {'conversation_id', 'step_index', 'state', 'step_type'}
            if (type(item) is not dict or not required <= set(item)
                    or set(item) - required - {'text_delta', 'duration_seconds', 'usage'}
                    or item['conversation_id'] != attempt.session
                    or type(item['step_index']) is not int or item['step_index'] < 0
                    or item['state'] not in {'ACTIVE', 'DONE'}
                    or item['step_type'] not in {'user_input', 'agent_response', 'checkpoint'}):
                raise ValueError('unsupported step')
            index = item['step_index']
            previous = attempt.message
            if previous is not None:
                old_index, old_kind, old_state = previous
                if (index < old_index or (index == old_index and
                        (item['step_type'] != old_kind or old_state == 'DONE'))
                        or (index > old_index and old_state != 'DONE')):
                    raise ValueError('invalid step order')
            if 'duration_seconds' in item and not _number(item['duration_seconds']):
                raise ValueError('invalid duration')
            if 'usage' in item:
                _usage(item['usage'])
            if 'text_delta' in item:
                if item['step_type'] != 'agent_response' or type(item['text_delta']) is not str:
                    raise ValueError('invalid text')
                attempt.raw_text += item['text_delta']
                if len(attempt.raw_text.encode('utf-8')) > MAX_TEXT:
                    raise ValueError('text limit')
            delta = item.get('text_delta', '')
            if self._profile.native_done_lf and item['step_type'] == 'agent_response' and item['state'] == 'DONE':
                # Pinned PollPrintmode appends exactly one formatting LF on a
                # nonempty completed response. Preserve any model-owned LF.
                if not delta.endswith('\n'):
                    raise ValueError('missing Native DONE formatting LF')
                delta = delta[:-1]
                attempt.formatting_lfs += 1
            attempt.text += delta
            attempt.message = (index, item['step_type'], item['state'])
            return
        if kind != 'result' or set(frame) != {'event', 'result'}:
            raise ValueError('unsupported event')
        item = frame['result']
        if (type(item) is not dict or set(item) != {'conversation_id', 'status',
                'response', 'duration_seconds', 'num_turns', 'usage'}
                or item['conversation_id'] != attempt.session or item['status'] != 'SUCCESS'
                or not _string(item['response'], MAX_TEXT)
                or not _number(item['duration_seconds'])
                or type(item['num_turns']) is not int or item['num_turns'] != 1
                or (attempt.message is not None and attempt.message[2] != 'DONE')
                or (attempt.raw_text and attempt.raw_text != item['response'])
                or (self._profile.native_done_lf and (attempt.raw_text != item['response']
                    or attempt.formatting_lfs == 0))):
            raise ValueError('invalid terminal result')
        _usage(item['usage'])
        if not self._profile.native_done_lf:
            attempt.text = item['response']
        attempt.finish = item

    def _pump(self, attempt):
        if attempt.terminal:
            return
        if self._clock() - attempt.started >= self._timeout:
            self._finish(attempt, State.ERROR, 'native_turn_timeout')
            return
        try:
            batch = attempt.transport.poll()
            if type(batch) is not tuple or len(batch) > MAX_BATCH:
                raise ValueError('invalid bounded poll')
            for chunk in batch:
                if type(chunk) is not bytes or not chunk or len(chunk) > MAX_LINE:
                    raise ValueError('invalid chunk')
                attempt.received += len(chunk)
                if attempt.received > MAX_BYTES:
                    raise ValueError('stream limit exceeded')
                attempt.buffer += chunk
                while b'\n' in attempt.buffer:
                    line, attempt.buffer = attempt.buffer.split(b'\n', 1)
                    if not line or len(line) > MAX_LINE:
                        raise ValueError('invalid line')
                    frame = json.loads(line.decode('utf-8'), object_pairs_hook=_object,
                                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                    self._frame(attempt, frame)
                if len(attempt.buffer) > MAX_LINE:
                    raise ValueError('unterminated line limit')
            drained = attempt.transport.drained()
            if type(drained) is not bool:
                raise ValueError('invalid EOF observation')
            if not drained:
                return
            if attempt.buffer or attempt.finish is None:
                raise ValueError('truncated stream or no terminal candidate')
            code = attempt.transport.wait_owned()
            if code is None:
                return
            if type(code) is not int or code != 0:
                raise ValueError('owned process did not exit normally')
            # A separate host capability binds actual lifecycle, executable,
            # admitted request/profile and this owned transport's session.
            proof = self._completion(attempt.request, attempt.transport,
                                     attempt.session, attempt.message, dict(attempt.finish), self._profile)
            if not _string(proof, 1024):
                raise ValueError('missing trusted completion proof')
            attempt.proof = proof
            self._finish(attempt, State.COMPLETED)
        except Exception:
            attempt.failed = True
            self._finish(attempt, State.ERROR, 'native_protocol_or_completion_unverified')

    def _get(self, ref):
        if ref not in self._attempts:
            raise ValueError('unknown Attempt')
        return self._attempts[ref]

    def events(self, ref, after=None):
        attempt, start = self._get(ref), 0
        if after is not None:
            ids = [event.event_id for event in attempt.events]
            if after not in ids:
                raise ValueError('unknown event cursor')
            start = ids.index(after) + 1
        self._pump(attempt)
        return tuple(attempt.events[start:])

    def status(self, ref):
        attempt = self._get(ref)
        self._pump(attempt)
        return next(e for e in reversed(attempt.events) if isinstance(e, StatusEvent))

    def stop(self, ref):
        if ref not in self._attempts:
            return StopReply(ref, StopStatus.ERROR, 'unknown Attempt')
        attempt = self._get(ref)
        if attempt.proof and attempt.terminal:
            return StopReply(ref, StopStatus.CONFIRMED, 'bound normal text turn and owned CLI completed', attempt.proof)
        self._finish(attempt, State.ERROR, 'stop_requested_cessation_unconfirmed')
        return StopReply(ref, StopStatus.UNCONFIRMED, 'cleanup is not Native cancellation proof')

    def resume(self, state):
        if (state.adapter != ADAPTER or state.ref not in self._attempts
                or self._get(state.ref).terminal):
            return OperationReply(state.ref, OperationStatus.INVALID_STATE, 'unknown or terminal resume identity')
        return OperationReply(state.ref, OperationStatus.UNSUPPORTED, 'Resume unsupported')

    def respond(self, response):
        if response.ref not in self._attempts or self._get(response.ref).terminal:
            return OperationReply(response.ref, OperationStatus.INVALID_STATE, 'unknown or terminal Attempt')
        return OperationReply(response.ref, OperationStatus.UNSUPPORTED, 'permission relay unsupported')

    def usage(self):
        return ()

    def diagnostic(self, ref):
        """Fixed role-specific observations; no Native values or raw errors."""
        attempt = self._get(ref)
        return {'phase': attempt.phase, 'frames_seen': attempt.frames,
                'init_observed': attempt.session is not None,
                'result_observed': attempt.finish is not None,
                'protocol_failed': attempt.failed,
                'native_done_lfs_decoded': attempt.formatting_lfs,
                'raw_response_sha256': hashlib.sha256(attempt.raw_text.encode()).hexdigest() if attempt.proof else None}

    def text_output(self, ref):
        """Private host artifact input; independent AC owns the verdict."""
        attempt = self._get(ref)
        if not attempt.terminal or not attempt.proof:
            raise ValueError('successful text output unavailable')
        return attempt.text

    def collect_output(self, ref):
        """Optional public collector for a verified output_mode=collect route.

        Wraps the audited private text_output: exactly one verbatim UTF-8
        text item exists only for an internally proven COMPLETED Attempt.
        Failed, stopped or unfinished Attempts keep the fixed ValueError
        refusal; an unknown ref is a CollectionError — no stream, tool,
        error or diagnostic material. Storage, digests and verdicts remain
        Controller-owned.
        """
        if ref not in self._attempts:
            raise CollectionError('attempt unavailable in this adapter instance')
        return (OutputItem(0, 'text/plain', self.text_output(ref)),)

    def close(self):
        self._closed = True
        for attempt in self._attempts.values():
            self._finish(attempt, State.ERROR, 'adapter_closed')
