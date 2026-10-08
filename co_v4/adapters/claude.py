"""Single text turn on Claude print/stream-json; no agent loop or tool relay.

Trusted host composition owns launch, exact delegation and authentication. Init
is observed AFTER submission. Structured success alone is insufficient: every
remaining frame, stdout EOF and owned exit are checked before a Result. Raw
Native text/errors never enter common events. Cancellation is not certified by
process cleanup. See design/0.3/CLAUDE-ADAPTER.md for the bounded role.
"""
from dataclasses import dataclass, field
import time
import math
from uuid import UUID, uuid4

from ..contracts import (CollectionError, NeverStarted, OperationReply, OperationStatus, State,
    StatusEvent, ResultEvent, Result, StopReply, StopStatus, OutputItem)
from ..delegation import job_payload

ADAPTER = 'claude.print'
# Minor bump marks the co.controller/4 compatibility change; v3 baseline
# was 0.1.0-dev. The -dev suffix honestly marks this adapter unqualified.
ADAPTER_VERSION = '0.2.0-dev'
CLI_VERSION = '2.1.285'
MAX_FRAMES = 4096
MAX_BATCH = 128
MAX_TEXT = 262144
ERROR_SUBTYPES = frozenset({'error_during_execution', 'error_max_turns',
    'error_max_budget_usd', 'error_max_structured_output_retries'})


# Diagnostic labels only, from the pinned 2.1.285 embedded system schemas
# (byte range 177190000..177295000). Membership grants no frame acceptance.
KNOWN_SYSTEM_SUBTYPES = frozenset({
    'agents_killed', 'api_error', 'api_retry', 'away_summary', 'background_tasks_changed',
    'cloud_session_delta', 'code_change_published', 'commands_changed', 'compact_boundary',
    'control_request_progress', 'dev_intent', 'elicitation_complete', 'feedback_draft_queued',
    'file_snapshot', 'files_persisted', 'hook_progress', 'hook_response', 'hook_started',
    'informational', 'init', 'local_command_output', 'memory_recall', 'memory_saved',
    'mirror_error', 'model_consent_fallback', 'model_fallback', 'model_refusal_fallback',
    'model_refusal_no_fallback', 'notification', 'peer_message_hold', 'per_turn_effort_changed',
    'permission_denied', 'permission_retry', 'plugin_install', 'post_turn_summary',
    'scheduled_task_fire', 'session_metadata', 'session_state_changed', 'session_title_changed',
    'status', 'stop_hook_summary', 'task_notification', 'task_progress', 'task_started',
    'task_summary', 'task_updated', 'thinking', 'thinking_tokens', 'turn_duration',
    'turn_handoff_available', 'turn_preempted', 'ui_focus', 'ui_invalidate', 'ui_log',
    'ui_panes', 'ui_scroll', 'ui_status', 'ui_toast', 'vcs_state_changed', 'worker_shutting_down',
})


# Fixed diagnostic vocabulary only. Never copy exception text, Native fields,
# paths, model names, session IDs or response bodies into diagnostics.
DIAGNOSTICS = {
    'invalid Native frame binding': 'frame_binding_rejected',
    'invalid command inventory': 'commands_inventory_rejected',
    'invalid rate limit metadata': 'rate_limit_metadata_rejected',
    'Native rate limit prohibits continuation': 'rate_limit_continuation_refused',
    'activity after terminal result': 'activity_after_result',
    'Native init configuration mismatch': 'init_configuration_rejected',
    'invalid assistant envelope': 'assistant_envelope_rejected',
    'tool or unsupported assistant activity': 'assistant_activity_rejected',
    'invalid assistant text': 'assistant_text_rejected',
    'invalid terminal envelope': 'result_envelope_rejected',
    'unexpected model use': 'result_model_usage_rejected',
    'contradictory or oversized success': 'result_success_rejected',
    'unknown terminal outcome': 'result_outcome_unknown',
    'contradictory error result': 'result_error_contradiction',
    'unknown Native frame or ordering': 'frame_kind_or_order_rejected',
    'invalid bounded poll': 'poll_shape_rejected',
    'invalid completion evidence': 'completion_evidence_rejected',
}


# Pinned 2.1.285 z2r/M0 schema and ba/_ao producer. No quota inference.
_RATE_ENUMS = {
    'status': {'allowed', 'allowed_warning', 'rejected'},
    'overageStatus': {'allowed', 'allowed_warning', 'rejected'},
    'rateLimitType': {'five_hour', 'seven_day', 'seven_day_opus', 'seven_day_sonnet',
                      'seven_day_overage_included', 'overage'},
    'overageDisabledReason': {'overage_not_provisioned', 'org_level_disabled',
        'org_level_disabled_until', 'out_of_credits', 'seat_tier_level_disabled',
        'member_level_disabled', 'seat_tier_zero_credit_limit', 'group_zero_credit_limit',
        'member_zero_credit_limit', 'org_service_level_disabled', 'no_limits_configured',
        'fetch_error', 'unknown'},
    'limitScope': {'service', 'channel', 'group_pool'},
    'errorCode': {'credits_required'},
}
_RATE_INTS = {'resetsAt', 'overageResetsAt'}
_RATE_NUMBERS = {'utilization', 'surpassedThreshold'}
_RATE_BOOLS = {'isUsingOverage', 'overageInUse', 'rateLimitGraceActive',
               'canUserPurchaseCredits', 'hasChargeableSavedPaymentMethod'}
_RATE_NESTED = {'unifiedWindows', 'overagePeriodMonthly', 'overagePeriodChannel'}


def _rate_metadata(message):
    def number(value):
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    def window(value, reset):
        keys = {'utilization', 'resetsAt'} if reset else {'utilization'}
        return (type(value) is dict and set(value) == keys and number(value['utilization'])
                and (not reset or type(value['resetsAt']) is int and value['resetsAt'] >= 0))
    if set(message) != {'type', 'rate_limit_info', 'uuid', 'session_id'}:
        raise ValueError('invalid rate limit metadata')
    identity = message.get('uuid')
    try:
        valid_uuid = type(identity) is str and str(UUID(identity)) == identity
    except ValueError:
        valid_uuid = False
    info = message.get('rate_limit_info')
    if (not valid_uuid or type(info) is not dict or 'status' not in info
            or set(info) - (_RATE_ENUMS.keys() | _RATE_INTS | _RATE_NUMBERS | _RATE_BOOLS | _RATE_NESTED)):
        raise ValueError('invalid rate limit metadata')
    for key, value in info.items():
        valid = True
        if key in _RATE_ENUMS:
            valid = type(value) is str and value in _RATE_ENUMS[key]
        elif key in _RATE_INTS:
            valid = type(value) is int and value >= 0
        elif key in _RATE_NUMBERS:
            valid = number(value)
        elif key in _RATE_BOOLS:
            valid = type(value) is bool
        elif key == 'unifiedWindows':
            valid = (type(value) is dict and not set(value) - {
                'five_hour', 'seven_day', 'seven_day_overage_included'}
                and all(window(row, True) for row in value.values()))
        elif key in {'overagePeriodMonthly', 'overagePeriodChannel'}:
            valid = window(value, False)
        if not valid:
            raise ValueError('invalid rate limit metadata')
    if (info['status'] not in {'allowed', 'allowed_warning'}
            or info.get('overageStatus') in {'allowed', 'allowed_warning'}
            or info.get('rateLimitType') == 'overage' or info.get('isUsingOverage') is True
            or info.get('overageInUse') is True or 'errorCode' in info):
        raise ValueError('Native rate limit prohibits continuation')
    return info['status']


def command_inventory_shape_valid(commands):
    """Public role schema helper; valid shape alone proves no command provenance."""
    def text(value, maximum, empty=False):
        return type(value) is str and (empty or bool(value)) and len(value.encode('utf-8')) <= maximum
    if type(commands) is not list or len(commands) > 256:
        return False
    for command in commands:
        if (type(command) is not dict or not {'name', 'description', 'argumentHint'} <= set(command)
                or set(command) - {'name', 'description', 'argumentHint', 'aliases', 'builtin'}
                or not text(command['name'], 256) or not text(command['description'], 8192, True)
                or not text(command['argumentHint'], 1024, True)
                or 'builtin' in command and type(command['builtin']) is not bool):
            return False
        if 'aliases' in command:
            aliases = command['aliases']
            if (type(aliases) is not list or len(aliases) > 32
                    or not all(text(alias, 256) for alias in aliases)):
                return False
    return True


class NativeUnavailable(RuntimeError):
    pass


def _refuse(*args):
    raise ValueError('host_unverified')


@dataclass
class _Attempt:
    request: object
    session: str
    started: float
    transport: object = None
    events: list = field(default_factory=list)
    initialized: bool = False
    result: dict | None = None
    text: str | None = None
    proof: str | None = None
    frames: int = 0
    terminal: bool = False
    closed: bool = False
    phase: str = 'launch'
    kind: str = 'none'
    system_subtype: str = 'none'
    commands_events: int = 0
    command_count: int = 0
    rate_limit_events: int = 0
    rate_limit_status: str = 'none'
    failed_checks: tuple = ()
    diagnostic: dict | None = None


class ClaudeAdapter:
    """Adapter Protocol mapping. Calls must be serialized by trusted host."""
    def __init__(self, *, verify_host=_refuse, transport_factory=None,
                 verify_completion=None, verify_native_plugins=None, verify_native_commands=None,
                 clock=time.monotonic, timeout=120):
        if type(timeout) not in (int, float) or not 0 < timeout <= 600:
            raise ValueError('bounded timeout required')
        self._verify, self._factory, self._completion = verify_host, transport_factory, verify_completion
        self._clock, self._timeout, self._attempts = clock, timeout, {}
        self._plugins = verify_native_plugins
        self._commands = verify_native_commands

    def execute(self, request):
        ref = request.ref
        if ref in self._attempts:
            return OperationReply(ref, OperationStatus.INVALID_STATE, 'Attempt already used')
        try:
            if request.conditions.adapter != ADAPTER or self._factory is None:
                raise ValueError('route unavailable')
            self._verify(request)
        except Exception as exc:
            status = OperationStatus.UNAVAILABLE if isinstance(exc, NativeUnavailable) else OperationStatus.UNSUPPORTED
            return OperationReply(ref, status, 'Claude host preflight refused',
                never_started=NeverStarted(request, 'claude.print:never-started:' + uuid4().hex))
        attempt = _Attempt(request, str(uuid4()), self._clock())
        # Reserve before factory: ambiguous creation/submission cannot retry.
        self._attempts[ref] = attempt
        self._status(attempt, State.PENDING)
        try:
            attempt.transport = self._factory(request, attempt.session, job_payload(request))
        except Exception:
            self._finish(attempt, State.ERROR, 'native_launch_or_submission_unknown')
            return OperationReply(ref, OperationStatus.ERROR, 'Native launch/submission outcome unknown')
        return OperationReply(ref, OperationStatus.ACCEPTED, 'submission attempted; Native outcome unverified')

    def _status(self, attempt, state):
        attempt.events.append(StatusEvent(attempt.request.ref, uuid4().hex, state))

    def _close(self, attempt):
        if not attempt.closed:
            attempt.closed = True
            if attempt.transport is not None:
                try:
                    attempt.transport.close()
                except Exception:
                    pass

    def _finish(self, attempt, state, reason=None):
        if attempt.terminal:
            return
        attempt.terminal = True
        if state != State.COMPLETED:
            attempt.text, attempt.proof = None, None
        self._status(attempt, state)
        attempt.events.append(ResultEvent(attempt.request.ref, uuid4().hex,
                                         Result(attempt.request.ref, state, reason)))
        self._close(attempt)

    def _message(self, attempt, message):
        attempt.frames += 1
        kind = message.get('type') if type(message) is dict else None
        attempt.kind = kind if type(kind) is str and kind in {
            'system', 'assistant', 'result', 'rate_limit_event', 'user', 'tool_progress'} else 'unknown'
        attempt.system_subtype = 'none'
        if type(message) is dict and kind == 'system':
            subtype = message.get('subtype')
            attempt.system_subtype = (subtype if type(subtype) is str and subtype in KNOWN_SYSTEM_SUBTYPES
                                      else 'unknown')
        attempt.phase = {'system': 'native_system', 'assistant': 'native_assistant',
                         'result': 'native_result', 'rate_limit_event': 'native_rate_limit'}.get(attempt.kind, 'native_other')
        if type(message) is dict and kind == 'system' and message.get('subtype') == 'init':
            attempt.phase = 'native_init'
        attempt.failed_checks = ()
        if (attempt.frames > MAX_FRAMES or type(message) is not dict
                or message.get('session_id') != attempt.session
                or message.get('parent_tool_use_id') is not None
                or message.get('isSynthetic', False) is not False
                or message.get('isSidechain', False) is not False
                or message.get('origin') is not None
                or message.get('deferred_tool_use')
                or message.get('permission_denials')):
            raise ValueError('invalid Native frame binding')
        if attempt.result is not None:
            raise ValueError('activity after terminal result')
        kind = message.get('type')
        if kind == 'system' and message.get('subtype') == 'init':
            plugins = message.get('plugins', [])
            plugins_verified = plugins == []
            if self._plugins is not None:
                try:
                    plugins_verified = self._plugins(attempt.request, attempt.session, plugins) is True
                except Exception:
                    plugins_verified = False
            if (attempt.initialized or message.get('model') != attempt.request.conditions.model
                    or message.get('cwd') != attempt.request.conditions.workspace
                    or message.get('claude_code_version') != CLI_VERSION
                    or message.get('tools') != [] or message.get('mcp_servers') != []
                    or message.get('permissionMode') != 'dontAsk'
                    or message.get('skills', []) != [] or not plugins_verified):
                checks = {
                    'init_once': not attempt.initialized,
                    'model_matches': message.get('model') == attempt.request.conditions.model,
                    'workspace_matches': message.get('cwd') == attempt.request.conditions.workspace,
                    'version_matches': message.get('claude_code_version') == CLI_VERSION,
                    'tools_empty': message.get('tools') == [],
                    'mcp_empty': message.get('mcp_servers') == [],
                    'permission_mode_matches': message.get('permissionMode') == 'dontAsk',
                    'skills_empty': message.get('skills', []) == [],
                    'plugins_verified': plugins_verified,
                }
                attempt.failed_checks = tuple(key for key, passed in checks.items() if not passed)
                raise ValueError('Native init configuration mismatch')
            attempt.initialized = True
            self._status(attempt, State.RUNNING)
        elif kind == 'system' and message.get('subtype') == 'commands_changed' and attempt.initialized:
            commands = message.get('commands')
            identity = message.get('uuid')
            try:
                valid_uuid = type(identity) is str and str(UUID(identity)) == identity
            except ValueError:
                valid_uuid = False
            if (set(message) != {'type', 'subtype', 'commands', 'uuid', 'session_id'}
                    or not valid_uuid or not command_inventory_shape_valid(commands)):
                raise ValueError('invalid command inventory')
            verified = commands == []
            if self._commands is not None:
                try:
                    verified = self._commands(attempt.request, attempt.session, commands) is True
                except Exception:
                    verified = False
            if not verified:
                raise ValueError('invalid command inventory')
            attempt.commands_events += 1
            attempt.command_count = len(commands)
        elif kind == 'assistant' and attempt.initialized:
            content = message.get('message', {})
            if (type(content) is not dict or content.get('role') != 'assistant'
                    or content.get('model') != attempt.request.conditions.model
                    or content.get('stop_reason') not in (None, 'end_turn')
                    or message.get('error') is not None
                    or type(content.get('content')) is not list):
                raise ValueError('invalid assistant envelope')
            for block in content['content']:
                if type(block) is not dict or block.get('type') not in {'text', 'thinking', 'redacted_thinking'}:
                    raise ValueError('tool or unsupported assistant activity')
                if block['type'] == 'text' and type(block.get('text')) is not str:
                    raise ValueError('invalid assistant text')
        elif kind == 'rate_limit_event' and attempt.initialized:
            info = message.get('rate_limit_info')
            status = info.get('status') if type(info) is dict else None
            attempt.rate_limit_status = (status if type(status) is str and status in _RATE_ENUMS['status']
                                         else 'unknown')
            _rate_metadata(message)
            attempt.rate_limit_events += 1
        elif kind == 'result' and attempt.initialized:
            subtype, error = message.get('subtype'), message.get('is_error')
            if (type(message.get('uuid')) is not str or not message['uuid']
                    or type(error) is not bool
                    or type(message.get('num_turns')) is not int or not 0 <= message['num_turns'] <= 1):
                raise ValueError('invalid terminal envelope')
            model_usage = message.get('modelUsage', {})
            if type(model_usage) is not dict or set(model_usage) - {attempt.request.conditions.model}:
                raise ValueError('unexpected model use')
            if subtype == 'success' and not error:
                if (message['num_turns'] != 1 or type(message.get('result')) is not str
                        or len(message['result'].encode('utf-8')) > MAX_TEXT
                        or message.get('stop_reason') not in (None, 'end_turn')
                        or message.get('terminal_reason') not in (None, 'completed')):
                    raise ValueError('contradictory or oversized success')
                attempt.text = message['result']
            elif subtype not in ERROR_SUBTYPES and not (subtype == 'success' and error):
                raise ValueError('unknown terminal outcome')
            elif not error:
                raise ValueError('contradictory error result')
            # Retain only bounded identity/outcome fields; errors stay private to Native.
            attempt.result = {'uuid': message['uuid'], 'subtype': subtype, 'is_error': error}
        else:
            raise ValueError('unknown Native frame or ordering')

    def _pump(self, attempt):
        if attempt.terminal:
            return
        try:
            if self._clock() - attempt.started >= self._timeout:
                self._finish(attempt, State.ERROR, 'native_turn_timeout')
                return
            attempt.phase = 'transport_poll'
            attempt.kind, attempt.system_subtype, attempt.failed_checks = 'none', 'none', ()
            messages = attempt.transport.poll()
            if type(messages) is not tuple or len(messages) > MAX_BATCH:
                raise ValueError('invalid bounded poll')
            for message in messages:
                self._message(attempt, message)
            # Short batches and a result never certify EOF. Later calls continue
            # draining and may invalidate an otherwise successful result.
            attempt.phase = 'transport_drain'
            if attempt.transport.drained():
                attempt.phase = 'owned_wait'
                code = attempt.transport.wait_owned()
                if code is None:
                    return
                if attempt.result is None:
                    self._finish(attempt, State.ERROR, 'native_exit_without_result')
                elif attempt.result['is_error']:
                    self._finish(attempt, State.ERROR, 'native_result_error')
                elif type(code) is not int or code != 0:
                    self._finish(attempt, State.ERROR, 'native_exit_contradicts_success')
                else:
                    if self._completion is not None:
                        attempt.phase = 'completion_verification'
                        proof = self._completion(attempt.request, attempt.session, attempt.result['uuid'])
                        if proof is not None and (type(proof) is not str or not proof):
                            raise ValueError('invalid completion evidence')
                        attempt.proof = proof
                    self._finish(attempt, State.COMPLETED)
        except Exception as exc:
            category = DIAGNOSTICS.get(str(exc)) if type(exc) is ValueError else None
            if category is None:
                category = {'transport_poll': 'transport_poll_failed',
                    'transport_drain': 'transport_drain_failed', 'owned_wait': 'owned_wait_failed',
                    'completion_verification': 'completion_verification_failed'}.get(
                        attempt.phase, 'native_frame_processing_failed')
            attempt.diagnostic = {'phase': attempt.phase, 'category': category,
                'frame_kind': attempt.kind, 'system_subtype': attempt.system_subtype, 'frames_seen': min(attempt.frames, MAX_FRAMES + 1),
                'init_observed': attempt.initialized, 'result_observed': attempt.result is not None,
                'failed_checks': attempt.failed_checks}
            self._finish(attempt, State.ERROR, 'native_protocol_or_transport_error')

    def commands_observation(self, ref):
        """Inventory counts only; never available capabilities or a dispatch route."""
        attempt = self._get(ref)
        return {'accepted_event_count': attempt.commands_events,
                'last_command_count': attempt.command_count, 'commands_executed_by_adapter': 0}

    def rate_limit_observation(self, ref):
        """Fixed observational metadata only; never remaining Usage or authorization."""
        attempt = self._get(ref)
        return {'accepted_event_count': attempt.rate_limit_events,
                'last_status': attempt.rate_limit_status, 'remaining_usage': 'unknown'}

    def protocol_diagnostic(self, ref):
        """Private fixed-category observation; not a success/cessation attestation."""
        value = self._get(ref).diagnostic
        return dict(value) if value is not None else None

    def _get(self, ref):
        if ref not in self._attempts:
            raise ValueError('unknown Attempt')
        return self._attempts[ref]

    def events(self, ref, after=None):
        attempt = self._get(ref)
        start = 0
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
        return next(event for event in reversed(attempt.events) if isinstance(event, StatusEvent))

    def stop(self, ref):
        if ref not in self._attempts:
            return StopReply(ref, StopStatus.ERROR, 'unknown Attempt')
        attempt = self._get(ref)
        if attempt.proof and attempt.terminal:
            return StopReply(ref, StopStatus.CONFIRMED, 'bound text turn completed and owned CLI exited', attempt.proof)
        if not attempt.terminal:
            self._finish(attempt, State.ERROR, 'stop_requested_cessation_unconfirmed')
        return StopReply(ref, StopStatus.UNCONFIRMED, 'owned process cleanup is not Native cancellation proof')

    def resume(self, state):
        if state.adapter != ADAPTER or state.ref not in self._attempts:
            return OperationReply(state.ref, OperationStatus.INVALID_STATE, 'unknown resume identity')
        if self._get(state.ref).terminal:
            return OperationReply(state.ref, OperationStatus.INVALID_STATE, 'Attempt is terminal')
        return OperationReply(state.ref, OperationStatus.UNSUPPORTED, 'same-Attempt Resume unsupported')

    def respond(self, response):
        if response.ref not in self._attempts:
            return OperationReply(response.ref, OperationStatus.INVALID_STATE, 'unknown Attempt')
        if self._get(response.ref).terminal:
            return OperationReply(response.ref, OperationStatus.INVALID_STATE, 'Attempt is terminal')
        return OperationReply(response.ref, OperationStatus.UNSUPPORTED, 'permission relay unsupported on text role')

    def usage(self):
        return ()

    def text_output(self, ref):
        """Private host output for independent AC/artifact handling; not a Result verdict."""
        attempt = self._get(ref)
        if not attempt.terminal or attempt.text is None:
            raise ValueError('successful text output unavailable')
        return attempt.text

    def collect_output(self, ref):
        """Optional public collector for a verified output_mode=collect route.

        Wraps the audited private text_output: exactly one verbatim UTF-8
        text item exists only for an internally proven COMPLETED Attempt.
        Failed, stopped or unfinished Attempts keep the fixed ValueError
        refusal; an unknown ref is a CollectionError — no transcript, tool,
        error or diagnostic material. Storage, digests and verdicts remain
        Controller-owned.
        """
        if ref not in self._attempts:
            raise CollectionError('attempt unavailable in this adapter instance')
        return (OutputItem(0, 'text/plain', self.text_output(ref)),)

    def close(self):
        for attempt in self._attempts.values():
            if not attempt.terminal:
                self._finish(attempt, State.ERROR, 'adapter_closed')
