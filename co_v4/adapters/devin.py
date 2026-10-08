"""Devin CLI ACP mapping, following the supplied 3000.11.3 live evidence.

session/update can precede session/new's result. The live default is
accept-edits; advertised modes include accept-edits/smart/ask/plan/bypass,
and session/set_config_option(mode=plan) was observed to succeed. Mode is
trusted constructor configuration, never Job/Worker policy. It is not proof
of interception: accept-edits has no interception guarantee. HostVerifier and
ExecutionConditions.environment_ref/control_evidence_refs own route safety;
Catalog verification must be scoped to that environment.

Every bounded poll drains all complete buffered frames within a finite limit
before deferred sends or successful completion, and unsupported Native
requests latch terminal before any transport send, even their best-effort
error reply. Mode drift fails closed. Callback targets remain incomplete and
ALLOW unsupported. Cancel receipts do not prove cessation; session/load receipts do not prove same-Attempt Resume. Only the trusted text host can attest
cessation from a bound prompt completion, validated EOF and owned-process wait.
Resume/Usage stay unsupported. One owned process per Attempt;
no daemon attach, process-name kills, auth changes or exported resume secrets.
Production Adapter live smoke is separate from the supplied probe evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
from ..devin_selection import ModelObservation
from ..devin_workspace import DevinWorkspaceBinding, execution_workspace
import subprocess
import time
from typing import Callable, Protocol
from uuid import uuid4

from ..contracts import (
    Action, AdapterEvent, AttemptRef, Confirmation, ConfirmationEvent,
    ConfirmationResponse, Decision, ExecuteRequest, NeverStarted, OperationReply,
    OperationStatus, Resolution, Result, ResultEvent, ResumeState, Scope, State,
    StatusEvent, StopReply, StopStatus, TERMINAL, Usage, validate_response,
)


ADAPTER = "devin.acp"
# Minor bump marks the co.controller/4 compatibility change; v3 baseline
# was 0.1.3-dev. The -dev suffix honestly marks this adapter unqualified.
ADAPTER_VERSION = "0.2.0-dev"
PROTOCOL_VERSION = 1
REQUEST_PERMISSION = "session/request_permission"
MAX_BYTES = 1024 * 1024
MAX_POLL = 128
INFORMATIONAL_NOTIFICATIONS = frozenset({
    "_cognition.ai/mcp/serversChanged", "_cognition.ai/output",
})
TURN_TELEMETRY = frozenset({"_cognition.ai/thinking_complete", "_cognition.ai/turn_stats",
                           "_cognition.ai/agent_stopped"})

# Fixed diagnostics only. Neither Native text nor arbitrary exception messages
# are copied into records, even when raised by a custom transport/verifier.
PROTOCOL_DIAGNOSTICS = {
    "invalid Native model advertisement": "invalid_native_model_advertisement",
    "Native model mismatch": "native_model_mismatch",
    "unknown notification on text route": "unknown_text_notification",
    "unsupported activity on text route": "unsupported_text_update",
    "invalid session update": "invalid_session_update",
    "candidate session mismatch": "candidate_session_mismatch",
    "session identity mismatch": "session_identity_mismatch",
    "session update identity mismatch": "session_update_identity_mismatch",
    "cross-session notification": "cross_session_notification",
    "session update outside session creation": "session_update_outside_creation",
    "missing or invalid JSON-RPC version": "invalid_jsonrpc_version",
    "invalid Native JSON": "invalid_native_json",
    "truncated Native frame": "truncated_native_frame",
    "uncorrelated response": "uncorrelated_response",
    "unsupported ACP protocol version": "unsupported_protocol_version",
    "effective mode unconfirmed": "effective_mode_unconfirmed",
    "Native permission mode changed": "native_mode_changed",
    "desired mode unavailable": "desired_mode_unavailable",
    "desired mode unavailable or unconfirmed": "desired_mode_unavailable",
    "desired mode unconfirmed": "desired_mode_unconfirmed",
    "mode switch API unavailable": "mode_switch_unavailable",
    "invalid config options": "invalid_config_options",
    "mode config missing or ambiguous": "mode_config_missing_or_ambiguous",
    "mode options missing": "mode_options_missing",
    "invalid mode options": "invalid_mode_options",
    "mode config update missing": "mode_config_update_missing",
    "completion EOF unconfirmed": "completion_eof_unconfirmed",
    "invalid servers metadata notification": "invalid_servers_metadata_notification",
    "invalid output log envelope": "invalid_output_log_envelope",
    "unbound output log session": "unbound_output_log_session",
    "unbound turn telemetry": "unbound_turn_telemetry",
    "invalid thinking telemetry": "invalid_thinking_telemetry",
    "invalid turn statistics envelope": "invalid_turn_statistics_envelope",
    "invalid agent stopped envelope": "invalid_agent_stopped_envelope",
    "Native stopped telemetry reports error": "native_stopped_telemetry_error",
    "Native stopped telemetry reports activity": "native_stopped_telemetry_activity",
    "invalid stopped statistics": "invalid_stopped_statistics",
    "Native stopped cause contradicts prompt": "native_stopped_cause_contradicts_prompt",
}
DIAGNOSTIC_VARIANTS = frozenset({
    "initialize", "session/new", "session/set_config_option", "session/prompt",
    "session/update", "session/request_permission", "current_mode_update",
    "config_option_update", "current_model_update", "model_update", "session_model_update",
    "user_message_chunk", "agent_message_chunk", "agent_thought_chunk", "tool_call",
    "tool_call_update", "plan", "available_commands_update", "session_info_update", "usage_update",
}) | INFORMATIONAL_NOTIFICATIONS | TURN_TELEMETRY

# ACP ToolKind -> CO action name. Display names are never trusted as the effect.
TOOL_ACTION = {
    "execute": "process.execute",
    "edit": "filesystem.write",
    "delete": "filesystem.write",
    "move": "filesystem.write",
    "read": "filesystem.read",
    "search": "filesystem.read",
    "fetch": "network.fetch",
    "think": "native.think",
    "switch_mode": "session.switch_mode",
    "other": "native.other",
}
PROMPT_OUTCOME = {
    "end_turn": (State.COMPLETED, None),
    "cancelled": (State.FAILED, "native_prompt_cancelled"),
    "refusal": (State.FAILED, "native_prompt_refusal"),
    "max_tokens": (State.ERROR, "native_prompt_limit"),
    "max_turn_requests": (State.ERROR, "native_prompt_limit"),
}


class NativeError(RuntimeError):
    """A sanitized transport/protocol failure, never raw Native output."""


class Transport(Protocol):
    def send(self, message: dict) -> None: ...
    # At most MAX_POLL complete frames per call; a remainder stays buffered
    # for the next call, never silently dropped. _pump drains before acting.
    def poll(self) -> tuple[dict, ...]: ...
    def alive(self) -> bool: ...
    def close(self) -> None: ...


class HostVerifier(Protocol):
    """Trusted composition dependency, NOT supplied by Worker/request JSON.

    Must resolve current evidence for the exact request and actual transport
    launch. phase='launch' precedes process creation; 'session' includes the
    effective session evidence after desired-mode confirmation. Raise on missing, stale or inadequate evidence.
    The transport factory and this verifier must describe the same host/config.
    Returning an evidence string without checking the host is not sufficient.
    """
    def __call__(self, request: ExecuteRequest, phase: str,
                 native: dict | None) -> None: ...


class TextCessationVerifier(Protocol):
    """Trusted text-host dependency, never Native/Worker evidence JSON.

    Verify the actual launch/submission binding, reap only the owned CLI, call
    drain to validate every remaining frame to EOF, then return a private proof
    reference. A process exit or a cancel receipt alone cannot satisfy this.
    """
    def __call__(self, request: ExecuteRequest, session: str, prompt_rpc: str,
                 stop_reason: str, drain: Callable[[Callable[[], bool]], None]) -> str | None: ...


def _refuse(request: ExecuteRequest, phase: str, native: dict | None) -> None:
    raise NativeError("host controls unverified")


def scrub_environment(environ: dict) -> dict:
    """Drop inherited DEVIN_* variables from a spawned CLI environment.

    #156 found DEVIN_SANDBOX=1 breaks nested `devin` argument parsing. Inherited
    permission/model/sandbox variables must not silently shape Worker autonomy.
    Authentication variables outside the DEVIN_ prefix are untouched; the host
    verifier owns credential policy.
    """
    return {key: value for key, value in environ.items()
            if not key.startswith("DEVIN_")}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise NativeError("duplicate JSON key")
        result[key] = value
    return result


def _scalar(value) -> str | None:
    return value if isinstance(value, str) and value else None


class AcpTransport:
    """Owned `devin acp` subprocess; bounded nonblocking NDJSON.

    Construction runs one bounded `devin version` probe (success required; an
    optional expected_version may pin the exact output). Version probing is not
    authentication or isolation proof. stderr is never copied into CO records.
    close reaps only our own process; it does NOT prove tool descendants
    stopped. DEVIN_* variables are removed from the child environment.
    """
    def __init__(self, executable: str, workspace: str, model: str, *,
                 expected_version: str | None = None, environ: dict | None = None):
        if not Path(executable).is_absolute():
            raise NativeError("absolute executable required")
        if not isinstance(model, str) or not model:
            raise NativeError("model required")
        env = scrub_environment(os.environ if environ is None else environ)
        version = subprocess.run([executable, "version"], capture_output=True,
                                 timeout=5, check=False, env=env)
        observed = version.stdout.strip()
        if version.returncode or not observed:
            raise NativeError("CLI version probe failed")
        if expected_version is not None and observed != expected_version.encode():
            raise NativeError("unsupported CLI version")
        self._process = subprocess.Popen(
            [executable, "acp", "--model", model], cwd=workspace,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, env=env,
        )
        self._incoming = bytearray()
        self._outgoing = bytearray()
        self._eof = False
        self._closed = False
        self._waited_exit = None
        self._cleanup_action = None
        self.prompt_binding = None
        for stream in (self._process.stdin, self._process.stdout):
            os.set_blocking(stream.fileno(), False)

    def send(self, message: dict) -> None:
        raw = json.dumps(message, allow_nan=False, separators=(",", ":")).encode() + b"\n"
        if not self.alive() or len(raw) + len(self._outgoing) > MAX_BYTES:
            raise NativeError("transport unavailable or write limit exceeded")
        if message.get("method") == "session/prompt":
            if self.prompt_binding is not None:
                raise NativeError("owned transport already submitted a prompt")
            self.prompt_binding = (message.get("params", {}).get("sessionId"), message.get("id"))
        self._outgoing.extend(raw)
        self._flush()

    def _flush(self):
        if self._outgoing:
            try:
                count = os.write(self._process.stdin.fileno(), self._outgoing)
            except BlockingIOError:
                return
            del self._outgoing[:count]

    def poll(self) -> tuple[dict, ...]:
        self._flush()
        if not self._eof:
            try:
                data = os.read(self._process.stdout.fileno(), 65536)
            except BlockingIOError:
                data = None
            if data == b"":
                self._eof = True
            elif data:
                self._incoming.extend(data)
        if len(self._incoming) > MAX_BYTES:
            raise NativeError("Native frame limit exceeded")
        messages = []
        while b"\n" in self._incoming and len(messages) < MAX_POLL:
            line, _, rest = self._incoming.partition(b"\n")
            self._incoming = bytearray(rest)
            try:
                message = json.loads(line, object_pairs_hook=_object,
                                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            except (ValueError, UnicodeError) as exc:
                raise NativeError("invalid Native JSON") from exc
            if not isinstance(message, dict):
                raise NativeError("Native frame must be an object")
            messages.append(message)
        if self._eof and self._incoming and b"\n" not in self._incoming:
            raise NativeError("truncated Native frame")
        return tuple(messages)

    def alive(self) -> bool:
        return self._process.poll() is None and not self._eof

    def reap_owned(self) -> None:
        """Wait for our CLI; keep stdout open for final protocol validation.

        Terminate/kill are host cleanup, never the Native turn outcome. The
        caller must already have the exact original prompt's completion.
        """
        if self._waited_exit is not None:
            return
        if self._process.poll() is None:
            self._cleanup_action = "terminate"
            self._process.terminate()
            try:
                self._waited_exit = self._process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._cleanup_action = "kill_after_terminate_timeout"
                self._process.kill()
                self._waited_exit = self._process.wait(timeout=1)
        else:
            self._cleanup_action = "already_exited"
            self._waited_exit = self._process.wait(timeout=1)

    def drained(self) -> bool:
        return self._eof and not self._incoming and not self._outgoing

    def close(self) -> None:
        if self._closed:
            return
        self.reap_owned()
        for stream in (self._process.stdin, self._process.stdout):
            stream.close()
        self._closed = True


def devin_confirmation(ref: AttemptRef, request_id: str, params: dict) -> Confirmation:
    """ACP request_permission -> CO Confirmation. Never a complete target.

    toolCall kind/name/title/locations and rawInput key names are display data;
    they do not prove the command, file content, repository, network target or
    side effects. Scope is always incomplete, so shared validation rejects
    allow; deny/cancel remain relayable.
    """
    tool = params["toolCall"]
    kind = _scalar(tool.get("kind"))
    locations = tool.get("locations")
    location = (locations[0].get("path") if isinstance(locations, list)
                and len(locations) == 1 and isinstance(locations[0], dict)
                else None)
    raw_input = tool.get("rawInput")
    fields = (",".join(sorted(key for key in raw_input if isinstance(key, str)))
              if isinstance(raw_input, dict) else None)
    dimensions = tuple((key, value) for key, value in (
        ("kind", kind), ("name", _scalar(tool.get("name"))),
        ("title", _scalar(tool.get("title"))), ("location", _scalar(location)),
        ("input_fields", fields or None)))
    action = Action(TOOL_ACTION.get(kind or "", "native.unknown"),
                    Scope(dimensions, complete=False))
    return Confirmation(ref, request_id, Decision.UNDETERMINED, action,
                        "Native permission requested; semantic target unresolved",
                        ADAPTER, True)


@dataclass
class _Callback:
    rpc_id: str | int
    message: dict
    confirmation: Confirmation
    reject_option: str | None
    response: ConfirmationResponse | None = None
    resolved: bool = False
    delivery_unknown: bool = False


@dataclass
class _Attempt:
    request: ExecuteRequest
    transport: Transport
    events: list[AdapterEvent] = field(default_factory=list)
    pending: dict[str, tuple[str, float | None]] = field(default_factory=dict)
    callbacks: dict[tuple[type, str | int], _Callback] = field(default_factory=dict)
    session: str | None = None
    candidate_session: str | None = None
    pre_session_updates: list[dict] = field(default_factory=list)
    pre_session_bytes: int = 0
    native: dict = field(default_factory=dict)
    models: ModelObservation | None = None
    current_mode: str | None = None
    advertised_modes: set[str] = field(default_factory=set)
    config_mode: dict | None = None
    mode_confirmed: bool = False
    deferred: list[Callable[[], None]] = field(default_factory=list)
    prompt_sent: bool = False
    prompt_rpc: str | None = None
    prompt_completion: str | None = None
    reported_stop_reason: str | None = None
    stopped: bool = False
    cancel_sent: bool = False
    cessation: str | None = None
    closed: bool = False
    phase: str = "initialize"
    diagnostic_variant: str = "unclassified"
    protocol_diagnostic: dict | None = None
    unknown_method_fingerprint: dict = field(default_factory=dict)


class DevinAdapter:
    """Fail-closed mapping of the provisional #156 Adapter Protocol onto ACP.

    Supplied live ordering/config observations guide the protocol mapping;
    they do not establish exact Action capture, ALLOW, cessation, Resume,
    isolation or Usage. Native output text, raw errors, session/tool-call and callback IDs
    are kept out of common events.
    """
    def __init__(self, *, verify_host: HostVerifier = _refuse,
                 transport_factory: Callable[[ExecuteRequest], Transport] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 rpc_timeout: float = 30, desired_mode: str = "plan",
                 verify_text_cessation: TextCessationVerifier | None = None,
                 workspace_binding: DevinWorkspaceBinding | None = None,
                 observe_model: Callable | None = None):
        if not 0 < rpc_timeout <= 300:
            raise ValueError("RPC timeout must be in (0, 300]")
        if not _scalar(desired_mode):
            raise ValueError("trusted desired_mode must be a nonempty string")
        self._observe_model_callback = observe_model
        self._workspace_binding = workspace_binding
        self._desired_mode = desired_mode
        self._verify_text_cessation = verify_text_cessation
        self._verify = verify_host
        self._factory = transport_factory
        self._clock = clock
        self._timeout = rpc_timeout
        self._attempts: dict[AttemptRef, _Attempt] = {}

    def execute(self, request: ExecuteRequest) -> OperationReply:
        ref, conditions = request.ref, request.conditions
        if ref in self._attempts:
            return OperationReply(ref, OperationStatus.INVALID_STATE, "Attempt already used")
        try:
            workspace = execution_workspace(request, self._workspace_binding)
        except Exception:
            return OperationReply(ref, OperationStatus.UNSUPPORTED, "workspace binding unverified",
                never_started=NeverStarted(request, "devin:before-transport:workspace-binding-unverified"))
        if (conditions.adapter != ADAPTER or not conditions.model
                or not Path(workspace).is_absolute()
                or not Path(workspace).is_dir()
                or not conditions.environment_ref or not conditions.control_evidence_refs):
            return OperationReply(ref, OperationStatus.INVALID_STATE, "invalid execution conditions",
                never_started=NeverStarted(request, "devin:before-transport:invalid-execution-conditions"))
        try:
            self._verify(request, "launch", None)
        except Exception:
            return OperationReply(ref, OperationStatus.UNSUPPORTED, "host controls unverified",
                never_started=NeverStarted(request, "devin:before-transport:host-controls-unverified"))
        if self._factory is None:
            return OperationReply(ref, OperationStatus.UNSUPPORTED, "verified transport not configured",
                never_started=NeverStarted(request, "devin:before-transport:verified-transport-not-configured"))
        try:
            transport = self._factory(request)
        except Exception:
            return OperationReply(ref, OperationStatus.UNAVAILABLE, "Native transport unavailable")
        attempt = _Attempt(request, transport, models=ModelObservation(conditions.model))
        self._attempts[ref] = attempt
        self._status(attempt, State.PENDING)
        try:
            self._rpc(attempt, "initialize", {
                "protocolVersion": PROTOCOL_VERSION,
                "clientCapabilities": {
                    "fs": {"readTextFile": False, "writeTextFile": False},
                    "terminal": False},
                "clientInfo": {"name": "co03_devin_adapter", "version": "0.3.0-dev"}})
        except Exception:
            self._fail(attempt, "adapter_transport_error")
            return OperationReply(ref, OperationStatus.ERROR, "Native initialize send failed")
        return OperationReply(ref, OperationStatus.ACCEPTED, "initialize queued; execution not confirmed")

    def _id(self) -> str:
        return uuid4().hex

    def _status(self, attempt: _Attempt, state: State):
        if not attempt.events or self._last_status(attempt).state != state:
            attempt.events.append(StatusEvent(attempt.request.ref, self._id(), state))

    def _last_status(self, attempt: _Attempt) -> StatusEvent:
        return next(e for e in reversed(attempt.events) if isinstance(e, StatusEvent))

    def _terminal(self, attempt: _Attempt) -> bool:
        return self._last_status(attempt).state in TERMINAL

    def _finish(self, attempt: _Attempt, state: State, reason: str | None):
        if self._terminal(attempt):
            return
        self._latch(attempt, state, reason)
        self._close(attempt)

    def _latch(self, attempt: _Attempt, state: State, reason: str | None):
        # Terminal Status+Result in one step; the caller chooses when the
        # owned transport closes relative to any best-effort reply.
        self._status(attempt, state)
        attempt.events.append(ResultEvent(attempt.request.ref, self._id(),
                                         Result(attempt.request.ref, state, reason)))

    def _close(self, attempt: _Attempt):
        if not attempt.closed:
            attempt.closed = True
            try:
                attempt.transport.close()
            except Exception:
                pass  # Never promote failed cleanup to confirmed cessation.

    def _fail(self, attempt: _Attempt, reason: str):
        self._finish(attempt, State.ERROR, reason)

    def _rpc(self, attempt: _Attempt, method: str, params: dict, *, wait=True):
        rpc_id = self._id()
        attempt.phase = method
        # session/prompt blocks until the Native turn ends; only the Controller's
        # own limits or stop() bound it, never this adapter's RPC timeout.
        deadline = self._clock() + self._timeout if wait else None
        attempt.pending[rpc_id] = (method, deadline)
        if method == "session/prompt":
            attempt.prompt_rpc = rpc_id
        attempt.transport.send({"jsonrpc": "2.0", "id": rpc_id,
                                "method": method, "params": params})

    def _get(self, ref: AttemptRef) -> _Attempt:
        if ref not in self._attempts:
            raise ValueError("unknown Attempt")
        return self._attempts[ref]

    def _pump(self, attempt: _Attempt):
        if self._terminal(attempt):
            return
        try:
            # A saturated batch is not a batch boundary: poll can leave
            # complete frames buffered, and no deferred send or completion
            # may run while they remain uninspected. The drain stays finite;
            # an endpoint that keeps returning full batches fails closed.
            for _ in range(MAX_POLL):
                messages = attempt.transport.poll()
                if len(messages) > MAX_POLL:
                    raise NativeError("poll limit exceeded")
                for message in messages:
                    if self._terminal(attempt):
                        break
                    self._message(attempt, message)
                if self._terminal(attempt) or len(messages) < MAX_POLL:
                    break
            else:
                raise NativeError("poll limit exceeded")
            if not self._terminal(attempt):
                if any(deadline is not None and deadline <= self._clock()
                       for _, deadline in attempt.pending.values()):
                    self._fail(attempt, "native_rpc_timeout")
                elif not attempt.transport.alive() and not (
                        self._verify_text_cessation and attempt.prompt_completion):
                    self._fail(attempt, "native_transport_lost")
            # A response is not a batch boundary: later frames can invalidate
            # both the next send and an otherwise successful prompt result.
            for transition in attempt.deferred:
                if self._terminal(attempt):
                    break
                transition()
        except Exception as exc:
            attempt.protocol_diagnostic = {
                "phase": attempt.phase,
                "category": (PROTOCOL_DIAGNOSTICS.get(str(exc), "unclassified_native_error")
                             if type(exc) is NativeError else "non_native_exception"),
                "variant": attempt.diagnostic_variant,
                **attempt.unknown_method_fingerprint,
            }
            self._fail(attempt, "adapter_protocol_error")
        finally:
            attempt.deferred.clear()

    def events(self, ref: AttemptRef, after: str | None = None) -> tuple[AdapterEvent, ...]:
        attempt = self._get(ref)
        start = 0
        if after is not None:
            ids = [event.event_id for event in attempt.events]
            if after not in ids:
                raise ValueError("unknown event cursor")
            start = ids.index(after) + 1
        self._pump(attempt)
        return tuple(attempt.events[start:start + MAX_POLL])

    def status(self, ref: AttemptRef) -> StatusEvent:
        attempt = self._get(ref)
        self._pump(attempt)
        return self._last_status(attempt)

    def protocol_diagnostic(self, ref: AttemptRef) -> dict | None:
        """Read only a fixed-category failure summary; never raw Native data."""
        diagnostic = self._get(ref).protocol_diagnostic
        return dict(diagnostic) if diagnostic is not None else None

    def _message(self, attempt: _Attempt, message: dict):
        if not isinstance(message, dict):
            raise NativeError("invalid message")
        variant = message.get("method")
        params = message.get("params")
        if variant == "session/update" and isinstance(params, dict):
            update = params.get("update")
            if isinstance(update, dict):
                variant = update.get("sessionUpdate")
        attempt.diagnostic_variant = (variant if isinstance(variant, str)
            and variant in DIAGNOSTIC_VARIANTS else "response" if "method" not in message else "unclassified")
        if message.get("jsonrpc") != "2.0":
            raise NativeError("missing or invalid JSON-RPC version")
        if "method" not in message:
            rpc_id = message.get("id")
            if not isinstance(rpc_id, str) or rpc_id not in attempt.pending:
                raise NativeError("uncorrelated response")
            method, _ = attempt.pending.pop(rpc_id)
            if "error" in message:
                self._fail(attempt, "native_rpc_error")
                return
            result = message.get("result")
            if not isinstance(result, dict):
                raise NativeError("invalid result")
            if method == "session/prompt" and rpc_id != attempt.prompt_rpc:
                raise NativeError("prompt identity mismatch")
            self._reply(attempt, method, result)
            return
        method, params = message["method"], message.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            raise NativeError("invalid notification")
        if "id" in message:
            self._callback(attempt, message)
        elif method == "session/update":
            self._session_update(attempt, params)
        elif method in INFORMATIONAL_NOTIFICATIONS:
            self._informational_notification(attempt, method, params)
        elif self._verify_text_cessation and method in TURN_TELEMETRY:
            self._turn_telemetry(attempt, method, params)
        elif isinstance(params.get("sessionId"), str) \
                and params["sessionId"] != attempt.session:
            raise NativeError("cross-session notification")
        elif self._verify_text_cessation:
            if len(method) <= 128:
                attempt.unknown_method_fingerprint = {
                    "method_sha256": hashlib.sha256(method.encode()).hexdigest(),
                    "method_length": len(method),
                }
            raise NativeError("unknown notification on text route")
        # Other notifications are progress data, never control evidence.

    def _informational_notification(self, attempt: _Attempt, method: str, params: dict):
        # CLI 3000.11.3 emits these during bootstrap and prompt execution. Its embedded
        # Native schema declares McpServersChangedNotification and the four-field
        # OutputChannelNotification. This is pinned-Native observation, not an
        # ACP standard. These informational envelopes grant no operation or
        # cessation authority and never suppress standard tool/mode/callback
        # validation. Native-global MCP containment is outside the adopted
        # handoff guarantee; session/new still explicitly supplies mcpServers=[].
        if method == "_cognition.ai/mcp/serversChanged":
            if params:
                raise NativeError("invalid servers metadata notification")
            return
        if (set(params) != {"channel", "level", "message", "sessionId"}
                or not _scalar(params["channel"]) or not _scalar(params["level"])
                or not isinstance(params["message"], str)):
            raise NativeError("invalid output log envelope")
        session = params["sessionId"]
        if session not in (None, ""):
            if not _scalar(session):
                raise NativeError("unbound output log session")
            if attempt.session is not None:
                if session != attempt.session:
                    raise NativeError("unbound output log session")
            else:
                # Like session/update, scoped output may precede session/new's
                # reply. Bind only while that RPC is pending; its eventual
                # sessionId must match before mode gating or prompt submission.
                if (not any(method == "session/new" for method, _ in attempt.pending.values())
                        or (attempt.candidate_session is not None
                            and session != attempt.candidate_session)):
                    raise NativeError("unbound output log session")
                attempt.candidate_session = session
        # Log values are neither interpreted as activity nor emitted to records.
        # Session MCP configuration is still explicitly empty in session/new;
        # this notification does not establish a global Native MCP inventory.

    def _turn_telemetry(self, attempt: _Attempt, method: str, params: dict):
        # Pinned CLI telemetry supplements observation; it never resolves a
        # pending prompt RPC or supplies cessation. Ignore display dimensions,
        # retain no text/IDs, and reject contradictory outcome/activity reports.
        if not attempt.prompt_sent or not attempt.session or params.get("sessionId") != attempt.session:
            raise NativeError("unbound turn telemetry")
        if method == "_cognition.ai/thinking_complete":
            if (set(params) != {"sessionId", "durationMs", "blockIndex"}
                    or any(type(params[key]) is not int or params[key] < 0
                           for key in ("durationMs", "blockIndex"))):
                raise NativeError("invalid thinking telemetry")
        elif method == "_cognition.ai/turn_stats":
            if (not {"sessionId", "turnClientMessageId"} <= set(params)
                    or set(params) - {"sessionId", "turnClientMessageId", "turnRequestId", "responseDimensions"}
                    or not _scalar(params["turnClientMessageId"])
                    or ("turnRequestId" in params and not _scalar(params["turnRequestId"]))
                    or ("responseDimensions" in params and not isinstance(params["responseDimensions"], list))):
                raise NativeError("invalid turn statistics envelope")
        else:
            if (set(params) not in ({"sessionId", "cause", "stats"},
                                   {"sessionId", "cause", "stats", "errorMessage"})
                    or not isinstance(params["cause"], str) or not isinstance(params["stats"], dict)):
                raise NativeError("invalid agent stopped envelope")
            expected = {"complete": "end_turn", "cancelled": "cancelled", "interrupted": "cancelled"}.get(params["cause"])
            if expected is None or params.get("errorMessage") not in (None, ""):
                raise NativeError("Native stopped telemetry reports error")
            stats = params["stats"]
            integers = {"toolCalls", "filesChanged", "commandsRun", "inputTokens", "outputTokens",
                        "ttftMs", "totalTimeMs"}
            numbers = {"tokensPerSec", "creditCost", "acuCost"}
            strings = {"requestId", "modelLabel"}
            allowed = integers | numbers | strings | {"responseDimensions"}
            if set(stats) - allowed or not {"toolCalls", "filesChanged", "commandsRun"} <= set(stats):
                raise NativeError("invalid stopped statistics")
            # The notification itself is optional. If it reports an activity
            # summary, all three counters must be present and zero. Performance
            # metrics legitimately differ between normal/cancelled completions.
            for key, value in stats.items():
                if ((key in integers and (type(value) is not int or value < 0))
                        or (key in numbers and (type(value) not in (int, float)
                            or not math.isfinite(value) or value < 0))
                        or (key in strings and not isinstance(value, str))
                        or (key == "responseDimensions" and not isinstance(value, list))):
                    raise NativeError("invalid stopped statistics")
            if any(stats.get(key, 0) != 0 for key in ("toolCalls", "filesChanged", "commandsRun")):
                raise NativeError("Native stopped telemetry reports activity")
            if attempt.reported_stop_reason not in (None, expected):
                raise NativeError("Native stopped cause contradicts prompt")
            attempt.reported_stop_reason = expected
            self._check_reported_stop(attempt)

    def _check_reported_stop(self, attempt: _Attempt):
        if (attempt.reported_stop_reason is not None and attempt.prompt_completion is not None
                and attempt.reported_stop_reason != attempt.prompt_completion):
            raise NativeError("Native stopped cause contradicts prompt")

    def _reply(self, attempt: _Attempt, method: str, result: dict):
        if method == "initialize":
            if result.get("protocolVersion") != PROTOCOL_VERSION:
                raise NativeError("unsupported ACP protocol version")
            attempt.deferred.append(lambda: self._rpc(attempt, "session/new", {
                "cwd": execution_workspace(attempt.request, self._workspace_binding), "mcpServers": []}))
        elif method == "session/new":
            session = _scalar(result.get("sessionId"))
            if not session or (attempt.candidate_session is not None
                               and session != attempt.candidate_session):
                raise NativeError("session identity mismatch")
            attempt.session = session
            attempt.native = dict(result)
            for params in attempt.pre_session_updates:
                self._session_update(attempt, params)
            attempt.pre_session_updates.clear()
            attempt.pre_session_bytes = 0
            self._observe_fields(attempt, result)
            attempt.deferred.append(lambda: self._mode_gate(attempt))
        elif method == "session/set_config_option":
            # An empty success receipt is not confirmation. A preceding mode
            # notification or the returned configOptions must confirm it.
            self._observe_fields(attempt, result)
            attempt.deferred.append(lambda: self._start_prompt(attempt))
        elif method == "session/prompt":
            self._observe_models(attempt, result)
            outcome = PROMPT_OUTCOME.get(result.get("stopReason"))
            if outcome is None:
                raise NativeError("unknown prompt stop reason")
            if "sessionId" in result and result["sessionId"] != attempt.session:
                raise NativeError("prompt session identity mismatch")
            attempt.prompt_completion = result["stopReason"]
            self._check_reported_stop(attempt)
            # Defer until trailing frames have been checked. Only an explicitly
            # configured text host may attest cessation; generic mappings retain
            # their existing unsupported behavior.
            attempt.deferred.append(lambda: self._complete_prompt(attempt, outcome))
        else:
            raise NativeError("unmapped RPC response")

    def _complete_prompt(self, attempt: _Attempt, outcome):
        attempt.phase = "completion"
        reason = attempt.prompt_completion
        if (self._verify_text_cessation is not None
                and reason in ("end_turn", "cancelled")
                and (reason != "cancelled" or attempt.cancel_sent)):
            if (self._desired_mode != "plan" or attempt.current_mode != "plan"
                    or not attempt.mode_confirmed or attempt.pending or attempt.callbacks
                    or not attempt.session or not attempt.prompt_rpc):
                raise NativeError("text cessation prerequisites missing")
            proof = self._verify_text_cessation(
                attempt.request, attempt.session, attempt.prompt_rpc, reason,
                lambda done: self._drain_completion(attempt, done))
            if self._terminal(attempt):
                return
            if proof is not None and (not isinstance(proof, str) or not proof):
                raise NativeError("text cessation proof missing")
            attempt.cessation = proof
        self._finish(attempt, *outcome)

    def _drain_completion(self, attempt: _Attempt, done: Callable[[], bool]):
        # Unlike a nonblocking progress poll, even short batches must be drained
        # to EOF after wait. No terminal result may hide late control activity.
        for _ in range(MAX_POLL):
            messages = attempt.transport.poll()
            if len(messages) > MAX_POLL:
                raise NativeError("completion drain limit exceeded")
            for message in messages:
                self._message(attempt, message)
                if self._terminal(attempt):
                    raise NativeError("completion invalidated")
            if done():
                return
        raise NativeError("completion EOF unconfirmed")

    def _observe_mode(self, attempt: _Attempt, mode):
        if not _scalar(mode):
            raise NativeError("effective mode unconfirmed")
        if attempt.mode_confirmed and mode != self._desired_mode:
            raise NativeError("Native permission mode changed")
        attempt.current_mode = mode
        if mode == self._desired_mode:
            attempt.mode_confirmed = True

    def _observe_models(self, attempt, fields, *, current_update=False):
        try:
            attempt.models.observe(fields, current_update=current_update)
        except ValueError as exc:
            # Notify the trusted host as well, so a former observation cannot
            # remain marked verified after a later advertisement invalidates it.
            if self._observe_model_callback:
                try: self._observe_model_callback(fields, current_update=current_update)
                except Exception: pass
            raise NativeError(str(exc)) from None
        if self._observe_model_callback:
            self._observe_model_callback(fields, current_update=current_update)
        if "models" in fields:
            attempt.native["models"] = fields["models"]
        if attempt.models.current is not None and attempt.models.available is not None:
            attempt.native["models"] = {
                "currentModelId": attempt.models.current,
                "availableModels": [{"modelId": uid} for uid in attempt.models.available]}

    def _observe_fields(self, attempt: _Attempt, fields: dict):
        self._observe_models(attempt, fields)
        if "modes" in fields:
            modes = fields["modes"]
            if not isinstance(modes, dict):
                raise NativeError("invalid modes")
            available = modes.get("availableModes")
            if not isinstance(available, list) or not available:
                raise NativeError("mode advertisement missing")
            ids = [m.get("id") if isinstance(m, dict) else None for m in available]
            if not all(_scalar(mid) for mid in ids):
                raise NativeError("invalid mode advertisement")
            attempt.advertised_modes = set(ids)
            attempt.native["modes"] = modes
            self._observe_mode(attempt, modes.get("currentModeId"))
        if "configOptions" in fields:
            options = fields["configOptions"]
            if not isinstance(options, list) or not all(isinstance(o, dict) for o in options):
                raise NativeError("invalid config options")
            mode_options = [o for o in options if (o.get("id") or o.get("configId")) == "mode"]
            if len(mode_options) != 1:
                raise NativeError("mode config missing or ambiguous")
            option = mode_options[0]
            values = option.get("options")
            if not isinstance(values, list) or not values:
                raise NativeError("mode options missing")
            ids = [v.get("value") if isinstance(v, dict) else None for v in values]
            if not all(_scalar(mid) for mid in ids):
                raise NativeError("invalid mode options")
            attempt.advertised_modes = set(ids)
            attempt.config_mode = option
            attempt.native["configOptions"] = options
            self._observe_mode(attempt, option.get("currentValue"))
        if attempt.mode_confirmed and self._desired_mode not in attempt.advertised_modes:
            raise NativeError("desired mode unavailable")

    def _mode_gate(self, attempt: _Attempt):
        if (self._desired_mode not in attempt.advertised_modes
                or attempt.current_mode is None):
            raise NativeError("desired mode unavailable or unconfirmed")
        if attempt.current_mode == self._desired_mode:
            self._start_prompt(attempt)
        elif attempt.config_mode is not None:
            self._rpc(attempt, "session/set_config_option", {
                "sessionId": attempt.session, "configId": "mode",
                "value": self._desired_mode})
        else:
            raise NativeError("mode switch API unavailable")

    def _start_prompt(self, attempt: _Attempt):
        if (not attempt.mode_confirmed or attempt.current_mode != self._desired_mode
                or self._desired_mode not in attempt.advertised_modes):
            raise NativeError("desired mode unconfirmed")
        if attempt.stopped or attempt.prompt_sent:
            raise NativeError("prompt transition no longer valid")
        # Supply the effective snapshot, including observations made after new.
        native = dict(attempt.native)
        if "modes" in native:
            native["modes"] = {**native["modes"], "currentModeId": attempt.current_mode}
        if "configOptions" in native:
            native["configOptions"] = [
                {**o, "currentValue": attempt.current_mode}
                if (o.get("id") or o.get("configId")) == "mode" else o
                for o in native["configOptions"]]
        self._verify(attempt.request, "session", native)
        job = attempt.request.job
        text = json.dumps({"instructions": job.instructions,
                           "context": json.loads(job.context_json),
                           "acceptance_criteria": job.acceptance_criteria}, ensure_ascii=False)
        # Set before send: a lost/partial write must not permit redispatch.
        attempt.prompt_sent = True
        self._rpc(attempt, "session/prompt", {
            "sessionId": attempt.session,
            "prompt": [{"type": "text", "text": text}]}, wait=False)
        self._refresh_running(attempt)

    def _session_update(self, attempt: _Attempt, params: dict):
        session = _scalar(params.get("sessionId"))
        update = params.get("update")
        if not session or not isinstance(update, dict):
            raise NativeError("invalid session update")
        variant = update.get("sessionUpdate")
        attempt.diagnostic_variant = (variant if isinstance(variant, str)
            and variant in DIAGNOSTIC_VARIANTS else "unclassified")
        if attempt.session is None:
            if not any(method == "session/new" for method, _ in attempt.pending.values()):
                raise NativeError("session update outside session creation")
            if attempt.candidate_session is not None and session != attempt.candidate_session:
                raise NativeError("candidate session mismatch")
            attempt.candidate_session = session
            attempt.pre_session_bytes += len(json.dumps(params).encode())
            if (len(attempt.pre_session_updates) >= MAX_POLL
                    or attempt.pre_session_bytes > MAX_BYTES):
                raise NativeError("pre-session update limit exceeded")
            attempt.pre_session_updates.append(params)
            return
        if session != attempt.session:
            raise NativeError("session update identity mismatch")
        model_update = update.get("sessionUpdate") in {
            "current_model_update", "model_update", "session_model_update"}
        self._observe_models(attempt, update, current_update=model_update)
        if model_update:
            return
        if update.get("sessionUpdate") == "current_mode_update":
            self._observe_mode(attempt, update.get("currentModeId"))
        elif update.get("sessionUpdate") == "config_option_update":
            if "configOptions" not in update:
                raise NativeError("mode config update missing")
            self._observe_fields(attempt, update)
        elif self._verify_text_cessation and update.get("sessionUpdate") not in {
                "user_message_chunk", "agent_message_chunk", "agent_thought_chunk",
                "plan", "available_commands_update", "session_info_update", "usage_update"}:
            raise NativeError("unsupported activity on text route")

    def _callback(self, attempt: _Attempt, message: dict):
        rpc_id, method, params = message["id"], message["method"], message["params"]
        if type(rpc_id) not in (int, str) or (isinstance(rpc_id, str) and not rpc_id):
            raise NativeError("invalid callback ID")
        if params.get("sessionId") != attempt.session:
            raise NativeError("callback identity mismatch")
        if self._verify_text_cessation and method == REQUEST_PERMISSION:
            raise NativeError("permission request on text-only route")
        if method == REQUEST_PERMISSION and not attempt.prompt_sent:
            raise NativeError("permission request before prompt turn")
        key = (type(rpc_id), rpc_id)
        if key in attempt.callbacks:
            if attempt.callbacks[key].message != message:
                raise NativeError("callback ID reused with changed target")
            return
        if method != REQUEST_PERMISSION:
            # Undelegated client-side requests (fs/terminal/elicitation/...)
            # are fatal when parsed: the terminal latch wins before ANY
            # transport side effect, so an error reply send that reenters
            # the adapter or raises cannot run a deferred prompt send or
            # successful completion queued by an earlier frame in this
            # batch. The error reply grants nothing, stays best-effort, and
            # the request's execution is not assumed stopped.
            self._latch(attempt, State.ERROR, "native_request_unsupported")
            try:
                attempt.transport.send({"jsonrpc": "2.0", "id": rpc_id, "error": {
                    "code": -32601, "message": "unsupported Native request"}})
            except Exception:
                pass
            self._close(attempt)
            return
        tool = params.get("toolCall")
        options = params.get("options")
        if (not isinstance(tool, dict)
                or not isinstance(tool.get("toolCallId"), str) or not tool["toolCallId"]
                or not isinstance(options, list)):
            raise NativeError("invalid permission request")
        reject = next((o.get("optionId") for o in options
                       if isinstance(o, dict) and o.get("kind") == "reject_once"
                       and isinstance(o.get("optionId"), str) and o["optionId"]), None)
        confirmation = devin_confirmation(attempt.request.ref, self._id(), params)
        attempt.callbacks[key] = _Callback(rpc_id, message, confirmation, reject)
        attempt.events.append(ConfirmationEvent(attempt.request.ref, self._id(), confirmation))
        self._status(attempt, State.WAITING_HUMAN)
        if attempt.stopped:
            attempt.deferred.append(lambda: self._cancel_callback(attempt, attempt.callbacks[key]))

    def _refresh_running(self, attempt: _Attempt):
        waiting = any(not cb.resolved for cb in attempt.callbacks.values())
        self._status(attempt, State.WAITING_HUMAN if waiting else State.RUNNING)

    def _cancel_callback(self, attempt: _Attempt, callback: _Callback):
        """Spec-required cancelled outcome after session/cancel; best-effort."""
        callback.resolved = True
        try:
            attempt.transport.send({"jsonrpc": "2.0", "id": callback.rpc_id,
                                    "result": {"outcome": {"outcome": "cancelled"}}})
        except Exception:
            pass  # Stop delivery is already unconfirmed; do not upgrade.

    def respond(self, response: ConfirmationResponse) -> OperationReply:
        ref = response.ref
        if ref not in self._attempts:
            return OperationReply(ref, OperationStatus.INVALID_STATE, "unknown Attempt")
        attempt = self._get(ref)
        self._pump(attempt)
        callback = next((cb for cb in attempt.callbacks.values()
                         if cb.confirmation.request_id == response.request_id), None)
        if callback is None:
            return OperationReply(ref, OperationStatus.INVALID_STATE, "unknown callback")
        if callback.response is not None:
            if callback.delivery_unknown:
                return OperationReply(ref, OperationStatus.ERROR,
                                      "response delivery unknown; do not retry")
            same = callback.response == response
            return OperationReply(ref, OperationStatus.ACCEPTED if same else OperationStatus.INVALID_STATE,
                                  "response already relayed" if same else "conflicting response")
        if self._terminal(attempt) or callback.resolved or attempt.stopped:
            return OperationReply(ref, OperationStatus.INVALID_STATE, "callback no longer answerable")
        try:
            if type(response.resolution) is not Resolution:
                raise ValueError("unknown resolution")
            validate_response(callback.confirmation, response)
        except ValueError:
            return OperationReply(ref, OperationStatus.INVALID_STATE, "response target/resolution rejected")
        if response.resolution == Resolution.ALLOW:
            return OperationReply(ref, OperationStatus.UNSUPPORTED, "allow selection unverified")
        if response.resolution == Resolution.DENY and callback.reject_option:
            outcome = {"outcome": "selected", "optionId": callback.reject_option}
        else:
            # CANCEL maps to cancelled; DENY without a reject_once option falls
            # back to cancelled (denies this invocation; the turn also ends).
            outcome = {"outcome": "cancelled"}
        # Record before send: ambiguous writes must never be retried.
        callback.response = response
        try:
            attempt.transport.send({"jsonrpc": "2.0", "id": callback.rpc_id,
                                    "result": {"outcome": outcome}})
        except Exception:
            callback.delivery_unknown = True
            self._fail(attempt, "adapter_response_delivery_unknown")
            return OperationReply(ref, OperationStatus.ERROR, "response delivery unknown; do not retry")
        callback.resolved = True
        self._refresh_running(attempt)
        return OperationReply(ref, OperationStatus.ACCEPTED, "response sent; Native outcome unverified")

    def stop(self, ref: AttemptRef) -> StopReply:
        if ref not in self._attempts:
            return StopReply(ref, StopStatus.ERROR, "unknown Attempt")
        attempt = self._get(ref)
        # Latch before polling: stop during bootstrap must never submit a prompt.
        attempt.stopped = True
        if not attempt.prompt_sent and not self._terminal(attempt):
            attempt.cessation = "devin.acp:no-prompt-submitted:" + self._id()
            self._finish(attempt, State.FAILED, "stopped_before_prompt")
        elif not self._terminal(attempt):
            self._pump(attempt)
            if not self._terminal(attempt):
                # ACP requires cancelled outcomes on pending permission requests.
                for callback in attempt.callbacks.values():
                    if not callback.resolved:
                        self._cancel_callback(attempt, callback)
                if not attempt.cancel_sent:
                    attempt.cancel_sent = True
                    try:
                        # Notification: there is no Native receipt to await.
                        attempt.transport.send({"jsonrpc": "2.0",
                                                "method": "session/cancel",
                                                "params": {"sessionId": attempt.session}})
                        if self._verify_text_cessation and attempt.prompt_rpc in attempt.pending:
                            attempt.pending[attempt.prompt_rpc] = (
                                "session/prompt", self._clock() + self._timeout)
                    except Exception:
                        self._fail(attempt, "adapter_cancel_delivery_unknown")
        if attempt.cessation:
            detail = ("bound text turn completed and owned CLI reaped" if attempt.prompt_sent
                      else "no model turn submitted")
            return StopReply(ref, StopStatus.CONFIRMED, detail, attempt.cessation)
        return StopReply(ref, StopStatus.UNCONFIRMED,
                         "cancel delivery/receipt does not prove cessation")

    def resume(self, state: ResumeState) -> OperationReply:
        if state.adapter != ADAPTER or state.ref not in self._attempts:
            return OperationReply(state.ref, OperationStatus.INVALID_STATE, "unknown resume identity")
        attempt = self._get(state.ref)
        self._pump(attempt)
        if self._terminal(attempt) or attempt.stopped:
            return OperationReply(state.ref, OperationStatus.INVALID_STATE, "Attempt is terminal or stopping")
        return OperationReply(state.ref, OperationStatus.UNSUPPORTED,
                              "session/load receipt does not prove same-Attempt Resume")

    def usage(self) -> tuple[Usage, ...]:
        return ()

    def close(self) -> None:
        """Release owned transports; loss of transport is not stop confirmation."""
        for attempt in self._attempts.values():
            if not self._terminal(attempt):
                self._fail(attempt, "adapter_closed")
