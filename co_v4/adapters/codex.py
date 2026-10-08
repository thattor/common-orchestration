"""Codex app-server 0.156.1 mapping; no live control capability is implied.

The default host gate refuses execution. A trusted host must resolve evidence
and verify actual credentials, filesystem/network access, protected CO storage,
and required controls BEFORE opening the transport, then check effective thread
configuration before a turn. Neither generated schemas nor a sandbox name do so.
This module does not supply that deployment-specific verifier.

Calls are serialized as required by Adapter. One private app-server per Attempt;
no daemon attach, auth changes, provider fallback, session-wide approvals or
process-name kills. Resume is deliberately unsupported until same-turn recovery
and protected persistence are demonstrated. No resume secret is exported.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
import os
import re
from pathlib import Path
import subprocess
import time
from typing import Callable, Protocol
from uuid import uuid4

from ..contracts import (
    AdapterEvent, AttemptRef, Confirmation, ConfirmationEvent,
    ConfirmationResponse, ExecuteRequest, NeverStarted, OperationReply, OperationStatus,
    Resolution, Result, ResultEvent, ResumeState, State, StatusEvent,
    StopReply, StopStatus, TERMINAL, Usage, validate_response,
)
from ..native_notifications import COMMAND_APPROVAL, codex_confirmation


ADAPTER = "codex.app-server"
# Minor bump marks the co.controller/4 compatibility change; v3 baseline
# was 0.1.2-dev. The -dev suffix honestly marks this adapter unqualified.
ADAPTER_VERSION = "0.2.0-dev"
CLI_VERSION = "codex-cli 0.156.1"
# Exact reviewed wire versions; this is not Native host admission evidence.
SUPPORTED_CLI_VERSIONS = frozenset({CLI_VERSION, "codex-cli 0.159.2"})
FILE_APPROVAL = "item/fileChange/requestApproval"
MAX_BYTES = 1024 * 1024
MAX_POLL = 128


class NativeError(RuntimeError):
    """A sanitized transport/protocol failure, never raw Native output."""


class Transport(Protocol):
    def send(self, message: dict) -> None: ...
    def poll(self) -> tuple[dict, ...]: ...
    def alive(self) -> bool: ...
    def close(self) -> None: ...


class HostVerifier(Protocol):
    """Trusted composition dependency, NOT supplied by Worker/request JSON.

    Must resolve current evidence for the exact request and actual transport
    launch. phase='launch' precedes process creation; 'turn' includes the Native
    thread/start result. Raise on missing, stale or inadequate evidence. The
    transport factory and this verifier must describe the same host/config.
    Returning an evidence string without checking the host is not sufficient.
    """
    def __call__(self, request: ExecuteRequest, phase: str,
                 native: dict | None) -> None: ...


def _refuse(request: ExecuteRequest, phase: str, native: dict | None) -> None:
    raise NativeError("host controls unverified")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise NativeError("duplicate JSON key")
        result[key] = value
    return result


class StdioTransport:
    """Bounded nonblocking NDJSON; stderr is never copied into CO records.

    Construction checks version but is not authentication or isolation proof.
    close reaps only our app-server; it does NOT prove tool descendants stopped.
    """
    def __init__(self, executable: str, workspace: str, *,
                 config_overrides: tuple[str, ...] = (), env: dict | None = None,
                 required_version: str | None = None):
        if not Path(executable).is_absolute():
            raise NativeError("absolute executable required")
        version = subprocess.run([executable, "--version"], capture_output=True,
                                 timeout=5, check=False)
        if version.returncode or version.stdout.strip() not in {
                item.encode() for item in SUPPORTED_CLI_VERSIONS}:
            raise NativeError("unsupported CLI version")
        self.native_version = version.stdout.strip().decode("ascii")
        if required_version is not None and self.native_version != required_version:
            raise NativeError("unsupported profile CLI version")
        argv = [executable, "app-server", "--stdio"]
        for override in config_overrides:
            argv.extend(("-c", override))
        self._process = subprocess.Popen(
            argv, cwd=workspace, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0,
        )
        self._incoming = bytearray()
        self._outgoing = bytearray()
        self._eof = False
        for stream in (self._process.stdin, self._process.stdout):
            os.set_blocking(stream.fileno(), False)

    def send(self, message: dict) -> None:
        raw = json.dumps(message, allow_nan=False, separators=(",", ":")).encode() + b"\n"
        if not self.alive() or len(raw) + len(self._outgoing) > MAX_BYTES:
            raise NativeError("transport unavailable or write limit exceeded")
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

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=1)
        for stream in (self._process.stdin, self._process.stdout):
            stream.close()


@dataclass
class _Callback:
    rpc_id: str | int
    message: dict
    confirmation: Confirmation
    response: ConfirmationResponse | None = None
    resolved: bool = False
    delivery_unknown: bool = False


@dataclass
class _Attempt:
    request: ExecuteRequest
    transport: Transport
    events: list[AdapterEvent] = field(default_factory=list)
    pending: dict[str, tuple[str, float]] = field(default_factory=dict)
    callbacks: dict[tuple[type, str | int], _Callback] = field(default_factory=dict)
    thread: str | None = None
    turn: str | None = None
    turn_sent: bool = False
    stopped: bool = False
    interrupt_sent: bool = False
    interrupt_ack: bool = False
    cessation: str | None = None
    closed: bool = False


class CodexAdapter:
    """Fail-closed mapping of the provisional #156 Adapter Protocol.

    Default usage is unavailable; no invented percentages. All approval scopes
    remain incomplete: only decline/cancel relay is implemented. Native output
    text, raw errors, thread IDs and callback IDs are kept out of common events.
    """
    def __init__(self, *, verify_host: HostVerifier = _refuse,
                 transport_factory: Callable[[ExecuteRequest], Transport] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 rpc_timeout: float = 30, permission_profile: str | None = None,
                 reasoning_effort: str | None = None):
        if not 0 < rpc_timeout <= 300:
            raise ValueError("RPC timeout must be in (0, 300]")
        if permission_profile is not None and (type(permission_profile) is not str
                or not re.fullmatch(r"co_readonly_[0-9a-f]{32}", permission_profile)):
            raise ValueError("invalid trusted permission profile")
        if reasoning_effort is not None and (permission_profile is None
                or type(reasoning_effort) is not str or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", reasoning_effort)):
            raise ValueError("invalid trusted reasoning effort")
        self._profile, self._effort = permission_profile, reasoning_effort
        self._verify = verify_host
        self._factory = transport_factory
        self._clock = clock
        self._timeout = rpc_timeout
        self._attempts: dict[AttemptRef, _Attempt] = {}

    def execute(self, request: ExecuteRequest) -> OperationReply:
        ref, conditions = request.ref, request.conditions
        if ref in self._attempts:
            return OperationReply(ref, OperationStatus.INVALID_STATE, "Attempt already used")
        if (conditions.adapter != ADAPTER or not conditions.model
                or not Path(conditions.workspace).is_absolute()
                or not Path(conditions.workspace).is_dir()
                or not conditions.environment_ref or not conditions.control_evidence_refs):
            return OperationReply(ref, OperationStatus.INVALID_STATE, "invalid execution conditions",
                never_started=NeverStarted(request, "codex:before-transport:invalid-execution-conditions"))
        try:
            self._verify(request, "launch", None)
        except Exception:
            return OperationReply(ref, OperationStatus.UNSUPPORTED, "host controls unverified",
                never_started=NeverStarted(request, "codex:before-transport:host-controls-unverified"))
        if self._factory is None:
            return OperationReply(ref, OperationStatus.UNSUPPORTED, "verified transport not configured",
                never_started=NeverStarted(request, "codex:before-transport:verified-transport-not-configured"))
        try:
            transport = self._factory(request)
        except Exception:
            return OperationReply(ref, OperationStatus.UNAVAILABLE, "Native transport unavailable")
        attempt = _Attempt(request, transport)
        self._attempts[ref] = attempt
        self._status(attempt, State.PENDING)
        try:
            params = {"clientInfo": {"name": "co03_codex_adapter", "version": "0.3.0-dev"}}
            if self._profile is not None:
                params["capabilities"] = {"experimentalApi": True}
            self._rpc(attempt, "initialize", params)
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
        self._status(attempt, state)
        attempt.events.append(ResultEvent(attempt.request.ref, self._id(),
                                         Result(attempt.request.ref, state, reason)))
        self._close(attempt)

    def _close(self, attempt: _Attempt):
        if not attempt.closed:
            attempt.closed = True
            try:
                attempt.transport.close()
            except Exception:
                pass  # Never promote failed cleanup to confirmed cessation.

    def _fail(self, attempt: _Attempt, reason: str):
        self._finish(attempt, State.ERROR, reason)

    def _rpc(self, attempt: _Attempt, method: str, params: dict):
        rpc_id = self._id()
        attempt.pending[rpc_id] = (method, self._clock() + self._timeout)
        attempt.transport.send({"id": rpc_id, "method": method, "params": params})

    def _get(self, ref: AttemptRef) -> _Attempt:
        if ref not in self._attempts:
            raise ValueError("unknown Attempt")
        return self._attempts[ref]

    def _pump(self, attempt: _Attempt):
        if self._terminal(attempt):
            return
        try:
            messages = attempt.transport.poll()
            if len(messages) > MAX_POLL:
                raise NativeError("poll limit exceeded")
            for message in messages:
                if self._terminal(attempt):
                    break
                self._message(attempt, message)
            if not self._terminal(attempt):
                if any(deadline <= self._clock() for _, deadline in attempt.pending.values()):
                    self._fail(attempt, "native_rpc_timeout")
                elif not attempt.transport.alive():
                    self._fail(attempt, "native_transport_lost")
        except Exception:
            self._fail(attempt, "adapter_protocol_error")

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

    def _message(self, attempt: _Attempt, message: dict):
        if not isinstance(message, dict):
            raise NativeError("invalid message")
        if "method" not in message:
            rpc_id = message.get("id")
            if not isinstance(rpc_id, str) or rpc_id not in attempt.pending:
                raise NativeError("uncorrelated response")
            method, _ = attempt.pending.pop(rpc_id)
            if "error" in message:
                if method == "turn/interrupt":
                    return  # Rejection is not cessation; stay observable.
                self._fail(attempt, "native_rpc_error")
                return
            result = message.get("result")
            if not isinstance(result, dict):
                raise NativeError("invalid result")
            self._reply(attempt, method, result)
            return
        method, params = message["method"], message.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            raise NativeError("invalid notification")
        if "id" in message:
            self._callback(attempt, message)
        elif method in {"turn/started", "turn/completed"}:
            if params.get("threadId") != attempt.thread or not attempt.turn_sent:
                raise NativeError("turn notification identity mismatch")
            self._turn(attempt, params.get("turn"), completed=method == "turn/completed")
        elif method == "serverRequest/resolved":
            if params.get("threadId") != attempt.thread:
                raise NativeError("callback resolution identity mismatch")
            rpc_id = params.get("requestId")
            callback = attempt.callbacks.get((type(rpc_id), rpc_id))
            if callback is None:
                raise NativeError("unknown resolved callback")
            callback.resolved = True
            self._refresh_running(attempt)
        # Output/item notifications are not pre-execution interception evidence.
        # Unknown requests are handled below, never treated as informational.

    def _reply(self, attempt: _Attempt, method: str, result: dict):
        c = attempt.request.conditions
        if method == "initialize":
            if not isinstance(result.get("userAgent"), str):
                raise NativeError("invalid initialize response")
            attempt.transport.send({"method": "initialized"})
            params = {
                "model": c.model, "modelProvider": "openai", "cwd": c.workspace,
                "sandbox": "read-only", "approvalPolicy": "on-request",
                "approvalsReviewer": "user", "ephemeral": True,
            }
            if self._profile is not None:
                del params["sandbox"]
                params.update(permissions=self._profile, environments=[])
            self._rpc(attempt, "thread/start", params)
        elif method == "thread/start":
            thread = result.get("thread", {}).get("id")
            if (not isinstance(thread, str) or not thread or result.get("model") != c.model
                    or result.get("modelProvider") != "openai" or result.get("cwd") != c.workspace
                    or result.get("approvalPolicy") != "on-request"
                    or result.get("approvalsReviewer") != "user"
                    or (self._profile is None and result.get("sandbox", {}).get("type") != "readOnly")
                    or (self._profile is not None and result.get("activePermissionProfile") not in (
                        {"id": self._profile}, {"id": self._profile, "extends": None}))
                    or (self._effort is not None and result.get("reasoningEffort") != self._effort)):
                raise NativeError("effective Native configuration mismatch")
            attempt.thread = thread
            self._verify(attempt.request, "turn", result)
            job = attempt.request.job
            text = json.dumps({"instructions": job.instructions,
                               "context": json.loads(job.context_json),
                               "acceptance_criteria": job.acceptance_criteria}, ensure_ascii=False)
            # Set before send: a lost/partial write must not permit redispatch.
            attempt.turn_sent = True
            params = {
                "threadId": thread, "input": [{"type": "text", "text": text}],
            }
            if self._profile is not None:
                params.update(permissions=self._profile, cwd=c.workspace)
            if self._effort is not None:
                params["effort"] = self._effort
            self._rpc(attempt, "turn/start", params)
        elif method == "turn/start":
            self._turn(attempt, result.get("turn"), completed=False)
        elif method == "turn/interrupt":
            attempt.interrupt_ack = True
        else:
            raise NativeError("unmapped RPC response")

    def _turn(self, attempt: _Attempt, turn: dict, *, completed: bool):
        if not isinstance(turn, dict) or not isinstance(turn.get("id"), str) or not turn["id"]:
            raise NativeError("invalid turn")
        if attempt.turn is not None and attempt.turn != turn["id"]:
            raise NativeError("turn identity mismatch")
        attempt.turn = turn["id"]
        status = turn.get("status")
        if status == "inProgress" and not completed:
            self._refresh_running(attempt)
            if attempt.stopped:
                self._interrupt(attempt)
        elif status in {"completed", "failed", "interrupted"} and completed:
            # This proves only a Native turn ended, not child-process cessation.
            state, reason = {
                "completed": (State.COMPLETED, None),
                "failed": (State.ERROR, "native_turn_failed"),
                "interrupted": (State.FAILED, "native_turn_interrupted"),
            }[status]
            self._finish(attempt, state, reason)
        elif status not in {"completed", "failed", "interrupted"}:
            raise NativeError("unknown turn state")
        # A terminal start receipt alone waits for turn/completed evidence.

    def _callback(self, attempt: _Attempt, message: dict):
        rpc_id, method, params = message["id"], message["method"], message["params"]
        if type(rpc_id) not in (int, str) or (isinstance(rpc_id, str) and not rpc_id):
            raise NativeError("invalid callback ID")
        if (params.get("threadId") != attempt.thread or not attempt.turn_sent
                or not isinstance(params.get("turnId"), str) or not params["turnId"]):
            raise NativeError("callback identity mismatch")
        if attempt.turn is None:
            attempt.turn = params["turnId"]
        elif attempt.turn != params["turnId"]:
            raise NativeError("callback turn mismatch")
        key = (type(rpc_id), rpc_id)
        if key in attempt.callbacks:
            if attempt.callbacks[key].message != message:
                raise NativeError("callback ID reused with changed target")
            return
        if method not in {COMMAND_APPROVAL, FILE_APPROVAL}:
            attempt.transport.send({"id": rpc_id, "error": {
                "code": -32601, "message": "unsupported Native request"}})
            self._fail(attempt, "native_request_unsupported")
            return
        if not isinstance(params.get("itemId"), str) or not params["itemId"]:
            raise NativeError("missing callback item")
        confirmation = codex_confirmation(attempt.request.ref, self._id(), method, params)
        if method == FILE_APPROVAL:
            confirmation = replace(confirmation, can_respond=True,
                                   reason="Native file approval lacks complete effect/content; deny/cancel only")
        attempt.callbacks[key] = _Callback(rpc_id, message, confirmation)
        attempt.events.append(ConfirmationEvent(attempt.request.ref, self._id(), confirmation))
        self._status(attempt, State.WAITING_HUMAN)
        if attempt.stopped:
            self._interrupt(attempt)

    def _refresh_running(self, attempt: _Attempt):
        waiting = any(not cb.resolved for cb in attempt.callbacks.values())
        self._status(attempt, State.WAITING_HUMAN if waiting else State.RUNNING)

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
            return OperationReply(ref, OperationStatus.UNSUPPORTED, "allow mapping unverified")
        # Record before send: ambiguous writes must never be retried.
        callback.response = response
        try:
            attempt.transport.send({"id": callback.rpc_id, "result": {
                "decision": "decline" if response.resolution == Resolution.DENY else "cancel"}})
        except Exception:
            callback.delivery_unknown = True
            self._fail(attempt, "adapter_response_delivery_unknown")
            return OperationReply(ref, OperationStatus.ERROR, "response delivery unknown; do not retry")
        return OperationReply(ref, OperationStatus.ACCEPTED, "response queued; Native resolution unconfirmed")

    def _interrupt(self, attempt: _Attempt):
        if attempt.turn and not attempt.interrupt_sent:
            attempt.interrupt_sent = True
            self._rpc(attempt, "turn/interrupt", {"threadId": attempt.thread, "turnId": attempt.turn})

    def stop(self, ref: AttemptRef) -> StopReply:
        if ref not in self._attempts:
            return StopReply(ref, StopStatus.ERROR, "unknown Attempt")
        attempt = self._get(ref)
        # Latch before polling: stop during bootstrap must never submit a turn.
        attempt.stopped = True
        if not attempt.turn_sent and not self._terminal(attempt):
            attempt.cessation = "codex:no-turn-submitted:" + self._id()
            self._finish(attempt, State.FAILED, "stopped_before_turn")
        elif not self._terminal(attempt):
            self._pump(attempt)
            if not self._terminal(attempt):
                try:
                    self._interrupt(attempt)
                except Exception:
                    self._fail(attempt, "adapter_interrupt_delivery_unknown")
        if attempt.cessation:
            return StopReply(ref, StopStatus.CONFIRMED, "no model turn submitted", attempt.cessation)
        if attempt.interrupt_ack and not self._terminal(attempt):
            return StopReply(ref, StopStatus.REQUESTED, "Native interrupt receipt; cessation unverified")
        return StopReply(ref, StopStatus.UNCONFIRMED, "tool cessation unverified; may still be running")

    def resume(self, state: ResumeState) -> OperationReply:
        if state.adapter != ADAPTER or state.ref not in self._attempts:
            return OperationReply(state.ref, OperationStatus.INVALID_STATE, "unknown resume identity")
        attempt = self._get(state.ref)
        self._pump(attempt)
        if self._terminal(attempt) or attempt.stopped:
            return OperationReply(state.ref, OperationStatus.INVALID_STATE, "Attempt is terminal or stopping")
        return OperationReply(state.ref, OperationStatus.UNSUPPORTED,
                              "same-turn resume and protected state unverified")

    def usage(self) -> tuple[Usage, ...]:
        return ()

    def close(self) -> None:
        """Release owned transports; loss of transport is not stop confirmation."""
        for attempt in self._attempts.values():
            if not self._terminal(attempt):
                self._fail(attempt, "adapter_closed")
