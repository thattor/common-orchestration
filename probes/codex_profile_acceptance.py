"""Operator-only single exact model/effort acceptance; importing never launches Native.

Root supplies the authentic current-platform authorization verifier. This is not
a HumanGateway receipt, Controller/Catalog cycle, or generic cessation factory.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import os
import math
import re
from pathlib import Path
import shutil
import sys
import time
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from co_v4.adapters.codex import CodexAdapter, StdioTransport, NativeError
from co_v4.codex_model_selection import validate_selection
from co_v4.codex_host import CodexHostConfig, CodexReadOnlyHost, HostUnverified
from co_v4.codex_service_tier import (subscription_gate, service_tier_overrides,
    service_tier_diagnostic, verify_service_tier, select_service_tier, append_service_tier_overrides)
from co_v4.codex_permissions import disabled_remote_notification
from co_v4.codex_profile_transport import CodexProfileTransport
from co_v4.contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job, TERMINAL, ResultEvent
from co_v4.delegation import DelegatedScope
from co_v4.state import ControlStore
from probes.codex_host_preflight import configured_launch_inventory

EXPECTED = "CO03_ACCEPTANCE_OK"
MODEL, EFFORT = "gpt-6-astra", "medium"
METADATA_PATH = Path(__file__).with_name("codex_profile_metadata_schemas.json")
METADATA_SCHEMAS = json.loads(METADATA_PATH.read_text())["schemas"]
OBSERVATION_ERROR_CODES = frozenset(('account_metadata_limit', 'activity_after_terminal', 'delta_final_text_mismatch', 'duplicate_item_start', 'observed_envelope_unverified', 'observed_frame_limit', 'observed_item_invalid', 'observed_metadata_schema_invalid', 'observed_params_invalid', 'observed_remote_status_invalid', 'observed_remote_status_limit', 'observed_status_thread_mismatch', 'observed_text_limit', 'observed_thread_binding_mismatch', 'observed_thread_start_unbound', 'observed_turn_identity_mismatch', 'observed_warning_invalid', 'observed_warning_limit', 'one_turn_limit', 'original_turn_rpc_unverified', 'outbound_frames_pending', 'owned_eof_missing', 'post_terminal_status_unverified', 'terminal_activity_unverified', 'terminal_completion_unverified', 'terminal_inventory_mismatch', 'terminal_item_mismatch', 'text_job_native_request', 'text_job_tool_or_unknown_item', 'text_job_waiting_activity', 'unbound_item_finish', 'unbound_observed_response', 'unbound_reasoning_activity', 'unbound_text_delta', 'unmapped_native_notification', 'usage_observation_invalid'))


def schema_valid(value, schema, definitions=None, depth=0):
    """Bounded validator for the fixed local metadata subset; unknown keys deny."""
    if depth > 32: return False
    if type(schema) is bool: return schema
    definitions = schema.get("definitions", {}) if definitions is None else definitions
    if "$ref" in schema:
        ref = schema["$ref"]
        return ref.startswith("#/definitions/") and schema_valid(value, definitions[ref.split("/")[-1]], definitions, depth + 1)
    for key, predicate in (("anyOf", any), ("allOf", all)):
        if key in schema and not predicate(schema_valid(value, s, definitions, depth + 1) for s in schema[key]): return False
    if "oneOf" in schema and sum(schema_valid(value, s, definitions, depth + 1) for s in schema["oneOf"]) != 1: return False
    if "enum" in schema and value not in schema["enum"]: return False
    if "const" in schema and value != schema["const"]: return False
    types = schema.get("type")
    types = [types] if type(types) is str else types
    matches = {"null": value is None, "string": type(value) is str, "integer": type(value) is int,
        "number": type(value) in (int, float) and math.isfinite(value), "boolean": type(value) is bool,
        "object": type(value) is dict, "array": type(value) is list}
    if types and not any(matches[t] for t in types): return False
    if type(value) is dict and (schema.get("type") == "object" or "properties" in schema):
        props = schema.get("properties", {})
        if not set(schema.get("required", ())) <= set(value): return False
        for key, item in value.items():
            spec = props.get(key, schema.get("additionalProperties", False))
            if not schema_valid(item, spec, definitions, depth + 1): return False
    if type(value) is list:
        if not schema.get("minItems", 0) <= len(value) <= min(schema.get("maxItems", 256), 256): return False
        if "items" in schema and not all(schema_valid(v, schema["items"], definitions, depth + 1) for v in value): return False
    if type(value) is str:
        try:
            if len(value.encode()) > 65536 or not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 65536): return False
        except UnicodeEncodeError: return False
        if "pattern" in schema and re.search(schema["pattern"], value) is None: return False
    if type(value) in (int, float) and not schema.get("minimum", -math.inf) <= value <= schema.get("maximum", math.inf): return False
    return True



def result_projection(events, ref):
    """Status alone is not a Result; preserve a single exact-attempt event."""
    results = [event for event in events if isinstance(event, ResultEvent)]
    if (len(results) != 1 or results[0].ref != ref or results[0].result.ref != ref
            or type(results[0].event_id) is not str or not results[0].event_id):
        return None
    event = results[0]
    return {"event_id": event.event_id, "run_id": ref.run_id, "job_id": ref.job_id,
            "attempt_id": ref.attempt_id, "state": event.result.status.value,
            "reason": event.result.reason}


def auth_metadata(path):
    """Metadata only: never open, hash or retain authentication file contents."""
    try:
        value = path.lstat()
    except OSError:
        return None
    return {name: getattr(value, "st_" + name) for name in
            ("dev", "ino", "mode", "uid", "gid", "size", "mtime_ns", "ctime_ns")}


def acceptance_passed(report):
    # Historical Astra receipts did not record a requested tier. Preserve them;
    # new explicit fast claims require all retained positive Native observations.
    if report.get("requested_service_tier") == "fast":
        tier = report.get("service_tier_observation")
        if (type(tier) is not dict or tier.get("requested") != "fast"
                or tier.get("effective_config") != "fast" or tier.get("original_thread_response") != "priority"
                or tier.get("matched_before_turn") is not True
                or tier.get("fast_configuration_verified") is not True):
            return False
    if report.get("requested_service_tier") == "normal":
        tier = report.get("service_tier_observation")
        if (type(tier) is not dict or tier.get("requested") != "normal"
                or tier.get("effective_config") != "default"
                or "original_thread_response" not in tier or tier["original_thread_response"] not in (None, "default")
                or tier.get("effective_fast_mode") is not False
                or tier.get("matched_before_turn") is not True):
            return False
    return bool(report.get("subscription_precondition")
        and report.get("adapter_result", {}).get("state") == "completed"
        and (report.get("native") or {}).get("scoped_completion_evidence_complete") is True
        and report.get("source_verified_after_cleanup") is True
        and report.get("control_store_unchanged") is True
        and type(report.get("workspace_entries")) is int and report["workspace_entries"] == 0)


class ObservedTransport(StdioTransport):
    """Independent bounded oracle and owned stdio drain; no authority to approve."""
    def __init__(self, *args, expected_effort=EFFORT, **kwargs):
        self.expected_effort = expected_effort
        super().__init__(*args, **kwargs)
        self.rpc = {}
        self.thread = self.turn = None
        self.thread_request_id = None
        self.thread_id = None
        self.warning_thread_candidate = None
        self.thread_notification_candidate = None
        self.status_thread_candidate = None
        self.informational_warnings = 0
        self.remote_status_count = 0
        self.account_notifications = 0
        self.turn_submissions = 0
        self.turn_rpc_confirmed = False
        self.started = set()
        self.item_types = {}
        self.finished = set()
        self.deltas = {}
        self.texts = {}
        self.terminal = None
        self.error = None
        self.observation_failure = None
        self.terminal_inventory = None
        self.usage = None
        self.frames = 0
        self.closed_observed = False
        self.eof_validated = False
        self.wait_exit = None
        self.cleanup_terminated = False

    def send(self, message):
        method = message.get("method")
        if method == "turn/start":
            if self.turn_submissions or message.get("params", {}).get("effort") != self.expected_effort:
                raise NativeError("one_turn_limit")
            self.turn_submissions = 1
        if "id" in message and method:
            self.rpc[message["id"]] = method
        if method == "thread/start": self.thread_request_id = message["id"]
        super().send(message)

    def _bind_turn(self, thread, turn):
        if (self.turn_submissions != 1 or thread != self.thread or type(turn) is not str or not turn
                or self.turn not in (None, turn)):
            raise NativeError("observed_turn_identity_mismatch")
        self.turn = turn

    def _observe(self, message):
        self.frames += 1
        if self.frames > 1024: raise NativeError("observed_frame_limit")
        method, params = message.get("method"), message.get("params", {})
        if method is None:
            rpc = self.rpc.pop(message.get("id"), None)
            if rpc is None: raise NativeError("unbound_observed_response")
            result = message.get("result", {})
            if rpc == "thread/start" and type(result) is dict:
                self.thread = result.get("thread", {}).get("id")
                if (type(self.thread) is not str or not self.thread
                        or self.warning_thread_candidate not in (None, self.thread)
                        or self.status_thread_candidate not in (None, self.thread)
                        or self.thread_notification_candidate not in (None, self.thread)):
                    raise NativeError("observed_thread_binding_mismatch")
                self.thread_id = self.thread
            if rpc == "turn/start" and type(result) is dict:
                self._bind_turn(self.thread, result.get("turn", {}).get("id"))
                if "error" in message or result.get("turn", {}).get("status") not in {"inProgress", "completed"}:
                    raise NativeError("original_turn_rpc_unverified")
                self.turn_rpc_confirmed = True
            return
        if "id" in message:
            raise NativeError("text_job_native_request")
        if type(params) is not dict: raise NativeError("observed_params_invalid")
        if (set(message) - {"method", "params", "jsonrpc", "emittedAtMs"}
                or ("jsonrpc" in message and message["jsonrpc"] != "2.0")
                or ("emittedAtMs" in message and (type(message["emittedAtMs"]) is not int
                    or not -(2 ** 63) <= message["emittedAtMs"] < 2 ** 63))):
            raise NativeError("observed_envelope_unverified")
        active = {"turn/started", "turn/completed", "item/started", "item/completed",
                  "item/agentMessage/delta", "thread/tokenUsage/updated"}
        if method not in active | set(METADATA_SCHEMAS) | {"warning", "remoteControl/status/changed"}:
            raise NativeError("unmapped_native_notification")
        if method == "remoteControl/status/changed":
            if not disabled_remote_notification(message): raise NativeError("observed_remote_status_invalid")
            self.remote_status_count += 1
            if self.remote_status_count > 8: raise NativeError("observed_remote_status_limit")
            return
        if method == "warning":
            if not CodexProfileTransport._pending_warning(self, message): raise NativeError("observed_warning_invalid")
            self.informational_warnings += 1
            if self.informational_warnings > 8: raise NativeError("observed_warning_limit")
            return
        if method in METADATA_SCHEMAS and not schema_valid(params, METADATA_SCHEMAS[method]):
            raise NativeError("observed_metadata_schema_invalid")
        if method == "account/updated":
            self.account_notifications += 1
            if self.account_notifications > 8: raise NativeError("account_metadata_limit")
        if method == "thread/started":
            identity = params["thread"]["id"]
            if (self.turn_submissions or self.thread_request_id is None or self.thread_notification_candidate is not None
                    or self.thread not in (None, identity)):
                raise NativeError("observed_thread_start_unbound")
            self.thread_notification_candidate = identity
        if method.startswith("item/reasoning/"):
            self._bind_turn(params["threadId"], params["turnId"])
            if (self.terminal is not None or self.item_types.get(params["itemId"]) != "reasoning"
                    or params["itemId"] in self.finished): raise NativeError("unbound_reasoning_activity")
        if method == "thread/status/changed":
            expected = self.thread or self.status_thread_candidate
            if ((self.thread is None and self.thread_request_id is None)
                    or (expected is not None and params["threadId"] != expected)):
                raise NativeError("observed_status_thread_mismatch")
            self.status_thread_candidate = params["threadId"]
            if params["status"]["type"] == "active" and params["status"]["activeFlags"]:
                raise NativeError("text_job_waiting_activity")
        if method == "turn/started" and self.terminal is not None:
            raise NativeError("activity_after_terminal")
        if method == "thread/status/changed" and self.terminal is not None:
            if params.get("threadId") != self.thread or params.get("status", {}).get("type") != "idle":
                raise NativeError("post_terminal_status_unverified")
        if method in {"turn/started", "turn/completed", "item/started", "item/completed", "item/agentMessage/delta", "thread/tokenUsage/updated"}:
            turn = params.get("turn", {}).get("id") if method.startswith("turn/") else params.get("turnId")
            self._bind_turn(params.get("threadId"), turn)
        if method in {"item/started", "item/completed"}:
            if self.terminal is not None: raise NativeError("activity_after_terminal")
            item = params.get("item")
            if type(item) is not dict or item.get("type") not in {"agentMessage", "reasoning", "userMessage"}:
                raise NativeError("text_job_tool_or_unknown_item")
            key = item.get("id")
            if type(key) is not str or not key or len(self.started) > 32:
                raise NativeError("observed_item_invalid")
            if method == "item/started":
                if key in self.started: raise NativeError("duplicate_item_start")
                self.started.add(key)
                self.item_types[key] = item["type"]
            else:
                if (key not in self.started or key in self.finished
                        or self.item_types[key] != item["type"]): raise NativeError("unbound_item_finish")
                self.finished.add(key)
                if item["type"] == "agentMessage":
                    value = item.get("text")
                    if type(value) is not str or len(value.encode()) > 2048:
                        raise NativeError("observed_text_limit")
                    if key in self.deltas and self.deltas[key] != value:
                        raise NativeError("delta_final_text_mismatch")
                    self.texts[key] = value
        if method == "item/agentMessage/delta":
            key, delta = params.get("itemId"), params.get("delta")
            if (self.terminal is not None or key not in self.started or key in self.finished
                    or self.item_types[key] != "agentMessage"
                    or type(delta) is not str): raise NativeError("unbound_text_delta")
            value = self.deltas.get(key, "") + delta
            if len(value.encode()) > 2048: raise NativeError("observed_text_limit")
            self.deltas[key] = value
        if method == "turn/completed":
            turn = params.get("turn")
            if (self.terminal is not None or turn.get("status") != "completed" or turn.get("error") is not None
                    or self.started != self.finished):
                raise NativeError("terminal_completion_unverified")
            if any(type(item) is not dict or item.get("type") not in {"agentMessage", "reasoning", "userMessage"}
                   for item in turn.get("items", [])):
                raise NativeError("terminal_activity_unverified")
            terminal_items = turn.get("items", [])
            view = turn.get("itemsView", "full")
            identities = [item["id"] for item in terminal_items]
            types = ("userMessage", "reasoning", "agentMessage")
            self.terminal_inventory = {
                "view": view, "terminal_count": len(terminal_items), "completed_count": len(self.finished),
                "terminal_types": {kind: sum(item["type"] == kind for item in terminal_items) for kind in types},
                "completed_types": {kind: sum(self.item_types[key] == kind for key in self.finished) for kind in types},
                "matched_id_count": sum(key in self.finished for key in identities),
                "unique_ids": len(set(identities)) == len(identities),
                "agent_texts_match_observed": all(item["id"] in self.texts and self.texts[item["id"]] == item["text"]
                    for item in terminal_items if item["type"] == "agentMessage")}
            if view == "notLoaded":
                if terminal_items: raise NativeError("terminal_inventory_mismatch")
            elif view == "summary":
                # Fixed Native producer emits only last_agent_message, not all
                # completed user/reasoning items. This one-response route still
                # requires that exact observed assistant item, never any subset.
                if (len(terminal_items) != 1 or terminal_items[0]["type"] != "agentMessage"
                        or len(self.texts) != 1 or set(identities) != set(self.texts)):
                    raise NativeError("terminal_inventory_mismatch")
            elif view != "full" or len(set(identities)) != len(identities) or set(identities) != self.finished:
                raise NativeError("terminal_inventory_mismatch")
            for item in terminal_items:
                key = item["id"]
                if (key not in self.finished or self.item_types[key] != item["type"] or
                        (item["type"] == "agentMessage" and item["text"] != self.texts.get(key))):
                    raise NativeError("terminal_item_mismatch")
            self.terminal = "completed"
        if method == "thread/tokenUsage/updated":
            usage = params.get("tokenUsage", {}).get("last")
            keys = {"cachedInputTokens", "inputTokens", "outputTokens", "reasoningOutputTokens", "totalTokens"}
            if (type(usage) is not dict or not keys <= set(usage)
                    or any(type(usage[k]) is not int or usage[k] < 0 for k in keys)):
                raise NativeError("usage_observation_invalid")
            self.usage = {k: usage[k] for k in sorted(keys)}

    def poll(self):
        message = None
        try:
            messages = super().poll()
            for message in messages: self._observe(message)
        except Exception as exc:
            if self.observation_failure is None:
                method = message.get("method") if type(message) is dict else None
                known = type(method) is str and method in set(METADATA_SCHEMAS) | {"warning", "remoteControl/status/changed"}
                params = message.get("params") if type(message) is dict else None
                keys = set(METADATA_SCHEMAS.get(method, {}).get("properties", {})) if known else set()
                if method == "warning": keys = {"message", "threadId"}
                if method == "remoteControl/status/changed": keys = {"status", "installationId", "serverName", "environmentId"}
                code = str(exc) if type(exc) is NativeError else None
                self.observation_failure = {
                    "phase": "drain" if self.closed_observed else "poll",
                    "category": code if code in OBSERVATION_ERROR_CODES else (
                        "stream_decode_unverified" if message is None else "observer_internal_error"),
                    "method": method if known else "unmapped" if method is not None else "response_or_stream",
                    "frame_index": self.frames,
                    "has_request_id": type(message) is dict and "id" in message and method is not None,
                    "known_parameter_keys": sorted(keys.intersection(params)) if type(params) is dict else [],
                    "unknown_parameter_keys_present": bool(set(params) - keys) if type(params) is dict else False,
                    "terminal_already_observed": self.terminal is not None,
                    "completed_items": len(self.finished)}
            self.error = "independent_native_observation_failed"
            raise
        return messages

    def close(self):
        if self.closed_observed: return
        self.closed_observed = True
        try:
            self._flush()
            if self._outgoing: raise NativeError("outbound_frames_pending")
            self._process.stdin.close()
            end = time.monotonic() + 5
            while time.monotonic() < end and not self._eof:
                self.poll()
                time.sleep(.01)
            if not self._eof: raise NativeError("owned_eof_missing")
            self.wait_exit = self._process.wait(timeout=1)
            self.eof_validated = not self._incoming and self.error is None
        except Exception:
            self.error = self.error or "owned_drain_unconfirmed"
        finally:
            if self._process.poll() is None:
                self.cleanup_terminated = True
                self._process.terminate()
                try: self._process.wait(timeout=1)
                except Exception:
                    self._process.kill(); self._process.wait(timeout=1)
            self.wait_exit = self._process.poll()
            for stream in (self._process.stdin, self._process.stdout):
                if not stream.closed: stream.close()

    def evidence(self):
        text = "".join(self.texts.values())
        ac = len(self.texts) == 1 and text == EXPECTED and self.error is None
        return {"turn_submissions": self.turn_submissions, "native_terminal": self.terminal,
            "original_turn_rpc_confirmed": self.turn_rpc_confirmed,
            "observed_sha256": hashlib.sha256(text.encode()).hexdigest(), "observed_utf8_bytes": len(text.encode()),
            "independent_response_ac_passed": ac, "unfinished_items": len(self.started - self.finished),
            "validated_eof": self.eof_validated, "owned_wait_exit": self.wait_exit,
            "cleanup_terminated": self.cleanup_terminated, "observation_error": self.error,
            "observation_failure": self.observation_failure,
            "terminal_inventory": self.terminal_inventory,
            "native_token_usage": self.usage, "additional_currency_cost": None,
            "account_updated_informational_notifications": self.account_notifications,
            "scoped_completion_evidence_complete": bool(ac and self.turn_rpc_confirmed and self.terminal == "completed" and self.eof_validated
                and self.wait_exit == 0 and not self.cleanup_terminated and self.started == self.finished),
            "generic_cessation_capability_granted": False}



def qualification_request(root: Path, attempt_id: str, *, model: str = MODEL, effort: str | None = EFFORT, service_tier: str = "default", mode: str | None = None):
    """Bind the selected exact model before authorization or any Native IO."""
    validate_selection(model, effort)
    if type(attempt_id) is not str or re.fullmatch("[0-9a-f]{32}", attempt_id) is None:
        raise HostUnverified("qualification_attempt_invalid")
    service_tier = select_service_tier(mode, service_tier)
    control_refs = ("current-platform-authorization", "reasoning-effort:" + (effort if effort is not None else "inherit")) + (("service-tier:" + service_tier,) if service_tier != "default" else ())
    ref = AttemptRef("platform-authorized-" + {MODEL: "astra", "gpt-6-sol": "sol"}.get(model, model),
                     "fixed-text", attempt_id)
    conditions = ExecutionConditions(model, "codex.app-server", str(root / "worker"),
        "candidate:codex-profile:" + ref.attempt_id, control_refs)
    return ExecuteRequest(ref, Job(ref.run_id, ref.job_id,
        "Use no tools. Output exactly CO03_ACCEPTANCE_OK with no additional text or whitespace.",
        ("response bytes equal CO03_ACCEPTANCE_OK",)), conditions)


def run(root: Path, *, authorization_ref: str, authorize, source_manifest: dict[str, str],
        model: str = MODEL, effort: str | None = EFFORT, service_tier: str = "default", mode: str | None = None):
    """Root calls once with its current platform source, never a fabricated receipt."""
    validate_selection(model, effort)
    service_tier = select_service_tier(mode, service_tier)
    tier_overrides = service_tier_overrides(service_tier)
    base = Path(__file__).resolve().parents[1]
    def check_source():
        if not source_manifest: raise HostUnverified("source_manifest_required")
        if str(METADATA_PATH.relative_to(base)) not in source_manifest:
            raise HostUnverified("metadata_schema_manifest_required")
        for name, digest in source_manifest.items():
            path = base / name
            if not path.resolve().is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise HostUnverified("source_manifest_mismatch")
        for name, module in tuple(sys.modules.items()):
            if not (name == "co_v4" or name.startswith("co_v4.") or name.startswith("probes.")):
                continue
            filename = getattr(module, "__file__", None)
            if filename is None:
                if name != "co_v4.adapters" or tuple(getattr(module, "__path__", ())) != (str(base / "co_v4/adapters"),):
                    raise HostUnverified("import_source_unverified")
                continue
            path = Path(filename).resolve()
            if not path.is_relative_to(base) or str(path.relative_to(base)) not in source_manifest:
                raise HostUnverified("import_source_unverified")
    check_source()
    if type(authorization_ref) is not str or not authorization_ref: raise HostUnverified("platform_authorization_required")
    root.mkdir(mode=0o700)  # exclusive: no resume or retry from an old claim
    root = root.resolve()
    workspace, control = root / "worker", root / "control"
    workspace.mkdir(mode=0o700); control.mkdir(mode=0o700)
    state = control / "control.db"
    def refuse(*args): raise RuntimeError("Human ingress is not part of this harness")
    store = ControlStore(state, verifier=refuse, evidence=refuse); store.close()
    state_before = hashlib.sha256(state.read_bytes()).hexdigest()
    request = qualification_request(root, uuid4().hex, model=model, effort=effort, service_tier=service_tier)
    ref, conditions = request.ref, request.conditions
    if authorize(request, authorization_ref) is not True: raise HostUnverified("platform_authorization_unverified")
    claim_fd = os.open(control / "launch-claimed.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(claim_fd, "w") as stream:
        json.dump({"attempt_id": ref.attempt_id, "authorization_ref": authorization_ref,
                   "model": model, "effort": effort, "service_tier": service_tier, "one_turn_only": True}, stream)
        stream.flush(); os.fsync(stream.fileno())
    exe, credential = Path(shutil.which("codex")).resolve(), (Path.home() / ".codex/auth.json").resolve(strict=True)
    auth_before = auth_metadata(credential)
    mcp, keys = configured_launch_inventory(exe, workspace)
    host = CodexReadOnlyHost(CodexHostConfig(conditions, exe, Path(sys.executable).resolve(),
        (state,), (credential,), DelegatedScope(authorization_ref, ref, str(workspace)),
        disabled_mcp_servers=mcp, cleared_environment_keys=keys, use_named_permissions=True, reasoning_effort=effort,
        mode=service_tier if mode is not None else None))
    report = {"started_at": datetime.now(timezone.utc).isoformat(), "model": model, "effort": effort,
              "requested_service_tier": service_tier, "mode": service_tier if mode is not None else None,
              "human_gateway_exercised": False, "controller_exercised": False, "catalog_promoted": False,
              "authorization_source": "current platform delegation", "status": "not_started"}
    observed = []
    # Patch only the trusted host's owned transport factory for this invocation.
    # The product adapter/host/profile/delegation gates all remain active.
    import co_v4.codex_host as host_module
    original_transport = host_module.StdioTransport
    def factory(*args, **kwargs):
        env = kwargs.get("env")
        report["native_api_environment_absent"] = type(env) is dict and not any(
            key in env for key in ("OPENAI_API_KEY", "OPENAI_ADMIN_KEY", "CODEX_API_KEY", "AZURE_OPENAI_API_KEY"))
        original_overrides = kwargs.get("config_overrides", ())
        if mode is None:
            kwargs["config_overrides"] = append_service_tier_overrides(original_overrides, service_tier)
        elif original_overrides[-len(tier_overrides):] != tier_overrides:
            raise HostUnverified("qualification_service_tier_override_conflict")
        report["sent_service_tier_overrides"] = list(tier_overrides)
        wire = ObservedTransport(*args, expected_effort=effort, **kwargs); observed.append(wire); return wire
    def verify(req, phase, native):
        host.verify(req, phase, native)
        if phase == "turn":
            try:
                if mode is not None:
                    report["subscription_precondition"] = host.observation["subscription_precondition"]
                    report["service_tier_observation"] = host.observation["service_tier_observation"]
                    check_source()
                    return
                account = host._rpc("account/read", {"refreshToken": False})
                usage = host._rpc("account/rateLimits/read", {})
                report["subscription_precondition"] = subscription_gate(account, usage,
                    api_environment_absent=report.get("native_api_environment_absent") is True)
                effective = host._rpc("config/read", {"cwd": str(workspace), "includeLayers": False})["config"]
                report["service_tier_diagnostic"] = service_tier_diagnostic(effective, native)
                report["service_tier_observation"] = verify_service_tier(service_tier, effective, native)
                check_source()
            except Exception as exc:
                host._admitted = False
                report["pre_model_rejection"] = str(exc) if isinstance(exc, HostUnverified) else "subscription_preflight_unavailable"
                raise
    adapter = CodexAdapter(verify_host=verify, transport_factory=host.transport,
        permission_profile=host._profile_name, reasoning_effort=effort, rpc_timeout=30)
    try:
        host_module.StdioTransport = factory
        reply = adapter.execute(request)
        report["execute_reply"] = reply.status.value
        end = time.monotonic() + 120
        while reply.status.value == "accepted" and time.monotonic() < end:
            if adapter.status(ref).state in TERMINAL: break
            time.sleep(.02)
        if reply.status.value == "accepted":
            report["adapter_result_state"] = adapter.status(ref).state.value
            result = result_projection(adapter.events(ref), ref)
            if result is not None: report["adapter_result"] = result
        report["status"] = "observed"
    except Exception:
        report["status"] = "acceptance_unconfirmed"
    finally:
        try:
            adapter.close()
        finally:
            host_module.StdioTransport = original_transport
        try:
            check_source()
            report["source_verified_after_cleanup"] = True
        except Exception:
            report["source_verified_after_cleanup"] = False
            report["status"] = "acceptance_unconfirmed"
        report["host_observation"] = host.observation
        report["native"] = observed[0].evidence() if len(observed) == 1 else None
        native_evidence = report["native"] or {}
        report["independent_ac"] = {
            "run_id": ref.run_id, "job_id": ref.job_id, "attempt_id": ref.attempt_id,
            "criterion": "exact fixed-response UTF-8 bytes from bounded Native agent message",
            "expected_sha256": hashlib.sha256(EXPECTED.encode()).hexdigest(),
            "observed_sha256": native_evidence.get("observed_sha256"),
            "status": ("passed" if native_evidence.get("independent_response_ac_passed") is True else
                       "failed" if native_evidence.get("turn_submissions") == 1 else "unconfirmed")}
        try:
            report["control_store_unchanged"] = hashlib.sha256(state.read_bytes()).hexdigest() == state_before
            report["workspace_entries"] = len(list(workspace.iterdir()))
        except OSError:
            report["control_store_unchanged"] = False
            report["workspace_entries"] = None
        auth_after = auth_metadata(credential)
        report["authentication_metadata"] = {"before": auth_before, "after": auth_after,
            "status": ("unavailable" if auth_before is None or auth_after is None else
                       "unchanged" if auth_before == auth_after else "changed"),
            "contents_read": False, "contents_unchanged_claimed": False,
            "scope": "metadata observation only; change does not establish its cause"}
        report["acceptance_passed"] = acceptance_passed(report)
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        fd = os.open(control / "evidence.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream: json.dump(report, stream, indent=2); stream.write("\n")
    return report
