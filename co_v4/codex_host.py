"""Bounded, launch-bound preflight for a configured Codex read-only environment.

This is trusted host composition, never configuration accepted from a Worker.
The probe is host-authored Python executed by command/exec in the *same* private
app-server as the Attempt, before its first model turn. An unavailable sandbox,
credential reachability, ambiguous result, or changed binding refuses the turn.
No observation from a model and no persisted report can authorize a launch.

The measured scope is local read-only commands with network disabled. The 0.3
guarantee binds instructions, context and invocation at Native handoff; arbitrary
Native in-process tool containment is not claimed. This does not grant approve,
confirmed cessation, Resume, or connector support.
External tools/hooks/plugins are disabled for this private launch and their
effective config is checked before the probe. Trusted composition still owns
credential inventory and must never expose CO handles to Worker code.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import time
from uuid import uuid4

from .adapters.codex import CodexAdapter, StdioTransport
from .codex_errors import HostUnverified
from .codex_model_selection import validate_selection, verify_selection
from .codex_service_tier import (select_service_tier, verify_service_tier,
    subscription_gate, append_service_tier_overrides)
from .contracts import ExecuteRequest, ExecutionConditions
from .delegation import DelegatedScope, DelegatedTransport
from .codex_permissions import ProfileError, profile_definition, profile_overrides, validate_profile_config
from .codex_profile_transport import CodexProfileTransport


DISABLED_FEATURES = ("apps", "plugins", "hooks", "memories", "multi_agent",
                     "remote_plugin", "skill_mcp_dependency_install")
OVERRIDES = ("mcp_servers={}", "plugins={}", "hooks={}", "notify=[]",
             'web_search="disabled"', 'shell_environment_policy.inherit="none"',
             "shell_environment_policy.set={}", "shell_environment_policy.include_only=[]",
             *("features." + name + "=false" for name in DISABLED_FEATURES))

# Exact Native releases reviewed for trusted host composition. This is an
# exact allowlist, not a version range; an unknown Native build is refused.
SUPPORTED_NATIVE_VERSIONS = frozenset({"codex-cli 0.159.2", "codex-cli 0.160.1"})

# Opt-in feature gates observed in the codex-cli 0.160.1 effective config
# readback. They are sent and verified only for an explicitly configured
# 0.160.1 named-permission launch; the legacy composition keeps
# DISABLED_FEATURES/OVERRIDES unchanged. This is a denial readback, not
# containment proof for Native in-process tools, and no plan, question or
# applyPatch control is claimed verified by it.
FEATURES_01601 = (
    "apps", "auth_elicitation", "browser_use", "browser_use_external",
    "browser_use_full_cdp_access", "chronicle", "code_mode", "code_mode_host",
    "code_mode_only", "code_mode_prewarm", "computer_use", "daemon_auto_start",
    "default_mode_request_user_input", "enable_mcp_apps", "goals",
    "guardian_conversation_history_tools", "hooks", "image_generation",
    "memories", "multi_agent", "multi_agent_v2", "plugins",
    "realtime_conversation", "remote_control", "remote_plugin",
    "request_permissions_tool", "shell_snapshot", "shell_snapshot_v2",
    "shell_tool", "skill_mcp_dependency_install", "skill_search",
    "sleep_tool", "tool_suggest", "unified_exec", "view_image",
    "workspace_dependencies")

# Diagnostic names only, from the fixed 0.159.2 ServerNotification schema.
# This map does not admit any notification or retain parameter values.
_DIAGNOSTIC_NOTIFICATION_KEYS = {
    "thread/status/changed": frozenset({"status", "threadId"}),
    "thread/started": frozenset({"thread"}),
    "account/updated": frozenset({"authMode", "planType"}),
    "account/rateLimits/updated": frozenset({"rateLimits"}),
    "remoteControl/status/changed": frozenset({"environmentId", "installationId", "serverName", "status"}),
    "mcpServer/startupStatus/updated": frozenset({"error", "failureReason", "name", "status", "threadId"}),
    "warning": frozenset({"message", "threadId"}),
    "configWarning": frozenset({"details", "path", "range", "summary"}),
    "error": frozenset({"error", "threadId", "turnId", "willRetry"}),
}


def _event_diagnostic(message):
    if type(message) is not dict:
        return {"method": "unmapped", "message_object": False}
    method = message.get("method")
    known = type(method) is str and method in _DIAGNOSTIC_NOTIFICATION_KEYS
    keys = _DIAGNOSTIC_NOTIFICATION_KEYS[method] if known else frozenset()
    params = message.get("params")
    return {"method": method if known else "unmapped", "message_object": True,
            "has_id": "id" in message, "params_object": type(params) is dict,
            "envelope_keys": sorted(set(message).intersection({"method", "params", "jsonrpc", "emittedAtMs", "id"})),
            "unknown_envelope_keys_present": bool(set(message) - {"method", "params", "jsonrpc", "emittedAtMs", "id"}),
            "parameter_keys": sorted(keys.intersection(params)) if type(params) is dict else [],
            "unknown_parameter_keys_present": bool(set(params) - keys) if type(params) is dict else False}


# No contents are read, including when an open unexpectedly succeeds. Only
# probe-owned exclusive empty files are created/deleted on a failed boundary.
# -I -S prevents Python startup imports from the workspace/user site.
PROBE = r'''
import errno, json, os, socket, sys
c = json.loads(sys.argv[1])
def opening(path, flags):
    try:
        fd = os.open(path, flags | os.O_NOFOLLOW)
    except OSError as e:
        return "denied" if e.errno in (errno.EACCES, errno.EPERM, errno.EROFS) else "unknown"
    os.close(fd)
    return "reachable"
def create(path):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        return "denied" if e.errno in (errno.EACCES, errno.EPERM, errno.EROFS) else "unknown"
    os.close(fd)
    os.unlink(path)
    return "reachable"
def network(family, address):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(.25)
            s.connect(address)
        return "reachable"
    except OSError as e:
        # Refused/timeout/unreachable is not a policy-denial observation.
        return "denied" if e.errno in (errno.EACCES, errno.EPERM) else "unknown"
print(json.dumps({"nonce": c["nonce"], "uid": os.getuid(), "euid": os.geteuid(),
    "cwd": os.getcwd(), "workspace_read": opening(c["workspace"], os.O_RDONLY),
    "workspace_create": create(c["workspace_create"]),
    "credential_read": [opening(p, os.O_RDONLY) for p in c["credentials"]],
    "credential_env_present": any(bool(os.environ.get(k)) for k in c["credential_env"]),
    "state_write": [opening(p, os.O_WRONLY) for p in c["state"]],
    "parent_create": [create(p) for p in c["parent_create"]],
    "network": [network(socket.AF_INET, ("127.0.0.1", 9)),
                network(socket.AF_INET6, ("::1", 9))]}))
'''


@dataclass(frozen=True)
class CodexHostConfig:
    conditions: ExecutionConditions
    executable: Path
    python: Path
    protected_state: tuple[Path, ...]
    credential_files: tuple[Path, ...]
    delegation: DelegatedScope
    # Native auth and Human-ingress credential files must both be inventoried
    # by trusted composition; an empty inventory is never considered safe.
    credential_environment: tuple[str, ...] = (
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEVIN_API_KEY", "GH_TOKEN", "GITHUB_TOKEN")
    disabled_mcp_servers: tuple[str, ...] = ()
    cleared_environment_keys: tuple[str, ...] = ()
    use_named_permissions: bool = False
    reasoning_effort: str | None = None
    mode: str | None = None
    native_version: str = "codex-cli 0.159.2"
    approval_policy: str = "on-request"
    strict_text_controls: bool = False


def _identity(path: Path):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise HostUnverified("noncanonical_target")
    s = path.stat()
    return (s.st_dev, s.st_ino, s.st_uid, s.st_mode)


class CodexReadOnlyHost:
    """Single-Attempt gate and transport factory; use make_adapter together.

    No success cache, permissive fallback, alternate transport, or detached
    report input. All checks occur for each configured actual launch. Reusing
    the host for another Attempt is refused; create a new composition instead.
    """

    def __init__(self, config: CodexHostConfig, transport_factory=None):
        if transport_factory is not None and not callable(transport_factory):
            raise HostUnverified("invalid_transport_factory")
        if (type(config.use_named_permissions) is not bool or (config.reasoning_effort is not None
                and (not config.use_named_permissions or type(config.reasoning_effort) is not str
                     or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", config.reasoning_effort)))):
            raise HostUnverified("invalid_profile_configuration")
        if (config.native_version not in SUPPORTED_NATIVE_VERSIONS
                or config.approval_policy not in ("on-request", "never")
                or type(config.strict_text_controls) is not bool
                or (config.approval_policy == "never" and not config.use_named_permissions)
                or (config.strict_text_controls and (
                    config.native_version != "codex-cli 0.160.1"
                    or not config.use_named_permissions or config.reasoning_effort is None
                    or config.approval_policy != "never"))):
            raise HostUnverified("invalid_native_configuration")
        if config.use_named_permissions:
            validate_selection(config.conditions.model, config.reasoning_effort)
        self._service_tier = select_service_tier(config.mode)
        self._factory = transport_factory
        self.config = config
        self._profile_name = "co_readonly_" + uuid4().hex if config.use_named_permissions else None
        self._request_digest = None
        self._profile_definition = None
        self._request = None
        self._transport = None
        self._native_version = None
        self._native_thread_id = None
        self._identities = None
        self._executable_hashes = None
        self._admitted = False
        self.observation = {"status": "not_run", "native_handoff_verified": False, "installed_production": False}

    def make_adapter(self):
        return CodexAdapter(verify_host=self.verify, transport_factory=self.transport,
                            permission_profile=self._profile_name,
                            reasoning_effort=self.config.reasoning_effort,
                            approval_policy=self.config.approval_policy,
                            strict_text_controls=self.config.strict_text_controls)

    def _targets(self):
        c = self.config
        state_parents = tuple(p.parent for p in c.protected_state)
        return (c.executable, c.python, Path(c.conditions.workspace),
                *c.protected_state, *state_parents, *c.credential_files)

    def _check_binding(self, request):
        c = self.config
        if self._request_digest is not None and self._digest(request) != self._request_digest:
            raise HostUnverified("request_digest_changed")
        d = c.delegation
        if (not isinstance(d, DelegatedScope) or not d.human_intent_ref
                or d.attempt != request.ref or d.workspace != c.conditions.workspace
                or d.capability != "codex.readonly.local"):
            raise HostUnverified("delegated_scope_mismatch")
        if request.conditions != c.conditions:
            raise HostUnverified("execution_conditions_mismatch")
        if (platform.system() != "Darwin" or platform.machine() != "arm64"
                or c.conditions.adapter != "codex.app-server"
                or not c.conditions.environment_ref or not c.conditions.control_evidence_refs
                or not 1 <= len(c.protected_state) <= 8
                or not 1 <= len(c.credential_files) <= 8):
            raise HostUnverified("environment_not_supported")
        root = Path(c.conditions.workspace)
        if not root.is_dir() or any(p.is_relative_to(root) for p in c.protected_state):
            raise HostUnverified("protected_state_inside_worker_workspace")
        if any(not p.is_file() for p in (*c.protected_state, *c.credential_files)):
            raise HostUnverified("required_target_missing")
        if any(not s or "=" in s for s in c.credential_environment):
            raise HostUnverified("invalid_credential_inventory")
        if (len(c.disabled_mcp_servers) > 64
                or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name)
                       for name in c.disabled_mcp_servers)):
            raise HostUnverified("unsupported_mcp_identifier")
        if (len(c.cleared_environment_keys) > 128
                or any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key)
                       for key in c.cleared_environment_keys)):
            raise HostUnverified("unsupported_environment_key")
        identities = tuple(_identity(p) for p in self._targets())
        if self._identities is not None and identities != self._identities:
            raise HostUnverified("host_target_changed")
        hashes = tuple(hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in (c.executable, c.python))
        if self._executable_hashes is not None and hashes != self._executable_hashes:
            raise HostUnverified("host_executable_changed")
        self._identities, self._executable_hashes = identities, hashes

    def _digest(self, request):
        value = {"request": asdict(request), "profile": self._profile_name,
                 "reasoning_effort": self.config.reasoning_effort,
                 "service_tier": self._service_tier,
                 "targets": [str(p) for p in self._targets()],
                 "credential_environment": self.config.credential_environment,
                 "disabled_mcp_servers": self.config.disabled_mcp_servers,
                 "cleared_environment_keys": self.config.cleared_environment_keys,
                 "delegation": asdict(self.config.delegation)}
        c = self.config
        if (c.native_version, c.approval_policy, c.strict_text_controls) != (
                "codex-cli 0.159.2", "on-request", False):
            value.update(native_version=c.native_version,
                         approval_policy=c.approval_policy,
                         strict_text_controls=c.strict_text_controls)
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()

    def _before_profile_turn(self):
        if not self._admitted or self._request is None:
            raise HostUnverified("profile_turn_not_admitted")
        self._check_binding(self._request)

    def verify(self, request: ExecuteRequest, phase: str, native: dict | None):
        try:
            c = self.config
            self._check_binding(request)
            if phase == "launch":
                if self._request is not None:
                    raise HostUnverified("host_already_used")
                self._request = request
                if self._profile_name is not None:
                    self._request_digest = self._digest(request)
                    self._profile_definition = profile_definition(c.credential_files, c.protected_state)
                self.observation = {"status": "awaiting_native_preflight",
                                    "native_handoff_verified": False, "installed_production": False}
                return
            if phase != "turn" or request != self._request or self._transport is None:
                raise HostUnverified("unbound_native_transport")
            expected = {"model": request.conditions.model, "modelProvider": "openai",
                        "cwd": request.conditions.workspace, "approvalPolicy": c.approval_policy,
                        "approvalsReviewer": "user"}
            if (not isinstance(native, dict) or any(native.get(k) != v for k, v in expected.items())
                    or (self._profile_name is None and native.get("sandbox") not in (
                        {"type": "readOnly"}, {"type": "readOnly", "networkAccess": False}))
                    or (self._profile_name is not None and (
                        self._native_version != c.native_version
                        or native.get("activePermissionProfile") not in (
                            {"id": self._profile_name}, {"id": self._profile_name, "extends": None})))
                    or (c.reasoning_effort is not None and native.get("reasoningEffort") != c.reasoning_effort)):
                raise HostUnverified("native_configuration_mismatch")
            thread = native.get("thread", {}).get("id")
            if type(thread) is not str or not thread:
                raise HostUnverified("native_thread_identity_unverified")
            self._native_thread_id = thread
            if self._profile_name is not None:
                if "reasoningEffort" not in native:
                    raise HostUnverified("native_reasoning_effort_missing")
                self.observation["model_selection"] = verify_selection(self._rpc,
                    model=request.conditions.model, effort=c.reasoning_effort,
                    effective_effort=native.get("reasoningEffort"), native_version=self._native_version,
                    request_digest=self._request_digest)
            self._probe(request, native.get("sandbox"))
            self._check_binding(request)
            if c.mode is not None:
                if self._native_version != c.native_version:
                    raise HostUnverified("mode_native_version_unsupported")
                account = self._rpc("account/read", {"refreshToken": False})
                usage = self._rpc("account/rateLimits/read", {})
                self.observation["subscription_precondition"] = subscription_gate(account, usage,
                    api_environment_absent=self._api_environment_absent)
                effective = self._rpc("config/read", {"cwd": c.conditions.workspace, "includeLayers": False})
                self.observation["service_tier_observation"] = verify_service_tier(
                    self._service_tier, effective.get("config"), native)
                self.observation["service_tier_observation"]["sent_config_overrides"] = list(
                    self._sent_service_tier_overrides)
            # 0.3 trusts Native to follow the scoped prompt. Child-process
            # sandbox measurements remain mandatory, without claiming they
            # contain Native's in-process tools.
            self._admitted = True
            self.observation.update(status="delegated_native_preflight_passed",
                                    native_handoff_verified=True,
                                    guarantee_model="native_handoff_v1")
        except (HostUnverified, ProfileError) as exc:
            self._admitted = False
            self.observation.update(status=str(exc), native_handoff_verified=False)
            raise
        except Exception:
            self._admitted = False
            self.observation.update(status="host_preflight_unavailable", native_handoff_verified=False)
            raise HostUnverified("host_preflight_unavailable") from None

    def transport(self, request):
        if request != self._request or self._transport is not None:
            raise HostUnverified("unbound_native_transport")
        self._check_binding(request)
        env = {key: os.environ[key] for key in ("HOME", "PATH", "TMPDIR", "USER", "LOGNAME", "LANG")
               if key in os.environ}
        # Native 0.156.1 merges empty tables; {} does not remove inherited MCP
        # entries. Disable each trusted identifier and check the effective map.
        overrides = OVERRIDES + tuple("mcp_servers." + name + ".enabled=false"
                                     for name in self.config.disabled_mcp_servers)
        overrides += tuple("shell_environment_policy.set." + key + '=""'
                           for key in self.config.cleared_environment_keys)
        profile_kwargs = {}
        if self._profile_name is not None:
            overrides += profile_overrides(self._profile_name, self._profile_definition)
            overrides += ("features.remote_control=false",)
            if self.config.native_version == "codex-cli 0.160.1":
                overrides += tuple("features." + name + "=false" for name in FEATURES_01601)
            if self.config.reasoning_effort is not None:
                overrides += ("model_reasoning_effort=" + json.dumps(self.config.reasoning_effort),)
            profile_kwargs["required_version"] = self.config.native_version
        if (self.config.native_version == "codex-cli 0.160.1"
                and self.config.approval_policy == "never"):
            overrides += ('approval_policy="never"', 'approvals_reviewer="user"')
        if self.config.mode is not None:
            overrides = append_service_tier_overrides(overrides, self._service_tier)
            self._sent_service_tier_overrides = overrides[-2:]
            profile_kwargs["required_version"] = self.config.native_version
        self._api_environment_absent = not any(key in env for key in (
            "OPENAI_API_KEY", "OPENAI_ADMIN_KEY", "CODEX_API_KEY", "AZURE_OPENAI_API_KEY"))
        factory = self._factory if self._factory is not None else StdioTransport
        inner = factory(str(self.config.executable), request.conditions.workspace,
                        config_overrides=overrides, env=env, **profile_kwargs)
        self._native_version = inner.native_version
        if self._profile_name is not None:
            if inner.native_version != self.config.native_version:
                inner.close()
                raise HostUnverified("profile_native_version_unsupported")
            inner = CodexProfileTransport(inner, request, self._profile_name, self.config.reasoning_effort,
                [str(self.config.python), "-I", "-S", "-c", PROBE], self._before_profile_turn)
        self._transport = DelegatedTransport(inner, request, self.config.delegation,
            admitted=lambda: self._admitted)
        return self._transport

    def _probe(self, request, policy):
        c = self.config
        effective = self._rpc("config/read", {"cwd": c.conditions.workspace, "includeLayers": False})
        config = effective.get("config", {})
        if self._profile_name is not None:
            validate_profile_config(config, self._profile_name, self._profile_definition)
            if (config.get("features", {}).get("remote_control") is not False
                    or (c.reasoning_effort is not None and config.get("model_reasoning_effort") != c.reasoning_effort)):
                raise HostUnverified("effective_profile_settings_mismatch")
            if c.native_version == "codex-cli 0.160.1":
                # Every 0.160.1 opt-in feature must read back exactly false; a
                # missing key is a refusal, never an assumption.
                features = config.get("features")
                if (not isinstance(features, dict)
                        or any(features.get(name) is not False for name in FEATURES_01601)):
                    raise HostUnverified("effective_profile_settings_mismatch")
                if (c.approval_policy == "never" and (
                        config.get("approval_policy") != "never"
                        or config.get("approvals_reviewer") != "user")):
                    raise HostUnverified("effective_profile_settings_mismatch")
                # Dynamic tool/permission controls are checked only when the
                # Native readback exposes them; absent keys add no assumption.
                for key, want in (("dynamic_tools", []),
                                  ("allow_provider_model_fallback", False),
                                  ("service_tier", "default"),
                                  ("approval_policy", c.approval_policy)):
                    if key in config and config.get(key) != want:
                        raise HostUnverified("effective_profile_settings_mismatch")
        servers = config.get("mcp_servers") if isinstance(config, dict) else None
        if (not isinstance(config, dict)
                or not isinstance(servers, (dict, type(None)))
                or any(not isinstance(entry, dict) or entry.get("enabled") is not False
                       for entry in (servers or {}).values())
                or config.get("notify") not in (None, [])
                or config.get("web_search") != "disabled"
                or any(config.get("features", {}).get(name) is not False for name in DISABLED_FEATURES)
                or config.get("shell_environment_policy", {}).get("inherit") != "none"
                or config.get("shell_environment_policy", {}).get("include_only") != []
                or not self._empty_environment(config.get("shell_environment_policy", {}).get("set"))):
            raise HostUnverified("external_tools_or_environment_unverified")
        # Dormant hooks/plugins tables may survive the merge. They confer no
        # admission: their corresponding Native feature must be exactly false,
        # and an actual MCP startup notification still fails closed below.
        nonce = uuid4().hex
        parents = tuple(dict.fromkeys(p.parent for p in c.protected_state))
        probe = {"nonce": nonce, "workspace": c.conditions.workspace,
                 "workspace_create": str(Path(c.conditions.workspace) / (".co-probe-" + nonce)),
                 "credentials": list(map(str, c.credential_files)),
                 "credential_env": c.credential_environment,
                 "state": list(map(str, c.protected_state)),
                 "parent_create": [str(p / (".co-probe-" + nonce)) for p in parents]}
        params = {
            "command": [str(c.python), "-I", "-S", "-c", PROBE, json.dumps(probe)],
            "cwd": c.conditions.workspace, "sandboxPolicy": policy,
            "timeoutMs": 5000, "outputBytesCap": 8192}
        if self._profile_name is not None:
            del params["sandboxPolicy"]
            params["permissionProfile"] = self._profile_name
        result = self._rpc("command/exec", params)
        self._validate_probe(result, c, nonce, parents)
        if self._profile_name is not None:
            self.observation.update(permission_profile=self._profile_name,
                profile_policy_sha256=hashlib.sha256(json.dumps(self._profile_definition, sort_keys=True).encode()).hexdigest(),
                request_binding_sha256=self._request_digest, reasoning_effort=c.reasoning_effort)

    def _empty_environment(self, values):
        # Native merges {} with user tables. Empty string explicitly clears a
        # known key for this process; absent/unset adds no value. Never treat a
        # nonempty string (including whitespace), unknown key or type as empty.
        if values is None:
            return True
        return (isinstance(values, dict)
                and all(key in self.config.cleared_environment_keys and value == ""
                        for key, value in values.items()))

    def _informational_warning(self, message):
        # Fixed Native notification, not an action/approval or a positive check.
        # No warning text is retained; actual config and open checks still run.
        if type(message) is not dict or message.get("method") != "warning":
            return False
        params = message.get("params")
        shape = type(params) is dict and set(params) in ({"message"}, {"message", "threadId"})
        text = params.get("message") if type(params) is dict else None
        try:
            bounded = type(text) is str and len(text.encode("utf-8")) <= 8192
        except UnicodeEncodeError:
            bounded = False
        checks = {
            "envelope_known": not bool(set(message) - {"method", "params", "jsonrpc", "emittedAtMs"}),
            "jsonrpc_known": "jsonrpc" not in message or message["jsonrpc"] == "2.0",
            "timestamp_valid": "emittedAtMs" not in message or (
                type(message["emittedAtMs"]) is int and -(2 ** 63) <= message["emittedAtMs"] < 2 ** 63),
            "parameter_shape_valid": shape,
            "message_bounded_utf8": bounded,
            "thread_binding_matches": shape and self._native_thread_id is not None
                and params.get("threadId") in (None, self._native_thread_id),
        }
        if not all(checks.values()):
            self.observation["warning_rejection_checks"] = checks
            return False
        self.observation["informational_warning_count"] = (
            self.observation.get("informational_warning_count", 0) + 1)
        return True

    def _rpc(self, method, params):
        rpc_id = "co-host-" + uuid4().hex
        self._transport.send({"id": rpc_id, "method": method, "params": params})
        end = time.monotonic() + 8
        result = None
        count = 0
        while result is None and time.monotonic() < end:
            messages = self._transport.poll()
            count += len(messages)
            if count > 128:
                raise HostUnverified("native_preflight_frame_limit")
            for message in messages:
                if message.get("id") == rpc_id and "method" not in message:
                    if result is not None or "error" in message:
                        raise HostUnverified("native_preflight_rpc_failed")
                    result = message.get("result")
                elif self._informational_warning(message):
                    continue
                elif "id" in message or message.get("method") not in {
                        "thread/started", "account/rateLimits/updated"}:
                    self.observation["unexpected_event"] = _event_diagnostic(message)
                    raise HostUnverified("unexpected_native_preflight_event")
            if result is None:
                if not self._transport.alive():
                    raise HostUnverified("native_preflight_transport_closed")
                time.sleep(.01)
        if result is None:
            raise HostUnverified("native_preflight_timeout")
        return result

    def _validate_probe(self, result, c, nonce, parents):
        if result.get("exitCode") != 0:
            # Preserve a fixed boundary, never Native stderr or raw output.
            code = "native_preflight_command_failed"
            if "sandbox_apply: Operation not permitted" in result.get("stderr", ""):
                code = "native_sandbox_apply_denied"
            raise HostUnverified(code)
        try:
            observed = json.loads(result["stdout"])
        except (KeyError, ValueError, TypeError):
            raise HostUnverified("invalid_host_observation") from None
        expected = {"nonce": nonce, "uid": os.getuid(), "euid": os.geteuid(),
                    "cwd": c.conditions.workspace, "workspace_read": "reachable",
                    "workspace_create": "denied",
                    "credential_read": ["denied"] * len(c.credential_files),
                    "credential_env_present": False,
                    "state_write": ["denied"] * len(c.protected_state),
                    "parent_create": ["denied"] * len(parents),
                    "network": ["denied", "denied"]}
        # Retain only the fixed host-helper schema with non-sensitive values.
        if not isinstance(observed, dict) or set(observed) != set(expected):
            raise HostUnverified("invalid_host_observation")
        for key in ("workspace_read", "workspace_create"):
            if observed[key] not in ("reachable", "denied", "unknown"):
                raise HostUnverified("invalid_host_observation")
        for key in ("credential_read", "state_write", "parent_create", "network"):
            values = observed[key]
            if (not isinstance(values, list) or len(values) != len(expected[key])
                    or any(v not in ("reachable", "denied", "unknown") for v in values)):
                raise HostUnverified("invalid_host_observation")
        if (type(observed["uid"]) is not int or type(observed["euid"]) is not int
                or type(observed["credential_env_present"]) is not bool):
            raise HostUnverified("invalid_host_observation")
        safe = {key: value for key, value in observed.items() if key not in ("nonce", "cwd")}
        self.observation["checks"] = safe
        if observed != expected:
            raise HostUnverified("native_boundary_not_proven")
        self.observation.update(status="bounded_readonly_preflight_passed",
                                command_preflight_verified=True,
                                native_handoff_verified=False, native_version=self._native_version,
                                credential_inventory_complete=False,
                                native_internal_isolation_claimed=False,
                                environment_ref=c.conditions.environment_ref,
                                human_intent_ref=c.delegation.human_intent_ref,
                                attempt_ref={"run_id": c.delegation.attempt.run_id,
                                             "job_id": c.delegation.attempt.job_id,
                                             "attempt_id": c.delegation.attempt.attempt_id},
                                delegated_capability=c.delegation.capability)
