"""Opt-in bounded preflight on an owned candidate ControlStore; zero model turns.

Existing Codex authentication is used in place. No credential values are read,
copied or logged; no OS permissions are changed. Evidence is preserved even on
failure. This is a candidate environment, never an installed production route.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from co_v4.adapters.codex import CodexAdapter, StdioTransport
from co_v4.codex_host import (CodexHostConfig, CodexReadOnlyHost, DelegatedScope,
                              HostUnverified, PROBE, OVERRIDES)
from co_v4.contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job, TERMINAL
from co_v4.state import ControlStore


def configured_launch_inventory(executable, workspace):
    """No thread/model; retain only identifiers for per-entry disabling.

    Config values, names and response payloads never enter the evidence record.
    A configuration race is handled by checking the actual launch again.
    """
    env = {k: os.environ[k] for k in ("HOME", "PATH", "TMPDIR", "USER", "LOGNAME", "LANG") if k in os.environ}
    transport = StdioTransport(str(executable), str(workspace), config_overrides=OVERRIDES, env=env)
    def rpc(method, params):
        transport.send({"id": method, "method": method, "params": params})
        end = time.monotonic() + 8
        count = 0
        while time.monotonic() < end:
            messages = transport.poll()
            count += len(messages)
            if count > 128: raise HostUnverified("config_discovery_frame_limit")
            for message in messages:
                if "id" in message and "method" in message:
                    raise HostUnverified("config_discovery_native_request")
                if message.get("id") == method:
                    if "error" in message: raise HostUnverified("config_discovery_rpc_error")
                    return message["result"]
            if not transport.alive(): raise HostUnverified("config_discovery_native_exit")
            time.sleep(.01)
        raise HostUnverified("config_discovery_timeout")
    try:
        rpc("initialize", {"clientInfo": {"name": "co_host_config_inventory", "version": "0.3.0-dev"}})
        transport.send({"method": "initialized"})
        config = rpc("config/read", {"cwd": str(workspace), "includeLayers": False})["config"]
        entries = config.get("mcp_servers") or {}
        if not isinstance(entries, dict) or len(entries) > 64:
            raise HostUnverified("invalid_mcp_inventory")
        policy = config.get("shell_environment_policy") or {}
        values = policy.get("set") or {}
        if not isinstance(values, dict) or len(values) > 128:
            raise HostUnverified("invalid_environment_inventory")
        # Retain keys only. Values, even hashes/tokens, are never logged.
        return tuple(entries), tuple(values)
    finally:
        transport.close()


def configured_mcp_identifiers(executable, workspace):
    return configured_launch_inventory(executable, workspace)[0]


def run(scratch_parent: Path):
    scratch_parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="158-codex-host-", dir=scratch_parent)).resolve()
    workspace, control = root / "worker", root / "control"
    workspace.mkdir(mode=0o700)
    control.mkdir(mode=0o700)
    state = control / "control.db"
    def refuse(*args): raise RuntimeError("probe has no Human ingress")
    store = ControlStore(state, verifier=refuse, evidence=refuse)
    store.close()
    before = hashlib.sha256(state.read_bytes()).hexdigest()
    conditions = ExecutionConditions("gpt-6-astra", "codex.app-server", str(workspace),
                         "candidate:codex-host:" + root.name, ("candidate:host-preflight",))
    credential = Path.home() / ".codex" / "auth.json"
    executable = Path(shutil.which("codex")).resolve()
    inventory_error = False
    try:
        mcp_names, environment_keys = configured_launch_inventory(executable, workspace)
    except Exception:
        mcp_names, environment_keys, inventory_error = (), (), True
    ref = AttemptRef("host-probe", "readonly", root.name)
    delegation = DelegatedScope(
        "https://github.com/thattor/ai-company/issues/161#issuecomment-5894814158",
        ref, str(workspace))
    host = CodexReadOnlyHost(CodexHostConfig(conditions,
        executable, Path(sys.executable).resolve(), (state,), (credential.resolve(),),
        delegation, disabled_mcp_servers=mcp_names,
        cleared_environment_keys=environment_keys))
    methods = []
    model_turn_attempts = []
    terminal = None
    # The transport wrapper enforces zero model submissions independently of
    # the verifier verdict. It logs method names only, never RPC contents.
    class NoModel:
        def __init__(self, inner): self.inner = inner
        def send(self, message):
            methods.append(message.get("method"))
            if message.get("method") == "turn/start":
                model_turn_attempts.append(True)
                raise HostUnverified("probe_model_turn_forbidden")
            self.inner.send(message)
        def poll(self): return self.inner.poll()
        def alive(self): return self.inner.alive()
        def close(self): self.inner.close()
    adapter = CodexAdapter(verify_host=host.verify,
                          transport_factory=lambda request: NoModel(host.transport(request)),
                          rpc_timeout=8)
    request = ExecuteRequest(ref,
        Job("host-probe", "readonly", "No model turn is permitted in this probe.", ()), conditions)
    result = {"evidence_kind": "candidate_native_host_preflight", "model_turns_submitted": 0,
              "environment_ref": conditions.environment_ref, "scratch_ref": str(root),
              "observed_at": datetime.now(timezone.utc).isoformat(),
              "credential_inventory": ["existing Codex auth file; metadata/open only"],
              "human_ingress": "disabled; no Human credential or ingress configured",
              "installed_production": False,
              "disabled_mcp_identifier_count": len(mcp_names),
              "mcp_inventory_unavailable": inventory_error,
              "cleared_environment_key_count": len(environment_keys),
              "probe_source_sha256": hashlib.sha256(PROBE.encode()).hexdigest()}
    result["delegation"] = {"human_intent_ref": delegation.human_intent_ref,
                            "run_id": ref.run_id, "job_id": ref.job_id,
                            "attempt_id": ref.attempt_id,
                            "capability": delegation.capability,
                            "workspace": str(workspace)}
    try:
        if inventory_error: raise HostUnverified("config_discovery_unavailable")
        reply = adapter.execute(request)
        result["execute_reply"] = reply.status.value
        end = time.monotonic() + 15
        while time.monotonic() < end:
            events = adapter.events(request.ref) if reply.status.value == "accepted" else ()
            if not events:
                time.sleep(.025)
            terminal = next((e for e in events if getattr(e, "state", None) in TERMINAL), None)
            if terminal is not None:
                break
            if reply.status.value != "accepted":
                break
        result["observation"] = host.observation
        result["terminal_state"] = terminal.state.value if terminal is not None else None
        result["native_preflight_reached"] = host.observation["status"] != "awaiting_native_preflight"
        result["model_turn_blocked_by_probe"] = bool(model_turn_attempts)
    except Exception:
        result["probe_failure"] = "native_probe_unavailable"
        result["observation"] = host.observation
    finally:
        adapter.close()
        result["control_store_unchanged"] = hashlib.sha256(state.read_bytes()).hexdigest() == before
        result["workspace_entries"] = len(list(workspace.iterdir()))
        result["native_method_names"] = methods
        result["owned_native_reaped"] = bool(host._transport is None or not host._transport.alive())
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(Path(__file__).resolve().parents[3] / ".orchestration-runs")
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))
