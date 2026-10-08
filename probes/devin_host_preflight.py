"""Opt-in Devin ACP production composition preflight; independently zero model turns.

Uses only explicitly inventoried existing credential paths (metadata checks).
No credential contents, model response, or raw Native frames are recorded.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from co_v4.adapters.devin import DevinAdapter
from co_v4.contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job, TERMINAL
from co_v4.delegation import DelegatedScope
from co_v4.devin_selection import resolve_model, selection
from co_v4.devin_host import DevinHostConfig, DevinTextHost
from co_v4.codex_host import HostUnverified
from co_v4.state import ControlStore


def run(scratch_parent, *, executable, native_version, model, credential_files, human_intent_ref, effort=None):
    model = resolve_model(model, effort)
    scratch_parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="161-devin-preflight-", dir=scratch_parent)).resolve()
    worker, control = root / "worker", root / "control"
    worker.mkdir(mode=0o700)
    control.mkdir(mode=0o700)
    state = control / "control.db"
    def refuse(*args): raise RuntimeError("preflight has no Human ingress")
    store = ControlStore(state, verifier=refuse, evidence=refuse)
    store.close()
    before = hashlib.sha256(state.read_bytes()).hexdigest()
    ref = AttemptRef("production-preflight", "devin-text", root.name)
    conditions = ExecutionConditions(model, "devin.acp", str(worker),
        "candidate:devin-text:" + root.name, ("human-approved:native-handoff-v1",))
    scope = DelegatedScope(human_intent_ref, ref, str(worker), "devin.text.only")
    host = DevinTextHost(DevinHostConfig(conditions, executable.resolve(), native_version,
                         (state,), tuple(p.resolve() for p in credential_files), scope))
    methods, attempts = [], []
    class NoModel:
        def __init__(self, inner): self.inner = inner
        def send(self, message):
            methods.append(message.get("method"))
            if message.get("method") == "session/prompt":
                attempts.append(True)
                raise HostUnverified("probe_model_turn_forbidden")
            self.inner.send(message)
        def poll(self): return self.inner.poll()
        def alive(self): return self.inner.alive()
        def close(self): self.inner.close()
    adapter = DevinAdapter(verify_host=host.verify,
        transport_factory=lambda request: NoModel(host.transport(request)), rpc_timeout=15, observe_model=host.observe_model)
    request = ExecuteRequest(ref, Job(ref.run_id, ref.job_id,
        "No model turn is permitted in this preflight.", ()), conditions)
    result = {"selection": selection(model), "evidence_kind": "devin_host_preflight", "model_turns_submitted": 0,
        "observed_at": datetime.now(timezone.utc).isoformat(), "scratch_ref": str(root),
        "credential_inventory_count": len(credential_files), "credential_values_read": False,
        "human_ingress": "disabled", "installed_production": False}
    try:
        reply = adapter.execute(request)
        result["execute_reply"] = reply.status.value
        end = time.monotonic() + 45
        while reply.status.value == "accepted" and time.monotonic() < end:
            events = adapter.events(ref)
            if any(getattr(event, "state", None) in TERMINAL for event in events): break
            time.sleep(.025)
        result["observation"] = dict(host.observation)
        result["model_turn_blocked_by_probe"] = bool(attempts)
    except Exception:
        result["probe_failure"] = "native_probe_unavailable"
        result["observation"] = dict(host.observation)
    finally:
        adapter.close()
        result["control_store_unchanged"] = hashlib.sha256(state.read_bytes()).hexdigest() == before
        result["workspace_entries"] = len(tuple(worker.iterdir()))
        result["native_method_names"] = methods
        result["owned_native_reaped"] = host._transport is None or not host._transport.alive()
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--executable", type=Path, default=shutil.which("devin"))
    parser.add_argument("--native-version", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--effort", choices=("medium", "high", "max"))
    parser.add_argument("--credential-file", type=Path, action="append", required=True)
    parser.add_argument("--human-intent-ref", required=True)
    args = parser.parse_args()
    result = run(Path(__file__).resolve().parents[3] / ".orchestration-runs",
        executable=args.executable, native_version=args.native_version, model=args.model, effort=args.effort,
        credential_files=args.credential_file, human_intent_ref=args.human_intent_ref)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))
