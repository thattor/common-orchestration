"""Opt-in single-turn Devin text smoke of the approved Native handoff route.

Existing authentication stays in place. This driver records only fixed-schema
CO events, host observations and a fixed-response match boolean. It does not
record Native text, credential values, or claim installed production acceptance.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from co_v4 import contracts as c
from co_v4.adapters.devin import DevinAdapter
from co_v4.codex_host import HostUnverified
from co_v4.delegation import DelegatedScope, ScopeDenied, WorkerWorkspace
from co_v4.devin_selection import resolve_model, selection
from co_v4.devin_host import DevinHostConfig, DevinTextHost
from co_v4.judgment import JudgmentRequest, TrustedEvidence
from co_v4.state import ControlStore, IngressReceipt, body_digest, create_run_body

EXPECTED = "CO03_NATIVE_SMOKE_OK"
INTENT = "Run one bounded Devin text-only production smoke under the approved CO 0.3 Native handoff model."


def digest(path):
    # Only our own known ControlStore file is hashed; credentials and arbitrary
    # Native-created files are never opened by this driver.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise HostUnverified("unexpected_control_store_type")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    finally:
        os.close(fd)


def workspace_snapshot(root):
    """Top-level metadata of initially empty owned dirs; never follow entries."""
    values = []
    for entry in root.iterdir():
        info = entry.lstat()
        values.append((entry.name, info.st_mode, info.st_ino, info.st_size, info.st_mtime_ns))
        if len(values) > 256:
            raise HostUnverified("workspace_observation_limit")
    return {"entry_count": len(values), "metadata_sha256": hashlib.sha256(
        json.dumps(sorted(values), separators=(",", ":")).encode()).hexdigest()}


def run(scratch_parent, *, executable, native_version, model, credential_files,
        human_intent_ref, timeout=120, effort=None):
    model = resolve_model(model, effort)
    if not 1 <= timeout <= 180 or not human_intent_ref.strip():
        raise ValueError("bounded timeout and Human Intent reference required")
    scratch_parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="161-devin-smoke-", dir=scratch_parent)).resolve()
    try:
        with ExitStack() as cleanup:
            return _run(root, cleanup=cleanup, executable=executable, native_version=native_version,
                model=model, credential_files=credential_files, human_intent_ref=human_intent_ref,
                timeout=timeout)
    except Exception:
        # Bootstrap and cleanup failures also leave a fixed, non-secret receipt.
        receipt = {"evidence_kind": "devin_text_live_smoke", "scratch_ref": str(root),
            "smoke_failure": "smoke_bootstrap_or_cleanup_failed", "installed_production": False,
            "model_submission_count_known": False}
        with (root / "failure-evidence.json").open("x") as stream:
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
        return receipt


def _run(root, *, cleanup, executable, native_version, model, credential_files,
         human_intent_ref, timeout):
    worker, control, other = root / "worker", root / "control", root / "other-worker"
    for directory in (worker, control, other): directory.mkdir(mode=0o700)
    state = control / "control.db"
    ref = c.AttemptRef("production-smoke", "devin-text", root.name)
    conditions = c.ExecutionConditions(model, "devin.acp", str(worker),
        "candidate:devin-text:" + root.name, ("human-approved:native-handoff-v1",))
    job = c.Job(ref.run_id, ref.job_id,
        "Return exactly " + EXPECTED + ". Do not use tools, read files, access the network, or change any state.",
        ("Return the exact fixed response using no tools.",))
    request = c.ExecuteRequest(ref, job, conditions)
    scope = DelegatedScope(human_intent_ref, ref, str(worker), "devin.text.only")
    host = DevinTextHost(DevinHostConfig(conditions, executable.resolve(), native_version,
        (state,), tuple(path.resolve() for path in credential_files), scope))
    action = c.Action("native.text.response", c.Scope((
        ("workspace", str(worker)), ("environment", conditions.environment_ref),
        ("adapter", conditions.adapter), ("response_sha256", hashlib.sha256(EXPECTED.encode()).hexdigest())), True))
    now = datetime.now(timezone.utc).isoformat()
    origin = IngressReceipt("operator-provided-existing-human-delegation", human_intent_ref,
                           body_digest(create_run_body(ref.run_id, INTENT)), now)
    def provenance(source):
        if source != human_intent_ref: raise HostUnverified("unexpected_human_intent_reference")
        return origin
    def evidence(run_record, judgment):
        if (judgment.conditions != conditions or judgment.action != action
                or judgment.ref not in (c.QuestionRef(ref.run_id, ref.job_id),
                                        c.QuestionRef(ref.run_id, ref.job_id, ref.attempt_id))
                or judgment.proposed_job not in (None, job)):
            raise HostUnverified("unexpected_judgment_request")
        # Proposed Job containment needs only the adopted fixed intent. Actual
        # Attempt admission stays false until this exact Native session passes.
        verified = host.observation.get("native_handoff_verified") is True
        return TrustedEvidence(body_digest(judgment), "native-handoff-v1",
            conditions.control_evidence_refs, body_digest(action), intent_contained=True,
            intent_authorizes=True, conditions_verified=verified, protection_verified=verified)
    store = ControlStore(state, verifier=provenance, evidence=evidence)
    cleanup.callback(store.close)
    controller, judgment = store.controller(), store.judgment()
    store.intake().create_run(ref.run_id, INTENT, human_intent_ref)
    job_judgment = JudgmentRequest(c.QuestionRef(ref.run_id, ref.job_id), action,
                                   "bounded-text-smoke", conditions, proposed_job=job)
    decision = judgment.judge(job_judgment)
    controller.add_job(job, decision.decision_id, controller.get_run(ref.run_id).revision)
    writer = WorkerWorkspace(scope, protected_state=(state,))
    cleanup.callback(writer.close)
    result = {"evidence_kind": "devin_text_live_smoke", "observed_at": now,
        "scratch_ref": str(root), "human_intent_ref": human_intent_ref,
        "origin_kind": "operator assertion of existing Human approval; no live ingress transport tested",
        "environment_ref": conditions.environment_ref, "installed_production": False,
        "credential_inventory_count": len(credential_files), "credential_values_read": False,
        "model_turns_submitted": 0, "events": [], "result": None,
        "native_boundary_scope": "Native handoff; arbitrary internal tools are not OS-contained",
        "observed_out_of_scope_write": False, "timeout": False,
        "mutation_observation_limit": "Own ControlStore bytes between polls and Controller commands; initially empty scratch workspaces; no system-wide audit"}
    expected_db = digest(state)
    initial_db = expected_db
    baseline_worker, baseline_other = workspace_snapshot(worker), workspace_snapshot(other)
    queued, cursor, reserved = [], None, False
    native_text, text_overflow, native_methods = "", False, []
    reply = None

    def check_control():
        if digest(state) != expected_db:
            result["observed_out_of_scope_write"] = True
            raise HostUnverified("unexpected_control_state_mutation")

    def verify_host(bound_request, phase, native):
        nonlocal expected_db, reserved
        check_control()
        host.verify(bound_request, phase, native)
        if phase == "session":
            # Reserve using freshly verified evidence from this exact session,
            # immediately before the Adapter attempts its one model submission.
            attempt_judgment = JudgmentRequest(c.QuestionRef(ref.run_id, ref.job_id, ref.attempt_id),
                                               action, "bounded-text-smoke", conditions)
            decision = judgment.judge(attempt_judgment)
            controller.begin_attempt(request, decision.decision_id, controller.get_run(ref.run_id).revision)
            reserved = True
            expected_db = digest(state)

    class Observe:
        def __init__(self, inner): self.inner = inner
        def send(self, message):
            nonlocal expected_db
            check_control()
            method = message.get("method")
            if method: native_methods.append(method)
            if method == "session/prompt":
                if result["model_turns_submitted"] or not reserved:
                    raise HostUnverified("unexpected_model_submission")
                result["model_turns_submitted"] += 1
            self.inner.send(message)
        def poll(self):
            nonlocal native_text, text_overflow
            check_control()
            messages = self.inner.poll()
            check_control()
            for message in messages:
                if message.get("method") != "session/update": continue
                update = message.get("params", {}).get("update", {})
                if update.get("sessionUpdate") != "agent_message_chunk": continue
                content = update.get("content", {})
                if content.get("type") == "text" and isinstance(content.get("text"), str):
                    if len(native_text) + len(content["text"]) <= 128:
                        native_text += content["text"]
                    else:
                        text_overflow = True
                        native_text = ""
            return messages
        def alive(self): return self.inner.alive()
        def close(self): self.inner.close()

    adapter = DevinAdapter(verify_host=verify_host,
        transport_factory=lambda bound: Observe(host.transport(bound)), rpc_timeout=15, observe_model=host.observe_model)
    cleanup.callback(adapter.close)
    try:
        reply = adapter.execute(request)
        result["execute_reply"] = reply.status.value
        started = time.monotonic()
        while reply.status == c.OperationStatus.ACCEPTED and time.monotonic() - started < timeout:
            events = adapter.events(ref, cursor)
            check_control()
            if events:
                cursor = events[-1].event_id
                queued.extend(events)
                for event in events:
                    if isinstance(event, c.StatusEvent):
                        result["events"].append({"kind": "status", "state": event.state.value})
                    elif isinstance(event, c.ResultEvent):
                        result["events"].append({"kind": "result", "status": event.result.status.value,
                                                 "reason": event.result.reason})
                        result["result"] = {"status": event.result.status.value, "reason": event.result.reason}
                    elif isinstance(event, c.ConfirmationEvent):
                        result["events"].append({"kind": "confirmation"})
                        raise HostUnverified("unexpected_confirmation_on_text_route")
            if reserved:
                if controller.execute_receipt(ref) is None:
                    controller.record_execute(reply, controller.get_attempt(ref).revision)
                    expected_db = digest(state)
                while queued:
                    event = queued.pop(0)
                    controller.record_event(event, controller.get_attempt(ref).revision)
                    expected_db = digest(state)
            if result["result"] is not None: break
            time.sleep(.025)
        if reply.status == c.OperationStatus.ACCEPTED and result["result"] is None:
            result["timeout"] = True
            stop = adapter.stop(ref)
            result["stop_status"] = stop.status.value
            if reserved:
                check_control()
                controller.record_stop(stop, controller.get_attempt(ref).revision)
                expected_db = digest(state)
        check_control()
        result["fixed_response_matched"] = not text_overflow and native_text == EXPECTED
        result["workspace_before"] = baseline_worker
        result["workspace_after_native"] = workspace_snapshot(worker)
        result["other_workspace_unchanged"] = workspace_snapshot(other) == baseline_other
        result["native_workspace_unchanged"] = result["workspace_after_native"] == baseline_worker
        if not result["native_workspace_unchanged"] or not result["other_workspace_unchanged"]:
            result["observed_out_of_scope_write"] = True
        # The same actual Worker Command is exercised on normal host filesystem,
        # with negative targets wholly inside the owned smoke scratch tree.
        denied = []
        from dataclasses import replace
        for name, target_ref, path in (
            ("other_attempt", replace(ref, attempt_id="other-attempt"), "denied.txt"),
            ("other_workspace", ref, "../other-worker/denied.txt"),
            ("protected_control", ref, "../control/control.db"),
            ("absolute_path", ref, str(other / "denied.txt"))):
            try:
                writer.create_artifact(target_ref, path, b"scope check")
            except ScopeDenied:
                denied.append(name)
            else:
                result["observed_out_of_scope_write"] = True
        check_control()
        writer.create_artifact(ref, "smoke-receipt.json", json.dumps({
            "attempt_id": ref.attempt_id, "result": result["result"],
            "fixed_response_matched": result["fixed_response_matched"]}).encode())
        result["worker_write_checks"] = {"owned_artifact_created": (worker / "smoke-receipt.json").is_file(),
                                        "denied": denied}
        if reserved:
            snapshot = controller.get_attempt(ref)
            result["stored_attempt_state"] = snapshot.state.value
            result["stored_result_matches"] = (snapshot.result is not None and result["result"] == {
                "status": snapshot.result.status.value, "reason": snapshot.result.reason})
            result["stored_event_count"] = len(controller.history(ref.run_id, "events"))
        result["control_state_changed_by_controller"] = expected_db != initial_db
    except Exception:
        result["smoke_failure"] = "bounded_smoke_failed"
    finally:
        native_text = ""
        adapter.close()
        writer.close()
        result["host_observation"] = dict(host.observation)
        result["native_method_names"] = native_methods
        result["owned_native_reaped"] = host._transport is None or not host._transport.alive()
        result["native_tool_event_count"] = 0 if host._transport is None else host._transport.tool_events
        try:
            check_control()
            result["control_state_has_only_observed_controller_mutations"] = True
            result["control_state_sha256"] = digest(state)
        except Exception:
            result["control_state_has_only_observed_controller_mutations"] = False
            result["observed_out_of_scope_write"] = True
        store.close()
        # The receipt survives success/failure and is exclusive to this run.
        with (root / "evidence.json").open("x") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-smoke", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--executable", type=Path, default=shutil.which("devin"))
    parser.add_argument("--native-version", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--effort", choices=("medium", "high", "max"))
    parser.add_argument("--credential-file", type=Path, action="append", required=True)
    parser.add_argument("--human-intent-ref", required=True)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    # Reserve the evidence output before any launch; an existing/unwritable
    # destination must not consume a model turn.
    with args.output.open("x") as stream:
        result = run(Path(__file__).resolve().parents[3] / ".orchestration-runs", executable=args.executable,
            native_version=args.native_version, model=args.model, effort=args.effort, credential_files=args.credential_file,
            human_intent_ref=args.human_intent_ref, timeout=args.timeout)
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))
