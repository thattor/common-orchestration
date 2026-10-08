"""Opt-in #158 Native preflight; deliberately cannot submit a model turn.

Run explicitly with --probe. Existing login/config are used unchanged. A fresh
empty cwd and private raw streams live under ignored .orchestration-runs.
Bootstrap failure is a boundary, never evidence about model/tool behavior.
Even bootstrap success cannot authorize a turn without verified confinement
and interception; this collector stops there. No CO routing is involved.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import time


VERSION = b"codex-cli 0.156.1"
LIMIT = 1024 * 1024
INITIALIZE = {"id": "probe-init", "method": "initialize", "params": {
    "clientInfo": {"name": "co03_codex_live_boundary", "version": "0.3.0-dev"}}}


def private_file(path):
    return os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb")


def capture(argv, cwd, scratch, deadline=8):
    """Keep stdin open while observing initialize; reap only the owned process.

    No server request can receive approval: no initialized notification, thread
    or turn is sent. Unexpected requests terminate this preflight immediately.
    Bytes are bounded, kept private, and never returned as public diagnostics.
    """
    wire = json.dumps(INITIALIZE).encode() + b"\n"
    with private_file(scratch / "stdin.jsonl") as stream:
        stream.write(wire)
    data = {"stdout": bytearray(), "stderr": bytearray()}
    reason = "initialize_timeout"
    initialized = False
    request_seen = False
    proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        proc.stdin.write(wire)
        proc.stdin.flush()
        end = time.monotonic() + deadline
        pending = bytearray()
        with selectors.DefaultSelector() as selector:
            for name in data:
                selector.register(getattr(proc, name), selectors.EVENT_READ, name)
            done = False
            while selector.get_map() and not done and time.monotonic() < end:
                for key, _ in selector.select(min(.05, max(0, end - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(data[key.data]) + len(chunk) > LIMIT:
                        reason, done = "stream_limit", True
                        break
                    data[key.data].extend(chunk)
                    if key.data != "stdout":
                        continue
                    pending.extend(chunk)
                    while b"\n" in pending and not done:
                        line, _, rest = pending.partition(b"\n")
                        pending = bytearray(rest)
                        try:
                            message = json.loads(line)
                        except (ValueError, UnicodeError):
                            reason, done = "invalid_native_frame", True
                            break
                        if not isinstance(message, dict):
                            reason, done = "invalid_native_frame", True
                        elif "method" in message and "id" in message:
                            request_seen = True
                            reason, done = "unexpected_request_no_approval_sent", True
                        elif message.get("id") == "probe-init":
                            initialized = (isinstance(message.get("result"), dict)
                                           and "error" not in message)
                            reason = ("host_confinement_and_interception_unverified"
                                      if initialized else "initialize_rejected")
                            done = True
            natural_exit = proc.poll()
            if not initialized and not done and not selector.get_map():
                reason = "native_eof_before_initialize"
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()
        for name, raw in data.items():
            with private_file(scratch / (name + ".raw")) as stream:
                stream.write(raw)
    sqlite_failed = b"failed to initialize sqlite state runtime" in data["stderr"]
    if sqlite_failed and not initialized:
        reason = "native_sqlite_initialization_failed_before_initialize"
    return {
        "boundary": reason, "initialize_response_seen": initialized,
        "unexpected_request_seen": request_seen,
        "approval_response_sent": False,
        "natural_exit_code_observed": natural_exit,
        "owned_process_exit_code": proc.returncode,
        "owned_process_reaped": proc.poll() is not None,
        "stdin_kept_open_until_boundary": True,
        "diagnostics": {
            "sqlite_initialization_failed": sqlite_failed,
            "path_alias_permission_denied": b"could not create PATH aliases" in data["stderr"],
        },
    }


def probe(checkout):
    private = checkout / ".orchestration-runs"
    private.mkdir(mode=0o700, exist_ok=True)
    # Raw streams must be ignored before any Native process can be launched.
    ignored = subprocess.run(["git", "check-ignore", "-q", str(private / "probe.raw")],
                             cwd=checkout, capture_output=True, check=False)
    if ignored.returncode:
        raise RuntimeError("private scratch is not ignored")
    scratch = Path(tempfile.mkdtemp(prefix="158-codex-boundary-", dir=private))
    cwd = scratch / "workspace"
    cwd.mkdir(mode=0o700)
    report = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "evidence_kind": "native_pre_turn_boundary_observation",
        "model_turn_submitted": False, "model_turn_count": 0,
        "planned_turn": {"model": "gpt-6-astra", "effort": "medium",
                         "sandbox": "read-only", "approval_policy": "on-request",
                         "intended_action": "pwd", "sent": False},
        "effective_turn_model": None, "effective_turn_effort": None,
        "live_features": {key: "not_observed_no_turn" for key in (
            "command_callback_before_execution", "approval_denial_relay",
            "stop_request", "confirmed_tool_cessation", "same_attempt_resume")},
        "auth_mode": "unverified", "cli_version": None,
        "boundary": "cli_unavailable", "owned_process_reaped": None,
        "scratch_ref": str(scratch.relative_to(checkout)),
        "worker_workspace_fresh_and_empty": True,
        "worker_workspace_unchanged": None,
    }
    cli = shutil.which("codex")
    if cli:
        for name, arguments in (("version", ["--version"]), ("auth-status", ["login", "status"])):
            result = subprocess.run([cli, *arguments], cwd=cwd, capture_output=True,
                                    timeout=5, check=False)
            with private_file(scratch / (name + ".raw")) as stream:
                stream.write(result.stdout + result.stderr)
            if name == "version":
                if result.returncode or result.stdout.strip() != VERSION:
                    report["boundary"] = "cli_version_unverified"
                    break
                report["cli_version"] = VERSION.decode()
            else:
                if result.returncode or b"Logged in using ChatGPT" not in result.stdout + result.stderr:
                    report["boundary"] = "existing_chatgpt_auth_unverified"
                    break
                report["auth_mode"] = "existing ChatGPT login"
                report.update(capture([cli, "app-server", "--stdio"], cwd, scratch))
    report["worker_workspace_unchanged"] = not any(cwd.iterdir())
    report["raw_artifacts"] = [{"file": p.name, "bytes": p.stat().st_size,
                                "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                               for p in sorted(scratch.iterdir()) if p.is_file()]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checkout = Path(__file__).resolve().parents[3]
    output = args.output.resolve()
    records = checkout / "common-orchestration/design/0.3/records"
    if output.exists() or output.parent != records:
        parser.error("output must be a new file directly under design/0.3/records")
    report = probe(checkout)
    with output.open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(output), "boundary": report["boundary"]}))


if __name__ == "__main__":
    main()
