"""Opt-in Native smoke. Not discovered by unittest; submits NO model turn.

Run from the standalone checkout root with PYTHONPATH=. using an existing
normal-host ChatGPT login. Writes one NEW sanitized record in the owning
checkout. No raw session IDs, credential contents, model output or stderr
are written. Existing evidence is not touched. This exercises the Native
transport, not the host protection gate.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import time

from co_v4.adapters.codex import CLI_VERSION, StdioTransport

CHECKOUT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checkout = CHECKOUT
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(checkout):
        parser.error("output must be a new file within this checkout")
    report = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "evidence_kind": "native_no_model_turn_transport_smoke",
        "expected_cli_version": CLI_VERSION,
        "auth_mode": "unverified",
        "model_turn_submitted": False,
        "effective_turn_model": None,
        "effective_turn_effort": None,
        "live_features": {key: "untested" for key in (
            "action_interception", "confirmation_relay", "turn_stop",
            "tool_cessation", "same_attempt_resume", "host_isolation")},
        "initialize": "not_run", "thread_start": "not_run", "thread_resume": "not_run",
        "owned_process_reaped": False,
    }
    wire = None
    try:
        executable = shutil.which("codex")
        if not executable:
            raise RuntimeError("CLI unavailable")
        auth = subprocess.run([executable, "login", "status"], capture_output=True,
                              text=True, timeout=5, check=False)
        if auth.returncode or "Logged in using ChatGPT" not in auth.stdout + auth.stderr:
            raise RuntimeError("existing ChatGPT auth unverified")
        report["auth_mode"] = "existing ChatGPT login"
        wire = StdioTransport(executable, str(checkout))

        def rpc(rpc_id, method, params):
            wire.send({"id": rpc_id, "method": method, "params": params})
            end = time.monotonic() + 10
            while time.monotonic() < end:
                for message in wire.poll():
                    if message.get("id") == rpc_id:
                        if "error" in message or not isinstance(message.get("result"), dict):
                            raise RuntimeError("Native RPC rejected")
                        return message["result"]
                    if "method" in message and "id" in message:
                        raise RuntimeError("unexpected Native request")
                if not wire.alive():
                    raise RuntimeError("Native transport ended")
                time.sleep(.02)
            raise RuntimeError("Native RPC timed out")

        rpc("init", "initialize", {"clientInfo": {"name": "co03_codex_transport_smoke", "version": "0.3.0-dev"}})
        report["initialize"] = "response_observed"
        wire.send({"method": "initialized"})
        config = {"model": "gpt-6-astra", "modelProvider": "openai", "cwd": str(checkout),
                  "approvalPolicy": "on-request", "approvalsReviewer": "user",
                  "sandbox": "read-only", "ephemeral": True}
        result = rpc("start", "thread/start", config)
        report["thread_start"] = "response_observed"
        report["effective_thread_configuration"] = {
            "model_matches": result.get("model") == config["model"],
            "provider_matches": result.get("modelProvider") == "openai",
            "cwd_matches": result.get("cwd") == str(checkout),
            "approval_policy_matches": result.get("approvalPolicy") == "on-request",
            "reviewer_matches": result.get("approvalsReviewer") == "user",
            "sandbox_type_matches": result.get("sandbox", {}).get("type") == "readOnly",
        }
        # No prompt, turn/start, tool request, or interrupt is sent. A resume of
        # an empty thread is only metadata API evidence, not Attempt continuity.
        try:
            rpc("resume", "thread/resume", {"threadId": result["thread"]["id"]})
            report["thread_resume"] = "empty_thread_response_observed_only"
        except Exception:
            report["thread_resume"] = "empty_thread_not_resumable"
        report["blocker"] = None
    except Exception:
        report["blocker"] = "Native smoke incomplete; no raw diagnostics published"
    finally:
        if wire is not None:
            wire.close()
            report["owned_process_reaped"] = not wire.alive()
    with output.open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
