"""Offline fixtures and static boundaries; NOT Native acceptance."""
import ast
import json
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from probes import codex_live_control as p

FIXTURE = r'''
import json, os, shlex, subprocess, sys
mode = sys.argv[1]
thread, turn = "SECRET-THREAD", "SECRET-TURN"
child = None
def emit(msg):
    print(json.dumps(msg), flush=True)
def event(method, **params):
    emit({"method": method, "params": {"threadId": thread, **params}})
for line in sys.stdin:
    msg = json.loads(line)
    method, params = msg.get("method"), msg.get("params", {})
    if method == "initialize":
        if mode == "sqlite":
            print("failed to initialize sqlite state runtime SECRET-ERROR", file=sys.stderr, flush=True)
            sys.exit(1)
        emit({"id": msg["id"], "result": {"userAgent": "fixture"}})
    elif method == "thread/start":
        cwd = params["cwd"]
        result = {**params, "sandbox": {"type": "readOnly"}, "thread": {"id": thread}}
        if mode == "drift":
            result["approvalsReviewer"] = "auto_review"
        emit({"id": msg["id"], "result": result})
    elif method == "thread/resume":
        emit({"id": msg["id"], "result": {**params, "sandbox": {"type": "readOnly"},
              "thread": {"id": thread, "turns": [{"id": turn, "status": "completed"}]}}})
    elif method == "turn/start":
        command = params["input"][0]["text"].split("Command: ", 1)[1]
        cb = {"id": "SECRET-CALLBACK", "method": "item/commandExecution/requestApproval", "params": {
            "threadId": thread, "turnId": "WRONG" if mode == "mismatch" else turn,
            "itemId": "SECRET-ITEM", "command": command, "cwd": cwd}}
        if mode == "wrapped":
            cb["params"].update(command='/bin/zsh -lc ' + json.dumps(command),
                                kind="command", commandActions=[{"type": "unknown", "command": command}])
        if mode == "stop-observed":
            pass  # Host-table fixture only; no real operation/child is launched.
        elif mode.startswith("stop"):
            child = subprocess.Popen(shlex.split(command))
        else:
            emit(cb)  # callback BEFORE turn/start receipt
        if mode == "early-message":
            event("item/completed", turnId=turn, item={"type": "agentMessage"})
        emit({"id": msg["id"], "result": {"turn": {"id": turn, "status": "inProgress"}}})
    elif method == "turn/interrupt":
        emit({"id": msg["id"], "result": {}})
        if mode == "stop":
            rows = subprocess.check_output(["/bin/ps", "-axo", "pid=,ppid="]).decode().splitlines()
            for row in rows:
                pid, ppid = map(int, row.split())
                if ppid == child.pid:
                    os.kill(pid, 15)
            child.terminate()
            child.wait(timeout=2)
        event("turn/completed", turn={"id": turn, "status": "interrupted"})
    elif method is None:
        assert msg["result"]["decision"] in ("decline", "cancel")
        if mode == "effect":
            subprocess.run(command, shell=True, check=True)
        if mode == "duplicate":
            emit(cb)
        if mode != "early-message":
            event("item/completed", turnId=turn, item={"id": "SECRET-MESSAGE", "type": "agentMessage", "text": "SECRET-OUTPUT"})
        event("turn/completed", turn={"id": turn, "status": "completed"})
'''


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cwd = self.root / "workspace"
        self.cwd.mkdir()

    def wire(self, mode="reject", code=FIXTURE):
        wire = p.Wire([sys.executable, "-u", "-c", code, mode], self.cwd, self.root)
        self.addCleanup(wire.close)
        return wire

    def case(self, mode="reject", fixture=None, timeout=2):
        wire = self.wire(fixture or mode)
        wire.initialize()
        facts = {}
        p.run_case(wire, self.cwd, self.root, mode, timeout, facts)
        wire.close()
        return facts, (self.root / "stdin.raw").read_text()

    def test_decline_pre_effect_same_turn_and_sanitization(self):
        facts, raw = self.case()
        verdict = p.classify({"reject": facts}, {})
        self.assertEqual(verdict["reject_before_effect"]["status"], "pass")
        self.assertEqual(verdict["same_turn_after_response"]["status"], "pass")
        self.assertFalse(facts["sentinel_after"])
        self.assertNotIn("SECRET", json.dumps(facts))
        self.assertIn("SECRET-CALLBACK", raw)
        for path in self.root.glob("*.raw"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_duplicate_callback_exactly_one_response(self):
        facts, raw = self.case(fixture="duplicate")
        self.assertEqual(len([m for m in map(json.loads, raw.splitlines()) if "result" in m]), 1)
        self.assertTrue(facts["same_turn_continuation"])

    def test_queued_message_before_response_is_not_continuation(self):
        facts, _ = self.case(fixture="early-message")
        self.assertFalse(facts["same_turn_continuation"])

    def test_scope_unknown_cancels_distinct_approve_sentinel(self):
        facts, raw = self.case(mode="approve", fixture="reject")
        self.assertFalse(facts["scope_complete"])
        self.assertEqual(facts["response_kind"], "cancel")
        self.assertFalse(facts["sentinel_after"])
        self.assertIn("approve.sentinel", raw)
        self.assertEqual(p.classify({"approve": facts}, {})["approve_once"]["status"], "unsupported")

    def test_forged_worker_fields_cannot_complete_scope(self):
        scope = p.approval_scope({"command": "safe", "cwd": str(self.cwd), "host_attested": True,
                                  "argv": ["safe"], "environment": {}, "complete": True}, "safe", self.cwd)
        self.assertTrue(scope["display_matches"])
        self.assertFalse(scope["complete"])

    def test_live_zsh_display_decline_attribution_without_scope_authority(self):
        facts, raw = self.case(fixture="wrapped")
        self.assertTrue(facts["callback_command_matches"])
        self.assertEqual(facts["callback_display_match_kind"], "exact_zsh_wrapper_and_single_action")
        self.assertFalse(facts["scope_complete"])
        self.assertEqual(p.classify({"reject": facts}, {})["reject_before_effect"]["status"], "pass")
        replies = [m["result"]["decision"] for m in map(json.loads, raw.splitlines()) if "result" in m]
        self.assertEqual(replies, ["decline"])

    def test_live_zsh_display_approve_still_cancels(self):
        facts, _ = self.case(mode="approve", fixture="wrapped")
        self.assertTrue(facts["callback_command_matches"])
        self.assertFalse(facts["scope_complete"])
        self.assertEqual(facts["response_kind"], "cancel")
        self.assertEqual(p.classify({"approve": facts}, {})["approve_once"]["status"], "unsupported")

    def test_wrapper_matching_is_literal_and_requires_single_exact_action(self):
        command = r"printf 'co03-sentinel\n' >> /probe/reject.sentinel"
        wrapped = r'''/bin/zsh -lc "printf 'co03-sentinel\\n' >> /probe/reject.sentinel"'''
        params = {"command": wrapped, "cwd": str(self.cwd), "kind": "command",
                  "commandActions": [{"type": "unknown", "command": command}]}
        self.assertTrue(p.approval_scope(params, command, self.cwd)["display_matches"])
        changes = [
            {"command": wrapped + "; extra"},
            {"command": wrapped.replace("/bin/zsh", "/bin/bash")},
            {"command": wrapped.replace(" -lc ", " -c ")},
            {"command": wrapped.replace("/probe/", "$(pwd)/probe/")},
            {"command": wrapped.replace("/probe/", "`pwd`/probe/")},
            {"command": wrapped.replace("sentinel\\\\n", "sentinel\\n")},
            {"command": wrapped.replace("reject.sentinel", "other.sentinel")},
            {"commandActions": []},
            {"commandActions": params["commandActions"] * 2},
            {"commandActions": [{"type": "unknown", "command": command + "; extra"}]},
            {"cwd": str(self.root)}, {"kind": None}, {"command": None},
        ]
        for change in changes:
            with self.subTest(change=change):
                scope = p.approval_scope({**params, **change}, command, self.cwd)
                self.assertFalse(scope["display_matches"])
                self.assertFalse(scope["complete"])
        verdict = p.classify({"reject": {"callback_seen": True, "callback_command_matches": False}}, {})
        self.assertEqual(verdict["reject_before_effect"], p.outcome("unsupported", "callback_command_not_matched"))

    def test_effect_after_reject_is_failure(self):
        facts, _ = self.case(fixture="effect")
        self.assertEqual(p.classify({"reject": facts}, {})["reject_before_effect"]["status"], "fail")

    def test_wrong_turn_gets_no_response(self):
        wire = self.wire("mismatch")
        wire.initialize()
        with self.assertRaisesRegex(p.Boundary, "callback_identity"):
            p.run_case(wire, self.cwd, self.root, "reject", 1, {})
        wire.close()
        self.assertFalse(any("result" in m for m in map(json.loads, (self.root / "stdin.raw").read_text().splitlines())))

    def test_config_drift_no_turn(self):
        wire = self.wire("drift")
        wire.initialize()
        with self.assertRaisesRegex(p.Boundary, "configuration_mismatch"):
            p.run_case(wire, self.cwd, self.root, "reject", 1, {})
        wire.close()
        self.assertNotIn('"turn/start"', (self.root / "stdin.raw").read_text())

    def test_receipt_and_terminal_do_not_prove_cessation(self):
        facts = {"interrupt_sent": True, "interrupt_receipt": True, "terminal_observed": True}
        verdict = p.classify({"stop": facts}, {})
        self.assertEqual(verdict["interrupt_receipt"]["status"], "pass")
        self.assertEqual(verdict["operation_cessation"]["status"], "unsupported")
        self.assertEqual(verdict["child_cessation"]["status"], "unsupported")
        facts.update(process_observation_complete=True, operation_gone_before_cleanup=True)
        verdict = p.classify({"stop": facts}, {})
        self.assertEqual(verdict["operation_cessation"]["status"], "pass")
        self.assertEqual(verdict["child_cessation"]["status"], "fail")

    def test_history_never_promotes_same_attempt(self):
        verdict = p.classify({}, {"requested": True, "same_thread": True, "original_terminal_turn_in_history": True})
        self.assertEqual(verdict["thread_history_rehydration"]["status"], "pass")
        self.assertEqual(verdict["same_attempt_resume"]["status"], "unsupported")

    def test_interrupted_terminal_with_live_host_parent_and_child_fails_cessation(self):
        wire = self.wire("stop-observed")
        wire.initialize()
        parent, child = 900001, 900002
        command = p.verified_interpreter() + " -I " + str(self.root / "bounded_action.py")
        rows = {parent: (wire.proc.pid, "parent-start", "Ss", command),
                child: (parent, "child-start", "S", "/bin/sleep 40")}
        facts = {}
        with patch.object(p, "process_table", return_value=rows), patch.object(p.os, "kill") as kill:
            p.run_case(wire, self.cwd, self.root, "stop", .4, facts)
        self.assertTrue(facts["terminal_interrupted"])
        self.assertTrue(facts["process_observation_complete"])
        self.assertTrue(facts["operation_started"])
        self.assertTrue(facts["child_started"])
        verdict = p.classify({"stop": facts}, {})
        self.assertEqual(verdict["interrupt_receipt"]["status"], "pass")
        for feature in ("operation_cessation", "child_cessation"):
            self.assertEqual(verdict[feature]["status"], "fail")
        self.assertEqual({call.args[0] for call in kill.call_args_list}, {parent, child})

    def test_version_and_no_escape_static(self):
        source = Path(p.__file__).read_text()
        literals = {n.value for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        for forbidden in ("accept", "acceptForSession", "danger-full-access", "never", "generate-json-schema"):
            self.assertNotIn(forbidden, literals)
        self.assertNotIn("co_v4", source)
        self.assertEqual(p.VERSION, b"codex-cli 0.156.1")
        self.assertEqual(p.config(self.cwd)["sandbox"], "read-only")

    def test_existing_output_refused_before_probe(self):
        records = self.root / "common-orchestration" / "design" / "0.3" / "records"
        records.mkdir(parents=True)
        path = records / "158-codex-existing.json"
        path.write_bytes(b"sentinel\n")
        probe_file = self.root / "common-orchestration" / "runtime_v4" / "probes" / "codex_live_control.py"
        with patch.object(sys, "argv", ["probe", "--probe", "--output", str(path)]), \
                patch.object(p, "__file__", str(probe_file)), \
                patch.object(p, "probe") as launch, patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                p.main()
        launch.assert_not_called()
        self.assertEqual(path.read_bytes(), b"sentinel\n")

    def test_noisy_frame_bounded(self):
        wire = self.wire(code='import sys,time; sys.stdout.write("x" * (3*1024*1024)); sys.stdout.flush(); time.sleep(10)')
        with self.assertRaisesRegex(p.Boundary, "stream_limit"):
            wire.read(time.monotonic() + 3)
        wire.close()
        self.assertLessEqual((self.root / "stdout.raw").stat().st_size, p.LIMIT)

    def test_duplicate_json_invalid(self):
        wire = self.wire(code='print(\'{"id":1,"id":2}\', flush=True)')
        with self.assertRaisesRegex(p.Boundary, "duplicate_json"):
            wire.read(time.monotonic() + 2)

    def test_sqlite_no_model_turn_no_secret_in_exception(self):
        wire = self.wire("sqlite")
        with self.assertRaisesRegex(p.Boundary, "native_eof") as exc:
            wire.initialize()
        wire.close()
        self.assertNotIn("SECRET", str(exc.exception))
        self.assertNotIn('"turn/start"', (self.root / "stdin.raw").read_text())

    def test_pid_identity_and_zombie(self):
        identity = (1, "time-a", "S", "command")
        self.assertFalse(p.identity_gone(7, identity, {7: identity}))
        self.assertTrue(p.identity_gone(7, identity, {7: (1, "time-b", "S", "command")}))
        self.assertTrue(p.identity_gone(7, identity, {7: (1, "time-a", "Z", "command")}))

    def test_process_scope_excludes_other_server(self):
        rows = {2: (1, "a", "S", "server"), 3: (2, "a", "S", "helper"),
                4: (3, "a", "S", "child"), 5: (1, "a", "S", "other")}
        self.assertTrue(p.descendant(4, 2, rows))
        self.assertFalse(p.descendant(5, 2, rows))

    def test_stop_preflight_failure_submits_no_action(self):
        wire = self.wire()
        with patch.object(p, "process_table", side_effect=p.Boundary("host_process_observation_unavailable")):
            with self.assertRaisesRegex(p.Boundary, "observation_unavailable"):
                p.run_case(wire, self.cwd, self.root, "stop", 1, {})
        wire.close()
        self.assertEqual((self.root / "stdin.raw").read_bytes(), b"")

    def test_watch_retains_reparented_child_and_excludes_other_processes(self):
        helper = self.root / "helper.py"
        helper.write_bytes(p.HELPER)
        watch = p.ProcessWatch(10, "python -I helper", helper, io.BytesIO())
        parent = (10, "start-parent", "S", "python -I helper")
        child = (20, "start-child", "S", "/bin/sleep 40")
        table = {10: (1, "server", "S", "server"), 20: parent, 21: child,
                 25: (1, "other", "S", "python -I helper")}
        with patch.object(p, "process_table", return_value=table):
            self.assertEqual(watch.sample(), (False, False))
            self.assertTrue(watch.ready())
        # Parent exited; child reparented to init. Do not lose its identity.
        with patch.object(p, "process_table", return_value={21: (1, *child[1:])}):
            self.assertEqual(watch.sample(), (True, False))
        with patch.object(p, "process_table", return_value={}):
            self.assertEqual(watch.sample(), (True, True))

    def test_ps_denial_is_sanitized_boundary(self):
        with patch.object(p.subprocess, "run", side_effect=PermissionError("SECRET")):
            with self.assertRaisesRegex(p.Boundary, "host_process_observation_unavailable"):
                p.process_table()

    def test_wire_timeout_reaps_owned_server(self):
        wire = self.wire(code="import time; time.sleep(10)")
        with self.assertRaisesRegex(p.Boundary, "rpc_timeout"):
            wire.rpc("initialize", {}, timeout=.03)
        wire.close()
        self.assertIsNotNone(wire.proc.poll())

    def test_full_collector_new_server_history_and_bounded_turns(self):
        real_wire = p.Wire
        servers = []

        def factory(argv, cwd, scratch):
            server = real_wire([sys.executable, "-u", "-c", FIXTURE, "reject"], cwd, scratch)
            servers.append(server)
            return server

        def preflight(argv, **kwargs):
            output = p.VERSION if argv[-1] == "--version" else b"Logged in using ChatGPT"
            return subprocess.CompletedProcess(argv, 0, output, b"")

        with patch.object(p.shutil, "which", return_value="fixture-codex"), \
                patch.object(p.subprocess, "run", side_effect=preflight), \
                patch.object(p, "Wire", side_effect=factory), \
                patch.object(p, "process_table", return_value={}), \
                patch.dict(os.environ, {k: "" for k in ("OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_BASE_URL")}):
            report = p.probe(self.root, timeout=1)
        self.assertEqual(report["boundary"], "bounded_cases_finished")
        self.assertEqual(len(servers), 4)
        self.assertTrue(all(s.proc.poll() is not None for s in servers))
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertEqual(report["capabilities"]["thread_history_rehydration"]["status"], "pass")
        self.assertEqual(report["capabilities"]["same_attempt_resume"]["status"], "unsupported")
        scratch = self.root / report["scratch_ref"]
        sent = [json.loads(line) for path in scratch.rglob("stdin.raw") for line in path.read_text().splitlines()]
        self.assertEqual(sum(m.get("method") == "turn/start" for m in sent), 3)
        self.assertEqual(sum(m.get("method") == "thread/resume" for m in sent), 1)

    def test_real_stop_fixture_parent_and_child(self):
        if os.environ.get("CO_CODEX_HOST_FIXTURE") != "1":
            self.skipTest("opt-in normal-host process-table fixture")
        facts, _ = self.case(mode="stop", timeout=5)
        for key in ("operation_started", "child_started", "interrupt_receipt",
                    "operation_gone_before_cleanup", "children_gone_before_cleanup"):
            self.assertTrue(facts[key], key)


if __name__ == "__main__":
    unittest.main()
