"""Offline subprocess tests; never invoke Codex, auth, or a model."""
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest

from probes.codex_live_boundary import capture, INITIALIZE, LIMIT


class BoundaryTests(unittest.TestCase):
    def run_child(self, code, deadline=2):
        with tempfile.TemporaryDirectory() as root:
            scratch = Path(root)
            cwd = scratch / "empty"
            cwd.mkdir()
            report = capture([sys.executable, "-u", "-c", code], cwd, scratch, deadline)
            raw = {p.name: p.read_bytes() for p in scratch.iterdir() if p.is_file()}
            self.assertTrue(report["owned_process_reaped"])
            self.assertEqual(json.loads(raw["stdin.jsonl"]), INITIALIZE)
            self.assertEqual(raw["stdin.jsonl"].count(b"\n"), 1)
            self.assertFalse(any(cwd.iterdir()))
            for p in scratch.iterdir():
                if p.is_file():
                    self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            return report, raw

    def test_initialize_keeps_stdin_open_and_never_submits_turn(self):
        report, _ = self.run_child('''
import json, select, sys, time
request = json.loads(sys.stdin.readline())
assert not select.select([sys.stdin], [], [], .05)[0], "stdin closed prematurely"
print(json.dumps({"id": request["id"], "result": {"private": "CANARY"}}), flush=True)
time.sleep(10)
''')
        self.assertTrue(report["initialize_response_seen"])
        self.assertEqual(report["boundary"], "host_confinement_and_interception_unverified")
        self.assertNotIn("CANARY", json.dumps(report))

    def test_sqlite_failure_is_preserved_without_sensitive_error(self):
        report, raw = self.run_child('''
import sys
sys.stdin.readline()
sys.stderr.write("failed to initialize sqlite state runtime: PRIVATE-CANARY\\n")
sys.exit(1)
''')
        self.assertEqual(report["boundary"], "native_sqlite_initialization_failed_before_initialize")
        self.assertFalse(report["initialize_response_seen"])
        self.assertIn(b"PRIVATE-CANARY", raw["stderr.raw"])
        self.assertNotIn("PRIVATE-CANARY", json.dumps(report))

    def test_unexpected_request_never_gets_approval(self):
        report, _ = self.run_child('''
import json, sys, time
sys.stdin.readline()
print(json.dumps({"id": 7, "method": "item/commandExecution/requestApproval",
                  "params": {"command": "outside scope"}}), flush=True)
time.sleep(10)
''')
        self.assertTrue(report["unexpected_request_seen"])
        self.assertFalse(report["approval_response_sent"])
        self.assertEqual(report["boundary"], "unexpected_request_no_approval_sent")

    def test_timeout_reaps_process_without_claiming_tool_cessation(self):
        report, _ = self.run_child("import time; time.sleep(10)", deadline=.1)
        self.assertEqual(report["boundary"], "initialize_timeout")
        self.assertNotIn("confirmed_tool_cessation", report)

    def test_noisy_native_is_bounded(self):
        report, raw = self.run_child('''
import sys, time
sys.stdin.readline()
sys.stdout.write("x" * (2 * 1024 * 1024))
sys.stdout.flush()
time.sleep(10)
''')
        self.assertEqual(report["boundary"], "stream_limit")
        self.assertLessEqual(len(raw["stdout.raw"]), LIMIT)

    def test_malformed_frame_stops_without_turn(self):
        report, _ = self.run_child('''
import sys, time
sys.stdin.readline()
print("not-json", flush=True)
time.sleep(10)
''')
        self.assertEqual(report["boundary"], "invalid_native_frame")


if __name__ == "__main__":
    unittest.main()
