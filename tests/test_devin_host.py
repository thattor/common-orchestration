"""Host/Adapter integration fixtures; live Native is a separate gate."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4.contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job, State
from co_v4.delegation import DelegatedScope
from co_v4.devin_host import DevinHostConfig, DevinTextHost


class Wire:
    def __init__(self):
        self.sent = []
        self.messages = []
        self.closed = False
        self.mode = "plan"
        self.tool = False
    def send(self, m):
        self.sent.append(m)
        if m.get("method") == "initialize":
            result = {"protocolVersion": 1}
        elif m.get("method") == "session/new":
            result = {"sessionId": "fixture-session", "modes": {
                "currentModeId": self.mode, "availableModes": [{"id": self.mode}]}}
        elif m.get("method") == "session/prompt":
            if self.tool:
                self.messages.append({"jsonrpc": "2.0", "method": "session/update", "params": {
                    "sessionId": "fixture-session", "update": {"sessionUpdate": "tool_call"}}})
            result = {"stopReason": "end_turn"}
        else: return
        self.messages.append({"jsonrpc": "2.0", "id": m["id"], "result": result})
    def poll(self):
        result, self.messages = tuple(self.messages), []
        return result
    def alive(self): return not self.closed
    def close(self): self.closed = True


class DevinHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.worker = self.root / "worker"
        self.worker.mkdir()
        self.state = self.root / "control.db"
        self.state.write_text("control")
        self.credential = self.root / "auth"
        self.credential.write_text("fixture-only")
        self.executable = self.root / "devin"
        self.executable.write_text("pinned executable fixture")
        conditions = ExecutionConditions("swe-1-6", "devin.acp", str(self.worker), "env", ("controls",))
        self.request = ExecuteRequest(AttemptRef("r", "j", "a"), Job("r", "j", "respond", ()), conditions)
        delegation = DelegatedScope("intent", self.request.ref, str(self.worker), "devin.text.only")
        self.host = DevinTextHost(DevinHostConfig(conditions, self.executable, "fixture-version",
                                  (self.state,), (self.credential,), delegation))
        self.wire = Wire()
        for name, value in (("platform.system", "Darwin"), ("platform.machine", "arm64")):
            patcher = patch(name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch("co_v4.devin_host.AcpTransport", return_value=self.wire)
        self.factory = patcher.start()
        self.addCleanup(patcher.stop)
        self.adapter = self.host.make_adapter()
        self.addCleanup(self.adapter.close)

    def run_attempt(self):
        self.reply = self.adapter.execute(self.request)
        for _ in range(5): self.adapter.events(self.request.ref)

    def test_bound_text_execute_through_events_and_result(self):
        self.run_attempt()
        self.assertEqual(self.adapter.status(self.request.ref).state, State.COMPLETED)
        self.assertTrue(self.host.observation["native_handoff_verified"])
        prompt = next(m for m in self.wire.sent if m.get("method") == "session/prompt")
        payload = json.loads(prompt["params"]["prompt"][0]["text"])
        self.assertEqual(payload["delegation"]["capability"], "devin.text.only")
        self.assertEqual(payload["delegation"]["attempt_id"], "a")
        initialize = self.wire.sent[0]
        self.assertFalse(initialize["params"]["clientCapabilities"]["terminal"])
        session = next(m for m in self.wire.sent if m.get("method") == "session/new")
        self.assertEqual(session["params"]["mcpServers"], [])
        self.assertEqual(self.factory.call_args.kwargs["expected_version"], "fixture-version")
        self.assertNotIn("GH_TOKEN", self.factory.call_args.kwargs["environ"])

    def test_mode_drift_blocks_prompt(self):
        self.wire.mode = "accept-edits"
        self.run_attempt()
        self.assertEqual(self.adapter.status(self.request.ref).state, State.ERROR)
        self.assertFalse(any(m.get("method") == "session/prompt" for m in self.wire.sent))
        self.assertFalse(self.host.observation["native_handoff_verified"])

    def test_tool_event_cannot_complete_text_only_route(self):
        self.wire.tool = True
        self.run_attempt()
        self.assertEqual(self.adapter.status(self.request.ref).state, State.ERROR)
        self.assertEqual(self.host._transport.tool_events, 1)

    def test_preflight_driver_independently_blocks_model_turn(self):
        from probes.devin_host_preflight import run
        receipt = run(self.root / "probe", executable=self.executable,
            native_version="fixture-version", model="swe-1-6",
            credential_files=(self.credential,), human_intent_ref="intent")
        self.assertTrue(receipt["observation"]["native_handoff_verified"])
        self.assertEqual(receipt["model_turns_submitted"], 0)
        self.assertTrue(receipt["model_turn_blocked_by_probe"])
        self.assertTrue(receipt["control_store_unchanged"])
        self.assertTrue(receipt["owned_native_reaped"])
        self.assertFalse(any(m.get("method") == "session/prompt" for m in self.wire.sent))

    def test_cross_attempt_request_refused_before_launch(self):
        wrong = replace(self.request, ref=AttemptRef("r", "j", "b"))
        reply = self.adapter.execute(wrong)
        self.assertEqual(reply.status.value, "unsupported")
        self.factory.assert_not_called()

    def test_changed_target_refused_before_model_submission(self):
        self.adapter.execute(self.request)
        self.executable.write_text("different bytes")
        for _ in range(4): self.adapter.events(self.request.ref)
        self.assertEqual(self.adapter.status(self.request.ref).state, State.ERROR)
        self.assertFalse(any(m.get("method") == "session/prompt" for m in self.wire.sent))
