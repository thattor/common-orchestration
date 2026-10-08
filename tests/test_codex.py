"""Synthetic protocol tests. No model invocation, authentication or host proof."""
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from co_v4.adapters.codex import (
    ADAPTER, COMMAND_APPROVAL, FILE_APPROVAL, MAX_BYTES,
    CodexAdapter, NativeError, StdioTransport,
)
from co_v4.contracts import (
    AttemptRef, ConfirmationEvent, ConfirmationResponse, ExecuteRequest,
    ExecutionConditions, Job, OperationStatus as Op, Resolution, ResultEvent,
    ResumeState, State, StopStatus,
)


class Wire:
    def __init__(self):
        self.sent = []
        self.incoming = []
        self.live = True
        self.closed = 0
        self.fail_send = False

    def send(self, message):
        if self.fail_send:
            raise OSError("SECRET transport detail")
        self.sent.append(message)

    def poll(self):
        messages, self.incoming = self.incoming, []
        return tuple(messages)

    def alive(self):
        return self.live

    def close(self):
        self.closed += 1
        self.live = False

    def reply(self, method, result=None, error=None):
        sent = next(m for m in reversed(self.sent) if m.get("method") == method)
        self.incoming.append({"id": sent["id"],
                              **({"error": error} if error else {"result": result})})


class CodexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ref = AttemptRef("r", "j", "a")
        self.request = ExecuteRequest(
            self.ref, Job("r", "j", "Return synthetic text", ("text returned",), '{"x":1}'),
            ExecutionConditions("gpt-6-astra", ADAPTER, self.tmp.name, "env", ("controls",)))
        self.wire = Wire()
        self.checks = []
        self.now = 0
        self.adapter = CodexAdapter(verify_host=self.verify,
                                   transport_factory=lambda _: self.wire,
                                   clock=lambda: self.now, rpc_timeout=5)
        self.addCleanup(self.adapter.close)

    def verify(self, request, phase, native):
        # Explicit fixture bypass, not a real host verifier.
        self.checks.append((request, phase, native))

    def launch(self):
        self.assertEqual(self.adapter.execute(self.request).status, Op.ACCEPTED)
        self.wire.reply("initialize", {"userAgent": "fixture"})
        self.adapter.events(self.ref)

    def thread_result(self):
        return {"thread": {"id": "thread-private"}, "model": "gpt-6-astra",
                "modelProvider": "openai", "cwd": self.tmp.name,
                "approvalPolicy": "on-request", "approvalsReviewer": "user",
                "sandbox": {"type": "readOnly"}}

    def running(self):
        self.launch()
        self.wire.reply("thread/start", self.thread_result())
        self.adapter.events(self.ref)
        self.wire.reply("turn/start", {"turn": {"id": "turn-private", "status": "inProgress"}})
        self.assertEqual(self.adapter.status(self.ref).state, State.RUNNING)

    def callback(self, rpc_id=7, method=COMMAND_APPROVAL, **overrides):
        params = {"threadId": "thread-private", "turnId": "turn-private", "itemId": "same-item",
                  "startedAtMs": 1, "command": "printf fixture", "cwd": self.tmp.name,
                  "environmentId": "local", "approvalId": "private-approval", **overrides}
        message = {"id": rpc_id, "method": method, "params": params}
        self.wire.incoming.append(message)
        events = self.adapter.events(self.ref)
        confirmations = [e.confirmation for e in events if isinstance(e, ConfirmationEvent)]
        return confirmations[-1] if confirmations else None

    def answer(self, confirmation, resolution=Resolution.DENY):
        return ConfirmationResponse(self.ref, confirmation.request_id,
                                    confirmation.requested_action, resolution, "decision")

    def terminal(self, status="completed", **changes):
        self.wire.incoming.append({"method": "turn/completed", "params": {
            "threadId": "thread-private", "turn": {"id": "turn-private", "status": status, **changes}}})
        return self.adapter.events(self.ref)

    def test_default_refuses_even_with_evidence_strings(self):
        calls = []
        adapter = CodexAdapter(transport_factory=lambda r: calls.append(r))
        self.assertEqual(adapter.execute(self.request).status, Op.UNSUPPORTED)
        self.assertEqual(calls, [])

    def test_invalid_conditions_do_not_launch(self):
        for change in ({"adapter": "devin"}, {"model": ""}, {"workspace": "relative"},
                       {"environment_ref": ""}, {"control_evidence_refs": ()}):
            with self.subTest(change=change):
                request = replace(self.request, conditions=replace(self.request.conditions, **change))
                self.assertEqual(self.adapter.execute(request).status, Op.INVALID_STATE)
        self.assertFalse(self.wire.sent)

    def test_launch_mapping_and_effective_host_recheck(self):
        self.running()
        self.assertEqual([c[1] for c in self.checks], ["launch", "turn"])
        self.assertEqual(self.checks[1][2], self.thread_result())
        start = next(m for m in self.wire.sent if m.get("method") == "thread/start")
        self.assertEqual(start["params"]["sandbox"], "read-only")
        turn = next(m for m in self.wire.sent if m.get("method") == "turn/start")
        job = json.loads(turn["params"]["input"][0]["text"])
        self.assertEqual(job["context"], {"x": 1})
        self.assertEqual(job["acceptance_criteria"], ["text returned"])
        self.assertNotIn("controls", turn["params"]["input"][0]["text"])

    def test_configuration_drift_blocks_model_turn(self):
        self.launch()
        result = self.thread_result()
        result["approvalsReviewer"] = "auto_review"
        self.wire.reply("thread/start", result)
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        self.assertFalse(any(m.get("method") == "turn/start" for m in self.wire.sent))

    def test_host_recheck_failure_blocks_turn(self):
        self.launch()
        self.adapter._verify = lambda *args: (_ for _ in ()).throw(RuntimeError("SECRET"))
        self.wire.reply("thread/start", self.thread_result())
        events = self.adapter.events(self.ref)
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        self.assertNotIn("SECRET", repr(events))
        self.assertFalse(any(m.get("method") == "turn/start" for m in self.wire.sent))

    def test_duplicate_execute_never_submits_second_attempt(self):
        self.running()
        before = len(self.wire.sent)
        self.assertEqual(self.adapter.execute(self.request).status, Op.INVALID_STATE)
        self.assertEqual(len(self.wire.sent), before)

    def test_confirmation_unknown_scope_deny_only_and_exact_native_id(self):
        self.running()
        confirmation = self.callback(rpc_id="native-string-id")
        self.assertFalse(confirmation.requested_action.scope.known)
        self.assertNotEqual(confirmation.request_id, "native-string-id")
        self.assertEqual(self.adapter.respond(self.answer(confirmation, Resolution.ALLOW)).status, Op.INVALID_STATE)
        response = self.answer(confirmation)
        self.assertEqual(self.adapter.respond(response).status, Op.ACCEPTED)
        self.assertEqual(self.wire.sent[-1], {"id": "native-string-id", "result": {"decision": "decline"}})
        self.assertEqual(self.adapter.status(self.ref).state, State.WAITING_HUMAN)
        count = len(self.wire.sent)
        self.assertEqual(self.adapter.respond(response).status, Op.ACCEPTED)
        self.assertEqual(len(self.wire.sent), count)
        self.assertEqual(self.adapter.respond(replace(response, resolution=Resolution.CANCEL)).status, Op.INVALID_STATE)

    def test_multiple_callbacks_same_item_and_id_types_are_distinct(self):
        self.running()
        first = self.callback(7)
        second = self.callback("7", approvalId="second")
        self.assertNotEqual(first.request_id, second.request_id)
        self.adapter.respond(self.answer(first))
        self.wire.incoming.append({"method": "serverRequest/resolved", "params": {
            "threadId": "thread-private", "requestId": 7}})
        self.assertEqual(self.adapter.status(self.ref).state, State.WAITING_HUMAN)
        self.adapter.respond(self.answer(second, Resolution.CANCEL))
        self.assertEqual(self.wire.sent[-1], {"id": "7", "result": {"decision": "cancel"}})

    def test_duplicate_callback_no_duplicate_event_changed_target_errors(self):
        self.running()
        confirmation = self.callback()
        self.assertEqual(self.callback().request_id, confirmation.request_id)
        self.assertEqual(len([e for e in self.adapter.events(self.ref) if isinstance(e, ConfirmationEvent)]), 1)
        self.callback(command="different command")
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_cross_callback_target_and_unknown_resolution_rejected(self):
        self.running()
        first = self.callback(1)
        second = self.callback(2, command="different")
        answer = self.answer(first)
        for response in (replace(answer, request_id=second.request_id),
                         replace(answer, decision_ref=""), replace(answer, resolution="allow"),
                         replace(answer, ref=AttemptRef("other", "j", "a"))):
            self.assertEqual(self.adapter.respond(response).status, Op.INVALID_STATE)

    def test_file_confirmation_never_approves_missing_content(self):
        self.running()
        c = self.callback(method=FILE_APPROVAL, grantRoot="/")
        self.assertFalse(c.requested_action.scope.known)
        self.assertEqual(self.adapter.respond(self.answer(c, Resolution.ALLOW)).status, Op.INVALID_STATE)
        self.assertEqual(self.adapter.respond(self.answer(c, Resolution.CANCEL)).status, Op.ACCEPTED)
        self.assertEqual(self.wire.sent[-1]["result"], {"decision": "cancel"})

    def test_callback_before_turn_start_receipt_is_correlated(self):
        self.launch()
        self.wire.reply("thread/start", self.thread_result())
        self.adapter.events(self.ref)
        c = self.callback()
        self.assertIsNotNone(c)
        self.wire.reply("turn/start", {"turn": {"id": "turn-private", "status": "inProgress"}})
        self.assertEqual(self.adapter.status(self.ref).state, State.WAITING_HUMAN)

    def test_unknown_request_errors_without_allow(self):
        self.running()
        self.callback(method="item/permissions/requestApproval")
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        self.assertEqual(self.wire.sent[-1]["error"]["code"], -32601)

    def test_mismatched_callback_cannot_be_answered(self):
        self.running()
        self.assertIsNone(self.callback(threadId="other-thread"))
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_delivery_unknown_is_never_retried_or_reported_accepted(self):
        self.running()
        c = self.callback()
        self.wire.fail_send = True
        response = self.answer(c)
        self.assertEqual(self.adapter.respond(response).status, Op.ERROR)
        self.wire.fail_send = False
        before = len(self.wire.sent)
        self.assertEqual(self.adapter.respond(response).status, Op.ERROR)
        self.assertEqual(len(self.wire.sent), before)

    def test_resolved_callback_rejects_late_answer(self):
        self.running()
        c = self.callback()
        self.wire.incoming.append({"method": "serverRequest/resolved", "params": {
            "threadId": "thread-private", "requestId": 7}})
        self.assertEqual(self.adapter.respond(self.answer(c)).status, Op.INVALID_STATE)

    def test_stop_before_turn_latches_without_poll_starting_work(self):
        self.launch()
        self.wire.reply("thread/start", self.thread_result())
        first = self.adapter.stop(self.ref)
        self.assertEqual(first.status, StopStatus.CONFIRMED)
        self.assertEqual(self.adapter.stop(self.ref), first)
        self.assertEqual(self.wire.closed, 1)
        self.assertFalse(any(m.get("method") == "turn/start" for m in self.wire.sent))

    def test_stop_receipt_distinct_from_turn_end_and_tool_cessation(self):
        self.running()
        self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        self.assertEqual(self.wire.sent[-1]["params"], {"threadId": "thread-private", "turnId": "turn-private"})
        self.wire.reply("turn/interrupt", {})
        self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.REQUESTED)
        self.terminal("interrupted")
        self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        self.assertEqual(sum(m.get("method") == "turn/interrupt" for m in self.wire.sent), 1)
        self.assertEqual(self.adapter.status(self.ref).state, State.FAILED)

    def test_stop_before_turn_id_sends_once_when_known(self):
        self.launch()
        self.wire.reply("thread/start", self.thread_result())
        self.adapter.events(self.ref)
        self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        self.wire.reply("turn/start", {"turn": {"id": "turn-private", "status": "inProgress"}})
        self.adapter.events(self.ref)
        self.assertEqual(self.wire.sent[-1]["method"], "turn/interrupt")

    def test_stop_error_and_disconnect_never_confirm(self):
        self.running()
        self.adapter.stop(self.ref)
        self.wire.reply("turn/interrupt", error={"code": 1, "message": "SECRET"})
        self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        self.wire.live = False
        self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        result = next(e.result for e in self.adapter.events(self.ref) if isinstance(e, ResultEvent))
        self.assertEqual(result.reason, "native_transport_lost")

    def test_events_stable_exclusive_cursor_unknown_errors(self):
        self.running()
        first = self.adapter.events(self.ref)
        self.assertEqual(self.adapter.events(self.ref), first)
        self.assertEqual(self.adapter.events(self.ref, first[-1].event_id), ())
        with self.assertRaises(ValueError):
            self.adapter.events(self.ref, "bad")
        unknown = AttemptRef("unknown", "j", "a")
        with self.assertRaises(ValueError):
            self.adapter.status(unknown)
        self.assertEqual(self.adapter.stop(unknown).status, StopStatus.ERROR)

    def test_result_completion_separate_from_ac_and_no_raw_secrets(self):
        self.running()
        events = self.terminal(items=[{"text": "SECRET"}])
        result = next(e.result for e in events if isinstance(e, ResultEvent))
        self.assertEqual(result.status, State.COMPLETED)
        self.assertIsNone(result.reason)
        self.assertNotIn("SECRET", repr(events))
        self.assertEqual(self.adapter.events(self.ref), events)

    def test_provider_failure_is_infrastructure_error_not_model_ac_failure(self):
        self.running()
        events = self.terminal("failed", error={"message": "SECRET", "codexErrorInfo": "usageLimitExceeded"})
        result = next(e.result for e in events if isinstance(e, ResultEvent))
        self.assertEqual((result.status, result.reason), (State.ERROR, "native_turn_failed"))
        self.assertNotIn("SECRET", repr(events))

    def test_unknown_native_status_fails_closed(self):
        self.running()
        self.terminal("invented")
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_timeout_and_malformed_responses_fail_closed(self):
        self.launch()
        self.now = 6
        events = self.adapter.events(self.ref)
        self.assertEqual(next(e.result.reason for e in events if isinstance(e, ResultEvent)), "native_rpc_timeout")

    def test_unmatched_rpc_id_is_not_success(self):
        self.launch()
        self.wire.incoming.append({"id": "unknown", "result": {}})
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_resume_and_usage_explicitly_unavailable(self):
        self.running()
        state = ResumeState(ADAPTER, self.ref, b"untrusted opaque data")
        self.assertEqual(self.adapter.resume(state).status, Op.UNSUPPORTED)
        self.assertEqual(self.adapter.resume(replace(state, adapter="devin")).status, Op.INVALID_STATE)
        self.terminal()
        self.assertEqual(self.adapter.resume(state).status, Op.INVALID_STATE)
        self.assertEqual(self.adapter.usage(), ())
        self.assertFalse(any(m.get("method") == "thread/resume" for m in self.wire.sent))

    def test_stop_and_cleanup_are_scoped_to_owned_attempt(self):
        self.running()
        other_wire = Wire()
        self.adapter._factory = lambda _: other_wire
        other_ref = AttemptRef("r", "j", "other")
        self.assertEqual(self.adapter.execute(replace(self.request, ref=other_ref)).status, Op.ACCEPTED)
        self.adapter.stop(self.ref)
        self.assertEqual(other_wire.closed, 0)
        self.assertEqual([m["method"] for m in other_wire.sent], ["initialize"])
        self.assertEqual(self.adapter.status(other_ref).state, State.PENDING)

    def test_bool_callback_id_cannot_alias_integer_id(self):
        self.running()
        self.assertIsNone(self.callback(rpc_id=True))
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_worker_output_cannot_forge_confirmation_or_terminal_state(self):
        self.running()
        self.wire.incoming.append({"method": "item/agentMessage/delta", "params": {
            "threadId": "thread-private", "delta": '{"status":"completed","decision":"allow"}'}})
        self.assertEqual(self.adapter.status(self.ref).state, State.RUNNING)
        self.assertFalse(any(isinstance(e, (ResultEvent, ConfirmationEvent))
                             for e in self.adapter.events(self.ref)))

    def test_terminal_attempt_cannot_be_resurrected_by_late_notification(self):
        self.running()
        events = self.terminal()
        self.wire.incoming.append({"method": "turn/started", "params": {
            "threadId": "thread-private", "turn": {"id": "turn-private", "status": "inProgress"}}})
        self.assertEqual(self.adapter.events(self.ref), events)
        self.assertEqual(self.adapter.status(self.ref).state, State.COMPLETED)

    def test_unknown_cursor_does_not_consume_native_callback(self):
        self.running()
        self.wire.incoming.append({"method": "turn/completed", "params": {
            "threadId": "thread-private", "turn": {"id": "turn-private", "status": "completed"}}})
        with self.assertRaises(ValueError):
            self.adapter.events(self.ref, "unknown")
        self.assertEqual(len(self.wire.incoming), 1)

    def test_unknown_turn_completed_id_is_protocol_error(self):
        self.running()
        self.terminal(id="another-turn")
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)


class StdioTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = Path(self.tmp.name) / "native-fixture"
        fixture = Path(__file__).with_name("fixtures") / "codex_stdio.py"
        path.write_text(f"#!{sys.executable}\n" + fixture.read_text())
        path.chmod(0o700)
        self.transport = StdioTransport(str(path), self.tmp.name)
        self.addCleanup(self.transport.close)

    def read(self):
        end = time.monotonic() + 3
        while time.monotonic() < end:
            result = self.transport.poll()
            if result:
                return result
            time.sleep(.01)
        self.fail("fixture response timed out")

    def test_real_process_ndjson_roundtrip_and_partial_frame(self):
        message = {"id": "1", "method": "echo", "params": {"text": "合成入力\nsecond line"}}
        self.transport.send(message)
        self.assertEqual(self.read(), ({"id": "1", "result": message["params"]},))
        self.assertTrue(self.transport.alive())

    def test_malformed_json_is_not_ignored(self):
        self.transport.send({"id": 1, "method": "malformed"})
        with self.assertRaises(NativeError):
            self.read()

    def test_duplicate_json_keys_rejected(self):
        self.transport.send({"id": 1, "method": "duplicate"})
        with self.assertRaises(NativeError):
            self.read()

    def test_write_limit_and_owned_process_cleanup(self):
        with self.assertRaises(NativeError):
            self.transport.send({"text": "x" * MAX_BYTES})
        self.transport.close()
        self.assertFalse(self.transport.alive())


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def stub(self, version, exit_code=0):
        path = self.root / "native-version-fixture"
        marker = self.root / "launched"
        path.write_text(f"#!{sys.executable}\nimport sys,json\nfrom pathlib import Path\n"
            f"if sys.argv[1:] == ['--version']:\n print({version!r})\n raise SystemExit({exit_code})\n"
            f"Path({str(marker)!r}).write_text('owned fixture started')\n"
            "for line in sys.stdin:\n m=json.loads(line)\n print(json.dumps({'id':m['id'],'result':m['params']}),flush=True)\n")
        path.chmod(0o700)
        return path, marker

    def test_both_exact_versions_launch_and_preserve_observed_identity(self):
        for version in ("codex-cli 0.156.1", "codex-cli 0.159.2"):
            with self.subTest(version=version):
                path, marker = self.stub(version)
                with_marker = marker.exists()
                if with_marker:
                    marker.unlink()
                transport = StdioTransport(str(path), self.tmp.name)
                try:
                    self.assertEqual(transport.native_version, version)
                    transport.send({"id": "fixture", "method": "echo", "params": {"bounded": True}})
                    end = time.monotonic() + 3
                    replies = ()
                    while not replies and time.monotonic() < end:
                        replies = transport.poll()
                        time.sleep(.01)
                    self.assertEqual(replies, ({"id": "fixture", "result": {"bounded": True}},))
                    self.assertTrue(marker.exists())
                finally:
                    transport.close()
                self.assertFalse(transport.alive())

    def test_unknown_or_misleading_version_never_starts_app_server(self):
        for version in ("codex-cli 0.159.1", "codex-cli 0.159.20", "codex-cli 0.160.0",
                        "codex-cli 0.159.2-alpha.1", "codex-cli 0.159.2 extra", ""):
            with self.subTest(version=version):
                path, marker = self.stub(version)
                with self.assertRaisesRegex(NativeError, "^unsupported CLI version$"):
                    StdioTransport(str(path), self.tmp.name)
                self.assertFalse(marker.exists())

    def test_failed_version_command_never_starts_app_server(self):
        path, marker = self.stub("codex-cli 0.159.2", exit_code=1)
        with self.assertRaisesRegex(NativeError, "^unsupported CLI version$"):
            StdioTransport(str(path), self.tmp.name)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
