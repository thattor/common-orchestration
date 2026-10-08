"""Synthetic ACP protocol tests. No model invocation, authentication or host proof."""
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from co_v4.adapters.devin import (
    ADAPTER, MAX_BYTES, MAX_POLL, AcpTransport, DevinAdapter, NativeError,
    scrub_environment,
)
from co_v4.contracts import (
    AttemptRef, ConfirmationEvent, ConfirmationResponse, ExecuteRequest,
    ExecutionConditions, Job, NeverStarted, OperationStatus as Op, Resolution,
    ResultEvent, ResumeState, State, StopStatus,
)


class Wire:
    def __init__(self):
        self.sent = []
        self.incoming = []
        self.live = True
        self.closed = 0
        self.fail_send = False
        self.cap = None
        self.flood = False
        self.on_send = None

    def send(self, message):
        if self.on_send is not None:
            self.on_send(message)
        if self.fail_send:
            raise OSError("SECRET transport detail")
        self.sent.append(message)

    def poll(self):
        if self.flood:
            return tuple({"jsonrpc": "2.0", "method": "session/update",
                          "params": {"sessionId": "sess-private", "update": {
                              "sessionUpdate": "agent_message_chunk",
                              "content": {"type": "text", "text": "chunk"}}}}
                         for _ in range(MAX_POLL))
        if self.cap is None:
            messages, self.incoming = self.incoming, []
        else:
            messages = self.incoming[:self.cap]
            self.incoming = self.incoming[self.cap:]
        return tuple(messages)

    def alive(self):
        return self.live

    def close(self):
        self.closed += 1
        self.live = False

    def reply(self, method, result=None, error=None):
        sent = next(m for m in reversed(self.sent) if m.get("method") == method)
        self.incoming.append({"jsonrpc": "2.0", "id": sent["id"],
                              **({"error": error} if error else {"result": result})})


class DevinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ref = AttemptRef("r", "j", "a")
        self.request = ExecuteRequest(
            self.ref, Job("r", "j", "Return synthetic text", ("text returned",), '{"x":1}'),
            ExecutionConditions("swe-2-high", ADAPTER, self.tmp.name, "env", ("controls",)))
        # One private transport per Attempt, matching production isolation:
        # closing an owned process must not affect unrelated attempts.
        self.wires = []
        self.wire = None
        self.checks = []
        self.now = 0
        self.adapter = DevinAdapter(verify_host=self.verify,
                                    transport_factory=self._factory,
                                    clock=lambda: self.now, rpc_timeout=5,
                                    desired_mode="accept-edits")
        self.addCleanup(self.adapter.close)

    def _factory(self, _request):
        self.wire = Wire()
        self.wires.append(self.wire)
        return self.wire

    def verify(self, request, phase, native):
        # Explicit fixture bypass, not a real host verifier.
        self.checks.append((request, phase, native))

    def config_options(self, mode="accept-edits", available=None):
        return [{"id": "mode", "name": "Mode", "type": "select",
                 "currentValue": mode, "options": [
                     {"value": value, "name": value} for value in
                     (available if available is not None else
                      ["accept-edits", "smart", "ask", "plan", "bypass"]) ]}]

    def session_result(self, mode="accept-edits", available=None):
        return {"sessionId": "sess-private",
                "configOptions": self.config_options(mode, available)}

    def update(self, mode=None, *, session="sess-private", config=False):
        update = ({"sessionUpdate": "config_option_update",
                   "configOptions": self.config_options(mode)} if config else
                  {"sessionUpdate": "current_mode_update", "currentModeId": mode})
        self.wire.incoming.append({"jsonrpc": "2.0", "method": "session/update",
                                   "params": {"sessionId": session, "update": update}})

    def progress(self, count=1, *, session="sess-private"):
        for _ in range(count):
            self.wire.incoming.append({"jsonrpc": "2.0",
                "method": "session/update", "params": {
                    "sessionId": session, "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "content": {"type": "text", "text": "chunk"}}}})

    def desired(self, mode):
        self.adapter.close()
        self.adapter = DevinAdapter(verify_host=self.verify,
                                    transport_factory=self._factory,
                                    clock=lambda: self.now, rpc_timeout=5,
                                    desired_mode=mode)
        self.addCleanup(self.adapter.close)

    def no_more_sends(self, before):
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        self.adapter.stop(self.ref)
        self.adapter.resume(ResumeState(ADAPTER, self.ref, b"opaque"))
        self.assertEqual(len(self.wire.sent), before)
        self.assertFalse(any(m.get("method") == "session/load" for m in self.wire.sent))

    def launch(self):
        self.assertEqual(self.adapter.execute(self.request).status, Op.ACCEPTED)
        self.wire.reply("initialize", {"protocolVersion": 1, "agentCapabilities": {},
                                       "authMethods": []})
        self.adapter.events(self.ref)

    def running(self):
        self.launch()
        self.update("accept-edits", config=True)
        self.wire.reply("session/new", self.session_result())
        self.adapter.events(self.ref)
        self.assertEqual(self.adapter.status(self.ref).state, State.RUNNING)

    def callback(self, rpc_id=7, method="session/request_permission", **overrides):
        params = {"sessionId": "sess-private",
                  "toolCall": {"toolCallId": "tc-1", "title": "exec git push",
                               "kind": "execute", "status": "pending",
                               "rawInput": {"command": "git push"},
                               "locations": [{"path": "/fixture"}]},
                  "options": [{"optionId": "o-allow", "name": "Allow", "kind": "allow_once"},
                              {"optionId": "o-always", "name": "Always", "kind": "allow_always"},
                              {"optionId": "o-reject", "name": "Reject", "kind": "reject_once"}],
                  **overrides}
        self.wire.incoming.append({"jsonrpc": "2.0", "id": rpc_id,
                                   "method": method, "params": params})
        events = self.adapter.events(self.ref)
        confirmations = [e.confirmation for e in events if isinstance(e, ConfirmationEvent)]
        return confirmations[-1] if confirmations else None

    def answer(self, confirmation, resolution=Resolution.DENY):
        return ConfirmationResponse(self.ref, confirmation.request_id,
                                    confirmation.requested_action, resolution, "decision")

    def prompt_end(self, stop_reason="end_turn"):
        self.wire.reply("session/prompt", {"stopReason": stop_reason})
        return self.adapter.events(self.ref)

    def test_default_refuses_even_with_evidence_strings(self):
        calls = []
        adapter = DevinAdapter(transport_factory=lambda r: calls.append(r))
        self.assertEqual(adapter.execute(self.request).status, Op.UNSUPPORTED)
        self.assertEqual(calls, [])

    def test_invalid_conditions_do_not_launch(self):
        for change in ({"adapter": "codex"}, {"model": ""}, {"workspace": "relative"},
                       {"environment_ref": ""}, {"control_evidence_refs": ()}):
            with self.subTest(change=change):
                request = replace(self.request, conditions=replace(self.request.conditions, **change))
                self.assertEqual(self.adapter.execute(request).status, Op.INVALID_STATE)
        self.assertFalse(self.wires)

    def test_launch_mapping_and_effective_host_recheck(self):
        self.running()
        self.assertEqual([c[1] for c in self.checks], ["launch", "session"])
        self.assertEqual(self.checks[1][2], self.session_result())
        init = next(m for m in self.wire.sent if m.get("method") == "initialize")
        self.assertEqual(init["params"]["protocolVersion"], 1)
        self.assertEqual(init["params"]["clientCapabilities"],
                         {"fs": {"readTextFile": False, "writeTextFile": False},
                          "terminal": False})
        new = next(m for m in self.wire.sent if m.get("method") == "session/new")
        self.assertEqual(new["params"], {"cwd": self.tmp.name, "mcpServers": []})
        prompt = next(m for m in self.wire.sent if m.get("method") == "session/prompt")
        job = json.loads(prompt["params"]["prompt"][0]["text"])
        self.assertEqual(job["context"], {"x": 1})
        self.assertEqual(job["acceptance_criteria"], ["text returned"])
        self.assertNotIn("controls", prompt["params"]["prompt"][0]["text"])

    def test_protocol_version_mismatch_blocks_session(self):
        self.assertEqual(self.adapter.execute(self.request).status, Op.ACCEPTED)
        self.wire.reply("initialize", {"protocolVersion": 2})
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        self.assertFalse(any(m.get("method") == "session/new" for m in self.wire.sent))

    def test_absent_or_mismatched_mode_blocks_prompt(self):
        for i, result in enumerate(({"sessionId": "s0"}, self.session_result("bypass", ["bypass"]))):
            with self.subTest(result=result):
                ref = AttemptRef("r", "j", f"a{i}")
                self.assertEqual(self.adapter.execute(replace(self.request, ref=ref)).status,
                                 Op.ACCEPTED)
                self.wire.reply("initialize", {"protocolVersion": 1})
                self.adapter.events(ref)
                self.wire.reply("session/new", result)
                self.assertEqual(self.adapter.status(ref).state, State.ERROR)
        self.assertFalse(any(m.get("method") == "session/prompt" for m in self.wire.sent))

    def test_pre_session_updates_across_polls_are_buffered(self):
        self.launch()
        self.update("accept-edits", config=True)
        self.assertEqual(self.adapter.status(self.ref).state, State.PENDING)
        self.assertEqual([c[1] for c in self.checks], ["launch"])
        self.wire.reply("session/new", {"sessionId": "sess-private"})
        self.assertEqual(self.adapter.status(self.ref).state, State.RUNNING)
        self.assertEqual(self.checks[-1][2], self.session_result())

    def test_cross_session_pre_update_and_new_result_fail(self):
        self.launch()
        self.update("accept-edits", session="foreign", config=True)
        self.wire.reply("session/new", self.session_result())
        self.no_more_sends(len(self.wire.sent))
        self.assertEqual([c[1] for c in self.checks], ["launch"])

    def test_cross_session_candidates_fail_before_result(self):
        self.launch()
        self.update("accept-edits", config=True)
        self.adapter.events(self.ref)
        self.update("accept-edits", session="foreign", config=True)
        self.no_more_sends(len(self.wire.sent))

    def test_pre_session_buffer_is_bounded_across_polls(self):
        self.launch()
        for _ in range(128):
            self.update("accept-edits", config=True)
            self.adapter.events(self.ref)
        self.update("accept-edits", config=True)
        self.no_more_sends(len(self.wire.sent))

    def test_plan_switch_uses_config_api_and_effective_host_evidence(self):
        self.desired("plan")
        self.launch()
        self.update("accept-edits", config=True)
        self.wire.reply("session/new", self.session_result())
        self.assertEqual(self.adapter.status(self.ref).state, State.PENDING)
        self.assertEqual(self.wire.sent[-1]["method"], "session/set_config_option")
        self.assertEqual(self.wire.sent[-1]["params"],
                         {"sessionId": "sess-private", "configId": "mode", "value": "plan"})
        self.assertEqual([c[1] for c in self.checks], ["launch"])
        self.wire.reply("session/set_config_option", {"configOptions": self.config_options("plan")})
        self.assertEqual(self.adapter.status(self.ref).state, State.RUNNING)
        self.assertEqual(self.checks[-1][2], self.session_result("plan"))
        self.assertEqual(self.wire.sent[-1]["method"], "session/prompt")

    def switch_pending(self):
        self.desired("plan")
        self.launch()
        self.wire.reply("session/new", self.session_result())
        self.adapter.events(self.ref)

    def test_switch_notification_can_confirm_empty_receipt(self):
        self.switch_pending()
        self.update("plan")
        self.wire.reply("session/set_config_option", {})
        self.assertEqual(self.adapter.status(self.ref).state, State.RUNNING)
        self.assertEqual(self.checks[-1][2], self.session_result("plan"))

    def test_switch_response_then_confirmation_same_batch(self):
        self.switch_pending()
        self.wire.reply("session/set_config_option", {})
        self.update("plan", config=True)
        self.assertEqual(self.adapter.status(self.ref).state, State.RUNNING)

    def test_switch_error_even_after_notification_blocks_prompt(self):
        self.switch_pending()
        self.update("plan")
        self.wire.reply("session/set_config_option", error={"code": -1})
        self.no_more_sends(len(self.wire.sent))
        self.assertEqual([c[1] for c in self.checks], ["launch"])

    def test_switch_empty_unconfirmed_receipt_blocks_prompt(self):
        self.switch_pending()
        self.wire.reply("session/set_config_option", {})
        self.no_more_sends(len(self.wire.sent))

    def test_switch_wrong_current_mode_blocks_prompt(self):
        self.switch_pending()
        self.wire.reply("session/set_config_option", {"configOptions": self.config_options("ask")})
        self.no_more_sends(len(self.wire.sent))

    def test_switch_timeout_blocks_prompt(self):
        self.switch_pending()
        self.now = 6
        self.no_more_sends(len(self.wire.sent))

    def test_advertised_modes_without_config_api_cannot_switch(self):
        self.desired("plan")
        self.launch()
        self.wire.reply("session/new", {"sessionId": "sess-private", "modes": {
            "currentModeId": "accept-edits", "availableModes": [
                {"id": "accept-edits"}, {"id": "plan"}]}})
        self.no_more_sends(len(self.wire.sent))

    def test_desired_mode_must_be_advertised_even_if_current_matches(self):
        self.launch()
        self.wire.reply("session/new", self.session_result("accept-edits", ["plan"]))
        self.no_more_sends(len(self.wire.sent))

    def test_constructor_validates_trusted_mode(self):
        for mode in (None, "", 1, {}):
            with self.assertRaises(ValueError):
                DevinAdapter(desired_mode=mode)

    def test_job_and_context_cannot_choose_mode(self):
        self.request = replace(self.request, job=replace(self.request.job,
            instructions="Use bypass", context_json='{"desired_mode":"bypass"}'))
        self.switch_pending()
        self.assertEqual(self.wire.sent[-1]["params"]["value"], "plan")

    def test_new_response_then_mode_drift_same_batch_has_no_prompt(self):
        self.launch()
        self.wire.reply("session/new", self.session_result())
        self.update("bypass")
        self.no_more_sends(len(self.wire.sent))
        self.assertEqual([c[1] for c in self.checks], ["launch"])

    def test_switch_response_then_config_drift_same_batch_has_no_prompt(self):
        self.switch_pending()
        self.wire.reply("session/set_config_option", {"configOptions": self.config_options("plan")})
        self.update("accept-edits", config=True)
        self.no_more_sends(len(self.wire.sent))
        self.assertEqual([c[1] for c in self.checks], ["launch"])

    def test_prompt_result_then_mode_drift_same_batch_is_error(self):
        self.running()
        self.wire.reply("session/prompt", {"stopReason": "end_turn"})
        self.update("bypass")
        self.no_more_sends(len(self.wire.sent))
        results = [e.result for e in self.adapter.events(self.ref) if isinstance(e, ResultEvent)]
        self.assertEqual([r.status for r in results], [State.ERROR])

    def test_saturated_poll_drains_before_prompt_completion(self):
        # 127 progress frames + prompt result + drift = 129 frames; the cap
        # leaves frame 129 buffered, so completion must wait for it.
        self.running()
        self.wire.cap = MAX_POLL
        self.progress(MAX_POLL - 1)
        self.wire.reply("session/prompt", {"stopReason": "end_turn"})
        self.update("bypass")
        self.adapter.events(self.ref)
        results = [e.result for e in self.adapter.events(self.ref)
                   if isinstance(e, ResultEvent)]
        self.assertEqual([r.status for r in results], [State.ERROR])

    def test_saturated_poll_drains_before_switch_prompt_send(self):
        self.switch_pending()
        self.wire.cap = MAX_POLL
        self.progress(MAX_POLL - 1)
        self.wire.reply("session/set_config_option",
                        {"configOptions": self.config_options("plan")})
        self.update("accept-edits")
        self.adapter.events(self.ref)
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        self.assertFalse(any(m.get("method") == "session/prompt"
                             for m in self.wire.sent))

    def test_saturated_clean_batch_still_completes(self):
        self.running()
        self.wire.cap = MAX_POLL
        self.progress(MAX_POLL)
        self.wire.reply("session/prompt", {"stopReason": "end_turn"})
        self.assertEqual(self.adapter.status(self.ref).state, State.COMPLETED)

    def test_unending_saturated_poll_fails_closed(self):
        self.running()
        self.wire.flood = True
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_switch_success_then_unsupported_request_blocks_prompt(self):
        self.switch_pending()
        self.wire.reply("session/set_config_option",
                        {"configOptions": self.config_options("plan")})
        self.wire.incoming.append({"jsonrpc": "2.0", "id": 99,
            "method": "fs/read_text_file",
            "params": {"sessionId": "sess-private"}})
        self.adapter.events(self.ref)
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        self.assertFalse(any(m.get("method") == "session/prompt"
                             for m in self.wire.sent))
        self.assertEqual(self.wire.sent[-1],
            {"jsonrpc": "2.0", "id": 99, "error": {
                "code": -32601, "message": "unsupported Native request"}})

    def test_prompt_success_then_unsupported_request_is_not_completed(self):
        self.running()
        self.wire.reply("session/prompt", {"stopReason": "end_turn"})
        self.wire.incoming.append({"jsonrpc": "2.0", "id": 99,
            "method": "fs/read_text_file",
            "params": {"sessionId": "sess-private"}})
        self.adapter.events(self.ref)
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        results = [e.result for e in self.adapter.events(self.ref)
                   if isinstance(e, ResultEvent)]
        self.assertEqual([(r.status, r.reason) for r in results],
                         [(State.ERROR, "native_request_unsupported")])
        self.assertEqual(self.wire.sent[-1]["error"]["code"], -32601)

    def unsupported_send_hook(self, order, *, raising):
        # order "switch": a successful set_config_option response queues a
        # deferred prompt send; order "prompt": a successful prompt result
        # queues a deferred completion. The unsupported request's error
        # reply send then reenters adapter.status and optionally raises.
        tag = f"u-{order}-{int(raising)}"
        self.ref = AttemptRef("r", "j", tag)
        self.request = replace(self.request, ref=self.ref)
        if order == "switch":
            self.switch_pending()
            self.wire.reply("session/set_config_option",
                            {"configOptions": self.config_options("plan")})
        else:
            self.desired("accept-edits")
            self.running()
            self.wire.reply("session/prompt", {"stopReason": "end_turn"})
        prompts = sum(m.get("method") == "session/prompt"
                      for m in self.wire.sent)
        observed = []
        self.wire.on_send = lambda _message: observed.append(
            self.adapter.status(self.ref).state)
        self.wire.fail_send = raising
        self.wire.incoming.append({"jsonrpc": "2.0", "id": 99,
            "method": "fs/read_text_file",
            "params": {"sessionId": "sess-private"}})
        self.adapter.events(self.ref)
        # Fatal was already latched when the send reentered; the queued
        # deferred transition never ran.
        self.assertEqual(observed, [State.ERROR])
        self.assertEqual(sum(m.get("method") == "session/prompt"
                             for m in self.wire.sent), prompts)
        results = [e.result for e in self.adapter.events(self.ref)
                   if isinstance(e, ResultEvent)]
        self.assertEqual([(r.status, r.reason) for r in results],
                         [(State.ERROR, "native_request_unsupported")])
        if not raising:
            self.assertEqual(self.wire.sent[-1],
                {"jsonrpc": "2.0", "id": 99, "error": {
                    "code": -32601, "message": "unsupported Native request"}})
        self.wire.fail_send = False
        self.no_more_sends(len(self.wire.sent))

    def test_reentrant_error_reply_send_never_outranks_fatal(self):
        for order in ("switch", "prompt"):
            with self.subTest(order=order):
                self.unsupported_send_hook(order, raising=False)

    def test_raising_error_reply_send_never_outranks_fatal(self):
        for order in ("switch", "prompt"):
            with self.subTest(order=order):
                self.unsupported_send_hook(order, raising=True)

    def test_config_drift_then_restore_never_recovers(self):
        self.running()
        self.update("bypass", config=True)
        self.update("accept-edits", config=True)
        self.no_more_sends(len(self.wire.sent))

    def test_stopping_callback_then_drift_does_not_send_cancel_response(self):
        self.running()
        self.adapter.stop(self.ref)
        self.wire.incoming.append({"jsonrpc": "2.0", "id": 99,
            "method": "session/request_permission", "params": {
                "sessionId": "sess-private", "toolCall": {"toolCallId": "tc"}, "options": []}})
        self.update("bypass")
        self.no_more_sends(len(self.wire.sent))

    def test_unknown_request_is_fatal_at_parse_even_with_trailing_drift(self):
        self.running()
        self.wire.incoming.append({"jsonrpc": "2.0", "id": 99,
            "method": "fs/read_text_file", "params": {"sessionId": "sess-private"}})
        self.update("bypass")
        before = len(self.wire.sent)
        self.adapter.events(self.ref)
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        results = [e.result for e in self.adapter.events(self.ref)
                   if isinstance(e, ResultEvent)]
        self.assertEqual([r.reason for r in results], ["native_request_unsupported"])
        self.assertEqual(self.wire.sent[before:], [{"jsonrpc": "2.0", "id": 99,
            "error": {"code": -32601, "message": "unsupported Native request"}}])
        self.no_more_sends(len(self.wire.sent))

    def test_host_recheck_failure_blocks_prompt(self):
        self.launch()
        self.adapter._verify = lambda *args: (_ for _ in ()).throw(RuntimeError("SECRET"))
        self.wire.reply("session/new", self.session_result())
        events = self.adapter.events(self.ref)
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        self.assertNotIn("SECRET", repr(events))
        self.assertFalse(any(m.get("method") == "session/prompt" for m in self.wire.sent))

    def test_duplicate_execute_never_submits_second_attempt(self):
        self.running()
        before = len(self.wire.sent)
        self.assertEqual(self.adapter.execute(self.request).status, Op.INVALID_STATE)
        self.assertEqual(len(self.wire.sent), before)

    def test_never_started_attests_exact_request_without_factory_calls(self):
        calls = []
        adapter = DevinAdapter(transport_factory=lambda request: calls.append(request))
        reply = adapter.execute(self.request)
        self.assertEqual((reply.status, reply.reason),
                         (Op.UNSUPPORTED, "host controls unverified"))
        self.assertEqual(reply.never_started,
                         NeverStarted(self.request,
                                      "devin:before-transport:host-controls-unverified"))
        self.assertIs(reply.never_started.request, self.request)
        bad = replace(self.request,
                      conditions=replace(self.request.conditions, model=""))
        reply = adapter.execute(bad)
        self.assertEqual((reply.status, reply.reason),
                         (Op.INVALID_STATE, "invalid execution conditions"))
        self.assertEqual(reply.never_started,
                         NeverStarted(bad,
                                      "devin:before-transport:invalid-execution-conditions"))
        missing = DevinAdapter(verify_host=lambda *args: None)
        self.addCleanup(missing.close)
        reply = missing.execute(self.request)
        self.assertEqual((reply.status, reply.reason),
                         (Op.UNSUPPORTED, "verified transport not configured"))
        self.assertEqual(reply.never_started,
                         NeverStarted(self.request,
                                      "devin:before-transport:verified-transport-not-configured"))
        self.assertEqual(calls, [])
        self.assertFalse(self.wires)

    def test_duplicate_attempt_and_post_factory_failures_stay_ambiguous(self):
        self.assertEqual(self.adapter.execute(self.request).status, Op.ACCEPTED)
        reply = self.adapter.execute(self.request)
        self.assertEqual((reply.status, reply.never_started), (Op.INVALID_STATE, None))
        def raising(_request):
            raise OSError("SECRET factory detail")
        adapter = DevinAdapter(verify_host=lambda *args: None,
                               transport_factory=raising)
        self.addCleanup(adapter.close)
        reply = adapter.execute(replace(self.request, ref=AttemptRef("r", "j", "a2")))
        self.assertEqual((reply.status, reply.never_started), (Op.UNAVAILABLE, None))
        self.assertNotIn("SECRET", repr(reply))
        wire = Wire()
        wire.fail_send = True
        sender = DevinAdapter(verify_host=lambda *args: None,
                              transport_factory=lambda _request: wire)
        self.addCleanup(sender.close)
        reply = sender.execute(self.request)
        self.assertEqual((reply.status, reply.never_started), (Op.ERROR, None))
        self.assertEqual(sender.status(self.ref).state, State.ERROR)

    def test_confirmation_unknown_scope_deny_only_and_exact_native_id(self):
        self.running()
        confirmation = self.callback(rpc_id="native-string-id")
        self.assertFalse(confirmation.requested_action.scope.known)
        self.assertNotEqual(confirmation.request_id, "native-string-id")
        self.assertEqual(confirmation.requested_action.name, "process.execute")
        self.assertEqual(dict(confirmation.requested_action.scope.dimensions)["kind"], "execute")
        self.assertEqual(self.adapter.status(self.ref).state, State.WAITING_HUMAN)
        self.assertEqual(self.adapter.respond(self.answer(confirmation, Resolution.ALLOW)).status,
                         Op.INVALID_STATE)
        response = self.answer(confirmation)
        self.assertEqual(self.adapter.respond(response).status, Op.ACCEPTED)
        self.assertEqual(self.wire.sent[-1], {"jsonrpc": "2.0",
            "id": "native-string-id",
            "result": {"outcome": {"outcome": "selected", "optionId": "o-reject"}}})
        self.assertEqual(self.adapter.status(self.ref).state, State.RUNNING)
        count = len(self.wire.sent)
        self.assertEqual(self.adapter.respond(response).status, Op.ACCEPTED)
        self.assertEqual(len(self.wire.sent), count)
        self.assertEqual(self.adapter.respond(replace(response, resolution=Resolution.CANCEL)).status,
                         Op.INVALID_STATE)

    def test_deny_without_reject_option_falls_back_to_cancelled(self):
        self.running()
        c = self.callback(options=[{"optionId": "o-allow", "name": "Allow", "kind": "allow_once"}])
        self.assertEqual(self.adapter.respond(self.answer(c)).status, Op.ACCEPTED)
        self.assertEqual(self.wire.sent[-1]["result"], {"outcome": {"outcome": "cancelled"}})

    def test_cancel_maps_to_cancelled_outcome(self):
        self.running()
        c = self.callback()
        self.assertEqual(self.adapter.respond(self.answer(c, Resolution.CANCEL)).status,
                         Op.ACCEPTED)
        self.assertEqual(self.wire.sent[-1]["result"], {"outcome": {"outcome": "cancelled"}})

    def test_multiple_callbacks_and_id_types_are_distinct(self):
        self.running()
        first = self.callback(7)
        second = self.callback("7", toolCall={"toolCallId": "tc-2"})
        self.assertNotEqual(first.request_id, second.request_id)
        self.adapter.respond(self.answer(first))
        self.assertEqual(self.adapter.status(self.ref).state, State.WAITING_HUMAN)
        self.adapter.respond(self.answer(second, Resolution.CANCEL))
        self.assertEqual(self.wire.sent[-1], {"jsonrpc": "2.0", "id": "7",
            "result": {"outcome": {"outcome": "cancelled"}}})
        self.assertEqual(self.adapter.status(self.ref).state, State.RUNNING)

    def test_duplicate_callback_no_duplicate_event_changed_target_errors(self):
        self.running()
        confirmation = self.callback()
        self.assertEqual(self.callback().request_id, confirmation.request_id)
        self.assertEqual(len([e for e in self.adapter.events(self.ref)
                              if isinstance(e, ConfirmationEvent)]), 1)
        self.callback(toolCall={"toolCallId": "tc-different"})
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_cross_callback_target_and_unknown_resolution_rejected(self):
        self.running()
        first = self.callback(1)
        second = self.callback(2, toolCall={"toolCallId": "tc-2"})
        answer = self.answer(first)
        for response in (replace(answer, request_id=second.request_id),
                         replace(answer, decision_ref=""),
                         replace(answer, resolution="allow"),
                         replace(answer, ref=AttemptRef("other", "j", "a"))):
            self.assertEqual(self.adapter.respond(response).status, Op.INVALID_STATE)

    def test_permission_during_prompt_turn_is_correlated(self):
        self.launch()
        self.wire.reply("session/new", self.session_result())
        self.adapter.events(self.ref)
        # session/prompt is still in flight; permission requests interleave it.
        c = self.callback()
        self.assertIsNotNone(c)
        self.assertEqual(self.adapter.status(self.ref).state, State.WAITING_HUMAN)
        self.assertEqual(self.adapter.respond(self.answer(c)).status, Op.ACCEPTED)
        self.prompt_end()
        self.assertEqual(self.adapter.status(self.ref).state, State.COMPLETED)

    def test_permission_before_session_errors(self):
        self.launch()
        # sessionId does not match a session that does not exist yet.
        self.assertIsNone(self.callback())
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_unknown_server_request_errors_without_allow(self):
        self.running()
        self.callback(method="fs/read_text_file")
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        self.assertEqual(self.wire.sent[-1]["error"]["code"], -32601)

    def test_mismatched_callback_cannot_be_answered(self):
        self.running()
        self.assertIsNone(self.callback(sessionId="other-session"))
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

    def test_terminal_or_answered_callback_rejects_late_answer(self):
        self.running()
        first = self.callback(1)
        second = self.callback(2, toolCall={"toolCallId": "tc-2"})
        self.adapter.respond(self.answer(first))
        self.prompt_end()
        self.assertEqual(self.adapter.respond(self.answer(second)).status, Op.INVALID_STATE)

    def test_stop_before_prompt_latches_without_poll_starting_work(self):
        self.launch()
        first = self.adapter.stop(self.ref)
        self.assertEqual(first.status, StopStatus.CONFIRMED)
        self.assertEqual(self.adapter.stop(self.ref), first)
        self.assertEqual(self.wire.closed, 1)
        self.assertFalse(any(m.get("method") == "session/prompt" for m in self.wire.sent))

    def test_stop_during_prompt_cancels_once_and_stays_unconfirmed(self):
        self.running()
        c = self.callback()
        reply = self.adapter.stop(self.ref)
        self.assertEqual(reply.status, StopStatus.UNCONFIRMED)
        cancel = next(m for m in self.wire.sent if m.get("method") == "session/cancel")
        self.assertEqual(cancel["params"], {"sessionId": "sess-private"})
        outcome = next(m for m in reversed(self.wire.sent) if m.get("id") == 7)
        self.assertEqual(outcome["result"], {"outcome": {"outcome": "cancelled"}})
        self.assertEqual(self.adapter.respond(self.answer(c)).status, Op.INVALID_STATE)
        self.prompt_end("cancelled")
        self.assertEqual(self.adapter.status(self.ref).state, State.FAILED)
        self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        self.assertEqual(sum(m.get("method") == "session/cancel" for m in self.wire.sent), 1)

    def test_prompt_outcomes_map_honestly(self):
        cases = {"end_turn": (State.COMPLETED, None),
                 "cancelled": (State.FAILED, "native_prompt_cancelled"),
                 "refusal": (State.FAILED, "native_prompt_refusal"),
                 "max_tokens": (State.ERROR, "native_prompt_limit"),
                 "max_turn_requests": (State.ERROR, "native_prompt_limit"),
                 "invented": (State.ERROR, "adapter_protocol_error")}
        for i, (reason, (state, result_reason)) in enumerate(cases.items()):
            with self.subTest(reason=reason):
                ref = AttemptRef("r", "j", f"p{i}")
                self.assertEqual(self.adapter.execute(replace(self.request, ref=ref)).status,
                                 Op.ACCEPTED)
                self.wire.reply("initialize", {"protocolVersion": 1})
                self.adapter.events(ref)
                self.wire.reply("session/new", self.session_result())
                self.adapter.events(ref)
                self.wire.reply("session/prompt", {"stopReason": reason})
                self.adapter.events(ref)
                self.assertEqual(self.adapter.status(ref).state, state)
                results = [e.result for e in self.adapter.events(ref) if isinstance(e, ResultEvent)]
                self.assertEqual(results[-1].reason, result_reason)

    def test_cancel_delivery_failure_stays_unconfirmed(self):
        self.running()
        self.wire.fail_send = True
        self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

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

    def test_result_completion_and_no_raw_secrets(self):
        self.running()
        self.wire.incoming.append({"jsonrpc": "2.0",
                                   "method": "session/update", "params": {
            "sessionId": "sess-private",
            "update": {"sessionUpdate": "agent_message_chunk",
                       "content": {"type": "text", "text": "SECRET"}}}})
        self.adapter.events(self.ref)
        events = self.prompt_end()
        result = next(e.result for e in events if isinstance(e, ResultEvent))
        self.assertEqual(result.status, State.COMPLETED)
        self.assertIsNone(result.reason)
        self.assertNotIn("SECRET", repr(events))
        self.assertEqual(self.adapter.events(self.ref), events)

    def test_provider_failure_is_infrastructure_error_not_model_ac_failure(self):
        self.running()
        self.wire.reply("session/prompt", error={"code": -32000, "message": "SECRET"})
        events = self.adapter.events(self.ref)
        result = next(e.result for e in events if isinstance(e, ResultEvent))
        self.assertEqual((result.status, result.reason), (State.ERROR, "native_rpc_error"))
        self.assertNotIn("SECRET", repr(events))

    def test_prompt_has_no_rpc_deadline_but_bootstrap_does(self):
        self.launch()
        self.now = 6
        events = self.adapter.events(self.ref)
        self.assertEqual(next(e.result.reason for e in events if isinstance(e, ResultEvent)),
                         "native_rpc_timeout")

    def test_long_prompt_turn_is_not_a_timeout(self):
        self.running()
        self.now = 10 ** 9
        self.assertEqual(self.adapter.status(self.ref).state, State.RUNNING)

    def test_every_outbound_frame_carries_jsonrpc_2(self):
        self.running()
        c = self.callback()
        self.assertEqual(self.adapter.respond(self.answer(c)).status, Op.ACCEPTED)
        self.adapter.stop(self.ref)
        methods = {m.get("method") for m in self.wire.sent}
        # initialize, session/new, session/prompt, permission response and
        # session/cancel are all covered by this flow.
        self.assertEqual(methods & {"initialize", "session/new",
                                    "session/prompt", "session/cancel"},
                         {"initialize", "session/new", "session/prompt",
                          "session/cancel"})
        self.assertTrue(any("result" in m for m in self.wire.sent))
        for message in self.wire.sent:
            self.assertEqual(message.get("jsonrpc"), "2.0")

    def test_error_response_to_native_request_carries_jsonrpc_2(self):
        self.running()
        self.callback(method="fs/read_text_file")
        error_reply = self.wire.sent[-1]
        self.assertEqual(error_reply["jsonrpc"], "2.0")
        self.assertEqual(error_reply["error"]["code"], -32601)

    def test_inbound_missing_or_wrong_jsonrpc_version_fails_closed(self):
        for i, incoming in enumerate((
                {"id": "x", "result": {"protocolVersion": 1}},
                {"jsonrpc": "1.0", "id": "x",
                 "result": {"protocolVersion": 1}})):
            with self.subTest(incoming=incoming):
                ref = AttemptRef("r", "j", f"j{i}")
                self.assertEqual(
                    self.adapter.execute(replace(self.request, ref=ref)).status,
                    Op.ACCEPTED)
                sent = next(m for m in self.wire.sent
                            if m.get("method") == "initialize")
                self.wire.incoming.append({**incoming, "id": sent["id"]})
                self.assertEqual(self.adapter.status(ref).state, State.ERROR)
                self.assertFalse(any(m.get("method") == "session/new"
                                     for m in self.wire.sent))

    def test_unmatched_rpc_id_is_not_success(self):
        self.launch()
        self.wire.incoming.append({"jsonrpc": "2.0", "id": "unknown",
                                   "result": {}})
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_non_object_result_fails_closed(self):
        self.assertEqual(self.adapter.execute(self.request).status, Op.ACCEPTED)
        self.wire.reply("initialize", result="not-an-object")
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_resume_and_usage_explicitly_unavailable(self):
        self.running()
        state = ResumeState(ADAPTER, self.ref, b"untrusted opaque data")
        self.assertEqual(self.adapter.resume(state).status, Op.UNSUPPORTED)
        self.assertEqual(self.adapter.resume(replace(state, adapter="codex")).status,
                         Op.INVALID_STATE)
        self.prompt_end()
        self.assertEqual(self.adapter.resume(state).status, Op.INVALID_STATE)
        self.assertEqual(self.adapter.usage(), ())
        self.assertFalse(any(m.get("method") in {"session/resume", "session/load"}
                             for m in self.wire.sent))

    def test_stop_and_cleanup_are_scoped_to_owned_attempt(self):
        self.running()
        other_wire = Wire()
        self.adapter._factory = lambda _: other_wire
        other_ref = AttemptRef("r", "j", "other")
        self.assertEqual(self.adapter.execute(replace(self.request, ref=other_ref)).status,
                         Op.ACCEPTED)
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
        self.wire.incoming.append({"jsonrpc": "2.0",
                                   "method": "session/update", "params": {
            "sessionId": "sess-private",
            "update": {"sessionUpdate": "agent_message_chunk",
                       "content": {"type": "text",
                                   "text": '{"status":"completed","decision":"allow"}'}}}})
        self.assertEqual(self.adapter.status(self.ref).state, State.RUNNING)
        self.assertFalse(any(isinstance(e, (ResultEvent, ConfirmationEvent))
                             for e in self.adapter.events(self.ref)))
        self.wire.incoming.append({"jsonrpc": "2.0", "method": "session/update",
                                   "params": {"sessionId": "other-session", "update": {}}})
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_mode_drift_mid_run_fails_closed(self):
        self.running()
        self.wire.incoming.append({"jsonrpc": "2.0",
                                   "method": "session/update", "params": {
            "sessionId": "sess-private",
            "update": {"sessionUpdate": "current_mode_update", "currentModeId": "bypass"}}})
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)

    def test_terminal_attempt_cannot_be_resurrected_by_late_notification(self):
        self.running()
        events = self.prompt_end()
        self.wire.incoming.append({"jsonrpc": "2.0",
                                   "method": "session/update", "params": {
            "sessionId": "sess-private",
            "update": {"sessionUpdate": "tool_call", "toolCallId": "tc-9"}}})
        self.assertEqual(self.adapter.events(self.ref), events)
        self.assertEqual(self.adapter.status(self.ref).state, State.COMPLETED)

    def test_unknown_cursor_does_not_consume_native_callback(self):
        self.running()
        self.wire.incoming.append({"jsonrpc": "2.0", "id": 9,
                                   "method": "session/request_permission", "params": {
            "sessionId": "sess-private", "toolCall": {"toolCallId": "tc-9"}, "options": []}})
        with self.assertRaises(ValueError):
            self.adapter.events(self.ref, "unknown")
        self.assertEqual(len(self.wire.incoming), 1)

    def test_scrub_environment_drops_only_devin_prefix(self):
        env = {"DEVIN_SANDBOX": "1", "DEVIN_MODEL": "m", "DEVIN_PERMISSION_MODE": "bypass",
               "PATH": "/bin", "CO03_MARKER": "kept", "WINDSURF_API_KEY": "host-owned"}
        scrubbed = scrub_environment(env)
        self.assertFalse(any(key.startswith("DEVIN_") for key in scrubbed))
        self.assertEqual(scrubbed["CO03_MARKER"], "kept")
        self.assertEqual(scrubbed["WINDSURF_API_KEY"], "host-owned")


class AcpTransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = Path(self.tmp.name) / "devin-fixture"
        fixture = Path(__file__).with_name("fixtures") / "devin_acp.py"
        path.write_text(f"#!{sys.executable}\n" + fixture.read_text())
        path.chmod(0o700)
        self.executable = str(path)

    def make(self, **kwargs):
        env = {"CO03_MARKER": "kept", "DEVIN_SANDBOX": "1", "DEVIN_MODEL": "foreign"}
        transport = AcpTransport(self.executable, self.tmp.name, "swe-2-high",
                                 environ=env, **kwargs)
        self.addCleanup(transport.close)
        return transport

    def read(self, transport):
        end = time.monotonic() + 3
        while time.monotonic() < end:
            result = transport.poll()
            if result:
                return result
            time.sleep(.01)
        self.fail("fixture response timed out")

    def test_argv_and_environment_scrubbed(self):
        transport = self.make()
        transport.send({"id": "1", "method": "probe_env", "params": {}})
        (result,) = self.read(transport)
        self.assertEqual(result["result"]["argv"], ["acp", "--model", "swe-2-high"])
        self.assertEqual(result["result"]["devin_prefix"], [])
        self.assertEqual(result["result"]["marker"], "kept")

    def test_real_process_ndjson_roundtrip_and_partial_frame(self):
        transport = self.make()
        message = {"id": "1", "method": "echo", "params": {"text": "合成入力\nsecond line"}}
        transport.send(message)
        self.assertEqual(self.read(transport), ({"jsonrpc": "2.0", "id": "1",
                                                 "result": message["params"]},))
        self.assertTrue(transport.alive())

    def test_adapter_stdio_pre_session_order_and_plan_switch(self):
        checks = []
        def verify(request, phase, native):
            checks.append((phase, native))  # Synthetic only, not host evidence.
        adapter = DevinAdapter(verify_host=verify,
            transport_factory=lambda request: self.make(), desired_mode="plan")
        self.addCleanup(adapter.close)
        ref = AttemptRef("stdio", "j", "a")
        request = ExecuteRequest(ref, Job("stdio", "j", "Synthetic turn", ("done",), '{}'),
            ExecutionConditions("swe-2-high", ADAPTER, self.tmp.name, "fixture", ("fixture",)))
        self.assertEqual(adapter.execute(request).status, Op.ACCEPTED)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            state = adapter.status(ref).state
            if state in (State.COMPLETED, State.ERROR):
                break
            time.sleep(.01)
        self.assertEqual(state, State.COMPLETED)
        self.assertEqual([phase for phase, _ in checks], ["launch", "session"])
        self.assertEqual(checks[-1][1]["configOptions"][0]["currentValue"], "plan")

    def test_poll_cap_retains_complete_frames_for_next_poll(self):
        transport = object.__new__(AcpTransport)
        transport._outgoing = bytearray()
        transport._incoming = bytearray(b"".join(
            json.dumps({"jsonrpc": "2.0", "method": "probe",
                        "params": {"i": i}}).encode() + b"\n"
            for i in range(MAX_POLL + 1)))
        transport._eof = True
        self.assertEqual(len(transport.poll()), MAX_POLL)
        self.assertEqual(len(transport.poll()), 1)

    def test_malformed_json_is_not_ignored(self):
        transport = self.make()
        transport.send({"id": 1, "method": "malformed"})
        with self.assertRaises(NativeError):
            self.read(transport)

    def test_duplicate_json_keys_rejected(self):
        transport = self.make()
        transport.send({"id": 1, "method": "duplicate"})
        with self.assertRaises(NativeError):
            self.read(transport)

    def test_write_limit_and_owned_process_cleanup(self):
        transport = self.make()
        with self.assertRaises(NativeError):
            transport.send({"text": "x" * MAX_BYTES})
        transport.close()
        self.assertFalse(transport.alive())

    def test_version_gate_and_executable_requirements(self):
        with self.assertRaises(NativeError):
            AcpTransport("relative/devin", self.tmp.name, "m")
        with self.assertRaises(NativeError):
            AcpTransport("/usr/bin/false", self.tmp.name, "m")
        with self.assertRaises(NativeError):
            AcpTransport(self.executable, self.tmp.name, "")
        with self.assertRaises(NativeError):
            AcpTransport(self.executable, self.tmp.name, "m",
                         expected_version="devin-cli 3000.11.3")
        transport = self.make(expected_version="devin-fixture 0.0.0")
        self.assertTrue(transport.alive())


if __name__ == "__main__":
    unittest.main()
