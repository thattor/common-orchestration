"""Fixture checks of launch binding/refusal. These are not Native isolation proof."""
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4.codex_host import (CodexHostConfig, CodexReadOnlyHost, DelegatedScope,
                              HostUnverified, DISABLED_FEATURES, OVERRIDES)
from co_v4.contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job, State


class NativeFixture:
    def __init__(self):
        self.native_version = "codex-cli 0.156.1"
        self.sent = []
        self.incoming = []
        self.changed = {}
        self.error = None
        self.closed = False
        self.config = {"mcp_servers": {}, "web_search": "disabled",
                       "features": dict.fromkeys(DISABLED_FEATURES, False),
                       "shell_environment_policy": {"inherit": "none", "include_only": []}}

    def send(self, m):
        self.sent.append(m)
        method = m.get("method")
        if method == "initialize":
            result = {"userAgent": "fixture"}
        elif method == "thread/start":
            result = {**m["params"], "thread": {"id": "thread"},
                      "sandbox": {"type": "readOnly", "networkAccess": False}}
        elif method == "config/read":
            result = {"config": self.config}
        elif method == "command/exec":
            c = json.loads(m["params"]["command"][-1])
            observed = {"nonce": c["nonce"], "uid": os.getuid(), "euid": os.geteuid(),
                        "cwd": c["workspace"], "workspace_read": "reachable",
                        "workspace_create": "denied",
                        "credential_read": ["denied"] * len(c["credentials"]),
                        "credential_env_present": False,
                        "state_write": ["denied"] * len(c["state"]),
                        "parent_create": ["denied"] * len(c["parent_create"]),
                        "network": ["denied", "denied"], **self.changed}
            result = self.error or {"exitCode": 0, "stdout": json.dumps(observed), "stderr": ""}
        else:
            return
        self.incoming.append({"id": m["id"], "result": result})

    def poll(self):
        result, self.incoming = tuple(self.incoming), []
        return result

    def alive(self): return not self.closed
    def close(self): self.closed = True


class CodexHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.workspace = self.root / "worker"
        self.workspace.mkdir()
        self.control = self.root / "control"
        self.control.mkdir()
        self.state = self.control / "control.db"
        self.state.write_text("control")
        self.credential = self.root / "credential"
        self.credential.write_text("credential-do-not-read")
        self.executable = self.root / "native"
        self.executable.write_text("pinned fixture")
        self.python = self.root / "python"
        self.python.write_text("pinned helper interpreter")
        self.conditions = ExecutionConditions("gpt-6-astra", "codex.app-server",
                        str(self.workspace), "candidate:unit", ("controls:unit",))
        self.request = ExecuteRequest(AttemptRef("r", "j", "a"),
                                     Job("r", "j", "fixture", ()), self.conditions)
        self.delegation = DelegatedScope("human-intent:fixture", self.request.ref,
                                         str(self.workspace))
        self.host = CodexReadOnlyHost(CodexHostConfig(self.conditions, self.executable,
                                        self.python, (self.state,), (self.credential,),
                                        self.delegation))
        self.wire = NativeFixture()
        for target, value in (("platform.system", "Darwin"), ("platform.machine", "arm64")):
            p = patch(target, return_value=value)
            p.start()
            self.addCleanup(p.stop)
        p = patch("co_v4.codex_host.StdioTransport", return_value=self.wire)
        self.factory = p.start()
        self.addCleanup(p.stop)
        self.adapter = self.host.make_adapter()
        self.addCleanup(self.adapter.close)

    def run_gate(self):
        self.adapter.execute(self.request)
        self.adapter.events(self.request.ref)
        self.adapter.events(self.request.ref)

    def mode_gate(self, mode, *, tier="fast", fast=True, thread_tier="priority",
                  usage=True, version="codex-cli 0.159.2", account_type="chatgpt"):
        host = CodexReadOnlyHost(replace(self.host.config, mode=mode))
        wire = NativeFixture()
        wire.native_version = version
        wire.config.update(service_tier=tier)
        wire.config["features"]["fast_mode"] = fast
        send = wire.send
        def respond(message):
            method = message.get("method")
            if method == "account/read":
                wire.sent.append(message)
                wire.incoming.append({"id": message["id"], "result": {
                    "account": {"type": account_type, "planType": "pro"}, "requiresOpenaiAuth": True}})
            elif method == "account/rateLimits/read":
                wire.sent.append(message)
                wire.incoming.append({"id": message["id"], "result": {
                    "ordinaryUsageAllowed": usage, "rateLimits": {}}})
            else:
                send(message)
                if method == "thread/start":
                    wire.incoming[-1]["result"]["serviceTier"] = thread_tier
        wire.send = respond
        with patch("co_v4.codex_host.StdioTransport", return_value=wire) as factory:
            adapter = host.make_adapter()
            try:
                adapter.execute(self.request)
                adapter.events(self.request.ref)
                adapter.events(self.request.ref)
                observation = dict(host.observation)
            finally:
                adapter.close()
        return observation, [m["method"] for m in wire.sent], factory.call_args

    def test_explicit_fast_and_tibo_alias_use_same_pre_turn_gates(self):
        for mode in ("fast", "tibo"):
            with self.subTest(mode=mode):
                observation, methods, launch = self.mode_gate(mode)
                self.assertTrue(observation["native_handoff_verified"], observation)
                self.assertLess(methods.index("account/rateLimits/read"), methods.index("turn/start"))
                evidence = observation["service_tier_observation"]
                self.assertEqual(evidence["requested"], "fast")
                self.assertEqual(evidence["original_thread_response"], "priority")
                self.assertEqual(launch.kwargs["config_overrides"][-2:],
                                 tuple(evidence["sent_config_overrides"]))
                self.assertEqual(launch.kwargs["required_version"], "codex-cli 0.159.2")

    def test_explicit_normal_must_match_actual_config_and_thread(self):
        observation, methods, launch = self.mode_gate("normal", tier="default", fast=False, thread_tier=None)
        self.assertTrue(observation["native_handoff_verified"], observation)
        self.assertIn("turn/start", methods)
        self.assertFalse(observation["service_tier_observation"]["effective_fast_mode"])
        self.assertEqual(launch.kwargs["config_overrides"][-2:],
                         ('service_tier="default"', 'features.fast_mode=false'))

    def test_mode_mismatch_or_usage_denial_never_submits_a_turn(self):
        cases = [("normal", {}), ("normal", {"tier": "default", "thread_tier": None}),
                 ("normal", {"tier": "default", "fast": False}),
                 ("fast", {"tier": "default"}), ("fast", {"fast": False}),
                 ("fast", {"thread_tier": "fast"}), ("fast", {"thread_tier": None}),
                 ("fast", {"usage": False}), ("normal", {"usage": False}),
                 ("fast", {"account_type": "apiKey"}),
                 ("fast", {"version": "codex-cli 0.156.1"})]
        for mode, changes in cases:
            with self.subTest(mode=mode, changes=changes):
                observation, methods, _ = self.mode_gate(mode, **changes)
                self.assertFalse(observation["native_handoff_verified"])
                self.assertNotIn("turn/start", methods)

    def test_unsupported_mode_fails_before_transport(self):
        for mode in ("turbo", "priority", "default", "FAST", True, []):
            with self.subTest(mode=mode), self.assertRaises(HostUnverified):
                CodexReadOnlyHost(replace(self.host.config, mode=mode))
        self.factory.assert_not_called()

    def test_successful_probe_admits_bound_native_handoff(self):
        self.run_gate()
        methods = [m["method"] for m in self.wire.sent]
        self.assertIn("command/exec", methods)
        self.assertIn("turn/start", methods)
        self.assertNotEqual(self.adapter.status(self.request.ref).state, State.ERROR)
        self.factory.assert_called_once()
        self.assertEqual(self.factory.call_args.args, (str(self.executable), str(self.workspace)))
        self.assertEqual(self.factory.call_args.kwargs["config_overrides"], OVERRIDES)
        self.assertNotIn("GH_TOKEN", self.factory.call_args.kwargs["env"])
        command = next(m for m in self.wire.sent if m["method"] == "command/exec")
        self.assertEqual(command["params"]["sandboxPolicy"],
                         {"type": "readOnly", "networkAccess": False})
        self.assertEqual(self.host.observation["status"], "delegated_native_preflight_passed")
        self.assertTrue(self.host.observation["command_preflight_verified"])
        self.assertTrue(self.host.observation["native_handoff_verified"])
        self.assertEqual(self.host.observation["human_intent_ref"], "human-intent:fixture")
        self.assertEqual(self.host.observation["delegated_capability"], "codex.readonly.local")

    def test_observation_uses_actual_transport_version(self):
        self.wire.native_version = "codex-cli 0.159.2"
        self.run_gate()
        self.assertEqual(self.host.observation["native_version"], "codex-cli 0.159.2")

    def test_new_version_does_not_waive_credential_boundary(self):
        self.wire.native_version = "codex-cli 0.159.2"
        self.wire.changed["credential_read"] = ["reachable"]
        self.run_gate()
        self.assertFalse(self.host.observation["native_handoff_verified"])
        self.assertEqual(self.host.observation["status"], "native_boundary_not_proven")
        self.assertNotIn("turn/start", [m["method"] for m in self.wire.sent])

    def test_diagnostic_known_names_never_admit_or_copy_parameter_values(self):
        send = self.wire.send
        def inject(message):
            if message.get("method") == "config/read":
                self.wire.incoming.append({"method": "thread/status/changed", "params": {
                    "threadId": "SECRET-ID", "status": {"type": "SECRET-STATUS"},
                    "SECRET-KEY": "SECRET-VALUE"}})
            send(message)
        self.wire.send = inject
        self.run_gate()
        self.assertEqual(self.host.observation["status"], "unexpected_native_preflight_event")
        self.assertFalse(self.host.observation["native_handoff_verified"])
        self.assertEqual(self.host.observation["unexpected_event"], {
            "method": "thread/status/changed", "message_object": True, "has_id": False,
            "envelope_keys": ["method", "params"], "unknown_envelope_keys_present": False,
            "params_object": True, "parameter_keys": ["status", "threadId"],
            "unknown_parameter_keys_present": True})
        self.assertNotIn("SECRET", repr(self.host.observation))
        self.assertNotIn("turn/start", [m["method"] for m in self.wire.sent])

    def test_unmapped_diagnostic_has_no_raw_method_or_key(self):
        from co_v4.codex_host import _event_diagnostic
        for value in (None, [], "SECRET", {"method": "SECRET", "params": {"SECRET": "VALUE"}},
                      {"method": [], "params": {"SECRET": "VALUE"}}):
            diagnostic = _event_diagnostic(value)
            self.assertEqual(diagnostic["method"], "unmapped")
            self.assertNotIn("SECRET", repr(diagnostic))

    def warning_gate(self, notification, *, reachable=False, unsafe_config=False):
        host = CodexReadOnlyHost(self.host.config)
        wire = NativeFixture()
        wire.native_version = "codex-cli 0.159.2"
        if reachable:
            wire.changed["credential_read"] = ["reachable"]
        if unsafe_config:
            wire.config["web_search"] = "enabled"
        send = wire.send
        def inject(message):
            if message.get("method") == "config/read":
                wire.incoming.append(notification)
            send(message)
        wire.send = inject
        with patch("co_v4.codex_host.StdioTransport", return_value=wire):
            adapter = host.make_adapter()
            try:
                adapter.execute(self.request)
                adapter.events(self.request.ref)
                adapter.events(self.request.ref)
            finally:
                adapter.close()
        return host.observation, [m["method"] for m in wire.sent]

    def test_known_global_and_exact_thread_warning_only_allow_real_checks(self):
        for params in ({"message": "fixture warning"},
                       {"message": "fixture warning", "threadId": None},
                       {"message": "fixture warning", "threadId": "thread"}):
            with self.subTest(params=params):
                observation, methods = self.warning_gate({"method": "warning", "params": params,
                    "emittedAtMs": 1})
                self.assertEqual(observation["informational_warning_count"], 1)
                self.assertTrue(observation["native_handoff_verified"])
                self.assertIn("command/exec", methods)
                self.assertNotIn("fixture warning", repr(observation))

    def test_warning_never_overrides_failed_configuration_or_credential_check(self):
        for change, reason in (({"reachable": True}, "native_boundary_not_proven"),
                               ({"unsafe_config": True}, "external_tools_or_environment_unverified")):
            observation, methods = self.warning_gate({"method": "warning", "params": {
                "message": "fixture says everything safe", "threadId": "thread"}}, **change)
            self.assertEqual(observation["status"], reason)
            self.assertFalse(observation["native_handoff_verified"])
            self.assertNotIn("turn/start", methods)

    def test_warning_schema_identity_size_and_request_negative_matrix(self):
        good = {"method": "warning", "params": {"message": "SECRET-CANARY", "threadId": "thread"}}
        negatives = [
            {**good, "id": 7}, {**good, "method": "unknown"}, {**good, "jsonrpc": "future"},
            *({**good, "emittedAtMs": value} for value in (True, "1", 1.5, 2 ** 63, -(2 ** 63) - 1)),
            {**good, "SECRET-KEY": True},
            *({**good, "params": params} for params in (
                {}, [], {"message": 1}, {"message": "SECRET-CANARY", "extra": True},
                {"message": "SECRET-CANARY", "threadId": "foreign"},
                {"message": "SECRET-CANARY", "threadId": ""},
                {"message": "SECRET-CANARY", "threadId": []},
                {"message": "x" * 8193}, {"message": "SECRET-CANARY\ud800"})),
        ]
        for notification in negatives:
            with self.subTest(case=negatives.index(notification)):
                observation, methods = self.warning_gate(notification)
                self.assertFalse(observation["native_handoff_verified"])
                self.assertEqual(observation["status"], "unexpected_native_preflight_event")
                self.assertNotIn("turn/start", methods)
                self.assertNotIn("SECRET", repr(observation))

    def test_delegation_mismatch_refuses_before_transport(self):
        cases = (replace(self.delegation, human_intent_ref=""),
                 replace(self.delegation, attempt=AttemptRef("r", "other", "a")),
                 replace(self.delegation, workspace=str(self.control)),
                 replace(self.delegation, capability="codex.workspace.write"))
        for delegation in cases:
            with self.subTest(delegation=delegation):
                host = CodexReadOnlyHost(replace(self.host.config, delegation=delegation))
                reply = host.make_adapter().execute(self.request)
                self.assertEqual(reply.status.value, "unsupported")
                self.assertEqual(host.observation["status"], "delegated_scope_mismatch")
        self.factory.assert_not_called()

    def test_actual_native_prompt_contains_exact_delegation(self):
        self.run_gate()
        turn = next(m for m in self.wire.sent if m.get("method") == "turn/start")
        payload = json.loads(turn["params"]["input"][0]["text"])
        self.assertEqual(payload["instructions"], self.request.job.instructions)
        self.assertEqual(payload["context"], {})
        self.assertEqual(payload["delegation"]["attempt_id"], self.request.ref.attempt_id)
        self.assertEqual(payload["delegation"]["human_intent_ref"], "human-intent:fixture")
        self.assertEqual(payload["delegation"]["capability"], "codex.readonly.local")

    def test_explicit_empty_environment_override(self):
        self.host.config = replace(self.host.config, cleared_environment_keys=("FIXTURE_SETTING",))
        self.wire.config["shell_environment_policy"]["set"] = {"FIXTURE_SETTING": ""}
        self.run_gate()
        self.assertTrue(self.host.observation["native_handoff_verified"])
        self.assertIn('shell_environment_policy.set.FIXTURE_SETTING=""',
                      self.factory.call_args.kwargs["config_overrides"])

    def test_empty_normalization_keeps_unknown_and_nonempty_fail_closed(self):
        self.host.config = replace(self.host.config, cleared_environment_keys=("FIXTURE_SETTING",))
        for value in (None, {}):
            self.assertTrue(self.host._empty_environment(value))
        self.assertTrue(self.host._empty_environment({"FIXTURE_SETTING": ""}))
        for value in ({"FIXTURE_SETTING": None}, {"FIXTURE_SETTING": "null"},
                      {"FIXTURE_SETTING": " "}, {"FIXTURE_SETTING": "active"},
                      {"UNEXPECTED_SETTING": ""}, []):
            self.assertFalse(self.host._empty_environment(value))

    def test_each_failed_boundary_blocks_turn(self):
        cases = ({"credential_read": ["reachable"]}, {"credential_read": ["unknown"]},
                 {"credential_env_present": True}, {"state_write": ["reachable"]},
                 {"parent_create": ["reachable"]}, {"workspace_create": "reachable"},
                 {"network": ["unknown", "denied"]}, {"network": ["denied", "reachable"]},
                 {"euid": os.geteuid() + 1}, {"nonce": "stale"})
        for changed in cases:
            with self.subTest(changed=changed):
                host = CodexReadOnlyHost(self.host.config)
                wire = NativeFixture()
                wire.changed = changed
                with patch("co_v4.codex_host.StdioTransport", return_value=wire):
                    adapter = host.make_adapter()
                    adapter.execute(self.request)
                    adapter.events(self.request.ref)
                    adapter.events(self.request.ref)
                    self.assertEqual(adapter.status(self.request.ref).state, State.ERROR)
                    self.assertFalse(any(m.get("method") == "turn/start" for m in wire.sent))
                    self.assertEqual(host.observation["status"], "native_boundary_not_proven")
                    adapter.close()

    def test_sandbox_denial_is_not_a_pass(self):
        self.wire.error = {"exitCode": 71, "stdout": "", "stderr":
                          "sandbox-exec: sandbox_apply: Operation not permitted"}
        self.run_gate()
        self.assertEqual(self.host.observation["status"], "native_sandbox_apply_denied")
        self.assertFalse(any(m.get("method") == "turn/start" for m in self.wire.sent))

    def test_raw_error_and_malformed_output_not_published(self):
        self.wire.changed = {"credential_read": ["SECRET VALUE"]}
        self.run_gate()
        self.assertNotIn("SECRET", repr(self.host.observation))
        self.assertEqual(self.host.observation["status"], "invalid_host_observation")

    def test_external_tool_configuration_refuses_before_probe(self):
        self.wire.config["mcp_servers"] = {"unbounded": {"command": "tool"}}
        self.run_gate()
        self.assertEqual(self.host.observation["status"], "external_tools_or_environment_unverified")
        self.assertFalse(any(m.get("method") in {"command/exec", "turn/start"} for m in self.wire.sent))

    def test_explicit_mcp_disable_and_dormant_tables(self):
        self.host.config = replace(self.host.config, disabled_mcp_servers=("fixture",))
        self.wire.config.update(mcp_servers={"fixture": {"enabled": False}},
                                hooks={"dormant": {}}, plugins={"dormant": {}})
        self.run_gate()
        self.assertIn("mcp_servers.fixture.enabled=false", self.factory.call_args.kwargs["config_overrides"])
        self.assertEqual(self.host.observation["status"], "delegated_native_preflight_passed")
        self.assertTrue(any(m.get("method") == "turn/start" for m in self.wire.sent))

    def test_include_only_drift_refuses_before_probe(self):
        self.wire.config["shell_environment_policy"]["include_only"] = ["GH_TOKEN"]
        self.run_gate()
        self.assertEqual(self.host.observation["status"], "external_tools_or_environment_unverified")

    def test_mcp_startup_notification_remains_fatal_even_after_disabled_config(self):
        original = self.wire.send
        def send(message):
            original(message)
            if message.get("method") == "config/read":
                self.wire.incoming.insert(0, {"method": "mcpServer/startupStatus/updated", "params": {}})
        self.wire.send = send
        self.run_gate()
        self.assertEqual(self.host.observation["status"], "unexpected_native_preflight_event")
        self.assertFalse(any(m.get("method") == "turn/start" for m in self.wire.sent))

    def test_unsupported_mcp_identifier_refuses_before_transport(self):
        self.host.config = replace(self.host.config, disabled_mcp_servers=("ambiguous.identifier",))
        self.adapter.execute(self.request)
        self.factory.assert_not_called()

    def test_changed_environment_ref_never_creates_transport(self):
        wrong = replace(self.request, conditions=replace(self.conditions, environment_ref="other"))
        self.adapter.execute(wrong)
        self.factory.assert_not_called()

    def test_state_replacement_between_launch_and_turn_is_refused(self):
        self.adapter.execute(self.request)
        new = self.control / "new.db"
        new.write_text("replacement")
        new.replace(self.state)
        self.adapter.events(self.request.ref)
        self.adapter.events(self.request.ref)
        self.assertEqual(self.host.observation["status"], "host_target_changed")
        self.assertFalse(any(m.get("method") == "command/exec" for m in self.wire.sent))

    def test_executable_content_change_is_refused(self):
        self.adapter.execute(self.request)
        self.executable.write_text("changed same inode")
        self.adapter.events(self.request.ref)
        self.adapter.events(self.request.ref)
        self.assertEqual(self.host.observation["status"], "host_executable_changed")

    def test_transport_cannot_be_reused_or_supplied_without_launch(self):
        with self.assertRaises(HostUnverified): self.host.transport(self.request)
        self.host.verify(self.request, "launch", None)
        self.host.transport(self.request)
        with self.assertRaises(HostUnverified): self.host.transport(self.request)
        with self.assertRaises(HostUnverified): self.host.verify(self.request, "launch", None)

    def test_empty_or_missing_credential_inventory_refuses_launch(self):
        for credentials in ((), (self.root / "missing",)):
            host = CodexReadOnlyHost(replace(self.host.config, credential_files=credentials))
            with self.assertRaises(HostUnverified): host.verify(self.request, "launch", None)

    def test_protected_state_inside_worker_workspace_refuses_launch(self):
        state = self.workspace / "state.db"
        state.write_text("control")
        host = CodexReadOnlyHost(replace(self.host.config, protected_state=(state,)))
        with self.assertRaises(HostUnverified): host.verify(self.request, "launch", None)


if __name__ == "__main__": unittest.main()
