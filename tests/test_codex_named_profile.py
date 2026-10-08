"""Offline product-path fixtures; no Native authentication or model calls."""
from dataclasses import replace
import json
import os
import subprocess
import tomllib
import unittest
from unittest.mock import patch

from co_v4.adapters.codex import StdioTransport, NativeError
from co_v4.codex_host import CodexHostConfig, CodexReadOnlyHost, HostUnverified
from co_v4.codex_permissions import ProfileError, account_updated_notification
from tests import test_codex_host as fixtures


class ProfileNative(fixtures.NativeFixture):
    def __init__(self):
        super().__init__()
        self.native_version = "codex-cli 0.159.2"
        self.thread_changes = {}
        self.model_rows = [{"model": "gpt-6-astra", "defaultReasoningEffort": "medium",
            "supportedReasoningEfforts": [{"reasoningEffort": e} for e in ("low", "medium", "high", "xhigh", "max", "ultra")]}]
        self.hook = lambda message: None

    def send(self, message):
        self.hook(message)
        if message.get("method") == "model/list":
            self.sent.append(message)
            self.incoming.append({"id": message["id"], "result": {"data": self.model_rows}})
            return
        super().send(message)
        if message.get("method") == "thread/start":
            self.incoming[-1]["result"].update(
                activePermissionProfile={"id": message["params"]["permissions"], "extends": None},
                reasoningEffort=self.config.get("model_reasoning_effort", "medium"), **self.thread_changes)


class NamedProfileHostTests(unittest.TestCase):
    setUp = fixtures.CodexHostTests.setUp
    run_gate = fixtures.CodexHostTests.run_gate

    def prepare(self):
        self.wire = ProfileNative()
        self.host = CodexReadOnlyHost(replace(self.host.config, use_named_permissions=True, reasoning_effort="medium"))
        self.adapter = self.host.make_adapter()
        self.addCleanup(self.adapter.close)
        def launch(*args, **kwargs):
            self.assertEqual(kwargs["required_version"], "codex-cli 0.159.2")
            for override in kwargs["config_overrides"]:
                parsed = tomllib.loads(override)
                for key, value in parsed.items():
                    if key == "permissions":
                        for name, definition in value.items():
                            self.wire.config.setdefault("permissions", {}).setdefault(name, {}).update(definition)
                    elif key == "features":
                        self.wire.config["features"].update(value)
                    elif key == "model_reasoning_effort": self.wire.config[key] = value
            return self.wire
        self.factory.side_effect = launch

    def methods(self): return [m.get("method") for m in self.wire.sent]

    def test_product_flow_binds_same_profile_thread_command_turn_and_effort(self):
        self.prepare(); self.run_gate()
        sent = {m["method"]: m.get("params", {}) for m in self.wire.sent}
        profile = sent["thread/start"]["permissions"]
        self.assertEqual(sent["initialize"]["capabilities"], {"experimentalApi": True})
        self.assertEqual(sent["command/exec"]["permissionProfile"], profile)
        self.assertEqual(sent["turn/start"]["permissions"], profile)
        self.assertEqual(sent["turn/start"]["effort"], "medium")
        self.assertEqual(sent["turn/start"]["cwd"], self.conditions.workspace)
        self.assertNotIn("sandbox", sent["thread/start"])
        self.assertNotIn("sandboxPolicy", sent["command/exec"])
        self.assertTrue(self.host.observation["native_handoff_verified"])
        self.assertEqual(len(self.host.observation["request_binding_sha256"]), 64)

    def test_async_account_metadata_across_startup_and_host_rpcs_is_informational(self):
        notice = {"method": "account/updated", "params": {"authMode": "chatgpt", "planType": "pro"}}
        self.prepare()
        self.wire.incoming.append(notice)
        def hook(message):
            if message.get("method") in {"thread/start", "config/read", "command/exec", "turn/start"}:
                self.wire.incoming.append(notice)
        self.wire.hook = hook
        self.run_gate()
        self.assertIn("turn/start", self.methods())
        self.assertTrue(self.host.observation["native_handoff_verified"])
        self.assertGreaterEqual(self.host._transport.inner.account_notifications, 4)

    def test_account_notification_cannot_replace_real_boundary_checks(self):
        self.prepare(); self.wire.changed["credential_read"] = ["reachable"]
        self.wire.incoming.append({"method": "account/updated", "params": {"authMode": "chatgpt", "planType": "pro"}})
        self.run_gate()
        self.assertEqual(self.host.observation["status"], "native_boundary_not_proven")
        self.assertNotIn("turn/start", self.methods())

    def test_account_metadata_schema_and_requests_fail_closed(self):
        self.prepare(); self.run_gate(); wire = self.host._transport.inner
        notice = {"method": "account/updated", "params": {"authMode": "chatgpt", "planType": "pro"}}
        for message in ({**notice, "id": "approval"}, {**notice, "jsonrpc": "other"},
                        {**notice, "emittedAtMs": True}, {**notice, "params": {"authMode": "unknown"}},
                        {**notice, "params": {"planType": 1}}, {**notice, "params": {"planType": []}},
                        {**notice, "params": {"planType": "pro", "secret": "CANARY"}}):
            self.wire.incoming = [message]
            with self.assertRaises(ProfileError): wire.poll()
        self.assertTrue(account_updated_notification({"method": "account/updated", "params": {}}))
        self.assertTrue(account_updated_notification({"method": "account/updated", "params": {"authMode": None, "planType": None}}))
        self.wire.incoming = [{"method": "unknown", "params": {}}]
        self.assertEqual(wire.poll(), ({"method": "unknown", "params": {}},))
        self.wire.incoming = [notice] * 9
        with self.assertRaises(ProfileError): wire.poll()

    def test_old_version_has_no_profile_fallback(self):
        self.prepare(); self.wire.native_version = "codex-cli 0.156.1"
        self.assertEqual(self.adapter.execute(self.request).status.value, "unavailable")
        self.assertNotIn("initialize", self.methods())
        self.assertTrue(self.wire.closed)

    def test_required_version_checked_before_real_transport_popen(self):
        with patch("co_v4.adapters.codex.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"codex-cli 0.156.1\n", b"")), patch("co_v4.adapters.codex.subprocess.Popen") as popen:
            with self.assertRaises(NativeError):
                StdioTransport(str(self.executable), self.conditions.workspace, required_version="codex-cli 0.159.2")
            popen.assert_not_called()

    def test_missing_or_wrong_active_profile_or_effort_refuses_before_probe_and_turn(self):
        for changes in ({"activePermissionProfile": None}, {"activePermissionProfile": {"id": "other"}},
                        {"reasoningEffort": "high"}):
            with self.subTest(changes=changes):
                self.prepare()
                # Mutation after the fixture's normal response construction.
                original = self.wire.send
                def send(message):
                    original(message)
                    if message.get("method") == "thread/start": self.wire.incoming[-1]["result"].update(changes)
                self.wire.send = send
                self.run_gate()
                self.assertNotIn("command/exec", self.methods())
                self.assertNotIn("turn/start", self.methods())

    def test_config_drift_and_null_unknown_not_admitted(self):
        for mutate in (lambda p: p["filesystem"].pop(str(self.credential)),
                       lambda p: p["network"].update(enabled=True),
                       lambda p: p.update(extends=":workspace"),
                       lambda p: p.update(unknown=None)):
            with self.subTest(mutate=mutate):
                self.prepare()
                def hook(message):
                    if message.get("method") == "config/read": mutate(self.wire.config["permissions"][self.host._profile_name])
                self.wire.hook = hook
                self.run_gate()
                self.assertNotIn("command/exec", self.methods())
                self.assertNotIn("turn/start", self.methods())

    def test_known_null_serialization_remains_same_policy(self):
        self.prepare()
        def hook(message):
            if message.get("method") == "config/read":
                profile = self.wire.config["permissions"][self.host._profile_name]
                profile.update(description=None, extends=None, workspace_roots=None)
                profile["filesystem"]["glob_scan_max_depth"] = None
                profile["network"]["proxy_url"] = None
        self.wire.hook = hook
        self.run_gate()
        self.assertIn("turn/start", self.methods())

    def test_credential_reachability_still_refuses(self):
        self.prepare(); self.wire.changed["credential_read"] = ["reachable"]
        self.run_gate()
        self.assertEqual(self.host.observation["status"], "native_boundary_not_proven")
        self.assertNotIn("turn/start", self.methods())

    def test_changed_request_or_target_cannot_reuse_admission(self):
        for kind in ("request", "target"):
            with self.subTest(kind=kind):
                self.prepare()
                def hook(message):
                    if message.get("method") == "command/exec":
                        if kind == "request": object.__setattr__(self.request.job, "instructions", "mutated")
                        else:
                            other = self.control / "replacement"
                            other.write_text("other")
                            os.replace(other, self.state)
                self.wire.hook = hook
                self.run_gate()
                self.assertNotIn("turn/start", self.methods())

    def test_other_attempt_and_duplicate_execute_refuse(self):
        self.prepare(); self.run_gate()
        count = self.methods().count("turn/start")
        self.adapter.execute(self.request)
        self.adapter.execute(replace(self.request, ref=replace(self.request.ref, attempt_id="other")))
        self.assertEqual(self.methods().count("turn/start"), count)
        self.assertEqual(self.factory.call_count, 1)

    def test_profile_transport_rejects_turn_override_and_resend(self):
        self.prepare(); self.run_gate()
        wire = self.host._transport.inner
        message = next(m for m in self.wire.sent if m["method"] == "turn/start")
        with self.assertRaises(ProfileError): wire.send(message)
        wire.submitted = False
        for change in ({"permissions": "other"}, {"sandboxPolicy": {"type": "readOnly"}},
                       {"threadId": "other"}, {"cwd": "/other"}, {"effort": "high"}):
            with self.assertRaises(ProfileError): wire.send(dict(message, params=dict(message["params"], **change)))

    def test_ambiguous_optin_refused(self):
        for value in (1, "yes", None):
            with self.assertRaises(HostUnverified): CodexReadOnlyHost(replace(self.host.config, use_named_permissions=value))

    def test_profile_metadata_filters_are_strict_and_bound(self):
        self.prepare(); self.run_gate()
        wire = self.host._transport.inner
        for message in (
            {"method": "remoteControl/status/changed", "params": {"status": "connected", "serverName": "s", "installationId": "i"}},
            {"method": "warning", "params": {"message": "x", "threadId": "foreign"}},
            {"method": "warning", "params": {"message": "x", "threadId": "thread", "unknown": None}},
            {"method": "warning", "id": "approval", "params": {"message": "x", "threadId": "thread"}}):
            self.wire.incoming = [message]
            with self.assertRaises(ProfileError): wire.poll()

    def test_pending_warning_must_match_actual_thread_response(self):
        self.prepare()
        original = self.wire.send
        def send(message):
            original(message)
            if message.get("method") == "thread/start":
                self.wire.incoming.insert(0, {"method": "warning", "params": {"message": "x", "threadId": "foreign"}})
        self.wire.send = send
        self.run_gate()
        self.assertNotIn("command/exec", self.methods())
        self.assertNotIn("turn/start", self.methods())

    def test_remote_feature_and_effort_readback_cannot_drift(self):
        for key in ("remote_control", "model_reasoning_effort"):
            self.prepare()
            def hook(message):
                if message.get("method") == "config/read":
                    if key == "remote_control": self.wire.config["features"][key] = True
                    else: self.wire.config[key] = "high"
            self.wire.hook = hook
            self.run_gate()
            self.assertNotIn("command/exec", self.methods())
            self.assertNotIn("turn/start", self.methods())

if __name__ == "__main__": unittest.main()
