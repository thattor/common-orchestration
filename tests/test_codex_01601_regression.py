"""Regression coverage for the 0.160.1 host-compatibility patch.

stdlib unittest only: no pytest, no Native process, no network, no global
config. The fixture environment is reused from tests.test_codex_host by
method assignment so no legacy 0.159.2 test bodies are inherited or copied.
"""
from dataclasses import asdict, replace
import hashlib
import json
import tomllib
import unittest
from unittest.mock import Mock

import co_v4.codex_host as host_module
from co_v4.codex_host import CodexReadOnlyHost, HostUnverified, FEATURES_01601
from co_v4.codex_model_selection import verify_selection
from tests import test_codex_host as fixtures


MODEL_ROWS = [{"model": "gpt-6-astra", "defaultReasoningEffort": "medium",
               "supportedReasoningEfforts": [{"reasoningEffort": effort} for effort in
                   ("low", "medium", "high", "xhigh", "max", "ultra")]}]


def _digest(value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode()
    return hashlib.sha256(payload).hexdigest()


def _projection(host, request, **extra):
    config = host.config
    value = {"request": asdict(request), "profile": host._profile_name,
             "reasoning_effort": config.reasoning_effort,
             "service_tier": host._service_tier,
             "targets": [str(path) for path in host._targets()],
             "credential_environment": config.credential_environment,
             "disabled_mcp_servers": config.disabled_mcp_servers,
             "cleared_environment_keys": config.cleared_environment_keys,
             "delegation": asdict(config.delegation)}
    value.update(extra)
    return value


class Profile016Native(fixtures.NativeFixture):
    """0.160.1 double: fresh model/list plus the strict denial readback."""

    def __init__(self):
        super().__init__()
        self.native_version = "codex-cli 0.160.1"
        self.thread_changes = {}
        self.config["features"].update(dict.fromkeys(FEATURES_01601, False))
        self.config.update(dynamic_tools=[], allow_provider_model_fallback=False,
                           service_tier="default", approval_policy="never")

    def send(self, message):
        if message.get("method") == "model/list":
            self.sent.append(message)
            self.incoming.append({"id": message["id"], "result": {"data": MODEL_ROWS}})
            return
        super().send(message)
        if message.get("method") == "thread/start":
            self.incoming[-1]["result"].update(
                activePermissionProfile={"id": message["params"]["permissions"],
                                         "extends": None},
                reasoningEffort=self.config.get("model_reasoning_effort", "medium"),
                **self.thread_changes)


class Codex01601RegressionTests(unittest.TestCase):
    setUp = fixtures.CodexHostTests.setUp
    run_gate = fixtures.CodexHostTests.run_gate

    def strict_config(self, **changes):
        fields = dict(use_named_permissions=True, reasoning_effort="medium",
                      native_version="codex-cli 0.160.1", approval_policy="never",
                      strict_text_controls=True)
        fields.update(changes)
        return replace(self.host.config, **fields)

    def prepare_strict(self):
        self.wire = Profile016Native()
        self.host = CodexReadOnlyHost(self.strict_config())
        self.adapter = self.host.make_adapter()
        self.addCleanup(self.adapter.close)
        wire = self.wire
        def launch(*args, **kwargs):
            self.assertEqual(kwargs["required_version"], "codex-cli 0.160.1")
            for override in kwargs["config_overrides"]:
                for key, value in tomllib.loads(override).items():
                    if key == "permissions":
                        for name, definition in value.items():
                            wire.config.setdefault("permissions", {}).setdefault(
                                name, {}).update(definition)
                    elif key == "features":
                        wire.config["features"].update(value)
                    elif key in ("model_reasoning_effort", "approval_policy", "approvals_reviewer"):
                        wire.config[key] = value
            return wire
        self.factory.side_effect = launch
        return wire

    def methods(self):
        return [message.get("method") for message in self.wire.sent]

    def assert_refused_before_turn(self):
        self.assertFalse(self.host.observation["native_handoff_verified"])
        self.assertNotIn("turn/start", self.methods())

    # --- transport factory binding --------------------------------------

    def test_default_host_resolves_transport_global_at_call_time(self):
        # self.host was constructed in setUp *before* the StdioTransport patch
        # started; the default must be resolved when transport() runs.
        self.assertIsNone(self.host._factory)
        self.assertIs(host_module.StdioTransport, self.factory)
        self.host.verify(self.request, "launch", None)
        bound = self.host.transport(self.request)
        self.factory.assert_called_once()
        self.assertEqual(self.factory.call_args.args,
                         (str(self.executable), str(self.workspace)))
        self.assertIs(bound.inner, self.wire)

    def test_explicit_factories_are_per_host_and_bypass_global(self):
        inners = [Mock(native_version="codex-cli 0.159.2") for _ in range(2)]
        factories = [Mock(return_value=inners[i]) for i in range(2)]
        hosts = [CodexReadOnlyHost(self.host.config, transport_factory=factory)
                 for factory in factories]
        for host in hosts:
            host.verify(self.request, "launch", None)
        bound = [host.transport(self.request) for host in hosts]
        for i in range(2):
            factories[i].assert_called_once()
            self.assertEqual(factories[i].call_args.args,
                             (str(self.executable), str(self.workspace)))
            self.assertIs(bound[i].inner, inners[i])
        # Neither host touched the module global; the setUp patch stays unused.
        self.factory.assert_not_called()
        self.assertIs(host_module.StdioTransport, self.factory)

    def test_noncallable_transport_factory_refuses_in_constructor(self):
        for bad in ("stdio", 7, object(), ["x"], {"k": 1}):
            with self.subTest(factory=repr(bad)):
                with self.assertRaises(HostUnverified):
                    CodexReadOnlyHost(self.host.config, transport_factory=bad)
        self.factory.assert_not_called()

    def test_invalid_native_version_refuses_before_any_transport(self):
        for version in ("codex-cli 0.160.2", "codex-cli 0.159.3", "", None, 1592):
            with self.subTest(version=version):
                with self.assertRaises(HostUnverified):
                    CodexReadOnlyHost(replace(self.host.config,
                                              native_version=version))
        self.factory.assert_not_called()

    # --- request digest ---------------------------------------------------

    def test_legacy_default_digest_matches_declared_projection(self):
        expected = _projection(self.host, self.request)
        self.assertNotIn("native_version", expected)
        self.assertEqual(self.host._digest(self.request), _digest(expected))

    def test_named_1592_digest_keeps_legacy_shape(self):
        host = CodexReadOnlyHost(replace(self.host.config,
            use_named_permissions=True, reasoning_effort="medium"))
        expected = _projection(host, self.request)
        self.assertEqual(host._digest(self.request), _digest(expected))

    def test_new_dimensions_add_all_three_fields_to_digest(self):
        strict = CodexReadOnlyHost(self.strict_config())
        expected = _projection(strict, self.request,
            native_version="codex-cli 0.160.1", approval_policy="never",
            strict_text_controls=True)
        self.assertEqual(strict._digest(self.request), _digest(expected))
        never_1592 = CodexReadOnlyHost(replace(self.host.config,
            use_named_permissions=True, reasoning_effort="medium",
            approval_policy="never"))
        expected = _projection(never_1592, self.request,
            native_version="codex-cli 0.159.2", approval_policy="never",
            strict_text_controls=False)
        self.assertEqual(never_1592._digest(self.request), _digest(expected))

    def test_changing_any_new_dimension_changes_digest(self):
        strict = CodexReadOnlyHost(self.strict_config())
        expected = _projection(strict, self.request,
            native_version="codex-cli 0.160.1", approval_policy="never",
            strict_text_controls=True)
        actual = strict._digest(self.request)
        for field, value in (("native_version", "codex-cli 0.159.2"),
                             ("approval_policy", "on-request"),
                             ("strict_text_controls", False)):
            with self.subTest(field=field):
                changed = dict(expected, **{field: value})
                self.assertNotEqual(_digest(changed), actual)

    def test_legacy_default_construction_unchanged(self):
        host = CodexReadOnlyHost(self.host.config)
        self.assertIsNone(host._factory)
        self.assertIsNone(host._profile_name)
        self.assertFalse(host.observation["native_handoff_verified"])
        self.factory.assert_not_called()

    # --- strict 0.160.1 launch / readback ---------------------------------

    def test_strict_01601_overrides_thread_params_and_feature_readback(self):
        self.assertEqual(len(FEATURES_01601), 36)
        wire = self.prepare_strict()
        self.run_gate()
        self.assertTrue(self.host.observation["native_handoff_verified"])
        launch = self.factory.call_args
        self.assertEqual(launch.kwargs["required_version"], "codex-cli 0.160.1")
        overrides = launch.kwargs["config_overrides"]
        for name in FEATURES_01601:
            self.assertIn("features." + name + "=false", overrides)
        self.assertIn("features.remote_control=false", overrides)
        self.assertIn('model_reasoning_effort="medium"', overrides)
        self.assertIn('approval_policy="never"', overrides)
        self.assertIn('approvals_reviewer="user"', overrides)
        features = wire.config["features"]
        for name in FEATURES_01601:
            self.assertIs(features[name], False)
        start = next(m for m in wire.sent if m["method"] == "thread/start")
        params = start["params"]
        self.assertEqual(params["approvalPolicy"], "never")
        self.assertEqual(params["dynamicTools"], [])
        self.assertIs(params["allowProviderModelFallback"], False)
        self.assertEqual(params["serviceTier"], "default")
        self.assertEqual(
            {k: wire.config[k] for k in ("dynamic_tools",
                "allow_provider_model_fallback", "service_tier", "approval_policy")},
            {"dynamic_tools": [], "allow_provider_model_fallback": False,
             "service_tier": "default", "approval_policy": "never"})

    def test_thread_start_tampering_refuses_before_turn(self):
        for changes in ({"approvalPolicy": "on-request"},
                        {"reasoningEffort": "high"},
                        {"approvalsReviewer": "granted"}):
            with self.subTest(changes=changes):
                wire = self.prepare_strict()
                wire.thread_changes.update(changes)
                self.run_gate()
                self.assert_refused_before_turn()

    def test_normal_tier_accepts_native_null_and_default(self):
        for tier in (None, "default"):
            with self.subTest(tier=tier):
                wire = self.prepare_strict()
                wire.thread_changes["serviceTier"] = tier
                self.run_gate()
                self.assertTrue(self.host.observation["native_handoff_verified"])
                self.assertIn("turn/start", self.methods())

    def test_missing_or_fast_native_tier_refuses_before_turn(self):
        for tier in ("missing", "fast"):
            with self.subTest(tier=tier):
                wire = self.prepare_strict()
                send = wire.send
                def change(message, _send=send):
                    _send(message)
                    if message.get("method") == "thread/start":
                        reply = wire.incoming[-1]["result"]
                        if tier == "missing":
                            reply.pop("serviceTier", None)
                        else:
                            reply["serviceTier"] = tier
                wire.send = change
                self.run_gate()
                self.assert_refused_before_turn()

    def test_effective_config_tampering_refuses_before_turn(self):
        mutations = (
            ("feature_missing", lambda w: w.config["features"].pop("apps", None)),
            ("feature_enabled", lambda w: w.config["features"].__setitem__("tool_suggest", True)),
            ("features_absent", lambda w: w.config.pop("features", None)),
            ("dynamic_tools", lambda w: w.config.__setitem__("dynamic_tools", ["command/exec"])),
            ("provider_fallback", lambda w: w.config.__setitem__("allow_provider_model_fallback", True)),
            ("service_tier", lambda w: w.config.__setitem__("service_tier", "fast")),
            ("approval_policy", lambda w: w.config.__setitem__("approval_policy", "on-request")),
            ("approval_policy_missing", lambda w: w.config.pop("approval_policy", None)),
            ("approvals_reviewer", lambda w: w.config.__setitem__("approvals_reviewer", "guardian")),
            ("approvals_reviewer_missing", lambda w: w.config.pop("approvals_reviewer", None)),
        )
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                wire = self.prepare_strict()
                send = wire.send
                def corrupt(message, _send=send, _mutate=mutate):
                    if message.get("method") == "config/read":
                        _mutate(wire)
                    _send(message)
                wire.send = corrupt
                self.run_gate()
                self.assert_refused_before_turn()

    # --- fresh Native catalog ---------------------------------------------

    def test_fresh_catalog_accepts_01601_and_exact_selected_effort(self):
        calls = []
        def rpc(method, params):
            calls.append(method)
            return {"data": MODEL_ROWS}
        result = verify_selection(rpc, model="gpt-6-astra", effort="medium",
            effective_effort="medium", native_version="codex-cli 0.160.1",
            request_digest="0" * 64)
        self.assertEqual(result["requested_effort"], "medium")
        self.assertEqual(result["effective_effort"], "medium")
        self.assertEqual(result["native_version"], "codex-cli 0.160.1")
        self.assertEqual(calls, ["model/list"])

    def test_fresh_catalog_rejects_unknown_version_or_missing_effort(self):
        rpc = lambda method, params: {"data": MODEL_ROWS}
        for changes in ({"native_version": "codex-cli 0.160.2"},
                        {"effort": "extreme", "effective_effort": "extreme"},
                        {"effort": None, "effective_effort": "extreme"},
                        {"model": "gpt-6-unknown"}):
            kwargs = dict(model="gpt-6-astra", effort="medium",
                          effective_effort="medium",
                          native_version="codex-cli 0.160.1",
                          request_digest="0" * 64)
            kwargs.update(changes)
            with self.subTest(**changes), self.assertRaises(HostUnverified):
                verify_selection(rpc, **kwargs)


if __name__ == "__main__":
    unittest.main()
