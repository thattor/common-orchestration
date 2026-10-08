"""Independent oracle fixtures; every subprocess is a local synthetic stub."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from co_v4.codex_host import HostUnverified
from co_v4.adapters.codex import NativeError, StdioTransport
from probes.codex_profile_acceptance import qualification_request, service_tier_diagnostic, service_tier_overrides, verify_service_tier, run, ObservedTransport, EXPECTED, subscription_gate, result_projection, acceptance_passed, auth_metadata
from co_v4.contracts import AttemptRef, Result, ResultEvent, StatusEvent, State


def frames(text=EXPECTED):
    return [
        {"method": "item/started", "params": {"startedAtMs": 1, "threadId": "t", "turnId": "u", "item": {"id": "i", "type": "agentMessage", "text": ""}}},
        {"method": "item/agentMessage/delta", "params": {"threadId": "t", "turnId": "u", "itemId": "i", "delta": text}},
        {"method": "item/completed", "params": {"completedAtMs": 2, "threadId": "t", "turnId": "u", "item": {"id": "i", "type": "agentMessage", "text": text}}},
        {"method": "turn/completed", "params": {"threadId": "t", "turn": {"id": "u", "status": "completed", "itemsView": "notLoaded", "items": [], "error": None}}}]


class AcceptanceTests(unittest.TestCase):
    def test_exact_sol_selection_binds_request_without_relabeling_astra(self):
        root = Path("/private/tmp/fixed-test")
        astra = qualification_request(root, "a" * 32)
        sol = qualification_request(root, "b" * 32, model="gpt-6-sol")
        self.assertEqual(astra.conditions.model, "gpt-6-astra")
        self.assertEqual(astra.ref.run_id, "platform-authorized-astra")
        self.assertEqual(sol.conditions.model, "gpt-6-sol")
        self.assertEqual(sol.ref.run_id, "platform-authorized-sol")
        self.assertEqual(sol.job.run_id, sol.ref.run_id)
        self.assertEqual(sol.conditions.workspace, str(root / "worker"))
        self.assertEqual(sol.conditions.environment_ref, "candidate:codex-profile:" + sol.ref.attempt_id)
        self.assertEqual(sol.job.instructions, astra.job.instructions)
        self.assertEqual(sol.job.context_json, "{}")
        self.assertEqual(sol.job.acceptance_criteria, astra.job.acceptance_criteria)
        fast = qualification_request(root, "b" * 32, model="gpt-6-sol", service_tier="fast")
        self.assertEqual(fast.conditions.control_evidence_refs, ("current-platform-authorization", "reasoning-effort:medium", "service-tier:fast"))
        self.assertNotEqual(sol, fast)

    def test_invalid_model_syntax_never_performs_io(self):
        for model in ("", "has space", "line\nbreak", None, [], "x" * 129):
            with self.subTest(model=model), patch.object(Path, "mkdir") as mkdir:
                with self.assertRaisesRegex(HostUnverified, "^qualification_model_unsupported$"):
                    run(Path("/private/tmp/must-not-exist"), authorization_ref="fixture",
                        authorize=lambda *_: self.fail("must not authorize"), source_manifest={}, model=model)
                mkdir.assert_not_called()

    def test_qualification_attempt_cannot_carry_arbitrary_context(self):
        for value in ("", "private-canary", "A" * 32, "a" * 31, None):
            with self.assertRaisesRegex(HostUnverified, "^qualification_attempt_invalid$"):
                qualification_request(Path("/private/tmp/fixed-test"), value, model="gpt-6-sol")

    def test_fast_requires_effective_config_original_thread_and_enabled_feature(self):
        config = {"service_tier": "fast", "features": {"fast_mode": True}}
        native = {"serviceTier": "priority"}
        self.assertEqual(service_tier_overrides("fast"), ('service_tier="fast"', 'features.fast_mode=true'))
        self.assertEqual(service_tier_overrides("default"), ())
        value = verify_service_tier("fast", config, native)
        self.assertTrue(value["fast_configuration_verified"])
        self.assertFalse(value["speed_increase_measured"])
        for changed_config, changed_native in (
            ({}, native), ({**config, "service_tier": "default"}, native),
            ({**config, "features": {}}, native), ({**config, "features": {"fast_mode": 1}}, native),
            (config, {}), (config, {"serviceTier": "default"}), (config, {"serviceTier": "fast"}), (config, {"serviceTier": "flex"}),
            (config, {"serviceTier": "private-canary"}), (None, native)):
            with self.assertRaisesRegex(HostUnverified, "^qualification_service_tier_unverified$"):
                verify_service_tier("fast", changed_config, changed_native)

    def test_legacy_default_does_not_echo_unknown_feature_values(self):
        observed = verify_service_tier("default", {
            "features": {"fast_mode": "SECRET-CANARY"}}, {})
        self.assertIsNone(observed["effective_fast_mode"])
        self.assertNotIn("SECRET-CANARY", repr(observed))

    def test_competing_override_spellings_are_rejected(self):
        from co_v4.codex_service_tier import append_service_tier_overrides
        for override in (' service_tier = "fast"', '"service_tier"="fast"',
                         'features . fast_mode=true', 'features={fast_mode=true}',
                         'features="invalid"', 'not toml'):
            with self.subTest(override=override), self.assertRaises(HostUnverified):
                append_service_tier_overrides((override,), "normal")
        self.assertEqual(append_service_tier_overrides(('features.apps=false',), "fast")[-2:],
                         service_tier_overrides("fast"))

    def test_mode_entry_canonicalizes_alias_and_rejects_conflict(self):
        from co_v4.codex_service_tier import select_service_tier
        self.assertEqual(select_service_tier("tibo"), "fast")
        self.assertEqual(select_service_tier("fast"), "fast")
        self.assertEqual(select_service_tier("normal"), "normal")
        self.assertEqual(select_service_tier(), "default")
        self.assertEqual(select_service_tier(service_tier="fast"), "fast")
        for mode, tier in (("normal", "fast"), ("tibo", "normal"), ("unknown", "default")):
            with self.assertRaises(HostUnverified):
                run(Path("/private/tmp/must-not-exist"), authorization_ref="fixture",
                    authorize=lambda *_: self.fail("must not authorize"), source_manifest={},
                    mode=mode, service_tier=tier)
        a = qualification_request(Path("/tmp"), "b" * 32, mode="fast")
        b = qualification_request(Path("/tmp"), "b" * 32, mode="tibo")
        self.assertEqual(a, b)

    def test_normal_requires_explicit_effective_feature_and_thread_evidence(self):
        config = {"service_tier": "default", "features": {"fast_mode": False}}
        native = {"serviceTier": None}
        self.assertTrue(verify_service_tier("normal", config, native)["matched_before_turn"])
        for cfg, thread in (({}, native), (config, {}), (config, {"serviceTier": "priority"}),
                            ({**config, "features": {}}, native),
                            ({**config, "features": {"fast_mode": True}}, native),
                            ({**config, "service_tier": "fast"}, native)):
            with self.assertRaises(HostUnverified):
                verify_service_tier("normal", cfg, thread)

    def test_default_does_not_silently_adopt_paid_or_fast_tier(self):
        for config, native in (({}, {}), ({"service_tier": "default"}, {"serviceTier": "default"})):
            self.assertFalse(verify_service_tier("default", config, native)["fast_configuration_verified"])
        for tier in ("fast", "flex", "private-canary"):
            with self.assertRaises(HostUnverified):
                verify_service_tier("default", {"service_tier": tier}, {"serviceTier": tier})
        for tier in ("flex", None, [], "private-canary"):
            with patch.object(Path, "mkdir") as mkdir:
                with self.assertRaisesRegex(HostUnverified, "^qualification_service_tier_unsupported$"):
                    run(Path("/private/tmp/must-not-exist"), authorization_ref="fixture",
                        authorize=lambda *_: self.fail("must not authorize"), source_manifest={}, service_tier=tier)
                mkdir.assert_not_called()

    def test_fast_configuration_is_not_included_usage_authority(self):
        verify_service_tier("fast", {"service_tier": "fast", "features": {"fast_mode": True}}, {"serviceTier": "priority"})
        for allowed in (False, None, "true", 1):
            with self.assertRaisesRegex(HostUnverified, "included_subscription_usage_unverified"):
                subscription_gate(self.account(), {"ordinaryUsageAllowed": allowed, "rateLimits": {}}, api_environment_absent=True)

    def test_tier_diagnostic_retains_only_fixed_booleans_not_unknown_values(self):
        value = service_tier_diagnostic({"service_tier": "SECRET-CANARY", "features": {"fast_mode": "SECRET-CANARY"}},
                                        {"serviceTier": "SECRET-CANARY"})
        self.assertTrue(all(type(item) is bool for item in value.values()))
        self.assertNotIn("SECRET-CANARY", repr(value))
        self.assertTrue(value["config_tier_present"])
        self.assertFalse(value["config_tier_fast"])
        self.assertFalse(value["fast_feature_boolean"])
        missing = service_tier_diagnostic(None, {})
        self.assertFalse(missing["config_object"])
        self.assertFalse(missing["thread_tier_present"])

    def test_fast_retained_acceptance_requires_all_actual_tier_evidence(self):
        good = {"subscription_precondition": {"ordinary_included_usage_allowed": True},
            "adapter_result": {"state": "completed"}, "native": {"scoped_completion_evidence_complete": True},
            "source_verified_after_cleanup": True, "control_store_unchanged": True, "workspace_entries": 0}
        self.assertTrue(acceptance_passed(good))  # Original Astra schema remains historical.
        good["requested_service_tier"] = "fast"
        self.assertFalse(acceptance_passed(good))
        tier = verify_service_tier("fast", {"service_tier": "fast", "features": {"fast_mode": True}}, {"serviceTier": "priority"})
        good["service_tier_observation"] = tier
        self.assertTrue(acceptance_passed(good))
        for key in ("requested", "effective_config", "original_thread_response", "matched_before_turn", "fast_configuration_verified"):
            self.assertFalse(acceptance_passed({**good, "service_tier_observation": {**tier, key: None}}))

    def account(self): return {"account": {"type": "chatgpt", "planType": "pro", "email": "CANARY-private@example.invalid"}, "requiresOpenaiAuth": True}

    def test_unchanged_store_and_empty_workspace_are_acceptance_conditions(self):
        good = {"subscription_precondition": {"ordinary_included_usage_allowed": True},
            "adapter_result": {"state": "completed"}, "native": {"scoped_completion_evidence_complete": True},
            "source_verified_after_cleanup": True, "control_store_unchanged": True, "workspace_entries": 0}
        self.assertTrue(acceptance_passed(good))
        for key, value in (("control_store_unchanged", False), ("workspace_entries", 1),
                           ("workspace_entries", None), ("workspace_entries", False),
                           ("source_verified_after_cleanup", False)):
            self.assertFalse(acceptance_passed({**good, key: value}))

    def test_account_notification_is_observed_at_any_rpc_phase_without_admission(self):
        notice = {"method": "account/updated", "params": {"authMode": "chatgpt", "planType": "pro"}}
        response = {"id": "account-rpc", "result": {"account": None}}
        wire = self.observer(); wire.rpc["account-rpc"] = "account/read"
        with patch.object(StdioTransport, "poll", return_value=[notice, response, notice]):
            self.assertEqual(wire.poll(), [notice, response, notice])
        self.assertEqual(wire.account_notifications, 2)
        self.assertFalse(wire.evidence()["scoped_completion_evidence_complete"])
        with self.assertRaises(HostUnverified):
            subscription_gate(response["result"], {"ordinaryUsageAllowed": True, "rateLimits": {}}, api_environment_absent=True)
        wire.rpc["other"] = "account/rateLimits/read"
        idle = {"method": "thread/status/changed", "params": {"threadId": "t", "status": {"type": "idle"}}}
        with patch.object(StdioTransport, "poll", return_value=[notice, idle]):
            self.assertEqual(wire.poll(), [notice, idle])

    def test_account_notification_malformed_unknown_or_request_never_filtered(self):
        notice = {"method": "account/updated", "params": {"authMode": "chatgpt", "planType": "pro"}}
        variants = [{**notice, "params": {"authMode": "CANARY"}},
                    {**notice, "params": {"authMode": "chatgpt", "unknown": "CANARY"}},
                    {**notice, "id": "native-request"}, {**notice, "method": "account/unknown"}]
        for value in variants:
            wire = self.observer(); wire.rpc["account-rpc"] = "account/read"
            with patch.object(StdioTransport, "poll", return_value=[value]):
                with self.assertRaises(NativeError): wire.poll()
            self.assertNotIn("CANARY", repr(wire.evidence()))
            self.assertEqual(wire.account_notifications, 0)

    def test_authentication_metadata_does_not_open_contents_or_claim_content_identity(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "synthetic-auth"
            path.write_text("private-canary")
            with patch.object(Path, "open", side_effect=AssertionError("must not open")):
                before = auth_metadata(path)
                self.assertEqual(before, auth_metadata(path))
                self.assertNotIn("private-canary", repr(before))
                path.chmod((before["mode"] & 0o777) ^ 0o100)
                self.assertNotEqual(before, auth_metadata(path))
                path.unlink()
                self.assertIsNone(auth_metadata(path))

    def test_result_requires_single_exact_attempt_event_separate_from_status(self):
        ref = AttemptRef("run", "job", "attempt")
        event = ResultEvent(ref, "event", Result(ref, State.COMPLETED))
        self.assertEqual(result_projection((event,), ref)["state"], "completed")
        self.assertIsNone(result_projection((StatusEvent(ref, "status", State.COMPLETED),), ref))
        self.assertIsNone(result_projection((event, event), ref))
        self.assertIsNone(result_projection((event,), AttemptRef("run", "job", "other")))
        self.assertIsNone(result_projection((ResultEvent(ref, "", event.result),), ref))
        failure = ResultEvent(ref, "failed", Result(ref, State.ERROR, "adapter_transport_error"))
        self.assertEqual(result_projection((failure,), ref)["state"], "error")

    def test_included_subscription_metadata_only_no_private_fields(self):
        value = subscription_gate(self.account(), {"ordinaryUsageAllowed": True, "rateLimits": {}}, api_environment_absent=True)
        self.assertTrue(value["ordinary_included_usage_allowed"])
        self.assertNotIn("CANARY", repr(value))
        self.assertNotIn("email", value)

    def test_no_inference_from_percent_credit_or_truthy_usage(self):
        for value in (None, False, 1, "true"):
            with self.assertRaises(HostUnverified):
                subscription_gate(self.account(), {"ordinaryUsageAllowed": value,
                    "rateLimits": {"primary": {"usedPercent": 0}, "credits": {"hasCredits": True, "unlimited": True}}},
                    api_environment_absent=True)
        for account in ({"account": None}, {"account": {"type": "apiKey"}, "requiresOpenaiAuth": True},
                        {"account": {"type": "chatgpt", "planType": "unknown"}, "requiresOpenaiAuth": True}):
            with self.assertRaises(HostUnverified): subscription_gate(account, {"ordinaryUsageAllowed": True, "rateLimits": {}}, api_environment_absent=True)
        with self.assertRaises(HostUnverified): subscription_gate(self.account(), {"ordinaryUsageAllowed": True, "rateLimits": {}}, api_environment_absent=False)

    def observer(self, messages=(), tail="", original_reply=True):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        if original_reply and messages:
            messages = [{"id": "turn-rpc", "result": {"turn": {"id": "u", "status": "inProgress"}}}, *messages]
        script = root / "synthetic-native"
        script.write_text("#!" + sys.executable + "\nimport sys,json\n"
            "if '--version' in sys.argv:\n print('codex-cli 0.159.2')\nelse:\n"
            " for line in sys.stdin: pass\n"
            " for m in " + repr(messages) + ": print(json.dumps(m))\n"
            " sys.stdout.write(" + repr(tail) + ");sys.stdout.flush()\n")
        script.chmod(0o700)
        wire = ObservedTransport(str(script), str(root), required_version="codex-cli 0.159.2")
        self.addCleanup(wire.close)
        wire.thread = "t"; wire.turn_submissions = 1
        wire.rpc["turn-rpc"] = "turn/start"
        return wire

    def test_exact_text_terminal_owned_eof_wait_are_separate_requirements(self):
        wire = self.observer(frames())
        self.assertFalse(wire.evidence()["scoped_completion_evidence_complete"])
        wire.close(); receipt = wire.evidence()
        self.assertTrue(receipt["independent_response_ac_passed"])
        self.assertTrue(receipt["validated_eof"])
        self.assertEqual(receipt["owned_wait_exit"], 0)
        self.assertTrue(receipt["scoped_completion_evidence_complete"])
        self.assertFalse(receipt["generic_cessation_capability_granted"])

    def test_wrong_text_does_not_pass_even_with_completion_and_exit(self):
        wire = self.observer(frames(EXPECTED + "wrong")); wire.close()
        self.assertFalse(wire.evidence()["independent_response_ac_passed"])

    def test_truncated_eof_and_post_terminal_activity_refuse(self):
        wire = self.observer(frames(), '{"truncated":'); wire.close()
        self.assertFalse(wire.evidence()["scoped_completion_evidence_complete"])
        wire2 = self.observer(frames() + [frames()[1]]); wire2.close()
        self.assertFalse(wire2.evidence()["scoped_completion_evidence_complete"])

    def test_notification_and_exit_without_original_rpc_are_not_completion_proof(self):
        wire = self.observer(frames(), original_reply=False); wire.close()
        self.assertTrue(wire.evidence()["independent_response_ac_passed"])
        self.assertFalse(wire.evidence()["scoped_completion_evidence_complete"])
        wire2 = self.observer(frames() + [{"method": "thread/status/changed", "params": {
            "threadId": "t", "status": {"type": "active", "activeFlags": []}}}]); wire2.close()
        self.assertFalse(wire2.evidence()["scoped_completion_evidence_complete"])

    def test_unknown_tool_foreign_turn_and_unfinished_item_refuse(self):
        variants = []
        tool = frames(); tool[0]["params"]["item"]["type"] = "commandExecution"; variants.append(tool)
        foreign = frames(); foreign[1]["params"]["turnId"] = "other"; variants.append(foreign)
        unfinished = frames(); unfinished.pop(2); variants.append(unfinished)
        delta = frames(); delta[2]["params"]["item"]["text"] = "different"; variants.append(delta)
        for items in variants:
            wire = self.observer(items); wire.close()
            self.assertFalse(wire.evidence()["scoped_completion_evidence_complete"])

    def test_drain_unknown_method_and_malformed_known_metadata_refuse(self):
        late = [
            {"method": "unknown/private-name", "params": {}},
            {"method": "warning", "params": {"message": "canary", "threadId": "foreign"}},
            {"method": "warning", "params": {"message": "canary", "threadId": "t", "extra": None}},
            {"method": "remoteControl/status/changed", "params": {"status": "connected", "installationId": "x", "serverName": "x"}},
            {"method": "thread/tokenUsage/updated", "params": {"threadId": "t", "turnId": "u", "tokenUsage": None}},
            {"method": "account/rateLimits/updated", "params": {"rateLimits": {"primary": {"usedPercent": "canary"}}}},
        ]
        for message in late:
            wire = self.observer(frames() + [message]); wire.close()
            self.assertFalse(wire.evidence()["scoped_completion_evidence_complete"])
            self.assertNotIn("canary", repr(wire.evidence()))

    def test_typed_idle_metadata_is_allowed_but_missing_activity_fields_refuse(self):
        idle = {"method": "thread/status/changed", "params": {"threadId": "t", "status": {"type": "idle"}}}
        wire = self.observer(frames() + [idle]); wire.close()
        self.assertTrue(wire.evidence()["scoped_completion_evidence_complete"])
        for index, key in ((0, "startedAtMs"), (2, "completedAtMs")):
            values = frames(); del values[index]["params"][key]
            wire = self.observer(values); wire.close()
            self.assertFalse(wire.evidence()["scoped_completion_evidence_complete"])

    def test_nonempty_terminal_inventory_must_match_observed_completed_items(self):
        good = frames(); item = copy.deepcopy(good[2]["params"]["item"])
        good[-1]["params"]["turn"]["items"] = [item]
        good[-1]["params"]["turn"]["itemsView"] = "full"
        wire = self.observer(good); wire.close()
        self.assertTrue(wire.evidence()["scoped_completion_evidence_complete"])
        for items in ([{**item, "id": "unobserved", "text": "EXTRA UNOBSERVED OUTPUT"}],
                      [item, item], [{**item, "text": "different"}]):
            bad = frames(); bad[-1]["params"]["turn"]["items"] = items
            bad[-1]["params"]["turn"]["itemsView"] = "full"
            wire = self.observer(bad); wire.close()
            self.assertFalse(wire.evidence()["scoped_completion_evidence_complete"])

    def test_summary_is_exact_observed_agent_not_full_stream_inventory(self):
        values = frames(); item = copy.deepcopy(values[2]["params"]["item"])
        reasoning = {"id": "reasoning", "type": "reasoning", "content": [], "summary": []}
        prefix = [
            {"method": "item/started", "params": {"threadId": "t", "turnId": "u", "startedAtMs": 1, "item": reasoning}},
            {"method": "item/completed", "params": {"threadId": "t", "turnId": "u", "completedAtMs": 2, "item": reasoning}}]
        values[-1]["params"]["turn"].update(itemsView="summary", items=[item])
        wire = self.observer(prefix + values); wire.close()
        self.assertTrue(wire.evidence()["scoped_completion_evidence_complete"])
        inventory = wire.evidence()["terminal_inventory"]
        self.assertEqual((inventory["terminal_count"], inventory["completed_count"], inventory["matched_id_count"]), (1, 2, 1))
        variants = [("summary", []), ("summary", [reasoning]), ("summary", [item, item]),
                    ("summary", [{**item, "id": "CANARY-unobserved"}]),
                    ("summary", [{**item, "text": "CANARY-other-answer"}]),
                    ("full", [item]), ("notLoaded", [item]), ("full", []), ("unknown", [item])]
        for view, items in variants:
            bad = copy.deepcopy(values); bad[-1]["params"]["turn"].update(itemsView=view, items=items)
            wire = self.observer(prefix + bad); wire.close(); receipt = wire.evidence()
            self.assertFalse(receipt["scoped_completion_evidence_complete"])
            self.assertNotIn("CANARY", repr(receipt))
        full = copy.deepcopy(values); full[-1]["params"]["turn"].update(items=[reasoning, item])
        del full[-1]["params"]["turn"]["itemsView"]  # official default: full
        wire = self.observer(prefix + full); wire.close()
        self.assertTrue(wire.evidence()["scoped_completion_evidence_complete"])
        missing = copy.deepcopy(values); del missing[-1]["params"]["turn"]["itemsView"]
        wire = self.observer(prefix + missing); wire.close()
        self.assertFalse(wire.evidence()["scoped_completion_evidence_complete"])

    def test_diagnostics_distinguish_schema_inventory_and_unknown_method_without_values(self):
        bad_schema = frames(); bad_schema[-1]["params"]["CANARY-key"] = "CANARY-value"
        bad_inventory = frames(); bad_inventory[-1]["params"]["turn"]["items"] = [
            {"id": "CANARY-id", "type": "agentMessage", "text": "CANARY-text"}]
        unknown = frames() + [{"method": "CANARY-method", "params": {"CANARY-key": "CANARY-value"}}]
        for messages, code, method in ((bad_schema, "observed_metadata_schema_invalid", "turn/completed"),
                (bad_inventory, "terminal_inventory_mismatch", "turn/completed"),
                (unknown, "unmapped_native_notification", "unmapped")):
            wire = self.observer(messages); wire.close(); evidence = wire.evidence()
            diagnostic = evidence["observation_failure"]
            self.assertEqual(diagnostic["phase"], "drain")
            self.assertEqual(diagnostic["category"], code)
            self.assertEqual(diagnostic["method"], method)
            self.assertNotIn("CANARY", repr(evidence))
            self.assertFalse(evidence["scoped_completion_evidence_complete"])

    def test_diagnostics_never_retain_decoder_exception_or_raw_frame(self):
        wire = self.observer()
        with patch.object(StdioTransport, "poll", side_effect=NativeError("CANARY-private-error")):
            with self.assertRaises(NativeError): wire.poll()
        diagnostic = wire.evidence()["observation_failure"]
        self.assertEqual(diagnostic["category"], "stream_decode_unverified")
        self.assertEqual(diagnostic["phase"], "poll")
        wire.close()
        self.assertEqual(wire.evidence()["observation_failure"], diagnostic)
        self.assertNotIn("CANARY", repr(wire.evidence()))

if __name__ == "__main__": unittest.main()
