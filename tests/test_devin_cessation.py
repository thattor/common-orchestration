"""Trusted text-host proof tests using owned offline child processes, not Native."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from co_v4.adapters.devin import AcpTransport, DevinAdapter
from co_v4.contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job, State, StopStatus
from co_v4.delegation import DelegatedScope
from co_v4.devin_host import DevinHostConfig, DevinTextHost


class CessationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.worker = self.root / "worker"
        self.worker.mkdir()
        self.state = self.root / "control.db"
        self.state.write_text("fixture control")
        self.credential = self.root / "auth"
        self.credential.write_text("fixture only; never read")
        self.executable = self.root / "devin-fixture"
        fixture = Path(__file__).with_name("fixtures") / "devin_cessation.py"
        self.executable.write_text(f"#!{sys.executable}\n" + fixture.read_text())
        self.executable.chmod(0o700)
        for name, value in (("platform.system", "Darwin"), ("platform.machine", "arm64")):
            patcher = patch(name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def fixture_model(self, scenario):
        # Scenario belongs to the offline child, never to production selection.
        self.executable.with_suffix(".scenario").write_text(scenario)
        return "swe-2-high"

    def launch(self, scenario="normal", generic=False):
        self.ref = AttemptRef("r", "j", scenario)
        conditions = ExecutionConditions(self.fixture_model(scenario), "devin.acp", str(self.worker), "env", ("controls",))
        self.request = ExecuteRequest(self.ref, Job("r", "j", "offline fixture", ()), conditions)
        self.host = DevinTextHost(DevinHostConfig(conditions, self.executable,
            "devin-cessation-fixture 0", (self.state,), (self.credential,),
            DelegatedScope("fixture-intent", self.ref, str(self.worker), "devin.text.only")))
        self.adapter = (DevinAdapter(verify_host=self.host.verify, transport_factory=self.host.transport)
                        if generic else self.host.make_adapter())
        self.addCleanup(self.adapter.close)
        self.assertEqual(self.adapter.execute(self.request).status.value, "accepted")
        self.until(lambda: self.host._transport.submitted)

    def until(self, predicate):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            self.adapter.events(self.ref)
            if predicate():
                return
            time.sleep(.005)
        self.fail("fixture did not reach expected state")

    def finish(self):
        self.until(lambda: self.adapter.status(self.ref).state in (State.COMPLETED, State.ERROR, State.FAILED))
        return self.adapter.stop(self.ref)

    def test_normal_original_prompt_and_wait_bound_without_private_ids(self):
        self.launch()
        stop = self.finish()
        self.assertEqual(stop.status, StopStatus.CONFIRMED)
        proof = self.host.observation["cessation"]
        inner = self.host._transport.inner
        self.assertEqual(proof["native_stop_reason"], "end_turn")
        self.assertEqual(proof["owned_exit_code"], 0)
        self.assertEqual(proof["owned_cleanup_action"], "terminate")
        self.assertEqual(proof["owned_pid"], inner._process.pid)
        self.assertIsNotNone(inner._process.returncode)
        self.assertTrue(proof["stdout_eof_validated"])
        self.assertEqual(proof["prompt_rpc_sha256"], hashlib.sha256(inner.prompt_binding[1].encode()).hexdigest())
        self.assertNotIn(inner.prompt_binding[0], json.dumps(self.host.observation))
        self.assertNotIn(inner.prompt_binding[1], repr(stop))
        self.assertEqual(self.adapter.stop(self.ref), stop)
        self.assertEqual(self.adapter.status(self.ref).state, State.COMPLETED)

    def test_model_selection_and_advertisement_are_bound_to_cessation(self):
        for scenario, verified in (("normal", False), ("model_advertised", True), ("late_model_match", True)):
            self.launch(scenario)
            self.assertEqual(self.finish().status, StopStatus.CONFIRMED)
            proof = self.host.observation["cessation"]
            self.assertEqual(proof["requested_model"], "swe-2-high")
            self.assertEqual(proof["selection"]["effort"], "high")
            self.assertEqual(proof["effective_model_verified"], verified)
            self.assertEqual(proof["effective_model"], "swe-2-high" if verified else None)
            self.assertFalse(proof["effective_effort_verified"])

    def test_cancel_requires_original_prompt_response_and_records_cancelled(self):
        self.launch("cancel")
        first = self.adapter.stop(self.ref)
        self.assertEqual(first.status, StopStatus.UNCONFIRMED)
        stop = self.finish()
        self.assertEqual(stop.status, StopStatus.CONFIRMED)
        self.assertEqual(self.host.observation["cessation"]["native_stop_reason"], "cancelled")
        self.assertEqual(self.adapter.status(self.ref).state, State.FAILED)
        self.assertEqual(self.adapter.stop(self.ref), stop)

    def test_normal_completion_winning_cancel_race_stays_distinct(self):
        self.launch("cancel_end_turn")
        self.adapter.stop(self.ref)
        self.assertEqual(self.finish().status, StopStatus.CONFIRMED)
        self.assertEqual(self.host.observation["cessation"]["native_stop_reason"], "end_turn")

    def test_cancel_missing_response_timeout_stays_unconfirmed(self):
        self.launch("cancel_silent")
        now = [0.0]
        self.adapter._clock = lambda: now[0]
        self.adapter._timeout = 1
        self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        self.assertTrue(self.host._transport.inner.alive())
        now[0] = 2
        self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
        self.assertNotIn("cessation", self.host.observation)

    def test_cancel_receipt_or_wrong_original_response_never_proves_stop(self):
        for scenario in ("cancel_receipt", "cancel_wrong_rpc"):
            with self.subTest(scenario=scenario):
                self.launch(scenario)
                self.adapter.stop(self.ref)
                self.assertEqual(self.finish().status, StopStatus.UNCONFIRMED)
                self.assertNotIn("cessation", self.host.observation)

    def test_unrequested_cancelled_never_proves_our_cancel(self):
        self.launch("unrequested_cancel")
        self.assertEqual(self.finish().status, StopStatus.UNCONFIRMED)

    def test_process_exit_without_completion_is_unconfirmed(self):
        self.launch("exit_only")
        self.assertEqual(self.finish().status, StopStatus.UNCONFIRMED)
        self.assertIsNotNone(self.host._transport.inner._process.returncode)

    def test_generic_adapter_has_no_cessation_authority(self):
        self.launch(generic=True)
        self.assertEqual(self.finish().status, StopStatus.UNCONFIRMED)
        self.assertEqual(self.adapter.status(self.ref).state, State.COMPLETED)

    def test_unknown_activity_or_mismatched_response_cannot_complete(self):
        for scenario in ("tool", "permission", "unknown_update", "unknown_notification", "wrong_session", "wrong_rpc"):
            with self.subTest(scenario=scenario):
                self.launch(scenario)
                self.assertEqual(self.finish().status, StopStatus.UNCONFIRMED)
                self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
                self.assertNotIn("cessation", self.host.observation)

    def test_trailing_frames_emitted_only_during_reap_are_validated(self):
        for scenario in ("late_mode", "late_tool", "late_permission", "late_unknown",
                         "late_wrong_session", "late_bad_json", "late_truncated",
                         "late_model", "late_model_empty"):
            with self.subTest(scenario=scenario):
                self.launch(scenario)
                self.assertEqual(self.finish().status, StopStatus.UNCONFIRMED)
                self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
                self.assertNotIn("cessation", self.host.observation)

    def test_benign_trailing_chunk_is_drained_to_eof(self):
        self.launch("late_benign")
        self.assertEqual(self.finish().status, StopStatus.CONFIRMED)

    def test_wait_failure_cannot_mint_proof(self):
        self.launch()
        inner = self.host._transport.inner
        with patch.object(inner, "reap_owned", side_effect=subprocess.TimeoutExpired("fixture", 1)):
            self.assertEqual(self.finish().status, StopStatus.UNCONFIRMED)
        inner.close()
        self.assertNotIn("cessation", self.host.observation)

    def test_bound_host_rejects_changed_attempt_session_or_rpc(self):
        self.launch("cancel_silent")
        original_session, original_rpc = self.host._transport.inner.prompt_binding
        for request, session, rpc in (
                (replace(self.request, ref=AttemptRef("r", "j", "other")), original_session, original_rpc),
                (self.request, "wrong-session", original_rpc),
                (self.request, original_session, "wrong-rpc")):
            with self.subTest(session=session, rpc=rpc), self.assertRaises(Exception):
                self.host.verify_text_cessation(request, session, rpc, "end_turn", lambda _: None)
        self.assertTrue(self.host._transport.inner.alive())

    def test_non_eof_cannot_mint_proof(self):
        self.launch()
        with patch.object(self.host._transport.inner, "drained", return_value=False):
            self.assertEqual(self.finish().status, StopStatus.UNCONFIRMED)
        self.assertNotIn("cessation", self.host.observation)

    def test_fake_transport_with_lookalike_proof_is_unconfirmed(self):
        from test_devin_host import DevinHostTests
        fixture = DevinHostTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.wire.prompt_binding = ("fixture-session", "pretend-rpc")
        fixture.wire._waited_exit = 0
        fixture.wire.cessation = "devin.acp:text-only:end_turn:pretend-proof"
        fixture.run_attempt()
        self.assertEqual(fixture.adapter.status(fixture.request.ref).state, State.COMPLETED)
        self.assertEqual(fixture.adapter.stop(fixture.request.ref).status, StopStatus.UNCONFIRMED)
        self.assertNotIn("cessation", fixture.host.observation)

    def test_bounded_probe_normal_and_cancel_use_production_composition(self):
        from probes.devin_cessation import run
        for mode, model in (("normal", "normal"), ("cancel", "cancel")):
            with self.subTest(mode=mode):
                receipt = run(self.root / "probes", executable=self.executable,
                    native_version="devin-cessation-fixture 0", model=self.fixture_model(model),
                    credential_files=(self.credential,), human_intent_ref="fixture-intent",
                    mode=mode, timeout=2, cancel_after=0)
                self.assertNotIn("probe_failure", receipt)
                self.assertEqual(receipt["stop_status"], "confirmed")
                self.assertTrue(receipt["matched_requested_completion"])
                self.assertEqual(receipt["model_turns_submitted"], 1)
                self.assertEqual(receipt["cancel_notifications_sent"], int(mode == "cancel"))
                self.assertTrue(receipt["owned_cli_reaped"])
                self.assertTrue(receipt["control_sentinel_unchanged"])
                self.assertTrue(receipt["worker_workspace_empty"])
                self.assertFalse(receipt["controller_goal_evaluated"])
                saved = json.loads((Path(receipt["scratch_ref"]) / "evidence.json").read_text())
                self.assertEqual(saved, receipt)

    def test_bounded_probe_timeout_cannot_claim_cancel_completion(self):
        from probes.devin_cessation import run
        receipt = run(self.root / "probes", executable=self.executable,
            native_version="devin-cessation-fixture 0", model=self.fixture_model("cancel_silent"),
            credential_files=(self.credential,), human_intent_ref="fixture-intent",
            mode="cancel", timeout=1, cancel_after=0)
        self.assertEqual(receipt["stop_status"], "unconfirmed")
        self.assertFalse(receipt["matched_requested_completion"])
        self.assertTrue(receipt["timeout"])
        self.assertTrue(receipt["owned_cli_reaped"])

    def test_preflight_probe_cannot_submit_even_when_bootstrap_succeeds(self):
        from probes.devin_cessation import run
        receipt = run(self.root / "probes", executable=self.executable,
            native_version="devin-cessation-fixture 0", model=self.fixture_model("normal"),
            credential_files=(self.credential,), human_intent_ref="fixture-intent",
            timeout=2, preflight_only=True)
        self.assertEqual(receipt["model_turns_submitted"], 0)
        self.assertTrue(receipt["model_submission_blocked_by_probe"])
        self.assertTrue(receipt["owned_cli_reaped"])
        self.assertNotIn("cessation", receipt["host_observation"])

    def test_bootstrap_diagnostic_uses_only_fixed_phase_category_and_variant(self):
        from probes.devin_cessation import run
        for model, variant in (("bootstrap_unknown", "unclassified"),
                               ("bootstrap_model", "current_model_update")):
            receipt = run(self.root / "probes", executable=self.executable,
                native_version="devin-cessation-fixture 0", model=self.fixture_model(model),
                credential_files=(self.credential,), human_intent_ref="fixture-intent",
                timeout=2, preflight_only=True)
            self.assertEqual(receipt["model_turns_submitted"], 0)
            self.assertEqual(receipt["protocol_diagnostic"], {
                "phase": "session/new", "category": ("invalid_native_model_advertisement" if model == "bootstrap_model"
                    else "unsupported_text_update"), "variant": variant})
            self.assertNotIn("SECRET", json.dumps(receipt))
            self.assertNotIn("PRIVATE_ARBITRARY_VARIANT", json.dumps(receipt))
            self.assertNotIn("cessation", receipt["host_observation"])

    def test_unknown_bootstrap_method_fingerprint_never_emits_method_or_params(self):
        from probes.devin_cessation import run
        receipt = run(self.root / "probes", executable=self.executable,
            native_version="devin-cessation-fixture 0", model=self.fixture_model("bootstrap_notification"),
            credential_files=(self.credential,), human_intent_ref="fixture-intent",
            timeout=2, preflight_only=True)
        self.assertEqual(receipt["model_turns_submitted"], 0)
        diagnostic = receipt["protocol_diagnostic"]
        self.assertEqual(diagnostic["category"], "unknown_text_notification")
        self.assertEqual(diagnostic["method_length"], len("PRIVATE_METHOD_SECRET"))
        self.assertEqual(diagnostic["method_sha256"], hashlib.sha256(b"PRIVATE_METHOD_SECRET").hexdigest())
        self.assertNotIn("PRIVATE_METHOD_SECRET", json.dumps(receipt))
        self.assertNotIn("SECRET", json.dumps(receipt))

    def test_exact_native_bootstrap_envelopes_do_not_grant_cessation(self):
        from probes.devin_cessation import run
        receipt = run(self.root / "probes", executable=self.executable,
            native_version="devin-cessation-fixture 0", model=self.fixture_model("bootstrap_valid"),
            credential_files=(self.credential,), human_intent_ref="fixture-intent",
            timeout=2, preflight_only=True)
        self.assertTrue(receipt["model_submission_blocked_by_probe"])
        self.assertEqual(receipt["model_turns_submitted"], 0)
        self.assertEqual(receipt["stop_status"], "unconfirmed")
        self.assertNotIn("cessation", receipt["host_observation"])
        self.assertNotIn("PRIVATE_NATIVE_LOG", json.dumps(receipt))
        self.launch("bootstrap_valid")
        self.assertEqual(self.finish().status, StopStatus.CONFIRMED)

    def test_bootstrap_envelope_mismatch_still_fails_before_model_submission(self):
        from probes.devin_cessation import run
        for suffix in ("servers", "session", "type", "fields"):
            receipt = run(self.root / "probes", executable=self.executable,
                native_version="devin-cessation-fixture 0", model=self.fixture_model("bootstrap_invalid_" + suffix),
                credential_files=(self.credential,), human_intent_ref="fixture-intent",
                timeout=2, preflight_only=True)
            self.assertEqual(receipt["model_turns_submitted"], 0)
            self.assertNotIn("model_submission_blocked_by_probe", receipt)
            self.assertNotIn("cessation", receipt["host_observation"])
            self.assertNotIn("PRIVATE_NATIVE_LOG", json.dumps(receipt))
            self.assertIn(receipt["protocol_diagnostic"]["category"], {
                "invalid_servers_metadata_notification", "invalid_output_log_envelope",
                "unbound_output_log_session"})

    def test_known_metadata_after_prompt_or_during_reap_does_not_invalidate_actual_completion(self):
        for model in ("post_prompt_log", "post_prompt_servers", "late_log"):
            self.launch(model)
            self.assertEqual(self.finish().status, StopStatus.CONFIRMED)
            self.assertIsNone(self.adapter.protocol_diagnostic(self.ref))
            self.assertNotIn("PRIVATE_NATIVE_LOG", json.dumps(self.host.observation))

    def test_scoped_bootstrap_output_must_match_eventual_session_new(self):
        from probes.devin_cessation import run
        for suffix in ("valid", "mismatch", "conflict"):
            receipt = run(self.root / "probes", executable=self.executable,
                native_version="devin-cessation-fixture 0", model=self.fixture_model("bootstrap_candidate_" + suffix),
                credential_files=(self.credential,), human_intent_ref="fixture-intent",
                timeout=2, preflight_only=True)
            self.assertEqual(receipt["model_turns_submitted"], 0)
            self.assertEqual(receipt.get("model_submission_blocked_by_probe", False), suffix == "valid")
            self.assertNotIn("cessation", receipt["host_observation"])
            if suffix != "valid":
                self.assertIn(receipt["protocol_diagnostic"]["category"], {
                    "session_identity_mismatch", "unbound_output_log_session"})
        self.launch("bootstrap_candidate_valid")
        self.assertEqual(self.finish().status, StopStatus.CONFIRMED)

    def test_informational_envelopes_cannot_replace_completion_or_mask_activity(self):
        for model in ("metadata_only_exit", "metadata_with_tool", "metadata_with_permission",
                      "metadata_with_mode_drift", "metadata_invalid_log", "late_log_foreign",
                      "late_servers_nonempty"):
            with self.subTest(model=model):
                self.launch(model)
                self.assertEqual(self.finish().status, StopStatus.UNCONFIRMED)
                self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
                self.assertNotIn("cessation", self.host.observation)

    def test_informational_envelopes_do_not_mask_original_cancelled_completion(self):
        self.launch("cancel_metadata")
        self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
        self.assertEqual(self.finish().status, StopStatus.CONFIRMED)
        self.assertEqual(self.host.observation["cessation"]["native_stop_reason"], "cancelled")

    def test_protocol_metadata_observation_never_attests_cessation_or_copies_native_values(self):
        from probes.devin_cessation import run
        for model in ("metadata_inventory", "metadata_inventory_limit"):
            receipt = run(self.root / "probes", executable=self.executable,
                native_version="devin-cessation-fixture 0", model=self.fixture_model(model),
                credential_files=(self.credential,), human_intent_ref="fixture-intent",
                timeout=2, protocol_metadata_only=True)
            self.assertEqual(receipt["model_turns_submitted"], 1)
            self.assertEqual(receipt["observed_original_prompt_stop_reason"], "end_turn")
            self.assertEqual(receipt["stop_status"], "unconfirmed")
            self.assertFalse(receipt["matched_requested_completion"])
            self.assertFalse(receipt["metadata_capture_includes_validated_eof"])
            self.assertNotIn("cessation", receipt["host_observation"])
            metadata = receipt["protocol_metadata"]
            self.assertLessEqual(len(metadata), 64)
            thinking = next(item for item in metadata if item["method"] == "_cognition.ai/thinking_complete")
            self.assertEqual(thinking["field_types"], {
                "sessionId": "string", "durationMs": "integer", "blockIndex": "integer"})
            self.assertTrue(thinking["session_matches_bound"])
            unknown = next(item for item in metadata if item["method"] == "unclassified")
            self.assertEqual(unknown["unknown_field_count"], 1)
            self.assertEqual(unknown["field_types"], {})
            stopped = next(item for item in metadata if item["method"] == "_cognition.ai/agent_stopped")
            self.assertEqual(stopped["cause_classification"], "completed")
            self.assertEqual(stopped["stats_activity_zero"], {
                "toolCalls": True, "filesChanged": True, "commandsRun": True})
            self.assertEqual(stopped["stats_shape"]["unknown_field_count"], 1)
            self.assertNotIn("PRIVATE_", json.dumps(receipt))
            self.assertNotIn("private-fixture-session", json.dumps(receipt))
            self.assertEqual(receipt["metadata_limit_reached"], model == "metadata_inventory_limit")

    def test_observed_normal_and_cancelled_telemetry_shapes_preserve_primary_proof(self):
        for scenario, reason in (("telemetry_valid", "end_turn"), ("cancel_telemetry", "cancelled")):
            self.launch(scenario)
            if scenario.startswith("cancel"):
                self.assertEqual(self.adapter.stop(self.ref).status, StopStatus.UNCONFIRMED)
            self.assertEqual(self.finish().status, StopStatus.CONFIRMED)
            self.assertEqual(self.host.observation["cessation"]["native_stop_reason"], reason)
            self.assertNotIn("PRIVATE_", json.dumps(self.host.observation))

    def test_telemetry_is_not_primary_completion_and_cannot_hide_contradiction(self):
        for variant in ("no_primary", "activity", "missing_activity", "bad_type", "nonfinite",
                        "unknown_stats", "error", "foreign", "bad_thinking", "bad_turn", "conflict"):
            with self.subTest(variant=variant):
                self.launch("telemetry_" + variant)
                self.assertEqual(self.finish().status, StopStatus.UNCONFIRMED)
                self.assertEqual(self.adapter.status(self.ref).state, State.ERROR)
                self.assertNotIn("cessation", self.host.observation)
                self.assertNotIn("PRIVATE_NATIVE_ERROR", repr(self.adapter.protocol_diagnostic(self.ref)))

    def test_late_stopped_telemetry_cannot_override_primary_completion(self):
        self.launch("late_telemetry_conflict")
        self.assertEqual(self.finish().status, StopStatus.UNCONFIRMED)
        self.assertEqual(self.adapter.protocol_diagnostic(self.ref)["category"],
                         "native_stopped_cause_contradicts_prompt")
