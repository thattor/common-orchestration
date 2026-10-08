"""Driver fixtures only; no model/credential access or production claim."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_devin_host
from probes.devin_text_smoke import EXPECTED, run


class SmokeDriverTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_devin_host.DevinHostTests('test_bound_text_execute_through_events_and_result')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def run_smoke(self):
        x = self.fixture
        return run(x.root / 'smoke', executable=x.executable, native_version='fixture-version',
                   model='swe-1-6', credential_files=(x.credential,), human_intent_ref='human:fixture',
                   timeout=1)

    def test_result_and_events_persist_via_public_controller_commands(self):
        x = self.fixture
        original = x.wire.send
        def send(message):
            original(message)
            if message.get('method') == 'session/prompt':
                x.wire.messages.insert(0, {'jsonrpc': '2.0', 'method': 'session/update', 'params': {
                    'sessionId': 'fixture-session', 'update': {'sessionUpdate': 'agent_message_chunk',
                        'content': {'type': 'text', 'text': EXPECTED}}}})
        x.wire.send = send
        receipt = self.run_smoke()
        self.assertEqual(receipt['model_turns_submitted'], 1)
        self.assertEqual(receipt['result'], {'status': 'completed', 'reason': None})
        self.assertTrue(receipt['fixed_response_matched'])
        self.assertTrue(receipt['stored_result_matches'])
        self.assertTrue(receipt['control_state_changed_by_controller'])
        self.assertTrue(receipt['control_state_has_only_observed_controller_mutations'])
        self.assertEqual(receipt['stored_event_count'], 4)
        self.assertEqual(len(receipt['worker_write_checks']['denied']), 4)
        self.assertTrue(receipt['worker_write_checks']['owned_artifact_created'])
        self.assertFalse(receipt['observed_out_of_scope_write'])
        self.assertNotIn(EXPECTED, json.dumps(receipt))
        self.assertEqual(json.loads((Path(receipt['scratch_ref']) / 'evidence.json').read_text()), receipt)
        self.assertTrue(receipt['owned_native_reaped'])

    def test_failed_preflight_preserves_sanitized_terminal_without_turn(self):
        self.fixture.wire.mode = 'accept-edits'
        receipt = self.run_smoke()
        self.assertEqual(receipt['model_turns_submitted'], 0)
        self.assertEqual(receipt['result']['status'], 'error')
        self.assertFalse(receipt['timeout'])
        self.assertFalse(receipt['fixed_response_matched'])
        self.assertTrue(receipt['owned_native_reaped'])

    def test_native_workspace_write_is_detected_without_reading_content(self):
        x = self.fixture
        original = x.wire.send
        def send(message):
            original(message)
            if message.get('method') == 'session/prompt':
                payload = json.loads(message['params']['prompt'][0]['text'])
                Path(payload['delegation']['workspace'], 'unexpected').write_text('do-not-publish')
        x.wire.send = send
        receipt = self.run_smoke()
        self.assertTrue(receipt['observed_out_of_scope_write'])
        self.assertFalse(receipt['native_workspace_unchanged'])
        self.assertNotIn('do-not-publish', json.dumps(receipt))

    def test_native_control_write_is_detected_and_receipt_survives(self):
        x = self.fixture
        original = x.wire.send
        def send(message):
            original(message)
            if message.get('method') == 'session/prompt':
                payload = json.loads(message['params']['prompt'][0]['text'])
                state = Path(payload['delegation']['workspace']).parent / 'control' / 'control.db'
                with state.open('ab') as stream: stream.write(b'fixture-unexpected-write')
        x.wire.send = send
        receipt = self.run_smoke()
        self.assertTrue(receipt['observed_out_of_scope_write'])
        self.assertFalse(receipt['control_state_has_only_observed_controller_mutations'])
        self.assertIn('smoke_failure', receipt)
        self.assertTrue(receipt['owned_native_reaped'])

    def test_early_bootstrap_failure_closes_store_and_preserves_receipt(self):
        from co_v4.state import ControlStore
        closed = []
        original = ControlStore.close
        def close(store):
            closed.append(True)
            original(store)
        with patch("co_v4.state.ControllerState.add_job", side_effect=RuntimeError("unpublished detail")), \
             patch.object(ControlStore, "close", close):
            receipt = self.run_smoke()
        self.assertEqual(receipt["smoke_failure"], "smoke_bootstrap_or_cleanup_failed")
        self.assertEqual(closed, [True])
        self.assertNotIn("unpublished", json.dumps(receipt))
        self.assertTrue((Path(receipt["scratch_ref"]) / "failure-evidence.json").is_file())
        self.assertEqual(self.fixture.wire.sent, [])

    def test_timeout_reports_unconfirmed_stop_and_reaps_owned_native(self):
        original = self.fixture.wire.send
        def send(message):
            if message.get("method") == "session/prompt":
                self.fixture.wire.sent.append(message)
                return
            original(message)
        self.fixture.wire.send = send
        receipt = self.run_smoke()
        self.assertTrue(receipt["timeout"])
        self.assertIsNone(receipt["result"])
        self.assertEqual(receipt["stop_status"], "unconfirmed")
        self.assertTrue(receipt["owned_native_reaped"])
        self.assertEqual(receipt["model_turns_submitted"], 1)
