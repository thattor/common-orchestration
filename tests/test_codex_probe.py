"""Offline probe regressions: real pipe framing, no Native/auth invocation."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from probes import codex_native


class CodexProbeTests(unittest.TestCase):
    def test_initialize_is_one_jsonl_frame_on_actual_stdin(self):
        run = codex_native.run
        calls = []

        def fake_cli(argv, timeout=10, payload=None):
            calls.append(argv[1:])
            if argv[1:] == ['--version']:
                return 0, 'fixture-cli', ''
            if argv[1:] == ['login', 'status']:
                return 0, '', 'Logged in using ChatGPT'
            if argv[1:3] == ['app-server', 'generate-json-schema']:
                return 0, '', ''
            self.assertEqual(argv[1:], ['app-server', '--stdio'])
            # Validate actual bytes at EOF; literal backslash-n is not JSONL.
            child = r'''
import json, sys
raw = sys.stdin.buffer.read()
assert raw.endswith(b'\n'), repr(raw)
assert raw.count(b'\n') == 1, repr(raw)
request = json.loads(raw)
assert request == {'id': 1, 'method': 'initialize', 'params': {
    'clientInfo': {'name': 'co03_contract_probe', 'version': '0.3.0-dev'}}}
print(json.dumps({'id': request['id'], 'result': {}}))
'''
            rc, out, err = run([sys.executable, '-c', child], timeout, payload)
            self.assertEqual(rc, 0, err)
            return rc, out, err

        with tempfile.TemporaryDirectory() as root, \
                patch.object(codex_native.shutil, 'which', return_value='fixture-codex'), \
                patch.object(codex_native, 'run', side_effect=fake_cli):
            report = codex_native.probe(root)
        self.assertEqual(len(calls), 4)
        self.assertTrue(report['bootstrap']['initialize_response_seen'])
        self.assertIsNone(report['blocker'])
        self.assertFalse(report['model_turn_submitted'])
        self.assertEqual(set(report['live_features'].values()), {'untested'})

    def test_receipt_is_valid_json_with_final_newline(self):
        with tempfile.TemporaryDirectory() as root:
            checkout = Path(root)
            output = checkout / 'receipt.json'
            script = checkout / 'a' / 'b' / 'c' / 'probe.py'
            with patch.object(codex_native, '__file__', str(script)), \
                    patch.object(codex_native, 'probe', return_value={'blocker': None}), \
                    patch.object(sys, 'argv', ['probe', '--output', str(output)]), \
                    patch('builtins.print'):
                codex_native.main()
            raw = output.read_bytes()
            self.assertTrue(raw.endswith(b'\n'))
            self.assertEqual(json.loads(raw), {'blocker': None})
