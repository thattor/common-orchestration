"""Offline Devin probe regressions: fake docs/home, no CLI or auth invoked."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from probes import devin_native


def write_fake_docs(version_dir):
    docs = version_dir / 'share' / 'devin' / 'docs'
    markers_by_file = {}
    for spec in devin_native.DOCS_SURFACE.values():
        markers_by_file.setdefault(spec['file'], []).extend(spec['markers'])
    for rel, markers in markers_by_file.items():
        path = docs / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('fixture doc ' + ' '.join(markers))
    return docs


class DevinProbeTests(unittest.TestCase):
    def test_report_shape_declared_docs_and_no_nested_cli(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / 'home'
            state = home / '.local' / 'share' / 'devin'
            versions = state / 'cli' / '_versions'
            (versions / '3000.10.31').mkdir(parents=True)
            (versions / '3000.11.3').mkdir(parents=True)
            (versions / 'current').symlink_to('3000.11.3')
            write_fake_docs(versions / '3000.11.3')
            (state / 'credentials.toml').write_text('fixture')
            (state / 'summaries').mkdir(parents=True)
            calls = []
            with patch.object(devin_native.shutil, 'which',
                              return_value=str(home / 'bin' / 'devin')), \
                    patch.object(devin_native.Path, 'home', return_value=home), \
                    patch.object(devin_native, 'fs_write_probe',
                                 return_value='denied'), \
                    patch.object(devin_native, 'network_probe',
                                 return_value='denied'), \
                    patch.object(devin_native.subprocess, 'run',
                                 side_effect=lambda *a, **k: calls.append(a)):
                report = devin_native.probe(Path(root) / 'work',
                                            state_dir=state)
        self.assertEqual(calls, [])
        self.assertFalse(report['nested_cli']['invoked'])
        self.assertEqual(report['cli_version'], '3000.11.3')
        self.assertEqual(report['cli_versions']['installed'],
                         ['3000.10.31', '3000.11.3'])
        self.assertEqual(report['cli_path'], '~/bin/devin')
        self.assertTrue(report['bundled_docs_root'].startswith('~/'))
        self.assertTrue(all(e['declared'] is True
                            for e in report['declared_surface'].values()))
        reach = report['reachability']
        self.assertEqual(reach['fs_workspace_write'], 'denied')
        self.assertEqual(reach['credentials_file'], 'present')
        self.assertEqual(reach['session_state_dir'], 'present')
        self.assertIsNone(report['usage'])
        self.assertIn('untested', report['live_features']['confirmation_relay'])
        self.assertEqual(len(report['historical_denials']), 3)
        self.assertIsNotNone(report['blocker'])
        # This run must not re-stamp prior-session claims as fresh evidence.
        self.assertEqual(report['schema_version'], 2)
        observer = report['observer']
        self.assertIsNone(observer['effective_model'])
        self.assertIsNone(observer['requested_model'])
        self.assertIsNone(observer['model_turn_submitted'])
        self.assertIn('historical',
                      report['live_features']['stop_request'])
        history = report['historical_observations']
        self.assertEqual(history['recorded_at'], '2026-09-28')
        self.assertEqual(history['session']['effective_model'], 'swe-2-high')
        self.assertTrue(history['session']['model_turn_submitted'])
        self.assertNotIn('session_observations', report)

    def test_absent_cli_docs_and_state_never_claim_support(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / 'home'
            home.mkdir()
            with patch.object(devin_native.shutil, 'which', return_value=None), \
                    patch.object(devin_native.Path, 'home', return_value=home), \
                    patch.object(devin_native, 'fs_write_probe',
                                 return_value='unreachable'), \
                    patch.object(devin_native, 'network_probe',
                                 return_value='error:gaierror'):
                report = devin_native.probe(Path(root) / 'work')
        self.assertIsNone(report['cli_path'])
        self.assertIsNone(report['cli_version'])
        self.assertIsNone(report['bundled_docs_root'])
        self.assertEqual(report['cli_versions']['state'], 'absent')
        self.assertTrue(all(e['declared'] == 'unknown'
                            for e in report['declared_surface'].values()))
        self.assertEqual(report['reachability']['credentials_file'], 'absent')

    def test_historical_observations_are_immutable_across_runs(self):
        before = json.loads(json.dumps(devin_native.HISTORICAL_OBSERVATIONS))
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / 'home'
            home.mkdir()
            with patch.object(devin_native.shutil, 'which',
                              return_value=None), \
                    patch.object(devin_native.Path, 'home', return_value=home), \
                    patch.object(devin_native, 'fs_write_probe',
                                 return_value='denied'), \
                    patch.object(devin_native, 'network_probe',
                                 return_value='denied'):
                first = devin_native.probe(Path(root) / 'work')
                second = devin_native.probe(Path(root) / 'work')
        self.assertEqual(devin_native.HISTORICAL_OBSERVATIONS, before)
        self.assertEqual(first['historical_observations'], before)
        self.assertEqual(second['historical_observations'], before)
        # Fixed historical content keeps its own date, not this run's stamp.
        self.assertNotEqual(first['historical_observations']['recorded_at'],
                            first['observed_at'])
        self.assertEqual(first['historical_denials'],
                         second['historical_denials'])

    def test_declared_session_model_marks_only_that_runs_observer(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / 'home'
            home.mkdir()
            with patch.object(devin_native.shutil, 'which',
                              return_value=None), \
                    patch.object(devin_native.Path, 'home', return_value=home), \
                    patch.object(devin_native, 'fs_write_probe',
                                 return_value='denied'), \
                    patch.object(devin_native, 'network_probe',
                                 return_value='denied'):
                declared = devin_native.probe(Path(root) / 'work',
                                              session_model='swe-2-high')
        observer = declared['observer']
        self.assertEqual(observer['effective_model'], 'swe-2-high')
        self.assertTrue(observer['model_turn_submitted'])
        self.assertIn('operator-declared',
                      observer['effective_model_evidence'])
        # The declared this-run claim does not rewrite the historical record.
        self.assertEqual(declared['historical_observations']['session']
                         ['effective_model_evidence'],
                         devin_native.HISTORICAL_OBSERVATIONS['session']
                         ['effective_model_evidence'])

    def test_sanitize_collapses_home_only(self):
        home = Path('/fixture-home')
        with patch.object(devin_native.Path, 'home', return_value=home):
            self.assertEqual(devin_native.sanitize('/fixture-home/x/y'), '~/x/y')
            self.assertEqual(devin_native.sanitize('/fixture-home'), '~')
            self.assertEqual(devin_native.sanitize('/other'), '/other')
            self.assertIsNone(devin_native.sanitize(None))

    def test_fs_write_probe_classifies_outcomes(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'probe'
            self.assertEqual(devin_native.fs_write_probe(target),
                             'allowed_and_removed')
            self.assertFalse(target.exists())
        with patch('builtins.open', side_effect=PermissionError('denied')):
            self.assertEqual(devin_native.fs_write_probe(Path('/x')), 'denied')
        missing = Path(tempfile.gettempdir()) / 'no-such-dir' / 'probe'
        self.assertEqual(devin_native.fs_write_probe(missing), 'unreachable')

    def test_network_probe_classifies_outcomes(self):
        class Conn:
            def close(self):
                pass
        for side, expected in ((PermissionError(), 'denied'),
                               (TimeoutError(), 'timeout'),
                               (ConnectionRefusedError(), 'refused'),
                               (OSError('x'), 'error:OSError')):
            with self.subTest(expected=expected), \
                    patch.object(devin_native.socket, 'create_connection',
                                 side_effect=side):
                self.assertEqual(devin_native.network_probe(), expected)
        with patch.object(devin_native.socket, 'create_connection',
                          return_value=Conn()):
            self.assertEqual(devin_native.network_probe(), 'connected')

    def test_receipt_is_valid_json_with_final_newline(self):
        with tempfile.TemporaryDirectory() as root:
            checkout = Path(root)
            output = checkout / 'receipt.json'
            script = checkout / 'a' / 'b' / 'c' / 'probe.py'
            with patch.object(devin_native, '__file__', str(script)), \
                    patch.object(devin_native, 'probe',
                                 return_value={'nested_cli': {'invoked': False}}), \
                    patch.object(sys, 'argv',
                                 ['probe', '--output', str(output)]), \
                    patch('builtins.print'):
                devin_native.main()
            raw = output.read_bytes()
            self.assertTrue(raw.endswith(b'\n'))
            self.assertEqual(json.loads(raw),
                             {'nested_cli': {'invoked': False}})


if __name__ == '__main__':
    unittest.main()
