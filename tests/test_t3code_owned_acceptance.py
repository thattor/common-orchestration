"""Probe prerequisites must refuse before any Native launch; no live calls."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'probes/t3code_owned_acceptance.py'
SPEC = importlib.util.spec_from_file_location('t3_owned_probe', PATH)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class ProbePrerequisiteTests(unittest.TestCase):
    def args(self, root):
        return SimpleNamespace(source=root, task_root=root / 'new', native=Path(sys.executable),
            node=Path(sys.executable), codex_home=root, model='model', effort='low')

    def test_existing_task_root_is_preserved_before_native(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            args = self.args(root)
            args.task_root.mkdir()
            marker = args.task_root / 'keep'
            marker.write_text('original')
            with patch.object(probe.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(ValueError, 'new short task root'):
                    probe.run(args)
                launch.assert_not_called()
            self.assertEqual(marker.read_text(), 'original')

    def test_unverified_source_and_missing_dependencies_never_start_native(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(Path(directory).resolve())
            for source_ok in (False, True):
                with patch.object(probe, 'source_verified', return_value=source_ok), patch.object(probe.subprocess, 'Popen') as launch:
                    with self.assertRaisesRegex(ValueError, 'pinned source and prepared dependencies'):
                        probe.run(args)
                    launch.assert_not_called()
                self.assertFalse(args.task_root.exists())

    def test_unsupported_node_refused_before_auth_or_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'node_modules').mkdir()
            args = self.args(root)
            with patch.object(probe, 'source_verified', return_value=True), patch.object(probe.subprocess, 'check_output', return_value='v22.23.1'), patch.object(probe.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(ValueError, 'Node24'):
                    probe.run(args)
                launch.assert_not_called()
            self.assertFalse(args.task_root.exists())

    def test_environment_projection_keeps_only_validated_names(self):
        value = {'shell_environment_policy': {'set': {'SAFE_KEY': 'SENSITIVE VALUE'}}}
        self.assertEqual(probe.cleared_environment_keys(value), ('SAFE_KEY',))
        self.assertNotIn('SENSITIVE', repr(probe.cleared_environment_keys(value)))
        for values in ([], '', False, {'invalid.name': 'x'}, {'bad-key': ''}, {str(i): '' for i in range(65)}):
            with self.assertRaises(ValueError):
                probe.cleared_environment_keys({'shell_environment_policy': {'set': values}})

    def test_projection_diagnostics_omit_text_and_untrusted_labels(self):
        value = {'messages': [{'role': 'assistant', 'text': 'PRIVATE SENTINEL', 'streaming': False}],
            'nodes': [{'kind': 'PRIVATE SENTINEL', 'status': 'completed'}], 'settings': {'secret': 'PRIVATE SENTINEL'}}
        facts = probe.projection_facts(value)
        self.assertNotIn('PRIVATE', repr(facts))
        self.assertEqual(facts['nodes'][0]['kind'], 'other:str')
        self.assertEqual(facts['messages'][0]['text_bytes'], 16)


    def test_metadata_status_requires_cleanup_and_zero_turns(self):
        from copy import deepcopy
        report = {'metadata_only': True, 'server_reaped': True,
            'local_service_auth_state_deleted': True, 'owner': {'closed': True, 'failed': False,
            'children': [{'native_turn_id': None, 'exit_code': 0, 'forced': False,
                'failed': False, 'escaped_group': False, 'stdout_eof': True,
                'stderr_eof': True, 'reaped': True, 'done': True}]}}
        self.assertTrue(probe.metadata_complete(report))
        for key in ('server_reaped', 'local_service_auth_state_deleted'):
            value=deepcopy(report);value[key]=False
            self.assertFalse(probe.metadata_complete(value))
        for key,new in [('native_turn_id','turn'),('stdout_eof',False),('stderr_eof',False),
                        ('reaped',False),('forced',True),('exit_code',1),('escaped_group',True)]:
            value=deepcopy(report);value['owner']['children'][0][key]=new
            self.assertFalse(probe.metadata_complete(value))
        value=deepcopy(report);value['error_type']='ValueError'
        self.assertFalse(probe.metadata_complete(value))
        value=deepcopy(report);value['owner']['children']=[]
        self.assertFalse(probe.metadata_complete(value))
