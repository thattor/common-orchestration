"""Disposable venv activation/deactivation and cross-process state persistence.

This is file-copy installation of the candidate modules, not wheel/release or
service-manager validation. Rollback returns to no active candidate; preserved
payload/DBs are not deleted or downgraded. No installed consumer is inspected.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import venv


class CandidateInstallE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source = Path(__file__).resolve().parents[1]
        self.candidate = self.root / 'candidate'
        self.candidate.mkdir()
        shutil.copytree(self.source / 'co_v4', self.candidate / 'co_v4',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copy2(self.source / 'VERSION', self.candidate / 'VERSION')
        self.assertEqual((self.candidate / 'VERSION').read_bytes(),
                         (self.source / 'VERSION').read_bytes())
        self.manifest = self.hashes(self.candidate)
        self.assertEqual(self.manifest, {k: hashlib.sha256((self.source / k).read_bytes()).hexdigest()
                                         for k in self.manifest})
        (self.root / 'manifest.json').write_text(json.dumps(self.manifest, sort_keys=True))
        self.venv = self.root / 'venv'
        venv.EnvBuilder(with_pip=False, system_site_packages=False, symlinks=True).create(self.venv)
        self.python = self.venv / 'bin/python'
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('PYTHON')}
        self.env['PYTHONDONTWRITEBYTECODE'] = '1'
        self.driver = self.root / 'driver'
        (self.driver / 'fixtures').mkdir(parents=True)
        shutil.copy2(self.source / 'tests/fixture_e2e.py', self.driver / 'fixture_e2e.py')
        shutil.copy2(self.source / 'tests/fixtures/e2e_candidate.py', self.driver / 'fixtures/e2e_candidate.py')
        purelib = Path(self.run_python('-c', 'import sysconfig; print(sysconfig.get_path("purelib"))').stdout.strip())
        self.assertTrue(purelib.is_relative_to(self.venv))
        self.activation = purelib / 'co_candidate_fixture.pth'
        self.assertFalse(self.activation.exists())
        self.assertEqual(self.available(), 'False')
        self.activation.write_text(str(self.candidate) + '\n')
        self.assertEqual(self.available(), 'True')

    def hashes(self, root):
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(root.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}

    def run_python(self, *args):
        return subprocess.run([str(self.python), '-I', '-B', *map(str, args)],
                              cwd=self.root, env=self.env, text=True,
                              capture_output=True, check=True, timeout=30)

    def available(self):
        return self.run_python('-c', 'import importlib.util; print(importlib.util.find_spec("co_v4") is not None)').stdout.strip()

    def driver_run(self, mode):
        result = json.loads(self.run_python(self.driver / 'fixtures/e2e_candidate.py', mode,
                                           self.root / 'state').stdout)
        self.assertTrue(Path(result['module']).is_relative_to(self.candidate))
        self.assertEqual(Path(result['prefix']), self.venv)
        return result

    def rollback(self):
        # Remove only this test's activation file. Keep candidate + DB evidence.
        before = self.hashes(self.root / 'state')
        self.activation.unlink()
        self.assertEqual(self.available(), 'False')
        self.assertEqual(self.hashes(self.root / 'state'), before)
        self.assertEqual(self.hashes(self.candidate), self.manifest)
        # Explicit reactivation restores terminal Controller state without dispatch.
        self.activation.write_text(str(self.candidate) + '\n')
        restarted = self.driver_run('reopen')
        self.assertEqual(restarted['recovery'], restarted['durable_state'])
        self.assertEqual(self.hashes(self.root / 'state'), before)
        self.activation.unlink()
        return restarted

    def test_candidate_copy_execute_restart_and_rollback_preserve_results(self):
        first = self.driver_run('complete')
        self.assertEqual((first['controller_state'], first['durable_state'], first['ac_count']),
                         ('completed', 'completed', 2))
        restarted = self.driver_run('reopen')
        self.assertEqual(restarted['recovery'], restarted['durable_state'])
        self.assertEqual(restarted['ac_count'], 2)
        self.assertEqual(restarted['trace_count'], first['trace_count'])
        self.assertEqual(self.rollback()['ac_count'], 2)

    def test_candidate_new_process_recovers_pending_required_job_and_finishes(self):
        first = self.driver_run('pending')
        self.assertEqual((first['executions'], first['durable_state']), (0, 'pending'))
        continued = self.driver_run('continue')
        self.assertEqual((continued['controller_state'], continued['durable_state'], continued['ac_count']),
                         ('completed', 'completed', 2))
        self.assertEqual(self.rollback()['recovery'], 'completed')

    def test_candidate_synthetic_stop_then_restart_keeps_stop_latch(self):
        stopped = self.driver_run('stop')
        self.assertEqual((stopped['controller_state'], stopped['cessation_confirmed'], stopped['executions']),
                         ('failed', True, 1))
        restarted = self.rollback()
        self.assertTrue(restarted['stop_requested'])
        self.assertEqual(restarted['ac_count'], 0)
        self.assertEqual(restarted['trace_count'], stopped['trace_count'])


if __name__ == '__main__': unittest.main()
