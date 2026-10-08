"""Synthetic Root capabilities and local stub executables; never invoke Orca."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from co_v4.orca_history import HistoryRefused
from co_v4.orca_history_host import CreationScope, OrcaCliReader, RootTerminalRegistry
from probes.orca_owned_history import _cleanup_verified, creation_arguments, run

MARKER = 'CO_ORCA_HISTORY_' + 'a' * 32


def envelope(value, key='terminal', runtime='runtime'):
    return json.dumps({'id': 'rpc', 'ok': True, '_meta': {'runtimeId': runtime},
                       'result': {key: value}}).encode()


class Reader:
    def __init__(self, scope):
        self.scope, self.calls = scope, []
        self.current = {'handle': 'term_fixture', 'ptyId': 'pty', 'tabId': 'tab',
            'worktreeId': scope.worktree_id, 'incarnationId': 'incarnation',
            'rendererGraphEpoch': 1, 'connected': True, 'writable': True,
            'orphaned': False, 'preview': 'PRIVATE-PREVIEW'}
        self.page = {'handle': 'term_fixture', 'status': 'running', 'tail': [MARKER],
            'oldestCursor': '0', 'nextCursor': '1', 'latestCursor': '1',
            'truncated': False, 'limited': False, 'source': 'stream'}
        self.runtime = 'runtime'
    def admit(self): self.calls.append('admit')
    def bind(self, handle): self.calls.append(('bind', handle))
    def show(self):
        self.calls.append('show')
        return envelope(self.current, runtime=self.runtime)
    def read(self, plan):
        self.calls.append('read')
        return envelope(self.page, runtime=self.runtime)


class HostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.scope = CreationScope('repo::' + self.temp.name, 'fixture-title', 'root-owner', self.temp.name)
        self.reader, self.captures, self.now = Reader(self.scope), [], 0
        self.receipt = {'handle': 'term_fixture', 'ptyId': 'pty', 'tabId': 'tab',
            'worktreeId': self.scope.worktree_id, 'title': self.scope.title, 'surface': 'background'}
        def capture(scope):
            self.captures.append(scope)
            return envelope(self.receipt)
        self.capture = capture
        self.registry = RootTerminalRegistry(self.reader, capture_creation=capture, clock=lambda: self.now)

    def test_capture_and_fresh_show_bind_then_revoke(self):
        history = self.registry.acquire(self.scope)
        page = history.read(history.plan(cursor='0'))
        self.assertEqual(page.tail, (MARKER,))
        self.assertEqual(self.captures, [self.scope])
        self.assertEqual(self.reader.calls.count('show'), 4)
        self.assertNotIn('PRIVATE', repr(history))
        self.registry.revoke()
        with self.assertRaises(HistoryRefused): history.plan(cursor='0')
        self.assertEqual(self.registry.cleanup_target().handle, 'term_fixture')
        with self.assertRaises(HistoryRefused): history.plan(cursor='0')
        with self.assertRaises(HistoryRefused): self.registry.acquire(self.scope)

    def test_default_gate_and_missing_directory_precede_creation(self):
        registry = RootTerminalRegistry(self.reader)
        with self.assertRaises(HistoryRefused): registry.acquire(self.scope)
        self.assertEqual(self.reader.calls, [])
        gone = str(Path(self.temp.name) / 'missing')
        scope = CreationScope('repo::'+gone, 'title', 'owner', gone)
        with self.assertRaises(HistoryRefused): self.registry.acquire(scope)
        self.assertEqual(self.captures, [])

    def test_creation_requires_actual_capability_reply_no_boolean(self):
        for raw in (True, False, {'handle': 'term_fixture'}, b'PRIVATE-ERROR'):
            registry = RootTerminalRegistry(self.reader, capture_creation=lambda _: raw)
            with self.assertRaisesRegex(HistoryRefused, '^creation_or_identity_unverified$'):
                registry.acquire(self.scope)

    def test_known_visible_surface_requires_same_full_owned_receipt(self):
        self.receipt['surface'] = 'visible'
        history = self.registry.acquire(self.scope)
        self.assertEqual(history.read(history.plan(cursor='0')).tail, (MARKER,))
        for mutation in ({'surface': 'renderer'}, {'ptyId': None}):
            receipt = {**self.receipt, **mutation}
            registry = RootTerminalRegistry(Reader(self.scope), capture_creation=lambda _: envelope(receipt))
            with self.assertRaises(HistoryRefused): registry.acquire(self.scope)

    def test_expired_read_does_not_reopen_but_exact_cleanup_may_observe(self):
        history = self.registry.acquire(self.scope); self.now = 121
        with self.assertRaises(HistoryRefused): history.plan(cursor='0')
        self.assertEqual(self.registry.cleanup_target().handle, 'term_fixture')
        self.assertNotIn('read', self.reader.calls)

    def test_identity_drift_matrix_rejects_read_and_cleanup(self):
        for key, value in {'ptyId': 'other', 'tabId': 'other', 'worktreeId': 'other',
            'incarnationId': 'other', 'rendererGraphEpoch': 2, 'connected': False,
            'orphaned': True, 'unknown': 'PRIVATE'}.items():
            with self.subTest(key=key):
                reader = Reader(self.scope)
                registry = RootTerminalRegistry(reader, capture_creation=self.capture)
                history = registry.acquire(self.scope)
                reader.current[key] = value
                with self.assertRaises(HistoryRefused): history.plan(cursor='0')
                with self.assertRaises(HistoryRefused): registry.cleanup_target()
                self.assertNotIn('read', reader.calls)

    def test_creation_identity_and_incarnation_missing_are_refused(self):
        for key, value in {'title': 'other', 'worktreeId': 'other', 'isReattach': True,
                          'warning': 'PRIVATE', 'incarnationId': 'other'}.items():
            with self.subTest(key=key):
                receipt = {**self.receipt, key: value}
                registry = RootTerminalRegistry(Reader(self.scope), capture_creation=lambda _: envelope(receipt))
                with self.assertRaises(HistoryRefused): registry.acquire(self.scope)
        del self.reader.current['incarnationId']
        with self.assertRaises(HistoryRefused): self.registry.acquire(self.scope)
        with self.assertRaises(HistoryRefused): self.registry.cleanup_target()

    def test_runtime_change_and_read_cross_handle_revoke(self):
        history = self.registry.acquire(self.scope)
        self.reader.runtime = 'replacement'
        with self.assertRaises(HistoryRefused): history.plan(cursor='0')
        reader = Reader(self.scope)
        registry = RootTerminalRegistry(reader, capture_creation=self.capture)
        history = registry.acquire(self.scope)
        plan = history.plan(cursor='0'); reader.page['handle'] = 'term_other'
        with self.assertRaises(HistoryRefused): history.read(plan)
        with self.assertRaises(HistoryRefused): history.plan(cursor='0')

    def test_probe_marker_and_real_receipt_shapes_cleanup_finally(self):
        cleanups = []
        def cleanup(binding):
            cleanups.append(binding)
            close = envelope({'handle': binding.handle, 'tabId': 'tab', 'ptyKilled': True}, 'close')
            absent = json.dumps({'id': 'after', 'ok': False, '_meta': {'runtimeId': 'runtime'},
                'error': {'code': 'terminal_handle_stale', 'message': 'PRIVATE'}}).encode()
            return close, absent
        report = run(self.scope, MARKER, reader=self.reader, capture_creation=self.capture, cleanup_owned=cleanup)
        self.assertEqual(report['history_ac'], 'pass')
        self.assertEqual(report['cleanup'], 'confirmed_owned_terminal')
        self.assertEqual(len(cleanups), 1)
        self.assertNotIn('PRIVATE', repr(report))
        self.assertNotIn('term_fixture', repr(report))

    def test_probe_gap_does_not_pass_and_false_cleanup_never_confirms(self):
        self.reader.page.update(truncated=True)
        report = run(self.scope, MARKER, reader=self.reader, capture_creation=self.capture,
                     cleanup_owned=lambda _: True)
        self.assertEqual(report['history_ac'], 'fail')
        self.assertEqual(report['cleanup'], 'unconfirmed')

    def test_source_backed_disconnected_record_cleanup_and_negatives(self):
        self.registry.acquire(self.scope)
        target = self.registry.cleanup_target()
        close = {'handle': target.handle, 'tabId': 'tab', 'ptyKilled': True}
        tombstone = {**self.reader.current, 'connected': False, 'writable': False,
                     'orphaned': True, 'exitCause': {'kind': 'operator_close'}}
        self.assertTrue(_cleanup_verified(target, (envelope(close, 'close'), envelope(tombstone))))
        for key, value in {'ptyId':'other', 'incarnationId':'other', 'worktreeId':'other',
                'tabId':'other', 'connected':True, 'writable':True,
                'exitCause':{'kind':'unknown'}}.items():
            with self.subTest(key=key):
                self.assertFalse(_cleanup_verified(target,
                    (envelope(close, 'close'), envelope({**tombstone, key:value}))))
        self.assertFalse(_cleanup_verified(target,
            (envelope(close, 'close'), envelope(tombstone, runtime='other'))))
        for bad in ({**close,'tabId':'other'}, {**close,'ptyKilled':False}, {**close,'ptyStopVerdict':'future-unknown'},
                    {**close,'ptyStopVerdict':'live'}, {**close,'ptyStopVerdict':'unverifiable'}):
            self.assertFalse(_cleanup_verified(target, (envelope(bad,'close'), envelope(tombstone))))

    def test_failure_phase_diagnostic_never_copies_raw_values(self):
        self.reader.current['incarnationId'] = None
        report = run(self.scope, MARKER, reader=self.reader, capture_creation=self.capture,
                     cleanup_owned=lambda _: self.fail('unbound cleanup'))
        self.assertEqual(report['failure_phase'], 'initial_show')
        self.assertEqual(report['refusal_code'], 'creation_or_identity_unverified')
        self.assertFalse(report['diagnostic']['checks']['incarnation_present'])
        self.assertNotIn('PRIVATE', repr(report))

    def test_probe_observes_startup_without_resubmission(self):
        original = self.reader.read
        reads = []
        def delayed(plan):
            reads.append(plan)
            if len(reads) == 1:
                return envelope({**self.reader.page, 'tail': [], 'nextCursor': '0', 'latestCursor': '0'})
            return original(plan)
        self.reader.read = delayed
        with patch('probes.orca_owned_history.time.sleep'):
            report = run(self.scope, MARKER, reader=self.reader, capture_creation=self.capture,
                         cleanup_owned=lambda _: None)
        self.assertEqual(report['history_ac'], 'pass')
        self.assertEqual(report['read_count'], 2)
        self.assertEqual(len(self.captures), 1)

    def test_creation_plan_is_only_one_explicit_effect_and_no_focus(self):
        args = creation_arguments(self.scope, MARKER)
        self.assertEqual(args[:2], ('terminal', 'create'))
        self.assertIn('id:'+self.scope.worktree_id, args)
        self.assertNotIn('--focus', args)
        self.assertNotIn('--agent', args)
        for marker in (None, {}, 'PRIVATE\ud800'):
            with self.assertRaisesRegex(HistoryRefused, '^probe_scope_invalid$'):
                creation_arguments(self.scope, marker)


class CliReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'stub'

    def stub(self, body, timeout=1):
        self.path.write_text('#!' + sys.executable + '\n' + body)
        self.path.chmod(0o700)
        return OrcaCliReader(str(self.path), hashlib.sha256(self.path.read_bytes()).hexdigest(),
                             cwd=self.temp.name, timeout=timeout)

    def test_real_local_stub_version_and_exact_readonly_argv(self):
        reader = self.stub('import sys,json\nprint("1.4.217" if sys.argv[1:]==["--version"] else json.dumps(sys.argv[1:]))\n')
        reader.admit(); reader.bind('term_fixture')
        self.assertEqual(json.loads(reader.show()), ['terminal', 'show', '--terminal', 'term_fixture', '--json'])
        with self.assertRaises(HistoryRefused): reader.bind('term_other')

    def test_output_timeout_exit_and_launcher_drift_are_bounded_and_sanitized(self):
        cases = [('import sys\nsys.stdout.write("x"*300000)\n', 1),
                 ('import time\ntime.sleep(10)\n', .05),
                 ('import sys\nsys.stderr.write("PRIVATE")\nsys.exit(1)\n', 1)]
        for body, timeout in cases:
            reader = self.stub(body, timeout); reader.bind('term_fixture')
            with self.assertRaisesRegex(HistoryRefused, '^cli_read_unavailable$'): reader.show()
        reader = self.stub('print("1.4.217")\n'); self.path.write_text('PRIVATE')
        with self.assertRaisesRegex(HistoryRefused, '^cli_version_unverified$'): reader.admit()


if __name__ == '__main__':
    unittest.main()
