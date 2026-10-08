"""Edge regressions: signal deferral in _spawn cleanup, post-claim
admission release, and call_dir ancestor-alias canonicalization."""
import json
import subprocess
import sys
import os
import signal
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from co_v4.task import admission, infer


@unittest.skipUnless(
    hasattr(signal, 'pthread_sigmask')
    and infer.child_status.supported()
    and hasattr(os, 'killpg'),
    'requires POSIX waitid/killpg/pthread_sigmask')
class SpawnSignalDeferralTests(unittest.TestCase):
    """Real signals arriving during cleanup must stay pending until the
    group stop proof and the once-only on_stopped callback have run."""

    @staticmethod
    def _fake_proc():
        out_r, out_w = os.pipe()
        err_r, err_w = os.pipe()
        os.close(out_w)
        os.close(err_w)
        proc = mock.Mock()
        proc.pid = 1 << 22
        proc.stdout = os.fdopen(out_r, 'rb')
        proc.stderr = os.fdopen(err_r, 'rb')
        proc.stdin = mock.Mock()
        proc.stdin.closed = False
        proc.wait.return_value = 0
        proc.returncode = 0
        return proc

    def _run(self, sigs):
        child = subprocess.run(
            [sys.executable, '-I', '-S', '-B', __file__, '--signal-case',
             *map(str, sigs)], capture_output=True, text=True, timeout=15)
        self.assertEqual(child.returncode, 0, child.stderr)
        return [tuple(e) if isinstance(e, list) else e
                for e in json.loads(child.stdout)]

    def _run_in_child(self, sigs):
        events = []
        fired = []
        proc = self._fake_proc()

        def stop(_proc):
            for s in sigs:
                os.kill(os.getpid(), s)
            if hasattr(signal, 'sigpending'):
                for s in sigs:
                    events.append(
                        ('pending', s, s in signal.sigpending()))
            events.append('stop')
            return True

        def on_stopped(ok):
            events.append(('stopped', ok))

        def handler(signum, _frame):
            events.append(('signal', signum))
            if not fired:
                fired.append(signum)
                raise KeyboardInterrupt

        old = {s: signal.getsignal(s) for s in sigs}
        try:
            for s in sigs:
                signal.signal(s, handler)
            with mock.patch.object(infer.subprocess, 'Popen',
                                   return_value=proc), \
                    mock.patch.object(infer, '_stop_group',
                                      side_effect=stop):
                with self.assertRaises(KeyboardInterrupt):
                    infer._spawn(['x'], {}, None, 5,
                                 on_stopped=on_stopped)
        finally:
            for s, h in old.items():
                signal.signal(s, h)
        return events

    def _assert_deferred(self, events, sigs):
        sig_events = [e for e in events
                      if isinstance(e, tuple) and e[0] == 'signal']
        rest = [e for e in events
                if not (isinstance(e, tuple) and e[0] == 'signal')]
        self.assertEqual(rest[-2:], ['stop', ('stopped', True)])
        for e in rest[:-2]:
            self.assertEqual(e[0], 'pending')
            self.assertTrue(e[2])
        self.assertEqual({e[1] for e in sig_events}, set(sigs))

    def test_sigint_deferred(self):
        self._assert_deferred(self._run([signal.SIGINT]),
                              [signal.SIGINT])

    def test_sigterm_deferred(self):
        self._assert_deferred(self._run([signal.SIGTERM]),
                              [signal.SIGTERM])

    def test_sighup_deferred(self):
        self._assert_deferred(self._run([signal.SIGHUP]),
                              [signal.SIGHUP])

    def test_paired_signals_deferred(self):
        sigs = [signal.SIGINT, signal.SIGTERM]
        self._assert_deferred(self._run(sigs), sigs)


class AdmissionPostClaimReleaseTests(unittest.TestCase):
    """A failed claimed-evidence write happens after claim() but before
    any child exists; the lease must release via the no-child evidence
    and the identical exception must propagate."""

    def test_emit_failure_after_claim_releases_lease(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            root = base / 'host-root'
            cwd = base / 'work'
            cwd.mkdir()
            call_dir = base / 'call'
            call_dir.mkdir()
            os.chmod(call_dir, 0o700)
            marker = base / 'would-send'
            boom = RuntimeError('claimed evidence write failed')
            real_emit = admission._emit

            def fake_emit(path, payload, *, create=False):
                if payload.get('claimed_at') is not None:
                    raise boom
                return real_emit(path, payload, create=create)

            def invoke(before_launch=None, on_stopped=None):
                before_launch()
                marker.write_text('sent')
                return 'ok'

            with mock.patch.object(admission, '_host_root',
                                   return_value=root):
                with admission.gate(cwd):
                    with mock.patch.object(admission, '_emit',
                                           fake_emit):
                        with self.assertRaises(RuntimeError) as cm:
                            admission.model_call(
                                'claude', 'm', 'prompt', call_dir,
                                invoke)
                self.assertIs(cm.exception, boom)
                self.assertFalse(marker.exists())
                status = admission.capacity_status()
                for counts in status['routes'].values():
                    self.assertEqual(counts['reserved'], 0)
                    self.assertEqual(counts['executing'], 0)


class CallDirCanonicalTests(unittest.TestCase):
    """Ancestor aliases in call_dir must canonicalize after private_dir
    while the final component stays a real private directory."""

    def _fixture(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        base = Path(td.name).resolve()
        callroot = base / 'calls'
        callroot.mkdir()
        os.chmod(callroot, 0o700)
        nested = callroot / 'nested'
        nested.mkdir()
        os.chmod(nested, 0o700)
        alias = base / 'alias'
        alias.symlink_to(callroot)
        return base, callroot, nested, alias

    def _infer(self, base, call_dir, native_call):
        state, cwd = base / 'state', base / 'native'
        state.mkdir(mode=0o700)
        cwd.mkdir(mode=0o700)
        selection = {'route': 'claude', 'model': 'm',
                     'measurement_digest': 'fixed-fixture'}
        entry = dict(selection, native_cwd=str(cwd), binary='/bin/true')
        with mock.patch.object(admission, '_host_root', return_value=base / 'host'), \
                mock.patch.object(infer, '_check_launch'), \
                mock.patch.object(infer, '_known_context', return_value=[]), \
                mock.patch.object(infer, '_call_claude', native_call):
            return infer._infer_pinned(
                state, selection, 'planner', 'p', call_dir, 30,
                lambda route, model: entry)

    def test_ancestor_alias_reaches_inference_as_canonical_path(self):
        base, _, nested, alias = self._fixture()
        call = nested / 'call'
        spelled = alias / 'nested' / 'call'
        native = mock.Mock(return_value={'text': 'ok', 'api_key_source': None})
        self._infer(base, spelled, native)
        native.assert_called_once()
        self.assertEqual(native.call_args.args[6], call)
        self.assertNotEqual(spelled, call)
        self.assertTrue((call / 'meta.json').exists())

    def test_symlink_final_component_refused_before_inference(self):
        base, _, nested, _ = self._fixture()
        link = base / 'call-link'
        link.symlink_to(nested)
        native = mock.Mock()
        with self.assertRaises(infer.TaskError):
            self._infer(base, link, native)
        native.assert_not_called()
        self.assertFalse((nested / 'meta.json').exists())


if __name__ == '__main__':
    if sys.argv[1:2] == ['--signal-case']:
        probe = SpawnSignalDeferralTests()
        print(json.dumps(probe._run_in_child(list(map(int, sys.argv[2:])))))
    else:
        unittest.main()
