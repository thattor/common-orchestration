"""Regressions for _spawn's cleanup-entry signal window.

An interrupt delivered while the cleanup mask is being installed - or a
second signal still pending when the drain loop's first raising handler
unwinds - must not skip the group stop, the once-only on_stopped
callback, or restoration of the original signal mask.  Real signals are
exercised only inside an owned child process so the test runner's own
mask and handlers are never touched.
"""
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from co_v4.task import admission, infer

_SIGS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def _fake_proc(keep_write_ends=False):
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    proc = mock.Mock()
    proc.pid = 1 << 22
    proc.stdout = os.fdopen(out_r, 'rb')
    proc.stderr = os.fdopen(err_r, 'rb')
    proc.stdin = mock.Mock()
    proc.stdin.closed = False
    proc.wait.return_value = 0
    proc.returncode = 0
    if keep_write_ends:
        return proc, (out_w, err_w)
    os.close(out_w)
    os.close(err_w)
    return proc, ()


@unittest.skipUnless(
    hasattr(signal, 'pthread_sigmask')
    and infer.child_status.supported()
    and hasattr(os, 'killpg'),
    'requires POSIX waitid/killpg/pthread_sigmask')
class SpawnCleanupEntryTests(unittest.TestCase):
    """Interrupts landing at cleanup entry must still leave the child
    group stopped, on_stopped invoked exactly once, and the caller's
    signal mask restored - the interrupt itself is re-raised last."""

    def _child(self, case, *args):
        child = subprocess.run(
            [sys.executable, '-I', '-S', '-B', __file__, case,
             *map(str, args)], capture_output=True, text=True, timeout=20)
        self.assertEqual(child.returncode, 0, child.stderr)
        return [tuple(e) if isinstance(e, list) else e
                for e in json.loads(child.stdout)]

    def _run_interrupt_during_drain(self, sigs):
        """Runs only in the child.  Both handlers raise; the write ends
        stay open and _leader_running is pinned True so the drain loop
        is alive when the signals land."""
        events = []
        proc, write_ends = _fake_proc(keep_write_ends=True)
        orig = signal.pthread_sigmask(signal.SIG_BLOCK, ())

        def handler(signum, _frame):
            events.append(('signal', int(signum)))
            raise KeyboardInterrupt

        def send_all(*_args):
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, sigs)
            try:
                for s in sigs:
                    os.kill(os.getpid(), s)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)

        def stop(_proc):
            events.append('stop')
            return True

        old = {s: signal.getsignal(s) for s in sigs}
        try:
            for s in sigs:
                signal.signal(s, handler)
            with mock.patch.object(infer.subprocess, 'Popen',
                                   return_value=proc), \
                    mock.patch.object(infer, '_leader_running',
                                      return_value=True), \
                    mock.patch.object(infer.selectors.DefaultSelector,
                                      'select', side_effect=send_all), \
                    mock.patch.object(infer, '_stop_group',
                                      side_effect=stop):
                with self.assertRaises(KeyboardInterrupt):
                    infer._spawn(['x'], {}, None, 10,
                                 on_stopped=lambda ok: events.append(
                                     ('stopped', ok)))
        finally:
            for s, h in old.items():
                signal.signal(s, h)
            for fd in write_ends:
                os.close(fd)
        events.append(
            ('mask', signal.pthread_sigmask(signal.SIG_BLOCK, ()) == orig))
        return events

    def _run_mask_raise_during_block(self):
        """Runs only in the child.  Simulates the documented
        pthread_sigmask behaviour of changing the mask and then raising
        from PyErr_CheckSignals, before the old code could bind `prev`
        or enter the contextmanager's try/finally."""
        events = []
        proc, _ = _fake_proc()
        real = signal.pthread_sigmask
        orig = real(signal.SIG_BLOCK, ())
        state = {'tripped': False}

        def flaky(how, mask):
            prev = real(how, mask)
            if (how == signal.SIG_BLOCK and set(mask) & set(_SIGS)
                    and not state['tripped']):
                state['tripped'] = True
                raise KeyboardInterrupt
            return prev

        def stop(_proc):
            events.append('stop')
            return True

        with mock.patch.object(infer.signal, 'pthread_sigmask', flaky), \
                mock.patch.object(infer.subprocess, 'Popen',
                                  return_value=proc), \
                mock.patch.object(infer, '_leader_running',
                                  return_value=False), \
                mock.patch.object(infer, '_stop_group',
                                  side_effect=stop):
            try:
                infer._spawn(['x'], {}, None, 5,
                             on_stopped=lambda ok: events.append(
                                 ('stopped', ok)))
            except KeyboardInterrupt:
                events.append('raised')
        events.append(('mask', real(signal.SIG_BLOCK, ()) == orig))
        return events

    def _assert_interrupted_cleanly(self, events, sigs):
        self.assertEqual(events[-1], ('mask', True))
        body = events[:-1]
        self.assertEqual(body.count('stop'), 1)
        self.assertEqual(body.count(('stopped', True)), 1)
        self.assertLess(body.index('stop'), body.index(('stopped', True)))
        sig_events = [e for e in body
                      if isinstance(e, tuple) and e[0] == 'signal']
        self.assertEqual({e[1] for e in sig_events}, set(sigs))
        self.assertEqual(len(sig_events), len(sigs))
        self.assertLess(body.index(sig_events[0]), body.index('stop'))

    def test_sigint_sigterm_during_drain(self):
        sigs = [int(signal.SIGINT), int(signal.SIGTERM)]
        self._assert_interrupted_cleanly(
            self._child('--drain-case', *sigs), sigs)

    def test_sigint_sighup_during_drain(self):
        sigs = [int(signal.SIGINT), int(signal.SIGHUP)]
        self._assert_interrupted_cleanly(
            self._child('--drain-case', *sigs), sigs)

    def test_mask_change_then_raise_still_cleans_up(self):
        self.assertEqual(
            self._child('--mask-case'),
            ['stop', ('stopped', True), 'raised', ('mask', True)])


class AdmissionLeaseReleaseTests(unittest.TestCase):
    """An interrupt captured at cleanup entry must still fire the
    once-only on_stopped callback so a committed claim is released
    before the interrupt propagates."""

    def test_interrupt_after_claim_releases_lease(self):
        real = signal.pthread_sigmask
        orig = real(signal.SIG_BLOCK, ())
        self.addCleanup(real, signal.SIG_SETMASK, orig)
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            root = base / 'host-root'
            cwd = base / 'work'
            cwd.mkdir()
            call_dir = base / 'call'
            call_dir.mkdir()
            os.chmod(call_dir, 0o700)
            proc, _ = _fake_proc()
            state = {'tripped': False}

            def flaky(how, mask):
                prev = real(how, mask)
                if (how == signal.SIG_BLOCK and set(mask) & set(_SIGS)
                        and not state['tripped']):
                    state['tripped'] = True
                    raise KeyboardInterrupt
                return prev

            def invoke(before_launch=None, on_stopped=None):
                before_launch()
                with mock.patch.object(infer.signal, 'pthread_sigmask',
                                       flaky), \
                        mock.patch.object(infer.subprocess, 'Popen',
                                          return_value=proc), \
                        mock.patch.object(infer, '_leader_running',
                                          return_value=False), \
                        mock.patch.object(infer, '_stop_group',
                                          return_value=True):
                    return infer._spawn(['x'], {}, None, 5,
                                        on_stopped=on_stopped)

            with mock.patch.object(admission, '_host_root',
                                   return_value=root):
                with admission.gate(cwd):
                    with self.assertRaises(KeyboardInterrupt):
                        admission.model_call('claude', 'm', 'prompt',
                                             call_dir, invoke)
                status = admission.capacity_status()
                for counts in status['routes'].values():
                    self.assertEqual(counts['reserved'], 0)
                    self.assertEqual(counts['executing'], 0)
        self.assertEqual(real(signal.SIG_BLOCK, ()), orig)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--drain-case']:
        probe = SpawnCleanupEntryTests()
        print(json.dumps(probe._run_interrupt_during_drain(
            [int(s) for s in sys.argv[2:]])))
    elif sys.argv[1:2] == ['--mask-case']:
        probe = SpawnCleanupEntryTests()
        print(json.dumps(probe._run_mask_raise_during_block()))
    else:
        unittest.main()
