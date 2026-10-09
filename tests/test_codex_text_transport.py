import contextlib
import os
import signal
import subprocess
import threading
import unittest
from unittest import mock

from co_v4.adapters.codex import NativeError, StdioTransport
from co_v4.codex_text_transport import (
    NoChild,
    OwnedTransport,
    SUPPORTED_TEXT_CLI,
)

VERSION_OUT = SUPPORTED_TEXT_CLI.encode() + b"\n"
CLEANUP_SIGS = frozenset((signal.SIGINT, signal.SIGTERM, signal.SIGHUP))


class FakeStream:
    def __init__(self, fd):
        self._fd = fd
        self.closed = False

    def fileno(self):
        return self._fd

    def close(self):
        if not self.closed:
            self.closed = True
            os.close(self._fd)


class FakeProc:
    """Popen stand-in backed by real pipes; poll/wait are instrumented."""

    def __init__(self):
        self.pid = 4242
        self.child_in, stdin_w = os.pipe()
        stdout_r, self.child_out = os.pipe()
        self.stdin = FakeStream(stdin_w)
        self.stdout = FakeStream(stdout_r)
        self.poll_calls = 0
        self.wait_calls = 0

    def poll(self):
        self.poll_calls += 1
        return None

    def wait(self, timeout=None):
        self.wait_calls += 1
        return 0

    def emit(self, data):
        os.write(self.child_out, data)

    def eof(self):
        if self.child_out >= 0:
            os.close(self.child_out)
            self.child_out = -1

    def cleanup(self):
        self.stdin.close()
        self.stdout.close()
        for fd in (self.child_in, self.child_out):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


class Spawn:
    """Patched run/Popen, helper fakes, and a fake pthread signal mask."""

    def __init__(self):
        self.proc = FakeProc()
        self.events = []
        self.timeline = []
        self.running = True
        self.exited = False
        self.exit_status = 0
        self.exit_code = os.CLD_EXITED
        self.stop_result = True
        self.stop_error = None
        self.popen_error = None
        self.popen_kw = {}
        self.mask_current = set()
        self.mask_calls = []
        self.mask_failures = {}
        self.mask_call_count = 0
        self.callback_masks = []
        self.stack = contextlib.ExitStack()
        enter = self.stack.enter_context
        self.run = enter(mock.patch.object(subprocess, "run",
                                           side_effect=self._run))
        self.popen = enter(mock.patch.object(subprocess, "Popen",
                                             side_effect=self._popen))
        self.sigmask = enter(mock.patch.object(
            signal, "pthread_sigmask", side_effect=self._sigmask))
        enter(mock.patch("co_v4.task.child_status.supported",
                         return_value=True))
        enter(mock.patch("co_v4.task.child_status.waitid",
                         side_effect=self._waitid))
        enter(mock.patch("co_v4.task.infer._leader_running",
                         side_effect=lambda proc: self.running))
        enter(mock.patch("co_v4.task.infer._stop_group",
                         side_effect=self._stop))

    def _event(self, value):
        self.events.append(value)
        self.timeline.append(value)

    def _sigmask(self, how, mask):
        self.mask_call_count += 1
        self.mask_calls.append((how, set(mask)))
        self.timeline.append(("mask", how, frozenset(mask)))
        error = self.mask_failures.get(self.mask_call_count)
        if error is not None:
            raise error
        old = set(self.mask_current)
        if how == signal.SIG_BLOCK:
            self.mask_current.update(mask)
        elif how == signal.SIG_SETMASK:
            self.mask_current = set(mask)
        else:
            raise ValueError("unsupported mask operation")
        return old

    def _run(self, argv, **kw):
        return mock.Mock(returncode=0, stdout=VERSION_OUT)

    def _popen(self, argv, **kw):
        self._event("popen")
        self.popen_kw = kw
        if self.popen_error is not None:
            raise self.popen_error
        return self.proc

    def _waitid(self, *args):
        if self.exited:
            return mock.Mock(si_code=self.exit_code,
                             si_status=self.exit_status)
        return None

    def _stop(self, proc):
        self._event("stop")
        if self.stop_error is not None:
            raise self.stop_error
        if self.stop_result:
            self.running = False
        return self.stop_result

    def natural_exit(self):
        self.exited = True
        self.running = False

    def transport(self, **kw):
        kw.setdefault("before_launch", lambda: self._event("before"))

        def stopped(flag):
            self.callback_masks.append(frozenset(self.mask_current))
            self._event(("stopped", flag))

        kw.setdefault("on_stopped", stopped)
        return OwnedTransport("/bin/codex", "/tmp", **kw)

    def close(self):
        self.stack.close()
        self.proc.cleanup()


class OwnedTransportTests(unittest.TestCase):
    def spawn(self):
        s = Spawn()
        self.addCleanup(s.close)
        return s

    def test_base_class_untouched(self):
        self.assertTrue(issubclass(OwnedTransport, StdioTransport))
        self.assertIsNot(OwnedTransport.alive, StdioTransport.alive)
        self.assertIsNot(OwnedTransport.close, StdioTransport.close)

    def test_unknown_version_refused_before_hooks(self):
        s = self.spawn()
        s.run.side_effect = lambda *a, **k: mock.Mock(
            returncode=0, stdout=b"codex-cli 0.0.0\n")
        with self.assertRaises(NativeError):
            s.transport()
        self.assertEqual(s.events, [])

    def test_required_version_must_match(self):
        s = self.spawn()
        with self.assertRaises(NativeError):
            s.transport(required_version="codex-cli 9.9.9")
        self.assertEqual(s.run.call_count, 0)
        self.assertEqual(s.events, [])

    def test_hooks_must_be_callable(self):
        s = self.spawn()
        with self.assertRaises(NativeError):
            s.transport(before_launch=None)
        with self.assertRaises(NativeError):
            s.transport(on_stopped=None)
        self.assertEqual(s.run.call_count, 0)
        self.assertEqual(s.events, [])

    def test_drain_budget_validation(self):
        s = self.spawn()
        for bad in (True, 0, 6, "5"):
            with self.assertRaises(NativeError):
                s.transport(max_drain_s=bad)
        self.assertEqual(s.run.call_count, 0)
        self.assertNotIn("popen", s.events)

    def test_missing_owned_helper_no_launch_no_callback(self):
        s = self.spawn()
        s.stack.enter_context(mock.patch(
            "co_v4.task.child_status.supported", return_value=False))
        with self.assertRaises(NoChild):
            s.transport()
        self.assertEqual(s.run.call_count, 1)
        self.assertEqual(s.popen.call_count, 0)
        self.assertEqual(s.events, [])

    def test_missing_pthread_surface_no_launch_no_callback(self):
        s = self.spawn()
        s.stack.enter_context(mock.patch.object(
            signal, "pthread_sigmask", None))
        with self.assertRaises(NoChild):
            s.transport()
        self.assertEqual(s.run.call_count, 1)
        self.assertEqual(s.popen.call_count, 0)
        self.assertEqual(s.events, [])

    def test_hooks_once_order_and_clean_close(self):
        s = self.spawn()
        t = s.transport()
        self.assertEqual(s.events, ["before", "popen"])
        self.assertTrue(s.popen_kw["start_new_session"])
        s.proc.eof()
        s.natural_exit()
        t.close()
        self.assertEqual(s.events,
                         ["before", "popen", "stop", ("stopped", True)])
        self.assertEqual(t.natural_exit, 0)
        self.assertTrue(t.validated_eof)
        self.assertTrue(t.drain_clean)
        self.assertFalse(t.cleanup_terminated)
        self.assertTrue(t.stopped)

    def test_close_idempotent(self):
        s = self.spawn()
        t = s.transport()
        s.proc.eof()
        s.natural_exit()
        t.close()
        seen = list(s.events)
        t.close()
        self.assertEqual(s.events, seen)
        self.assertEqual(s.events.count("stop"), 1)

    def test_before_launch_rejection_launches_nothing(self):
        s = self.spawn()

        def reject():
            s._event("before")
            raise NativeError("denied")

        with self.assertRaises(NativeError):
            s.transport(before_launch=reject)
        self.assertEqual(s.events, ["before"])
        self.assertEqual(s.run.call_count, 1)
        self.assertEqual(s.popen.call_count, 0)
        self.assertNotIn("stop", s.events)

    def test_popen_oserror_is_proven_no_child_once(self):
        s = self.spawn()
        error = OSError("spawn denied")
        s.popen_error = error
        with self.assertRaises(OSError) as cm:
            s.transport()
        self.assertIs(cm.exception, error)
        self.assertEqual(s.events,
                         ["before", "popen", ("stopped", True)])
        self.assertEqual(s.callback_masks, [frozenset()])
        self.assertNotIn("stop", s.events)

    def test_popen_non_oserror_is_unknown_not_no_child(self):
        for exc in (KeyboardInterrupt(), SystemExit(9), RuntimeError("boom")):
            with self.subTest(exc=type(exc).__name__):
                s = self.spawn()
                s.popen_error = exc
                with self.assertRaises(type(exc)) as cm:
                    s.transport()
                self.assertIs(cm.exception, exc)
                self.assertEqual(
                    s.events, ["before", "popen", ("stopped", False)])
                self.assertEqual(s.callback_masks, [frozenset()])
                self.assertNotIn("stop", s.events)

    def test_spawn_failure_cleans_once(self):
        s = self.spawn()
        s.stack.enter_context(mock.patch.object(
            os, "set_blocking", side_effect=OSError("boom")))
        with self.assertRaises(OSError):
            s.transport()
        self.assertEqual(s.events,
                         ["before", "popen", "stop", ("stopped", True)])
        self.assertTrue(s.proc.stdin.closed)
        self.assertTrue(s.proc.stdout.closed)

    def test_constructor_stop_failure_reports_false_once(self):
        s = self.spawn()
        s.stop_error = RuntimeError("stop failed")
        s.stack.enter_context(mock.patch.object(
            os, "set_blocking", side_effect=OSError("setblocking")))
        with self.assertRaises(OSError):
            s.transport()
        self.assertEqual(
            s.events, ["before", "popen", "stop", ("stopped", False)])
        self.assertEqual(len(s.mask_calls), 4)
        self.assertEqual(s.mask_calls[-1], (signal.SIG_SETMASK, set()))
        self.assertEqual(s.callback_masks, [CLEANUP_SIGS])

    def test_constructor_interrupted_cleanup_still_stops(self):
        s = self.spawn()
        s.mask_failures[3] = KeyboardInterrupt()
        s.stack.enter_context(mock.patch.object(
            os, "set_blocking", side_effect=OSError("setblocking")))
        with self.assertRaises(KeyboardInterrupt):
            s.transport()
        self.assertEqual(s.events,
                         ["before", "popen", "stop", ("stopped", True)])
        self.assertEqual(len(s.mask_calls), 4)
        self.assertEqual(s.mask_calls[-1], (signal.SIG_SETMASK, set()))
        self.assertTrue(s.proc.stdin.closed)
        self.assertTrue(s.proc.stdout.closed)

    def test_partial_eof_dirty_but_stopped_true(self):
        s = self.spawn()
        t = s.transport()
        s.proc.emit(b'{"x":1')
        s.proc.eof()
        s.exited = True
        s.exit_code = os.CLD_KILLED
        s.running = False
        t.close()
        self.assertFalse(t.validated_eof)
        self.assertFalse(t.drain_clean)
        self.assertIsNone(t.natural_exit)
        self.assertTrue(t.stopped)
        self.assertEqual(s.events[-1], ("stopped", True))

    def test_forced_cleanup_still_releases_lease(self):
        s = self.spawn()
        t = s.transport(max_drain_s=1)
        s.proc.eof()
        t.close()
        self.assertTrue(t.validated_eof)
        self.assertTrue(t.drain_clean)
        self.assertTrue(t.cleanup_terminated)
        self.assertTrue(t.stopped)
        self.assertEqual(s.events[-1], ("stopped", True))

    def test_stop_failure_reported_false(self):
        s = self.spawn()
        s.stop_result = False
        t = s.transport()
        s.proc.eof()
        s.natural_exit()
        t.close()
        self.assertFalse(t.stopped)
        self.assertEqual(s.events[-1], ("stopped", False))

    def test_stop_exception_reported_false(self):
        s = self.spawn()
        t = s.transport()
        s.proc.eof()
        s.natural_exit()
        with mock.patch("co_v4.task.infer._stop_group",
                        side_effect=RuntimeError("boom")):
            t.close()
        self.assertFalse(t.stopped)
        self.assertNotIn("stop", s.events)
        self.assertEqual(s.events[-1], ("stopped", False))

    def test_natural_exit_nonzero_recorded(self):
        s = self.spawn()
        s.exit_status = 3
        t = s.transport()
        s.proc.eof()
        s.natural_exit()
        t.close()
        self.assertEqual(t.natural_exit, 3)
        self.assertTrue(t.validated_eof)
        self.assertTrue(t.drain_clean)
        self.assertTrue(t.stopped)
        self.assertEqual(s.events[-1], ("stopped", True))

    def test_dirty_drain_eof_validated_not_clean(self):
        s = self.spawn()
        t = s.transport()
        orig_close = s.proc.stdin.close
        state = {"failed": False}

        def flaky_close():
            if not state["failed"]:
                state["failed"] = True
                raise OSError("boom")
            orig_close()

        s.proc.stdin.close = flaky_close
        s.proc.eof()
        s.natural_exit()
        with self.assertRaises(OSError):
            t.close()
        self.assertTrue(t.validated_eof)
        self.assertFalse(t.drain_clean)
        self.assertTrue(t.stopped)
        self.assertTrue(s.proc.stdin.closed)
        self.assertEqual(s.events[-1], ("stopped", True))

    def test_cleanup_mask_order_and_callback_under_mask(self):
        s = self.spawn()
        t = s.transport()
        s.proc.eof()
        s.natural_exit()
        t.close()
        self.assertEqual(
            s.mask_calls,
            [(signal.SIG_BLOCK, set()),
             (signal.SIG_BLOCK, set()),
             (signal.SIG_BLOCK, set(CLEANUP_SIGS)),
             (signal.SIG_SETMASK, set())])
        self.assertEqual(
            s.timeline,
            [("mask", signal.SIG_BLOCK, frozenset()),
             "before", "popen",
             ("mask", signal.SIG_BLOCK, frozenset()),
             ("mask", signal.SIG_BLOCK, CLEANUP_SIGS),
             "stop", ("stopped", True),
             ("mask", signal.SIG_SETMASK, frozenset())])
        self.assertEqual(s.callback_masks, [CLEANUP_SIGS])
        self.assertEqual(s.mask_current, set())

    def test_mask_block_interrupt_still_stops_and_restores(self):
        s = self.spawn()
        s.mask_failures[3] = KeyboardInterrupt()
        t = s.transport()
        s.proc.eof()
        s.natural_exit()
        with self.assertRaises(KeyboardInterrupt):
            t.close()
        self.assertIn("stop", s.events)
        self.assertTrue(t.stopped)
        self.assertEqual(s.events[-1], ("stopped", True))
        self.assertEqual(len(s.mask_calls), 4)
        self.assertEqual(s.mask_calls[-1], (signal.SIG_SETMASK, set()))
        self.assertEqual(s.callback_masks, [frozenset()])

    def test_read_interrupt_with_unproven_stop_reports_false(self):
        s = self.spawn()
        s.stop_result = False
        t = s.transport()
        s.proc.eof()
        with mock.patch("os.read", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                t.close()
        self.assertFalse(t.stopped)
        self.assertEqual(s.events[-1], ("stopped", False))
        self.assertEqual(len(s.mask_calls), 4)
        self.assertEqual(s.mask_calls[-1], (signal.SIG_SETMASK, set()))
        self.assertEqual(s.callback_masks, [CLEANUP_SIGS])

    def test_groupstop_interrupt_false_callback_and_restores(self):
        s = self.spawn()
        t = s.transport()
        s.proc.eof()
        s.natural_exit()
        stop = s.stack.enter_context(mock.patch(
            "co_v4.task.infer._stop_group",
            side_effect=KeyboardInterrupt()))
        with self.assertRaises(KeyboardInterrupt):
            t.close()
        stop.assert_called_once_with(s.proc)
        self.assertFalse(t.stopped)
        self.assertEqual(s.events[-1], ("stopped", False))
        self.assertEqual(len(s.mask_calls), 4)
        self.assertEqual(s.mask_calls[-1], (signal.SIG_SETMASK, set()))
        self.assertEqual(s.callback_masks, [CLEANUP_SIGS])

    def test_callback_interrupt_restores_mask(self):
        s = self.spawn()
        calls = []

        def interrupted(flag):
            calls.append(flag)
            s.callback_masks.append(frozenset(s.mask_current))
            raise KeyboardInterrupt()

        t = s.transport(on_stopped=interrupted)
        s.proc.eof()
        s.natural_exit()
        with self.assertRaises(KeyboardInterrupt):
            t.close()
        self.assertEqual(calls, [True])
        self.assertTrue(t.stopped)
        self.assertEqual(len(s.mask_calls), 4)
        self.assertEqual(s.mask_calls[-1], (signal.SIG_SETMASK, set()))
        self.assertEqual(s.callback_masks, [CLEANUP_SIGS])

    def test_unexpected_read_errors_still_stop_group(self):
        for exc in (ValueError("boom"), OSError("boom"), KeyboardInterrupt()):
            with self.subTest(exc=type(exc).__name__):
                s = self.spawn()
                t = s.transport()
                s.proc.eof()
                with mock.patch("os.read", side_effect=exc):
                    with self.assertRaises(type(exc)):
                        t.close()
                self.assertIn("stop", s.events)
                self.assertTrue(t.stopped)
                self.assertEqual(s.events[-1], ("stopped", True))

    def test_waitid_unexpected_error_still_stops(self):
        s = self.spawn()
        t = s.transport()
        s.proc.eof()
        with mock.patch("co_v4.task.child_status.waitid",
                        side_effect=ValueError("boom")):
            with self.assertRaises(ValueError):
                t.close()
        self.assertIn("stop", s.events)
        self.assertTrue(t.stopped)
        self.assertEqual(s.events[-1], ("stopped", True))

    def test_pending_outgoing_flush_error_still_stops(self):
        s = self.spawn()
        t = s.transport()
        s.proc.eof()
        s.natural_exit()
        t._outgoing.extend(b"x")
        with mock.patch("os.write", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                t.close()
        self.assertIn("stop", s.events)
        self.assertFalse(t.drain_clean)
        self.assertTrue(t.stopped)
        self.assertEqual(s.events[-1], ("stopped", True))

    def test_callback_error_propagates_once(self):
        s = self.spawn()
        calls = []

        def boom(flag):
            calls.append(flag)
            raise RuntimeError("hook")

        t = s.transport(on_stopped=boom)
        s.proc.eof()
        s.natural_exit()
        with self.assertRaises(RuntimeError):
            t.close()
        t.close()
        self.assertEqual(calls, [True])
        self.assertTrue(t.stopped)
        self.assertEqual(len(s.mask_calls), 4)

    def test_alive_never_reaps_leader(self):
        s = self.spawn()
        t = s.transport()
        self.assertTrue(t.alive())
        self.assertEqual(s.proc.poll_calls, 0)
        self.assertEqual(s.proc.wait_calls, 0)
        s.running = False
        self.assertFalse(t.alive())


class OwnedTransportDeltaTests(unittest.TestCase):
    spawn = OwnedTransportTests.spawn

    @staticmethod
    def _hold(lock, held, free):
        with lock:
            held.set()
            free.wait(5)

    def test_owner_and_non_owner_complete_without_lock(self):
        s = self.spawn(); t = s.transport(max_drain_s=1)
        hit, go, held, free, waiting = (threading.Event() for _ in range(5))
        wait = t._stop_done.wait
        s.stack.enter_context(mock.patch.object(t._stop_done, "wait",
            side_effect=lambda timeout: (waiting.set(), wait(timeout))[1]))
        s.stack.enter_context(mock.patch.object(t._infer, "_stop_group",
            lambda p: (hit.set(), go.wait(5), s._stop(p))[2]))
        out = {}
        owner = threading.Thread(target=lambda: out.setdefault("o", t.stop_group_only(lock_timeout_s=.05)))
        late = threading.Thread(target=lambda: out.setdefault("n", t.stop_group_only(lock_timeout_s=.05)))
        holder = threading.Thread(target=lambda: self._hold(t._state_lock, held, free))
        try:
            owner.start(); self.assertTrue(hit.wait(5))
            late.start(); self.assertTrue(waiting.wait(5))
            holder.start(); self.assertTrue(held.wait(5))
            go.set(); owner.join(1); late.join(1)
            self.assertFalse(owner.is_alive() or late.is_alive())
            self.assertIs(out.get("o"), False); self.assertIs(out.get("n"), False)
            self.assertTrue(t._stop_done.is_set() and t.stopped)
            self.assertFalse(t._process.stdin.closed or t._callback_fired)
        finally:
            go.set(); free.set()
            for th in (owner, late, holder):
                if th.ident is not None: th.join(1)
        t.close()
        self.assertEqual((s.events.count(("stopped", True)), s.events.count("stop")), (1, 1))

    def test_helper_interrupt_fires_callback_false_once(self):
        s = self.spawn(); s.stop_error = KeyboardInterrupt()
        t = s.transport(max_drain_s=1)
        with self.assertRaises(KeyboardInterrupt) as cm: t.stop_group_only()
        self.assertIs(cm.exception, s.stop_error)
        self.assertTrue(t._stop_done.is_set() and not t.stopped)
        self.assertFalse(t._process.stdin.closed)
        self.assertEqual(s.events.count(("stopped", False)), 1)
        t.close()
        self.assertEqual((s.events.count(("stopped", False)), s.events.count("stop")), (1, 1))
        self.assertTrue(t._process.stdin.closed)
    def test_main_construct_worker_cleanup_does_not_mask_worker(self):
        s = self.spawn(); t = s.transport()
        s.proc.eof(); s.natural_exit(); errors = []
        def worker():
            try: t.close()
            except BaseException as exc: errors.append(exc)
        th = threading.Thread(target=worker); th.start(); th.join(2)
        self.assertFalse(th.is_alive()); self.assertEqual(errors, [])
        self.assertEqual(s.mask_calls, [(signal.SIG_BLOCK, set())])
        self.assertEqual(s.events.count("stop"), 1)
        self.assertEqual(s.events[-1], ("stopped", True))

    def test_cleanup_restores_mask_changed_after_constructor(self):
        s = self.spawn(); t = s.transport()
        s.mask_current = {signal.SIGUSR1}
        s.proc.eof(); s.natural_exit(); t.close()
        self.assertEqual(s.mask_current, {signal.SIGUSR1})
        self.assertEqual(s.mask_calls[-1], (signal.SIG_SETMASK, {signal.SIGUSR1}))
        self.assertEqual(s.callback_masks, [CLEANUP_SIGS | {signal.SIGUSR1}])

    def test_stdout_one_shot_close_failure_dirty_and_reported(self):
        s = self.spawn(); t = s.transport(); error = OSError("close failure")
        original = s.proc.stdout.close; calls = []
        def flaky():
            calls.append(True)
            if len(calls) == 1: raise error
            original()
        s.proc.stdout.close = flaky
        s.proc.eof(); s.natural_exit()
        with self.assertRaises(OSError) as cm: t.close()
        self.assertIs(cm.exception, error); self.assertEqual(len(calls), 2)
        self.assertFalse(t.drain_clean); self.assertTrue(t.validated_eof)
        self.assertEqual(t.natural_exit, 0); self.assertTrue(t.stopped)
        self.assertTrue(s.proc.stdin.closed); self.assertTrue(s.proc.stdout.closed)
        seen = list(s.events); t.close(); self.assertEqual(s.events, seen)
        self.assertEqual(s.events.count("stop"), 1)
        self.assertEqual(s.events.count(("stopped", True)), 1)

    def test_prior_drain_error_wins_over_descriptor_error(self):
        s = self.spawn(); t = s.transport(); error = ValueError("read failure")
        close_error = OSError("close failure"); original = s.proc.stdout.close
        calls = []
        def flaky():
            calls.append(True)
            if len(calls) == 1: raise close_error
            original()
        s.proc.stdout.close = flaky; s.proc.eof(); s.natural_exit()
        with mock.patch("os.read", side_effect=error):
            with self.assertRaises(ValueError) as cm: t.close()
        self.assertIs(cm.exception, error); self.assertFalse(t.drain_clean)
        self.assertTrue(t.stopped); self.assertTrue(s.proc.stdout.closed)
        self.assertEqual(s.events.count(("stopped", True)), 1)

    def test_cleanup_snapshot_failure_still_stops_without_unknown_restore(self):
        s = self.spawn(); t = s.transport(); error = KeyboardInterrupt()
        s.mask_failures[2] = error; s.proc.eof(); s.natural_exit()
        with self.assertRaises(KeyboardInterrupt) as cm: t.close()
        self.assertIs(cm.exception, error); self.assertEqual(len(s.mask_calls), 2)
        self.assertTrue(t.stopped); self.assertTrue(s.proc.stdout.closed)
        self.assertEqual(s.events.count(("stopped", True)), 1)

    def test_concurrent_stop_and_close_once(self):
        s = self.spawn()
        t = s.transport()
        entered, release = threading.Event(), threading.Event()
        calls = []
        def fake_stop(proc):
            calls.append(proc.pid)
            entered.set()
            release.wait(timeout=10)
            s.running = False
            return True
        s.stack.enter_context(mock.patch.object(
            t._infer, "_stop_group", side_effect=fake_stop))
        out = {}
        stop_th = threading.Thread(
            target=lambda: out.__setitem__("rc", t.stop_group_only()))
        stop_th.start()
        self.assertTrue(entered.wait(timeout=5))
        close_th = threading.Thread(target=t.close)
        close_th.start()
        release.set()
        stop_th.join(timeout=15)
        close_th.join(timeout=15)
        self.assertFalse(stop_th.is_alive() or close_th.is_alive())
        self.assertEqual(len(calls), 1)
        self.assertTrue(out.get("rc"))
        self.assertTrue(t.stopped)
        self.assertFalse(t.drain_clean)
        flags = [e[1] for e in s.events
                 if isinstance(e, tuple) and e[:1] == ("stopped",)]
        self.assertEqual(flags, [True])

    def test_public_stop_leaves_descriptors_for_worker_close(self):
        s = self.spawn()
        t = s.transport()
        self.assertTrue(t.stop_group_only())
        self.assertTrue(t._cancel.is_set())
        self.assertFalse(t._process.stdin.closed)
        self.assertFalse(t._process.stdout.closed)
        t.close()
        self.assertTrue(t._process.stdin.closed)
        self.assertTrue(t._process.stdout.closed)
        self.assertTrue(t.stopped)

    def test_retained_false_is_not_retried(self):
        s = self.spawn()
        s.stop_result = False
        t = s.transport()
        self.assertFalse(t.stop_group_only())
        self.assertFalse(t.stop_group_only())
        t.close()
        self.assertFalse(t.stop_group_only())
        self.assertFalse(t.stopped)
        self.assertEqual(1, sum(1 for e in s.events
                                if e == "stop" or (isinstance(e, tuple)
                                                   and e[:1] == ("stop",))))

    def test_normal_close_never_sets_cancel(self):
        s = self.spawn()
        t = s.transport(max_drain_s=1)
        t.close()
        self.assertFalse(t._cancel.is_set())
        self.assertTrue(t.stopped)

    def test_no_leader_queries_after_stop_owner_starts(self):
        s = self.spawn()
        t = s.transport(max_drain_s=5)
        entered, release = threading.Event(), threading.Event()
        first_waitid = threading.Event()
        waitid_calls, leader_calls = [], []
        def fake_stop(proc):
            entered.set()
            release.wait(timeout=10)
            s.running = False
            return True
        def fake_waitid(*args):
            waitid_calls.append(args)
            first_waitid.set()
            return None
        s.stack.enter_context(mock.patch.object(
            t._infer, "_stop_group", side_effect=fake_stop))
        s.stack.enter_context(mock.patch.object(
            t._child_status, "waitid", side_effect=fake_waitid))
        s.stack.enter_context(mock.patch.object(
            t._infer, "_leader_running",
            side_effect=lambda p: leader_calls.append(p) or s.running))
        close_th = threading.Thread(target=t.close)
        close_th.start()
        self.assertTrue(first_waitid.wait(timeout=5))
        stop_th = threading.Thread(target=t.stop_group_only)
        stop_th.start()
        self.assertTrue(entered.wait(timeout=5))
        seen = len(waitid_calls)
        release.set()
        stop_th.join(timeout=15)
        close_th.join(timeout=15)
        self.assertFalse(stop_th.is_alive() or close_th.is_alive())
        self.assertEqual(len(waitid_calls), seen)
        self.assertFalse(t.alive())
        self.assertFalse(leader_calls)

    def test_interrupt_publishes_event_callback_once_descriptors(self):
        s = self.spawn()
        s.stop_error = KeyboardInterrupt()
        t = s.transport(max_drain_s=1)
        with self.assertRaises(KeyboardInterrupt):
            t.close()
        self.assertTrue(t._stop_done.is_set())
        self.assertFalse(t.stopped)
        self.assertTrue(t._process.stdin.closed)
        self.assertTrue(t._process.stdout.closed)
        self.assertFalse(t.stop_group_only())
        self.assertEqual(1, sum(1 for e in s.events
                                if e == "stop" or (isinstance(e, tuple)
                                                   and e[:1] == ("stop",))))
        flags = [e[1] for e in s.events
                 if isinstance(e, tuple) and e[:1] == ("stopped",)]
        self.assertEqual(flags, [False])


class OwnedTransportBirthTests(unittest.TestCase):
    spawn = OwnedTransportDeltaTests.spawn

    def test_gate_and_registration_snapshot(self):
        s = self.spawn(); cancel = threading.Event(); cancel.set(); seen = []
        with self.assertRaises(NoChild):
            s.transport(cancel=cancel, register_transport=seen.append)
        self.assertEqual((seen, s.events, s.popen.call_count), ([], [], 0))
        s = self.spawn(); seen = []
        def register(t):
            seen.append((t._process, bytes(t._incoming), bytes(t._outgoing),
                         t._eof, t._launch_state, t._closed)); s.events.append("register")
        t = s.transport(register_transport=register)
        self.assertEqual(seen, [(None, b"", b"", False, "not_attempted", False)])
        self.assertEqual(s.events[:3], ["register", "before", "popen"]); t.close()

    def test_rejected_registration_or_hook_cannot_spawn(self):
        s = self.spawn(); slots = []
        def bad_register(t): slots.append(t); raise RuntimeError("slot")
        with self.assertRaisesRegex(RuntimeError, "slot"):
            s.transport(register_transport=bad_register)
        self.assertTrue(slots[0]._closed); self.assertTrue(slots[0].stop_group_only())
        s2 = self.spawn()
        def bad_before(): s2.events.append("before"); raise ValueError("claim")
        with self.assertRaisesRegex(ValueError, "claim"):
            s2.transport(register_transport=slots.append, before_launch=bad_before)
        self.assertTrue(slots[1]._closed); self.assertTrue(slots[1].stop_group_only())
        self.assertEqual((s.popen.call_count, s2.popen.call_count), (0, 0))
        self.assertEqual((s.events, s2.events), ([], ["before"]))

    def test_cancel_after_returned_hook_is_once_true(self):
        s = self.spawn(); cancel = threading.Event()
        def before(): s.events.append("before"); cancel.set()
        with self.assertRaises(NoChild):
            s.transport(cancel=cancel, before_launch=before)
        self.assertEqual(s.events, ["before", ("stopped", True)])
        s.popen.assert_not_called(); self.assertNotIn("stop", s.events)

    def test_public_timeout_then_inflight_child_is_stopped_once(self):
        s = self.spawn(); entered = threading.Event(); release = threading.Event()
        done = threading.Event(); slot = []; outcome = []
        def blocked_popen(argv, **kw):
            s.events.append("popen"); entered.set()
            if not release.wait(2): raise RuntimeError("release")
            return s.proc
        s.popen.side_effect = blocked_popen
        def birth():
            try: s.transport(register_transport=slot.append)
            except BaseException as exc: outcome.append(exc)
            finally: done.set()
        worker = threading.Thread(target=birth, daemon=True); worker.start()
        try:
            self.assertTrue(entered.wait(2)); child = slot[0]
            self.assertFalse(child.stop_group_only(lock_timeout_s=0.05))
        finally: release.set()
        self.assertTrue(done.wait(2)); worker.join(1); self.assertFalse(worker.is_alive())
        self.assertIs(type(outcome[0]), NativeError)
        self.assertIs(child._process, s.proc); self.assertEqual(s.popen.call_count, 1)
        self.assertIn("stop", s.events); self.assertIn(("stopped", True), s.events)
        self.assertTrue(s.proc.stdin.closed)

    def test_unknown_failure_and_original_interrupt_survive(self):
        s = self.spawn(); slots = []; original = RuntimeError("boom")
        s.popen_error = original
        with self.assertRaises(RuntimeError) as caught:
            s.transport(register_transport=slots.append)
        self.assertIs(caught.exception, original); partial = slots[0]
        self.assertEqual(partial._launch_state, "unknown")
        self.assertFalse(partial.stop_group_only()); partial.close()
        self.assertEqual((s.popen.call_count, s.events.count("stop"),
                          s.events.count(("stopped", False))), (1, 0, 1))
        s = self.spawn(); original = KeyboardInterrupt("launch")
        s.popen_error = original
        def stopped(flag): raise SystemExit("callback")
        with self.assertRaises(KeyboardInterrupt) as caught:
            s.transport(on_stopped=stopped)
        self.assertIs(caught.exception, original)
    def test_alive_lookup_precedes_stop_election_at_lock_exit(self):
        s = self.spawn(); t = s.transport(); real = t._state_lock; fired = []
        class BoundaryLock:
            def acquire(self, *a, **kw): return real.acquire(*a, **kw)
            def release(self): return real.release()
            def __enter__(self): real.acquire(); return self
            def __exit__(self, *_):
                real.release()
                if not fired: fired.append(True); t.stop_group_only()
        def leader(proc): self.assertIsNone(t._stop_state); return s.running
        t._state_lock = BoundaryLock()
        with mock.patch.object(t._infer, "_leader_running", side_effect=leader):
            self.assertTrue(t.alive())
        self.assertTrue(t.stopped); t.close()


if __name__ == "__main__":
    unittest.main()
