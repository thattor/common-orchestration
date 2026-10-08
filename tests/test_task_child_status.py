"""Real-child tests for the Darwin ctypes waitid fallback.

child_status._ctypes_waitid is called directly on EVERY supported
interpreter - including 3.13 where os.waitid exists - so the fallback
is exercised in exactly the configuration that ships it on 3.11/3.12.
All waitid calls use WEXITED|WNOHANG|WNOWAIT and never reap; children
are reaped only by proc.wait(), and no signal is ever sent after a
reap. This helper observes child processes; it makes no model or
network calls.
"""

import ctypes
import errno
import os
import select
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from co_v4.task import child_status, infer

if sys.platform != "darwin":
    raise unittest.SkipTest("ctypes fallback is Darwin-only")

_OPTS = os.WEXITED | os.WNOHANG | os.WNOWAIT


def _blocked_child(exit_code=7):
    """Child that reports readiness on one pipe, blocks on another.

    Returns (proc, ready_fd, release_fd): the parent reads one byte
    from ready_fd to prove the child is running, then writes/closes
    release_fd so the child exits with exit_code.
    """
    ready_r, ready_w = os.pipe()
    rel_r, rel_w = os.pipe()
    code = ("import os;"
            "os.write({w}, b'R');"
            "os.read({r}, 1);"
            "os._exit({c})").format(w=ready_w, r=rel_r, c=exit_code)
    try:
        proc = subprocess.Popen([sys.executable, "-c", code],
                                pass_fds=(ready_w, rel_r))
    except BaseException:
        for fd in (ready_r, ready_w, rel_r, rel_w):
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    os.close(ready_w)
    os.close(rel_r)
    return proc, ready_r, rel_w


def _close(fd):
    try:
        os.close(fd)
    except OSError:
        pass


def _finish(proc, *fds):
    """Bounded teardown: release the child, then reap it exactly once."""
    for fd in fds:
        _close(fd)
    if proc.returncode is None:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def _await_ready(ready_r):
    r, _, _ = select.select([ready_r], [], [], 10)
    if not r:
        raise AssertionError("child never reported readiness")
    return os.read(ready_r, 1)


def _poll_exit(fn, pid, timeout=10.0):
    deadline = time.monotonic() + timeout
    while True:
        res = fn(os.P_PID, pid, _OPTS)
        if res is not None:
            return res
        if time.monotonic() >= deadline:
            raise AssertionError("pid %d never reported an exit" % pid)
        time.sleep(0.01)


class LayoutTests(unittest.TestCase):

    def test_siginfo_abi_matches_sdk_probe(self):
        S = child_status._SigInfo
        self.assertEqual(104, ctypes.sizeof(S))
        self.assertEqual(12, S.si_pid.offset)
        self.assertEqual(20, S.si_status.offset)
        self.assertEqual(24, S.si_addr.offset)
        self.assertEqual(32, S.si_value.offset)
        self.assertEqual(40, S.si_band.offset)
        self.assertEqual(48, S.si_pad.offset)

    def test_backend_resolves_and_is_cached(self):
        fn = child_status._ctypes_backend()
        self.assertIsNotNone(fn)
        self.assertIs(fn, child_status._ctypes_backend())
        self.assertTrue(child_status.supported())


class CtypesRealChildTests(unittest.TestCase):

    def test_exit7_reported_repeatedly_without_reaping(self):
        fn = child_status._ctypes_waitid
        proc, ready_r, rel_w = _blocked_child()
        try:
            self.assertEqual(b"R", _await_ready(ready_r))
            _close(ready_r)
            ready_r = -1
            # Still blocked: no state change to report.
            self.assertIsNone(fn(os.P_PID, proc.pid, _OPTS))
            os.write(rel_w, b"X")
            _close(rel_w)
            rel_w = -1
            res = _poll_exit(fn, proc.pid)
            self.assertEqual(proc.pid, res.si_pid)
            self.assertEqual(7, res.si_status)
            self.assertEqual(getattr(os, "CLD_EXITED", 3), res.si_code)
            self.assertEqual(signal.SIGCHLD, res.si_signo)
            # WNOWAIT: the exit is still reported, never consumed.
            for _ in range(20):
                again = fn(os.P_PID, proc.pid, _OPTS)
                self.assertEqual(proc.pid, again.si_pid)
                self.assertEqual(7, again.si_status)
                self.assertEqual(res.si_code, again.si_code)
            self.assertIsNone(proc.returncode)
            os.kill(proc.pid, 0)  # zombie: still our unreaped child
            if child_status._native_waitid is not None:
                nres = child_status._native_waitid(
                    os.P_PID, proc.pid, _OPTS)
                self.assertIsNotNone(nres)
                for field in ("si_pid", "si_uid", "si_signo",
                              "si_status", "si_code"):
                    self.assertEqual(getattr(res, field),
                                     getattr(nres, field), field)
            self.assertEqual(7, proc.wait(timeout=10))
            # Reaped: ownership is gone.
            with self.assertRaises(ChildProcessError):
                fn(os.P_PID, proc.pid, _OPTS)
            # An unrelated live pid is not our child either.
            with self.assertRaises(ChildProcessError):
                fn(os.P_PID, os.getppid(), _OPTS)
        finally:
            _finish(proc, ready_r, rel_w)

    def test_sigkill_reported_without_reaping(self):
        fn = child_status._ctypes_waitid
        proc, ready_r, rel_w = _blocked_child()
        try:
            self.assertEqual(b"R", _await_ready(ready_r))
            os.kill(proc.pid, signal.SIGKILL)
            res = _poll_exit(fn, proc.pid)
            self.assertEqual(proc.pid, res.si_pid)
            self.assertEqual(signal.SIGKILL, res.si_status)
            self.assertEqual(getattr(os, "CLD_KILLED", 2), res.si_code)
            self.assertIsNone(proc.returncode)
            if child_status._native_waitid is not None:
                nres = child_status._native_waitid(
                    os.P_PID, proc.pid, _OPTS)
                self.assertEqual(res.si_pid, nres.si_pid)
                self.assertEqual(res.si_status, nres.si_status)
                self.assertEqual(res.si_code, nres.si_code)
            self.assertEqual(-signal.SIGKILL, proc.wait(timeout=10))
            with self.assertRaises(ChildProcessError):
                fn(os.P_PID, proc.pid, _OPTS)
        finally:
            _finish(proc, ready_r, rel_w)

    def test_public_waitid_dispatches_to_fallback(self):
        proc, ready_r, rel_w = _blocked_child()
        try:
            self.assertEqual(b"R", _await_ready(ready_r))
            with mock.patch.object(child_status, "_native_waitid", None):
                self.assertIsNone(
                    child_status.waitid(os.P_PID, proc.pid, _OPTS))
        finally:
            _finish(proc, ready_r, rel_w)


class CtypesErrorTests(unittest.TestCase):

    def _stubbed(self, fake):
        child_status._ctypes_backend()  # resolve cache before patching
        return mock.patch.object(child_status, "_libc_waitid", fake)

    def test_eintr_retries_then_succeeds(self):
        real = child_status._ctypes_backend()
        proc, ready_r, rel_w = _blocked_child()
        calls = []

        def flaky(idtype, pid, pinfo, options):
            calls.append(1)
            if len(calls) > 1:
                return real(idtype, pid, pinfo, options)
            ctypes.set_errno(errno.EINTR)
            return -1

        try:
            self.assertEqual(b"R", _await_ready(ready_r))
            with self._stubbed(flaky):
                self.assertIsNone(
                    child_status._ctypes_waitid(os.P_PID, proc.pid,
                                                _OPTS))
            self.assertEqual(2, len(calls))
        finally:
            _finish(proc, ready_r, rel_w)

    def test_eintr_with_raising_handler_propagates(self):
        child = subprocess.run(
            [sys.executable, "-I", "-S", "-B", __file__, "--eintr-signal"],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stdout.strip(), "handler-propagated")

    def _assert_raising_handler(self):
        fired = []

        def handler(signum, frame):
            fired.append(signum)
            raise RuntimeError("pending handler")

        calls = []

        def eintr(idtype, pid, pinfo, options):
            calls.append(1)
            if len(calls) == 1:
                os.kill(os.getpid(), signal.SIGUSR1)
            if len(calls) >= 100:
                return 0  # bound: report no change if handler never ran
            ctypes.set_errno(errno.EINTR)
            return -1

        old = signal.signal(signal.SIGUSR1, handler)
        try:
            with self._stubbed(eintr):
                with self.assertRaises(RuntimeError):
                    child_status._ctypes_waitid(os.P_PID, os.getpid(),
                                                _OPTS)
        finally:
            signal.signal(signal.SIGUSR1, old)
        self.assertEqual([signal.SIGUSR1], fired)

    def test_eperm_raises_plain_oserror(self):
        def denied(idtype, pid, pinfo, options):
            ctypes.set_errno(errno.EPERM)
            return -1

        with self._stubbed(denied):
            with self.assertRaises(OSError) as cm:
                child_status._ctypes_waitid(os.P_PID, os.getpid(), _OPTS)
        self.assertEqual(errno.EPERM, cm.exception.errno)
        self.assertNotIsInstance(cm.exception, ChildProcessError)

    def test_echild_maps_to_childprocesserror(self):
        def echild(idtype, pid, pinfo, options):
            ctypes.set_errno(errno.ECHILD)
            return -1

        with self._stubbed(echild):
            with self.assertRaises(ChildProcessError):
                child_status._ctypes_waitid(os.P_PID, os.getpid(), _OPTS)

    def test_invalid_args_fail_before_any_native_call(self):
        fake = mock.MagicMock()
        native = mock.MagicMock()
        child_status._ctypes_backend()
        with mock.patch.object(child_status, "_libc_waitid", fake), \
                mock.patch.object(child_status, "_native_waitid", native):
            for bad in (0, -1, 2 ** 31, 2 ** 40):
                with self.assertRaises(ValueError):
                    child_status._ctypes_waitid(os.P_PID, bad, _OPTS)
                with self.assertRaises(ValueError):
                    child_status.waitid(os.P_PID, bad, _OPTS)
            with self.assertRaises(ValueError):
                child_status.waitid(0, os.getpid(), _OPTS)
            with self.assertRaises(ValueError):
                child_status.waitid(os.P_PID, os.getpid(), os.WNOHANG)
        fake.assert_not_called()
        native.assert_not_called()


class PreflightTests(unittest.TestCase):

    def test_supported_false_refuses_before_spawn(self):
        before = mock.MagicMock()
        with mock.patch.object(child_status, "supported",
                               return_value=False), \
                mock.patch.object(infer.subprocess, "Popen") as mpopen, \
                mock.patch.object(infer.os, "killpg") as mkillpg:
            with self.assertRaises(infer.RouteFailure) as cm:
                infer._spawn(["cmd"], {}, None, 10,
                             before_launch=before)
            with self.assertRaises(infer.TaskError) as tm:
                infer._spawn(["cmd"], {}, None, 10)
        code = getattr(cm.exception, "code", cm.exception.args[0])
        self.assertEqual("route_unavailable", code)
        tcode = getattr(tm.exception, "code", tm.exception.args[0])
        self.assertEqual("route_unavailable", tcode)
        before.assert_not_called()
        mpopen.assert_not_called()
        mkillpg.assert_not_called()


if __name__ == "__main__":
    if sys.argv[1:] == ["--eintr-signal"]:
        CtypesErrorTests()._assert_raising_handler()
        print("handler-propagated")
    else:
        unittest.main()
