"""Tests for owned-process-group cleanup in task.infer.

Models the local Darwin experiment: an exit-7 leader is still reported by
waitid(WNOWAIT) as OUR unreaped child, SIGKILL on the zombie-only group
raises EPERM, the bounded wait then reaps it, and killpg(pid, 0) proves
the group empty with ESRCH. All clocks and sleeps are mocked; nothing
really waits 5s.
"""

import contextlib
import os
import signal
import subprocess
import unittest
from unittest import mock

import co_v4.task.infer as tp


def make_proc(pid=4321, wait_result=7):
    proc = mock.MagicMock(name="proc")
    proc.pid = pid
    if isinstance(wait_result, BaseException):
        proc.wait.side_effect = wait_result
    else:
        proc.wait.return_value = wait_result
        proc.returncode = wait_result
    proc.stdin.fileno.return_value = 10
    proc.stdout.fileno.return_value = 11
    proc.stderr.fileno.return_value = 12
    return proc


@contextlib.contextmanager
def stop_env():
    with mock.patch.object(tp.os, "waitid") as mwaitid, \
            mock.patch.object(tp.os, "killpg") as mkillpg, \
            mock.patch.object(tp.time, "monotonic") as mmono, \
            mock.patch.object(tp.time, "sleep") as msleep:
        mmono.return_value = 0.0
        yield mwaitid, mkillpg, mmono, msleep


@contextlib.contextmanager
def spawn_env(proc, sel, stop_result=True, leader_running=False):
    with mock.patch.object(tp.subprocess, "Popen", return_value=proc), \
            mock.patch.object(tp.selectors, "DefaultSelector",
                              return_value=sel), \
            mock.patch.object(tp.os, "set_blocking"), \
            mock.patch.object(tp, "_leader_running",
                              return_value=leader_running), \
            mock.patch.object(tp, "_stop_group") as mstop, \
            mock.patch.object(tp.time, "monotonic") as mmono:
        if isinstance(stop_result, BaseException):
            mstop.side_effect = stop_result
        else:
            mstop.return_value = stop_result
        mmono.return_value = 0.0
        yield mstop, mmono


class StopGroupTests(unittest.TestCase):

    def test_exited_leader_reaped_group_absent_succeeds(self):
        # waitid(WNOWAIT) saw the exit-7 leader: still OUR unreaped child.
        proc = make_proc()
        with stop_env() as (mwaitid, mkillpg, _, _):
            mwaitid.return_value = object()
            mkillpg.side_effect = [None, ProcessLookupError()]
            self.assertTrue(tp._stop_group(proc))
        args = mwaitid.call_args[0]
        self.assertEqual(proc.pid, args[1])
        self.assertTrue(args[2] & os.WNOWAIT)
        self.assertTrue(args[2] & os.WNOHANG)
        mkillpg.assert_any_call(proc.pid, signal.SIGKILL)
        mkillpg.assert_any_call(proc.pid, 0)
        proc.wait.assert_called_once_with(timeout=5)

    def test_eperm_at_kill_then_reaped_absent_succeeds(self):
        # Darwin: EPERM from SIGKILL on a zombie-only group is not proof
        # of failure; the reap + absence proof decides.
        proc = make_proc()
        with stop_env() as (mwaitid, mkillpg, _, _):
            mwaitid.return_value = object()
            mkillpg.side_effect = [
                PermissionError(1, "Operation not permitted"),
                ProcessLookupError(),
            ]
            self.assertTrue(tp._stop_group(proc))
        proc.wait.assert_called_once_with(timeout=5)
        mkillpg.assert_any_call(proc.pid, 0)

    def test_group_present_or_eperm_after_deadline_fails_closed(self):
        proc = make_proc()
        with stop_env() as (mwaitid, mkillpg, mmono, msleep):
            mwaitid.return_value = None  # leader still running
            mkillpg.side_effect = [
                None,  # SIGKILL accepted
                PermissionError(1, "Operation not permitted"),
                PermissionError(1, "Operation not permitted"),
            ]
            mmono.side_effect = [0.0, 0.1, 10.0]
            self.assertFalse(tp._stop_group(proc))
        self.assertIn(mock.call(proc.pid, 0), mkillpg.call_args_list)
        msleep.assert_called_with(0.05)

    def test_unreaped_leader_fails_without_absence_proof(self):
        proc = make_proc(wait_result=subprocess.TimeoutExpired("cmd", 5))
        with stop_env() as (mwaitid, mkillpg, _, _):
            mwaitid.return_value = None
            self.assertFalse(tp._stop_group(proc))
        # only the pre-reap SIGKILL; the killpg(pid, 0) probe never ran
        self.assertEqual([mock.call(proc.pid, signal.SIGKILL)],
                         mkillpg.call_args_list)

    def test_lost_ownership_sends_no_signal(self):
        proc = make_proc()
        with stop_env() as (mwaitid, mkillpg, _, _):
            mwaitid.side_effect = ChildProcessError()
            self.assertFalse(tp._stop_group(proc))
        mkillpg.assert_not_called()
        proc.wait.assert_not_called()

    def test_no_destructive_signal_after_reap(self):
        proc = make_proc()
        events = []
        proc.wait.side_effect = lambda timeout: events.append("wait") or 7
        with stop_env() as (mwaitid, mkillpg, _, _):
            mwaitid.return_value = None

            def killpg(pgid, sig):
                events.append((pgid, sig))
                if sig == 0 and events.count((proc.pid, 0)) == 2:
                    raise ProcessLookupError()

            mkillpg.side_effect = killpg
            self.assertTrue(tp._stop_group(proc))
        wait_idx = events.index("wait")
        self.assertIn((proc.pid, signal.SIGKILL), events[:wait_idx])
        tail = events[wait_idx + 1:]
        self.assertTrue(tail)
        self.assertTrue(all(e == (proc.pid, 0) for e in tail))


class SpawnCleanupTests(unittest.TestCase):

    def test_exit7_confirmed_callback_called_once(self):
        proc = make_proc()
        sel = mock.MagicMock()
        sel.get_map.return_value = {}
        cb = mock.MagicMock()
        with spawn_env(proc, sel) as (mstop, _):
            rc, out, err = tp._spawn(["cmd"], {}, None, 10, on_stopped=cb)
        self.assertEqual(7, rc)
        self.assertEqual((b"", b""), (out, err))
        cb.assert_called_once_with(True)
        mstop.assert_called_once_with(proc)

    def test_cleanup_keyboard_interrupt_calls_callback_and_propagates(self):
        proc = make_proc()
        sel = mock.MagicMock()
        sel.get_map.return_value = {}
        cb = mock.MagicMock()
        with spawn_env(proc, sel, stop_result=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                tp._spawn(["cmd"], {}, None, 10, on_stopped=cb)
        cb.assert_called_once_with(False)

    def test_body_failure_preserved_over_callback_failure(self):
        proc = make_proc()
        sel = mock.MagicMock()
        sel.get_map.return_value = {11: object()}
        sel.select.side_effect = ValueError("body broke")
        cb = mock.MagicMock(side_effect=RuntimeError("cb broke"))
        with spawn_env(proc, sel):
            with self.assertRaises(ValueError):
                tp._spawn(["cmd"], {}, None, 10, on_stopped=cb)
        cb.assert_called_once_with(True)

    def test_timeout_keeps_route_timeout_over_callback_failure(self):
        proc = make_proc()
        sel = mock.MagicMock()
        sel.get_map.return_value = {11: object()}
        cb = mock.MagicMock(side_effect=RuntimeError("cb broke"))
        with spawn_env(proc, sel) as (mstop, mmono):
            mmono.side_effect = [0.0, 100.0]
            with self.assertRaises(tp.TaskError) as cm:
                tp._spawn(["cmd"], {}, None, 10, on_stopped=cb)
        code = getattr(cm.exception, "code", cm.exception.args[0])
        self.assertEqual("route_timeout", code)
        cb.assert_called_once_with(True)


if __name__ == "__main__":
    unittest.main()
