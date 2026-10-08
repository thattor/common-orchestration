"""Cross-process admission accounting tests for co_v4.task.admission.

Spawns real OS processes (multiprocessing 'spawn') to prove the admission
ledger is shared across processes and that a SIGKILLed holder's entry is
not auto-released. The ``invoke`` fixtures are local stand-ins: nothing
here touches a real Native model, the network, or the real account home --
``admission._host_root`` is patched to a private canonical temp dir in
both the parent and every child process.
"""
import multiprocessing as mp
import shutil
import signal
import sys
import tempfile
import traceback
import unittest
from pathlib import Path
from typing import NamedTuple
from unittest import mock

from co_v4.task import admission

LIMIT = 12
READY_TIMEOUT = 20.0
RESULT_TIMEOUT = 15.0
JOIN_TIMEOUT = 10.0
CHILD_CMD_TIMEOUT = 60.0


class _Kid(NamedTuple):
    proc: object
    ready: object
    cmd: object
    result: object


def _reason(exc):
    return str(getattr(exc, "reason", None) or getattr(exc, "code", None) or exc)


def _report_error(result_w):
    try:
        result_w.send(("error", traceback.format_exc()))
    except Exception:
        pass
    finally:
        result_w.close()
    sys.exit(1)


def _held_child(root, state, cwd, call_dir, route, model, setup,
                ready_w, cmd_r, result_w):
    """Acquire a lease, signal readiness, hold until told to finish."""
    try:
        with mock.patch.object(admission, "_host_root",
                               return_value=Path(root)):
            def invoke(*, before_launch, on_stopped):
                before_launch()
                ready_w.send("ready")
                if cmd_r.poll(CHILD_CMD_TIMEOUT) and cmd_r.recv() == "finish":
                    on_stopped(True)
                    return "stopped"
                return "aborted"
            with admission.gate(cwd, state_dir=state, setup=setup,
                                binding={"route": route, "model": model}):
                ret = admission.model_call(route, model, "prompt",
                                           call_dir, invoke)
            result_w.send(("ok", ret))
            result_w.close()
    except BaseException:
        _report_error(result_w)


def _quick_child(root, state, cwd, call_dir, route, model, setup, result_w):
    """Fresh process performing one complete admission call, then exiting."""
    try:
        with mock.patch.object(admission, "_host_root",
                               return_value=Path(root)):
            def invoke(*, before_launch, on_stopped):
                before_launch()
                on_stopped(True)
                return "done"
            with admission.gate(cwd, state_dir=state, setup=setup,
                                binding={"route": route, "model": model}):
                ret = admission.model_call(route, model, "prompt",
                                           call_dir, invoke)
            result_w.send(("ok", ret))
            result_w.close()
    except BaseException:
        _report_error(result_w)


class AdmissionCrossProcessTest(unittest.TestCase):

    def setUp(self):
        self.ctx = mp.get_context("spawn")
        self.kids = []
        self._new_root()
        self._start_patch()

    def tearDown(self):
        for kid in self.kids:
            if kid.proc.is_alive():
                kid.proc.kill()
            kid.proc.join(JOIN_TIMEOUT)
            for connection in (kid.ready, kid.cmd, kid.result):
                connection.close()
            kid.proc.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- environment -----------------------------------------------------

    def _new_root(self):
        # resolve() first: on macOS the temp dir is a /var -> /private/var
        # symlink and the admission root must be canonical.
        self.tmp = Path(tempfile.mkdtemp(prefix="admission-xproc-")).resolve()
        self.host = self.tmp / "host"        # host root: outside state/native
        self.cwd_a = self.tmp / "native-a"
        self.cwd_b = self.tmp / "native-b"
        self.cwds = (self.cwd_a, self.cwd_b)
        self.states = [self.tmp / ("state-%d" % i) for i in range(3)]
        for d in (self.host, self.cwd_a, self.cwd_b, *self.states):
            d.mkdir(mode=0o700)
            d.chmod(0o700)

    def _start_patch(self):
        self._patch = mock.patch.object(admission, "_host_root",
                                        return_value=self.host)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def _reset_root(self):
        # Fresh canonical root => a clean ledger for the next subtest.
        for kid in self.kids:
            if kid.proc.is_alive():
                kid.proc.kill()
            kid.proc.join(JOIN_TIMEOUT)
            for connection in (kid.ready, kid.cmd, kid.result):
                connection.close()
            kid.proc.close()
        self.kids.clear()
        self._patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)
        self._new_root()
        self._start_patch()

    def _call_dir(self, state, tag):
        d = state / ("call-%s" % tag)   # call_dir: outside native and host
        d.mkdir(mode=0o700)
        d.chmod(0o700)
        return str(d)

    # -- process helpers -------------------------------------------------

    def _spawn_holder(self, *, state, cwd, route, model, call_tag,
                      setup=False):
        ready_r, ready_w = self.ctx.Pipe(duplex=False)
        cmd_r, cmd_w = self.ctx.Pipe(duplex=False)
        result_r, result_w = self.ctx.Pipe(duplex=False)
        proc = self.ctx.Process(
            target=_held_child,
            args=(str(self.host), str(state), str(cwd),
                  self._call_dir(state, call_tag), route, model, setup,
                  ready_w, cmd_r, result_w))
        proc.start()
        ready_w.close(); cmd_r.close(); result_w.close()
        kid = _Kid(proc, ready_r, cmd_w, result_r)
        self.kids.append(kid)
        return kid

    def _run_quick_child(self, *, state, cwd, route, model, tag,
                         setup=False):
        """Run one complete call in a fresh spawned process (restart sim)."""
        result_r, result_w = self.ctx.Pipe(duplex=False)
        proc = self.ctx.Process(
            target=_quick_child,
            args=(str(self.host), str(state), str(cwd),
                  self._call_dir(state, tag), route, model, setup, result_w))
        proc.start()
        result_w.close()
        try:
            self.assertTrue(result_r.poll(RESULT_TIMEOUT),
                            "quick child produced no result")
            kind, payload = result_r.recv()
        finally:
            proc.join(JOIN_TIMEOUT)
            if proc.is_alive():
                proc.kill()
                proc.join(JOIN_TIMEOUT)
            result_r.close()
        self.assertEqual(kind, "ok", payload)
        self.assertEqual(proc.exitcode, 0)
        proc.close()
        return payload

    def _kid_error(self, kid):
        if kid.result.poll(1.0):
            try:
                kind, payload = kid.result.recv()
            except EOFError:
                kind, payload = "eof", ""
            if kind == "error":
                return payload
        return "child exitcode=%r, no result" % kid.proc.exitcode

    def _wait_ready(self, kid):
        if kid.ready.poll(READY_TIMEOUT):
            try:
                self.assertEqual(kid.ready.recv(), "ready")
                return
            except EOFError:
                pass
        if kid.proc.is_alive():
            kid.proc.kill()
        kid.proc.join(JOIN_TIMEOUT)
        self.fail(self._kid_error(kid))

    def _finish(self, kid):
        kid.cmd.send("finish")
        self.assertTrue(kid.result.poll(RESULT_TIMEOUT),
                        "child did not finish")
        kind, payload = kid.result.recv()
        kid.proc.join(JOIN_TIMEOUT)
        self.assertFalse(kid.proc.is_alive())
        self.assertEqual((kind, kid.proc.exitcode), ("ok", 0), payload)
        self.kids.remove(kid)
        for connection in (kid.ready, kid.cmd, kid.result):
            connection.close()
        kid.proc.close()
        return payload

    # -- same-process helpers --------------------------------------------

    def _status(self):
        st = admission.capacity_status()
        self.assertTrue(st["initialized"])
        self.assertEqual(st["limit"], LIMIT)
        return st

    def _executing(self, route):
        return self._status()["routes"][route]["executing"]

    def _quick_call(self, route, model, state, cwd, tag, setup=False):
        launched = mock.Mock()

        def invoke(*, before_launch, on_stopped):
            before_launch()
            on_stopped(True)
            return "done"

        with admission.gate(str(cwd), state_dir=str(state), setup=setup,
                            binding={"route": route, "model": model}):
            ret = admission.model_call(route, model, "prompt",
                                       self._call_dir(state, tag), invoke,
                                       before_launch=launched)
        launched.assert_called_once()
        return ret

    # -- tests ------------------------------------------------------------

    def test_capacity_shared_across_processes(self):
        kids = [
            self._spawn_holder(state=self.states[i % 3], cwd=self.cwds[i % 2],
                               route="claude", model="m-%d" % (i % 2),
                               call_tag=i)
            for i in range(LIMIT)
        ]
        for kid in kids:
            self._wait_ready(kid)
        self.assertEqual(self._executing("claude"), LIMIT)

        # A 13th claude call from a new state/model/cwd hits the shared cap
        # before invoke is ever called.
        extra = self.tmp / "state-extra"
        extra.mkdir(mode=0o700); extra.chmod(0o700)
        invoke = mock.Mock()
        with self.assertRaises(admission.TaskError) as cm:
            with admission.gate(str(self.cwd_b), state_dir=str(extra),
                                binding={"route": "claude", "model": "m-x"}):
                admission.model_call("claude", "m-x", "p",
                                     self._call_dir(extra, "x"), invoke)
        self.assertIn("capacity_full", _reason(cm.exception))
        invoke.assert_not_called()
        self.assertEqual(self._executing("claude"), LIMIT)

        # devin has an independent adapter budget.
        self.assertEqual(self._quick_call("devin", "d-1", extra,
                                          self.cwd_b, "dev"), "done")
        self.assertEqual(self._executing("devin"), 0)
        self.assertEqual(self._executing("claude"), LIMIT)

        # Completing one holder frees exactly one slot for a new call.
        self._finish(kids[0])
        self.assertEqual(self._executing("claude"), LIMIT - 1)
        self.assertEqual(self._quick_call("claude", "m-9", extra,
                                          self.cwd_a, "r"), "done")
        self.assertEqual(self._executing("claude"), LIMIT - 1)

        for kid in kids[1:]:
            self._finish(kid)
        self.assertEqual(self._executing("claude"), 0)
        self.assertEqual(self._executing("devin"), 0)

    def test_sigkilled_holder_keeps_lease(self):
        for setup in (False, True):
            with self.subTest(setup=setup):
                self._reset_root()
                kid = self._spawn_holder(state=self.states[0],
                                         cwd=self.cwd_a, route="claude",
                                         model="m-h", call_tag="h",
                                         setup=setup)
                self._wait_ready(kid)
                kid.proc.kill()
                kid.proc.join(JOIN_TIMEOUT)
                self.assertFalse(kid.proc.is_alive())
                self.assertEqual(kid.proc.exitcode, -signal.SIGKILL)

                # Killing the process releases its flock, but the ledger
                # entry stays held: no proof of on_stopped was recorded.
                self.assertEqual(self._executing("claude"), 1)

                if not setup:
                    # A held normal lease does not block an ordinary gate
                    # on the same cwd; a fresh process still gets in.
                    self.assertEqual(
                        self._run_quick_child(state=self.states[1],
                                              cwd=self.cwd_a,
                                              route="claude",
                                              model="m-n", tag="n"),
                        "done")
                    # ...but any held task blocks an exclusive setup gate.
                    with self.assertRaises(admission.TaskError) as cm:
                        with admission.gate(
                                str(self.cwd_a),
                                state_dir=str(self.states[1]), setup=True,
                                binding={"route": "claude",
                                         "model": "m-s"}):
                            pass
                    self.assertIn("route_busy", _reason(cm.exception))
                else:
                    # A held setup lease blocks an ordinary gate on the
                    # same cwd.
                    with self.assertRaises(admission.TaskError) as cm:
                        with admission.gate(
                                str(self.cwd_a),
                                state_dir=str(self.states[1]),
                                binding={"route": "claude",
                                         "model": "m-n"}):
                            pass
                    self.assertIn("route_busy", _reason(cm.exception))
                    # A different cwd is unaffected.
                    self.assertEqual(
                        self._run_quick_child(state=self.states[1],
                                              cwd=self.cwd_b,
                                              route="claude",
                                              model="m-n", tag="n"),
                        "done")

                self.assertEqual(self._executing("claude"), 1)


if __name__ == "__main__":
    unittest.main()
