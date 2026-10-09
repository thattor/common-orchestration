"""Owned stdio NDJSON transport for a future Codex text session (macOS).

The spawned CLI is our own session/group leader: liveness and teardown go
through the co_v4.task waitid/killpg helpers, never Popen.poll/terminate,
so the leader stays owned and unreaped until the trusted group-stop path.
Bounded NDJSON framing is inherited from StdioTransport. Engine, session,
model-turn, HTTP and task-selection logic live elsewhere; this module
reserves no admission ledger. stderr is discarded, never captured.

on_stopped(flag) reports ONLY the owned physical group-cessation proof:
flag is self.stopped from the trusted _stop_group bound to our actual
proc (leader reaped AND group absent), or True for the one proven
spawn-no-child case: Popen raised OSError. Every other Popen exception
is ambiguous after fork/return-path failure, reports False once, and
propagates; False means "not proven gone", not "alive". The callback
never reports normal-output/EOF success: the session engine decides
normality separately from natural_exit == 0, validated_eof, drain_clean,
not cleanup_terminated, stopped and its own independent observer.

Only the bounded cleanup snapshots the cleanup-time thread signal
mask, blocks SIGINT/SIGTERM/SIGHUP on the main thread for the section,
and restores that snapshot afterwards; no global handlers change and
masking does not span normal model/session inference. close() worst case is
max_drain_s of
graceful drain plus _stop_group's bounded ~10s (5s leader reap + 5s
group absence): about 15s total, not 5s.
"""

from __future__ import annotations

import math
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

from co_v4.adapters.codex import NativeError, StdioTransport

SUPPORTED_TEXT_CLI = "codex-cli 0.160.1"
_WAIT_FLAGS = os.WEXITED | os.WNOHANG | os.WNOWAIT
_CLEANUP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class NoChild(NativeError):
    """A checked launch-capability failure raised before a session Popen.

    It is a negative fact: a required owned-child or pthread-mask surface
    is absent, so no owned session group was launched or claimed. It is
    not inferred from native output and carries no output or secrets.
    """


class OwnedTransport(StdioTransport):
    """StdioTransport whose child is an owned, unreaped group leader."""

    def __init__(self, executable: str, workspace: str, *,
                 config_overrides: tuple[str, ...] = (),
                 env: dict | None = None,
                 required_version: str | None = SUPPORTED_TEXT_CLI,
                 before_launch, on_stopped, max_drain_s: float = 5,
                 state_lock=None, cancel=None, register_transport=None):
        if not callable(before_launch) or not callable(on_stopped):
            raise NativeError("before_launch/on_stopped must be callable")
        if (register_transport is not None
                and not callable(register_transport)):
            raise NativeError("register_transport must be callable")
        if (isinstance(max_drain_s, bool)
                or not isinstance(max_drain_s, (int, float))
                or not 1 <= max_drain_s <= 5):
            raise NativeError("max_drain_s must be a number within 1..5")
        if required_version != SUPPORTED_TEXT_CLI:
            raise NativeError("unsupported profile CLI version")
        exe, work = Path(executable), Path(workspace)
        if not exe.is_absolute() or not work.is_absolute():
            raise NativeError("absolute executable/workspace required")
        executable, workspace = str(exe.resolve()), str(work.resolve())
        probe = subprocess.run([executable, "--version"], capture_output=True,
                               timeout=5, check=False)
        if probe.returncode or probe.stdout.strip() != SUPPORTED_TEXT_CLI.encode():
            raise NativeError("unsupported CLI version")
        self.native_version = probe.stdout.strip().decode("ascii")
        try:
            from co_v4.task import child_status, infer
        except ImportError as exc:
            raise NoChild("owned-child helpers unavailable") from exc
        try:
            supported = (callable(getattr(child_status, "supported", None))
                         and child_status.supported())
        except Exception as exc:
            raise NoChild("owned-child helpers unavailable") from exc
        if not (supported
                and callable(getattr(child_status, "waitid", None))
                and callable(getattr(infer, "_leader_running", None))
                and callable(getattr(infer, "_stop_group", None))
                and hasattr(os, "killpg")):
            raise NoChild("owned-child helpers unavailable")
        if threading.current_thread() is threading.main_thread():
            pthread_sigmask = getattr(signal, "pthread_sigmask", None)
            if not callable(pthread_sigmask):
                raise NoChild("pthread signal-mask surface unavailable")
            try:
                pthread_sigmask(signal.SIG_BLOCK, ())
            except Exception as exc:
                raise NoChild(
                    "pthread signal-mask surface unavailable") from exc
        self._child_status = child_status
        self._infer = infer
        self._max_drain_s = float(max_drain_s)
        self._on_stopped = on_stopped
        self._state_lock = (state_lock if state_lock is not None
                            else threading.RLock())
        self._cancel = cancel if cancel is not None else threading.Event()
        self._stop_state = None
        self._stop_result = False
        self._stop_done = threading.Event()
        self._callback_fired = False
        self._closed = False
        self.natural_exit: int | None = None
        self.validated_eof = False
        self.drain_clean = False
        self.cleanup_terminated = False
        self.stopped = False
        self._process = None
        self._incoming = bytearray()
        self._outgoing = bytearray()
        self._eof = False
        self._launch_state = "not_attempted"
        self._launch_hook_returned = False
        argv = [executable, "app-server", "--stdio"]
        for override in config_overrides:
            argv.extend(("-c", override))
        launch_error = None
        stopped_flag = None
        needs_cleanup = False
        with self._state_lock:
            def gate():
                return (self._closed or self._cancel.is_set()
                        or self._stop_state is not None)
            def done(state, flag):
                self._launch_state = state
                self._stop_result = self.stopped = flag
                self._stop_state = "done"
                self._stop_done.set()
            try:
                if gate():
                    raise NoChild("transport launch canceled")
                if register_transport is not None:
                    register_transport(self)
                if gate():
                    raise NoChild("transport launch canceled")
                before_launch()
                self._launch_hook_returned = True
                if gate():
                    stopped_flag = True
                    done("no_child", True)
                    raise NoChild("transport launch canceled")
                self._launch_state = "attempted"
                try:
                    self._process = subprocess.Popen(
                        argv, cwd=workspace, env=env,
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, bufsize=0,
                        start_new_session=True)
                except OSError:
                    stopped_flag = True
                    done("no_child", True)
                    raise
                except BaseException:
                    stopped_flag = False
                    done("unknown", False)
                    raise
                self._launch_state = "started"
                needs_cleanup = True
                for stream in (self._process.stdin, self._process.stdout):
                    os.set_blocking(stream.fileno(), False)
                if self._cancel.is_set():
                    raise NativeError("transport launch canceled")
                needs_cleanup = False
            except BaseException as exc:
                self._closed = True
                launch_error = exc
        if launch_error is not None:
            if needs_cleanup:
                try:
                    self._cleanup(prior_error=True)
                except BaseException as exc:
                    if (not isinstance(launch_error,
                                       (KeyboardInterrupt, SystemExit))
                            and isinstance(exc,
                                           (KeyboardInterrupt, SystemExit))):
                        raise exc
            elif stopped_flag is not None:
                try:
                    self._fire_stopped(stopped_flag)
                except (KeyboardInterrupt, SystemExit) as exc:
                    if not isinstance(launch_error,
                                      (KeyboardInterrupt, SystemExit)):
                        raise exc
                except BaseException:
                    pass
            raise launch_error

    def alive(self) -> bool:
        with self._state_lock:
            if (self._cancel.is_set()
                    or self._closed
                    or self._eof
                    or self._stop_state is not None
                    or self._launch_state != "started"):
                return False
            proc = self._process
            return proc is not None and bool(
                self._infer._leader_running(proc))

    def send(self, message: dict) -> None:
        with self._state_lock:
            proc = self._process
            stdin = getattr(proc, "stdin", None)
            if (self._cancel.is_set()
                    or self._closed
                    or self._stop_state is not None
                    or self._launch_state != "started"
                    or proc is None
                    or self._eof
                    or stdin is None
                    or getattr(stdin, "closed", True)):
                raise NativeError("transport unavailable")
            super().send(message)

    def _flush(self):
        with self._state_lock:
            if not self._outgoing:
                return
            if (self._cancel.is_set()
                    or self._stop_state is not None):
                return
            proc = self._process
            stdin = getattr(proc, "stdin", None)
            if (self._launch_state != "started"
                    or proc is None
                    or stdin is None
                    or getattr(stdin, "closed", True)):
                raise NativeError("transport unavailable")
            super()._flush()

    def poll(self) -> tuple[dict, ...]:
        with self._state_lock:
            proc = self._process
            stdout = getattr(proc, "stdout", None)
            if (self._launch_state != "started"
                    or proc is None
                    or stdout is None
                    or getattr(stdout, "closed", True)):
                raise NativeError("transport unavailable")
            return super().poll()

    def close(self) -> None:
        """Idempotent shutdown; on_stopped fires once with proof only.

        The callback bool is ONLY the physical group-cessation proof
        (self.stopped from the trusted _stop_group bound to our actual
        proc), never normal-output/EOF success, so a forced or dirty
        close still releases the stopped lease only when the group is
        proven gone. Drain exceptions are delivered after the bounded
        group stop, pipe close, callback, and mask restore.
        """
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            can_drain = (self._launch_state == "started"
                         and self._process is not None)
        prior_error = False
        try:
            if can_drain:
                self._drain()
        except BaseException:
            prior_error = True
            raise
        finally:
            self._cleanup(prior_error=prior_error)

    def _drain(self) -> None:
        """Bounded graceful drain; state flags stay independent of proof."""
        proc, status = self._process, self._child_status
        clean = True
        drain_exc = None
        deadline = time.monotonic() + self._max_drain_s
        try:
            while time.monotonic() < deadline:
                with self._state_lock:
                    if not self._outgoing:
                        break
                    if (self._cancel.is_set()
                            or self._stop_state is not None):
                        clean = False
                        break
                self._flush()
                if self._outgoing:
                    time.sleep(0.01)
        except (OSError, ValueError) as exc:
            clean = False
            drain_exc = exc
        try:
            proc.stdin.close()
        except (OSError, ValueError) as exc:
            clean = False
            if drain_exc is None:
                drain_exc = exc
        if not proc.stdin.closed:
            try:
                proc.stdin.close()
            except (OSError, ValueError) as exc:
                clean = False
                if drain_exc is None:
                    drain_exc = exc
        exited = False
        while time.monotonic() < deadline and not (self._eof and exited):
            try:
                self.poll()
            except NativeError:
                clean = False
                break
            try:
                with self._state_lock:
                    if self._stop_state is not None:
                        clean = False
                        break
                    info = status.waitid(
                        os.P_PID, proc.pid, _WAIT_FLAGS)
            except (ChildProcessError, OSError):
                break
            if info is None:
                time.sleep(0.01)
            else:
                exited = True
                if (self.natural_exit is None
                        and getattr(info, "si_code", None) == os.CLD_EXITED):
                    self.natural_exit = getattr(info, "si_status", None)
        self.validated_eof = bool(
            self._eof and not self._incoming and not self._outgoing)
        self.drain_clean = bool(clean and not self._outgoing)
        with self._state_lock:
            self.cleanup_terminated = bool(
                self._stop_state is None
                and self._infer._leader_running(proc))
        if drain_exc is not None:
            raise drain_exc

    def stop_group_only(self, *, lock_timeout_s: float = 1.0,
                        wait_timeout_s: float = 11.0) -> bool:
        for value, bound, name in ((lock_timeout_s, 1.0, "lock_timeout_s"),
                                   (wait_timeout_s, 11.0, "wait_timeout_s")):
            if (isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not math.isfinite(value) or not 0 < value <= bound):
                raise NativeError(
                    f"{name} must be a finite number within (0, {bound}]")
        self._cancel.set()
        deadline = time.monotonic() + float(lock_timeout_s)
        result = False
        original = None
        try:
            result = self._physical_stop_once(
                lock_timeout_s=float(lock_timeout_s),
                wait_timeout_s=float(wait_timeout_s))
        except BaseException as exc:
            original = exc
        cb_exc = None
        fired = None
        if self._stop_done.is_set():
            try:
                fired = self._fire_stopped(
                    bool(self._stop_result), deadline)
            except BaseException as exc:
                cb_exc = exc
        if original is not None:
            if (not isinstance(original,
                               (KeyboardInterrupt, SystemExit))
                    and isinstance(cb_exc,
                                   (KeyboardInterrupt, SystemExit))):
                raise cb_exc
            raise original
        if cb_exc is not None:
            raise cb_exc
        if fired is False:
            return False
        return result

    def _physical_stop_once(self, *, lock_timeout_s=None,
                          wait_timeout_s=11.0) -> bool:
        if lock_timeout_s is None:
            self._state_lock.acquire()
            acquired = True
        else:
            acquired = self._state_lock.acquire(timeout=lock_timeout_s)
        if not acquired:
            return False
        launch_state = None
        proc = None
        try:
            owner = self._stop_state is None
            if owner:
                self._stop_state = "stopping"
                launch_state = self._launch_state
                proc = self._process
                if launch_state == "not_attempted":
                    self._closed = True
        finally:
            self._state_lock.release()
        if not owner:
            if not self._stop_done.wait(wait_timeout_s):
                if self._stop_state != "done":
                    return False
                self._stop_done.set()
            return bool(self._stop_result)
        result = launch_state in ("not_attempted", "no_child")
        interrupt = None
        try:
            if launch_state == "started" and proc is not None:
                result = bool(self._infer._stop_group(proc))
        except (KeyboardInterrupt, SystemExit) as exc:
            interrupt = exc
        except Exception:
            pass
        finally:
            self._stop_result = result
            self.stopped = result
            self._stop_state = "done"
            self._stop_done.set()
        if interrupt is not None:
            raise interrupt
        return result

    def _fire_stopped(self, flag: bool, deadline=None) -> bool:
        if deadline is None:
            acquired = self._state_lock.acquire()
        else:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                acquired = self._state_lock.acquire(timeout=remaining)
            else:
                acquired = self._state_lock.acquire(blocking=False)
        if not acquired:
            return False
        try:
            if (self._callback_fired
                    or not self._launch_hook_returned):
                return True
            self._callback_fired = True
        finally:
            self._state_lock.release()
        self._on_stopped(flag)
        return True

    def _cleanup(self, *, prior_error: bool) -> None:
        """Trusted bounded stop, pipe close, callback, and mask restore.

        Ordinary stop failures only make the proof false; pipe failures
        only mark the drain dirty. An earlier drain or constructor
        exception wins over ordinary cleanup and callback failures;
        deferred mask failures and user interrupts still propagate
        after every cleanup step and mask restore.
        """
        deferred = None
        cleanup_mask = None
        mask_captured = False
        if threading.current_thread() is threading.main_thread():
            try:
                cleanup_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
                mask_captured = True
                signal.pthread_sigmask(signal.SIG_BLOCK, _CLEANUP_SIGNALS)
            except BaseException as exc:
                deferred = exc
        cleanup_exc = cb_exc = None

        def remember_base(exc):
            nonlocal deferred, cleanup_exc
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                if deferred is None:
                    deferred = exc
            elif cleanup_exc is None:
                cleanup_exc = exc

        try:
            try:
                self._physical_stop_once()
            except Exception:
                pass
            except BaseException as exc:
                remember_base(exc)
            for stream in (getattr(self._process, "stdin", None),
                           getattr(self._process, "stdout", None)):
                for _attempt in range(2):
                    try:
                        if stream is not None and not stream.closed:
                            stream.close()
                        break
                    except BaseException as exc:
                        self.drain_clean = False
                        remember_base(exc)
            try:
                if self._stop_done.is_set():
                    self._fire_stopped(bool(self._stop_result))
            except (KeyboardInterrupt, SystemExit) as exc:
                if deferred is None:
                    deferred = exc
            except BaseException as exc:
                if cb_exc is None:
                    cb_exc = exc
        finally:
            if mask_captured:
                try:
                    signal.pthread_sigmask(
                        signal.SIG_SETMASK, cleanup_mask)
                except BaseException as exc:
                    if deferred is None:
                        deferred = exc
        if deferred is not None:
            raise deferred
        if prior_error:
            return
        if cleanup_exc is not None:
            raise cleanup_exc
        if cb_exc is not None:
            raise cb_exc
