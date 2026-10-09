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

Only the bounded cleanup section masks SIGINT/SIGTERM/SIGHUP, only on
the main thread, after pthread_sigmask support and the original mask
were established before the caller's launch claim. The original mask is
always restored; no global handlers change and masking does not span
normal model/session inference. close() worst case is max_drain_s of
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
                 state_lock=None, cancel=None):
        if not callable(before_launch) or not callable(on_stopped):
            raise NativeError("before_launch/on_stopped must be callable")
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
        argv = [executable, "app-server", "--stdio"]
        for override in config_overrides:
            argv.extend(("-c", override))
        before_launch()
        try:
            self._process = subprocess.Popen(
                argv, cwd=workspace, env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, bufsize=0,
                start_new_session=True)
        except OSError:
            self._closed = True
            self.stopped = True
            callback_exc = None
            try:
                self._on_stopped(True)
            except (KeyboardInterrupt, SystemExit) as exc:
                callback_exc = exc
            except BaseException:
                pass
            if callback_exc is not None:
                raise callback_exc
            raise
        except BaseException:
            self._closed = True
            self.stopped = False
            callback_exc = None
            try:
                self._on_stopped(False)
            except (KeyboardInterrupt, SystemExit) as exc:
                callback_exc = exc
            except BaseException:
                pass
            if callback_exc is not None:
                raise callback_exc
            raise
        self._incoming = bytearray()
        self._outgoing = bytearray()
        self._eof = False
        try:
            for stream in (self._process.stdin, self._process.stdout):
                os.set_blocking(stream.fileno(), False)
        except BaseException:
            self._closed = True
            self._cleanup(prior_error=True)
            raise

    def alive(self) -> bool:
        if self._eof:
            return False
        with self._state_lock:
            if self._stop_state is not None:
                return False
            return bool(self._infer._leader_running(self._process))

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
        prior_error = False
        try:
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
            while self._outgoing and time.monotonic() < deadline:
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
        result = self._physical_stop_once(
            lock_timeout_s=float(lock_timeout_s),
            wait_timeout_s=float(wait_timeout_s))
        if self._stop_done.is_set():
            with self._state_lock:
                proof = bool(self._stop_result)
            self._fire_stopped(proof)
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
        try:
            owner = self._stop_state is None
            if owner:
                self._stop_state = "stopping"
        finally:
            self._state_lock.release()
        if not owner:
            if not self._stop_done.wait(wait_timeout_s):
                return False
            with self._state_lock:
                self.stopped = bool(self._stop_result)
            return self.stopped
        result = False
        try:
            result = bool(self._infer._stop_group(self._process))
        except Exception:
            result = False
        finally:
            with self._state_lock:
                self._stop_result = result
                self._stop_state = "done"
                self.stopped = result
            self._stop_done.set()
        return result

    def _fire_stopped(self, flag: bool) -> None:
        with self._state_lock:
            if self._callback_fired:
                return
            self._callback_fired = True
        self._on_stopped(flag)

    def _cleanup(self, *, prior_error: bool) -> None:
        """Trusted bounded stop, pipe close, callback, and mask restore.

        Ordinary stop/pipe failures only make the proof false. An earlier
        drain or constructor exception wins over ordinary cleanup and
        callback failures; deferred mask failures and user interrupts
        still propagate after every cleanup step and mask restore.
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
                self.stopped = bool(self._physical_stop_once())
            except Exception:
                self.stopped = False
            except BaseException as exc:
                self.stopped = False
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
                    with self._state_lock:
                        proof = bool(self._stop_result)
                    self._fire_stopped(proof)
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
