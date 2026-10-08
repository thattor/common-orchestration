"""waitid(2) compatibility shim for co.task process cleanup.

macOS Python 3.11/3.12 ship the waitid constants but not os.waitid
(it only appears on Darwin in 3.13). This module uses os.waitid when
callable and otherwise falls back to libSystem waitid via ctypes on
Darwin arm64, whose siginfo_t ABI was measured against the public SDK
(LP64: sizeof 104, si_pid@12, si_status@20). The platform, pointer
size, layout, and symbol are all checked before the backend is
accepted; any failure resolves to supported() == False so the
_spawn preflight fails closed before Popen instead of crashing at
import. Neither backend is ever asked to reap: callers always pass
WEXITED|WNOHANG|WNOWAIT.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import sys
from collections import namedtuple

waitid_result = namedtuple(
    "waitid_result",
    ["si_pid", "si_uid", "si_signo", "si_status", "si_code"])

# Darwin waitid constants; the same values are also exposed via os.
_P_PID = 1
_WNOHANG = 0x01
_WEXITED = 0x04
_WNOWAIT = 0x20
_OPTIONS = _WNOHANG | _WEXITED | _WNOWAIT
_LIBSYSTEM = "/usr/lib/libSystem.B.dylib"


class _SigInfo(ctypes.Structure):
    """Darwin LP64 siginfo_t: int x6, void* addr, sigval, long, pad[7]."""

    _fields_ = [
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("si_pid", ctypes.c_int),
        ("si_uid", ctypes.c_uint),
        ("si_status", ctypes.c_int),
        ("si_addr", ctypes.c_void_p),
        ("si_value", ctypes.c_void_p),
        ("si_band", ctypes.c_long),
        ("si_pad", ctypes.c_ulong * 7),
    ]


_native_waitid = getattr(os, "waitid", None)
if not callable(_native_waitid):
    _native_waitid = None

_libc_waitid = None
_backend_done = False


def _layout_ok():
    S = _SigInfo
    return (ctypes.sizeof(S) == 104
            and S.si_pid.offset == 12
            and S.si_status.offset == 20
            and S.si_addr.offset == 24
            and S.si_value.offset == 32
            and S.si_band.offset == 40
            and S.si_pad.offset == 48)


def _ctypes_backend():
    """Return the cached libSystem waitid, or None when unusable."""
    global _libc_waitid, _backend_done
    if _backend_done:
        return _libc_waitid
    _backend_done = True
    try:
        if (sys.platform != "darwin"
                or platform.machine() != "arm64"
                or ctypes.sizeof(ctypes.c_void_p) != 8
                or not _layout_ok()):
            return None
        fn = ctypes.CDLL(_LIBSYSTEM, use_errno=True).waitid
    except (OSError, AttributeError):
        return None
    fn.restype = ctypes.c_int
    fn.argtypes = [ctypes.c_int, ctypes.c_uint32,
                   ctypes.POINTER(_SigInfo), ctypes.c_int]
    _libc_waitid = fn
    return fn


def _check_args(idtype, pid, options):
    if (isinstance(pid, bool) or not isinstance(pid, int)
            or not 0 < pid < 2 ** 31):
        raise ValueError("pid out of range: %r" % (pid,))
    if idtype != _P_PID:
        raise ValueError("only P_PID is supported: %r" % (idtype,))
    if options != _OPTIONS:
        raise ValueError("options must be WEXITED|WNOHANG|WNOWAIT: %r"
                         % (options,))


def _ctypes_waitid(idtype, pid, options):
    """Direct ctypes backend, exposed so tests force it even on 3.13.

    Raises ValueError before any native call on out-of-contract input.
    A missing backend or a failed call raises OSError (ECHILD maps to
    ChildProcessError via OSError); EINTR retries in a Python loop so
    pending signal handlers run and a raising handler propagates.
    Returns None when si_pid is 0 (no state change); any other si_pid
    different from the requested pid raises OSError.
    """
    _check_args(idtype, pid, options)
    fn = _ctypes_backend()
    if fn is None:
        raise OSError(errno.ENOSYS, os.strerror(errno.ENOSYS))
    while True:
        info = _SigInfo()
        if fn(idtype, pid, ctypes.byref(info), options) == 0:
            break
        err = ctypes.get_errno()
        if err != errno.EINTR:
            raise OSError(err, os.strerror(err))
    if info.si_pid == 0:
        return None
    if info.si_pid != pid:
        raise OSError(errno.EIO,
                      "waitid reported si_pid %d for pid %d"
                      % (info.si_pid, pid))
    return waitid_result(info.si_pid, info.si_uid, info.si_signo,
                         info.si_status, info.si_code)


def waitid(idtype, pid, options):
    """os.waitid-compatible entry point for infer.py's non-reaping
    checks; call as child_status.waitid so tests can mock this site."""
    _check_args(idtype, pid, options)
    if _native_waitid is not None:
        return _native_waitid(idtype, pid, options)
    return _ctypes_waitid(idtype, pid, options)


def supported():
    """True iff some waitid backend is usable; never raises."""
    if _native_waitid is not None:
        return True
    try:
        return _ctypes_backend() is not None
    except Exception:
        return False
