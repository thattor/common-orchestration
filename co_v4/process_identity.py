"""Darwin arm64 kernel process identity reader (#190 M3).

Reads identity for an OWNED provider process only — the launch-record
attestation path — never an arbitrary process inventory. proc_pidinfo
BSD info (pid/uid/birth) is compared BEFORE proc_pidpath and the
KERN_PROCARGS2 read, so a mismatched or dead PID is refused without
ever touching argv. A second BSD read after the argv read proves birth
consistency across the window: a PID-reuse race is 'mismatch', never a
silently accepted record. The KERN_PROCARGS2 environment tail is never
decoded, returned or logged.

Backend is injectable for negative tests only; the real backend is a
narrow ctypes binding over libSystem libproc/sysctl using the exact
proc_bsdinfo ABI (136 bytes, MAXCOMLEN=16).
"""
import ctypes
from dataclasses import dataclass
import os
import platform

CTL_KERN = 1
KERN_PROCARGS2 = 49
PROC_PIDTBSDINFO = 3
MAXCOMLEN = 16
BSDINFO_SIZE = 136
PATH_SIZE = 4096
MAX_ARGS_BYTES = 1024 * 1024
MAX_ARGC = 4096
MAX_USEC = 1_000_000
_LIBSYSTEM = '/usr/lib/libSystem.B.dylib'

REASONS = frozenset({
    'platform', 'invalid_pid', 'invalid_uid', 'invalid_start',
    'bool', 'nonfinite', 'dead', 'mismatch', 'short', 'truncated',
    'unterminated', 'invalid_args', 'invalid_text'})


class ProcessIdentityRejected(Exception):
    """Fixed-reason refusal; never carries argv, env or exception text."""
    def __init__(self, reason):
        if reason not in REASONS:
            raise ValueError('closed identity rejection reason required')
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ProcessIdentity:
    """Kernel-attested identity for one owned PID."""
    pid: int
    uid: int
    start_sec: int
    start_usec: int
    executable: str                      # canonical absolute proc_pidpath
    argv: tuple


class _Fail(Exception):
    """Internal kernel-read failure carrying one closed reason."""
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class _ProcBsdInfo(ctypes.Structure):
    """Exact Darwin arm64 proc_bsdinfo ABI (sys/proc_info.h)."""
    _fields_ = [
        ('pbi_flags', ctypes.c_uint32), ('pbi_status', ctypes.c_uint32),
        ('pbi_xstatus', ctypes.c_uint32), ('pbi_pid', ctypes.c_uint32),
        ('pbi_ppid', ctypes.c_uint32), ('pbi_uid', ctypes.c_uint32),
        ('pbi_gid', ctypes.c_uint32), ('pbi_ruid', ctypes.c_uint32),
        ('pbi_rgid', ctypes.c_uint32), ('pbi_svuid', ctypes.c_uint32),
        ('pbi_svgid', ctypes.c_uint32), ('rfu_1', ctypes.c_uint32),
        ('pbi_comm', ctypes.c_char * MAXCOMLEN),
        ('pbi_name', ctypes.c_char * (2 * MAXCOMLEN)),
        ('pbi_nfiles', ctypes.c_uint32), ('pbi_pgid', ctypes.c_uint32),
        ('pbi_pjobc', ctypes.c_uint32), ('e_tdev', ctypes.c_uint32),
        ('e_tpgid', ctypes.c_uint32), ('pbi_nice', ctypes.c_int32),
        ('pbi_start_tvsec', ctypes.c_uint64),
        ('pbi_start_tvusec', ctypes.c_uint64)]


class _LibprocBackend:
    """Real Darwin backend; only constructible on the supported platform."""
    def __init__(self):
        if (platform.system() != 'Darwin'
                or platform.machine() != 'arm64'
                or ctypes.sizeof(_ProcBsdInfo) != BSDINFO_SIZE):
            raise ProcessIdentityRejected('platform')
        lib = ctypes.CDLL(_LIBSYSTEM, use_errno=True)
        lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int,
            ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        lib.proc_pidinfo.restype = ctypes.c_int
        lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                     ctypes.c_uint32]
        lib.proc_pidpath.restype = ctypes.c_int
        lib.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int),
            ctypes.c_uint, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p,
            ctypes.c_size_t]
        lib.sysctl.restype = ctypes.c_int
        self._lib = lib

    def bsd_info(self, pid):
        buf = _ProcBsdInfo()
        ret = self._lib.proc_pidinfo(
            pid, PROC_PIDTBSDINFO, 0, ctypes.byref(buf), BSDINFO_SIZE)
        if ret <= 0:
            raise _Fail('dead')
        if ret != BSDINFO_SIZE:
            raise _Fail('short')
        return (buf.pbi_pid, buf.pbi_uid,
                buf.pbi_start_tvsec, buf.pbi_start_tvusec)

    def pid_path(self, pid):
        buf = ctypes.create_string_buffer(PATH_SIZE)
        ret = self._lib.proc_pidpath(pid, buf, PATH_SIZE)
        if ret <= 0:
            raise _Fail('dead')
        if ret >= PATH_SIZE:
            raise _Fail('truncated')
        end = buf.raw.find(b'\0')
        if end < 0:
            raise _Fail('unterminated')
        if end == 0:
            raise _Fail('short')
        return buf.raw[:end]

    def proc_args(self, pid):
        mib = (ctypes.c_int * 3)(CTL_KERN, KERN_PROCARGS2, pid)
        size = ctypes.c_size_t(0)
        if self._lib.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            raise _Fail('dead')
        if size.value == 0:
            raise _Fail('short')
        if size.value > MAX_ARGS_BYTES:
            raise _Fail('truncated')
        capacity = size.value
        buf = ctypes.create_string_buffer(capacity)
        got = ctypes.c_size_t(capacity)
        if self._lib.sysctl(mib, 3, buf, ctypes.byref(got), None, 0) != 0:
            raise _Fail('dead')
        if got.value < 4:
            raise _Fail('short')
        if got.value > capacity:
            raise _Fail('truncated')   # kernel grew past the allocation
        return buf.raw[:got.value]


_kernel = None


def _backend():
    global _kernel
    if _kernel is None:
        _kernel = _LibprocBackend()
    return _kernel


def _cstr(blob, pos):
    end = blob.find(b'\0', pos)
    if end < 0:
        raise _Fail('unterminated')
    return blob[pos:end], end + 1


def _decode_text(raw):
    try:
        return raw.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        raise _Fail('invalid_text') from None


def _decode_args(blob):
    """argc + exec path + argv only; the environment tail is never read."""
    if type(blob) is not bytes:
        raise _Fail('invalid_args')
    if len(blob) < 4:
        raise _Fail('short')
    if len(blob) > MAX_ARGS_BYTES:
        raise _Fail('truncated')
    argc = int.from_bytes(blob[:4], 'little', signed=True)
    if not 1 <= argc <= MAX_ARGC:
        raise _Fail('invalid_args')
    _exec, pos = _cstr(blob, 4)            # kernel exec path: skipped
    while pos < len(blob) and blob[pos] == 0:
        pos += 1                           # NUL padding before argv[0]
    argv = []
    for _ in range(argc):
        raw, pos = _cstr(blob, pos)
        argv.append(_decode_text(raw))
    return tuple(argv)


def _int_field(value, bad):
    if type(value) is bool:
        raise ProcessIdentityRejected('bool')
    if type(value) is float:
        raise ProcessIdentityRejected('nonfinite')
    if type(value) is not int:
        raise ProcessIdentityRejected(bad)


def _checked_bsd(backend, pid, expected_uid):
    """One BSD read; wrong-typed backend data is 'mismatch', never trust."""
    try:
        info = backend.bsd_info(pid)
    except _Fail:
        raise
    except Exception:
        raise _Fail('mismatch') from None
    if (type(info) is not tuple or len(info) != 4
            or any(type(v) is not int or type(v) is bool for v in info)):
        raise _Fail('mismatch')
    pid_, uid_, sec, usec = info
    if (pid_ != pid or uid_ != expected_uid or sec < 0
            or not 0 <= usec < MAX_USEC):
        raise _Fail('mismatch')
    return info


def read_owned_process(pid, expected_uid, expected_start=None, *,
                       backend=None):
    """Kernel identity for one owned PID; raises ProcessIdentityRejected.

    expected_start=None is permitted ONLY for the owner's first birth
    acquisition of its own freshly launched child; every other caller
    must pass the recorded (sec, usec) tuple. BSD pid/uid/birth is
    verified before path and argv are read, and re-verified after, so a
    PID-reuse race is refused as 'mismatch'.
    """
    _int_field(pid, 'invalid_pid')
    if not 1 <= pid <= 0x7FFFFFFF:          # ctypes c_int domain
        raise ProcessIdentityRejected('invalid_pid')
    _int_field(expected_uid, 'invalid_uid')
    if expected_uid != os.getuid():
        raise ProcessIdentityRejected('invalid_uid')
    if expected_start is not None:
        if type(expected_start) is not tuple or len(expected_start) != 2:
            raise ProcessIdentityRejected('invalid_start')
        for value in expected_start:
            _int_field(value, 'invalid_start')
        sec, usec = expected_start
        if sec < 0 or not 0 <= usec < MAX_USEC:
            raise ProcessIdentityRejected('invalid_start')
        expected_start = tuple(expected_start)
    backend = _backend() if backend is None else backend
    try:
        info = _checked_bsd(backend, pid, expected_uid)
        if expected_start is not None and info[2:] != expected_start:
            raise _Fail('mismatch')
        try:
            raw = backend.pid_path(pid)
        except _Fail:
            raise
        except Exception:
            raise _Fail('dead') from None
        if type(raw) is not bytes:
            raise _Fail('invalid_text')
        executable = _decode_text(raw)
        if not executable.startswith('/'):
            raise _Fail('invalid_text')
        executable = os.path.realpath(executable)
        try:
            blob = backend.proc_args(pid)
        except _Fail:
            raise
        except Exception:
            raise _Fail('dead') from None
        argv = _decode_args(blob)
        # PID-reuse race window: birth must be identical on both sides.
        if _checked_bsd(backend, pid, expected_uid) != info:
            raise _Fail('mismatch')
    except _Fail as exc:
        raise ProcessIdentityRejected(exc.reason) from None
    return ProcessIdentity(pid, info[1], info[2], info[3],
                           executable, argv)
