"""Owned external provider launcher (#190 M3).

Explicit host-owned launcher for the qualified provider — NOT the
service's automatic startup. One spawn boundary: env={} exactly,
shell=False, owned stdio; never None, never os.environ, never an added
variable. That empty environment is a code contract proven by launcher
tests — it cannot be observed at runtime and is never claimed in the
launch record. Fresh credential files are CSPRNG ASCII written 0600;
existing credentials are never read, extracted, migrated or printed,
and no token crosses this API (paths and refs only). The launch record
is written only after argv allowlist, descriptor identities, owned
bounded readiness and the kernel-bound record builder all succeed; an
existing target is refused, never overwritten. Failure cleanup touches
only the original unreaped Popen handle.
"""
import os
import secrets
import stat
import string
import subprocess
from dataclasses import dataclass
from uuid import uuid4

from .launch_attestation import (build_launch_record, file_descriptor,
                                 validate_launch_argv)
from .process_identity import read_owned_process

MIN_KEY_CHARS = 32
MAX_KEY_BYTES = 512
TERM_SECONDS = 5.0
KILL_SECONDS = 5.0
_KEY_ALPHABET = string.ascii_letters + string.digits + '_-'

CODES = frozenset({
    'argv_invalid', 'descriptor_invalid', 'credential_refused',
    'target_refused', 'spawn_failed', 'ready_failed',
    'record_failed', 'cleanup_failed'})


class LauncherRejected(Exception):
    """Fixed-code refusal; never raw exception text, argv or key bytes."""
    def __init__(self, code):
        if code not in CODES:
            raise ValueError('closed launcher rejection code required')
        self.code = code
        self.child = None            # owned handle retained if unconfirmed
        super().__init__(code)


@dataclass(frozen=True)
class LaunchResult:
    """Output contract: the fresh owned process and its record path."""
    process: object
    record_path: str


_popen = subprocess.Popen        # test-only seam; production never varies


def spawn_owned(argv, *, stdin, stdout, stderr):
    """The single public spawn boundary, shared by provider and helpers.

    env={} and shell=False are constants — the signature exposes no
    environment argument. No trampoline or wrapper is admitted.
    """
    return _popen(list(argv), env={}, shell=False,
                  stdin=stdin, stdout=stdout, stderr=stderr)


def _target_dir(path):
    """Absolute canonical owned 0700 dir + nonexistent target, or refuse."""
    if (type(path) is not str or not os.path.isabs(path)
            or '\0' in path):
        raise LauncherRejected('target_refused')
    directory, name = os.path.split(path)
    try:
        st = os.lstat(directory)
    except (OSError, ValueError):
        raise LauncherRejected('target_refused') from None
    try:
        canonical = os.path.realpath(directory)
        exists = os.path.lexists(path)
    except (OSError, ValueError):
        raise LauncherRejected('target_refused') from None
    if (not name or not stat.S_ISDIR(st.st_mode)
            or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) != 0o700
            or canonical != directory or exists):
        raise LauncherRejected('target_refused')
    return directory


def _fsync_dir(directory):
    fd = os.open(directory,
                 os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0)
                 | getattr(os, 'O_CLOEXEC', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_owned_file(path, blob):
    """Atomic 0600 single-link publish; never overwrites another file."""
    directory = _target_dir(path)
    if type(blob) is not bytes or not blob:
        raise LauncherRejected('target_refused')
    tmp = os.path.join(directory, '.tmp-' + uuid4().hex)
    fd = -1
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), 0o600)
        with os.fdopen(fd, 'wb') as handle:
            fd = -1
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
        st = os.lstat(tmp)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
                or st.st_nlink != 1
                or stat.S_IMODE(st.st_mode) != 0o600):
            raise LauncherRejected('target_refused')
        try:
            os.link(tmp, path)      # atomic; EEXIST refuses, never replaces
        except OSError:
            raise LauncherRejected('target_refused') from None
        _fsync_dir(directory)
    except LauncherRejected:
        raise
    except (OSError, ValueError):
        raise LauncherRejected('target_refused') from None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass


def provision_credential(path, *, length=64):
    """Fresh CSPRNG key file: 32..512 exact ASCII chars, mode 0600.

    Byte-exact — no newline, no trailing bytes. The value is never
    returned, printed or read back; an existing path is refused.
    """
    if (type(length) is not int or type(length) is bool
            or not MIN_KEY_CHARS <= length <= MAX_KEY_BYTES):
        raise LauncherRejected('credential_refused')
    blob = ''.join(secrets.choice(_KEY_ALPHABET)
                   for _ in range(length)).encode('ascii')
    try:
        _write_owned_file(path, blob)
    except (LauncherRejected, OSError, ValueError):
        raise LauncherRejected('credential_refused') from None


def _stop_child(proc):
    """Bounded cleanup of ONLY the original unreaped handle: terminate,
    bounded wait, kill if still live, then always a final bounded wait —
    even when the child already exited — so the owned handle is reaped
    or the refusal carries it. Never a PID lookup, never a global kill."""
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=TERM_SECONDS)
            except Exception:
                if proc.poll() is None:
                    proc.kill()
        proc.wait(timeout=KILL_SECONDS)
    except Exception:
        raise LauncherRejected('cleanup_failed') from None


def _cleanup_or_refuse(proc):
    try:
        _stop_child(proc)
    except LauncherRejected as exc:
        exc.child = proc          # cannot confirm ended: retain, no claim
        raise


def _record_launch(*, proc, before, argv, manifest_sha256, endpoint,
                   credential_ref, credential_file, model_id, threads,
                   slots, record_path):
    """Shared record half: closed-schema kernel-bound build, then the
    atomic 0600 single-link publish. Caller owns the child handle."""
    _target_dir(record_path)
    try:
        record = build_launch_record(
            proc=proc, before=before, argv=argv,
            manifest_sha256=manifest_sha256, endpoint=endpoint,
            credential_ref=credential_ref,
            credential_file=credential_file, model_id=model_id,
            threads=threads, slots=slots,
            read_process=read_owned_process)
        if type(record) is not bytes:
            raise LauncherRejected('record_failed')
        _write_owned_file(record_path, record)
    except LauncherRejected:
        raise
    except Exception:
        raise LauncherRejected('record_failed') from None


def launch_provider(*, argv, executable_path, model_path, template_path,
                    credential_file, manifest_sha256, endpoint,
                    credential_ref, model_id, threads, slots, host, port,
                    record_path, ready):
    """Launch the owned provider, then publish its launch record.

    manifest_sha256 is the caller-verified manifest digest. ready() is
    the owned bounded readiness callback (it may GET /models); it must
    return exactly True, and owns its own deadline. stdio stays owned:
    stdin/stdout/stderr are DEVNULL — no provider log pipe exists here.
    On failure only the original Popen handle is stopped; an
    unconfirmed stop raises cleanup_failed with the handle retained on
    .child — nothing claims the child ended.
    """
    if (type(manifest_sha256) is not str
            or type(endpoint) is not str
            or type(credential_ref) is not str
            or not callable(ready)):
        raise LauncherRejected('argv_invalid')
    try:
        argv = tuple(argv)                     # inside the fixed boundary
        validate_launch_argv(argv=argv, executable_path=executable_path,
            model_path=model_path, template_path=template_path,
            credential_file=credential_file, model_id=model_id,
            threads=threads, slots=slots, host=host, port=port)
    except Exception:
        raise LauncherRejected('argv_invalid') from None
    _target_dir(record_path)                 # refuse before any spawn
    try:
        before = {'executable': file_descriptor(executable_path),
                  'model': file_descriptor(model_path),
                  'template': file_descriptor(template_path)}
    except Exception:
        raise LauncherRejected('descriptor_invalid') from None
    try:
        proc = spawn_owned(argv, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    except Exception:
        raise LauncherRejected('spawn_failed') from None
    try:
        if ready(proc) is not True:          # exact True, never truthy
            raise LauncherRejected('ready_failed')
        _record_launch(proc=proc, before=before, argv=argv,
            manifest_sha256=manifest_sha256, endpoint=endpoint,
            credential_ref=credential_ref,
            credential_file=credential_file, model_id=model_id,
            threads=threads, slots=slots, record_path=record_path)
    except LauncherRejected:
        _cleanup_or_refuse(proc)
        raise
    except Exception:
        _cleanup_or_refuse(proc)
        raise LauncherRejected('record_failed') from None
    return LaunchResult(proc, record_path)


def record_owned_launch(*, proc, before, argv, manifest_sha256,
                        endpoint, credential_ref, credential_file,
                        model_id, threads, slots, record_path):
    """Complete an owned launch AFTER capture verification.

    External qualification workflow only: the caller spawned through
    spawn_owned with a validated argv, took `before` descriptors, ran
    its own bounded readiness/capture step and verified manifest_sha256
    — the same caller-verified-digest contract launch_provider holds.
    This function never spawns, never provisions a credential, never
    reads an environment. Kernel PID/argv/birth, post-launch descriptor
    identity and the closed argv allowlist all re-run inside
    build_launch_record before the atomic publish. Every failure —
    including invalid arguments — bounds-stops THIS proc handle; an
    unconfirmed stop raises cleanup_failed with .child retained.
    """
    try:
        try:
            argv = tuple(argv)
        except Exception:
            raise LauncherRejected('argv_invalid') from None
        if (type(manifest_sha256) is not str
                or type(endpoint) is not str
                or type(credential_ref) is not str):
            raise LauncherRejected('argv_invalid')
        _record_launch(proc=proc, before=before, argv=argv,
            manifest_sha256=manifest_sha256, endpoint=endpoint,
            credential_ref=credential_ref,
            credential_file=credential_file, model_id=model_id,
            threads=threads, slots=slots, record_path=record_path)
    except LauncherRejected:
        _cleanup_or_refuse(proc)
        raise
    except Exception:
        _cleanup_or_refuse(proc)
        raise LauncherRejected('record_failed') from None
    return LaunchResult(proc, record_path)
