"""Sandboxed verifier execution for co_v4 workspaces (macOS seatbelt).

Scope is deliberately narrow: an allow-default SBPL profile denies all
network and mach services, reads of the task state dir, the repo, the
canonical HOME, state root and sensitive parents, and ALL writes outside
the per-run owned scratch dir (plus /dev/null). Listed inputs are
fingerprint-compared before/after and protected additionally by the
write deny. A canary must prove the carve-out and denials with EPERM/
EACCES before every real run; failure -> sandbox_unavailable, never an
uncontained fallback. No claim of full-machine containment: a process
that escapes its own process group is outside this design's guarantee.

preflight_verifier() runs the identical setup and canary but never
executes the spec's verify command, letting the runner fail closed
before the first planner call instead of at verification time.
"""
from __future__ import annotations

import os
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .common import TaskError
from .workspace import RESERVED_PREFIX, _check_relpath, fingerprint

VERIFY_TIMEOUT = 60
CANARY_TIMEOUT = 20
MAX_LOG = 1 << 20
GRACE = 1.0
SANDBOX_EXEC = "/usr/bin/sandbox-exec"
TMP_PREFIX = RESERVED_PREFIX + "-"
READ_DENY_PARENTS = (
    "/Users", "/Volumes", "/Network", "/private/tmp",
    "/private/var/folders", "/private/var/root",
    "/Library/Keychains", "/System/Library/Keychains",
    "/private/var/Keychains",
)

_CANARY = r"""
import errno, os, socket, sys
tmp, sentinel, port, ws, sample = sys.argv[1:6]
port = int(port)
ok = True
DENY = (errno.EPERM, errno.EACCES)

def expect(fn, deny):
    try:
        fn()
        return not deny
    except OSError as e:
        return deny and e.errno in DENY

def w():
    p = os.path.join(tmp, "c")
    with open(p, "w") as f:
        f.write("x")
    if open(p).read() != "x":
        raise RuntimeError("readback")
    os.remove(p)
ok = expect(w, False) and ok
if sample:
    ok = expect(lambda: open(os.path.join(ws, sample), "rb").read(),
                False) and ok
ok = expect(lambda: open(sentinel, "rb").read(), True) and ok
def wr():
    with open(sentinel + ".w", "w") as f:
        f.write("x")
ok = expect(wr, True) and ok
def wsr():
    with open(os.path.join(ws, "canary-w"), "w") as f:
        f.write("x")
ok = expect(wsr, True) and ok
def conn():
    socket.create_connection(("127.0.0.1", port), 2).close()
ok = expect(conn, True) and ok
sys.exit(0 if ok else 1)
"""


def _sbq(s):
    """SBPL string literal; reject injection via quotes/backslash/ctrl."""
    if not s or any(ord(c) < 0x20 or c in '"\\' for c in s):
        raise TaskError("input_invalid")
    return '"' + s + '"'


def _profile(ws, task_dir, repo, state_root, home, tmp):
    parents = [p for p in (*READ_DENY_PARENTS, home, repo, state_root)
               if p]
    deny = "\n".join(f"        (subpath {_sbq(p)})" for p in parents)
    return f'''(version 1)
(allow default)
(deny network*)
(deny mach-lookup)
(deny mach-register)
(deny file-write*
  (require-all
    (require-not (subpath {_sbq(tmp)}))
    (require-not (literal "/dev/null"))))
(deny file-read*
  (require-any
    (subpath {_sbq(ws + "/.git")})
    (require-all
      (subpath {_sbq(task_dir)})
      (require-not (subpath {_sbq(ws)})))
    (require-all
      (require-not (subpath {_sbq(ws)}))
      (require-any
{deny}))))
'''


def _env(argv0, tmp):
    parts = [os.path.dirname(argv0), "/usr/bin", "/bin",
             "/usr/sbin", "/sbin"]
    return {"PATH": os.pathsep.join(dict.fromkeys(parts)),
            "TMPDIR": str(tmp), "HOME": str(tmp),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1"}


def _killpg(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


def _run(prof, cmd, cwd, tmp, timeout):
    """Bounded run: capped log via selector, wall deadline, group cleanup
    on every exit path (leader exit still kills stray group members)."""
    try:
        proc = subprocess.Popen([SANDBOX_EXEC, "-f", str(prof), *cmd],
                                cwd=str(cwd), env=_env(cmd[0], tmp),
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, bufsize=0,
                                start_new_session=True)
    except OSError as e:
        raise TaskError("sandbox_unavailable") from e
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    log = bytearray()
    status, grace = None, None
    deadline = time.monotonic() + timeout
    try:
        while sel.get_map() or proc.poll() is None:
            now = time.monotonic()
            if now >= deadline:
                status = "timeout"
                break
            limit = deadline
            if proc.poll() is not None:
                if grace is None:
                    grace = now + GRACE
                limit = min(deadline, grace)
            # EOF is not process completion; descendants can also keep a
            # silent pipe open after the leader exits. Poll both conditions.
            for key, _ in sel.select(min(0.1, max(0.0, limit - now))):
                data = os.read(key.fd, 65536)
                if not data:
                    sel.unregister(key.fd)
                    continue
                room = MAX_LOG - len(log)
                log += data[:room]
                if len(data) > room:
                    status = "log_overflow"
                    break
            if status or (grace is not None
                          and time.monotonic() >= grace):
                break
    finally:
        _killpg(proc)      # also terminate surviving group members
        rc = proc.wait()   # reap the owned leader before scanning
        sel.close()
        proc.stdout.close()
    return rc, bytes(log), status


def _scan(ws, spec):
    try:
        fp, err = fingerprint(ws, spec), None
    except TaskError as e:
        fp, err = {}, getattr(e, "code", str(e))
    scope = set(spec["readable"]) | set(spec["writable"])
    extras, modes = set(), {}
    for root, dirs, files in os.walk(ws):
        dirs.sort()
        rel = os.path.relpath(root, ws)
        kept = []
        for d in dirs:
            if rel == "." and d.startswith(RESERVED_PREFIX):
                continue
            kept.append(d)
            r = os.path.normpath(os.path.join(rel, d))
            if os.path.islink(os.path.join(root, d)):
                extras.add(r + os.sep)
        dirs[:] = kept
        for f in files:
            r = os.path.normpath(os.path.join(rel, f))
            if r in scope:
                modes[r] = stat.S_IMODE(
                    os.lstat(os.path.join(root, f)).st_mode)
            else:
                extras.add(r)
    return fp, modes, extras, err


def _clean_tmps(ws):
    for e in os.scandir(ws):
        if not e.name.startswith(RESERVED_PREFIX):
            continue
        if e.is_symlink() or not e.is_dir(follow_symlinks=False):
            raise TaskError("workspace_violation")
        shutil.rmtree(e.path)


def _under(path, root):
    return path == root or path.startswith(root + os.sep)


def _protected(real, ws_real, roots):
    # Every root is read-denied by the profile except the workspace
    # subtree carved out of it; a binary the sandbox cannot even read
    # would die with an opaque EPERM, so it is rejected up front.
    return (any(_under(real, r) for r in roots if r)
            and not _under(real, ws_real))


def _prepare(spec, workspace, task_dir):
    """Shared preamble for preflight_verifier() and run_verifier():
    platform/argv/scope validation, realpath resolution, refusal of
    verify executables under read-denied roots, then owned scratch,
    profile, base scan and canary sentinel. The caller owns sentinel
    cleanup on every exit path after this returns."""
    if (sys.platform != "darwin" or not os.path.isfile(SANDBOX_EXEC)
            or not os.access(SANDBOX_EXEC, os.X_OK)):
        raise TaskError("sandbox_unavailable")
    ws, task_dir = Path(workspace), Path(task_dir)
    argv = list(spec.get("verify") or [])
    if (not argv or not os.path.isabs(argv[0])
            or not (os.path.isfile(argv[0]) and os.access(argv[0], os.X_OK))):
        raise TaskError("input_invalid")
    for p in set(spec["readable"]) | set(spec["writable"]):
        _check_relpath(p)
    if not ws.is_dir() or os.path.islink(ws):
        raise TaskError("input_invalid")
    ws_real = os.path.realpath(ws)
    task_real = os.path.realpath(task_dir)
    repo_real = os.path.realpath(spec["repo"])
    state_root = os.path.realpath(os.path.join(task_real, os.pardir,
                                               os.pardir))
    try:
        home = os.path.realpath(os.path.expanduser("~"))
    except Exception:
        home = ""
    roots = (*READ_DENY_PARENTS, repo_real, state_root, home)
    if _protected(os.path.realpath(argv[0]), ws_real, roots):
        raise TaskError("verify_executable_blocked")
    _clean_tmps(ws_real)
    tmp = tempfile.mkdtemp(prefix=TMP_PREFIX, dir=ws_real)
    prof = task_dir / "verify.sb"
    prof.write_text(_profile(ws_real, task_real, repo_real, state_root,
                             home, tmp))
    os.chmod(prof, 0o600)
    # Scan before creating the sentinel so a scan failure cannot leave
    # the sentinel behind outside owned scratch.
    before = _scan(ws_real, spec)
    sfd, sentinel = tempfile.mkstemp(prefix="verify-canary-",
                                     dir=task_real)
    os.write(sfd, b"sentinel")
    os.close(sfd)
    return {"argv": argv, "ws": ws_real, "tmp": tmp, "prof": prof,
            "sentinel": sentinel, "roots": roots,
            "readable": set(spec["readable"]), "before": before}


def _canary(ctx):
    """Run the real seatbelt canary; raises sandbox_unavailable unless
    every expected allow/deny is proven inside the sandbox."""
    # The host may run from a venv inside protected task state. Probe
    # with its real base interpreter, not that venv's path; if even that
    # sits under a denied root the sandbox could never exec it, so fail
    # fast instead of spending a canary timeout on a guaranteed EPERM.
    python = os.path.realpath(getattr(sys, "_base_executable",
                                      sys.executable))
    if _protected(python, ctx["ws"], ctx["roots"]):
        raise TaskError("sandbox_unavailable")
    before_fp = ctx["before"][0]
    sample = next((p for p in sorted(ctx["readable"])
                   if before_fp.get(p)), "")
    try:
        with socket.socket(socket.AF_INET,
                           socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            rc, _, cst = _run(ctx["prof"],
                              [python, "-I", "-c", _CANARY,
                               ctx["tmp"], ctx["sentinel"],
                               str(listener.getsockname()[1]),
                               ctx["ws"], sample],
                              ctx["ws"], ctx["tmp"], CANARY_TIMEOUT)
    except OSError as exc:
        raise TaskError("sandbox_unavailable") from exc
    if rc != 0 or cst:
        raise TaskError("sandbox_unavailable")


def preflight_verifier(spec, workspace, task_dir):
    """Fail-closed readiness check for the runner to call after
    workspace_ready and before the first planner call. Performs the
    same executable-location checks and real canary as run_verifier()
    but NEVER executes the spec's verify command. Returns None when
    the sandbox provably enforces; raises TaskError otherwise."""
    ctx = _prepare(spec, workspace, task_dir)
    try:
        _canary(ctx)
    finally:
        # The sentinel lives in task state outside owned scratch, so it
        # must be removed even when the canary raises.
        try:
            os.unlink(ctx["sentinel"])
        except OSError:
            pass


def run_verifier(spec, workspace, task_dir):
    ctx = _prepare(spec, workspace, task_dir)
    try:
        _canary(ctx)
        rc, log, status = _run(ctx["prof"], ctx["argv"], ctx["ws"],
                               ctx["tmp"], VERIFY_TIMEOUT)
        after_fp, after_m, after_ex, aerr = _scan(ctx["ws"], spec)
    finally:
        try:
            os.unlink(ctx["sentinel"])
        except OSError:
            pass
    before_fp, before_m, before_ex, berr = ctx["before"]
    scope = sorted(set(spec["readable"]) | set(spec["writable"]))
    violations = []
    for e in (berr, aerr):
        if e and "fingerprint:" + e not in violations:
            violations.append("fingerprint:" + e)
    for p in scope:
        if before_fp.get(p) != after_fp.get(p):
            violations.append("mutated:" + p)
        elif before_m.get(p) != after_m.get(p):
            violations.append("mode:" + p)
    for r in sorted(before_ex | after_ex):
        violations.append("unexpected:" + r)
    if status:
        violations.append(status)
    if violations:
        tail = ("\nco-verify: " + "; ".join(violations) + "\n").encode()
        tail = tail[:MAX_LOG]
        log = log[:MAX_LOG - len(tail)] + tail
    return {"exit": rc, "passed": rc == 0 and not violations,
            "log": log.decode("utf-8", "replace"),
            "before": before_fp, "after": after_fp,
            "sandbox": "seatbelt-v1", "violations": violations}
