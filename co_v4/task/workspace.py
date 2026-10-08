"""Partial per-task workspace for co_v4.

Only listed blobs are read from the fixed base commit via git plumbing
(rev-parse / ls-tree / cat-file) with hooks, user config, replace objects,
fsmonitor, lazy fetching and pathspec globs disabled. The owner worktree,
index and dirty tree are never touched; writes go to a fresh private
workspace dir. All workspace access walks components via dirfd with
O_NOFOLLOW so ancestor/symlink swaps cannot escape the tree.
"""
from __future__ import annotations

import difflib
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

from .common import TaskError, digest
from .spec import _no_ancestor

MAX_FILE = 65536
MAX_CONTEXT = 262144
RESERVED_PREFIX = ".co-verify-tmp"  # verifier-owned scratch namespace

_GIT_TIMEOUT = 30
_MIN_GIT = (2, 46)  # minimum supported version for this plumbing contract
_GIT_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_LITERAL_PATHSPECS": "1",
}
_GIT_FLAGS = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false")
_GIT_CANDIDATES = ("/usr/bin/git", "/bin/git", "/opt/homebrew/bin/git",
                   "/usr/local/bin/git")
_SHA40 = re.compile(r"[0-9a-f]{40}")
_BLOB_MODES = {0o100644: 0o644, 0o100755: 0o755}
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIR_RO = os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW


def _git_version(path):
    try:
        proc = subprocess.run([path, *_GIT_FLAGS, "--version"],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, env=_GIT_ENV,
                              timeout=_GIT_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    m = re.search(r"version (\d+)\.(\d+)",
                  proc.stdout.decode("ascii", "replace"))
    return (int(m.group(1)), int(m.group(2))) if m else None


def _git_path():
    # PATH preference alone lets an old install mask a qualifying binary.
    ran = False
    for cand in _GIT_CANDIDATES:
        if not os.path.isfile(cand) or not os.access(cand, os.X_OK):
            continue
        version = _git_version(cand)
        if version is None:
            continue
        ran = True
        if version >= _MIN_GIT:
            return cand
    raise TaskError("git_unsupported" if ran else "git_unavailable")


def _git(git, repo, args, data=None):
    cmd = [git, *_GIT_FLAGS, "-C", str(repo), *args]
    try:
        proc = subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=_GIT_ENV,
                              timeout=_GIT_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        raise TaskError("git_timeout") from e
    except OSError as e:
        raise TaskError("git_unavailable") from e
    if proc.returncode != 0:
        raise TaskError("git_failed")
    return proc.stdout


def _check_relpath(path):
    if (not isinstance(path, str) or not path or path.startswith("/")
            or "\\" in path or '"' in path or "\0" in path
            or any(ord(c) < 32 or ord(c) == 127 for c in path)):
        raise TaskError("input_invalid")
    parts = path.split("/")
    if any(c in ("", ".", "..") or c.casefold() == ".git"
           or c.casefold().startswith(RESERVED_PREFIX)
           for c in parts):
        raise TaskError("input_invalid")
    return parts


def _resolve(ws, path, create=False):
    """Walk components via dirfd + O_NOFOLLOW from the ws root.

    Returns (dir_fd, basename, stat|None); caller owns dir_fd. Any
    symlink or non-regular/non-dir component -> workspace_violation.
    With create=True missing parents are mkdir'd under the pinned fd.
    """
    parts = _check_relpath(path)
    fd = os.open(str(ws), _DIR_RO)
    try:
        for part in parts[:-1]:
            try:
                st = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o755, dir_fd=fd)
                os.fsync(fd)
                st = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(st.st_mode):
                raise TaskError("workspace_violation")
            nfd = os.open(part, _DIR_RO, dir_fd=fd)
            os.close(fd)
            fd = nfd
        try:
            st = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None and not stat.S_ISREG(st.st_mode) \
                and not stat.S_ISDIR(st.st_mode):
            raise TaskError("workspace_violation")
        return fd, parts[-1], st
    except BaseException:
        os.close(fd)
        raise


def _read_at(dirfd, name):
    fd = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=dirfd)
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise TaskError("workspace_violation")
    return data


def _write_at(dirfd, name, data, mode):
    """Atomic replace under a pinned dirfd: temp file, fsync, rename."""
    tmp = ".co-tmp-" + os.urandom(8).hex()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                 0o600, dir_fd=dirfd)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode, dir_fd=dirfd, follow_symlinks=False)
        os.replace(tmp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dirfd)
        except OSError:
            pass
        raise
    os.fsync(dirfd)


def resolve_base(repo, base="HEAD"):
    """Resolve base to an exact 40-hex commit SHA; read-only plumbing."""
    repo = os.path.realpath(repo)
    if not os.path.isdir(repo):
        raise TaskError("input_invalid")
    git = _git_path()
    if not isinstance(base, str) or not base or base.startswith("-"):
        raise TaskError("input_invalid")
    try:
        out = _git(git, repo, ["rev-parse", "--verify", "--end-of-options",
                               base + "^{commit}"])
    except TaskError as e:
        raise TaskError("input_invalid") from e
    text = out.decode("ascii", "replace").strip()
    if not _SHA40.fullmatch(text):
        raise TaskError("input_invalid")
    return text


def _ls_tree(git, repo, base, paths):
    if not paths:
        return {}
    out = _git(git, repo, ["ls-tree", "-z", base, "--", *paths])
    entries = {}
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, _, name = rec.partition(b"\t")
        try:
            mode_s, typ_s, oid = meta.split()
        except ValueError:
            raise TaskError("input_invalid")
        oid = oid.decode("ascii", "replace")
        if not _SHA40.fullmatch(oid):
            raise TaskError("input_invalid")
        entries[name.decode("utf-8", "surrogateescape")] = (
            int(mode_s, 8), typ_s.decode("ascii", "replace"), oid)
    if not set(entries) <= set(paths):
        raise TaskError("input_invalid")
    return entries


def _cat_blobs(git, repo, oids):
    """batch-check sizes before reading; never load an oversized blob."""
    if not oids:
        return {}
    arg = ("\n".join(oids) + "\n").encode("ascii")
    lines = _git(git, repo, ["cat-file", "--batch-check"],
                 data=arg).decode("ascii", "replace").splitlines()
    if len(lines) != len(oids):
        raise TaskError("input_invalid")
    sizes, total = {}, 0
    for oid, line in zip(oids, lines):
        f = line.split()
        if len(f) != 3 or f[0] != oid or f[1] != "blob":
            raise TaskError("input_invalid")
        size = int(f[2])
        if size > MAX_FILE:
            raise TaskError("input_invalid")
        total += size
        if total > MAX_CONTEXT:
            raise TaskError("input_invalid")
        sizes[oid] = size
    out = _git(git, repo, ["cat-file", "--batch"], data=arg)
    blobs, i = {}, 0
    for oid in oids:
        try:
            nl = out.index(b"\n", i)
        except ValueError:
            raise TaskError("input_invalid")
        want = sizes[oid]
        if out[i:nl].split() != [oid.encode(), b"blob",
                                 str(want).encode()]:
            raise TaskError("input_invalid")
        i = nl + 1
        blob = out[i:i + want]
        if len(blob) != want or out[i + want:i + want + 1] != b"\n":
            raise TaskError("input_invalid")
        blobs[oid] = blob
        i += want + 1
    return blobs


def materialize(spec, task_dir):
    """Create a fresh workspace holding only the listed base blobs."""
    task_dir = Path(task_dir)
    ws = task_dir / "workspace"
    if os.path.lexists(ws):
        raise TaskError("workspace_exists")
    if not _SHA40.fullmatch(str(spec["base_sha"])):
        raise TaskError("input_invalid")
    repo = os.path.realpath(spec["repo"])
    readable = set(spec["readable"])
    writable = set(spec["writable"])
    scope = sorted(readable | writable)
    _no_ancestor(scope)
    for p in scope:
        _check_relpath(p)
    git = _git_path()
    entries = _ls_tree(git, repo, spec["base_sha"], scope)
    oids, plans = [], {}
    for p in scope:
        ent = entries.get(p)
        if ent is None:
            if p in writable and p not in readable:
                plans[p] = None
                continue
            raise TaskError("input_invalid")
        if p in writable and p not in readable:
            raise TaskError("input_invalid")
        mode, typ, oid = ent
        if typ != "blob" or mode not in _BLOB_MODES:
            raise TaskError("input_invalid")
        oids.append(oid)
        plans[p] = (oid, _BLOB_MODES[mode])
    blobs = _cat_blobs(git, repo, oids)
    snap = {}
    for p in scope:
        plan = plans[p]
        if plan is None:
            snap[p] = {"text": None, "mode": 0o644, "sha256": None}
            continue
        raw = blobs[plan[0]]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise TaskError("input_invalid") from e
        snap[p] = {"text": text, "mode": plan[1], "sha256": digest(raw)}
    try:
        task_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        ws.mkdir(mode=0o700)
    except FileExistsError as e:
        raise TaskError("workspace_exists") from e
    except OSError as e:
        raise TaskError("workspace_io") from e
    for p, meta in snap.items():
        if meta["text"] is None:
            continue
        fd, name, st = _resolve(ws, p, create=True)
        try:
            if st is not None:
                raise TaskError("workspace_violation")
            _write_at(fd, name, meta["text"].encode("utf-8"), meta["mode"])
        finally:
            os.close(fd)
    return {"base": snap, "workspace": str(ws)}


def fingerprint(workspace, spec):
    """Map every readable|writable path to digest or None; reject links."""
    out = {}
    for p in sorted(set(spec["readable"]) | set(spec["writable"])):
        try:
            fd, name, st = _resolve(workspace, p)
        except FileNotFoundError:
            out[p] = None
            continue
        try:
            if st is None:
                out[p] = None
            elif not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE:
                raise TaskError("workspace_violation")
            else:
                out[p] = digest(_read_at(fd, name))
        finally:
            os.close(fd)
    return out


def apply_changes(workspace, spec, changes, pre):
    """Validate whole batch, then atomic dirfd writes; modes preserved."""
    _no_ancestor(list(set(spec["readable"]) | set(spec["writable"])))
    if fingerprint(workspace, spec) != pre:
        raise TaskError("workspace_diverged")
    writable = set(spec["writable"])
    seen, prepared = set(), []
    for ch in changes:
        p, content = ch.get("path"), ch.get("content")
        if p not in writable or p in seen or not isinstance(content, str):
            raise TaskError("input_invalid")
        seen.add(p)
        try:
            data = content.encode("utf-8")
        except UnicodeEncodeError as e:
            raise TaskError("input_invalid") from e
        if len(data) > MAX_FILE:
            raise TaskError("input_invalid")
        try:
            fd, name, st = _resolve(workspace, p)
        except FileNotFoundError:
            st = None
        else:
            os.close(fd)
        if st is not None and not stat.S_ISREG(st.st_mode):
            raise TaskError("workspace_violation")
        prepared.append((p, data,
                         stat.S_IMODE(st.st_mode) if st else 0o644))
    for p, data, mode in prepared:
        fd, name, _ = _resolve(workspace, p, create=True)
        try:
            _write_at(fd, name, data, mode)
        finally:
            os.close(fd)
    return fingerprint(workspace, spec)


def _current(workspace, p):
    try:
        fd, name, st = _resolve(workspace, p)
    except FileNotFoundError:
        return None
    try:
        if st is None or not stat.S_ISREG(st.st_mode):
            return None
        return _read_at(fd, name)
    finally:
        os.close(fd)


def diff(snapshot, workspace, spec):
    """Unified diff of base blobs vs workspace bytes, pure Python."""
    chunks, total = [], 0
    for p, meta in sorted(snapshot["base"].items()):
        old = meta["text"]
        cur = _current(workspace, p)
        new = cur.decode("utf-8", "replace") if cur is not None else None
        if new == old:
            continue
        text = "".join(difflib.unified_diff(
            old.splitlines(True) if old is not None else [],
            new.splitlines(True) if new is not None else [],
            fromfile="/dev/null" if old is None else "a/" + p,
            tofile="/dev/null" if new is None else "b/" + p))
        total += len(text.encode("utf-8"))
        if total > 2 * MAX_CONTEXT:
            raise TaskError("diff_too_large")
        chunks.append(text)
    return "".join(chunks)


def read_context(workspace, spec):
    """Read all listed readable paths, bounded by MAX_FILE/MAX_CONTEXT."""
    out, total = {}, 0
    for p in sorted(set(spec["readable"])):
        cur = _current(workspace, p)
        if cur is None:
            raise TaskError("workspace_diverged")
        total += len(cur)
        if total > MAX_CONTEXT:
            raise TaskError("context_too_large")
        out[p] = cur.decode("utf-8")
    return out
