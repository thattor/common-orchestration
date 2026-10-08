import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from co_v4.task import verify as vf
from co_v4.task import workspace as wsm
from co_v4.task.common import TaskError

GIT = shutil.which("git")
BASE_PYTHON = os.path.realpath(getattr(sys, "_base_executable", sys.executable))
HAS_SANDBOX = (sys.platform == "darwin"
               and os.access("/usr/bin/sandbox-exec", os.X_OK))


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True)


def make_repo(root, files):
    repo = Path(root) / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    for rel, (content, mode) in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if mode == "link":
            os.symlink(content, p)
        else:
            p.write_text(content)
            os.chmod(p, mode)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    return repo


def spec_for(repo, sha, readable, writable, verify=None):
    return {"schema": "co.task/1", "goal": "t", "repo": str(repo),
            "base_sha": sha, "readable": readable, "writable": writable,
            "verify": verify or ["/usr/bin/true"], "max_steps": 6,
            "max_repairs": 1, "call_timeout": 60}


def code_of(e):
    return getattr(e, "code", str(e))


def fake_git(path, version, delegate=None):
    body = ("#!/bin/sh\n"
            'for arg in "$@"; do\n'
            '  if [ "$arg" = "--version" ]; then\n'
            "    printf '%s\\n' " + shlex.quote("git version " + version) + "\n"
            "    exit 0\n"
            "  fi\n"
            "done\n")
    body += ('exec ' + shlex.quote(delegate) + ' "$@"\n') if delegate \
        else "exit 42\n"
    p = Path(path)
    p.write_text(body)
    p.chmod(0o755)
    return str(p)


class ProfileTest(unittest.TestCase):
    def test_quote_injection_rejected(self):
        for bad in ('/tmp/a"b', "/tmp/a\\b", "/tmp/a\nb"):
            with self.assertRaises(TaskError) as cm:
                vf._profile(bad, "/tmp/t", "/tmp/r", "/tmp/s",
                            "/tmp/h", "/tmp/tm")
            self.assertEqual(code_of(cm.exception), "input_invalid")


@unittest.skipUnless(GIT, "git required")
class WorkspaceTest(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp(prefix="co-ws-"))
        self.addCleanup(shutil.rmtree, self.td, True)

    def _spec(self, files, readable, writable):
        repo = make_repo(self.td, files)
        return spec_for(repo, wsm.resolve_base(str(repo)), readable,
                        writable)

    def test_materialize_partial_and_modes(self):
        spec = self._spec({"app.py": ("print(1)\n", 0o644),
                           "run.sh": ("#!/bin/sh\n", 0o755),
                           "secret.txt": ("x", 0o644)},
                          ["app.py", "run.sh"], ["app.py"])
        snap = wsm.materialize(spec, self.td / "task")
        ws = Path(snap["workspace"])
        self.assertTrue((ws / "app.py").is_file())
        self.assertFalse((ws / "secret.txt").exists())
        self.assertEqual(stat.S_IMODE((ws / "run.sh").stat().st_mode),
                         0o755)
        self.assertEqual(snap["base"]["app.py"]["mode"], 0o644)
        self.assertTrue(
            snap["base"]["app.py"]["sha256"].startswith("sha256:"))

    def test_malformed_scopes(self):
        spec = self._spec({"a.py": ("1\n", 0o644), "l": ("a.py", "link")},
                          ["a.py"], [])
        for i, readable in enumerate(
                (["a.py", "nope"], ["l"], ["../x"], ["/abs"], ["a//b"],
                 [".git/config"], [".co-verify-tmp-x"],
                 ["d/../../e"])):
            with self.assertRaises(TaskError) as cm:
                wsm.materialize(dict(spec, readable=readable),
                                self.td / f"t{i}")
            self.assertEqual(code_of(cm.exception), "input_invalid")
        with self.assertRaises(TaskError):
            wsm.materialize(dict(spec, base_sha="notasha"),
                            self.td / "t9")

    def test_nested_new_and_parent_link(self):
        spec = self._spec({"app.py": ("v1\n", 0o644)}, ["app.py"],
                          ["app.py", "d/sub/new.py"])
        snap = wsm.materialize(spec, self.td / "task")
        ws = Path(snap["workspace"])
        pre = wsm.fingerprint(ws, spec)
        post = wsm.apply_changes(
            ws, spec, [{"path": "d/sub/new.py", "content": "deep\n"}],
            pre)
        self.assertIsNotNone(post["d/sub/new.py"])
        self.assertEqual((ws / "d" / "sub" / "new.py").read_text(),
                         "deep\n")
        shutil.rmtree(ws / "d")
        os.symlink("/etc", ws / "d")
        with self.assertRaises(TaskError):
            wsm.fingerprint(ws, spec)
        with self.assertRaises(TaskError) as cm:
            wsm.apply_changes(ws, spec,
                              [{"path": "d/sub/new.py",
                                "content": "x"}], pre)
        self.assertEqual(code_of(cm.exception), "workspace_violation")

    def test_diverged_duplicates_and_scope(self):
        spec = self._spec({"app.py": ("v1\n", 0o644)}, ["app.py"],
                          ["app.py"])
        snap = wsm.materialize(spec, self.td / "task")
        ws = Path(snap["workspace"])
        pre = wsm.fingerprint(ws, spec)
        (ws / "app.py").write_text("evil\n")
        with self.assertRaises(TaskError) as cm:
            wsm.apply_changes(ws, spec,
                              [{"path": "app.py", "content": "z\n"}], pre)
        self.assertEqual(code_of(cm.exception), "workspace_diverged")
        pre = wsm.fingerprint(ws, spec)
        for batch in ([{"path": "../x", "content": "y"}],
                      [{"path": "other.py", "content": "y"}],
                      [{"path": "app.py", "content": "a"},
                       {"path": "app.py", "content": "b"}],
                      [{"path": "app.py", "content": "\ud800"}]):
            with self.assertRaises(TaskError) as cm:
                wsm.apply_changes(ws, spec, batch, pre)
            self.assertEqual(code_of(cm.exception), "input_invalid")

    def test_oversize_and_context_caps(self):
        spec = self._spec({"big.py": ("x" * (wsm.MAX_FILE + 1), 0o644)},
                          ["big.py"], [])
        with self.assertRaises(TaskError):
            wsm.materialize(spec, self.td / "task")
        files = {f"f{i}.py": ("y" * wsm.MAX_FILE, 0o644)
                 for i in range(5)}
        shutil.rmtree(self.td / "repo")
        spec = self._spec(files, sorted(files), [])
        with self.assertRaises(TaskError) as cm:
            wsm.materialize(spec, self.td / "task2")
        self.assertEqual(code_of(cm.exception), "input_invalid")


    def test_old_system_git_never_masks_qualifying_homebrew(self):
        repo = make_repo(self.td / "g1", {"a.py": ("1\n", 0o644)})
        old = fake_git(self.td / "git-old", "2.39.0")
        new = fake_git(self.td / "git-new", "2.50.0", GIT)
        poison = self.td / "caller-bin"
        poison.mkdir()
        fake_git(poison / "git", "99.0.0")
        with mock.patch.object(wsm, "_GIT_CANDIDATES",
                               (str(self.td / "absent"), old, new)), \
                mock.patch.dict(os.environ, {"PATH": str(poison),
                                             "GIT_CONFIG_GLOBAL": "/not-a-config"}):
            sha = wsm.resolve_base(str(repo))
            snap = wsm.materialize(spec_for(repo, sha, ["a.py"], []),
                                   self.td / "task")
        self.assertTrue(re.fullmatch(r"[0-9a-f]{40}", sha))
        self.assertEqual((Path(snap["workspace"]) / "a.py").read_text(), "1\n")

    def test_old_homebrew_never_masks_qualifying_system(self):
        repo = make_repo(self.td / "g2", {"a.py": ("1\n", 0o644)})
        old = fake_git(self.td / "git-old", "2.39.0")
        new = fake_git(self.td / "git-new", "2.50.0", GIT)
        with mock.patch.object(wsm, "_GIT_CANDIDATES", (new, old)):
            sha = wsm.resolve_base(str(repo))
            snap = wsm.materialize(spec_for(repo, sha, ["a.py"], []),
                                   self.td / "task")
        self.assertEqual((Path(snap["workspace"]) / "a.py").read_text(), "1\n")

    def test_no_qualifying_git(self):
        repo = make_repo(self.td / "g3", {"a.py": ("1\n", 0o644)})
        v1 = fake_git(self.td / "git-a", "2.45.9")
        v2 = fake_git(self.td / "git-b", "1.9.0")
        with mock.patch.object(wsm, "_GIT_CANDIDATES", (v1, v2)):
            with self.assertRaises(TaskError) as cm:
                wsm.resolve_base(str(repo))
            self.assertEqual(code_of(cm.exception), "git_unsupported")
        with mock.patch.object(wsm, "_GIT_CANDIDATES",
                               (str(self.td / "no-git"),)):
            with self.assertRaises(TaskError) as cm:
                wsm.resolve_base(str(repo))
            self.assertEqual(code_of(cm.exception), "git_unavailable")


PROBE = r'''
import os, socket, subprocess, sys, tempfile
TASKDIR = %r
res = []

def denied(fn):
    try:
        fn()
        return False
    except OSError:
        return True

def chk(n, v):
    print(n, v, flush=True)
    res.append(v)

chk("state", denied(lambda: open(TASKDIR + "/state.txt", "rb").read()))
chk("alias", denied(lambda: open("/tmp/co-esc", "w").write("x")))
chk("tmp", denied(lambda: open("/private/tmp/co-esc", "w").write("x")))
chk("src", denied(lambda: open("probe.py", "w").write("x")))
chk("home", denied(lambda: os.listdir("/Users")))
chk("net", denied(lambda: socket.create_connection(("127.0.0.1", 1), 1)))
r = subprocess.run([sys.executable, "-c",
                    "open('/tmp/e2','w').write('x')"],
                   capture_output=True)
chk("child", r.returncode != 0)
p = os.path.join(tempfile.gettempdir(), "ok")
open(p, "w").write("ok")
chk("scratch", open(p).read() == "ok")
sys.exit(0 if all(res) else 1)
'''


@unittest.skipUnless(GIT and HAS_SANDBOX, "needs git and sandbox-exec")
class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp(prefix="co-vf-"))
        self.addCleanup(shutil.rmtree, self.td, True)
        self.task = self.td / "task"

    def _setup(self, files, readable, writable, argv):
        repo = make_repo(self.td / "r", files)
        spec = spec_for(repo, wsm.resolve_base(str(repo)), readable,
                        writable, argv)
        snap = wsm.materialize(spec, self.task)
        return spec, Path(snap["workspace"])

    def test_pass_fail(self):
        spec, ws = self._setup(
            {"app.py": ("VALUE = 1\n", 0o644),
             "test_app.py": ("import unittest, app\n"
                             "class T(unittest.TestCase):\n"
                             "    def test_v(self):\n"
                             "        self.assertEqual(app.VALUE, 1)\n",
                             0o644)},
            ["app.py", "test_app.py"], ["app.py"],
            [BASE_PYTHON, "-I", "-m", "unittest", "discover",
             "-s", ".", "-p", "test_*.py"])
        res = vf.run_verifier(spec, ws, self.task)
        self.assertEqual(res["exit"], 0)
        self.assertTrue(res["passed"], res["log"])
        self.assertEqual(res["before"], res["after"])
        (ws / "app.py").write_text("VALUE = 2\n")
        res = vf.run_verifier(spec, ws, self.task)
        self.assertNotEqual(res["exit"], 0)
        self.assertFalse(res["passed"])

    def test_denials_aliases_and_children(self):
        spec, ws = self._setup(
            {"app.py": ("x = 1\n", 0o644),
             "probe.py": (PROBE % (str(self.task),), 0o644)},
            ["app.py", "probe.py"], ["app.py"],
            [BASE_PYTHON, "probe.py"])
        (self.task / "state.txt").write_text("secret")
        res = vf.run_verifier(spec, ws, self.task)
        self.assertTrue(res["passed"], res["log"])

    def test_writable_mutation_fails(self):
        spec, ws = self._setup(
            {"app.py": ("x = 1\n", 0o644),
             "p.py": ("open('app.py','w').write('bad')\n", 0o644)},
            ["app.py", "p.py"], ["app.py"], [BASE_PYTHON, "p.py"])
        res = vf.run_verifier(spec, ws, self.task)
        self.assertNotEqual(res["exit"], 0)  # sandbox denies the write
        # detection layer independently: permissive profile still fails
        with mock.patch.object(vf, "_profile",
                               return_value="(version 1)\n(allow default)\n"), \
             mock.patch.object(vf, "_CANARY", "import sys; sys.exit(0)"):
            res = vf.run_verifier(spec, ws, self.task)
        self.assertFalse(res["passed"])
        self.assertIn("mutated:app.py", res["log"])

    def test_mode_change_and_extras(self):
        spec, ws = self._setup(
            {"app.py": ("x = 1\n", 0o644),
             "p.py": ("import os\nos.chmod('app.py', 0o777)\n", 0o644)},
            ["app.py", "p.py"], [], [BASE_PYTHON, "p.py"])
        with mock.patch.object(vf, "_profile",
                               return_value="(version 1)\n(allow default)\n"), \
             mock.patch.object(vf, "_CANARY", "import sys; sys.exit(0)"):
            res = vf.run_verifier(spec, ws, self.task)
        self.assertFalse(res["passed"])
        self.assertIn("mode:app.py", res["log"])
        # pre-existing stray must also fail
        (ws / "stray.txt").write_text("x")
        res = vf.run_verifier(spec, ws, self.task)
        self.assertFalse(res["passed"])
        self.assertIn("unexpected:stray.txt", res["log"])

    def test_grandchild_reaped(self):
        tmp_marker = 'touch "$TMPDIR/late"'
        argv = ["/bin/sh", "-c",
                f"(sleep 3; {tmp_marker}) >/dev/null 2>&1 &"]
        spec, ws = self._setup({"a.py": ("1\n", 0o644)}, ["a.py"], [],
                               argv)
        res = vf.run_verifier(spec, ws, self.task)
        self.assertTrue(res["passed"], res["log"])
        tmpdirs = [d for d in os.listdir(ws) if d.startswith(vf.TMP_PREFIX)]
        time.sleep(4)
        for d in tmpdirs:
            self.assertFalse((ws / d / "late").exists())

    def test_timeout_logcap_and_fail_closed(self):
        argv = [BASE_PYTHON, "-c", "import time; time.sleep(30)"]
        spec, ws = self._setup({"a.py": ("1\n", 0o644)}, ["a.py"], [],
                               argv)
        with mock.patch.object(vf, "VERIFY_TIMEOUT", 1):
            res = vf.run_verifier(spec, ws, self.task)
        self.assertFalse(res["passed"])
        self.assertIn("timeout", res["log"])
        loud = [BASE_PYTHON, "-c", "print('x' * 100000)"]
        spec2 = dict(spec, verify=loud)
        with mock.patch.object(vf, "MAX_LOG", 1024):
            res = vf.run_verifier(spec2, ws, self.task)
        self.assertFalse(res["passed"])
        self.assertIn("log_overflow", res["log"])
        with mock.patch.object(vf, "SANDBOX_EXEC", "/nonexistent/x"):
            with self.assertRaises(TaskError) as cm:
                vf.run_verifier(spec, ws, self.task)
            self.assertEqual(code_of(cm.exception), "sandbox_unavailable")

    def test_closed_stdout_does_not_cancel_live_leader(self):
        spec, ws = self._setup({"a.py": ("1\n", 0o644)}, ["a.py"], [],
            ["/bin/sh", "-c", "exec >/dev/null 2>&1; sleep 0.2; exit 0"])
        result = vf.run_verifier(spec, ws, self.task)
        self.assertTrue(result["passed"], result)

    def test_silent_child_pipe_does_not_wait_full_timeout(self):
        spec, ws = self._setup({"a.py": ("1\n", 0o644)}, ["a.py"], [],
            ["/bin/sh", "-c", "sleep 30 & exit 0"])
        started = time.monotonic()
        result = vf.run_verifier(spec, ws, self.task)
        self.assertTrue(result["passed"], result)
        self.assertLess(time.monotonic() - started, 8)
        with mock.patch.object(vf, "_profile", return_value="(broken"):
            with self.assertRaises(TaskError) as cm:
                vf.run_verifier(spec, ws, self.task)
            self.assertEqual(code_of(cm.exception), "sandbox_unavailable")

    def test_preflight_ready_never_runs_command(self):
        # marker lands in the sandboxed TMPDIR (inside ws scratch) if the
        # verify command ever executes; preflight must leave none
        argv = ["/bin/sh", "-c", "echo ran > \"$TMPDIR/preflight-ran\""]
        spec, ws = self._setup({"a.py": ("1\n", 0o644)}, ["a.py"], [],
                               argv)
        self.assertIsNone(vf.preflight_verifier(spec, ws, self.task))
        self.assertEqual(list(ws.rglob("preflight-ran")), [])
        self.assertEqual([e.name for e in os.scandir(self.task)
                          if e.name.startswith("verify-canary-")], [])

    def test_blocked_verify_executable_and_symlink(self):
        spec, ws = self._setup({"a.py": ("1\n", 0o644)}, ["a.py"], [],
                               ["/usr/bin/true"])
        tool = Path(spec["repo"]) / "tool.sh"
        tool.write_text("#!/bin/sh\nexit 0\n")
        os.chmod(tool, 0o755)
        # a symlink inside the workspace resolves into the denied repo
        # tree, so it must be refused exactly like the direct path
        os.symlink(tool, ws / "tool-link")
        for argv0 in (str(tool), str(ws / "tool-link")):
            for fn in (vf.preflight_verifier, vf.run_verifier):
                with self.assertRaises(TaskError) as cm:
                    fn(dict(spec, verify=[argv0]), ws, self.task)
                self.assertEqual(code_of(cm.exception),
                                 "verify_executable_blocked")

    def test_preflight_blocked_host_interpreter(self):
        spec, ws = self._setup({"a.py": ("1\n", 0o644)}, ["a.py"], [],
                               ["/usr/bin/true"])
        # a base interpreter under task state is unreadable inside the
        # sandbox; preflight must fail fast with the fixed error
        fake = self.task / "host-python"
        with mock.patch.object(sys, "_base_executable", str(fake),
                               create=True):
            with self.assertRaises(TaskError) as cm:
                vf.preflight_verifier(spec, ws, self.task)
            self.assertEqual(code_of(cm.exception),
                             "sandbox_unavailable")
        # the sentinel lives outside owned scratch; it must not leak
        self.assertEqual([e.name for e in os.scandir(self.task)
                          if e.name.startswith("verify-canary-")], [])

    def test_preflight_fail_closed(self):
        spec, ws = self._setup({"a.py": ("1\n", 0o644)}, ["a.py"], [],
                               ["/usr/bin/true"])
        with mock.patch.object(vf, "SANDBOX_EXEC", "/nonexistent/x"):
            with self.assertRaises(TaskError) as cm:
                vf.preflight_verifier(spec, ws, self.task)
            self.assertEqual(code_of(cm.exception), "sandbox_unavailable")


if __name__ == "__main__":
    unittest.main()
