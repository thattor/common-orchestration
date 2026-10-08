"""Unit tests for co_v4.task.infer.

All CLI calls go through infer._spawn, patched with a fake that emits
measured shapes: claude stream-json, Devin ATIF-v1.7 exports (including
induction request/denial observations), and `devin models list --format
json`. A few tests exercise the real _spawn with /bin utilities only.
"""

import fcntl
import json
import os
import re
import shlex
import tempfile
import time
import unittest
import unittest.mock as mock
from pathlib import Path

from co_v4.task import infer
from co_v4.task.common import TaskError, canonical, digest

VERSIONS = {"claude": "2.1.291", "devin": "3000.11.3"}
MODELS_FREE = {"families": [{"family_uid": "swe-2", "variants": [
    {"model_uid": "swe-2-high", "label": "SWE-2 High",
     "max_context_tokens": 262000, "max_output_tokens": 128000,
     "cost_tier": "Free"}]}]}


def code_of(exc):
    return getattr(exc, "code", None) or exc.args[0]


def claude_stream(model="claude-opus-5-5", text="OK", tool_uses=0,
                  init=True, api="none", mcp=None, tools_init=None,
                  error=False, asst_model="claude-opus-5-5", raw_extra=""):
    ev = []
    if init:
        ev.append({"type": "system", "subtype": "init", "model": model,
                   "tools": [] if tools_init is None else tools_init,
                   "mcp_servers": [] if mcp is None else mcp,
                   "apiKeySource": api})
    content = [{"type": "text", "text": "hi"}] + [
        {"type": "tool_use", "name": "exec"} for _ in range(tool_uses)]
    ev.append({"type": "assistant",
               "message": {"model": asst_model, "content": content}})
    ev.append({"type": "result", "subtype": "error" if error else "success",
               "is_error": error, "result": text})
    return ("\n".join(json.dumps(e) for e in ev) + raw_extra + "\n").encode()


def atif(prompt, model="swe-2-high", version="3000.11.3", extra_user=False,
         tool_src=False, tc="absent", gen=None, final="implemented",
         schema="ATIF-v1.7"):
    steps = [{"source": "system", "message": "sys"},
             {"source": "user", "message": prompt},
             {"source": "system", "message": "tool defs"}]
    if extra_user:
        steps.append({"source": "user", "message": "another user msg"})
    if tool_src:
        steps.append({"source": "tool", "message": "tool output"})
    a = {"source": "agent", "model_name": model, "message": final,
         "extra": {"generation_model": gen or model}}
    if tc != "absent":
        a["tool_calls"] = tc
    steps.append(a)
    return {"schema_version": schema, "session_id": "s-1",
            "agent": {"name": "devin", "version": version,
                      "model_name": "SWE-2 High", "tool_definitions": []},
            "steps": steps, "final_metrics": {"steps": len(steps)}}


def atif_ind(prompt, tname, targs, obs_content=None, call_id="c1",
             drop_obs=False, obs_call_id=None, agent_msg="I could not.",
             model="swe-2-high", version="3000.11.3"):
    """ATIF with one tool request and (optionally) one observation."""
    steps = [{"source": "system", "message": "sys"},
             {"source": "user", "message": prompt},
             {"source": "agent", "model_name": model, "message": "trying",
              "tool_calls": [{"tool_call_id": call_id, "function_name": tname,
                              "arguments": targs}],
              "extra": {"generation_model": model}}]
    if not drop_obs:
        steps[-1]["observation"] = {"results": [
            {"source_call_id": obs_call_id or call_id,
             "content": obs_content}]}
    steps.append({"source": "agent", "model_name": model,
                  "message": agent_msg, "tool_calls": [],
                  "extra": {"generation_model": model}})
    return {"schema_version": "ATIF-v1.7", "session_id": "s-2",
            "agent": {"name": "devin", "version": version,
                      "model_name": "SWE-2 High", "tool_definitions": []},
            "steps": steps, "final_metrics": {}}


def _ind_parts(prompt):
    """Split an induction prompt into (kind, tool name, args, denial)."""
    if "Read the file at " in prompt:
        path = prompt.split("Read the file at ", 1)[1].split(" ", 1)[0]
        return ("read", "read", {"file_path": path},
                "Read access to '%s' was denied. The user needs to grant "
                "read permission for this directory." % path)
    if "Write a new file at " in prompt:
        path = prompt.split("Write a new file at ", 1)[1].split(" ", 1)[0]
        return ("write", "write", {"file_path": path},
                "Write access to '%s' was denied. The user needs to grant "
                "write permission for this directory — ask them to approve "
                "the write access request or add the directory to the "
                "workspace." % path)
    cmd = prompt.split("nothing else: ", 1)[1].strip()
    path = shlex.split(cmd)[1]
    return ("exec", "exec", {"command": cmd},
            "Permission to run the command `%s` was denied. The user needs to approve command execution." % cmd)


def devin_export_factory(mode="deny"):
    """Fake export builder covering nonce and read/write/exec induction."""
    def build(prompt):
        if ("Read the file at " in prompt or "Write a new file at " in prompt
                or "shell command" in prompt):
            kind, tname, targs, denial = _ind_parts(prompt)
            kw = {}
            if mode == "deny":
                content = denial
            elif mode == "success":
                if kind == "read":
                    content = Path(targs["file_path"]).read_text()
                else:
                    Path(targs.get("file_path") or
                         shlex.split(targs["command"])[1]).write_text("x")
                    content = "done"
            elif mode == "wrong_target":
                targs = ({"file_path": "/etc/hostname"} if kind != "exec"
                         else {"command": "touch /etc/hostname"})
                content = denial
            elif mode == "no_obs":
                kw["drop_obs"] = True
                content = None
            elif mode == "bad_callid":
                kw["obs_call_id"] = "other"
                content = denial
            elif mode == "fabricated":
                kw["drop_obs"] = True
                kw["agent_msg"] = denial
                content = None
            else:
                raise AssertionError(mode)
            return atif_ind(prompt, tname, targs, obs_content=content, **kw)
        nonce = prompt.rstrip().split()[-1]
        d = atif(prompt, tc=[])
        d["steps"][-1]["message"] = nonce
        return d
    return build


class Spawn:
    """Fake _spawn. claude: bytes or callable(input_bytes)->bytes.
    export: callable(prompt)->ATIF dict. models: models-list doc."""

    def __init__(self, claude=None, export=None, versions=None, models=None,
                 mutate=None, rc=0):
        self.claude = claude
        self.export = export
        self.versions = versions or {}
        self.models = MODELS_FREE if models is None else models
        self.mutate = mutate
        self.rc = rc
        self.calls = []

    def __call__(self, argv, env, cwd, timeout, input_bytes=None):
        self.calls.append(list(argv))
        if "--version" in argv:
            name = Path(argv[0]).name
            v = self.versions.get(name, VERSIONS[name])
            return 0, (v + "\n").encode(), b""
        if argv[1:4] == ["models", "list", "--format"]:
            return 0, json.dumps(self.models).encode(), b""
        if self.mutate:
            self.mutate(cwd)
        if "--export" in argv:
            ef = Path(argv[argv.index("--export") + 1])
            pf = Path(argv[argv.index("--prompt-file") + 1])
            ef.write_text(json.dumps(self.export(pf.read_text())))
            return self.rc, b"ok\n", b""
        out = self.claude(input_bytes) if callable(self.claude) else (
            self.claude if self.claude is not None else claude_stream())
        return self.rc, out, b""


def _route_entry(route, binary, cfg, cwd):
    model = infer.ROUTE_DEFAULT_MODEL[route]
    tmpl = (infer._CLAUDE_ARGV_TEMPLATE if route == "claude"
            else infer._DEVIN_ARGV_TEMPLATE)
    e = {"route": route, "available": True, "binary": str(binary),
         "native_cwd": str(cwd),
         "model": model, "models": [model], "version": VERSIONS[route],
         "version_argv": ["--version"], "argv_template": tmpl,
         "argv_digest": digest(canonical(tmpl).encode()),
         "probes": [], "known_context": [],
         "cost_tier": "Free" if route == "devin" else None}
    if route == "devin":
        e["tools_schema_digest"] = infer.DEVIN_TOOLS_DIGEST
        e["config"] = str(cfg)
        e["config_digest"] = digest(cfg.read_bytes())
        e["models_digest"] = digest(canonical(MODELS_FREE).encode())
    e["measurement_digest"] = infer._measurement_digest(e)
    return e


def make_registry(cwd, claude_bin, devin_bin, cfg):
    return {"schema": infer.ROUTES_SCHEMA, "created": 1, "cwd": str(cwd),
            "role_models": {r: [t, m] for r, (t, m) in
                            infer.ROLE_MODELS.items()},
            "routes": {"claude": _route_entry("claude", claude_bin, cfg, cwd),
                       "devin": _route_entry("devin", devin_bin, cfg, cwd)}}


class InferTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(infer, "DEVIN_TOOLS_DIGEST", digest(canonical([]).encode()))
        patch.start()
        self.addCleanup(patch.stop)
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.state, self.cwd, self.call = (root / "state", root / "cwd",
                                           root / "call")
        for d in (self.state, self.cwd, self.call, root / "bin"):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.claude_bin = root / "bin" / "claude"
        self.devin_bin = root / "bin" / "devin"
        for b in (self.claude_bin, self.devin_bin):
            b.write_text("#!/bin/sh\n")
            b.chmod(0o755)
        self.cfg = self.state / "devin-no-tools.json"
        self.cfg.write_text(json.dumps(infer.DEVIN_NO_TOOLS_CONFIG))
        self._write_reg(make_registry(self.cwd, self.claude_bin,
                                      self.devin_bin, self.cfg))
        self.routes = infer.NativeRoutes(self.state)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_reg(self, reg):
        (self.state / "routes.json").write_text(json.dumps(reg))

    def assertCode(self, ctx, code):
        self.assertEqual(code_of(ctx.exception), code)

    def _setup_with(self, claude_fn, export_fn):
        newstate = Path(self.tmp.name) / ("s-" + str(next(self._n)))
        sp = Spawn(claude=claude_fn, export=export_fn)
        with mock.patch.object(infer, "_spawn", sp), \
                mock.patch.object(infer.shutil, "which",
                                  side_effect=lambda n: str(
                                      self.claude_bin if n == "claude"
                                      else self.devin_bin)):
            return infer.setup_routes(newstate, self.cwd), newstate

    _n = iter(range(1000))

    # ---- selection / registry integrity ----

    def test_config_digest_uses_native_normalized_bytes(self):
        normalized = json.loads(self.cfg.read_text())
        normalized.update(version=1, devin={"org_id": "test-existing-account"},
                          shell={"setup_complete": True}, theme_mode="dark")
        self.cfg.write_text(json.dumps(normalized, indent=2) + "\n")
        self.assertEqual(infer._measured_devin_config(self.cfg),
                         digest(self.cfg.read_bytes()))

    def test_config_normalization_never_changes_policy_or_types(self):
        base = json.loads(self.cfg.read_text())
        bad = [[], dict(base, auto_update=True), dict(base, subagents_enabled=0),
               dict(base, permissions={"deny": []}), dict(base, version=True),
               dict(base, shell={"setup_complete": 1}),
               dict(base, devin={"org_id": "test", "api_key": "not-a-secret"}),
               dict(base, theme_mode="unknown"), dict(base, new_permission=True)]
        for value in bad:
            with self.subTest(value=value):
                self.cfg.write_text(json.dumps(value))
                with self.assertRaises(TaskError) as cm:
                    infer._measured_devin_config(self.cfg)
                self.assertCode(cm, "route_unqualified")

    def test_selection(self):
        s = self.routes.selection("implement")
        self.assertEqual(s["route"], "devin")
        self.assertEqual(s["model"], "swe-2-high")
        self.assertEqual(s["reason"], "role_suitability")

    def test_launch_binding_changes_refuse_before_spawn(self):
        for key, value in [("binary", "/usr/bin/false"),
                           ("version_argv", ["--help"]),
                           ("models", ["swe-2-high", "another"]),
                           ("config", "/tmp/changed.json"),
                           ("native_cwd", "/tmp/changed"),
                           ("available", 1), ("measured_at", 42)]:
            with self.subTest(key=key):
                reg = make_registry(self.cwd, self.claude_bin, self.devin_bin, self.cfg)
                reg["routes"]["devin"][key] = value
                self._write_reg(reg)
                with mock.patch.object(infer, "_spawn") as spawn:
                    with self.assertRaises(TaskError) as cm:
                        infer.NativeRoutes(self.state).infer("implement", "x", self.call)
                    self.assertCode(cm, "route_unmeasured")
                    spawn.assert_not_called()

    def test_context_added_after_setup_is_disclosed_at_launch(self):
        path = self.cwd / "AGENTS.md"
        path.write_text("new local context")
        with mock.patch.object(infer, "_spawn", Spawn(claude=claude_stream())):
            result = self.routes.infer("design", "x", self.call)
        self.assertIn(str(path.resolve()), [c["path"] for c in result["evidence"]["known_context"]])
        self.assertTrue(result["evidence"]["context_changed_since_setup"])

    def test_invalid_registry_cwd_and_role_return_fixed_errors(self):
        reg = make_registry(self.cwd, self.claude_bin, self.devin_bin, self.cfg)
        del reg["cwd"]
        self._write_reg(reg)
        with self.assertRaises(TaskError) as cm:
            infer.NativeRoutes(self.state)
        self.assertCode(cm, "route_unmeasured")
        with self.assertRaises(TaskError) as cm:
            self.routes.selection([])
        self.assertCode(cm, "input_invalid")

    def test_unknown_role(self):
        with self.assertRaises(TaskError) as cm:
            self.routes.selection("nope")
        self.assertCode(cm, "input_invalid")

    def test_role_models_tampered(self):
        reg = make_registry(self.cwd, self.claude_bin, self.devin_bin,
                            self.cfg)
        reg["role_models"]["implement"] = ["devin", "swe-2-low"]
        self._write_reg(reg)
        with self.assertRaises(TaskError) as cm:
            infer.NativeRoutes(self.state)
        self.assertCode(cm, "route_unmeasured")

    def test_template_tampered(self):
        reg = make_registry(self.cwd, self.claude_bin, self.devin_bin,
                            self.cfg)
        reg["routes"]["claude"]["argv_template"] = ["{bin}", "--yolo"]
        self._write_reg(reg)
        routes = infer.NativeRoutes(self.state)
        with self.assertRaises(TaskError) as cm:
            routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_unmeasured")

    def test_measurement_digest_tampered(self):
        reg = make_registry(self.cwd, self.claude_bin, self.devin_bin,
                            self.cfg)
        reg["routes"]["claude"]["measurement_digest"] = "sha256:" + "f" * 64
        self._write_reg(reg)
        routes = infer.NativeRoutes(self.state)
        with self.assertRaises(TaskError) as cm:
            routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_unmeasured")

    def test_missing_registry(self):
        with self.assertRaises(TaskError) as cm:
            infer.NativeRoutes(self.cwd / "nope")
        self.assertCode(cm, "route_unmeasured")

    # ---- claude stream ----

    def test_claude_ok(self):
        sp = Spawn(claude=lambda inp: claude_stream(text="echoed"))
        with mock.patch.object(infer, "_spawn", sp):
            r = self.routes.infer("design", "do thing", self.call)
        self.assertEqual(r["text"], "echoed")
        self.assertEqual(r["tool_calls"], 0)
        self.assertEqual(r["evidence"]["api_key_source"], "none")
        argv = [c for c in sp.calls if "--version" not in c][0]
        self.assertNotIn("do thing", argv)  # prompt went via stdin

    def test_claude_missing_init(self):
        with mock.patch.object(infer, "_spawn",
                               Spawn(claude=claude_stream(init=False))):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_failed")

    def test_claude_bad_api_key_source(self):
        bad = claude_stream(api="apiKey")
        with mock.patch.object(infer, "_spawn", Spawn(claude=bad)):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_violation")

    def test_claude_mcp_nonempty(self):
        bad = claude_stream(mcp=[{"name": "m"}])
        with mock.patch.object(infer, "_spawn", Spawn(claude=bad)):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_violation")

    def test_claude_init_tools_nonempty(self):
        bad = claude_stream(tools_init=["exec"])
        with mock.patch.object(infer, "_spawn", Spawn(claude=bad)):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_violation")

    def test_claude_malformed_line(self):
        bad = claude_stream(raw_extra="\n{not json")
        with mock.patch.object(infer, "_spawn", Spawn(claude=bad)):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_failed")

    def test_claude_tool_use(self):
        with mock.patch.object(infer, "_spawn",
                               Spawn(claude=claude_stream(tool_uses=1))):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_violation")

    def test_claude_assistant_model_mismatch(self):
        bad = claude_stream(asst_model="claude-sonnet-4-6")
        with mock.patch.object(infer, "_spawn", Spawn(claude=bad)):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_violation")

    def test_claude_refusal(self):
        bad = claude_stream(text="no", error=True)
        with mock.patch.object(infer, "_spawn", Spawn(claude=bad)):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_refused")

    def test_version_mismatch(self):
        sp = Spawn(claude=claude_stream(), versions={"claude": "9.9.9"})
        with mock.patch.object(infer, "_spawn", sp):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_unmeasured")

    def test_binary_missing(self):
        reg = make_registry(self.cwd, self.claude_bin, self.devin_bin,
                            self.cfg)
        reg["routes"]["claude"]["binary"] = str(self.state / "gone")
        reg["routes"]["claude"]["measurement_digest"] = (
            infer._measurement_digest(reg["routes"]["claude"]))
        self._write_reg(reg)
        routes = infer.NativeRoutes(self.state)
        with self.assertRaises(TaskError) as cm:
            routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_unavailable")

    # ---- devin ATIF (normal path stays strict) ----

    def test_devin_ok(self):
        exp = lambda p: atif(p, tc=[])
        with mock.patch.object(infer, "_spawn", Spawn(export=exp)):
            r = self.routes.infer("implement", "write code", self.call)
        self.assertEqual(r["text"], "implemented")
        self.assertEqual(r["route"], "devin")
        self.assertEqual(r["evidence"]["cost_tier"], "Free")

    def test_devin_prompt_binding_mismatch(self):
        with mock.patch.object(infer, "_spawn",
                               Spawn(export=lambda p: atif("tampered prompt",
                                                           tc=[]))):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("implement", "real prompt", self.call)
        self.assertCode(cm, "route_failed")

    def test_devin_extra_user_message(self):
        exp = lambda p: atif(p, tc=[], extra_user=True)
        with mock.patch.object(infer, "_spawn", Spawn(export=exp)):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("implement", "x", self.call)
        self.assertCode(cm, "route_failed")

    def test_devin_denied_request_still_rejected_normal(self):
        """A denied tool REQUEST is still a violation on a normal call."""
        path = str(self.cwd / "victim.txt")
        prompt = "Read the file at %s and report its contents." % path
        exp = lambda p: atif_ind(
            p, "read", {"file_path": path},
            obs_content="Read access to '%s' was denied. The user needs to "
                        "grant read permission for this directory." % path)
        with mock.patch.object(infer, "_spawn", Spawn(export=exp)):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("implement", prompt, self.call)
        self.assertCode(cm, "route_violation")

    def test_devin_missing_tool_calls(self):
        with mock.patch.object(infer, "_spawn",
                               Spawn(export=lambda p: atif(p))):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("implement", "x", self.call)
        self.assertCode(cm, "route_violation")

    def test_devin_nonempty_tool_calls(self):
        exp = lambda p: atif(p, tc=[{"name": "exec"}])
        with mock.patch.object(infer, "_spawn", Spawn(export=exp)):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("implement", "x", self.call)
        self.assertCode(cm, "route_violation")

    def test_devin_generation_model_mismatch(self):
        exp = lambda p: atif(p, tc=[], gen="swe-2-low")
        with mock.patch.object(infer, "_spawn", Spawn(export=exp)):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("implement", "x", self.call)
        self.assertCode(cm, "route_violation")

    def test_devin_agent_version_mismatch(self):
        exp = lambda p: atif(p, tc=[], version="2999.0.0")
        with mock.patch.object(infer, "_spawn", Spawn(export=exp)):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("implement", "x", self.call)
        self.assertCode(cm, "route_violation")

    def test_devin_paid_model_blocks_before_launch(self):
        paid = {"families": [{"family_uid": "swe-2", "variants": [
            {"model_uid": "swe-2-high", "cost_tier": "Paid"}]}]}
        sp = Spawn(export=lambda p: atif(p, tc=[]), models=paid)
        with mock.patch.object(infer, "_spawn", sp):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("implement", "x", self.call)
        self.assertCode(cm, "route_unmeasured")
        self.assertFalse(any("--export" in c for c in sp.calls))

    def test_devin_model_absent_blocks(self):
        sp = Spawn(export=lambda p: atif(p, tc=[]),
                   models={"families": []})
        with mock.patch.object(infer, "_spawn", sp):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("implement", "x", self.call)
        self.assertCode(cm, "route_unmeasured")

    def test_devin_stale_export_rejected(self):
        (self.call).mkdir(exist_ok=True)
        (self.call / "devin-export.json").write_text("{}")
        sp = Spawn(export=lambda p: atif(p, tc=[]))
        with mock.patch.object(infer, "_spawn", sp):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("implement", "x", self.call)
        self.assertCode(cm, "route_failed")

    # ---- cwd mutation / locking ----

    def test_cwd_mutated_on_failed_call(self):
        def mut(cwd):
            (Path(cwd) / "spawned.txt").write_text("x")
        sp = Spawn(claude=claude_stream(error=True), mutate=mut)
        with mock.patch.object(infer, "_spawn", sp):
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("design", "x", self.call)
        self.assertCode(cm, "route_violation")

    def test_infer_lock_busy(self):
        fd = os.open(str(self.state / "infer.lock"),
                     os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with self.assertRaises(TaskError) as cm:
                self.routes.infer("design", "x", self.call)
            self.assertCode(cm, "route_busy")
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_child_env_strips_secrets(self):
        with mock.patch.dict(os.environ,
                             {"ANTHROPIC_API_KEY": "sk",
                              "OPENAI_API_KEY": "sk",
                              "XDG_CONFIG_HOME": "/tmp/x"}):
            env = infer._child_env()
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("XDG_CONFIG_HOME", env)
        self.assertEqual(env["TERM"], "dumb")

    # ---- real _spawn ----

    def test_spawn_stdin_no_deadlock(self):
        data = b"z" * 300_000
        rc, out, err = infer._spawn(["/bin/cat"], {}, None, 15, data)
        self.assertEqual(rc, 0)
        self.assertEqual(out, data)

    def test_spawn_timeout_kills(self):
        with self.assertRaises(TaskError) as cm:
            infer._spawn(["/bin/sleep", "30"], {}, None, 0.5)
        self.assertCode(cm, "route_timeout")

    def test_spawn_closed_streams_waits_for_successful_leader(self):
        marker = Path(self.tmp.name) / "export-finished"
        command = "exec 1>&- 2>&-; sleep 0.2; touch " + shlex.quote(str(marker))
        rc, out, err = infer._spawn(["/bin/sh", "-c", command],
                                   {"PATH": "/usr/bin:/bin"}, None, 5)
        self.assertEqual((rc, out, err), (0, b"", b""))
        self.assertTrue(marker.is_file())

    def test_spawn_closed_streams_still_times_out(self):
        with self.assertRaises(TaskError) as cm:
            infer._spawn(["/bin/sh", "-c", "exec 1>&- 2>&-; sleep 30"],
                         {"PATH": "/usr/bin:/bin"}, None, 0.2)
        self.assertCode(cm, "route_timeout")

    def test_spawn_overflow(self):
        with self.assertRaises(TaskError) as cm:
            infer._spawn(["/bin/sh", "-c", "cat /dev/zero"], {}, None, 30)
        self.assertCode(cm, "route_overflow")

    def test_spawn_leftover_child_stopped(self):
        marker = Path(self.tmp.name) / "leftover-marker"
        cmd = "(sleep 3; touch %s) & echo done" % marker
        rc, out, _ = infer._spawn(["/bin/sh", "-c", cmd], {}, None, 10)
        self.assertEqual(rc, 0)
        time.sleep(4)
        self.assertFalse(marker.exists())

    # ---- setup ----

    def _claude_echo(self, inp):
        nonce = inp.decode().rstrip().split()[-1]
        return claude_stream(text=nonce)

    def test_setup_no_overwrite(self):
        with self.assertRaises(TaskError) as cm:
            infer.setup_routes(self.state, self.cwd)
        self.assertCode(cm, "route_exists")

    def test_setup_state_inside_cwd_rejected(self):
        with self.assertRaises(TaskError) as cm:
            infer.setup_routes(self.cwd / "st", self.cwd)
        self.assertCode(cm, "input_invalid")

    def test_setup_missing_binary(self):
        newstate = Path(self.tmp.name) / "s2"
        with mock.patch.object(infer.shutil, "which", return_value=None):
            with self.assertRaises(TaskError) as cm:
                infer.setup_routes(newstate, self.cwd)
        self.assertCode(cm, "route_unavailable")

    def test_setup_denial_qualifies_devin(self):
        reg, newstate = self._setup_with(self._claude_echo,
                                         devin_export_factory("deny"))
        dev = reg["routes"]["devin"]
        self.assertTrue(dev["available"])
        kinds = {p.get("kind") for p in dev["probes"]}
        self.assertEqual(kinds & {"read", "write", "exec"},
                         {"read", "write", "exec"})
        for p in dev["probes"]:
            if p.get("kind"):
                self.assertTrue(p["ok"], p)
                self.assertEqual((p["requested"], p["denied"], p["executed"]),
                                 (1, 1, 0))
                self.assertTrue(p["cwd_unchanged"])
                self.assertTrue(p["cwd_restored"])
        leftovers = [p for p in self.cwd.iterdir()
                     if p.name.startswith(".co-route-probe-")]
        self.assertEqual(leftovers, [])
        self.assertFalse((newstate / "route_setup_failure.json").exists())

    def test_setup_read_success_unqualified(self):
        """An executed read exposes the canary nonce -> unqualified."""
        with self.assertRaises(TaskError) as cm:
            self._setup_with(self._claude_echo,
                             devin_export_factory("success"))
        self.assertCode(cm, "route_unqualified")

    def test_setup_wrong_target_unqualified(self):
        with self.assertRaises(TaskError) as cm:
            self._setup_with(self._claude_echo,
                             devin_export_factory("wrong_target"))
        self.assertCode(cm, "route_unqualified")

    def test_setup_missing_observation_unqualified(self):
        with self.assertRaises(TaskError) as cm:
            self._setup_with(self._claude_echo,
                             devin_export_factory("no_obs"))
        self.assertCode(cm, "route_unqualified")

    def test_setup_bad_call_id_unqualified(self):
        with self.assertRaises(TaskError) as cm:
            self._setup_with(self._claude_echo,
                             devin_export_factory("bad_callid"))
        self.assertCode(cm, "route_unqualified")

    def test_setup_fabricated_message_unqualified(self):
        """Denial-looking agent text without a real observation fails."""
        newstate = Path(self.tmp.name) / "s-fab"
        sp = Spawn(claude=self._claude_echo,
                   export=devin_export_factory("fabricated"))
        with mock.patch.object(infer, "_spawn", sp), \
                mock.patch.object(infer.shutil, "which",
                                  side_effect=lambda n: str(
                                      self.claude_bin if n == "claude"
                                      else self.devin_bin)):
            with self.assertRaises(TaskError) as cm:
                infer.setup_routes(newstate, self.cwd)
        self.assertCode(cm, "route_unqualified")
        fail = json.loads(
            (newstate / "route_setup_failure.json").read_text())
        self.assertEqual(fail["code"], "route_unqualified")
        self.assertEqual(fail["route"], "devin")
        self.assertEqual(fail["probe"], "read")
        self.assertEqual(fail["reason"], "observation")
        self.assertFalse((newstate / "routes.json").exists())

    # ---- fake routes ----

    def test_fake_routes(self):
        fr = infer.FakeRoutes({"implement": "done",
                               "review": lambda role, p: "ok"})
        self.assertEqual(fr.infer("implement", "p")["text"], "done")
        self.assertEqual(fr.infer("review", "p")["route"], "fake")
        with self.assertRaises(TaskError):
            fr.infer("design", "p")


if __name__ == "__main__":
    unittest.main()
