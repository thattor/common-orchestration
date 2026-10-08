"""Tests for co_v4.task.__main__ covering Task/2 mode/selection contracts.

NativeCandidates / NativeRoutes / runner are mocked; each command must emit
exactly one JSON object on stdout and the SIGTERM handler is patched out so
main() never mutates the real process signal table.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from co_v4.task import __main__ as cli  # noqa: E402


class TaskCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.state = base / "state"
        self.cwd = base / "native"
        self.repo = base / "repo"
        for d in (self.state, self.cwd, self.repo):
            d.mkdir()
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        self.select = stack.enter_context(mock.patch.object(cli, "_select"))
        self.infer = stack.enter_context(mock.patch.object(cli, "_infer"))
        self.runner = stack.enter_context(mock.patch.object(cli, "runner"))
        self.select.setup_candidates.return_value = {"candidates": []}
        self.select.show_catalog.return_value = {"sanitized": True}
        self.infer.setup_routes.return_value = {"routes": []}
        self.runner.run_task.return_value = {"verified": True}
        self.runner.resume_task.return_value = {"verified": True}
        self.runner.status_task.return_value = {"phase": "done"}
        self.runner.task_schema.return_value = "co.task/2"
        self.candidates = self.select.NativeCandidates.return_value
        self.candidates.resolve_targets.return_value = {
            "implement": {"route": "devin", "model": "swe-1"}}

    def invoke(self, argv):
        out, err = io.StringIO(), io.StringIO()
        sig = mock.MagicMock()
        with mock.patch.object(cli, "signal", sig):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(list(argv))
        lines = [ln for ln in out.getvalue().splitlines() if ln.strip()]
        self.assertEqual(1, len(lines),
                         "stdout must carry exactly one JSON object")
        return code, json.loads(lines[0]), sig

    def mark_ready(self):
        (self.state / "routes2.json").write_text("")

    def run_argv(self, *extra):
        return ["run", "--state-dir", str(self.state), "--repo",
                str(self.repo), "--goal", "ship it", *extra]

    def test_setup_defaults_to_native_candidates(self):
        code, out, sig = self.invoke([
            "setup", "--state-dir", str(self.state),
            "--native-cwd", str(self.cwd)])
        self.assertEqual(0, code)
        self.assertEqual({"status": "ok", "routes": {"candidates": []}}, out)
        self.select.setup_candidates.assert_called_once_with(
            self.state, self.cwd, timeout=180)
        self.infer.setup_routes.assert_not_called()
        sig.signal.assert_called_once()
        self.assertIs(sig.signal.call_args.args[1], cli._sigterm)

    def test_setup_legacy_uses_routes_registry(self):
        code, out, _ = self.invoke([
            "setup", "--state-dir", str(self.state),
            "--native-cwd", str(self.cwd), "--legacy", "--timeout", "30"])
        self.assertEqual(0, code)
        self.assertEqual({"status": "ok", "routes": {"routes": []}}, out)
        self.infer.setup_routes.assert_called_once_with(
            self.state, self.cwd, timeout=30)
        self.select.setup_candidates.assert_not_called()

    def test_run_requires_routes2_before_any_task(self):
        code, out, _ = self.invoke(self.run_argv("--verify", "/bin/true"))
        self.assertEqual(2, code)
        self.assertEqual("error", out["status"])
        self.assertEqual("routing_setup_required", out["error"]["code"])
        self.assertEqual(cli._ROUTES2_HELP, out["error"]["help"])
        self.select.NativeCandidates.assert_not_called()
        self.runner.run_task.assert_not_called()

    def test_run_spec_contract(self):
        self.mark_ready()
        code, _, _ = self.invoke(self.run_argv(
            "--base", "main", "--read", "a", "--read", "b", "--write", "c",
            "--max-steps", "6", "--max-repairs", "1", "--call-timeout", "30",
            "--mode", "usage", "--focus", "coding", "--quiet",
            "--model", "implement=devin/swe-1", "--model",
            "review=claude/opus",
            "--verify", "--", "/usr/bin/env", "echo", "--", "-n", "done"))
        self.assertEqual(0, code)
        self.select.NativeCandidates.assert_called_once_with(self.state)
        self.candidates.resolve_targets.assert_called_once_with(
            ["implement=devin/swe-1", "review=claude/opus"])
        self.runner.run_task.assert_called_once()
        state, spec, native = self.runner.run_task.call_args.args
        self.assertEqual(self.state, state)
        self.assertIs(native, self.candidates)
        self.assertEqual({
            "schema": "co.task/3",
            "goal": "ship it",
            "repo": str(Path(str(self.repo)).resolve()),
            "base": "main",
            "readable": ["a", "b"],
            "writable": ["c"],
            "verify": ["/usr/bin/env", "echo", "--", "-n", "done"],
            "max_steps": 6,
            "max_repairs": 1,
            "call_timeout": 30,
            "focus": "coding",
            "announcement": "quiet",
            "selection": {"mode": "usage", "targets":
                          {"implement": {"route": "devin",
                                         "model": "swe-1"}}},
        }, spec)
        self.select.show_catalog.assert_not_called()

    def test_verify_remainder_is_literal(self):
        self.mark_ready()
        code, _, _ = self.invoke(self.run_argv(
            "--verify", "/bin/check", "--mode", "fixed", "--max-steps", "99"))
        self.assertEqual(0, code)
        spec = self.runner.run_task.call_args.args[1]
        self.assertEqual(
            ["/bin/check", "--mode", "fixed", "--max-steps", "99"],
            spec["verify"])
        self.assertEqual("suitability", spec["selection"]["mode"])
        self.assertEqual(6, spec["max_steps"])
        self.assertEqual("standard", spec["announcement"])
        self.assertEqual("architecture_planning", spec["focus"])
        self.candidates.resolve_targets.assert_called_once_with([])

    def test_verify_requires_absolute_path(self):
        self.mark_ready()
        code, out, _ = self.invoke(self.run_argv("--verify", "./local-check"))
        self.assertEqual(2, code)
        self.assertEqual("verify_argv_invalid", out["error"]["code"])
        self.candidates.resolve_targets.assert_not_called()
        self.runner.run_task.assert_not_called()

    def test_corrupt_routes2_reaches_candidates_rejection(self):
        self.select.NativeCandidates.side_effect = \
            cli.TaskError("candidates_corrupt")
        for kind in ("junk_file", "directory", "dangling_symlink"):
            with self.subTest(kind=kind):
                state = Path(self.tmp.name) / f"state-{kind}"
                state.mkdir()
                marker = state / "routes2.json"
                if kind == "junk_file":
                    marker.write_text("{corrupt")
                elif kind == "directory":
                    marker.mkdir()
                else:
                    marker.symlink_to(state / "missing-target")
                code, out, _ = self.invoke([
                    "run", "--state-dir", str(state), "--repo",
                    str(self.repo), "--goal", "g", "--verify", "/bin/true"])
                self.assertEqual(2, code)
                self.assertEqual("candidates_corrupt", out["error"]["code"])
                self.runner.run_task.assert_not_called()

    def test_resume_selects_provider_by_saved_schema(self):
        for schema, provider in (("co.task/1", "legacy"),
                                 ("co.task/2", "candidates"),
                                 ("co.task/3", "candidates")):
            with self.subTest(schema=schema):
                self.runner.reset_mock()
                self.select.reset_mock()
                self.infer.reset_mock()
                self.runner.task_schema.return_value = schema
                code, _, _ = self.invoke([
                    "resume", "--state-dir", str(self.state),
                    "--task", "t1"])
                self.assertEqual(0, code)
                self.runner.task_schema.assert_called_once_with(
                    self.state, "t1")
                if provider == "legacy":
                    self.infer.NativeRoutes.assert_called_once_with(self.state)
                    self.select.NativeCandidates.assert_not_called()
                    native = self.infer.NativeRoutes.return_value
                else:
                    self.select.NativeCandidates.assert_called_once_with(
                        self.state)
                    self.infer.NativeRoutes.assert_not_called()
                    native = self.select.NativeCandidates.return_value
                self.runner.resume_task.assert_called_once_with(
                    self.state, "t1", native)

    def test_resume_unknown_schema_rejected(self):
        self.runner.task_schema.return_value = "co.task/99"
        code, out, _ = self.invoke([
            "resume", "--state-dir", str(self.state), "--task", "t1"])
        self.assertEqual(2, code)
        self.assertEqual("task_schema_unknown", out["error"]["code"])
        self.runner.resume_task.assert_not_called()
        self.select.NativeCandidates.assert_not_called()
        self.infer.NativeRoutes.assert_not_called()

    def test_status_calls_neither_provider(self):
        code, out, _ = self.invoke([
            "status", "--state-dir", str(self.state), "--task", "t1"])
        self.assertEqual(0, code)
        self.assertEqual({"status": "ok", "task": {"phase": "done"}}, out)
        self.runner.status_task.assert_called_once_with(self.state, "t1")
        self.select.NativeCandidates.assert_not_called()
        self.infer.NativeRoutes.assert_not_called()

    def test_routes_add_forwards_and_shows_catalog(self):
        code, out, _ = self.invoke([
            "routes", "add", "--state-dir", str(self.state),
            "--native-cwd", str(self.cwd), "--route", "claude",
            "--model", "opus-4", "--timeout", "30", "--reprobe"])
        self.assertEqual(0, code)
        self.assertEqual({"status": "ok", "routes": {"sanitized": True}}, out)
        self.select.add_candidate.assert_called_once_with(
            self.state, self.cwd, "claude", "opus-4",
            timeout=30, reprobe=True)
        self.select.show_catalog.assert_called_once_with(self.state)

    def test_routes_fit_forwards_degree_none_and_explicit(self):
        code, out, _ = self.invoke([
            "routes", "fit", "--state-dir", str(self.state),
            "--route", "devin", "--model", "swe-1", "--category", "coding",
            "--source-ref", "job/1"])
        self.assertEqual(0, code)
        self.assertEqual({"status": "ok", "routes": {"sanitized": True}}, out)
        self.select.set_fit.assert_called_once_with(
            self.state, "devin", "swe-1", "coding",
            degree=None, origin="prior", source_ref="job/1")
        self.select.show_catalog.assert_called_once_with(self.state)

        code, _, _ = self.invoke([
            "routes", "fit", "--state-dir", str(self.state),
            "--route", "claude", "--model", "opus-4", "--category",
            "research", "--degree", "3", "--origin", "measured",
            "--source-ref", "job/2"])
        self.assertEqual(0, code)
        self.select.set_fit.assert_called_with(
            self.state, "claude", "opus-4", "research",
            degree=3, origin="measured", source_ref="job/2")
        self.assertEqual(2, self.select.set_fit.call_count)

    def test_interrupted_run_reports_interrupted(self):
        self.mark_ready()
        self.runner.run_task.side_effect = KeyboardInterrupt
        code, out, _ = self.invoke(self.run_argv("--verify", "/bin/true"))
        self.assertEqual(130, code)
        self.assertEqual({"status": "interrupted"}, out)


if __name__ == "__main__":
    unittest.main()
