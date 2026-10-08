"""Tests for the co_v4.task pending human route-decision contract.

runner / _select / _infer are mocked; only cli.main(argv) is exercised.
A pause report is answered through a numbered stderr menu only when both
sys.stdin and sys.stderr are TTYs; stdout always carries exactly one JSON
object.  All fixtures stay inside a TemporaryDirectory.
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

SHA = "sha256:" + "ab" * 32
OPT_SWE = {"option_id": "opt-swe", "route": "devin", "model": "swe-fixture",
           "requires_override": False,
           "pin": {"route": "devin", "model": "swe-fixture"}}
OPT_CLAUDE = {"option_id": "opt-claude", "route": "claude",
              "model": "claude-fixture", "requires_override": True,
              "pin": {"route": "claude", "model": "claude-fixture"}}


class _Stdin(io.StringIO):
    """stdin stand-in with controllable isatty() / injectable failure."""

    def __init__(self, text="", tty=True, exc=None):
        super().__init__(text)
        self._tty = tty
        self._exc = exc

    def isatty(self):
        return self._tty

    def readline(self, *args):
        if self._exc is not None:
            raise self._exc
        return super().readline(*args)


class _Stderr(io.StringIO):
    def __init__(self, tty=False):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty


def pending(task_id="t-1", pause_id="pause-1", mode="suitability",
            outcome="not_started", options=(OPT_SWE, OPT_CLAUDE)):
    return {
        "status": "awaiting_decision",
        "task_id": task_id,
        "pause": {
            "pause_id": pause_id,
            "report_sha256": SHA,
            "task_id": task_id,
            "call_id": "call-1",
            "attempt_id": "attempt-1",
            "role": "implement",
            "focus": "coding",
            "selection": {"mode": mode, "route": "devin",
                          "model": "swe-fixture"},
            "outcome": outcome,
            "phase": "preflight" if outcome == "not_started" else "inference",
            "code": "route_unavailable",
            "quota": "unknown",
            "process_outcome": outcome,
            "options": [dict(o) for o in options],
            "candidates": [{"route": "devin", "model": "swe-fixture"},
                           {"route": "claude", "model": "claude-fixture"}],
            "cancel": True,
        },
    }


class TaskRecoveryCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.state = base / "state"
        self.repo = base / "repo"
        for d in (self.state, self.repo):
            d.mkdir()
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        self.select = stack.enter_context(mock.patch.object(cli, "_select"))
        self.infer = stack.enter_context(mock.patch.object(cli, "_infer"))
        self.runner = stack.enter_context(mock.patch.object(cli, "runner"))
        self.runner.run_task.return_value = {"verified": True}
        self.runner.resume_task.return_value = {"verified": True}
        self.runner.status_task.return_value = {"phase": "done"}
        self.runner.task_schema.return_value = "co.task/3"
        self.runner.decide_task.return_value = {"status": "decision_recorded"}
        self.candidates = self.select.NativeCandidates.return_value
        self.candidates.resolve_targets.return_value = {}

    def invoke(self, argv, stdin=None, stderr=None):
        out = io.StringIO()
        err = stderr if stderr is not None else _Stderr(tty=False)
        with mock.patch.object(cli, "signal", mock.MagicMock()):
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                if stdin is None:
                    code = cli.main(list(argv))
                else:
                    with mock.patch.object(sys, "stdin", stdin):
                        code = cli.main(list(argv))
        lines = [ln for ln in out.getvalue().splitlines() if ln.strip()]
        self.assertEqual(1, len(lines),
                         "stdout must carry exactly one JSON object")
        return code, json.loads(lines[0]), err.getvalue()

    def decided(self):
        self.runner.decide_task.assert_called_once()
        call = self.runner.decide_task.call_args
        confirm = call.kwargs.get(
            "confirm_override",
            call.args[5] if len(call.args) > 5 else False)
        return call.args, confirm

    def mark_ready(self):
        (self.state / "routes2.json").write_text("")

    def run_argv(self, *extra):
        return ["run", "--state-dir", str(self.state), "--repo",
                str(self.repo), "--goal", "ship it", *extra]

    def tty_run(self, rep, text, *extra):
        self.runner.run_task.return_value = rep
        argv = extra or ("--verify", "/bin/true")
        return self.invoke(self.run_argv(*argv),
                           stdin=_Stdin(text, tty=True),
                           stderr=_Stderr(tty=True))

    def test_run_spec_uses_task3_schema(self):
        self.mark_ready()
        code, _, _ = self.invoke(self.run_argv("--verify", "/bin/true"))
        self.assertEqual(0, code)
        spec = self.runner.run_task.call_args.args[1]
        self.assertEqual("co.task/3", spec["schema"])
        self.assertEqual("ship it", spec["goal"])

    def test_pending_nontty_returns_75_without_decision(self):
        self.mark_ready()
        rep = pending()
        cases = ((None, None),
                 (_Stdin("1\n", tty=True), _Stderr(tty=False)),
                 (_Stdin("1\n", tty=False), _Stderr(tty=True)))
        for stdin, stderr in cases:
            self.runner.run_task.return_value = rep
            code, out, _ = self.invoke(
                self.run_argv("--verify", "/bin/true"),
                stdin=stdin, stderr=stderr)
            self.assertEqual(75, code)
            self.assertEqual(rep, out)
        self.runner.decide_task.assert_not_called()
        self.runner.resume_task.assert_not_called()

    def test_pending_tty_numbered_choice_decides_then_resumes(self):
        self.mark_ready()
        rep = pending()
        code, out, err = self.tty_run(rep, "1\n")
        self.assertEqual(0, code)
        self.assertEqual({"verified": True}, out)
        args, confirm = self.decided()
        self.assertEqual(
            (self.state, "t-1", "pause-1", SHA, "opt-swe"), args[:5])
        self.assertFalse(confirm)
        self.runner.resume_task.assert_called_once_with(
            self.state, "t-1", self.candidates)
        self.assertIn("swe-fixture", err)
        self.assertIn("claude-fixture", err)
        self.assertLess(len(err), 8192)

    def test_fixed_override_yes_confirms_with_names(self):
        self.mark_ready()
        rep = pending(mode="fixed", options=(OPT_CLAUDE,))
        code, _, err = self.tty_run(rep, "1\nyes\n")
        self.assertEqual(0, code)
        args, confirm = self.decided()
        self.assertEqual("opt-claude", args[4])
        self.assertTrue(confirm)
        self.runner.resume_task.assert_called_once_with(
            self.state, "t-1", self.candidates)
        for text in ("devin", "swe-fixture", "claude", "claude-fixture",
                     "implement", "attempt"):
            self.assertIn(text, err)

    def test_fixed_override_no_or_eof_defers_without_writes(self):
        self.mark_ready()
        rep = pending(mode="fixed", options=(OPT_CLAUDE,))
        for label, text in (("no", "1\nno\n"), ("eof", "1\n")):
            with self.subTest(label):
                self.runner.decide_task.reset_mock()
                self.runner.resume_task.reset_mock()
                code, out, _ = self.tty_run(rep, text)
                self.assertEqual(75, code)
                self.assertEqual(rep, out)
                self.runner.decide_task.assert_not_called()
                self.runner.resume_task.assert_not_called()

    def test_unknown_outcome_has_no_actionable_choice(self):
        self.mark_ready()
        rep = pending(outcome="unknown", options=())
        code, out, err = self.tty_run(rep, "1\n")
        self.assertEqual(75, code)
        self.assertEqual(rep, out)
        self.runner.decide_task.assert_not_called()
        self.runner.resume_task.assert_not_called()
        self.assertIn("unconfirmed", err.lower())

    def test_defer_empty_eof_and_interrupt_leave_pending(self):
        self.mark_ready()
        rep = pending()
        cases = (("eof", _Stdin("", tty=True)),
                 ("empty", _Stdin("\n", tty=True)),
                 ("zero", _Stdin("0\n", tty=True)),
                 ("interrupt", _Stdin(tty=True, exc=KeyboardInterrupt())))
        for label, stdin in cases:
            with self.subTest(label):
                self.runner.decide_task.reset_mock()
                self.runner.resume_task.reset_mock()
                self.runner.run_task.return_value = rep
                code, out, _ = self.invoke(
                    self.run_argv("--verify", "/bin/true"),
                    stdin=stdin, stderr=_Stderr(tty=True))
                self.assertEqual(75, code)
                self.assertEqual(rep, out)
                self.runner.decide_task.assert_not_called()
                self.runner.resume_task.assert_not_called()

    def test_invalid_answer_defers_without_native(self):
        self.mark_ready()
        rep = pending()
        for text in ("bogus\n", "9\n", "1" + " " * 300 + "\n", "1"):
            self.runner.decide_task.reset_mock()
            code, out, _ = self.tty_run(rep, text)
            self.assertEqual(75, code)
            self.assertEqual(rep, out)
            self.runner.decide_task.assert_not_called()
        self.runner.resume_task.assert_not_called()

    def test_quiet_still_shows_decision_prompt(self):
        self.mark_ready()
        code, _, err = self.tty_run(pending(), "1\n",
                                    "--quiet", "--verify", "/bin/true")
        self.assertEqual(0, code)
        self.assertIn("swe-fixture", err)
        self.runner.decide_task.assert_called_once()

    def test_cancel_decides_and_seals_failure(self):
        self.mark_ready()
        self.runner.resume_task.return_value = {
            "status": "failed",
            "error": {"code": "route_decision_cancelled"}}
        code, out, err = self.tty_run(pending(), "c\n")
        self.assertEqual(1, code)
        args, confirm = self.decided()
        self.assertEqual("cancel", args[4])
        self.assertFalse(confirm)
        self.runner.resume_task.assert_called_once_with(
            self.state, "t-1", self.candidates)
        self.assertEqual("route_decision_cancelled", out["error"]["code"])
        self.assertIn("cancel", err.lower())

    def test_new_pause_after_choice_is_not_auto_accepted(self):
        self.mark_ready()
        first, second = pending(pause_id="pause-1"), pending(pause_id="pause-2")
        self.runner.resume_task.return_value = second
        code, out, _ = self.tty_run(first, "1\n0\n")
        self.assertEqual(75, code)
        self.assertEqual(second, out)
        args, _ = self.decided()
        self.assertEqual("pause-1", args[2])
        self.runner.resume_task.assert_called_once()

    def test_status_stays_readonly_on_pending_task(self):
        self.runner.status_task.return_value = pending()
        code, out, _ = self.invoke(
            ["status", "--state-dir", str(self.state), "--task", "t-1"],
            stdin=_Stdin("1\n", tty=True), stderr=_Stderr(tty=True))
        self.assertEqual(0, code)
        self.assertEqual("ok", out["status"])
        self.assertEqual("awaiting_decision", out["task"]["status"])
        self.runner.decide_task.assert_not_called()
        self.runner.resume_task.assert_not_called()

    def test_resume_picks_candidates_for_task2_and_task3(self):
        for schema, native in (
                ("co.task/1", self.infer.NativeRoutes.return_value),
                ("co.task/2", self.candidates),
                ("co.task/3", self.candidates)):
            with self.subTest(schema):
                self.runner.task_schema.return_value = schema
                self.runner.resume_task.reset_mock()
                code, _, _ = self.invoke(
                    ["resume", "--state-dir", str(self.state),
                     "--task", "t-1"])
                self.assertEqual(0, code)
                self.runner.resume_task.assert_called_once_with(
                    self.state, "t-1", native)

    def test_resume_pause_decides_then_resumes_again(self):
        self.runner.task_schema.return_value = "co.task/3"
        self.runner.resume_task.side_effect = [pending(), {"verified": True}]
        code, out, _ = self.invoke(
            ["resume", "--state-dir", str(self.state), "--task", "t-1"],
            stdin=_Stdin("1\n", tty=True), stderr=_Stderr(tty=True))
        self.assertEqual(0, code)
        args, confirm = self.decided()
        self.assertEqual("opt-swe", args[4])
        self.assertFalse(confirm)
        self.assertEqual(2, self.runner.resume_task.call_count)
        self.runner.resume_task.assert_called_with(
            self.state, "t-1", self.candidates)

    def test_resume_pending_nontty_returns_75(self):
        self.runner.task_schema.return_value = "co.task/3"
        self.runner.resume_task.return_value = pending()
        code, out, _ = self.invoke(
            ["resume", "--state-dir", str(self.state), "--task", "t-1"])
        self.assertEqual(75, code)
        self.assertEqual(1, self.runner.resume_task.call_count)
        self.runner.decide_task.assert_not_called()


if __name__ == "__main__":
    unittest.main()
