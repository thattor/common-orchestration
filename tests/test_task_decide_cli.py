"""Noninteractive ``co_v4.task decide`` CLI tests.

Real subprocess coverage for the thin ``decide`` forwarder: it records a
pause decision without constructing Native routes, without routes2.json,
and without resuming the task.  The recovery fixture is reused through
the test_task_recovery module only -- importing its TestCase at module
level would make the unittest loader re-run those tests here.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_task_recovery as fxmod

ROOT = Path(__file__).resolve().parents[1]


def _roles(first_impl):
    """planner plan, then implement fails once and has a retry queued."""
    return {"planner": [fxmod.PLAN_I],
            "implement": [first_impl, fxmod.CHANGES]}


class DecideCliTest(unittest.TestCase):
    def setUp(self):
        self.fx = fxmod.TaskRecoveryTest()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    @staticmethod
    def _env():
        env = {"PYTHONPATH": str(ROOT)}
        for key in ("PATH", "HOME", "TMPDIR", "SYSTEMROOT"):
            if os.environ.get(key):
                env[key] = os.environ[key]
        return env

    def _decide(self, tid, pause_id, sha, option_id, confirm=False):
        argv = [sys.executable, "-B", "-m", "co_v4.task", "decide",
                "--state-dir", str(self.fx.state), "--task", tid,
                "--pause-id", pause_id, "--report-sha256", sha,
                "--option-id", option_id]
        if confirm:
            argv.append("--confirm-override")
        proc = subprocess.run(argv, cwd=str(ROOT), env=self._env(),
                              stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(len(proc.stdout.splitlines()), 1, proc.stdout)
        self.assertEqual(proc.stderr, "")
        return proc, json.loads(proc.stdout)

    def _pause(self, first_impl, spec=None):
        tid = self.fx._paused(_roles(first_impl), spec=spec)
        return tid, self.fx._report(tid)

    def _counts(self):
        return len(self.fx.native.infer_calls), self.fx.native.launches

    @staticmethod
    def _verified(res):
        return res.get("verified") is True

    def test_decide_records_only_then_resume_verifies(self):
        tid, report = self._pause(
            fxmod.common.RouteFailure("route_unavailable", "not_started",
                                      "preflight"))
        self.assertFalse((self.fx.state / "routes2.json").exists())
        opts = [o for o in report["options"]
                if not o.get("requires_override")]
        self.assertTrue(opts, report["options"])
        events0 = self.fx._events(tid)
        counts0 = self._counts()
        proc, out = self._decide(tid, report["pause_id"],
                                 report["report_sha256"],
                                 opts[0]["option_id"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(out, {"status": "decision_recorded",
                               "task_id": tid})
        events1 = self.fx._events(tid)
        self.assertEqual(events1[:len(events0)], events0)
        self.assertEqual(len(events1), len(events0) + 1)
        self.assertEqual(events1[-1]["kind"], "route_decision")
        self.assertEqual(self._counts(), counts0)
        res = fxmod.runner.resume_task(self.fx.state, tid,
                                       self.fx.native,
                                       verifier=self.fx.verifier)
        self.assertTrue(self._verified(res), res)

    def test_fixed_override_requires_flag(self):
        spec = self.fx.spec3()
        spec["selection"] = {"mode": "fixed", "targets": {
            r: {"route": "claude", "model": "claude-fixture"}
            for r in ("planner", "design", "implement", "review")}}
        tid, report = self._pause(
            fxmod.common.RouteFailure("route_unavailable", "not_started",
                                      "preflight"), spec=spec)
        overs = [o for o in report["options"] if o.get("requires_override")]
        self.assertTrue(overs, report["options"])
        over = overs[0]
        snap0 = self.fx._snap()
        proc, out = self._decide(tid, report["pause_id"],
                                 report["report_sha256"],
                                 over["option_id"])
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(out["error"]["code"], "route_decision_invalid")
        self.assertEqual(self.fx._snap(), snap0)
        proc, out = self._decide(tid, report["pause_id"],
                                 report["report_sha256"],
                                 over["option_id"], confirm=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(out["status"], "decision_recorded")
        res = fxmod.runner.resume_task(self.fx.state, tid,
                                       self.fx.native,
                                       verifier=self.fx.verifier)
        self.assertTrue(self._verified(res), res)
        selected = self.fx.native.infer_calls[-1]["pin"]
        self.assertEqual(selected["model"], over["model"])
        self.assertEqual(selected["route"], over["route"])

    def test_stale_digest_and_duplicate_rejected(self):
        tid, report = self._pause(
            fxmod.common.RouteFailure("route_unavailable", "not_started",
                                      "preflight"))
        opt = next(o for o in report["options"]
                   if not o.get("requires_override"))
        snap0 = self.fx._snap()
        proc, out = self._decide(tid, report["pause_id"],
                                 "sha256:" + "0" * 64,
                                 opt["option_id"])
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(out["error"]["code"], "route_decision_invalid")
        self.assertEqual(self.fx._snap(), snap0)
        proc, out = self._decide(tid, report["pause_id"],
                                 report["report_sha256"],
                                 opt["option_id"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        snap1 = self.fx._snap()
        proc, out = self._decide(tid, report["pause_id"],
                                 report["report_sha256"],
                                 opt["option_id"])
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(out["error"]["code"], "route_decision_invalid")
        self.assertEqual(self.fx._snap(), snap1)

    def test_unknown_outcome_cancel_only(self):
        tid, report = self._pause(
            fxmod.common.RouteFailure("route_timeout", "unknown", "inference"))
        self.assertEqual(report.get("outcome"), "unknown")
        cands = report.get("candidates") or []
        self.assertTrue(cands, report)
        snap0 = self.fx._snap()
        counts0 = self._counts()
        bad = cands[0]["option_id"]
        proc, out = self._decide(tid, report["pause_id"],
                                 report["report_sha256"], bad)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(out["error"]["code"], "route_decision_invalid")
        self.assertEqual(self.fx._snap(), snap0)
        proc, out = self._decide(tid, report["pause_id"],
                                 report["report_sha256"], "cancel")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(out["status"], "decision_recorded")
        res = fxmod.runner.resume_task(self.fx.state, tid,
                                       self.fx.native,
                                       verifier=self.fx.verifier)
        self.assertEqual(res["status"], "failed")
        self.assertEqual(res["error"]["code"], "route_decision_cancelled")
        self.assertEqual(res["attempts"][-1]["failure"]["outcome"], "unknown")
        self.assertEqual(self._counts(), counts0)

    def test_terminal_task_rejected(self):
        self.fx._mk({"planner": [fxmod.PLAN_I],
                     "implement": [fxmod.CHANGES]})
        res = self.fx._run()
        self.assertTrue(self._verified(res), res)
        tid = self.fx._tid(res)
        proc, out = self._decide(tid, "none", "sha256:" + "0" * 64,
                                 "cancel")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(out["error"]["code"], "task_already_terminal")


if __name__ == "__main__":
    unittest.main()
