"""Task/3 pause / decide / resume recovery tests for co_v4.task.runner.

Independent behavioral tests for the approved co.task/3 recovery
contract.  Native3 subclasses the trusted task/2 FakeNative and adds
the v3 protocol surface: ``options(role, focus, policy)`` candidate
pins and the ``before_launch`` callback on ``infer_selected``.  No
native CLI is spawned and there is no network; all git fixtures are
local.  These tests do not subclass TaskModesTest: only the tiny
fixture setup is copied.
"""
import copy
import json
import sys
import tempfile
import unittest
import uuid
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from co_v4.task import runner
from co_v4.task import common
from co_v4.task import recovery
from co_v4.task.common import TaskError, canonical, digest
from co_v4.task.journal import Journal
from test_task_runner import _git, verifier_seq
from test_task_runner import (CALC, TEST, GOAL, CHANGES, CHANGES2,
                              REVIEW_RC, REVIEW_OK, FIXED2)
from test_task_modes import FakeNative, TARGETS, PLAN_I, PLAN_IR


PLAN_II = json.dumps({"schema": "co.task-plan/2", "steps": [
    {"id": "s1", "role": "implement", "instructions": "fix add",
     "inputs": [], "focus": "coding"},
    {"id": "s2", "role": "implement", "instructions": "fix sub",
     "inputs": ["s1"], "focus": "coding"}]})


class _PreKI(KeyboardInterrupt):
    """Interrupt before the launch callback fires."""


class _PostKI(KeyboardInterrupt):
    """Interrupt after the launch callback fired."""


class Native3(FakeNative):
    """Trusted v3 in-process Native.

    ``by_role`` entries may be text (success), RouteFailure, or
    KeyboardInterrupt markers.  A preflight RouteFailure is raised
    without invoking ``before_launch``; any later failure invokes it
    exactly once first.  ``launches`` counts real callback fires and is
    distinct from the inherited ``infer_calls`` entry log.
    """

    def __init__(self, by_role, skip_roles=(), **kw):
        super().__init__(by_role, **kw)
        self.skip_roles = set(skip_roles)
        self.launches = 0

    def _fired(self, role, before_launch):
        if before_launch is not None and role not in self.skip_roles:
            before_launch()
            self.launches += 1

    def options(self, role, focus, policy):
        out = []
        for route, model in (("claude", "claude-fixture"),
                             ("devin", "swe-fixture")):
            pol = copy.deepcopy(policy) or {}
            tgts = dict(pol.get("targets") or {})
            tgts[role] = {"route": route, "model": model}
            pol["targets"] = tgts
            n = len(self.selections)
            out.append(self.selection(role, focus, pol))
            del self.selections[n:]
        return out

    def infer_selected(self, pin, role, prompt, call_dir, timeout=900,
                       before_launch=None):
        q = self.by_role.get(role)
        item = q[0] if q else None
        if isinstance(item, common.RouteFailure):
            q.pop(0)
            if getattr(item, "phase", "") != "preflight":
                self._fired(role, before_launch)
            raise item
        if isinstance(item, KeyboardInterrupt):
            q.pop(0)
            if isinstance(item, _PostKI):
                self._fired(role, before_launch)
            raise item
        self._fired(role, before_launch)
        return super().infer_selected(pin, role, prompt, call_dir,
                                      timeout=timeout)


def _rf(code, outcome, phase):
    return common.RouteFailure(code, outcome, phase)


class TaskRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.repo = root / "repo"
        self.repo.mkdir()
        (self.repo / "calc.py").write_text(CALC)
        (self.repo / "test_calc.py").write_text(TEST)
        _git(self.repo, "init")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-m", "init")
        self.state = root / "state"
        self.state.mkdir(mode=0o700)
        self.verifier, self.vcalls = verifier_seq([True] * 8)
        self.native = None
        self.routes = {}

    def _mk(self, by_role, **kw):
        self.native = Native3(by_role, **kw)
        self.routes = self.native
        return self.native

    def spec3(self):
        return {"schema": "co.task/3", "goal": GOAL,
                "repo": str(self.repo), "base": "HEAD",
                "readable": ["calc.py", "test_calc.py"],
                "writable": ["calc.py"],
                "verify": [sys.executable, "-c", "pass"],
                "max_steps": 6, "max_repairs": 1, "call_timeout": 60,
                "focus": "architecture_planning",
                "announcement": "standard",
                "selection": {"mode": "suitability", "targets": {}}}

    def _run(self, spec=None):
        return runner.run_task(self.state, spec or self.spec3(),
                               self.routes, verifier=self.verifier)

    @staticmethod
    def _tid(res):
        if isinstance(res, str):
            return res
        return res.get("task_id") or res.get("id") or res.get("task")

    def _only_tid(self):
        ids = [p.name for p in (self.state / "tasks").iterdir()
               if p.is_dir()]
        self.assertEqual(len(ids), 1)
        return ids[0]

    def _journal(self, task_id):
        hits = [p for p in self.state.rglob("journal.jsonl")
                if task_id in str(p)]
        self.assertTrue(hits, "journal.jsonl missing for " + str(task_id))
        return hits[0]

    def _events(self, task_id):
        with Journal(self._journal(task_id).parent) as journal:
            return journal.events

    def _kinds(self, task_id):
        return [e.get("kind") for e in self._events(task_id)]

    def _snap(self):
        out = {}
        for p in sorted(self.state.rglob("*")):
            if p.is_file():
                out[str(p.relative_to(self.state))] = \
                    digest(p.read_bytes())
        return out

    def _report(self, task_id):
        report = runner.status_task(self.state, task_id)["pause"]
        self.assertIsInstance(report, dict)
        return report

    def _rewrite_journal(self, task_id, fn):
        path = self._journal(task_id)
        lines = []
        for ln in path.read_text().splitlines():
            if not ln.strip():
                continue
            e = json.loads(ln)
            fn(e)
            lines.append(canonical({"seq": e["seq"],
                                    "kind": e["kind"],
                                    "data": e["data"]}))
        path.write_text("\n".join(lines) + "\n")

    def _paused(self, by_role, spec=None):
        self._mk(by_role)
        res = self._run(spec)
        tid = self._tid(res)
        self.assertEqual(res.get("status"), "awaiting_decision", res)
        return tid

    def test_preflight_failure_pauses_awaiting_decision(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_unavailable", "not_started", "preflight")]})
        st = runner.status_task(self.state, tid)
        self.assertEqual(st.get("status"), "awaiting_decision")
        self.assertFalse(st.get("verified"))
        self.assertTrue(st.get("pause"))
        kinds = self._kinds(tid)
        self.assertNotIn("task_failed", kinds)
        self.assertNotIn("result", kinds)
        self.assertEqual(self.native.launches, 1)

    def test_decide_other_model_then_resume_verified(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_unavailable", "not_started", "preflight"),
            CHANGES]})
        rep = self._report(tid)
        opt = next(o for o in rep["options"]
                   if o["route"] == "claude"
                   and o["model"] == "claude-fixture")
        dec = runner.decide_task(self.state, tid, rep["pause_id"],
                                 rep["report_sha256"], opt["option_id"])
        self.assertEqual(dec.get("status"), "decision_recorded")
        self.assertEqual(len(self.native.infer_calls), 1)
        res = runner.resume_task(self.state, tid, self.routes,
                                 verifier=self.verifier)
        self.assertTrue(res.get("verified"))
        aids = [a.get("attempt_id") for a in res.get("attempts", [])]
        self.assertIn("s1-a1", aids)
        self.assertIn("s1-a2", aids)
        self.assertEqual(self.native.infer_calls[-1]["pin"]["route"],
                         "claude")
        self.assertEqual(self.native.infer_calls[-1]["pin"]["model"],
                         "claude-fixture")

    def test_fixed_choice_requires_confirm(self):
        spec = self.spec3()
        spec["selection"] = {"mode": "fixed", "targets": copy.deepcopy(TARGETS)}
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_unavailable", "not_started", "preflight"),
            CHANGES]}, spec)
        rep = self._report(tid)
        fixed = next(o for o in rep["options"]
                     if o["route"] == "claude"
                     and o["model"] == "claude-fixture")
        self.assertTrue(fixed.get("requires_override"))
        snap = self._snap()
        with self.assertRaises(TaskError):
            runner.decide_task(self.state, tid, rep["pause_id"],
                               rep["report_sha256"], fixed["option_id"])
        self.assertEqual(snap, self._snap())
        dec = runner.decide_task(self.state, tid, rep["pause_id"],
                                 rep["report_sha256"],
                                 fixed["option_id"],
                                 confirm_override=True)
        self.assertEqual(dec.get("status"), "decision_recorded")
        res = runner.resume_task(self.state, tid, self.routes,
                                 verifier=self.verifier)
        self.assertTrue(res.get("verified"))
        self.assertEqual(self.native.infer_calls[-1]["pin"]["route"],
                         "claude")

    def test_override_scoped_to_next_attempt_only(self):
        spec = self.spec3()
        spec["selection"] = {"mode": "fixed", "targets": copy.deepcopy(TARGETS)}
        tid = self._paused({"planner": [PLAN_II], "implement": [
            _rf("route_unavailable", "not_started", "preflight"),
            CHANGES, CHANGES2]}, spec)
        rep = self._report(tid)
        alt = next(o for o in rep["options"] if o["route"] == "claude")
        runner.decide_task(self.state, tid, rep["pause_id"],
                           rep["report_sha256"], alt["option_id"],
                           confirm_override=True)
        res = runner.resume_task(self.state, tid, self.routes,
                                 verifier=self.verifier)
        self.assertTrue(res.get("verified"))
        impl = [c for c in self.native.infer_calls
                if c["role"] == "implement"]
        self.assertEqual(len(impl), 2)
        self.assertEqual(impl[0]["pin"]["route"], "claude")
        self.assertEqual(impl[1]["pin"]["route"], "devin")

    def test_unknown_timeout_candidates_informational(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_timeout", "unknown", "inference"), CHANGES]})
        self.assertEqual(self.native.launches, 2)
        rep = self._report(tid)
        self.assertEqual(rep.get("outcome"), "unknown")
        self.assertEqual(rep["options"], [])
        self.assertEqual(rep["quota"], "unknown")
        cand = rep["candidates"]
        self.assertTrue(cand)
        snap = self._snap()
        with self.assertRaises(TaskError):
            runner.decide_task(self.state, tid, rep["pause_id"],
                               rep["report_sha256"],
                               cand[0]["option_id"],
                               confirm_override=True)
        self.assertEqual(snap, self._snap())
        self.assertEqual(runner.status_task(self.state, tid)["status"],
                         "awaiting_decision")

    def test_pending_resume_and_status_are_noops(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_unavailable", "not_started", "preflight"),
            CHANGES]})
        snap = self._snap()
        runner.status_task(self.state, tid)
        self.assertEqual(snap, self._snap())
        n = len(self._events(tid))
        runner.resume_task(self.state, tid, self.routes,
                           verifier=self.verifier)
        self.assertEqual(len(self._events(tid)), n)
        self.assertEqual(len(self.native.infer_calls), 1)
        self.assertEqual(runner.status_task(self.state, tid)["status"],
                         "awaiting_decision")

    def test_cancel_terminates_without_process_claim(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_timeout", "unknown", "inference"),
            CHANGES]})
        rep = self._report(tid)
        self.assertTrue(rep.get("cancel"))
        dec = runner.decide_task(self.state, tid, rep["pause_id"],
                                 rep["report_sha256"], "cancel")
        self.assertEqual(dec.get("status"), "decision_recorded")
        runner.resume_task(self.state, tid, self.routes,
                           verifier=self.verifier)
        st = runner.status_task(self.state, tid)
        self.assertEqual(st["status"], "failed")
        self.assertEqual(st["error"]["code"], "route_decision_cancelled")
        self.assertEqual(st["attempts"][-1]["failure"]["outcome"], "unknown")
        self.assertEqual(self.native.launches, 2)
        self.assertEqual(len(self.native.infer_calls), 1)
        self.assertFalse(any("process" in k and "stop" in k
                             for k in self._kinds(tid)))

    def test_double_answer_rejected(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_unavailable", "not_started", "preflight"),
            CHANGES]})
        rep = self._report(tid)
        opt = rep["options"][0]
        runner.decide_task(self.state, tid, rep["pause_id"],
                           rep["report_sha256"], opt["option_id"])
        n = len(self._events(tid))
        with self.assertRaises(TaskError):
            runner.decide_task(self.state, tid, rep["pause_id"],
                               rep["report_sha256"], opt["option_id"])
        self.assertEqual(len(self._events(tid)), n)

    def test_invalid_and_stale_choice_rejected(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_unavailable", "not_started", "preflight"),
            CHANGES]})
        rep = self._report(tid)
        snap = self._snap()
        with self.assertRaises(TaskError):
            runner.decide_task(self.state, tid, rep["pause_id"],
                               rep["report_sha256"], "nonexistent")
        with self.assertRaises(TaskError):
            runner.decide_task(self.state, tid, rep["pause_id"],
                               "sha256:" + "0" * 64,
                               rep["options"][0]["option_id"])
        self.assertEqual(snap, self._snap())
        self.assertEqual(len(self.native.infer_calls), 1)

    def test_interrupt_before_launch_then_durable_call_failed(self):
        self._mk({"planner": [PLAN_I],
                  "implement": [_PreKI(), CHANGES]})
        interrupted = self._run()
        self.assertEqual(interrupted["status"], "interrupted")
        tid = self._only_tid()
        runner.resume_task(self.state, tid, self.routes,
                           verifier=self.verifier)
        self.assertTrue(any("call_failed" in k
                            for k in self._kinds(tid)))

    def test_interrupt_after_launch_pauses_unknown(self):
        self._mk({"planner": [PLAN_I],
                  "implement": [_PostKI(), CHANGES]})
        interrupted = self._run()
        self.assertEqual(interrupted["status"], "interrupted")
        tid = self._only_tid()
        self.assertEqual(self.native.launches, 2)
        runner.resume_task(self.state, tid, self.routes,
                           verifier=self.verifier)
        st = runner.status_task(self.state, tid)
        self.assertEqual(st.get("status"), "awaiting_decision")
        self.assertEqual(self._report(tid).get("outcome"), "unknown")

    def test_success_without_callback_is_route_violation(self):
        self._mk({"planner": [PLAN_I], "implement": [CHANGES]},
                 skip_roles=("implement",))
        res = self._run()
        self.assertEqual(res["status"], "failed")
        self.assertEqual(res["error"]["code"], "route_violation")
        tid = self._only_tid()
        self.assertFalse(any("pause" in k for k in self._kinds(tid)))

    def test_forged_report_rejected(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_unavailable", "not_started", "preflight"),
            CHANGES]})
        rep = self._report(tid)
        forged = dict(rep)
        forged["outcome"] = "unknown"
        forged["phase"] = "inference"
        body = {k: v for k, v in forged.items()
                if k != "report_sha256"}
        forged["report_sha256"] = digest(canonical(body).encode())
        def tamper(ev):
            if ev["kind"] == "route_paused":
                ev["data"]["report"] = forged
        self._rewrite_journal(tid, tamper)
        with self.assertRaises(TaskError):
            runner.decide_task(self.state, tid, rep["pause_id"],
                               forged["report_sha256"],
                               rep["options"][0]["option_id"])
        self.assertEqual(len(self.native.infer_calls), 1)

    def test_call_done_tamper_rejected(self):
        self._mk({"planner": [PLAN_I], "implement": [CHANGES]})
        res = self._run()
        self.assertTrue(res.get("verified"))
        tid = self._tid(res)
        self.assertTrue(any(e.get("kind") == "call_done"
                            for e in self._events(tid)))

        def tamper(e):
            if e.get("kind") == "call_done" and \
                    isinstance(e.get("data"), dict):
                e["data"]["model"] = "forged-model"

        self._rewrite_journal(tid, tamper)
        with self.assertRaises(TaskError):
            runner.status_task(self.state, tid)

    def test_task2_run_still_verified_no_pause(self):
        native = FakeNative({"planner": [PLAN_I],
                             "implement": [CHANGES]})
        self.routes = native
        spec = self.spec3()
        spec["schema"] = "co.task/2"
        res = runner.run_task(self.state, spec, self.routes,
                              verifier=self.verifier)
        self.assertTrue(res.get("verified"))
        tid = self._tid(res)
        kinds = self._kinds(tid)
        self.assertFalse(any("pause" in k for k in kinds))
        self.assertFalse(any("launch" in k for k in kinds))


    def test_changed_offered_candidate_requires_fresh_answer(self):
        for change in ("measurement", "fit"):
            with self.subTest(change=change):
                tid = self._paused({"planner": [PLAN_I], "implement": [
                    _rf("route_unavailable", "not_started", "preflight"), CHANGES]})
                report = self._report(tid)
                opt = next(o for o in report["options"] if o["route"] == "claude")
                runner.decide_task(self.state, tid, report["pause_id"],
                                   report["report_sha256"], opt["option_id"])
                original = self.native.options
                def changed(*args):
                    pins = original(*args)
                    for pin in pins:
                        if pin["route"] == "claude":
                            if change == "measurement":
                                pin["measurement_digest"] = digest(b"fresh measurement")
                                pin["environment_ref"] = "native:" + pin["measurement_digest"]
                            else:
                                pin["fit"]["degree"] = 1
                    return pins
                with mock.patch.object(self.native, "options", side_effect=changed):
                    res = runner.resume_task(self.state, tid, self.native,
                                             verifier=self.verifier)
                self.assertEqual(res["status"], "awaiting_decision")
                self.assertNotEqual(res["pause"]["pause_id"], report["pause_id"])
                self.assertEqual(len(self.native.infer_calls), 1)
                snap = self._snap()
                with self.assertRaises(TaskError):
                    runner.decide_task(self.state, tid, report["pause_id"],
                                       report["report_sha256"], opt["option_id"])
                self.assertEqual(snap, self._snap())

    def test_prompt_drift_after_answer_does_not_dispatch(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_unavailable", "not_started", "preflight"), CHANGES]})
        rep = self._report(tid)
        runner.decide_task(self.state, tid, rep["pause_id"],
                           rep["report_sha256"], rep["options"][0]["option_id"])
        original = runner._prompt
        with mock.patch.object(runner, "_prompt", side_effect=lambda *a, **k:
                               original(*a, **k) + "\nchanged context"):
            res = runner.resume_task(self.state, tid, self.native,
                                     verifier=self.verifier)
        self.assertEqual(res["status"], "failed")
        self.assertEqual(len(self.native.infer_calls), 1)
        starts = [e for e in self._events(tid) if e["kind"] == "call_started"]
        self.assertEqual(len(starts), 2)

    def test_launch_marker_cannot_be_relabelled_as_preflight_failure(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_timeout", "unknown", "inference")]})
        def tamper(ev):
            if ev["kind"] == "call_failed":
                ev["data"].update(outcome="not_started", phase="preflight")
            if ev["kind"] == "route_paused":
                rep = ev["data"]["report"]
                rep.update(outcome="not_started", phase="preflight",
                           process_outcome="not_started")
                rep["report_sha256"] = digest(canonical({k: v for k, v in rep.items()
                                                        if k != "report_sha256"}).encode())
        self._rewrite_journal(tid, tamper)
        with self.assertRaises(TaskError):
            runner.status_task(self.state, tid)
        self.assertEqual(self.native.launches, 2)

    def test_unknown_v3_event_is_rejected(self):
        self._mk({"planner": [_PreKI()]})
        result = self._run()
        tid = result["task_id"]
        with Journal(self._journal(tid).parent) as journal:
            journal.append("unrecognized")
        with self.assertRaises(TaskError):
            runner.status_task(self.state, tid)

    def test_other_task_can_finish_while_first_waits(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_unavailable", "not_started", "preflight")]})
        before = self._journal(tid).read_bytes()
        other = Native3({"planner": [PLAN_I], "implement": [CHANGES]})
        result = runner.run_task(self.state, self.spec3(), other,
                                 verifier=self.verifier)
        self.assertTrue(result["verified"])
        self.assertNotEqual(result["task_id"], tid)
        self.assertEqual(self._journal(tid).read_bytes(), before)
        self.assertEqual(runner.status_task(self.state, tid)["status"],
                         "awaiting_decision")


    @staticmethod
    def _fresh_report(report, **changes):
        report = copy.deepcopy(report)
        report.update(changes, pause_id=uuid.uuid4().hex)
        report.pop("report_sha256")
        report["report_sha256"] = digest(canonical(report).encode())
        return report

    def test_forged_pause_after_cancel_is_corrupt(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_unavailable", "not_started", "preflight")]})
        report = self._report(tid)
        runner.decide_task(self.state, tid, report["pause_id"],
                           report["report_sha256"], "cancel")
        with Journal(self._journal(tid).parent) as journal:
            journal.append("route_paused", report=self._fresh_report(report))
        with self.assertRaises(TaskError) as caught:
            runner.status_task(self.state, tid)
        self.assertEqual(caught.exception.code, "journal_corrupt")
        self.assertEqual(self.native.launches, 1)

    def test_other_call_cannot_start_after_cancel(self):
        tid = self._paused({"planner": [PLAN_II], "implement": [
            _rf("route_unavailable", "not_started", "preflight")]})
        report = self._report(tid)
        started = copy.deepcopy(next(e["data"] for e in self._events(tid)
            if e["kind"] == "call_started" and e["data"]["call_id"] == "s1"))
        started.update(step_id="s2", call_id="s2", attempt_id="s2-a1")
        runner.decide_task(self.state, tid, report["pause_id"],
                           report["report_sha256"], "cancel")
        with Journal(self._journal(tid).parent) as journal:
            journal.append("call_started", **started)
        with self.assertRaises(TaskError) as caught:
            runner.status_task(self.state, tid)
        self.assertEqual(caught.exception.code, "journal_corrupt")
        self.assertEqual(self.native.launches, 1)

    def test_completed_call_cannot_change_step_or_role(self):
        self._mk({"planner": [PLAN_I], "implement": [CHANGES]})
        result = self._run()
        self.assertTrue(result["verified"])
        tid = result["task_id"]
        before = self._snap()
        calls = len(self.native.infer_calls)
        task_dir = self._journal(tid).parent
        with Journal(task_dir) as journal:
            st = runner._replay(journal, runner._new_state(), tid)
            for step, role in (("another-step", "planner"), ("plan", "review")):
                with self.subTest(step=step, role=role):
                    with self.assertRaises(TaskError) as caught:
                        recovery.call(journal, task_dir, st["spec"], self.native,
                                      st, step, "plan", role)
                    self.assertEqual(caught.exception.code, "call_context_changed")
        self.assertEqual(len(self.native.infer_calls), calls)
        self.assertEqual(self._snap(), before)

    def test_pause_exception_does_not_expose_mutable_state(self):
        tid = self._paused({"planner": [PLAN_I], "implement": [
            _rf("route_unavailable", "not_started", "preflight")]})
        task_dir = self._journal(tid).parent
        with Journal(task_dir) as journal:
            st = runner._replay(journal, runner._new_state(), tid)
            before = copy.deepcopy(st)
            with self.assertRaises(recovery.RoutePaused) as caught:
                recovery.call(journal, task_dir, st["spec"], self.native,
                              st, "s1", "s1", "implement")
            caught.exception.report["pause_id"] = "edited"
            caught.exception.report["options"][0]["pin"]["model"] = "edited"
            self.assertEqual(st, before)

    def test_pause_for_other_call_cannot_accumulate_grants(self):
        tid = self._paused({"planner": [PLAN_II], "implement": [
            _rf("route_unavailable", "not_started", "preflight")]})
        report = self._report(tid)
        runner.decide_task(self.state, tid, report["pause_id"],
                           report["report_sha256"], report["options"][0]["option_id"])
        with Journal(self._journal(tid).parent) as journal:
            st = runner._replay(journal, runner._new_state(), tid)
            other = copy.deepcopy(st["recovery"]["attempts"]["s1"][-1])
            other.update(call_id="s2", step_id="s2", attempt_id="s2-a1")
            st["recovery"]["attempts"]["s2"] = [other]
            forged = self._fresh_report(report, call_id="s2", step_id="s2",
                                         attempt_id="s2-a1")
            with self.assertRaises(TaskError) as caught:
                recovery.event(journal, st, "route_paused", {"report": forged})
            self.assertEqual(caught.exception.code, "journal_corrupt")
        self.assertEqual(self.native.launches, 1)

    def test_applied_repair_is_reused_after_interruption(self):
        self._mk({"planner": [PLAN_IR], "implement": [CHANGES, CHANGES2],
                  "review": [REVIEW_RC, REVIEW_OK]})
        original = Journal.append

        def interrupt_after_apply(journal, kind, **data):
            event = original(journal, kind, **data)
            if kind == "apply_done" and data.get("id") == "s1-repair":
                raise KeyboardInterrupt
            return event

        with mock.patch.object(Journal, "append", interrupt_after_apply):
            first = self._run()
        self.assertEqual(first["status"], "interrupted")
        count = len(self.native.infer_calls)
        resumed = runner.resume_task(self.state, first["task_id"], self.native,
                                     verifier=self.verifier)
        self.assertTrue(resumed["verified"], resumed)
        self.assertEqual([c["role"] for c in self.native.infer_calls[count:]],
                         ["review"])
        self.assertEqual((Path(resumed["workspace"]) / "calc.py").read_text(), FIXED2)


if __name__ == "__main__":
    unittest.main()
