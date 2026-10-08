"""Task/2 selection-mode integration tests for co_v4.task.runner.

FakeNative is a trusted in-process Native: ``selection(role, focus,
policy)`` returns a complete pin bound to that triple, and
``infer_selected`` returns scripted text with evidence digests bound to
the pin it received.  No native CLI is spawned and there is no network.
Legacy one-arg ``.selection`` / ``.infer`` fail loudly if invoked.
"""
import contextlib
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from co_v4.task import runner
from co_v4.task import __main__ as cli
from co_v4.task import workspace as wsm
from co_v4.task.common import TaskError, canonical, digest
from co_v4.task.journal import Journal
from test_task_runner import _git, verifier_seq
from test_task_runner import CALC, TEST, CHANGES, CHANGES2, GOAL
from test_task_runner import REVIEW_OK, REVIEW_RC



def _md(tag):
    return "sha256:" + hashlib.sha256(tag.encode()).hexdigest()


FOCUSES = ["coding", "review", "research", "architecture_planning",
           "reasoning", "writing", "general"]

TARGETS = {"planner": {"route": "claude", "model": "claude-fixture"},
           "implement": {"route": "devin", "model": "swe-fixture"},
           "review": {"route": "claude", "model": "claude-fixture"}}

PLAN_IR = json.dumps({"schema": "co.task-plan/2", "steps": [
    {"id": "s1", "role": "implement", "instructions": "fix add",
     "inputs": [], "focus": "coding"},
    {"id": "s2", "role": "review", "instructions": "review fix",
     "inputs": ["s1"], "focus": "review"}]})
PLAN_I = json.dumps({"schema": "co.task-plan/2", "steps": [
    {"id": "s1", "role": "implement", "instructions": "fix add",
     "inputs": [], "focus": "coding"}]})
PLAN_NOFOCUS = json.dumps({"schema": "co.task-plan/2", "steps": [
    {"id": "s1", "role": "implement", "instructions": "fix add",
     "inputs": []}]})
PLAN_V1 = json.dumps({"schema": "co.task-plan/1", "steps": [
    {"id": "s1", "role": "implement", "instructions": "fix add",
     "inputs": []}]})
PLAN_RESEARCH = json.dumps({"schema": "co.task-plan/2", "steps": [
    {"id": "s1", "role": "design", "instructions": "explore options",
     "inputs": [], "focus": "research"},
    {"id": "s2", "role": "implement", "instructions": "implement",
     "inputs": ["s1"], "focus": "coding"}]})


class FakeNative:
    ROUTE_OF = {"planner": "claude", "design": "claude",
                "implement": "devin", "review": "claude"}
    MODEL_OF = {"planner": "claude-fixture", "design": "claude-fixture",
                "implement": "swe-fixture", "review": "claude-fixture"}

    def __init__(self, by_role, forbid=(), corrupt=(), force_route=None,
                 force_model=None, infer_model=None, evidence_mode="ok",
                 tool_calls_value=0, mutate_pin=False):
        self.by_role = {r: list(v) for r, v in by_role.items()}
        self.forbid = set(forbid)
        self.corrupt = set(corrupt)
        self.force_route = force_route or {}
        self.force_model = force_model or {}
        self.infer_model = infer_model
        self.evidence_mode = evidence_mode
        self.tool_calls_value = tool_calls_value
        self.mutate_pin = mutate_pin
        self.selections = []   # {"role", "focus", "policy"} per selection
        self.infer_calls = []  # {"role", "prompt", "pin"} per infer
        self.plans = []
        self.focus_calls = 0

    def infer(self, *a, **k):  # legacy v1 protocol must never fire
        raise AssertionError("legacy infer() invoked")

    def supported_focuses(self):
        self.focus_calls += 1
        return list(FOCUSES)

    def validate_plan(self, plan, policy):
        self.plans.append(copy.deepcopy(plan))
        if any(s.get("focus") == "research" for s in plan.get("steps", [])):
            raise TaskError("plan_unfittable")

    def selection(self, role, focus, policy):
        if role in self.forbid:
            raise AssertionError("dormant role selected: " + role)
        tgt = ((policy or {}).get("targets") or {}).get(role) or {}
        md = _md("m:" + role)
        pin = {"route": self.force_route.get(role) or tgt.get("route")
               or self.ROUTE_OF[role],
               "model": self.force_model.get(role) or tgt.get("model")
               or self.MODEL_OF[role],
               "measurement_digest": md,
               "environment_ref": "native:" + md,
               "mode": (policy or {}).get("mode"),
               "reason": "role_suitability",
               "focus": focus,
               "fit": {"degree": 3, "origin": "prior",
                       "source_ref": "fixture://fit"},
               "usage": {"remaining_percent": None,
                         "reason": "native_usage_unsupported",
                         "comparison_group": None,
                         "low_remaining": False, "source_ref": None},
               "catalog_digest": _md("c:" + role),
               "excluded": []}
        self.selections.append({"role": role, "focus": focus,
                                "policy": copy.deepcopy(policy)})
        return pin

    def infer_selected(self, pin, role, prompt, call_dir, timeout=900):
        original = copy.deepcopy(pin)
        self.infer_calls.append({"role": role, "prompt": prompt,
                                 "pin": original})
        if self.mutate_pin:
            pin["model"] = "MUTATED"
            pin["route"] = "mutated-route"
        q = self.by_role.get(role)
        if not q:
            raise TaskError("route_unmeasured")
        item = q.pop(0)
        if isinstance(item, BaseException):
            raise item
        text = item(prompt) if callable(item) else item
        bad = role in self.corrupt
        md = original["measurement_digest"]
        sd = digest(canonical(original).encode())
        if bad and self.evidence_mode == "bad_md":
            md = _md("evil")
        elif bad and self.evidence_mode == "bad_sd":
            sd = _md("evil")
        model = self.infer_model if (bad and self.infer_model) \
            else original["model"]
        return {"text": text, "model": model, "route": original["route"],
                "tool_calls": self.tool_calls_value if bad else 0,
                "evidence": {"measurement_digest": md,
                             "selection_digest": sd}}


class TaskModesTest(unittest.TestCase):
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
        self.verifier, self.vcalls = verifier_seq([True])

    def spec(self, mode="suitability", targets=None,
             announcement="standard"):
        return {"schema": "co.task/2", "goal": GOAL, "repo": str(self.repo),
                "base": "HEAD",
                "readable": ["calc.py", "test_calc.py"],
                "writable": ["calc.py"],
                "verify": [sys.executable, "-c", "pass"],
                "max_steps": 6, "max_repairs": 1, "call_timeout": 60,
                "focus": "architecture_planning",
                "announcement": announcement,
                "selection": {"mode": mode, "targets": targets or {}}}

    @staticmethod
    def _tid(res):
        if isinstance(res, str):
            return res
        return res.get("task_id") or res.get("id") or res.get("task")

    def _journal(self, task_id):
        hits = [p for p in self.state.rglob("journal.jsonl")
                if task_id in str(p)]
        self.assertTrue(hits, "journal.jsonl missing for " + str(task_id))
        return hits[0]

    def _events(self, task_id):
        with Journal(self._journal(task_id).parent) as journal:
            return journal.events

    def _call_events(self, task_id):
        return [e for e in self._events(task_id)
                if e.get("kind") == "call_done"]

    def _sole_task_id(self):
        hits = list(self.state.rglob("journal.jsonl"))
        self.assertEqual(len(hits), 1)
        return hits[0].parent.name

    @staticmethod
    def _find(node, key):
        if isinstance(node, dict):
            if key in node:
                return node
            for v in node.values():
                r = TaskModesTest._find(v, key)
                if r is not None:
                    return r
        elif isinstance(node, list):
            for v in node:
                r = TaskModesTest._find(v, key)
                if r is not None:
                    return r
        return None

    @staticmethod
    def _tree_hash(root):
        h = hashlib.sha256()
        for p in sorted(Path(root).rglob("*")):
            if p.is_file():
                h.update(str(p.relative_to(root)).encode())
                h.update(p.read_bytes())
        return h.hexdigest()

    def _reject_reason(self, fn):
        try:
            return repr(fn())
        except TaskError as e:
            return str(e) + repr(getattr(e, "code", ""))

    def test_modes_finish_with_bound_selections(self):
        for mode in ("suitability", "usage", "fixed"):
            with self.subTest(mode=mode):
                fake = FakeNative({"planner": [PLAN_IR],
                                   "implement": [CHANGES],
                                   "review": [REVIEW_OK]},
                                  forbid={"design"})
                verifier, _ = verifier_seq([True])
                res = runner.run_task(str(self.state),
                                      self.spec(mode, TARGETS),
                                      fake, verifier)
                tid = self._tid(res)
                self.assertEqual(res.get("status"), "verified")
                seq = [(s["role"], s["focus"]) for s in fake.selections]
                self.assertEqual(seq, [("planner", "architecture_planning"),
                                       ("implement", "coding"),
                                       ("review", "review")])
                self.assertEqual([c["role"] for c in fake.infer_calls],
                                 ["planner", "implement", "review"])
                for s in fake.selections:
                    if isinstance(s["policy"], dict):
                        self.assertEqual(s["policy"].get("mode"), mode)
                for c in fake.infer_calls:
                    tgt = TARGETS[c["role"]]
                    self.assertEqual((c["pin"]["route"], c["pin"]["model"]),
                                     (tgt["route"], tgt["model"]))
                prompt = fake.infer_calls[0]["prompt"]
                self.assertIn("focus", prompt)
                self.assertIn('"schema":"co.task-plan/2"', prompt)
                self.assertNotIn('co.task-plan/1', prompt)
                self.assertFalse(prompt.endswith("\n"))
                self.assertNotIn("writable", prompt)
                self.assertNotIn("verify", prompt)
                calls = self._call_events(tid)
                self.assertEqual(len(calls), 3)
                for ev in calls:
                    d = ev["data"]
                    self.assertIn("attempt_id", d)
                    self.assertEqual(d["attempt_id"], d.get("call_id"))
                    pin = self._find(d, "environment_ref")
                    evd = self._find(d, "selection_digest")
                    self.assertIsNotNone(pin)
                    self.assertIsNotNone(evd)
                    self.assertEqual(evd["measurement_digest"],
                                     pin["measurement_digest"])
                    self.assertEqual(evd["selection_digest"],
                                     digest(canonical(pin).encode()))

    def test_quiet_suppresses_progress_not_results(self):
        fake = FakeNative({"planner": [PLAN_I], "implement": [CHANGES]})
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            res = runner.run_task(str(self.state),
                                  self.spec("suitability", TARGETS,
                                            announcement="quiet"),
                                  fake, self.verifier)
        self.assertEqual(buf.getvalue(), "")
        self.assertEqual(res.get("status"), "verified")
        self.assertTrue(self._call_events(self._tid(res)))
        buf2 = io.StringIO()
        fake2 = FakeNative({"planner": [PLAN_I], "implement": [CHANGES]})
        verifier2, _ = verifier_seq([True])
        with contextlib.redirect_stderr(buf2):
            runner.run_task(str(self.state),
                            self.spec("suitability", TARGETS),
                            fake2, verifier2)
        self.assertNotEqual(buf2.getvalue(), "")

    def test_completed_resume_and_read_apis_touch_nothing(self):
        fake = FakeNative({"planner": [PLAN_I], "implement": [CHANGES]})
        res = runner.run_task(str(self.state),
                              self.spec("suitability", TARGETS),
                              fake, self.verifier)
        tid = self._tid(res)
        n_calls = len(self._call_events(tid))
        fake2 = FakeNative({"planner": [PLAN_IR], "implement": [CHANGES2],
                            "review": [REVIEW_OK]},
                           force_model={"implement": "changed"})
        res2 = runner.resume_task(str(self.state), tid, fake2, self.verifier)
        if isinstance(res2, dict):
            self.assertEqual(res2.get("status"), "verified")
        self.assertEqual(fake2.selections, [])
        self.assertEqual(fake2.infer_calls, [])
        self.assertEqual(fake2.focus_calls, 0)
        self.assertEqual(len(self._call_events(tid)), n_calls)
        td = self._journal(tid).parent
        before = self._tree_hash(td)
        self.assertEqual(runner.status_task(str(self.state), tid)["status"],
                         "verified")
        self.assertIn("co.task/2",
                      repr(runner.task_schema(str(self.state), tid)))
        self.assertEqual(before, self._tree_hash(td))

    def test_fixed_requires_targets_for_planned_roles(self):
        targets = {k: v for k, v in TARGETS.items() if k != "review"}
        fake = FakeNative({"planner": [PLAN_IR], "implement": [CHANGES],
                           "review": [REVIEW_OK]})
        res = runner.run_task(str(self.state), self.spec("fixed", targets),
                              fake, self.verifier)
        self.assertEqual(res["error"]["code"], "plan_invalid")
        self.assertNotIn("review",
                         [c["role"] for c in fake.infer_calls])

    def test_cli_resume_missing_or_malformed_registry_emits_json(self):
        fake = FakeNative({"planner": [PLAN_I], "implement": [CHANGES]})
        result = runner.run_task(str(self.state),
                                 self.spec(announcement="quiet"),
                                 fake, self.verifier)
        self.assertTrue(result["verified"])
        for content, expected in ((None, "registry_missing"),
                                  ("{", "json_invalid")):
            with self.subTest(content=content):
                if content is not None:
                    catalog = self.state / "routes2.json"
                    catalog.write_text(content)
                    catalog.chmod(0o600)
                out, err = io.StringIO(), io.StringIO()
                with mock.patch.object(cli, "signal"), \
                        mock.patch.object(cli._infer, "_spawn") as spawn, \
                        contextlib.redirect_stdout(out), \
                        contextlib.redirect_stderr(err):
                    code = cli.main(["resume", "--state-dir", str(self.state),
                                     "--task", result["task_id"]])
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(out.getvalue())["error"]["code"],
                                 expected)
                self.assertEqual(err.getvalue(), "")
                spawn.assert_not_called()
        self.assertTrue(runner.status_task(self.state, result["task_id"])["verified"])

    def test_unregistered_route_pin_rejected_without_explicit_target(self):
        fake = FakeNative({"planner": [PLAN_I], "implement": [CHANGES]},
                          force_route={"planner": "unregistered"})
        result = runner.run_task(str(self.state), self.spec(),
                                 fake, self.verifier)
        self.assertEqual(result["error"]["code"], "route_violation")
        self.assertEqual(fake.infer_calls, [])

    def test_interrupt_then_resume_reports_outcome_unknown(self):
        fake = FakeNative({"planner": [PLAN_I],
                           "implement": [KeyboardInterrupt("boom")]})
        try:
            res = runner.run_task(str(self.state),
                                  self.spec("suitability", TARGETS),
                                  fake, self.verifier)
            tid = self._tid(res)
        except KeyboardInterrupt:
            tid = self._sole_task_id()
        self.assertEqual(runner.status_task(str(self.state), tid)["status"],
                         "interrupted")
        fake2 = FakeNative({"planner": [PLAN_IR], "implement": [CHANGES],
                            "review": [REVIEW_OK]},
                           force_route={"implement": "other"})
        res2 = runner.resume_task(str(self.state), tid, fake2, self.verifier)
        blob = (repr(res2)
                + repr(runner.status_task(str(self.state), tid))
                + repr([e.get("kind") for e in self._events(tid)]))
        self.assertIn("call_outcome_unknown", blob)
        self.assertEqual(fake2.selections, [])
        self.assertEqual(fake2.infer_calls, [])

    def test_crash_during_apply_reuses_recorded_output(self):
        fake = FakeNative({"planner": [PLAN_I], "implement": [CHANGES]})
        orig, armed = wsm.apply_changes, {"on": True}

        def flaky(*a, **k):
            if armed["on"]:
                armed["on"] = False
                raise KeyboardInterrupt("apply crash")
            return orig(*a, **k)

        with mock.patch.object(wsm, "apply_changes", flaky):
            try:
                res = runner.run_task(str(self.state),
                                      self.spec("suitability", TARGETS),
                                      fake, self.verifier)
                tid = self._tid(res)
            except KeyboardInterrupt:
                tid = self._sole_task_id()
        n_calls = len(self._call_events(tid))
        fake2 = FakeNative({})
        res2 = runner.resume_task(str(self.state), tid, fake2, self.verifier)
        if isinstance(res2, dict):
            self.assertEqual(res2.get("status"), "verified")
        self.assertEqual(runner.status_task(str(self.state), tid)["status"],
                         "verified")
        self.assertEqual(fake2.selections, [])
        self.assertEqual(fake2.infer_calls, [])
        self.assertEqual(len(self._call_events(tid)), n_calls)

    def test_journal_semantic_tamper_detected(self):
        cases = {
            "selection_model": lambda d: self._find(
                d, "environment_ref").update({"model": "evil-model"}),
            "attempt_id": lambda d: self._find(
                d, "attempt_id").update({"attempt_id": "evil"}),
            "selection_digest": lambda d: self._find(
                d, "selection_digest").update(
                    {"selection_digest": _md("evil")}),
        }
        for name, mutate in cases.items():
            with self.subTest(field=name):
                fake = FakeNative({"planner": [PLAN_I],
                                   "implement": [CHANGES]})
                verifier, _ = verifier_seq([True])
                res = runner.run_task(str(self.state),
                                      self.spec("suitability", TARGETS),
                                      fake, verifier)
                tid = self._tid(res)
                jf = self._journal(tid)
                evs = [json.loads(l) for l in
                       jf.read_text().splitlines() if l.strip()]
                idx = next(i for i, e in enumerate(evs)
                           if e.get("kind") == "call_done")
                mutate(evs[idx]["data"])
                jf.write_text("".join(canonical(e) + "\n" for e in evs))
                blob = self._reject_reason(
                    lambda: runner.status_task(str(self.state), tid))
                self.assertIn("journal_corrupt", blob)

    def test_targets_enforced_against_malicious_pin(self):
        for mode in ("suitability", "usage"):
            with self.subTest(mode=mode):
                fake = FakeNative({"planner": [PLAN_IR],
                                   "implement": [CHANGES],
                                   "review": [REVIEW_OK]},
                                  force_route={"implement": "evil-route"},
                                  force_model={"implement": "evil-model"})
                verifier, _ = verifier_seq([True])
                blob = self._reject_reason(lambda: runner.run_task(
                    str(self.state), self.spec(mode, TARGETS),
                    fake, verifier))
                self.assertIn("route_violation", blob)
                self.assertEqual([c["role"] for c in fake.infer_calls],
                                 ["planner"])

    def test_infer_actuals_mismatch_rejected(self):
        cases = {"model": {"infer_model": "WRONG"},
                 "measurement_digest": {"evidence_mode": "bad_md"},
                 "selection_digest": {"evidence_mode": "bad_sd"},
                 "tool_calls": {"tool_calls_value": False}}
        for name, kw in cases.items():
            with self.subTest(field=name):
                fake = FakeNative({"planner": [PLAN_I],
                                   "implement": [CHANGES]},
                                  corrupt={"implement"}, **kw)
                verifier, _ = verifier_seq([True])
                try:
                    res = runner.run_task(str(self.state),
                                          self.spec("suitability", TARGETS),
                                          fake, verifier)
                except TaskError:
                    res = None
                if res is not None:
                    self.assertNotEqual(res.get("status"), "verified")
                self.assertEqual([c["role"] for c in fake.infer_calls],
                                 ["planner", "implement"])

    def test_plan_focus_and_schema_enforced(self):
        for name, plan in (("missing_focus", PLAN_NOFOCUS),
                           ("legacy_plan", PLAN_V1)):
            with self.subTest(plan=name):
                fake = FakeNative({"planner": [plan],
                                   "implement": [CHANGES]})
                verifier, _ = verifier_seq([True])
                res = runner.run_task(str(self.state),
                                      self.spec("suitability", TARGETS),
                                      fake, verifier)
                self.assertEqual(res["error"]["code"], "plan_invalid")
                self.assertEqual([c["role"] for c in fake.infer_calls],
                                 ["planner"])

    def test_plan_unfittable_stops_before_work(self):
        fake = FakeNative({"planner": [PLAN_RESEARCH], "design": [],
                           "implement": [CHANGES]})
        verifier, _ = verifier_seq([True])
        blob = self._reject_reason(lambda: runner.run_task(
            str(self.state), self.spec("suitability", TARGETS),
            fake, verifier))
        self.assertIn("plan_unfittable", blob)
        self.assertEqual([c["role"] for c in fake.infer_calls], ["planner"])

    def test_pin_mutation_does_not_corrupt_journal(self):
        fake = FakeNative({"planner": [PLAN_I], "implement": [CHANGES]},
                          mutate_pin=True)
        res = runner.run_task(str(self.state),
                              self.spec("suitability", TARGETS),
                              fake, self.verifier)
        self.assertEqual(res.get("status"), "verified")
        ev = self._call_events(self._tid(res))[-1]
        pin = self._find(ev["data"], "environment_ref")
        self.assertEqual((pin["route"], pin["model"]),
                         ("devin", "swe-fixture"))

    def test_repair_preserves_plan_step_focus(self):
        verifier, vcalls = verifier_seq([False, True])
        fake = FakeNative({"planner": [PLAN_IR],
                           "implement": [CHANGES, CHANGES2],
                           "review": [REVIEW_OK]})
        res = runner.run_task(str(self.state),
                              self.spec("suitability", TARGETS),
                              fake, verifier)
        self.assertEqual(res.get("status"), "verified")
        self.assertEqual(len(fake.selections), len(fake.infer_calls))
        foci = {}
        for s in fake.selections:
            foci.setdefault(s["role"], set()).add(s["focus"])
        self.assertEqual(foci.get("implement"), {"coding"})
        self.assertEqual(foci.get("review"), {"review"})
        impl = [c for c in fake.infer_calls if c["role"] == "implement"]
        self.assertLessEqual(len(impl), 2)  # bounded by max_repairs
        self.assertEqual(len(vcalls), 2)


if __name__ == "__main__":
    unittest.main()
