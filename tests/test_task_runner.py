"""Deterministic tests for co_v4.task.runner.

FakeRoutes implements .selection/.infer with a .seen log; FakeVerifier
returns scripted results while preserving files.  Git fixture is a real
temporary repo; no network and no real CLI/native invocations.
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from co_v4.task import runner
from co_v4.task import workspace as wsm
from co_v4.task.common import TaskError, digest
from co_v4.task.journal import Journal

GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
           "PATH": os.environ.get("PATH", "")}

CALC = "def add(a, b):\n    return a - b  # buggy\n"
TEST = ("import unittest\nimport calc\n\n"
        "class T(unittest.TestCase):\n"
        "    def test_add(self):\n"
        "        self.assertEqual(calc.add(1, 2), 3)\n")
FIXED = "def add(a, b):\n    return a + b\n"
FIXED2 = "def add(a, b):\n    return a + b\n\n"
NEWMOD = "VALUE = 'NEWMOD-CONTENT'\n"

GOAL = "fix add() so the tests pass; include a design step and an independent review"

PLAN3 = json.dumps({"schema": "co.task-plan/1", "steps": [
    {"id": "s1", "role": "design", "instructions": "design fix", "inputs": []},
    {"id": "s2", "role": "implement", "instructions": "fix add",
     "inputs": ["s1"]},
    {"id": "s3", "role": "review", "instructions": "review",
     "inputs": ["s2"]}]})
PLAN1 = json.dumps({"schema": "co.task-plan/1", "steps": [
    {"id": "s1", "role": "implement", "instructions": "fix add",
     "inputs": []}]})
PLAN_STALE = json.dumps({"schema": "co.task-plan/1", "steps": [
    {"id": "s1", "role": "implement", "instructions": "a", "inputs": []},
    {"id": "s2", "role": "review", "instructions": "r", "inputs": ["s1"]},
    {"id": "s3", "role": "implement", "instructions": "b", "inputs": []}]})
CHANGES = json.dumps({"files": [
    {"path": "calc.py", "content": FIXED}], "summary": "fix add"})
CHANGES2 = json.dumps({"files": [
    {"path": "calc.py", "content": FIXED2}], "summary": "fix add v2"})
CHANGES_NEW = json.dumps({"files": [
    {"path": "calc.py", "content": FIXED},
    {"path": "newmod.py", "content": NEWMOD}], "summary": "fix + new mod"})
CHANGES_BAD = json.dumps({"files": [
    {"path": "calc.py", "content": FIXED},
    {"path": "test_calc.py", "content": "# tampered\n"}],
    "summary": "bad"})
REVIEW_OK = json.dumps({"verdict": "approve", "findings": []})
REVIEW_RC = json.dumps({"verdict": "request_changes", "findings": ["wrong"]})
REVIEW_RC2 = json.dumps({"verdict": "request_changes", "findings": ["still"]})
GARBAGE = "this is not json at all"

ROUTE_OF = {"planner": "claude", "design": "claude",
            "implement": "devin", "review": "claude"}


def _git(repo, *a):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "-C", str(repo), *a], check=True, env=dict(GIT_ENV),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class FakeRoutes:
    def __init__(self, by_role, wrong_model=False):
        self.by_role = {r: list(v) for r, v in by_role.items()}
        self.seen = []
        self.wrong_model = wrong_model

    def selection(self, role):
        return {"route": ROUTE_OF[role], "model": "fake-" + role,
                "reason": "role_suitability",
                "measurement_digest": "sha256:" + "0" * 64}

    def infer(self, role, prompt, call_dir, timeout=900):
        self.seen.append({"role": role, "prompt": prompt})
        q = self.by_role.get(role)
        if not q:
            raise TaskError("route_unmeasured")
        item = q.pop(0)
        if isinstance(item, BaseException):
            raise item
        text = item(prompt) if callable(item) else item
        return {"text": text,
                "model": "WRONG" if self.wrong_model else "fake-" + role,
                "route": ROUTE_OF[role],
                "tool_calls": 0, "evidence": {"fake": True}}


def verifier_seq(results, **mut):
    calls = []

    def v(spec, workspace, task_dir):
        calls.append(str(workspace))
        ok = results[min(len(calls) - 1, len(results) - 1)]
        res = {"exit": 0 if ok else 1, "passed": bool(ok),
               "log": "verify-%d" % len(calls),
               "before": wsm.fingerprint(workspace, spec),
               "after": wsm.fingerprint(workspace, spec),
               "sandbox": "fake"}
        res.update(mut)
        return res
    return v, calls


def make_spec(repo, max_repairs=1, extra_write=()):
    return {"schema": "co.task/1", "goal": GOAL, "repo": str(repo),
            "base": "HEAD", "readable": ["calc.py", "test_calc.py"],
            "writable": ["calc.py"] + list(extra_write),
            "verify": [sys.executable, "-c", "pass"],
            "max_steps": 6, "max_repairs": max_repairs, "call_timeout": 60}


def _d(ev):
    return ev["data"]


@unittest.skipUnless(shutil.which("git"), "git required")
class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp(prefix="co4repo-"))
        _git(self.repo, "init", "-q")
        (self.repo / "calc.py").write_text(CALC)
        (self.repo / "test_calc.py").write_text(TEST)
        (self.repo / "secret.txt").write_text("TOPSECRET-XYZ\n")
        (self.repo / "dirty.txt").write_text("clean\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "init")
        (self.repo / "dirty.txt").write_text("DIRTY-UNCOMMITTED\n")
        (self.repo / "untracked.txt").write_text("UNTRACKED-1\n")
        self.state = Path(tempfile.mkdtemp(prefix="co4state-"))
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
        self.addCleanup(shutil.rmtree, self.state, ignore_errors=True)

    def routes(self, **kw):
        wrong = kw.pop("wrong_model", False)
        d = {"planner": [PLAN3], "design": ["a design"],
             "implement": [CHANGES], "review": [REVIEW_OK]}
        d.update(kw)
        return FakeRoutes(d, wrong_model=wrong)

    def tdir(self, task_id):
        return self.state / "tasks" / task_id

    def events(self, task_id):
        with Journal(self.tdir(task_id)) as j:
            return list(j.events)

    def rewrite_journal(self, task_id, fn):
        jl = list(self.tdir(task_id).rglob("*.jsonl"))
        self.assertTrue(jl)
        p = jl[0]
        evs = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
        evs = fn(evs)
        for i, e in enumerate(evs, 1):
            e["seq"] = i
        p.write_text("".join(json.dumps(e) + "\n" for e in evs))

    def run_ok(self, **kw):
        fr = self.routes(**kw.pop("routes_kw", {}))
        v, _ = verifier_seq([True])
        return runner.run_task(self.state, make_spec(self.repo, **kw),
                               fr, verifier=v), fr

    # -- E2E -----------------------------------------------------------
    def test_e2e_verified(self):
        r, fr = self.run_ok()
        self.assertTrue(r["verified"])
        self.assertEqual(r["status"], "verified")
        self.assertFalse(r["integrated"])
        self.assertTrue(r["workspace_partial"])
        self.assertTrue(r["diff_digest"].startswith("sha256:"))
        ws = Path(r["workspace"])
        self.assertEqual((ws / "calc.py").read_text(), FIXED)
        self.assertEqual((ws / "test_calc.py").read_text(), TEST)
        self.assertEqual([s["role"] for s in fr.seen],
                         ["planner", "design", "implement", "review"])
        # dirty tree + unlisted files untouched
        self.assertEqual((self.repo / "calc.py").read_text(), CALC)
        self.assertEqual((self.repo / "dirty.txt").read_text(),
                         "DIRTY-UNCOMMITTED\n")
        self.assertEqual((self.repo / "untracked.txt").read_text(),
                         "UNTRACKED-1\n")
        allp = "".join(s["prompt"] for s in fr.seen)
        for bad in ("TOPSECRET-XYZ", "DIRTY-UNCOMMITTED", "UNTRACKED-1"):
            self.assertNotIn(bad, allp)
        # design step_done recorded (journal.append role kwarg regression)
        sd = [_d(e) for e in self.events(r["task_id"])
              if e.get("kind") == "step_done"]
        self.assertEqual([x["step_id"] for x in sd], ["s1"])
        rj = json.loads((self.tdir(r["task_id"]) / "result.json").read_text())
        self.assertTrue(rj["verified"])
        self.assertIn("calc.py",
                      (self.tdir(r["task_id"]) / "result.diff").read_text())
        for c in r["calls"]:
            self.assertTrue(c["selection"]["measurement_digest"]
                            .startswith("sha256:"))
            with Journal(self.tdir(r["task_id"])) as journal:
                self.assertEqual(c["text_sha256"],
                                 digest(journal.get_text(c["output"]).encode()))
            self.assertTrue(c["evidence"]["fake"])

    def test_single_implement_step(self):
        r, fr = self.run_ok(routes_kw={"planner": [PLAN1]})
        self.assertTrue(r["verified"])
        self.assertEqual([s["role"] for s in fr.seen],
                         ["planner", "implement"])

    def test_dependent_implementation_verifies_only_completed_work(self):
        plan = json.dumps({"schema": "co.task-plan/1", "steps": [
            {"id": "s1", "role": "implement", "instructions": "prepare", "inputs": []},
            {"id": "s2", "role": "implement", "instructions": "finish", "inputs": ["s1"]}]})
        fr = self.routes(planner=[plan], implement=[CHANGES, CHANGES2])
        observed = []
        def verify(spec, workspace, task_dir):
            observed.append((workspace / "calc.py").read_text())
            return verifier_seq([observed[-1] == FIXED2])[0](spec, workspace, task_dir)
        result = runner.run_task(self.state, make_spec(self.repo), fr, verifier=verify)
        self.assertTrue(result["verified"], result)
        self.assertEqual(result["repairs_used"], 0)
        self.assertEqual(observed, [FIXED2])

    def test_orphan_design_stops_before_spending_worker_calls(self):
        plan = json.loads(PLAN3)
        plan["steps"][1]["inputs"] = []
        fr = self.routes(planner=[json.dumps(plan)])
        result = runner.run_task(self.state, make_spec(self.repo), fr,
                                 verifier=verifier_seq([True])[0])
        self.assertEqual(result["error"]["code"], "plan_invalid")
        self.assertEqual([x["role"] for x in fr.seen], ["planner"])

    def test_sandbox_preflight_failure_spends_no_model_calls(self):
        for code in ("sandbox_unavailable", "verify_executable_blocked"):
            with self.subTest(code=code):
                fr = self.routes()
                with mock.patch.object(runner, "preflight_verifier",
                                       side_effect=TaskError(code)) as probe:
                    result = runner.run_task(self.state, make_spec(self.repo), fr)
                self.assertEqual(result["error"]["code"], code)
                self.assertEqual(fr.seen, [])
                probe.assert_called_once()

    def test_multiple_reviews_rejected_before_worker_calls(self):
        plan = json.loads(PLAN3)
        plan["steps"].append({"id": "s4", "role": "review",
                              "instructions": "second review", "inputs": ["s2"]})
        fr = self.routes(planner=[json.dumps(plan)])
        result = runner.run_task(self.state, make_spec(self.repo), fr,
                                 verifier=verifier_seq([True])[0])
        self.assertEqual(result["error"]["code"], "plan_invalid")
        self.assertEqual([x["role"] for x in fr.seen], ["planner"])

    def test_cached_verify_refuses_current_workspace_drift(self):
        result, fr = self.run_ok()
        task = self.tdir(result["task_id"])
        with Journal(task) as journal:
            st = runner._replay(journal, runner._new_state(), result["task_id"])
            (Path(result["workspace"]) / "calc.py").write_text("changed after test")
            with self.assertRaises(TaskError) as cm:
                runner._verify(journal, task, st["spec"], mock.Mock(), st, "recheck")
            self.assertEqual(cm.exception.code, "workspace_diverged")

    def test_cached_call_refuses_other_role_or_step(self):
        result, fr = self.run_ok()
        task = self.tdir(result["task_id"])
        with Journal(task) as journal:
            st = runner._replay(journal, runner._new_state(), result["task_id"])
            for step, role in [("s9", "implement"), ("s2", "review")]:
                with self.assertRaises(TaskError) as cm:
                    runner._call(journal, task, st["spec"], fr, st, step, "s2", role)
                self.assertEqual(cm.exception.code, "journal_corrupt")

    # -- repair / re-review --------------------------------------------
    def test_rereview_approve(self):
        r, fr = self.run_ok(routes_kw={"implement": [CHANGES, CHANGES2],
                                     "review": [REVIEW_RC, REVIEW_OK]})
        self.assertTrue(r["verified"])
        self.assertEqual(r["repairs_used"], 1)
        roles = [s["role"] for s in fr.seen]
        self.assertEqual(roles.count("implement"), 2)
        self.assertEqual(roles.count("review"), 2)
        self.assertEqual((Path(r["workspace"]) / "calc.py").read_text(),
                         FIXED2)

    def test_rereview_receives_original_findings_and_repair_digests(self):
        finding = json.dumps({"verdict": "request_changes",
                              "findings": ["CHECK-DISTINCTIVE-BOUNDARY-42"]})
        result, fr = self.run_ok(routes_kw={"implement": [CHANGES, CHANGES2],
                                          "review": [finding, REVIEW_OK]})
        self.assertTrue(result["verified"])
        prompt = [x["prompt"] for x in fr.seen if x["role"] == "review"][-1]
        self.assertIn(finding, prompt)
        self.assertIn(digest(finding.encode()), prompt)
        self.assertIn(CHANGES2, prompt)
        self.assertIn(digest(CHANGES2.encode()), prompt)

    def test_rereview_reject(self):
        fr = self.routes(implement=[CHANGES, CHANGES2],
                         review=[REVIEW_RC, REVIEW_RC2])
        v, _ = verifier_seq([True, True, True])
        r = runner.run_task(self.state, make_spec(self.repo), fr, verifier=v)
        self.assertEqual(r["error"]["code"], "review_unresolved")
        self.assertEqual(r["repairs_used"], 1)
        self.assertEqual([s["role"] for s in fr.seen].count("review"), 2)

    def test_resume_after_review_repair_applied(self):
        fr = self.routes(implement=[CHANGES, CHANGES2],
                         review=[REVIEW_RC, REVIEW_OK])
        v, _ = verifier_seq([True])
        original = Journal.append

        def interrupt_after_apply(journal, kind, **data):
            event = original(journal, kind, **data)
            if kind == "apply_done" and data.get("id") == "s2-repair":
                raise KeyboardInterrupt
            return event

        with mock.patch.object(Journal, "append", interrupt_after_apply):
            first = runner.run_task(self.state, make_spec(self.repo), fr, verifier=v)
        self.assertEqual(first["status"], "interrupted")
        before = len(fr.seen)
        resumed = runner.resume_task(self.state, first["task_id"], fr, verifier=v)
        self.assertTrue(resumed["verified"], resumed)
        self.assertEqual(resumed["repairs_used"], 1)
        self.assertEqual([x["role"] for x in fr.seen[before:]], ["review"])
        self.assertEqual((Path(resumed["workspace"]) / "calc.py").read_text(), FIXED2)

    def test_malformed_review_verdict_binds_repaired_output(self):
        result, _ = self.run_ok(routes_kw={"review": [GARBAGE, REVIEW_OK]})
        self.assertTrue(result["verified"])
        self.assertEqual(result["reviews"]["s3"]["call_id"], "s3-repair")
        calls = {e["data"]["call_id"]: e["data"] for e in self.events(result["task_id"])
                 if e["kind"] == "call_done"}
        with Journal(self.tdir(result["task_id"])) as journal:
            self.assertEqual(journal.get_text(calls["s3-repair"]["output"]), REVIEW_OK)

    def test_verify_fail_then_repair(self):
        fr = self.routes(implement=[CHANGES, CHANGES2])
        v, vcalls = verifier_seq([False, True, True])
        r = runner.run_task(self.state, make_spec(self.repo), fr, verifier=v)
        self.assertTrue(r["verified"])
        self.assertEqual(r["repairs_used"], 1)
        self.assertEqual(len(vcalls), 2)

    def test_verify_fail_exhausts_repair(self):
        fr = self.routes(implement=[CHANGES, CHANGES2])
        v, _ = verifier_seq([False, False])
        r = runner.run_task(self.state, make_spec(self.repo), fr, verifier=v)
        self.assertEqual(r["error"]["code"], "verification_failed")
        self.assertEqual(r["repairs_used"], 1)

    def test_repair_spent_later_rc_terminal(self):
        fr = self.routes(implement=[CHANGES, CHANGES2],
                         review=[REVIEW_RC])
        v, _ = verifier_seq([False, True, True])
        r = runner.run_task(self.state, make_spec(self.repo), fr, verifier=v)
        self.assertEqual(r["error"]["code"], "review_unresolved")
        self.assertEqual(r["repairs_used"], 1)

    def test_malformed_output_repair(self):
        fr = self.routes(implement=[GARBAGE, CHANGES])
        v, _ = verifier_seq([True])
        r = runner.run_task(self.state, make_spec(self.repo), fr, verifier=v)
        self.assertTrue(r["verified"])
        self.assertEqual(r["repairs_used"], 1)
        self.assertEqual([s["role"] for s in fr.seen].count("implement"), 2)

    def test_malformed_output_twice_terminal(self):
        fr = self.routes(implement=[GARBAGE, GARBAGE])
        v, _ = verifier_seq([True])
        r = runner.run_task(self.state, make_spec(self.repo), fr, verifier=v)
        self.assertEqual(r["error"]["code"], "output_invalid")

    def test_protected_tamper_repair(self):
        r, fr = self.run_ok(routes_kw={"implement": [CHANGES_BAD, CHANGES]})
        self.assertTrue(r["verified"])
        self.assertEqual(r["repairs_used"], 1)
        self.assertEqual(
            (Path(r["workspace"]) / "test_calc.py").read_text(), TEST)

    def test_malformed_plan(self):
        fr = self.routes(planner=[GARBAGE])
        v, _ = verifier_seq([True])
        r = runner.run_task(self.state, make_spec(self.repo), fr, verifier=v)
        self.assertEqual(r["error"]["code"], "plan_invalid")
        self.assertEqual(r["repairs_used"], 0)
        self.assertEqual(len(fr.seen), 1)

    def test_stale_review_plan_rejected(self):
        fr = self.routes(planner=[PLAN_STALE])
        v, _ = verifier_seq([True])
        r = runner.run_task(self.state, make_spec(self.repo), fr, verifier=v)
        self.assertEqual(r["error"]["code"], "plan_invalid")
        self.assertEqual(len(fr.seen), 1)

    # -- crash / resume --------------------------------------------------
    def test_crash_call_outcome_unknown(self):
        fr = self.routes(review=[KeyboardInterrupt(), REVIEW_OK])
        v, _ = verifier_seq([True])
        r1 = runner.run_task(self.state, make_spec(self.repo), fr, verifier=v)
        self.assertEqual(r1["status"], "interrupted")
        self.assertEqual(len(fr.seen), 4)
        fr2 = self.routes()
        r2 = runner.resume_task(self.state, r1["task_id"], fr2,
                                verifier=verifier_seq([True])[0])
        self.assertEqual(r2["error"]["code"], "call_outcome_unknown")
        self.assertEqual(len(fr2.seen), 0)

    def test_apply_crash_replays_output(self):
        fr = self.routes()
        v, _ = verifier_seq([True])
        orig = wsm.apply_changes

        def boom(*a, **k):
            raise KeyboardInterrupt
        wsm.apply_changes = boom
        try:
            r1 = runner.run_task(self.state, make_spec(self.repo), fr,
                                 verifier=v)
        finally:
            wsm.apply_changes = orig
        self.assertEqual(r1["status"], "interrupted")
        n_impl = [s["role"] for s in fr.seen].count("implement")
        r2 = runner.resume_task(self.state, r1["task_id"], fr,
                                verifier=verifier_seq([True])[0])
        self.assertTrue(r2["verified"])
        self.assertEqual([s["role"] for s in fr.seen].count("implement"),
                         n_impl)  # call_done replayed, not re-sent

    def test_partial_workspace_archived(self):
        # crash before workspace_ready: partial ws preserved, not deleted
        fr = self.routes()
        v, _ = verifier_seq([True])
        orig = wsm.materialize

        def partial(spec, task_dir):
            (Path(task_dir) / "workspace").mkdir()
            (Path(task_dir) / "workspace" / "half.txt").write_text("x")
            raise KeyboardInterrupt
        wsm.materialize = partial
        try:
            r1 = runner.run_task(self.state, make_spec(self.repo), fr,
                                 verifier=v)
        finally:
            wsm.materialize = orig
        self.assertEqual(r1["status"], "interrupted")
        r2 = runner.resume_task(self.state, r1["task_id"], fr,
                                verifier=verifier_seq([True])[0])
        self.assertTrue(r2["verified"])
        partials = list(self.tdir(r1["task_id"]).glob("workspace.partial*"))
        self.assertTrue(partials)
        self.assertEqual((partials[0] / "half.txt").read_text(), "x")

    # -- verify acceptance ------------------------------------------------
    def test_false_passed_nonzero_exit(self):
        fr = self.routes()
        v, _ = verifier_seq([True], exit=1)
        r = runner.run_task(self.state, make_spec(self.repo, max_repairs=0),
                            fr, verifier=v)
        self.assertEqual(r["error"]["code"], "verification_failed")

    def test_verify_after_mismatch(self):
        fr = self.routes()
        v, _ = verifier_seq([True], after={"calc.py": "sha256:bad"})
        r = runner.run_task(self.state, make_spec(self.repo, max_repairs=0),
                            fr, verifier=v)
        self.assertEqual(r["error"]["code"], "verification_failed")

    def test_selection_mismatch(self):
        fr = self.routes(wrong_model=True)
        v, _ = verifier_seq([True])
        r = runner.run_task(self.state, make_spec(self.repo), fr, verifier=v)
        self.assertEqual(r["error"]["code"], "route_violation")

    # -- divergence / integrity -------------------------------------------
    def test_chmod_divergence_status(self):
        r, _ = self.run_ok()
        os.chmod(Path(r["workspace"]) / "calc.py", 0o755)
        st = runner.status_task(self.state, r["task_id"])
        self.assertEqual(st["status"], "failed")
        self.assertEqual(st["error"]["code"], "workspace_diverged")
        self.assertRaises(TaskError, runner.resume_task, self.state,
                          r["task_id"], self.routes(),
                          verifier=verifier_seq([True])[0])

    def test_extra_file_divergence(self):
        r, _ = self.run_ok()
        (Path(r["workspace"]) / "evil.py").write_text("x=1\n")
        st = runner.status_task(self.state, r["task_id"])
        self.assertEqual(st["status"], "failed")

    def test_task_id_validation(self):
        for bad in ("../x", "a" * 31, "Z" * 32, "/etc/passwd",
                    "..%2f..%2f", "", "../" + "a" * 32):
            self.assertRaises(TaskError, runner.status_task,
                              self.state, bad)

    def test_journal_corrupt_line(self):
        r, _ = self.run_ok()
        jl = list(self.tdir(r["task_id"]).rglob("*.jsonl"))
        with open(jl[0], "ab") as f:
            f.write(b'{"seq": 999, "kind": "bogus"')
        self.assertRaises(TaskError, runner.status_task,
                          self.state, r["task_id"])

    def test_dropped_call_started(self):
        r, _ = self.run_ok()

        def drop(evs):
            return [e for e in evs if not (
                e.get("kind") == "call_started"
                and _d(e).get("call_id") == "s2")]
        self.rewrite_journal(r["task_id"], drop)
        self.assertRaises(TaskError, runner.status_task,
                          self.state, r["task_id"])

    def test_duplicate_call_started(self):
        r, _ = self.run_ok()

        def dup(evs):
            out = []
            for e in evs:
                out.append(e)
                if e.get("kind") == "call_started" \
                        and _d(e).get("call_id") == "s2":
                    out.append(dict(e))
            return out
        self.rewrite_journal(r["task_id"], dup)
        self.assertRaises(TaskError, runner.status_task,
                          self.state, r["task_id"])

    def test_output_record_swapped(self):
        r, _ = self.run_ok()

        def swap(evs):
            dones = [e for e in evs if e.get("kind") == "call_done"
                     and _d(e).get("call_id") in ("s1", "s2")]
            dones[0]["data"]["output"], dones[1]["data"]["output"] = \
                dones[1]["data"]["output"], dones[0]["data"]["output"]
            return evs
        self.rewrite_journal(r["task_id"], swap)
        self.assertRaises(TaskError, runner.status_task,
                          self.state, r["task_id"])

    def test_diff_error_fails_not_empty_success(self):
        fr = self.routes()
        v, _ = verifier_seq([True])
        orig = wsm.diff

        def boom(*a, **k):
            raise TaskError("diff_broken")
        wsm.diff = boom
        try:
            r = runner.run_task(self.state, make_spec(self.repo), fr,
                                verifier=v)
        finally:
            wsm.diff = orig
        self.assertFalse(r["verified"])
        self.assertNotEqual(r["status"], "verified")

    # -- context -----------------------------------------------------------
    def test_new_file_in_review_context(self):
        fr = self.routes(implement=[CHANGES_NEW])
        v, _ = verifier_seq([True])
        r = runner.run_task(self.state,
                            make_spec(self.repo, extra_write=["newmod.py"]),
                            fr, verifier=v)
        self.assertTrue(r["verified"])
        rp = [s["prompt"] for s in fr.seen if s["role"] == "review"][0]
        self.assertIn("NEWMOD-CONTENT", rp)
        self.assertIn("newmod.py", rp)
        impl_prompt = [s["prompt"] for s in fr.seen
                       if s["role"] == "implement"][0]
        self.assertIn("does not exist yet", impl_prompt)

    def test_handoff_digest(self):
        r, fr = self.run_ok()
        evs = self.events(r["task_id"])
        started = {_d(e)["call_id"]: _d(e)
                   for e in evs if e.get("kind") == "call_started"}
        for s in fr.seen:
            cid = {"planner": "plan", "design": "s1", "implement": "s2",
                   "review": "s3"}[s["role"]]
            self.assertEqual(started[cid]["prompt_sha256"],
                             digest(s["prompt"].encode("utf-8")))
        review_prompt = [s["prompt"] for s in fr.seen
                         if s["role"] == "review"][0]
        self.assertIn(digest(CHANGES.encode("utf-8")), review_prompt)

    # -- status / misc ------------------------------------------------------
    def test_status_readonly(self):
        r, _ = self.run_ok()
        st = runner.status_task(self.state, r["task_id"])
        self.assertEqual(st["status"], "verified")
        self.assertTrue(st["verified"])
        self.assertFalse(
            (self.tdir(r["task_id"]) / "calls" / "zzz").exists())

    def test_cli_status_needs_no_routes_but_execution_fails_closed(self):
        from co_v4.task import __main__ as cli
        r, _ = self.run_ok()
        registry = self.state / "routes.json"
        def saved():
            return {str(p.relative_to(self.state)): p.read_bytes()
                    for p in self.state.rglob("*") if p.is_file()}
        for content in (None, "broken json", '{"schema":"unknown"}'):
            with self.subTest(registry=content):
                if content is not None:
                    registry.write_text(content)
                    registry.chmod(0o600)
                before = saved()
                buf = io.StringIO()
                with mock.patch.object(cli._infer, "NativeRoutes") as nr, \
                        mock.patch.object(cli.signal, "signal"), \
                        mock.patch("subprocess.run", side_effect=AssertionError("spawn")), \
                        mock.patch("sys.stdout", buf):
                    code = cli.main(["status", "--state-dir", str(self.state),
                                     "--task", r["task_id"]])
                nr.assert_not_called()
                self.assertEqual(code, 0)
                self.assertTrue(json.loads(buf.getvalue())["task"]["verified"])
                for args in (["resume", "--task", r["task_id"]],
                             ["run", "--repo", str(self.repo), "--goal", GOAL,
                              "--read", "calc.py", "--write", "calc.py",
                              "--verify", "/usr/bin/true"]):
                    buf = io.StringIO()
                    with mock.patch.object(cli.signal, "signal"), \
                            mock.patch("subprocess.run", side_effect=AssertionError("spawn")), \
                            mock.patch("sys.stdout", buf):
                        code = cli.main([args[0], "--state-dir", str(self.state),
                                         *args[1:]])
                    self.assertEqual(code, 2)
                    self.assertEqual(json.loads(buf.getvalue())["error"]["code"],
                                     "route_unmeasured" if args[0] == "resume"
                                     else "routing_setup_required")
                self.assertEqual(saved(), before)

    def test_cli_status_without_routes_still_detects_workspace_drift(self):
        from co_v4.task import __main__ as cli
        r, _ = self.run_ok()
        (Path(r["workspace"]) / "calc.py").write_text("changed\n")
        buf = io.StringIO()
        with mock.patch.object(cli.signal, "signal"), mock.patch("sys.stdout", buf):
            code = cli.main(["status", "--state-dir", str(self.state),
                             "--task", r["task_id"]])
        self.assertEqual(code, 0)
        st = json.loads(buf.getvalue())["task"]
        self.assertFalse(st["verified"])
        self.assertEqual(st["error"]["code"], "workspace_diverged")

    def test_state_dir_inside_repo_rejected(self):
        inside = self.repo / "co-state"
        inside.mkdir()
        self.assertRaises(TaskError, runner.run_task, inside,
                          make_spec(self.repo), self.routes(),
                          verifier=verifier_seq([True])[0])

    def test_workspace_diverged_on_resume(self):
        r, _ = self.run_ok()
        (Path(r["workspace"]) / "test_calc.py").write_text("# tampered\n")
        self.assertRaises(TaskError, runner.resume_task, self.state,
                          r["task_id"], self.routes(),
                          verifier=verifier_seq([True])[0])


if __name__ == "__main__":
    unittest.main()
