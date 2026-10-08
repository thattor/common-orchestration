import copy
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from co_v4.task import infer, select as m, spec
from co_v4.task.common import TaskError, RouteFailure
from test_task_candidates import _Base, _measured_entry, CLAUDE_MODEL


def _code(exc):
    code = getattr(exc, "code", None)
    if code:
        return code
    return exc.args[0] if exc.args else None


ALLOWED_CODES = (
    "route_unavailable", "route_unmeasured", "measurement_missing",
    "measurement_drift", "route_failed", "route_refused",
    "route_timeout", "route_overflow")
ALLOWED_PAIRS = (
    ("not_started", "preflight"),
    ("not_started", "spawn"),
    ("unknown", "inference"))


class RouteFailureContract(unittest.TestCase):

    def test_is_taskerror_and_preserves_code_outcome_phase(self):
        e = RouteFailure("route_timeout", "unknown", "inference")
        self.assertIsInstance(e, TaskError)
        self.assertEqual(e.code, "route_timeout")
        self.assertEqual(e.outcome, "unknown")
        self.assertEqual(e.phase, "inference")

    def test_accepts_all_contract_codes_and_pairs(self):
        for code in ALLOWED_CODES:
            for outcome, phase in ALLOWED_PAIRS:
                with self.subTest(code=code, outcome=outcome, phase=phase):
                    e = RouteFailure(code, outcome, phase)
                    self.assertEqual(
                        (e.code, e.outcome, e.phase), (code, outcome, phase))

    def test_rejects_out_of_contract_values_with_valueerror(self):
        for bad in ("route_violation", "route_busy", "context_overflow",
                    "input_invalid", "not_a_code", ""):
            with self.subTest(code=bad):
                with self.assertRaises(ValueError):
                    RouteFailure(bad, "not_started", "spawn")
        for pair in (("not_started", "inference"), ("unknown", "spawn"),
                     ("unknown", "preflight"), ("failed", "preflight"),
                     ("", "")):
            with self.subTest(pair=pair):
                with self.assertRaises(ValueError):
                    RouteFailure("route_timeout", pair[0], pair[1])


class SpawnBeforeLaunch(unittest.TestCase):

    def _tmp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        return Path(d.name)

    def test_callback_runs_exactly_once_before_popen(self):
        d = self._tmp()
        marker = d / "cb-done"
        order = []

        def cb():
            order.append("cb")
            marker.write_text("x")

        real_popen = subprocess.Popen

        def tracking(*a, **k):
            order.append("popen")
            return real_popen(*a, **k)

        argv = [sys.executable, "-c",
                "import sys,pathlib;"
                "sys.exit(0 if pathlib.Path(sys.argv[1]).exists() else 7)",
                str(marker)]
        with mock.patch.object(infer.subprocess, "Popen",
                               side_effect=tracking):
            rc, out, err = infer._spawn(argv, dict(os.environ), d, 30,
                                        before_launch=cb)
        self.assertEqual(rc, 0)
        self.assertEqual(order, ["cb", "popen"])

    def test_callback_exception_propagates_and_child_never_runs(self):
        d = self._tmp()
        sentinel = d / "child-ran"
        argv = [sys.executable, "-c",
                "import sys,pathlib;"
                "pathlib.Path(sys.argv[1]).write_text('ran')",
                str(sentinel)]
        boom = TaskError("route_unavailable")

        def cb():
            raise boom

        with self.assertRaises(TaskError) as cm:
            infer._spawn(argv, dict(os.environ), d, 30, before_launch=cb)
        self.assertIs(cm.exception, boom)
        self.assertNotIsInstance(cm.exception, RouteFailure)
        self.assertFalse(sentinel.exists())

        other = RuntimeError("cb boom")

        def cb2():
            raise other

        with self.assertRaises(RuntimeError) as cm2:
            infer._spawn(argv, dict(os.environ), d, 30, before_launch=cb2)
        self.assertIs(cm2.exception, other)
        self.assertFalse(sentinel.exists())

    def test_popen_oserror_wrapping_depends_on_callback(self):
        d = self._tmp()
        argv = [sys.executable, "-c", "pass"]
        with mock.patch.object(infer.subprocess, "Popen",
                               side_effect=OSError("noexec")):
            with self.assertRaises(RouteFailure) as cm:
                infer._spawn(argv, dict(os.environ), d, 30,
                             before_launch=lambda: None)
        e = cm.exception
        self.assertIsInstance(e, TaskError)
        self.assertEqual((e.code, e.outcome, e.phase),
                         ("route_unavailable", "not_started", "spawn"))

        with mock.patch.object(infer.subprocess, "Popen",
                               side_effect=OSError("noexec")):
            with self.assertRaises(TaskError) as cm2:
                infer._spawn(argv, dict(os.environ), d, 30)
        self.assertIs(type(cm2.exception), TaskError)
        self.assertEqual(_code(cm2.exception), "route_unavailable")

    def test_timeout_is_not_reported_as_not_started(self):
        d = self._tmp()
        argv = [sys.executable, "-c", "import time;time.sleep(30)"]
        with self.assertRaises(TaskError) as cm:
            infer._spawn(argv, dict(os.environ), d, 0.5,
                         before_launch=lambda: None)
        e = cm.exception
        self.assertEqual(_code(e), "route_timeout")
        self.assertNotEqual(getattr(e, "outcome", None), "not_started")


    def test_selector_failure_reaps_the_started_process(self):
        procs = []
        real_popen = subprocess.Popen
        def track(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            procs.append(proc)
            return proc
        outcome = None
        try:
            with mock.patch.object(infer.subprocess, "Popen", side_effect=track), \
                    mock.patch.object(infer.selectors, "DefaultSelector",
                                      side_effect=OSError("descriptor failure")):
                with self.assertRaises(OSError):
                    infer._spawn([sys.executable, "-c", "import time;time.sleep(30)"],
                                 dict(os.environ), self._tmp(), 5,
                                 before_launch=lambda: None)
            self.assertEqual(len(procs), 1)
            outcome = procs[0].poll()
            self.assertTrue(all(f.closed for f in
                                (procs[0].stdin, procs[0].stdout, procs[0].stderr)))
        finally:
            for proc in procs:
                if proc.poll() is None:
                    infer._stop_group(proc)
        self.assertIsNotNone(outcome, "post-spawn setup failure left its child running")


class InferPinnedRecovery(_Base):

    def _claude_entry(self):
        return _measured_entry("claude", CLAUDE_MODEL, self.native)

    def _selection(self, entry):
        return {"route": entry["route"], "model": entry["model"],
                "measurement_digest": entry["measurement_digest"]}

    def _spawn_call(self, argv):
        def fake(binary, model, prompt, cwd, env, timeout, call_dir,
                 before_launch=None):
            rc, out, err = infer._spawn(argv, dict(os.environ), cwd, timeout,
                                        before_launch=before_launch)
            if rc != 0:
                raise TaskError("route_failed")
            return {"text": out.decode("utf-8", "replace"),
                    "api_key_source": None}
        return fake

    def _patches(self, call_fake):
        return (mock.patch.object(infer, "_check_launch", lambda e: None),
                mock.patch.object(infer, "_known_context", lambda c: []),
                mock.patch.object(infer, "_call_claude", call_fake))

    def test_success_runs_callback_before_child_and_writes_meta(self):
        entry = self._claude_entry()
        sel = self._selection(entry)
        marker = self.root / "cb-ran"
        calls = []

        def cb():
            calls.append(1)
            marker.write_text("x")

        argv = [sys.executable, "-c",
                "import sys,pathlib;"
                "sys.exit(0 if pathlib.Path(sys.argv[1]).exists() else 9)",
                str(marker)]
        call_dir = self.root / "call-ok"
        p1, p2, p3 = self._patches(self._spawn_call(argv))
        with p1, p2, p3:
            res = infer._infer_pinned(
                self.state, sel, "planner", "do thing", call_dir, 30,
                lambda r, mdl: dict(entry), before_launch=cb)
        self.assertEqual(calls, [1])
        self.assertEqual(res["route"], "claude")
        self.assertEqual(res["model"], CLAUDE_MODEL)
        self.assertTrue((call_dir / "meta.json").is_file())
        self.assertFalse((self.state / "meta.json").exists())
        self.assertNotEqual(call_dir.resolve(), self.state.resolve())
        self.assertNotEqual(call_dir.resolve(),
                            Path(entry["native_cwd"]).resolve())

    def test_preflight_route_error_classification_depends_on_callback(self):
        entry = self._claude_entry()
        sel = self._selection(entry)
        stale = dict(entry)
        stale["measurement_digest"] = "0" * 64
        cb = mock.Mock(name="before_launch")
        p1, p2, p3 = self._patches(
            self._spawn_call([sys.executable, "-c", "pass"]))
        with p1, p2, p3:
            with self.assertRaises(RouteFailure) as cm:
                infer._infer_pinned(
                    self.state, sel, "planner", "p", self.root / "call-pf",
                    30, lambda r, mdl: stale, before_launch=cb)
        e = cm.exception
        self.assertEqual((e.code, e.outcome, e.phase),
                         ("route_unmeasured", "not_started", "preflight"))
        cb.assert_not_called()

        cb2 = mock.Mock(name="before_launch2")
        with mock.patch.object(
                infer, "_check_launch",
                mock.Mock(side_effect=TaskError("route_unavailable"))), \
             mock.patch.object(infer, "_known_context", lambda c: []), \
             mock.patch.object(
                 infer, "_call_claude",
                 self._spawn_call([sys.executable, "-c", "pass"])):
            with self.assertRaises(RouteFailure) as cm2:
                infer._infer_pinned(
                    self.state, sel, "planner", "p", self.root / "call-pf2",
                    30, lambda r, mdl: dict(entry), before_launch=cb2)
        e2 = cm2.exception
        self.assertEqual((e2.code, e2.outcome, e2.phase),
                         ("route_unavailable", "not_started", "preflight"))
        cb2.assert_not_called()

        p1, p2, p3 = self._patches(
            self._spawn_call([sys.executable, "-c", "pass"]))
        with p1, p2, p3:
            with self.assertRaises(TaskError) as cm3:
                infer._infer_pinned(
                    self.state, sel, "planner", "p", self.root / "call-pf3",
                    30, lambda r, mdl: stale)
        self.assertIs(type(cm3.exception), TaskError)
        self.assertEqual(_code(cm3.exception), "route_unmeasured")

    def test_route_error_after_callback_is_unknown_inference(self):
        entry = self._claude_entry()
        sel = self._selection(entry)
        seen = []
        argv = [sys.executable, "-c", "import time;time.sleep(30)"]
        p1, p2, p3 = self._patches(self._spawn_call(argv))
        with p1, p2, p3:
            with self.assertRaises(RouteFailure) as cm:
                infer._infer_pinned(
                    self.state, sel, "planner", "p", self.root / "call-to",
                    0.5, lambda r, mdl: dict(entry),
                    before_launch=lambda: seen.append(1))
        e = cm.exception
        self.assertEqual(_code(e), "route_timeout")
        self.assertEqual((e.outcome, e.phase), ("unknown", "inference"))
        self.assertEqual(seen, [1])

    def test_same_error_code_after_launch_cannot_claim_no_start(self):
        entry = self._claude_entry()
        def fail(*args, before_launch=None):
            before_launch()
            raise TaskError("route_unavailable")
        p1, p2, p3 = self._patches(fail)
        with p1, p2, p3, self.assertRaises(RouteFailure) as cm:
            infer._infer_pinned(self.state, self._selection(entry), "planner",
                                "p", self.root / "after-launch", 30,
                                lambda *args: entry, before_launch=lambda: None)
        self.assertEqual((cm.exception.outcome, cm.exception.phase), ("unknown", "inference"))

    def test_spawn_failure_after_callback_stays_not_started_spawn(self):
        entry = self._claude_entry()
        sel = self._selection(entry)
        seen = []
        argv = [sys.executable, "-c", "pass"]
        p1, p2, p3 = self._patches(self._spawn_call(argv))
        with p1, p2, p3, mock.patch.object(
                infer.subprocess, "Popen", side_effect=OSError("gone")):
            with self.assertRaises(RouteFailure) as cm:
                infer._infer_pinned(
                    self.state, sel, "planner", "p", self.root / "call-sp",
                    30, lambda r, mdl: dict(entry),
                    before_launch=lambda: seen.append(1))
        e = cm.exception
        self.assertEqual((e.code, e.outcome, e.phase),
                         ("route_unavailable", "not_started", "spawn"))
        self.assertEqual(seen, [1])

    def test_hard_route_errors_are_not_reclassified(self):
        entry = self._claude_entry()
        sel = self._selection(entry)
        with infer.PrivateFileLock(Path(self.state) / "infer.lock",
                                   busy_code="route_busy"):
            with self.assertRaises(TaskError) as cm:
                infer._infer_pinned(
                    self.state, sel, "planner", "p", self.root / "call-busy",
                    30, lambda r, mdl: dict(entry),
                    before_launch=lambda: None)
        self.assertEqual(_code(cm.exception), "route_busy")
        self.assertNotIsInstance(cm.exception, RouteFailure)

        def mutate(binary, model, prompt, cwd, env, timeout, call_dir,
                   before_launch=None):
            moved = cwd.parent / (cwd.name + "-moved")
            os.rename(cwd, moved)
            cwd.mkdir(0o700)
            (cwd / "injected").write_text("x")
            return {"text": "ok", "api_key_source": None}

        p1, p2, p3 = self._patches(mutate)
        with p1, p2, p3:
            with self.assertRaises(TaskError) as cm2:
                infer._infer_pinned(
                    self.state, sel, "planner", "p", self.root / "call-mut",
                    30, lambda r, mdl: dict(entry),
                    before_launch=lambda: None)
        self.assertEqual(_code(cm2.exception), "route_violation")
        self.assertNotIsInstance(cm2.exception, RouteFailure)

    def test_callback_exception_passes_through_unchanged(self):
        entry = self._claude_entry()
        sel = self._selection(entry)
        boom = TaskError("route_unavailable")

        def cb():
            raise boom

        argv = [sys.executable, "-c", "pass"]
        p1, p2, p3 = self._patches(self._spawn_call(argv))
        with p1, p2, p3:
            with self.assertRaises(TaskError) as cm:
                infer._infer_pinned(
                    self.state, sel, "planner", "p", self.root / "call-cb",
                    30, lambda r, mdl: dict(entry), before_launch=cb)
        self.assertIs(cm.exception, boom)
        self.assertNotIsInstance(cm.exception, RouteFailure)

        other = RuntimeError("cb boom")

        def cb2():
            raise other

        p1, p2, p3 = self._patches(self._spawn_call(argv))
        with p1, p2, p3:
            with self.assertRaises(RuntimeError) as cm2:
                infer._infer_pinned(
                    self.state, sel, "planner", "p", self.root / "call-cb2",
                    30, lambda r, mdl: dict(entry), before_launch=cb2)
        self.assertIs(cm2.exception, other)
        self.assertNotIsInstance(cm2.exception, RouteFailure)


    def test_postlaunch_oserror_is_unknown_and_callback_error_is_preserved(self):
        entry = self._claude_entry()
        selection = self._selection(entry)
        def success(binary, model, prompt, cwd, env, timeout, call_dir,
                    before_launch=None):
            if before_launch is not None:
                before_launch()
            return {"text": "ok", "api_key_source": None}
        for legacy in (False, True):
            boom = OSError("private metadata write failed")
            p1, p2, p3 = self._patches(success)
            with p1, p2, p3, mock.patch.object(infer, "_write_private", side_effect=boom):
                with self.assertRaises(OSError if legacy else RouteFailure) as caught:
                    infer._infer_pinned(self.state, selection, "planner", "p",
                                        self.root / ("legacy-io" if legacy else "post-io"),
                                        30, lambda *_: dict(entry),
                                        before_launch=None if legacy else lambda: None)
            if legacy:
                self.assertIs(caught.exception, boom)
            else:
                self.assertEqual((caught.exception.code, caught.exception.outcome,
                                  caught.exception.phase),
                                 ("route_failed", "unknown", "inference"))
        boom = OSError("callback write failed")
        def callback():
            raise boom
        p1, p2, p3 = self._patches(success)
        with p1, p2, p3:
            with self.assertRaises(OSError) as caught:
                infer._infer_pinned(self.state, selection, "planner", "p",
                                    self.root / "callback-io", 30,
                                    lambda *_: dict(entry), before_launch=callback)
        self.assertIs(caught.exception, boom)


class CandidatesPins(_Base):

    def test_missing_measurement_does_not_hide_other_eligible_candidate(self):
        self._setup()
        self._drop_measurement("claude/" + CLAUDE_MODEL)
        self.stub.calls.clear()
        with mock.patch.object(infer.subprocess, "Popen",
                               side_effect=AssertionError("options launched a process")):
            options = m.NativeCandidates(self.state).options(
                "planner", "architecture_planning")
        self.assertEqual([(p["route"], p["model"]) for p in options], [self.DEVIN])
        self.assertEqual(self.stub.calls, [])


    def test_options_returns_exact_pins_for_each_eligible_candidate(self):
        self._setup()
        self.stub.calls.clear()
        reg = self._reg()["measurements"]
        self.assertTrue(reg)
        policy = {"mode": "fixed", "targets": {"planner": {"route": "claude", "model": CLAUDE_MODEL}}}
        before = copy.deepcopy(policy)
        with mock.patch.object(infer.subprocess, "Popen", side_effect=AssertionError("options launched a process")):
            opts = m.NativeCandidates(self.state, usage={}).options("planner", "architecture_planning", policy)
        self.assertEqual(policy, before)
        self.assertTrue(all(o["usage"]["remaining_percent"] is None for o in opts))
        self.assertEqual(self.stub.calls, [])
        self.assertTrue(opts)
        by_pair = {}
        for o in opts:
            self.assertIsInstance(o.get("route"), str)
            self.assertIsInstance(o.get("model"), str)
            self.assertIsInstance(o.get("measurement_digest"), str)
            by_pair[(o["route"], o["model"])] = o
        for key, e in reg.items():
            with self.subTest(candidate=key):
                o = by_pair[(e["route"], e["model"])]
                self.assertEqual(o["route"], e["route"])
                self.assertEqual(o["model"], e["model"])
                self.assertEqual(o["measurement_digest"],
                                 e["measurement_digest"])
        opts2 = m.NativeCandidates(self.state).options("planner", "architecture_planning", None)
        self.assertEqual({(o["route"], o["model"]) for o in opts2},
                         set(by_pair))
        self.assertEqual(self.stub.calls, [])

    def test_infer_selected_forwards_optional_before_launch(self):
        self._setup()
        nc = m.NativeCandidates(self.state)
        pin = nc.selection("planner", "architecture_planning", None)
        call_dir = self.root / "call-sel"
        cb = mock.Mock()
        with mock.patch.object(infer, "_infer_pinned", return_value={"text": "t"}) as p:
            nc.infer_selected(pin, "planner", "prompt", call_dir, 30,
                              before_launch=cb)
        self.assertIs(p.call_args.kwargs["before_launch"], cb)
        with mock.patch.object(infer, "_infer_pinned", return_value={"text": "t"}) as p:
            nc.infer_selected(pin, "planner", "prompt", call_dir, 30)
        self.assertEqual(p.call_args.kwargs, {})
        self.assertEqual(p.call_args.args[:6],
                         (nc.state_dir, pin, "planner", "prompt", call_dir, 30))


class SpecTaskV3(unittest.TestCase):
    def _task_doc(self, schema):
        obj = {"schema": schema, "repo": "/tmp/repo", "base_sha": "a" * 40,
               "goal": "g", "readable": ["a.py"], "writable": ["a.py"],
               "verify": ["/bin/true"]}
        if schema != "co.task/1":
            obj.update(focus="coding", selection={"mode": "suitability", "targets": {}})
        return spec.validate_spec(obj)

    def _plan_doc(self, schema="co.task-plan/2", step_role="implement"):
        step = {"id": "s1", "role": step_role, "instructions": "fix a.py", "inputs": []}
        if schema != "co.task-plan/1":
            step["focus"] = "coding"
        return {"schema": schema, "steps": [step]}

    def test_task_versions_accept_minimal_docs(self):
        for schema in ("co.task/1", "co.task/2", "co.task/3"):
            with self.subTest(schema=schema):
                self.assertEqual(self._task_doc(schema)["schema"], schema)
        two, three = self._task_doc("co.task/2"), self._task_doc("co.task/3")
        two.pop("schema"); three.pop("schema")
        self.assertEqual(two, three)

    def test_plan_schema_compat_with_task_versions(self):
        plan2 = self._plan_doc()
        for schema in ("co.task/2", "co.task/3"):
            self.assertEqual(spec.validate_plan(plan2, self._task_doc(schema)), plan2)
        for schema in ("co.task-plan/1", "co.task-plan/3"):
            with self.subTest(schema=schema), self.assertRaises(TaskError) as cm:
                spec.validate_plan(self._plan_doc(schema), self._task_doc("co.task/3"))
            self.assertEqual(cm.exception.code, "plan_invalid")

    def test_planner_is_not_a_valid_plan_step(self):
        with self.assertRaises(TaskError) as cm:
            spec.validate_plan(self._plan_doc(step_role="planner"), self._task_doc("co.task/3"))
        self.assertEqual(cm.exception.code, "plan_invalid")


if __name__ == "__main__":
    unittest.main()
