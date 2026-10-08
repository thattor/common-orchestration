"""Contract tests for co_v4.task.select (CO #199).

Synthetic fixtures only. Every Native boundary is stubbed: ``_measure``
is replaced by a builder producing well-formed measured entries, and
the infer-time launch/dispatch helpers are patched out. No Native CLI
is spawned and no network is used. Fixture versions/digests are
synthetic and make no real qualification claims.
"""

import fcntl
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import co_v4.task.select as m
from co_v4.task import admission, infer
from co_v4.task.common import TaskError, canonical, digest

CLAUDE_MODEL = "claude-opus-5-5"
DEVIN_MODEL = "swe-2-high"
CLAUDE_FIT = {"architecture_planning": 3, "coding": 2, "writing": 3, "review": 3,
              "reasoning": 3, "general": 2}
DEVIN_FIT = {"coding": 3, "architecture_planning": 2, "writing": 1, "review": 2,
             "reasoning": 2, "general": 2}
PRESET_SOURCE = "https://github.com/thattor/ai-company/issues/199#issuecomment-6049204846"
FIXED_TIME = 1_700_000_000


def _measured_entry(route, model, cwd, version="0.1.0-test",
                    measured_at=FIXED_TIME):
    """A real-shaped entry whose digests are computed by the product's
    own infer helpers (synthetic fixture, not a real qualification)."""
    tmpl = (infer._CLAUDE_ARGV_TEMPLATE if route == "claude"
            else infer._DEVIN_ARGV_TEMPLATE)
    entry = {
        "route": route,
        "version": version,
        "model": model,
        "binary": "/usr/bin/true",
        "version_argv": ["--version"],
        "models": [model],
        "native_cwd": str(cwd),
        "available": True,
        "measured_at": measured_at,
        "argv_template": tmpl,
        "argv_digest": digest(canonical(tmpl).encode()),
        "probes": [],
        "known_context": [],
        "cost_tier": "Free" if route == "devin" else None,
    }
    if route == "devin":
        entry["tools_schema_digest"] = infer.DEVIN_TOOLS_DIGEST
        config = Path(cwd).parent / (Path(cwd).name + '-fixture-config.json')
        config.write_text('{"fixture": true}')
        config.chmod(0o600)
        entry["config"] = str(config)
        entry["config_digest"] = digest(config.read_bytes())
    entry["measurement_digest"] = infer._measurement_digest(entry)
    return entry


class _MeasureStub:
    """Stands in for the Native measurement boundary."""

    def __init__(self):
        self.fail = set()
        self.version = "0.1.0-test"
        self.calls = []

    def __call__(self, state_dir, route, model, cwd, timeout):
        self.calls.append((route, model))
        if route in self.fail or (route, model) in self.fail:
            raise TaskError("route_unmeasured")
        return _measured_entry(route, model, cwd, version=self.version)


class _Base(unittest.TestCase):
    CLAUDE = ("claude", CLAUDE_MODEL)
    DEVIN = ("devin", DEVIN_MODEL)
    NOW = FIXED_TIME

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        host = mock.patch.object(admission, '_host_root', return_value=self.root / 'host')
        host.start()
        self.addCleanup(host.stop)
        os.chmod(self.root, 0o700)
        self.state = self.root / "state"
        self.native = self.root / "native"
        self.state.mkdir(0o700)
        self.native.mkdir(0o700)
        self.stub = _MeasureStub()

    def _new_state(self, tag):
        s = self.root / ("state-" + tag)
        n = self.root / ("native-" + tag)
        s.mkdir(0o700)
        n.mkdir(0o700)
        return s, n

    def _patch_measure(self):
        p = mock.patch.object(m, "_measure", self.stub)
        p.start()
        self.addCleanup(p.stop)
        return self.stub

    def _setup(self):
        self._patch_measure()
        return m.setup_candidates(self.state, self.native)

    def _reg(self):
        return json.loads((self.state / "routes2.json").read_text())

    def _entry(self, key):
        return self._reg()["measurements"][key]

    def _drop_measurement(self, key):
        p = self.state / "routes2.json"
        data = json.loads(p.read_text())
        del data["measurements"][key]
        p.write_text(json.dumps(data))
        os.chmod(p, 0o600)

    def _nc(self, usage=None, clock=None):
        kwargs = {}
        if usage is not None:
            kwargs["usage"] = usage
        if clock is not None:
            kwargs["clock"] = clock
        return m.NativeCandidates(self.state, **kwargs)

    def _snap(self, remaining=50, group="seat", low=False,
              observed=None, max_age=600):
        return {"remaining_percent": remaining,
                "comparison_group": group,
                "low_remaining": low,
                "observed_at": self.NOW if observed is None else observed,
                "max_age": max_age,
                "source_ref": "quota-fixture"}

    @staticmethod
    def _code(exc):
        code = getattr(exc, "code", None)
        if code:
            return code
        return exc.args[0] if exc.args else None


class SetupTests(_Base):

    def test_presets_schema_and_private_registry_file(self):
        reg = self._setup()
        self.assertEqual(set(reg), {"schema", "created", "cwd",
                                    "measurements", "candidates"})
        self.assertEqual(reg["schema"], "co.routes/2")
        cands = {(c["route"], c["model"]): c for c in reg["candidates"]}
        self.assertEqual(set(cands), {self.CLAUDE, self.DEVIN})
        for cand in reg["candidates"]:
            self.assertEqual(set(cand), {"route", "model", "fit"})
            for f in cand["fit"]:
                self.assertEqual(set(f), {"category", "degree",
                                          "origin", "source_ref"})
                self.assertEqual(f["origin"], "prior")
                self.assertEqual(f["source_ref"], PRESET_SOURCE)
        self.assertEqual({f["category"]: f["degree"]
                          for f in cands[self.CLAUDE]["fit"]}, CLAUDE_FIT)
        self.assertEqual({f["category"]: f["degree"]
                          for f in cands[self.DEVIN]["fit"]}, DEVIN_FIT)
        self.assertEqual(sorted(self.stub.calls),
                         sorted([self.CLAUDE, self.DEVIN]))
        entry = self._entry("devin/" + DEVIN_MODEL)
        self.assertIsInstance(entry["measurement_digest"], str)
        self.assertEqual(entry["native_cwd"], str(self.native))
        p = self.state / "routes2.json"
        st = p.lstat()
        self.assertTrue(stat.S_ISREG(st.st_mode))
        self.assertFalse(stat.S_ISLNK(st.st_mode))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)

    def test_refuse_overwrite_preserves_bytes_and_legacy_files(self):
        legacy = self.state / "routes.json"
        legacy.write_bytes(b'{"legacy": "keep-me"}')
        cfg = self.state / "config.json"
        cfg.write_bytes(b'{"cfg": 1}')
        self._setup()
        p = self.state / "routes2.json"
        before = p.read_bytes()
        with self.assertRaises(TaskError):
            m.setup_candidates(self.state, self.native)
        self.assertEqual(p.read_bytes(), before)
        self.assertEqual(legacy.read_bytes(), b'{"legacy": "keep-me"}')
        self.assertEqual(cfg.read_bytes(), b'{"cfg": 1}')

    def test_partial_failure_keeps_subset_total_failure_errors(self):
        self.stub.fail = {"claude"}
        self._patch_measure()
        reg = m.setup_candidates(self.state, self.native)
        self.assertEqual({(c["route"], c["model"])
                          for c in reg["candidates"]}, {self.DEVIN})
        report = json.loads((self.state / "setup-report.json").read_text())
        blob = json.dumps(report)
        self.assertIn("claude", blob)
        self.assertNotIn(str(self.native), blob)
        self.assertNotIn("/usr/bin/true", blob)

        s2, n2 = self._new_state("allfail")
        self.stub.fail = {"claude", "devin"}
        with self.assertRaises(TaskError):
            m.setup_candidates(s2, n2)


class AddCandidateTests(_Base):

    def test_unknown_model_empty_fit_then_null_degree_eligible(self):
        self._setup()
        reg = m.add_candidate(self.state, self.native, "devin",
                              "swe-x-experimental")
        cand = next(c for c in reg["candidates"]
                    if c["model"] == "swe-x-experimental")
        self.assertEqual(cand["fit"], [])
        pin = self._nc().selection("implement", "coding",
                                   {"mode": "suitability",
                                    "targets": {}})
        self.assertEqual((pin["route"], pin["model"]), self.DEVIN)
        # no implicit fit: an explicit null-degree fit makes it exact-eligible
        m.set_fit(self.state, "devin", "swe-x-experimental", "coding",
                  degree=None, source_ref="manual-review")
        pin2 = self._nc().selection(
            "implement", "coding",
            {"mode": "fixed",
             "targets": {"implement": {"route": "devin",
                                       "model": "swe-x-experimental"}}})
        self.assertEqual(pin2["model"], "swe-x-experimental")
        self.assertIsNone(pin2["fit"]["degree"])

    def test_known_preset_seed_and_duplicate_rejected(self):
        self.stub.fail = {"claude"}
        self._setup()
        self.stub.fail.clear()
        reg = m.add_candidate(self.state, self.native, "claude",
                              CLAUDE_MODEL)
        cand = next(c for c in reg["candidates"]
                    if c["route"] == "claude")
        self.assertEqual({f["category"]: f["degree"]
                          for f in cand["fit"]}, CLAUDE_FIT)
        with self.assertRaises(TaskError):
            m.add_candidate(self.state, self.native, "claude",
                            CLAUDE_MODEL)

    def test_reprobe_preserves_fit_and_refreshes_measurement(self):
        self._setup()
        before = self._entry("devin/" + DEVIN_MODEL)
        self.stub.version = "9.9.9-reprobe"
        reg = m.add_candidate(self.state, self.native, "devin",
                              DEVIN_MODEL, reprobe=True)
        after = self._entry("devin/" + DEVIN_MODEL)
        self.assertEqual(after["version"], "9.9.9-reprobe")
        self.assertNotEqual(after["measurement_digest"],
                            before["measurement_digest"])
        cand = next(c for c in reg["candidates"]
                    if c["route"] == "devin")
        self.assertEqual({f["category"]: f["degree"]
                          for f in cand["fit"]}, DEVIN_FIT)

    def test_limits_locks_and_no_native_on_invalid_input(self):
        self._setup()
        for i in range(14):
            m.add_candidate(self.state, self.native, "devin",
                            "swe-extra-%02d" % i)
        with self.assertRaises(TaskError):
            m.add_candidate(self.state, self.native, "devin",
                            "swe-overflow")
        self.stub.calls.clear()
        with self.assertRaises(TaskError):
            m.add_candidate(self.state, self.native, "", "x")
        with self.assertRaises(TaskError):
            m.add_candidate(self.state, self.native, "devin", "")
        other_native = self._new_state("othercwd")[1]
        with self.assertRaises(TaskError):
            m.add_candidate(self.state, other_native, "devin",
                            "swe-cwd-x")
        self.assertEqual(self.stub.calls, [])
        # registry lock conflicts abort before any Native call
        lock = os.open(str(self.state / "routes2.lock"),
                       os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(TaskError):
                m.add_candidate(self.state, self.native, "devin",
                                "swe-locked")
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            os.close(lock)
        self.assertEqual(self.stub.calls, [])
        # fit-only edits take the registry lock, not infer.lock
        ilock = os.open(str(self.state / "infer.lock"),
                        os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(ilock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            m.set_fit(self.state, "devin", DEVIN_MODEL, "coding",
                      degree=1, source_ref="lock-ok")
        finally:
            fcntl.flock(ilock, fcntl.LOCK_UN)
            os.close(ilock)


class SetFitTests(_Base):

    def test_validation_rejects_bad_and_override_preserves_rest(self):
        self._setup()
        mdig = self._entry("devin/" + DEVIN_MODEL)["measurement_digest"]
        bad = [
            dict(degree=True), dict(degree=0), dict(degree=4),
            dict(degree="3"), dict(degree=2.5),
            dict(degree=1, origin="bogus"),
            dict(degree=1, source_ref=""),
            dict(degree=1, source_ref=None),
            dict(degree=1, source_ref="x" * 9000),
            dict(degree=1, source_ref=mdig),
        ]
        for kw in bad:
            with self.subTest(kw=kw):
                with self.assertRaises(TaskError):
                    m.set_fit(self.state, "devin", DEVIN_MODEL,
                              "coding", **kw)
        with self.assertRaises(TaskError):
            m.set_fit(self.state, "devin", DEVIN_MODEL,
                      "no-such-category", degree=1)
        reg = m.set_fit(self.state, "devin", DEVIN_MODEL, "coding",
                        degree=1, origin="measured",
                        source_ref="bench-2026-10")
        cand = next(c for c in reg["candidates"]
                    if c["route"] == "devin")
        fit = {f["category"]: f for f in cand["fit"]}
        self.assertEqual(fit["coding"],
                         {"category": "coding", "degree": 1,
                          "origin": "measured",
                          "source_ref": "bench-2026-10"})
        rest = {k: v["degree"] for k, v in fit.items()
                if k != "coding"}
        self.assertEqual(rest, {k: v for k, v in DEVIN_FIT.items()
                                if k != "coding"})


class ResolveTests(_Base):

    def test_forms_and_rejections(self):
        self._setup()
        nc = self._nc()
        t = nc.resolve_targets([
            "implement=devin/" + DEVIN_MODEL,
            "design=" + CLAUDE_MODEL,
            "review=claude/" + CLAUDE_MODEL,
        ])
        self.assertEqual(t["implement"],
                         {"route": "devin", "model": DEVIN_MODEL})
        self.assertEqual(t["design"],
                         {"route": "claude", "model": CLAUDE_MODEL})
        self.assertEqual(t["review"],
                         {"route": "claude", "model": CLAUDE_MODEL})
        self.assertEqual(sorted(self.stub.calls),
                         sorted([self.CLAUDE, self.DEVIN]))
        with self.assertRaises(TaskError):
            nc.resolve_targets(["implement=devin/" + DEVIN_MODEL,
                                "implement=devin/" + DEVIN_MODEL])
        with self.assertRaises(TaskError):
            nc.resolve_targets(["implement=devin/" + DEVIN_MODEL,
                                "implement=claude/" + CLAUDE_MODEL])
        with self.assertRaises(TaskError):
            nc.resolve_targets(["implement=devin/no-such"])
        with self.assertRaises(TaskError):
            nc.resolve_targets(["nosuchrole=devin/" + DEVIN_MODEL])
        # A model from another route is rejected before Native qualification.
        self.stub.calls.clear()
        with self.assertRaises(TaskError):
            m.add_candidate(self.state, self.native, "claude", DEVIN_MODEL)
        self.assertEqual(self.stub.calls, [])


class SelectionTests(_Base):

    def test_policy_shape_and_fixed_requires_target(self):
        self._setup()
        nc = self._nc()
        bad = [
            {"mode": "suitability"},
            {"targets": {}},
            {"mode": "suitability", "targets": {}, "extra": 1},
            {"mode": "bogus", "targets": {}},
            {"mode": "fixed",
             "targets": {"implement": "devin/" + DEVIN_MODEL}},
            {"mode": "fixed",
             "targets": {"implement": {"route": "devin"}}},
        ]
        for pol in bad:
            with self.subTest(pol=pol):
                with self.assertRaises(TaskError):
                    nc.selection("implement", "coding", pol)
        with self.assertRaises(TaskError) as ctx:
            nc.selection("implement", "coding",
                         {"mode": "fixed", "targets": {}})
        self.assertEqual(self._code(ctx.exception),
                         "selection_unconfigured")

    def test_suitability_fit_order_pin_shape_and_stable_tie(self):
        self._setup()
        nc = self._nc()
        pol = {"mode": "suitability", "targets": {}}
        pin = nc.selection("implement", "coding", pol)
        self.assertEqual((pin["route"], pin["model"]), self.DEVIN)
        entry = self._entry("devin/" + DEVIN_MODEL)
        self.assertEqual(pin["measurement_digest"],
                         entry["measurement_digest"])
        self.assertEqual(pin["environment_ref"],
                         "native:" + entry["measurement_digest"])
        self.assertEqual(pin["mode"], "suitability")
        self.assertEqual(pin["focus"], "coding")
        self.assertEqual(set(pin["fit"]),
                         {"degree", "origin", "source_ref"})
        self.assertEqual(pin["fit"]["degree"], 3)
        self.assertTrue(pin["catalog_digest"])
        self.assertEqual(set(pin["usage"]),
                         {"remaining_percent", "reason",
                          "comparison_group", "low_remaining",
                          "source_ref"})
        self.assertLessEqual(len(pin["excluded"]), 16)
        for ex in pin["excluded"]:
            self.assertEqual(set(ex), {"route", "model", "reason"})
        # same role picks a different route when its fit ranks first
        pin_w = nc.selection("implement", "writing", pol)
        self.assertEqual((pin_w["route"], pin_w["model"]), self.CLAUDE)
        self.assertEqual(pin_w["fit"]["degree"], 3)
        # equal fit resolves by stable registry candidate order
        reg = {"schema": "co.routes/2", "created": self.NOW,
               "cwd": str(self.native),
               "measurements": {
                   "devin/swe-tie-z": _measured_entry(
                       "devin", "swe-tie-z", self.native),
                   "devin/swe-tie-a": _measured_entry(
                       "devin", "swe-tie-a", self.native)},
               "candidates": [
                   {"route": "devin", "model": "swe-tie-z",
                    "fit": [{"category": "coding", "degree": 2,
                             "origin": "prior", "source_ref": "t"}]},
                   {"route": "devin", "model": "swe-tie-a",
                    "fit": [{"category": "coding", "degree": 2,
                             "origin": "prior", "source_ref": "t"}]}]}
        p = self.state / "routes2.json"
        p.write_text(json.dumps(reg))
        os.chmod(p, 0o600)
        pin_t = self._nc().selection("implement", "coding", pol)
        self.assertEqual(pin_t["model"], "swe-tie-z")

    def test_exact_modes_honored_never_fall_back(self):
        self._setup()
        m.add_candidate(self.state, self.native, "devin", "swe-nofit")
        nc = self._nc()
        pol = {"mode": "fixed",
               "targets": {"implement": {"route": "claude",
                                         "model": CLAUDE_MODEL}}}
        pin = nc.selection("implement", "coding", pol)
        self.assertEqual((pin["route"], pin["model"]), self.CLAUDE)
        self.assertEqual(pin["mode"], "fixed")
        pol2 = {"mode": "fixed",
                "targets": {"implement": {"route": "devin",
                                          "model": "swe-nofit"}}}
        with self.assertRaises(TaskError) as ctx:
            nc.selection("implement", "coding", pol2)
        self.assertEqual(self._code(ctx.exception),
                         "no_exact_replacement")
        self._drop_measurement("claude/" + CLAUDE_MODEL)
        with self.assertRaises(TaskError) as ctx2:
            self._nc().selection("implement", "coding", pol)
        self.assertEqual(self._code(ctx2.exception),
                         "no_exact_replacement")

    def test_unmeasured_excluded_others_eligible_none_left(self):
        self._setup()
        self._drop_measurement("claude/" + CLAUDE_MODEL)
        pin = self._nc().selection("implement", "coding",
                                   {"mode": "suitability",
                                    "targets": {}})
        self.assertEqual((pin["route"], pin["model"]), self.DEVIN)
        excluded = {(e["route"], e["model"]) for e in pin["excluded"]}
        self.assertIn(self.CLAUDE, excluded)
        self._drop_measurement("devin/" + DEVIN_MODEL)
        with self.assertRaises(TaskError) as ctx:
            self._nc().selection("implement", "coding",
                                 {"mode": "suitability",
                                  "targets": {}})
        self.assertEqual(self._code(ctx.exception), "no_eligible_route")

    def test_unknown_and_missing_usage_falls_back_with_reasons(self):
        self._setup()
        unsupported = self._nc().selection(
            "implement", "coding", {"mode": "usage", "targets": {}})
        self.assertEqual(unsupported["usage"]["reason"],
                         "native_usage_unsupported")
        self.assertIsNone(unsupported["usage"]["remaining_percent"])
        pin = self._nc(usage={}, clock=lambda: self.NOW).selection(
            "implement", "coding", {"mode": "usage", "targets": {}})
        self.assertEqual((pin["route"], pin["model"]), self.DEVIN)
        self.assertEqual(pin["reason"], "usage_unknown_then_suitability")
        self.assertEqual(pin["usage"]["reason"],
                         "usage_unobserved")
        # a candidate with no snap is not penalised, excluded or faked
        usage = {(CLAUDE_MODEL, "claude"): self._snap(remaining=100)}
        pin2 = self._nc(usage=usage, clock=lambda: self.NOW).selection(
            "implement", "coding", {"mode": "usage", "targets": {}})
        self.assertEqual((pin2["route"], pin2["model"]), self.DEVIN)

    def test_comparable_usage_switches_winner(self):
        self._setup()
        usage = {
            (DEVIN_MODEL, "devin"): self._snap(remaining=5),
            (CLAUDE_MODEL, "claude"): self._snap(remaining=95),
        }
        pin = self._nc(usage=usage, clock=lambda: self.NOW).selection(
            "implement", "coding", {"mode": "usage", "targets": {}})
        self.assertEqual((pin["route"], pin["model"]), self.CLAUDE)
        self.assertEqual(pin["usage"]["remaining_percent"], 95)
        self.assertEqual(pin["usage"]["comparison_group"], "seat")
        self.assertEqual(pin["usage"]["source_ref"], "quota-fixture")
        excluded = {(e["route"], e["model"]) for e in pin["excluded"]}
        self.assertNotIn(self.DEVIN, excluded)

    def test_incomparable_groups_and_low_signal(self):
        self._setup()
        usage = {
            (DEVIN_MODEL, "devin"): self._snap(5, group="a"),
            (CLAUDE_MODEL, "claude"): self._snap(95, group="b"),
        }
        pin = self._nc(usage=usage, clock=lambda: self.NOW).selection(
            "implement", "coding", {"mode": "usage", "targets": {}})
        self.assertEqual((pin["route"], pin["model"]), self.DEVIN)
        usage2 = {
            (DEVIN_MODEL, "devin"): self._snap(None, group="a", low=True),
            (CLAUDE_MODEL, "claude"): self._snap(None, group="b"),
        }
        pin2 = self._nc(usage=usage2, clock=lambda: self.NOW).selection(
            "implement", "coding", {"mode": "usage", "targets": {}})
        self.assertEqual((pin2["route"], pin2["model"]), self.CLAUDE)

    def test_stale_future_and_malformed_usage_stay_unknown(self):
        self._setup()
        variants = [
            {"observed_at": self.NOW - 10000, "max_age": 60},
            {"observed_at": self.NOW + 10000, "max_age": 10 ** 9},
            {"remaining_percent": True},
            {"remaining_percent": 10 ** 30},
            {"remaining_percent": "90"},
            {"remaining_percent": -1},
        ]
        for over in variants:
            with self.subTest(over=over):
                bad = self._snap(remaining=1)
                bad.update(over)
                usage = {
                    (DEVIN_MODEL, "devin"): bad,
                    (CLAUDE_MODEL, "claude"): self._snap(remaining=99),
                }
                pin = self._nc(
                    usage=usage, clock=lambda: self.NOW).selection(
                    "implement", "coding",
                    {"mode": "usage", "targets": {}})
                # untrusted snap -> unknown -> falls back to fit
                self.assertEqual((pin["route"], pin["model"]),
                                 self.DEVIN)


class FocusAndPlanTests(_Base):

    def test_supported_focuses_sorted_and_measurement_backed(self):
        self._setup()
        self.assertEqual(self._nc().supported_focuses(),
                         ["architecture_planning", "coding", "general", "reasoning",
                          "review", "writing"])
        self._drop_measurement("claude/" + CLAUDE_MODEL)
        self._drop_measurement("devin/" + DEVIN_MODEL)
        self.assertEqual(self._nc().supported_focuses(), [])

    def test_validate_plan_static_outcomes(self):
        self._setup()
        nc = self._nc()
        plan = {"schema": "co.task-plan/2", "steps": [
            {"id": "d", "role": "design", "instructions": "outline",
             "inputs": [], "focus": "writing"},
            {"id": "i", "role": "implement", "instructions": "code",
             "inputs": ["d"], "focus": "coding"},
            {"id": "r", "role": "review", "instructions": "check",
             "inputs": ["i"], "focus": "review"}]}
        nc.validate_plan(plan, {"mode": "suitability", "targets": {}})
        research = {"schema": "co.task-plan/2", "steps": [
            {"id": "i", "role": "implement", "instructions": "x",
             "inputs": [], "focus": "research"}]}
        with self.assertRaises(TaskError) as ctx:
            nc.validate_plan(research,
                             {"mode": "suitability", "targets": {}})
        self.assertEqual(self._code(ctx.exception), "plan_unfittable")
        m.add_candidate(self.state, self.native, "devin", "swe-nofit")
        nc2 = self._nc()
        coding = {"schema": "co.task-plan/2", "steps": [
            {"id": "i", "role": "implement", "instructions": "x",
             "inputs": [], "focus": "coding"}]}
        with self.assertRaises(TaskError) as ctx2:
            nc2.validate_plan(coding, {
                "mode": "fixed",
                "targets": {"implement": {"route": "devin",
                                          "model": "swe-nofit"}}})
        self.assertEqual(self._code(ctx2.exception), "no_exact_replacement")
        # roles unused by the plan require nothing under fixed mode
        nc2.validate_plan(coding, {
            "mode": "fixed",
            "targets": {"implement": {"route": "devin",
                                      "model": DEVIN_MODEL}}})


class RegistryHardeningTests(_Base):

    def test_copied_state_inside_native_cwd_is_rejected_on_read(self):
        self._setup()
        moved = self.native / "copied-state"
        shutil.copytree(self.state, moved)
        with self.assertRaises(TaskError) as ctx:
            m.NativeCandidates(moved)
        self.assertEqual(ctx.exception.code, "state_location")

    def test_fifo_registry_is_rejected_without_waiting_for_writer(self):
        p = self.state / "routes2.json"
        os.mkfifo(p, 0o600)
        probe = (
            "import sys; from co_v4.task.select import NativeCandidates; "
            "NativeCandidates(sys.argv[1])")
        out = subprocess.run([sys.executable, "-B", "-c", probe, str(self.state)],
                             capture_output=True, text=True, timeout=5)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("registry_invalid", out.stderr)

    def _base_reg(self):
        entry = _measured_entry("devin", DEVIN_MODEL, self.native)
        return {"schema": "co.routes/2", "created": FIXED_TIME,
                "cwd": str(self.native),
                "measurements": {"devin/" + DEVIN_MODEL: entry},
                "candidates": [{"route": "devin", "model": DEVIN_MODEL,
                                "fit": [{"category": "coding",
                                         "degree": 3,
                                         "origin": "prior",
                                         "source_ref": "t"}]}]}

    def test_malformed_symlink_and_oversized_fail_closed(self):
        base = self._base_reg()
        variants = [
            dict(base, extra_key=1),
            dict(base, candidates=base["candidates"] * 2),
            dict(base, candidates=[{"route": "devin",
                                    "model": DEVIN_MODEL,
                                    "fit": "coding"}]),
            dict(base, candidates=[{"route": "devin",
                                    "model": DEVIN_MODEL,
                                    "fit": [{"category": "coding",
                                             "degree": True,
                                             "origin": "prior",
                                             "source_ref": "t"}]}]),
            dict(base, candidates=[{"route": "devin",
                                    "model": DEVIN_MODEL,
                                    "fit": [{"category": "coding",
                                             "degree": 3,
                                             "origin": "prior",
                                             "source_ref": "t",
                                             "extra": 1}]}]),
        ]
        p = self.state / "routes2.json"
        for i, variant in enumerate(variants):
            with self.subTest(variant=i):
                p.write_text(json.dumps(variant))
                os.chmod(p, 0o600)
                with self.assertRaises(TaskError):
                    m.NativeCandidates(self.state)
        target = self.root / "outside.json"
        target.write_text(json.dumps(self._base_reg()))
        p.unlink()
        os.symlink(target, p)
        with self.assertRaises(TaskError):
            m.NativeCandidates(self.state)
        s2, _ = self._new_state("big")
        big = self._base_reg()
        big["candidates"][0]["fit"][0]["source_ref"] = "x" * (5 * 1024 * 1024)
        bp = s2 / "routes2.json"
        bp.write_text(json.dumps(big))
        os.chmod(bp, 0o600)
        with self.assertRaises(TaskError):
            m.NativeCandidates(s2)

    def test_show_catalog_sanitised(self):
        self._setup()
        out = m.show_catalog(self.state)
        text = (out if isinstance(out, str)
                else json.dumps(out, default=str))
        self.assertIn(DEVIN_MODEL, text)
        self.assertIn("coding", text)
        self.assertIn(self._entry("devin/" + DEVIN_MODEL)
                      ["measurement_digest"], text)
        self.assertNotIn("/usr/bin/true", text)
        self.assertNotIn(str(self.native), text)
        self.assertNotIn("argv_template", text)
        self.assertNotIn("version_argv", text)
        self.assertNotIn("devin-config.json", text)
        reg = self._reg()
        reg["measurements"]["devin/" + DEVIN_MODEL]["measurement_digest"] = {
            "unexpected": "not-a-public-digest"}
        (self.state / "routes2.json").write_text(json.dumps(reg))
        shown = m.show_catalog(self.state)
        self.assertIsNone(shown["measurements"]["devin/" + DEVIN_MODEL])
        self.assertNotIn("not-a-public-digest", json.dumps(shown))


class InferSelectedTests(_Base):

    def test_bad_inference_parameters_spend_no_native_call(self):
        self._setup()
        pin = self._coding_pin(self._nc())
        cc, dc = self._patch_native()
        for role, timeout in ((None, 30), ("unknown", 30),
                              ("implement", True), ("implement", 0),
                              ("implement", 901), ("implement", "30")):
            with self.subTest(role=role, timeout=timeout):
                with self.assertRaises(TaskError):
                    self._nc().infer_selected(pin, role, "go",
                                             self.root / "bad-call", timeout)
                cc.assert_not_called()
                dc.assert_not_called()

    def test_unsafe_infer_lock_stops_before_native_launch(self):
        self._setup()
        pin = self._coding_pin(self._nc())
        cc, dc = self._patch_native()
        target = self.root / "sentinel"
        target.write_bytes(b"must-not-change")
        target.chmod(0o600)
        lock = self.state / "infer.lock"
        for kind in ("symlink", "hardlink", "permissive", "fifo"):
            with self.subTest(kind=kind):
                lock.unlink()
                if kind == "symlink":
                    lock.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, lock)
                elif kind == "fifo":
                    os.mkfifo(lock, 0o600)
                else:
                    lock.write_bytes(b"")
                    lock.chmod(0o666)
                with self.assertRaises(TaskError):
                    self._nc().infer_selected(pin, "implement", "go",
                                             self.root / ("call-" + kind))
                dc.assert_not_called()
                cc.assert_not_called()
                self.assertEqual(target.read_bytes(), b"must-not-change")
        lock.unlink()

    def _patch_native(self):
        patches = [
            mock.patch.object(infer, "_check_launch", lambda e: None),
            mock.patch.object(infer, "_known_context", lambda cwd: []),
            mock.patch.object(
                infer, "_call_claude",
                return_value={"text": "claude-out",
                              "api_key_source": "env"}),
            mock.patch.object(
                infer, "_call_devin",
                return_value={"text": "devin-out",
                              "api_key_source": "env"}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return infer._call_claude, infer._call_devin

    def _coding_pin(self, nc):
        return nc.selection("implement", "coding", {
            "mode": "fixed",
            "targets": {"implement": {"route": "devin",
                                      "model": DEVIN_MODEL}}})

    def test_runs_pinned_model_and_binds_digests(self):
        self._setup()
        pin = self._coding_pin(self._nc())
        expected_sel = digest(canonical(pin).encode())
        cc, dc = self._patch_native()
        call_dir = self.root / "call-1"
        res = self._nc().infer_selected(pin, "implement",
                                        "do the thing", call_dir)
        self.assertEqual(res["text"], "devin-out")
        self.assertEqual(res["model"], DEVIN_MODEL)
        self.assertEqual(res["route"], "devin")
        dc.assert_called_once()
        cc.assert_not_called()
        self.assertIn(DEVIN_MODEL, dc.call_args[0])
        entry = self._entry("devin/" + DEVIN_MODEL)
        ev = res["evidence"]
        self.assertEqual(ev["measurement_digest"],
                         entry["measurement_digest"])
        self.assertEqual(ev["selection_digest"], expected_sel)
        self.assertEqual(ev["cost_tier"], "Free")
        meta = json.loads((call_dir / "meta.json").read_text())
        self.assertEqual(meta["selection_digest"], expected_sel)
        self.assertEqual(meta["measurement_digest"],
                         entry["measurement_digest"])
        self.assertEqual(meta["role"], "implement")

    def test_drift_stops_fit_edit_tolerated_bad_prompt(self):
        self._setup()
        pin = self._coding_pin(self._nc())
        cc, dc = self._patch_native()
        # catalog-only change: measurement untouched -> still runs
        m.set_fit(self.state, "devin", DEVIN_MODEL, "coding",
                  degree=1, source_ref="post-pin-edit")
        res = self._nc().infer_selected(pin, "implement", "go",
                                        self.root / "call-a")
        self.assertEqual(res["text"], "devin-out")
        dc.assert_called_once()
        # re-measurement changes the digest -> stale pin, hard stop
        self.stub.version = "9.9.9-new"
        m.add_candidate(self.state, self.native, "devin", DEVIN_MODEL,
                        reprobe=True)
        dc.reset_mock()
        with self.assertRaises(TaskError) as ctx:
            self._nc().infer_selected(pin, "implement", "go",
                                      self.root / "call-b")
        self.assertEqual(self._code(ctx.exception), "measurement_drift")
        dc.assert_not_called()
        cc.assert_not_called()
        with self.assertRaises(TaskError) as ctx2:
            self._nc().infer_selected(pin, "implement", "",
                                      self.root / "call-c")
        self.assertEqual(self._code(ctx2.exception), "input_invalid")


if __name__ == "__main__":
    unittest.main()
