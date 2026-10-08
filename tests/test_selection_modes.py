from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import unittest

from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.contracts import Decision
from co_v4.routing import Assessment, select_route
from co_v4.selection import SelectionCandidate, select_candidates
from co_v4.usage import UsageStore


def cand(key, suitability=None, percent=None, group=None, low=False):
    return SelectionCandidate(key, suitability, percent, group, low)


class SuitabilityModeTests(unittest.TestCase):
    def test_best_fit_wins_despite_lower_remaining(self):
        fit_low_quota = cand(("fit", "x"), 3, 10.0, "w")
        other_high_quota = cand(("other", "y"), 2, 90.0, "w")
        decision = select_candidates([other_high_quota, fit_low_quota])
        self.assertEqual(decision.selected, fit_low_quota)
        self.assertEqual(decision.reason, "suitability_then_stable_order")

    def test_top_fit_peers_compare_percent_in_shared_group(self):
        a = cand(("a", "x"), 3, 40.0, "w")
        b = cand(("b", "y"), 3, 80.0, "w")
        decision = select_candidates([a, b])
        self.assertEqual(decision.selected, b)
        self.assertEqual(decision.reason, "comparable_usage")
        tied_b = cand(("b", "y"), 3, 40.0, "w")
        decision = select_candidates([a, tied_b])
        self.assertEqual(decision.selected, a)
        self.assertEqual(decision.reason, "comparable_usage")

    def test_different_or_missing_groups_stay_incomparable(self):
        for groups in (("w1", "w2"), (None, "w"), (None, None)):
            with self.subTest(groups=groups):
                a = cand(("a", "x"), 3, 10.0, groups[0])
                b = cand(("b", "y"), 3, 90.0, groups[1])
                decision = select_candidates([a, b])
                self.assertEqual(decision.selected, a)
                self.assertEqual(decision.reason, "suitability_then_stable_order")

    def test_unrated_remains_eligible_after_rated_peers(self):
        unrated = cand(("u", "x"), None, 99.0, "w")
        rated = cand(("r", "y"), 1, 5.0, "w")
        decision = select_candidates([unrated, rated])
        self.assertEqual(decision.selected, rated)
        self.assertEqual(select_candidates([unrated]).selected, unrated)


class UsageModeTests(unittest.TestCase):
    def test_mode_changes_selected_candidate(self):
        fit_low_quota = cand(("fit", "x"), 3, 20.0, "w")
        other_high_quota = cand(("other", "y"), 2, 90.0, "w")
        options = [fit_low_quota, other_high_quota]
        self.assertEqual(select_candidates(options).selected, fit_low_quota)
        decision = select_candidates(options, mode="usage")
        self.assertEqual(decision.selected, other_high_quota)
        self.assertEqual(decision.reason, "comparable_usage")

    def test_all_comparable_orders_by_remaining_then_fit_then_input(self):
        tied_a = cand(("a", "x"), 1, 90.0, "w")
        tied_b = cand(("b", "y"), 1, 90.0, "w")
        lower = cand(("c", "z"), 3, 10.0, "w")
        decision = select_candidates([lower, tied_a, tied_b], mode="usage")
        self.assertEqual(decision.selected, tied_a)

    def test_unknown_not_penalized_and_low_evidence_demoted(self):
        unknown = cand(("u", "x"), 2)
        known = cand(("k", "y"), 1, 5.0, "w")
        low = cand(("l", "z"), 3, low=True)
        decision = select_candidates([low, unknown, known], mode="usage")
        self.assertEqual(decision.selected, unknown)
        self.assertEqual(decision.reason, "low_remaining_avoided")
        decision = select_candidates([low, known], mode="usage")
        self.assertEqual(decision.selected, known)

    def test_all_unknown_uses_fit_then_stable_order(self):
        a = cand(("a", "x"), 1)
        b = cand(("b", "y"), 3)
        c = cand(("c", "z"), 3)
        decision = select_candidates([a, b, c], mode="usage")
        self.assertEqual(decision.selected, b)
        self.assertEqual(decision.reason, "suitability_then_stable_order")

    def test_equal_options_keep_input_order(self):
        first = cand(("b", "y"), 3)
        second = cand(("a", "x"), 3)
        self.assertEqual(select_candidates([first, second]).selected, first)
        self.assertEqual(select_candidates([first, second], mode="usage").selected,
                         first)


class FixedAndExactTests(unittest.TestCase):
    def test_fixed_selects_exact_or_reports_no_match(self):
        a = cand(("a", "x"), 3)
        b = cand(("b", "y"), 1)
        decision = select_candidates([a, b], mode="fixed", exact_key=("b", "y"))
        self.assertEqual(decision.selected, b)
        self.assertEqual(decision.reason, "exact_match")
        decision = select_candidates([a, b], mode="fixed", exact_key=("z", "q"))
        self.assertIsNone(decision.selected)
        self.assertEqual(decision.reason, "no_match")
        self.assertEqual(select_candidates([], mode="fixed",
                                           exact_key=("z", "q")).reason,
                         "no_candidate")

    def test_fixed_requires_exact_key_and_exact_constrains_other_modes(self):
        a = cand(("a", "x"), 1)
        b = cand(("b", "y"), 3)
        with self.assertRaises(ValueError):
            select_candidates([a, b], mode="fixed")
        decision = select_candidates([a, b], exact_key=("a", "x"))
        self.assertEqual(decision.selected, a)
        decision = select_candidates([a, b], mode="usage",
                                     exact_key=("missing", "q"))
        self.assertIsNone(decision.selected)
        self.assertEqual(decision.reason, "no_match")

    def test_empty_candidates_after_mode_validation(self):
        decision = select_candidates([])
        self.assertIsNone(decision.selected)
        self.assertEqual(decision.reason, "no_candidate")
        with self.assertRaises(ValueError):
            select_candidates([], mode="bogus")
        with self.assertRaises(ValueError):
            select_candidates([], mode="fixed")


class CandidateValidationTests(unittest.TestCase):
    def test_field_types_and_ranges(self):
        for kwargs in ({"suitability": True}, {"suitability": 0},
                       {"suitability": 4}, {"suitability": 2.0},
                       {"suitability": "3"}, {"remaining_percent": True},
                       {"remaining_percent": float("nan")},
                       {"remaining_percent": float("inf")},
                       {"remaining_percent": -1.0},
                       {"remaining_percent": 100.1},
                       {"remaining_percent": "50"},
                       {"comparison_group": ""}, {"comparison_group": " "},
                       {"comparison_group": 3}, {"low_remaining": 1},
                       {"low_remaining": "yes"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                SelectionCandidate(("m", "a"), **{"suitability": None, **kwargs})
        self.assertEqual(SelectionCandidate(("m", "a"), 2, 50).remaining_percent, 50)
        self.assertEqual(SelectionCandidate(("m", "a"), 2, 0.0).remaining_percent, 0.0)

    def test_key_identities_and_duplicates(self):
        for key in (("m",), ("m", "a", "x"), ("m", 1), (1, "a"), ("", "a"),
                    ("m", ""), ("m ", "a"), ["m", "a"], "m,a", None):
            with self.subTest(key=key), self.assertRaises(ValueError):
                SelectionCandidate(key, 1)
        a = SelectionCandidate(("a", "x"), 1)
        with self.assertRaises(ValueError):
            select_candidates([a, SelectionCandidate(("a", "x"), 3)])
        with self.assertRaises(ValueError):
            select_candidates([a, object()])
        with self.assertRaises(ValueError):
            select_candidates(None)

    def test_mode_and_exact_key_parameters(self):
        a = cand(("a", "x"), 1)
        for mode in ("", "Fixed", "usage ", 3, None, True):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                select_candidates([a], mode=mode)
        for exact in (("a",), ["a", "x"], "a", ("a", 3), (" ", "x"), ("a", "")):
            with self.subTest(exact=exact), self.assertRaises(ValueError):
                select_candidates([a], exact_key=exact)


@dataclass(frozen=True)
class _Job:
    output_candidate: bool = False


@dataclass(frozen=True)
class _Conditions:
    model: str
    adapter: str
    environment_ref: str
    workspace: str = "ws"
    control_evidence_refs: tuple = ("ev",)


@dataclass(frozen=True)
class _Usage:
    model: str
    adapter: str
    window: str
    remaining_percent: float
    updated_at: str


class RouteSelectionTests(unittest.TestCase):
    def setUp(self):
        self.use = UseCase("coding")
        self.env = "env-1"
        self.now = datetime(2026, 10, 8, tzinfo=timezone.utc)
        self.window = "daily-quota"
        self.job = _Job()

    def entry(self, model, adapter, rating):
        verification = Verification(model, adapter, self.use, self.env,
                                    "official", "impl", "measure", "ac")
        return CatalogEntry(model, adapter,
                            {self.use: rating} if rating else {},
                            (verification,))

    def assessment(self, model, adapter):
        return Assessment(self.job, _Conditions(model, adapter, self.env),
                          Decision.NORMAL, "ref", controls_verified=True)

    def route(self, catalog, usage, **kwargs):
        assessments = [self.assessment(e.model, e.adapter) for e in catalog.entries]
        return select_route(catalog, self.job, self.use, assessments, usage,
                            now=self.now, max_usage_age=timedelta(minutes=5),
                            **kwargs)

    def test_default_mode_preserves_legacy_ordering_and_reasons(self):
        catalog = Catalog((self.entry("a", "x", 3), self.entry("b", "y", 3)))
        usage = UsageStore()
        result = self.route(catalog, usage)
        self.assertEqual(result.selected.entry.key, ("a", "x"))
        self.assertEqual(result.reason, "suitability_then_stable_order")
        self.assertEqual(tuple(o.entry.key for o in result.eligible),
                         (("a", "x"), ("b", "y")))
        usage.update(_Usage("a", "x", self.window, 10.0,
                            "2026-10-08T00:00:00+00:00"))
        usage.update(_Usage("b", "y", self.window, 80.0,
                            "2026-10-08T00:00:00+00:00"))
        result = self.route(catalog, usage, usage_window=self.window)
        self.assertEqual(result.selected.entry.key, ("b", "y"))
        self.assertEqual(result.reason, "comparable_usage")

    def test_stale_usage_is_not_compared(self):
        catalog = Catalog((self.entry("a", "x", 3), self.entry("b", "y", 3)))
        usage = UsageStore()
        usage.update(_Usage("a", "x", self.window, 10.0,
                            "2020-01-01T00:00:00+00:00"))
        usage.update(_Usage("b", "y", self.window, 90.0,
                            "2020-01-01T00:00:00+00:00"))
        result = self.route(catalog, usage, usage_window=self.window)
        self.assertEqual(result.selected.entry.key, ("a", "x"))
        self.assertEqual(result.reason, "suitability_then_stable_order")

    def test_usage_mode_orders_eligible_by_comparable_remaining(self):
        catalog = Catalog((self.entry("a", "x", 3), self.entry("b", "y", 2)))
        usage = UsageStore()
        usage.update(_Usage("a", "x", self.window, 20.0,
                            "2026-10-08T00:00:00+00:00"))
        usage.update(_Usage("b", "y", self.window, 90.0,
                            "2026-10-08T00:00:00+00:00"))
        result = self.route(catalog, usage, usage_window=self.window)
        self.assertEqual(result.selected.entry.key, ("a", "x"))
        result = self.route(catalog, usage, usage_window=self.window,
                            selection_mode="usage")
        self.assertEqual(result.selected.entry.key, ("b", "y"))
        self.assertEqual(result.reason, "comparable_usage")

    def test_usage_mode_keeps_unknown_eligible_without_penalty(self):
        catalog = Catalog((self.entry("a", "x", 3), self.entry("b", "y", 2)))
        usage = UsageStore()
        usage.update(_Usage("b", "y", self.window, 90.0,
                            "2026-10-08T00:00:00+00:00"))
        result = self.route(catalog, usage, usage_window=self.window,
                            selection_mode="usage")
        self.assertEqual(result.selected.entry.key, ("a", "x"))
        self.assertEqual(result.reason, "suitability_then_stable_order")

    def test_fixed_constraints_and_no_fallback(self):
        catalog = Catalog((self.entry("a", "x", 3), self.entry("b", "y", 1)))
        usage = UsageStore()
        result = self.route(catalog, usage, selection_mode="fixed",
                            explicit_model="b", explicit_adapter="y")
        self.assertEqual(result.selected.entry.key, ("b", "y"))
        self.assertEqual(result.reason, "exact_match")
        self.assertEqual(result.excluded[0].reason, "explicit_selection_mismatch")
        result = self.route(catalog, usage, selection_mode="fixed",
                            explicit_model="absent", explicit_adapter="z")
        self.assertIsNone(result.selected)
        self.assertEqual(result.reason, "no_eligible_route")
        for kwargs in ({"selection_mode": "fixed"},
                       {"selection_mode": "fixed", "explicit_model": "a"},
                       {"selection_mode": "fixed", "explicit_adapter": "x"},
                       {"selection_mode": "bogus"},
                       {"selection_mode": None}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.route(catalog, usage, **kwargs)

    def test_explicit_selectors_still_constrain_default_mode(self):
        catalog = Catalog((self.entry("a", "x", 3), self.entry("b", "y", 3)))
        result = self.route(catalog, UsageStore(), explicit_model="b")
        self.assertEqual(result.selected.entry.key, ("b", "y"))
        self.assertEqual(len(result.eligible), 1)
        self.assertEqual(result.excluded[0].reason, "explicit_selection_mismatch")
