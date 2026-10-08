from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.contracts import Decision, ExecutionConditions, Job, Usage
from co_v4.routing import Assessment, select_route
from co_v4.usage import UsageStore


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.job = Job("run", "job", "Review fixture", ("fixture inspected",))
        self.use = UseCase("review")
        self.now = datetime(2026, 9, 28, 12, tzinfo=timezone.utc)
        self.usage = UsageStore()
        self.a, self.b = self.entry("a"), self.entry("b")

    def entry(self, model, adapter="fixture-adapter", rating=2):
        evidence = Verification(model, adapter, self.use, "fixture:environment-v1",
                                "fixture:official", "fixture:implementation",
                                "fixture:measurement", "fixture:ac-pass")
        return CatalogEntry(model, adapter, {} if rating is None else {self.use: rating},
                            (evidence,))

    def assessment(self, entry, **changes):
        value = Assessment(self.job, ExecutionConditions(*entry.key, "/fixture",
                           "fixture:environment-v1", ("fixture:control-validation",)),
                           Decision.NORMAL, "fixture:decision", True)
        return replace(value, **changes)

    def sample(self, entry, remaining, **changes):
        value = Usage(*entry.key, remaining, "2026-09-28T12:00:00Z",
                      "fixture:usage", "fixture:common-bucket")
        self.usage.update(replace(value, **changes))

    def route(self, entries=None, assessments=None, **changes):
        entries = (self.a, self.b) if entries is None else entries
        args = dict(now=self.now, max_usage_age=timedelta(minutes=1),
                    usage_window="fixture:common-bucket")
        args.update(changes)
        return select_route(Catalog(entries), self.job, self.use,
                            tuple(self.assessment(e) for e in entries)
                            if assessments is None else assessments, self.usage, **args)

    def test_explicit_selection_precedes_suitability_no_silent_fallback(self):
        higher = self.entry("a", rating=3)
        self.assertEqual(self.route((higher, self.b), explicit_model="b").selected.entry, self.b)
        self.assertIsNone(self.route(explicit_model="missing").selected)
        self.assertIsNone(self.route(explicit_adapter="missing").selected)
        alternate = self.entry("a", "different-adapter", rating=3)
        result = self.route((self.a, alternate), explicit_adapter="fixture-adapter")
        self.assertEqual(result.selected.entry, self.a)

    def test_explicit_high_rating_cannot_bypass_judgment(self):
        for decision in (Decision.CONFIRM, Decision.DENY, Decision.UNDETERMINED):
            with self.subTest(decision=decision):
                result = self.route(assessments=(self.assessment(self.a, decision=decision),
                                                self.assessment(self.b)), explicit_model="a")
                self.assertIsNone(result.selected)
                self.assertIn("judgment_not_normal", [e.reason for e in result.excluded])

    def test_missing_controls_or_changed_conditions_are_not_executable(self):
        valid = self.assessment(self.a)
        changes = [replace(valid, controls_verified=False), replace(valid, decision_ref=""),
                   replace(valid, job=replace(self.job, instructions="different job intent")),
                   replace(valid, job=replace(self.job, run_id="other-run"))]
        for fields in ({"environment_ref": "fixture:new-configuration"},
                       {"control_evidence_refs": ()}, {"workspace": ""}):
            changes.append(replace(valid, conditions=replace(valid.conditions, **fields)))
        for assessment in changes:
            with self.subTest(assessment=assessment):
                self.assertIsNone(self.route((self.a,), (assessment,)).selected)
        self.assertIsNone(self.route((self.a,), ()).selected)

    def test_usage_breaks_only_equal_suitability_with_comparable_fresh_samples(self):
        self.sample(self.a, 10); self.sample(self.b, 90)
        result = self.route()
        self.assertEqual(result.selected.entry, self.b)
        self.assertEqual(result.reason, "comparable_usage")
        higher = self.entry("a", rating=3)
        self.assertEqual(self.route((higher, self.b)).selected.entry, higher)
        self.assertEqual(self.route(usage_window=None).selected.entry, self.a)

    def test_unknown_stale_future_or_other_window_does_not_gain_usage_rank(self):
        for changes in ({"window": "different-bucket"},
                        {"updated_at": "2026-09-28T11:58:00Z"},
                        {"updated_at": "2026-09-28T12:01:00Z"}):
            self.usage = UsageStore()
            self.sample(self.a, 10, **changes); self.sample(self.b, 90)
            result = self.route()
            self.assertEqual(result.selected.entry, self.a)
            self.assertIsNone(result.selected.usage.remaining_percent)
        self.usage = UsageStore()
        self.sample(self.b, 90)
        self.assertEqual(self.route().selected.entry, self.a)

    def test_unknown_rating_still_eligible_but_unverified_use_is_not(self):
        unknown = self.entry("c", rating=None)
        result = self.route((unknown,))
        self.assertEqual(result.selected.entry, unknown)
        self.assertIsNone(result.selected.entry.recommended_for.get(self.use))
        unverified = replace(self.a, recommended_for={}, verifications=(
            replace(self.a.verifications[0], use_case=UseCase("coding")),))
        self.assertIsNone(self.route((unverified,)).selected)

    def test_catalog_only_addition_uses_existing_adapter_without_provider_logic(self):
        before = self.route((self.a,), explicit_model="new-model")
        self.assertIsNone(before.selected)
        added = self.entry("new-model")
        after = self.route((self.a, added), explicit_model="new-model")
        self.assertEqual(after.selected.entry, added)
        self.assertEqual(after.selected.assessment.conditions.adapter, self.a.adapter)

    def test_stable_order_does_not_depend_on_catalog_order_and_empty_is_safe(self):
        self.assertEqual(self.route((self.b, self.a)).selected.entry, self.a)
        self.assertIsNone(self.route(()).selected)
        for value in ("", " "):
            with self.assertRaises(ValueError):
                self.route(explicit_model=value)
        with self.assertRaises(ValueError):
            self.route(assessments=(self.assessment(self.a), self.assessment(self.a)))
