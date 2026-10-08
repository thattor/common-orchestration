"""Regression tests for the Devin model-list cost gate.

infer._devin_cost_free walks `devin models list --format json` output.
A malformed variants group must make only that family ineligible - never
raise - while later families are still examined; exact model matching
and the Free-only policy stay unchanged.
"""

import json
import unittest

from co_v4.task import infer

MODEL = "swe-2-high"
MALFORMED_VARIANTS = [True, 1, 0, 1.5, 0.0]


def _family(variants):
    return {"family_uid": "swe-2", "variants": variants}


def _variant(model_uid=MODEL, cost_tier="Free"):
    return {"model_uid": model_uid, "cost_tier": cost_tier}


def _doc(families):
    return {"families": families}


def _free(model_list):
    return infer._devin_cost_free(model_list, MODEL)


class CostGateTests(unittest.TestCase):
    def test_malformed_variants_alone_returns_false(self):
        for bad in MALFORMED_VARIANTS:
            with self.subTest(variants=bad):
                self.assertIs(_free(_doc([_family(bad)])), False)

    def test_malformed_family_then_valid_free(self):
        for bad in MALFORMED_VARIANTS:
            with self.subTest(variants=bad):
                self.assertIs(
                    _free(_doc([_family(bad), _family([_variant()])])),
                    True)

    def test_malformed_family_then_paid(self):
        for bad in MALFORMED_VARIANTS:
            with self.subTest(variants=bad):
                self.assertIs(_free(_doc(
                    [_family(bad),
                     _family([_variant(cost_tier="Paid")])])), False)

    def test_wellformed_free_paid_missing_tier(self):
        self.assertIs(_free(_doc([_family([_variant()])])), True)
        self.assertIs(
            _free(_doc([_family([_variant(cost_tier="Paid")])])), False)
        self.assertIs(
            _free(_doc([_family([{"model_uid": MODEL}])])), False)

    def test_exact_model_matching(self):
        for uid in ("swe-2-high-preview", "SWE-2-HIGH", "other-model"):
            with self.subTest(model_uid=uid):
                self.assertIs(
                    _free(_doc([_family([_variant(model_uid=uid)])])),
                    False)
        self.assertIs(_free(_doc([])), False)
        self.assertIs(
            infer._devin_cost_free(_doc([_family([_variant()])]),
                                   "other-model"), False)

    def test_skippable_family_shapes(self):
        skippable = [
            _family([]),                # empty variants list
            {"family_uid": "swe-2"},    # missing variants key
            _family(None),              # variants None
            "not-a-dict",               # non-dict family
            None,                       # non-dict family
        ]
        for bad in skippable:
            with self.subTest(family=bad):
                self.assertIs(_free(_doc([bad])), False)
                self.assertIs(
                    _free(_doc([bad, _family([_variant()])])), True)

    def test_non_dict_variant_skipped(self):
        for bad in ("not-a-dict", None, 42):
            with self.subTest(variant=bad):
                self.assertIs(_free(_doc([_family([bad])])), False)
                self.assertIs(
                    _free(_doc([_family([bad]), _family([_variant()])])),
                    True)

    def test_non_list_families_returns_false(self):
        self.assertIs(_free({}), False)
        for families in ({"swe-2": {}}, "families"):
            with self.subTest(families=families):
                self.assertIs(_free({"families": families}), False)

    def test_json_roundtrip_variants_true(self):
        doc = json.loads('{"families": [{"family_uid": "swe-2",'
                         ' "variants": true}, {"family_uid": "swe-2",'
                         ' "variants": [{"model_uid": "swe-2-high",'
                         ' "cost_tier": "Free"}]}]}')
        self.assertIs(_free(doc), True)


if __name__ == "__main__":
    unittest.main()
