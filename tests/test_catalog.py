from dataclasses import replace
import unittest

from co_v4.catalog import Candidate, Catalog, CatalogEntry, UseCase, Verification


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.use = UseCase("coding")
        self.evidence = Verification("model", "adapter", self.use, "fixture:environment-v1",
                                     "fixture:official", "fixture:implementation",
                                     "fixture:measurement", "fixture:ac-pass")

    def entry(self, **changes):
        fields = dict(model="model", adapter="adapter", recommended_for={self.use: 3},
                      verifications=(self.evidence,))
        fields.update(changes)
        return CatalogEntry(**fields)

    def test_empty_default_and_candidates_never_promoted(self):
        self.assertEqual(Catalog().entries, ())
        with self.assertRaises(ValueError):
            Catalog((Candidate("model", "adapter", "official:discovery"),))
        with self.assertRaises(ValueError):
            self.entry(verifications=())

    def test_each_evidence_stage_is_required(self):
        for field in ("official_ref", "implementation_ref", "measurement_ref", "ac_ref"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(self.evidence, **{field: ""})

    def test_verification_cannot_leak_across_combination_use_role_or_environment(self):
        for field in ("model", "adapter"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.entry(verifications=(replace(self.evidence, **{field: "different"}),))
        entry = self.entry()
        self.assertIsNone(entry.verification(UseCase("review"), self.evidence.environment_ref))
        self.assertIsNone(entry.verification(UseCase("coding", role="controller"),
                                             self.evidence.environment_ref))
        self.assertIsNone(entry.verification(self.use, "fixture:environment-v2"))
        self.assertEqual(entry.verification(self.use, self.evidence.environment_ref), self.evidence)

    def test_unknown_rating_is_not_unsupported_and_general_not_wildcard(self):
        entry = self.entry(recommended_for={})
        self.assertIsNone(entry.recommended_for.get(self.use))
        self.assertIsNotNone(entry.verification(self.use, self.evidence.environment_ref))
        self.assertIsNone(entry.verification(UseCase("general"), self.evidence.environment_ref))
        with self.assertRaises(ValueError):
            self.entry(recommended_for={UseCase("review"): 3})

    def test_coarse_ratings_and_other_controller_use(self):
        for degree in (0, 4, True, 2.5, "3"):
            with self.subTest(degree=degree), self.assertRaises(ValueError):
                self.entry(recommended_for={self.use: degree})
        other = UseCase("other", "Japanese editing", "controller")
        entry = self.entry(recommended_for={other: 2},
                           verifications=(replace(self.evidence, use_case=other),))
        self.assertEqual(entry.recommended_for[other], 2)
        for args in (("other",), ("coding", "free text"), ("invented",)):
            with self.assertRaises(ValueError):
                UseCase(*args)
        self.assertIsNone(entry.verification(UseCase("other", "English editing", "controller"),
                                             self.evidence.environment_ref))

    def test_snapshot_copies_input_and_rejects_duplicates(self):
        ratings, extra, evidence = {self.use: 3}, {"note": "reviewed"}, [self.evidence]
        entry = self.entry(recommended_for=ratings, extra=extra, verifications=evidence)
        ratings.clear(); extra.clear(); evidence.clear()
        self.assertEqual(entry.recommended_for[self.use], 3)
        self.assertEqual(entry.extra["note"], "reviewed")
        self.assertEqual(len(entry.verifications), 1)
        with self.assertRaises(TypeError):
            entry.recommended_for[self.use] = 1
        with self.assertRaises(ValueError):
            Catalog((entry, entry))
        with self.assertRaises(ValueError):
            self.entry(verifications=(self.evidence, self.evidence))
