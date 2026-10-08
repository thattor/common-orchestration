from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from co_v4.contracts import Usage
from co_v4.usage import UsageStore


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.store = UsageStore()
        self.now = datetime(2026, 9, 28, 12, tzinfo=timezone.utc)
        self.sample = Usage("model", "adapter", 40, "2026-09-28T11:59:00Z",
                            "fixture:usage", "fixture:common-bucket")

    def view(self, **changes):
        args = dict(model="model", adapter="adapter", window=self.sample.window,
                    now=self.now, max_age=timedelta(minutes=1))
        args.update(changes)
        return self.store.view(**args)

    def test_missing_stale_future_remain_unknown_with_raw_evidence(self):
        self.assertIsNone(self.view().remaining_percent)
        self.store.update(self.sample)
        self.assertEqual(self.view().remaining_percent, 40)
        for now, reason in ((self.now + timedelta(microseconds=1), "stale"),
                            (self.now - timedelta(minutes=2), "future")):
            view = self.view(now=now)
            self.assertEqual(view.reason, reason)
            self.assertIsNone(view.remaining_percent)
            self.assertEqual(view.sample, self.sample)

    def test_exact_pair_and_window_and_invalidation(self):
        self.store.update(self.sample)
        for change in ({"model": "other"}, {"adapter": "other"}, {"window": "other"}):
            self.assertIsNone(self.view(**change).remaining_percent)
        self.store.invalidate("model", "adapter", self.sample.window)
        self.assertEqual(self.view().reason, "missing")

    def test_delayed_observation_cannot_replace_newer_value(self):
        self.store.update(self.sample)
        self.store.update(replace(self.sample, remaining_percent=99,
                                  updated_at="2026-09-28T11:58:00Z"))
        self.assertEqual(self.view().remaining_percent, 40)
        self.store.update(self.sample)  # Idempotent replay.
        with self.assertRaises(ValueError):
            self.store.update(replace(self.sample, remaining_percent=80))
        self.store.update(replace(self.sample, remaining_percent=0,
                                  updated_at="2026-09-28T12:00:00Z"))
        self.assertEqual(self.view().remaining_percent, 0)

    def test_timezone_offsets_and_bad_time_policy(self):
        self.store.update(replace(self.sample, updated_at="2026-09-28T20:59:00+09:00"))
        self.assertEqual(self.view().remaining_percent, 40)
        for value in ("not-a-time", "2026-09-28T11:59:00"):
            with self.assertRaises(ValueError):
                self.store.update(replace(self.sample, updated_at=value))
        for kwargs in ({"now": self.now.replace(tzinfo=None)},
                       {"max_age": timedelta(seconds=-1)}):
            with self.assertRaises(ValueError):
                self.view(**kwargs)
