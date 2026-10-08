"""Dynamic Usage cache, independent of Catalog; no provider polling or estimates."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .contracts import Usage


def _instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("usage time must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class UsageView:
    remaining_percent: float | None
    # Preserve raw observation even when it cannot be used for comparison.
    sample: Usage | None
    reason: str


class UsageStore:
    """Single-writer in-memory store. Caller supplies time and freshness policy.

    Window names must identify comparable allocation buckets, not merely a
    duration. Call invalidate on unavailable collection when prior data should
    no longer be trusted. No missing value becomes zero or full capacity.
    """
    def __init__(self):
        self._samples: dict[tuple[str, str, str], Usage] = {}

    def update(self, sample: Usage) -> None:
        observed = _instant(sample.updated_at)
        key = sample.model, sample.adapter, sample.window
        previous = self._samples.get(key)
        if previous is not None:
            previous_time = _instant(previous.updated_at)
            if observed < previous_time:
                return  # Delayed delivery cannot restore an older allowance.
            if observed == previous_time and sample != previous:
                raise ValueError("conflicting observations at the same instant")
        self._samples[key] = sample

    def invalidate(self, model: str, adapter: str, window: str) -> None:
        self._samples.pop((model, adapter, window), None)

    def view(self, model: str, adapter: str, window: str, *, now: datetime,
             max_age: timedelta) -> UsageView:
        if now.tzinfo is None or now.utcoffset() is None or max_age < timedelta(0):
            raise ValueError("aware current time and nonnegative max_age required")
        sample = self._samples.get((model, adapter, window))
        if sample is None:
            return UsageView(None, None, "missing")
        age = now.astimezone(timezone.utc) - _instant(sample.updated_at)
        if age < timedelta(0):
            return UsageView(None, sample, "future")
        if age > max_age:
            return UsageView(None, sample, "stale")
        return UsageView(sample.remaining_percent, sample, "fresh")
