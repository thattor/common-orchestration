"""Pure shared ordering over already-eligible exact Model + Adapter options.

Callers gate eligibility, minimum fit, controls, and qualification before these
candidates are built; ranking here grants no permission and never substitutes
for rejudgment. Unknown usage stays eligible without a quota penalty or an
invented percentage. Unknown ratings follow rated candidates. Quota comparison is valid only inside
one explicit bucket identity (comparison_group): options without a group, or
in different groups, are incomparable and fall back to fit then stable input
order. low_remaining is trusted provider-specific evidence supplied by the
caller; it is never inferred from a percentage here.
"""
import math
from collections.abc import Iterable
from dataclasses import dataclass

MODES = frozenset({"suitability", "usage", "fixed"})


def _identifier(value) -> bool:
    return type(value) is str and bool(value.strip()) and value == value.strip()


def _key(value) -> bool:
    return (type(value) is tuple and len(value) == 2
            and all(_identifier(part) for part in value))


def _fit(option) -> int:
    # Zero is an ordering sentinel only; the public unknown rating stays None.
    return option.suitability or 0


@dataclass(frozen=True)
class SelectionCandidate:
    """One eligible option: opaque (model, adapter) identity plus evidence.

    suitability is a coarse degree 1..3 or None for a verified but unrated
    use. remaining_percent is a finite 0..100 observation meaningful only
    inside comparison_group; None means unknown or incomparable. low_remaining
    marks trusted evidence of near-exhaustion independent of a comparable
    percentage and is never derived from the percent value.
    """
    key: tuple[str, str]
    suitability: int | None
    remaining_percent: float | None = None
    comparison_group: str | None = None
    low_remaining: bool = False

    def __post_init__(self):
        if not _key(self.key):
            raise ValueError("key must be an exact (model, adapter) tuple")
        if self.suitability is not None and (
                type(self.suitability) is not int
                or self.suitability not in (1, 2, 3)):
            raise ValueError("suitability must be degree 1..3 or unknown")
        if self.remaining_percent is not None and (
                type(self.remaining_percent) not in (int, float)
                or not 0 <= self.remaining_percent <= 100
                or not math.isfinite(self.remaining_percent)):
            raise ValueError("remaining_percent must be finite within 0..100")
        if self.comparison_group is not None and not _identifier(self.comparison_group):
            raise ValueError("comparison_group must be an exact bucket identity")
        if type(self.low_remaining) is not bool:
            raise ValueError("low_remaining must be a boolean")


@dataclass(frozen=True)
class SelectionDecision:
    selected: SelectionCandidate | None
    reason: str

    def __post_init__(self):
        if self.selected is not None and type(self.selected) is not SelectionCandidate:
            raise ValueError("selected must be a SelectionCandidate or None")
        if type(self.reason) is not str or not self.reason:
            raise ValueError("reason is required")


def _comparable(options) -> bool:
    groups = {option.comparison_group for option in options}
    return (len(options) > 1 and len(groups) == 1 and None not in groups
            and all(option.remaining_percent is not None for option in options))


def _fit_order(options) -> SelectionDecision:
    best = max(_fit(option) for option in options)
    peers = [option for option in options if _fit(option) == best]
    if _comparable(peers):
        # max returns the first maximum, preserving stable input order on ties.
        return SelectionDecision(
            max(peers, key=lambda option: option.remaining_percent),
            "comparable_usage")
    return SelectionDecision(peers[0], "suitability_then_stable_order")


def _usage_order(options) -> SelectionDecision:
    if _comparable(options):
        ranked = sorted(options, key=lambda option: (-option.remaining_percent,
                                                   -_fit(option)))
        return SelectionDecision(ranked[0], "comparable_usage")
    normal = sorted((option for option in options if not option.low_remaining),
                    key=_fit, reverse=True)
    low = sorted((option for option in options if option.low_remaining),
                 key=_fit, reverse=True)
    return SelectionDecision((normal + low)[0],
                             "low_remaining_avoided" if normal and low
                             else "suitability_then_stable_order")


def select_candidates(candidates: Iterable[SelectionCandidate], *,
                      mode: str = "suitability",
                      exact_key: tuple[str, str] | None = None) -> SelectionDecision:
    """Order eligible candidates; exact constraints apply before ranking.

    'suitability' picks the best fit, comparing remaining quota only when every
    top-fit peer shares one nonempty comparable bucket. 'usage' compares quota
    across all candidates only when all are comparable; otherwise candidates
    with trusted low-remaining evidence move behind others, then fit, then
    input order. 'fixed' requires exact_key and never falls back: a missing
    exact option returns no match. Input order is the final stable tie-break.
    """
    if type(mode) is not str or mode not in MODES:
        raise ValueError("unknown selection mode")
    if exact_key is not None and not _key(exact_key):
        raise ValueError("exact_key must be an exact (model, adapter) tuple")
    if mode == "fixed" and exact_key is None:
        raise ValueError("fixed mode requires exact_key")
    if not isinstance(candidates, Iterable):
        raise ValueError("ordered candidates are required")
    ordered = list(candidates)
    if any(type(option) is not SelectionCandidate for option in ordered):
        raise ValueError("candidates must be SelectionCandidate")
    if len({option.key for option in ordered}) != len(ordered):
        raise ValueError("duplicate candidate identity")
    if not ordered:
        return SelectionDecision(None, "no_candidate")
    if exact_key is not None:
        ordered = [option for option in ordered if option.key == exact_key]
        if not ordered:
            return SelectionDecision(None, "no_match")
    if mode == "fixed":
        return SelectionDecision(ordered[0], "exact_match")
    if mode == "usage":
        return _usage_order(ordered)
    return _fit_order(ordered)
