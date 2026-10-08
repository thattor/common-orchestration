"""Catalog selection seam for the Controller; does not execute or authorize.

#157/#158 must supply current, trusted per-Job assessments of actual conditions
and necessary controls. This module does not implement Judgment, preflight,
rejection/timeout handling, lifecycle state, or final acceptance criteria.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from .catalog import Catalog, CatalogEntry, UseCase, Verification
from .contracts import Decision, ExecutionConditions, Job
from .selection import MODES, SelectionCandidate, select_candidates
from .usage import UsageStore, UsageView


@dataclass(frozen=True)
class Assessment:
    job: Job
    conditions: ExecutionConditions
    decision: Decision
    decision_ref: str
    # True only after trusted preflight verifies required enforcement/isolation.
    controls_verified: bool = False

    @property
    def key(self) -> tuple[str, str]:
        return self.conditions.model, self.conditions.adapter


@dataclass(frozen=True)
class RouteOption:
    entry: CatalogEntry
    assessment: Assessment
    verification: Verification
    usage: UsageView


@dataclass(frozen=True)
class Exclusion:
    model: str
    adapter: str
    reason: str


@dataclass(frozen=True)
class RoutingResult:
    selected: RouteOption | None
    eligible: tuple[RouteOption, ...]
    excluded: tuple[Exclusion, ...]
    reason: str


def select_route(catalog: Catalog, job: Job, use_case: UseCase,
                 assessments: Iterable[Assessment], usage: UsageStore, *,
                 now: datetime, max_usage_age: timedelta,
                 usage_window: str | None = None,
                 explicit_model: str | None = None,
                 explicit_adapter: str | None = None,
                 selection_mode: str = "suitability") -> RoutingResult:
    """Exact explicit constraints, coarse suitability, then comparable Usage.

    An explicit but unavailable selection returns no route, never a silent
    fallback. Missing recommendation stays unknown (not unsupported): verified
    uses with no rating remain eligible after rated uses. Compare remaining
    quota only when ALL equally suitable options have fresh samples for the
    requested common window. Otherwise use stable Model/Adapter ordering.
    selection_mode='usage' instead ranks all eligible options by comparable
    remaining quota before fit; 'fixed' pins the route to the explicit pair,
    requires both selectors, and never falls back. This policy grants no
    permission: selection is a snapshot, not authority to skip rejudgment
    before execution.
    """
    if type(selection_mode) is not str or selection_mode not in MODES:
        raise ValueError("unknown selection mode")
    if selection_mode == "fixed" and (explicit_model is None
                                     or explicit_adapter is None):
        raise ValueError("fixed mode requires explicit Model and Adapter")
    for value in (explicit_model, explicit_adapter, usage_window):
        if value is not None and (not isinstance(value, str) or not value.strip()
                                  or value != value.strip()):
            raise ValueError("selectors must be nonempty exact identifiers")
    by_key = {}
    for assessment in assessments:
        if assessment.key in by_key:
            raise ValueError("duplicate assessment for Model + Adapter")
        by_key[assessment.key] = assessment
    eligible, excluded = [], []
    for entry in catalog.entries:
        assessment = by_key.get(entry.key)
        reason = None
        verification = None
        if ((explicit_model is not None and entry.model != explicit_model) or
                (explicit_adapter is not None and entry.adapter != explicit_adapter)):
            reason = "explicit_selection_mismatch"
        elif assessment is None or assessment.job != job:
            reason = "missing_current_job_assessment"
        elif assessment.decision is not Decision.NORMAL:
            reason = "judgment_not_normal"
        elif not assessment.decision_ref.strip():
            reason = "missing_judgment_evidence"
        elif (assessment.controls_verified is not True or
              not assessment.conditions.workspace.strip() or
              not assessment.conditions.environment_ref.strip() or
              not assessment.conditions.control_evidence_refs or
              any(not ref.strip() for ref in assessment.conditions.control_evidence_refs)):
            reason = "unverified_execution_conditions"
        else:
            verification = entry.verification(use_case, assessment.conditions.environment_ref)
            if verification is None:
                reason = "use_or_environment_unverified"
            elif job.output_candidate and verification.output_mode != 'collect':
                reason = "output_collect_unverified"
            elif catalog.lifecycle is not None:
                reason = catalog.lifecycle.admission_reason(entry.model, entry.adapter,
                    verification.auth_route, now=now)
        if reason:
            excluded.append(Exclusion(*entry.key, reason))
            continue
        view = (usage.view(*entry.key, usage_window, now=now, max_age=max_usage_age)
                if usage_window is not None else UsageView(None, None, "window_unspecified"))
        eligible.append(RouteOption(entry, assessment, verification, view))
    if not eligible:
        return RoutingResult(None, (), tuple(excluded), "no_eligible_route")
    candidates = []
    for option in sorted(eligible, key=lambda o: o.entry.key):
        fresh = (option.usage.reason == "fresh"
                 and option.usage.remaining_percent is not None)
        candidates.append(SelectionCandidate(
            key=option.entry.key,
            suitability=option.entry.recommended_for.get(use_case),
            remaining_percent=option.usage.remaining_percent if fresh else None,
            comparison_group=usage_window if fresh else None))
    decision = select_candidates(
        candidates, mode=selection_mode,
        exact_key=(explicit_model, explicit_adapter)
        if selection_mode == "fixed" else None)
    selected = (next((o for o in eligible if o.entry.key == decision.selected.key), None)
                if decision.selected is not None else None)
    return RoutingResult(selected, tuple(eligible), tuple(excluded), decision.reason)
