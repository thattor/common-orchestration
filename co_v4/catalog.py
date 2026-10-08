"""Trusted, in-process Catalog snapshots; no discovery or automatic promotion.

Evidence references are attestations supplied by the CO maintainer after review,
not proof checked by this module. Never construct these from Worker output.
Empty Catalog is the production default; fixture evidence is not live evidence.
"""
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from .model_lifecycle import AUTH_ROUTES, ModelLifecyclePolicy

CATEGORIES = frozenset({"coding", "review", "research", "architecture_planning",
                        "reasoning", "writing", "general", "other"})


def _text(value: str) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


@dataclass(frozen=True)
class UseCase:
    category: str
    other: str = ""
    role: str = "worker"

    def __post_init__(self):
        if self.category not in CATEGORIES or self.role not in {"worker", "controller"}:
            raise ValueError("unknown category or role")
        if (self.category == "other" and not _text(self.other)) or (
                self.category != "other" and self.other != ""):
            raise ValueError("other requires exact free text only for category other")


@dataclass(frozen=True)
class Verification:
    """Exact combination, use and tested environment/configuration revision.

    environment_ref must identify an immutable configuration, including relevant
    Native/Adapter versions and controls. Changed conditions need new evidence.
    A measurement must cover the use and required controls; logs/schema discovery
    alone cannot establish pre-action enforcement or verified isolation.
    """
    model: str
    adapter: str
    use_case: UseCase
    environment_ref: str
    official_ref: str
    implementation_ref: str
    measurement_ref: str
    ac_ref: str
    # Trusted auth observation belonging to this exact verified environment.
    auth_route: str | None = None
    # Verified output collection: None or 'none' means unverified; only
    # 'collect' may route an output-candidate Job.
    output_mode: str | None = None

    def __post_init__(self):
        if not isinstance(self.use_case, UseCase) or not all(_text(v) for v in (
                self.model, self.adapter, self.environment_ref, self.official_ref,
                self.implementation_ref, self.measurement_ref, self.ac_ref)):
            raise ValueError("verification requires all four reviewed evidence stages")
        if self.auth_route is not None and (type(self.auth_route) is not str or self.auth_route not in AUTH_ROUTES):
            raise ValueError("unknown verified authentication route")
        if self.output_mode is not None and self.output_mode not in {'none', 'collect'}:
            raise ValueError("unknown output mode")


@dataclass(frozen=True)
class Candidate:
    """Unverified discovery information. Catalog deliberately cannot ingest it."""
    model: str
    adapter: str
    source_ref: str


@dataclass(frozen=True)
class CatalogEntry:
    model: str
    adapter: str
    recommended_for: Mapping[UseCase, int]
    verifications: tuple[Verification, ...]
    # Non-secret textual metadata only; never interpreted as permission/control.
    extra: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not all(_text(v) for v in (self.model, self.adapter)):
            raise ValueError("exact model and adapter are required")
        verifications = tuple(self.verifications)
        if not verifications or any(not isinstance(v, Verification) or
                (v.model, v.adapter) != self.key for v in verifications):
            raise ValueError("entry needs verification for this exact combination")
        identities = [(v.use_case, v.environment_ref) for v in verifications]
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate verification scope")
        recommendations = dict(self.recommended_for)
        for use, degree in recommendations.items():
            if (not isinstance(use, UseCase) or type(degree) is not int or
                    degree not in {1, 2, 3} or
                    not any(v.use_case == use for v in verifications)):
                raise ValueError("recommendation requires verified use and degree 1..3")
        extra = dict(self.extra)
        if any(not _text(k) or not isinstance(v, str) for k, v in extra.items()):
            raise ValueError("extra must contain textual metadata")
        object.__setattr__(self, "verifications", verifications)
        object.__setattr__(self, "recommended_for", MappingProxyType(recommendations))
        object.__setattr__(self, "extra", MappingProxyType(extra))

    @property
    def key(self) -> tuple[str, str]:
        return self.model, self.adapter

    def verification(self, use_case: UseCase, environment_ref: str) -> Verification | None:
        return next((v for v in self.verifications if v.use_case == use_case
                     and v.environment_ref == environment_ref), None)


@dataclass(frozen=True)
class Catalog:
    entries: tuple[CatalogEntry, ...] = ()
    lifecycle: ModelLifecyclePolicy | None = None

    def __post_init__(self):
        if self.lifecycle is not None and type(self.lifecycle) is not ModelLifecyclePolicy:
            raise ValueError("loaded trusted lifecycle policy required")
        entries = tuple(self.entries)
        if any(not isinstance(e, CatalogEntry) for e in entries):
            raise ValueError("only explicitly verified Catalog entries are accepted")
        if len({e.key for e in entries}) != len(entries):
            raise ValueError("duplicate Model + Adapter")
        object.__setattr__(self, "entries", entries)
