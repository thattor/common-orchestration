"""Pinned Devin selection; no billing, authentication or availability inference.

CLI 3000.11.3 expresses SWE-2 effort in the exact model UID, not --effort.
Aliases are deliberately closed. New Native UIDs require reviewed metadata.
"""
from dataclasses import dataclass

EFFORTS = ("medium", "high", "max")
FAMILY_VARIANTS = {
    "swe-2": {effort: "swe-2-" + effort for effort in EFFORTS},
    "swe-1.7": {"medium": "swe-1-7-medium", "max": "swe-1-7"},
    "swe-1.7-lightning": {"medium": "swe-1-7-lightning-medium", "max": "swe-1-7-lightning"},
}
# SWE-1.7 effort names describe selectable variants in the pinned metadata;
# neither those labels nor CLI arguments attest effective Native reasoning.
VARIANT_EFFORT = {uid: effort for variants in FAMILY_VARIANTS.values() for effort, uid in variants.items()}
EXACT_MODELS = frozenset({"swe-1-6", "swe-1-6-fast", *VARIANT_EFFORT})


def resolve_model(model: str, effort: str | None = None) -> str:
    """Resolve a trusted family selection before constructing ExecutionConditions."""
    if type(model) is not str or (effort is not None and effort not in EFFORTS):
        raise ValueError("unsupported_devin_selection")
    if model in FAMILY_VARIANTS and effort in FAMILY_VARIANTS[model]:
        return FAMILY_VARIANTS[model][effort]
    if model not in EXACT_MODELS:
        raise ValueError("unsupported_devin_model")
    if effort is not None and VARIANT_EFFORT.get(model) != effort:
        raise ValueError("contradictory_devin_effort")
    return model


def selection(model: str, effort: str | None = None) -> dict:
    exact = resolve_model(model, effort)
    return {"requested_model": exact,
            "effort": VARIANT_EFFORT.get(exact),
            "effort_binding": "exact_native_model_uid"}


@dataclass
class ModelObservation:
    """Validate each advertisement, including superseded queued observations.

    Missing whole advertisements are invocation-bound only. A present models
    object must be complete; current_model_update can report just the current UID.
    No display labels are used as identity or pricing evidence.
    """
    requested: str
    current: str | None = None
    available: tuple[str, ...] | None = None

    def observe(self, fields: dict, *, current_update: bool = False) -> bool:
        advertisements = []
        if "models" in fields:
            if not isinstance(fields["models"], dict):
                raise ValueError("invalid Native model advertisement")
            advertisements.append((fields["models"], False))
        if "availableModels" in fields or "currentModelId" in fields:
            advertisements.append((fields, current_update and "availableModels" not in fields))
        if current_update and not advertisements:
            raise ValueError("invalid Native model advertisement")
        for values, partial in advertisements:
            current = values.get("currentModelId")
            if type(current) is not str or not current:
                raise ValueError("invalid Native model advertisement")
            available = self.available
            if not partial:
                items = values.get("availableModels")
                if type(items) is not list or not items:
                    raise ValueError("invalid Native model advertisement")
                ids = [item.get("modelId") if isinstance(item, dict) else None for item in items]
                if (any(type(uid) is not str or not uid for uid in ids)
                        or len(set(ids)) != len(ids) or current not in ids):
                    raise ValueError("invalid Native model advertisement")
                available = tuple(ids)
            if current != self.requested or (available is not None and current not in available):
                raise ValueError("Native model mismatch")
            self.current, self.available = current, available
        return bool(advertisements)

    def evidence(self) -> dict:
        return {"requested_model": self.requested, "effective_model": self.current,
                "effective_model_verified": self.current is not None,
                "effective_effort_verified": False,
                "model_binding": ("native_session_advertisement" if self.current is not None
                                  else "invocation_bound_only")}
