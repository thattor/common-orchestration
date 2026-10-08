"""Select against the current owned Native model/list, never a global effort table."""
import hashlib
import json
import re

from .codex_errors import HostUnverified

NATIVE_VERSION = "codex-cli 0.159.2"


def validate_selection(model, effort):
    # Syntax only. Availability and compatibility require this launch's metadata.
    if type(model) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", model) is None:
        raise HostUnverified("qualification_model_unsupported")
    if effort is not None and (type(effort) is not str or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", effort) is None):
        raise HostUnverified("qualification_effort_unsupported")


def model_choices(rpc):
    """Read bounded paginated Native metadata; retain only selection fields."""
    choices, cursors, cursor = {}, set(), None
    for _ in range(16):
        params = {"includeHidden": False, "limit": 100}
        if cursor is not None:
            params["cursor"] = cursor
        page = rpc("model/list", params)
        if type(page) is not dict or type(page.get("data")) is not list or len(page["data"]) > 100:
            raise HostUnverified("model_metadata_invalid")
        for row in page["data"]:
            if type(row) is not dict:
                raise HostUnverified("model_metadata_invalid")
            model, default, options = row.get("model"), row.get("defaultReasoningEffort"), row.get("supportedReasoningEfforts")
            validate_selection(model, default)
            if model in choices or default is None or type(options) is not list or not 1 <= len(options) <= 32:
                raise HostUnverified("model_metadata_invalid")
            efforts = []
            for option in options:
                if type(option) is not dict or option.get("reasoningEffort") is None:
                    raise HostUnverified("model_metadata_invalid")
                value = option["reasoningEffort"]
                validate_selection(model, value)
                if value in efforts:
                    raise HostUnverified("model_metadata_invalid")
                efforts.append(value)
            if default not in efforts:
                raise HostUnverified("model_metadata_invalid")
            choices[model] = {"model": model, "supported_efforts": efforts, "default_effort": default}
        cursor = page.get("nextCursor")
        if cursor is None:
            return choices
        if type(cursor) is not str or not 1 <= len(cursor) <= 1024 or cursor in cursors:
            raise HostUnverified("model_metadata_pagination_invalid")
        cursors.add(cursor)
    raise HostUnverified("model_metadata_page_limit")


def verify_selection(rpc, *, model, effort, effective_effort, native_version, request_digest):
    validate_selection(model, effort)
    if native_version != NATIVE_VERSION:
        raise HostUnverified("model_selection_native_version_unsupported")
    choices = model_choices(rpc)
    selected = choices.get(model)
    if selected is None:
        raise HostUnverified("qualification_model_unsupported")
    supported = selected["supported_efforts"]
    if effort is not None and effort not in supported:
        raise HostUnverified("qualification_effort_unsupported")
    # None means Native/user configuration inheritance, not catalog-default override.
    if ((effective_effort is not None and effective_effort not in supported)
            or (effort is not None and effective_effort != effort)):
        raise HostUnverified("native_reasoning_effort_mismatch")
    return {**selected, "requested_effort": effort, "effective_effort": effective_effort,
            "effective_effort_reported": effective_effort is not None,
            "native_version": native_version, "request_binding_sha256": request_digest,
            "metadata_sha256": hashlib.sha256(json.dumps(choices, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest(),
            "source": "owned_native_model_list", "live_inference_qualified": False}
