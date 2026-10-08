"""Codex-only process-local fast mode policy; no launch or authority on import."""
import tomllib

from .codex_errors import HostUnverified


def select_service_tier(mode=None, service_tier="default"):
    """Canonical fast mode, with tibo as an input alias; preserve legacy omission."""
    service_tier_overrides(service_tier)
    if mode is None:
        return service_tier
    if type(mode) is not str or mode not in {"normal", "fast", "tibo"}:
        raise HostUnverified("qualification_mode_unsupported")
    selected = "fast" if mode == "tibo" else mode
    if service_tier != "default" and service_tier != selected:
        raise HostUnverified("qualification_service_tier_override_conflict")
    return selected


def subscription_gate(account_response, usage_response, *, api_environment_absent):
    """Backend ordinaryUsageAllowed is authoritative; percentages are not."""
    account = account_response.get("account") if type(account_response) is dict else None
    allowed_plans = {"plus", "pro", "prolite", "promax", "team", "business", "enterprise", "edu", "edu_plus", "edu_pro"}
    if (api_environment_absent is not True or type(account) is not dict
            or account.get("type") != "chatgpt" or type(account.get("planType")) is not str
            or account.get("planType") not in allowed_plans
            or account_response.get("requiresOpenaiAuth") is not True
            or type(usage_response) is not dict or usage_response.get("ordinaryUsageAllowed") is not True
            or type(usage_response.get("rateLimits")) is not dict):
        raise HostUnverified("included_subscription_usage_unverified")
    return {"account_type": "chatgpt", "plan_type": account["planType"],
            "ordinary_included_usage_allowed": True, "api_environment_absent": True,
            "additional_payment_or_grant_enabled": False}


def service_tier_overrides(tier):
    """Process-only selection; subscription and actual Native tier still gate send."""
    if type(tier) is not str or tier not in {"default", "normal", "fast"}:
        raise HostUnverified("qualification_service_tier_unsupported")
    if tier == "normal":
        return ('service_tier="default"', 'features.fast_mode=false')
    return () if tier == "default" else ('service_tier="fast"', 'features.fast_mode=true')


def service_tier_diagnostic(effective, native):
    """Fixed booleans only; never echo unknown config or Native values."""
    config = effective if type(effective) is dict else {}
    thread = native if type(native) is dict else {}
    features = config.get("features")
    return {"config_object": type(effective) is dict, "thread_object": type(native) is dict,
        "config_tier_present": "service_tier" in config,
        "config_tier_string": type(config.get("service_tier")) is str,
        "config_tier_null": config.get("service_tier") is None,
        "config_tier_fast": config.get("service_tier") == "fast",
        "config_tier_default": config.get("service_tier") == "default",
        "thread_tier_present": "serviceTier" in thread,
        "thread_tier_string": type(thread.get("serviceTier")) is str,
        "thread_tier_null": thread.get("serviceTier") is None,
        "thread_tier_fast": thread.get("serviceTier") == "fast",
        "thread_tier_priority": thread.get("serviceTier") == "priority",
        "thread_tier_default": thread.get("serviceTier") == "default",
        "features_object": type(features) is dict,
        "fast_feature_present": type(features) is dict and "fast_mode" in features,
        "fast_feature_boolean": type(features) is dict and type(features.get("fast_mode")) is bool,
        "fast_feature_enabled": type(features) is dict and features.get("fast_mode") is True}


def verify_service_tier(tier, effective, native):
    service_tier_overrides(tier)
    if type(effective) is not dict or type(native) is not dict:
        raise HostUnverified("qualification_service_tier_unverified")
    config_tier, thread_tier = effective.get("service_tier"), native.get("serviceTier")
    if tier == "fast":
        features = effective.get("features")
        # Fixed 0.159.2 core config normalizes Fast.request_value() to
        # "priority"; the thread/start producer returns that effective value.
        valid = (config_tier == "fast" and thread_tier == "priority" and type(features) is dict
                 and features.get("fast_mode") is True)
    elif tier == "normal":
        features = effective.get("features")
        valid = ("service_tier" in effective and config_tier == "default"
                 and "serviceTier" in native and thread_tier in (None, "default")
                 and type(features) is dict and features.get("fast_mode") is False)
    else:
        valid = config_tier in (None, "default") and thread_tier in (None, "default")
    if not valid:
        raise HostUnverified("qualification_service_tier_unverified")
    features = effective.get("features")
    fast_mode = features.get("fast_mode") if type(features) is dict else None
    return {"requested": tier, "sent_config_overrides": list(service_tier_overrides(tier)),
            "effective_fast_mode": fast_mode if type(fast_mode) is bool else None,
            "effective_config": config_tier,
            "original_thread_response": thread_tier, "matched_before_turn": True,
            "fast_configuration_verified": tier == "fast", "speed_increase_measured": False}



def append_service_tier_overrides(overrides, tier):
    """Reject competing keys, including TOML quoted/dotted/table spellings."""
    selected = service_tier_overrides(tier)
    if type(overrides) is not tuple:
        raise HostUnverified("qualification_service_tier_override_conflict")
    for value in overrides:
        try:
            parsed = tomllib.loads(value)
        except (TypeError, ValueError):
            raise HostUnverified("qualification_service_tier_override_conflict") from None
        if ("service_tier" in parsed or ("features" in parsed and
                (type(parsed["features"]) is not dict or "fast_mode" in parsed["features"]))):
            raise HostUnverified("qualification_service_tier_override_conflict")
    return overrides + selected
