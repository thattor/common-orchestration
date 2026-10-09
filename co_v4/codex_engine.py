"""Bounded result projection for the Codex text route; no launch or authority."""

import hashlib
import math

NATIVE_VERSION = "codex-cli 0.160.1"
ADAPTER = "codex.app-server"
CAPABILITY = "codex.readonly.local"
_MAX_OUTPUT_BYTES = 1 << 20
_CODES = frozenset({"route_unavailable", "route_failed", "route_violation",
                    "route_overflow", "route_timeout"})
_PAIRS = frozenset({("not_started", "preflight"), ("not_started", "spawn"),
                    ("unknown", "inference")})
_PLANS = frozenset({"plus", "pro", "prolite", "promax", "team", "business",
                    "enterprise", "edu", "edu_plus", "edu_pro"})
_TIER_OVERRIDES = ['service_tier="default"', 'features.fast_mode=false']
_SEALED = {"bounded": True}


class CodexTextError(RuntimeError):
    """Fixed-code route failure; never carries raw Native/model payloads."""

    def __init__(self, code, outcome="unknown", phase="inference", evidence=None):
        if (code not in _CODES or (outcome, phase) not in _PAIRS
                or (evidence is not None and type(evidence) is not dict)
                or (type(evidence) is dict and any(
                    isinstance(v, BaseException) for v in evidence.values()))):
            raise ValueError("codex_text_error_invalid")
        self.code = code
        self.outcome = outcome
        self.phase = phase
        self.detail = "%s/%s/%s" % (code, outcome, phase)
        self.evidence = dict(evidence) if evidence else {}
        super().__init__(self.detail)


def no_turn_proven(observed):
    """True only for a transport-observed stop with exactly zero turn submissions."""
    return (observed is not None
            and getattr(observed, "stopped", None) is True
            and type(getattr(observed, "turn_submissions", None)) is int
            and observed.turn_submissions == 0)


def accepted_result(request, config, host, observed, *, source_verified):
    """Project a verified Codex turn into a bounded result; refuse unproven claims."""

    def inference(code="route_violation"):
        raise CodexTextError(code, "unknown", "inference", dict(_SEALED))

    def gate():
        # A failed source/binding/Host gate alone never proves no turn ran.
        if no_turn_proven(observed):
            raise CodexTextError("route_violation", "not_started", "preflight",
                                 dict(_SEALED))
        inference()

    cond = getattr(request, "conditions", None)
    effort = getattr(config, "reasoning_effort", None)
    scope = getattr(config, "delegation", None)
    if (source_verified is not True or cond is None
            or getattr(cond, "adapter", None) != ADAPTER
            or cond != getattr(config, "conditions", None)
            or not getattr(scope, "human_intent_ref", None)
            or getattr(scope, "attempt", None) != getattr(request, "ref", None)
            or getattr(scope, "workspace", None) != getattr(cond, "workspace", None)
            or getattr(scope, "capability", None) != CAPABILITY
            or getattr(config, "use_named_permissions", None) is not True
            or getattr(config, "native_version", None) != NATIVE_VERSION
            or getattr(config, "approval_policy", None) != "never"
            or getattr(config, "mode", None) != "normal"
            or type(effort) is not str or not effort):
        gate()
    obs = getattr(host, "observation", None)
    if type(obs) is not dict:
        gate()
    sel = obs.get("model_selection")
    sub = obs.get("subscription_precondition")
    tier = obs.get("service_tier_observation")
    if (obs.get("native_handoff_verified") is not True or type(sel) is not dict
            or type(sub) is not dict or type(tier) is not dict):
        gate()
    if (sel.get("model") != getattr(cond, "model", None)
            or sel.get("requested_effort") != effort
            or sel.get("effective_effort") != effort
            or sel.get("effective_effort_reported") is not True
            or sel.get("native_version") != NATIVE_VERSION
            or sel.get("source") != "owned_native_model_list"):
        gate()
    if (sub.get("account_type") != "chatgpt"
            or type(sub.get("plan_type")) is not str
            or sub.get("plan_type") not in _PLANS
            or sub.get("ordinary_included_usage_allowed") is not True
            or sub.get("api_environment_absent") is not True
            or sub.get("additional_payment_or_grant_enabled") is not False):
        gate()
    if (tier.get("requested") != "normal"
            or tier.get("sent_config_overrides") != _TIER_OVERRIDES
            or tier.get("effective_fast_mode") is not False
            or tier.get("effective_config") != "default"
            or tier.get("original_thread_response") not in (None, "default")
            or tier.get("matched_before_turn") is not True
            or tier.get("fast_configuration_verified") is not False
            or tier.get("speed_increase_measured") is not False):
        gate()
    if (observed is None
            or getattr(observed, "native_version", None) != NATIVE_VERSION
            or getattr(observed, "expected_effort", None) != effort
            or getattr(observed, "error", None) is not None
            or getattr(observed, "terminal", None) != "completed"
            or type(getattr(observed, "turn_submissions", None)) is not int
            or observed.turn_submissions != 1
            or getattr(observed, "turn_rpc_confirmed", None) is not True
            or type(getattr(observed, "tool_calls", None)) is not int
            or observed.tool_calls != 0
            or getattr(observed, "stopped", None) is not True
            or getattr(observed, "validated_eof", None) is not True
            or getattr(observed, "drain_clean", None) is not True
            or getattr(observed, "cleanup_terminated", None) is not False
            or type(getattr(observed, "natural_exit", None)) is not int
            or observed.natural_exit != 0):
        inference()
    texts = getattr(observed, "texts", None)
    if type(texts) is not dict or len(texts) != 1:
        inference()
    key = next(iter(texts))
    text = texts[key]
    if type(key) is not str or type(text) is not str or not text:
        inference()
    try:
        raw = text.encode("utf-8")
    except UnicodeEncodeError:
        inference()
    if len(raw) > _MAX_OUTPUT_BYTES:
        inference("route_overflow")
    wrote = getattr(observed, "turn_write_attempt_at", None)
    start = getattr(observed, "turn_started_at", None)
    done = getattr(observed, "turn_completed_at", None)
    if (any(type(v) not in (int, float) or not math.isfinite(v)
            for v in (wrote, start, done)) or not wrote <= start <= done):
        inference()
    return {"text": text, "model": sel["model"], "effort": effort,
            "route": "codex", "native_version": NATIVE_VERSION, "tool_calls": 0,
            "evidence": {
                "normal_completion": True, "stopped": True,
                "source_verified": True, "native_handoff_verified": True,
                "natural_exit": 0, "validated_eof": True, "drain_clean": True,
                "cleanup_terminated": False, "turn_submissions": 1,
                "turn_rpc_confirmed": True, "final_count": 1, "tool_calls": 0,
                "native_version": NATIVE_VERSION,
                "model_selection": {"model": sel["model"],
                                    "requested_effort": effort,
                                    "effective_effort": effort,
                                    "native_version": NATIVE_VERSION},
                "output_bytes": len(raw),
                "output_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "turn_write_attempt_at": float(wrote),
                "turn_started_at": float(start),
                "turn_completed_at": float(done)}}
