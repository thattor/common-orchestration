"""Task3 manual failure recovery for CO #199.

Attempt-scoped call journal, durable route pauses and human decisions.
Only task3 wires this module; task1/task2 keep the legacy single-shot path.
"""

import copy
import re
import uuid

from .common import RouteFailure

_KINDS = frozenset((
    "call_started", "call_launching", "call_failed", "call_done",
    "route_paused", "route_decision",
))
_OUTCOMES = frozenset(("not_started", "unknown"))
_PHASES = frozenset(("preflight", "spawn", "inference"))
_RESUMABLE_PHASES = frozenset(("preflight", "spawn"))
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UUIDHEX = re.compile(r"[0-9a-f]{32}\Z")
_SYNTHETIC_FAILURES = frozenset((
    ("not_started", "preflight", "interrupted_prelaunch"),
    ("unknown", "inference", "outcome_unrecorded"),
))


class RoutePaused(Exception):
    """Internal control flow: task waits for a human route decision."""

    def __init__(self, report=None):
        super().__init__("route_paused")
        self.report = report


def _runner():
    from . import runner
    return runner


def _err(code, detail=""):
    return _runner().TaskError(code, detail)


def _corrupt():
    raise _err("journal_corrupt")


def _tok(v, limit):
    return isinstance(v, str) and 0 < len(v) <= limit and all(
        not ch.isspace() and ch.isprintable() for ch in v)


def _sha(v):
    return isinstance(v, str) and _SHA.match(v) is not None


def _uuidhex(v):
    return isinstance(v, str) and _UUIDHEX.match(v) is not None


def _link_ok(outcome, phase, code, launched):
    if outcome == "not_started" and phase == "preflight":
        return not launched
    if outcome == "not_started" and phase == "spawn":
        return launched and code == "route_unavailable"
    if outcome == "unknown":
        return launched
    return False


def _rf_pair_ok(outcome, phase, code):
    try:
        RouteFailure(code, outcome, phase)
    except (TypeError, ValueError):
        return False
    return True


def _failure_valid(outcome, phase, code, launched):
    if outcome not in _OUTCOMES or phase not in _PHASES \
            or not _tok(code, 128) \
            or not _link_ok(outcome, phase, code, launched):
        return False
    if (outcome, phase, code) in _SYNTHETIC_FAILURES:
        return True
    return _rf_pair_ok(outcome, phase, code)


def _valid_failure(cur):
    f = cur.get("failure")
    return isinstance(f, dict) and _failure_valid(
        f.get("outcome"), f.get("phase"), f.get("code"),
        cur.get("launched") is True)


def _resumable_report(rep):
    return rep.get("outcome") == "not_started" \
        and rep.get("phase") in _RESUMABLE_PHASES


def _find_option(rep, option_id):
    for o in rep.get("options") or []:
        if isinstance(o, dict) and o.get("option_id") == option_id:
            return o
    return None


def _decision_target(p, data):
    if not isinstance(data, dict) or not isinstance(p, dict) \
            or p.get("pause_id") != data.get("pause_id") \
            or p.get("report_sha256") != data.get("report_sha256") \
            or p.get("call_id") != data.get("call_id") \
            or p.get("attempt_id") != data.get("attempt_id"):
        return None
    co = data.get("confirm_override")
    if type(co) is not bool:
        return None
    base = {"pause_id", "report_sha256", "call_id", "attempt_id",
            "confirm_override", "option_id", "cancel"}
    if data.get("cancel") is True:
        if set(data) != base or p.get("cancel") is not True \
                or data.get("option_id") != "cancel" or co is not False:
            return None
        return "cancel"
    if data.get("cancel") is not False or not _resumable_report(p) \
            or set(data) != base | {"route", "model", "selection"}:
        return None
    opt = _find_option(p, data.get("option_id"))
    if opt is None:
        return None
    req = opt.get("requires_override") is True
    if (req and not co) or data.get("route") != opt.get("route") \
            or data.get("model") != opt.get("model") \
            or data.get("selection") != opt.get("pin"):
        return None
    return opt


def new_state():
    return {"attempts": {}, "pending": None, "pauses": [],
            "decisions": [], "grants": {}, "cancelled": {}}


def _ensure(st):
    rec = st.get("recovery")
    if not isinstance(rec, dict):
        rec = new_state()
        st["recovery"] = rec
    for key, val in new_state().items():
        rec.setdefault(key, val)
    return rec


def _latest(rec, call_id):
    attempts = rec["attempts"].get(call_id) or []
    return attempts[-1] if attempts else None


def pending(st):
    rec = st.get("recovery")
    rep = rec.get("pending") if isinstance(rec, dict) else None
    return copy.deepcopy(rep) if isinstance(rep, dict) else None


def history(st):
    rec = st.get("recovery")
    if not isinstance(rec, dict):
        return []
    out = []
    for call_id, attempts in (rec.get("attempts") or {}).items():
        for r in attempts:
            sel = r.get("selection") or {}
            out.append({"call_id": call_id,
                        "attempt_id": r.get("attempt_id"),
                        "step_id": r.get("step_id"),
                        "role": r.get("role"),
                        "prompt_sha256": r.get("prompt_sha256"),
                        "route": sel.get("route"),
                        "model": sel.get("model"),
                        "launched": r.get("launched") is True,
                        "done": r.get("done") is not None,
                        "failure": copy.deepcopy(r.get("failure"))})
    return out


# ---------------------------------------------------------------- events

def _ev_call_started(rec, st, data):
    cid = data.get("call_id")
    aid = data.get("attempt_id")
    step_id = data.get("step_id")
    role = data.get("role")
    sel = data.get("selection")
    allowed = {"planner": ("plan",), "design": (step_id,),
               "implement": (step_id, str(step_id) + "-repair"),
               "review": (step_id, str(step_id) + "-repair",
                          str(step_id) + "-rereview")}
    if not _tok(cid, 128) or not _tok(step_id, 128) or not _tok(role, 64) \
            or cid not in allowed.get(role, ()) \
            or type(data.get("prompt_bytes")) is not int \
            or not 0 < data["prompt_bytes"] <= _runner().MAX_CONTEXT_BYTES \
            or not _sha(data.get("prompt_sha256")) \
            or not isinstance(sel, dict):
        _corrupt()
    if rec["pending"] is not None:
        _corrupt()
    for lst in rec["attempts"].values():
        for old in lst:
            if old.get("done") is None and old.get("failure") is None:
                _corrupt()
    for gcid in rec["grants"]:
        if gcid != cid:
            _corrupt()
    r = _runner()
    spec = st.get("spec")
    policy = spec.get("selection") if isinstance(spec, dict) else None
    if not isinstance(policy, dict):
        _corrupt()
    try:
        r._v2_focus(spec, st, role, step_id)
    except Exception:
        _corrupt()
    attempts = rec["attempts"].setdefault(cid, [])
    n = len(attempts) + 1
    if not isinstance(aid, str) or aid != "%s-a%d" % (cid, n):
        _corrupt()
    prev = attempts[-1] if attempts else None
    grant = rec["grants"].get(cid)
    if prev is None:
        if grant is not None or cid in (st.get("calls") or {}):
            _corrupt()
        for e in (st.get("outputs") or {}).get(step_id) or []:
            if isinstance(e, dict) and e.get("call_id") == cid:
                _corrupt()
        eff = spec
    else:
        if prev.get("done") is not None or not _valid_failure(prev) \
                or prev["failure"]["outcome"] != "not_started" \
                or grant is None:
            _corrupt()
        if data.get("step_id") != prev.get("step_id") \
                or data.get("role") != prev.get("role") \
                or data.get("prompt_sha256") != prev.get("prompt_sha256") \
                or grant.get("attempt_id") != prev.get("attempt_id") \
                or grant.get("prompt_sha256") \
                != data.get("prompt_sha256"):
            _corrupt()
        offered = grant.get("selection")
        if not isinstance(offered, dict) \
                or sel.get("route") != offered.get("route") \
                or sel.get("model") != offered.get("model") \
                or sel.get("measurement_digest") \
                != offered.get("measurement_digest") \
                or sel.get("fit") != offered.get("fit"):
            _corrupt()
        eff = copy.deepcopy(spec)
        eff_policy = eff["selection"]
        targets = eff_policy.get("targets")
        if not isinstance(targets, dict):
            targets = {}
            eff_policy["targets"] = targets
        targets[role] = {"route": sel.get("route"),
                         "model": sel.get("model")}
    try:
        r._validate_pin(eff, st, role, step_id, sel)
    except Exception:
        _corrupt()
    if grant is not None:
        del rec["grants"][cid]
    r_new = {"call_id": cid, "attempt_id": aid, "n": n,
             "step_id": step_id, "role": role,
             "prompt_sha256": data["prompt_sha256"],
             "selection": copy.deepcopy(sel), "done": None,
             "launched": False, "failure": None}
    attempts.append(r_new)
    st["calls"][cid] = r_new


def _ev_call_launching(rec, data):
    cur = _latest(rec, data.get("call_id"))
    if cur is None or cur["attempt_id"] != data.get("attempt_id") \
            or cur["done"] is not None or cur["failure"] is not None \
            or cur["launched"] \
            or data.get("step_id") != cur["step_id"] \
            or data.get("role") != cur["role"]:
        _corrupt()
    cur["launched"] = True


def _ev_call_failed(rec, data):
    cur = _latest(rec, data.get("call_id"))
    if cur is None or cur["attempt_id"] != data.get("attempt_id") \
            or cur["done"] is not None or cur["failure"] is not None:
        _corrupt()
    if data.get("step_id") != cur["step_id"] \
            or data.get("role") != cur["role"]:
        _corrupt()
    outcome = data.get("outcome")
    phase = data.get("phase")
    code = data.get("code")
    if not _failure_valid(outcome, phase, code, cur["launched"] is True):
        _corrupt()
    cur["failure"] = {"outcome": outcome, "phase": phase, "code": code}


def _ev_call_done(j, rec, st, data):
    cur = _latest(rec, data.get("call_id"))
    if cur is None or cur["attempt_id"] != data.get("attempt_id") \
            or cur["done"] is not None or cur["failure"] is not None \
            or cur["launched"] is not True:
        _corrupt()
    r = _runner()
    sel = cur["selection"]
    if data.get("step_id") != cur["step_id"] \
            or data.get("role") != cur["role"] \
            or data.get("selection") != sel \
            or data.get("route") != sel.get("route") \
            or data.get("model") != sel.get("model"):
        _corrupt()
    ev = data.get("evidence")
    if not isinstance(ev, dict) \
            or ev.get("measurement_digest") != sel.get("measurement_digest") \
            or ev.get("selection_digest") != r.digest(r._pin_data(sel)):
        _corrupt()
    if type(data.get("tool_calls")) is not int or data["tool_calls"] != 0 \
            or not _sha(data.get("text_sha256")):
        _corrupt()
    record = data.get("output")
    r._check_binding(record, cur["step_id"], cur["attempt_id"])
    text = j.get_text(record)
    if not isinstance(text, str) or not text \
            or r.digest(text.encode("utf-8")) != data["text_sha256"]:
        _corrupt()
    cur["done"] = {"attempt_id": cur["attempt_id"],
                   "output": copy.deepcopy(record),
                   "model": sel.get("model"),
                   "route": sel.get("route"),
                   "evidence": copy.deepcopy(ev),
                   "tool_calls": 0,
                   "selection": copy.deepcopy(sel),
                   "text_sha256": data["text_sha256"]}
    st.setdefault("outputs", {}).setdefault(cur["step_id"], []).append(
        {"call_id": cur["call_id"], "text": text,
         "sha256": data["text_sha256"]})


def _ev_route_paused(rec, st, data):
    rep = data.get("report")
    if not isinstance(rep, dict) or rec["pending"] is not None:
        _corrupt()
    keys = {"pause_id", "task_id", "call_id", "attempt_id", "step_id",
            "role", "focus", "prompt_sha256", "selection", "outcome",
            "phase", "code", "quota", "process_outcome", "options",
            "candidates", "cancel", "report_sha256"}
    if set(rep) != keys:
        _corrupt()
    r = _runner()
    if not _sha(rep.get("report_sha256")):
        _corrupt()
    body = {k: v for k, v in rep.items() if k != "report_sha256"}
    if r.digest(r.canonical(body).encode("utf-8")) != rep["report_sha256"]:
        _corrupt()
    pid = rep.get("pause_id")
    if not _uuidhex(pid) or any(
            isinstance(p, dict) and p.get("pause_id") == pid
            for p in rec["pauses"]):
        _corrupt()
    cur = _latest(rec, rep.get("call_id"))
    if cur is None or cur["attempt_id"] != rep.get("attempt_id") \
            or cur["done"] is not None or not _valid_failure(cur):
        _corrupt()
    outcome, phase, code = _failure_view(cur)
    if rep.get("task_id") != st.get("task_id") \
            or rep.get("step_id") != cur["step_id"] \
            or rep.get("role") != cur["role"] \
            or rep.get("prompt_sha256") != cur["prompt_sha256"] \
            or rep.get("selection") != cur["selection"] \
            or rep.get("outcome") != outcome \
            or rep.get("phase") != phase \
            or rep.get("code") != code \
            or rep.get("quota") != "unknown" \
            or rep.get("process_outcome") != (
                "not_started" if outcome == "not_started" else "unknown") \
            or rep.get("cancel") is not True:
        _corrupt()
    spec = st.get("spec")
    policy = spec.get("selection") if isinstance(spec, dict) else None
    if not isinstance(policy, dict):
        _corrupt()
    try:
        focus = r._v2_focus(spec, st, cur["role"], cur["step_id"])
    except Exception:
        _corrupt()
    if rep.get("focus") != focus:
        _corrupt()
    if _resumable_report(rep):
        listed, other = rep.get("options"), rep.get("candidates")
    else:
        listed, other = rep.get("candidates"), rep.get("options")
    if not isinstance(listed, list) or len(listed) > 16 or other != []:
        _corrupt()
    target = r._v2_target(policy, cur["role"])
    pairs = set()
    for i, e in enumerate(listed):
        if not isinstance(e, dict) or set(e) != {
                "option_id", "route", "model", "requires_override", "pin"}:
            _corrupt()
        pin = e.get("pin")
        if not isinstance(pin, dict) \
                or e.get("option_id") != "o%d" % i \
                or e.get("route") != pin.get("route") \
                or e.get("model") != pin.get("model") \
                or not _tok(pin.get("route"), 128) \
                or not _tok(pin.get("model"), 128):
            _corrupt()
        req = bool(isinstance(target, dict) and (
            target.get("route") != pin.get("route")
            or target.get("model") != pin.get("model")))
        if e.get("requires_override") is not req:
            _corrupt()
        pair = (pin.get("route"), pin.get("model"))
        if pair in pairs:
            _corrupt()
        pairs.add(pair)
        eff = copy.deepcopy(spec)
        eff_policy = eff["selection"]
        targets = eff_policy.get("targets")
        if not isinstance(targets, dict):
            targets = {}
            eff_policy["targets"] = targets
        targets[cur["role"]] = {"route": pin["route"],
                                "model": pin["model"]}
        try:
            r._validate_pin(eff, st, cur["role"], cur["step_id"], pin)
        except Exception:
            _corrupt()
    if any(k != cur["call_id"] for k in rec["grants"]):
        _corrupt()
    grant = rec["grants"].get(cur["call_id"])
    if grant is not None and grant.get("attempt_id") != cur["attempt_id"]:
        _corrupt()
    rep = copy.deepcopy(rep)
    rec["pending"] = rep
    rec["pauses"].append(rep)
    if grant is not None:
        del rec["grants"][cur["call_id"]]


def _ev_route_decision(rec, data):
    p = rec["pending"]
    tgt = _decision_target(p, data)
    if tgt is None:
        _corrupt()
    cid = p["call_id"]
    if tgt == "cancel":
        rec["cancelled"][cid] = True
    else:
        rec["grants"][cid] = {"pause_id": p["pause_id"],
                              "attempt_id": p["attempt_id"],
                              "prompt_sha256": p.get("prompt_sha256"),
                              "route": tgt["route"],
                              "model": tgt["model"],
                              "selection": copy.deepcopy(tgt["pin"])}
    rec["decisions"].append(copy.deepcopy(data))
    rec["pending"] = None


def event(j, st, kind, data):
    if kind not in _KINDS:
        return False
    rec = _ensure(st)
    if rec["cancelled"]:
        _corrupt()
    if kind == "call_started":
        _ev_call_started(rec, st, data)
    elif kind == "call_launching":
        _ev_call_launching(rec, data)
    elif kind == "call_failed":
        _ev_call_failed(rec, data)
    elif kind == "call_done":
        _ev_call_done(j, rec, st, data)
    elif kind == "route_paused":
        _ev_route_paused(rec, st, data)
    else:
        _ev_route_decision(rec, data)
    return True


# ---------------------------------------------------------------- pauses

def _failure_view(cur):
    f = cur.get("failure")
    if isinstance(f, dict):
        return f["outcome"], f["phase"], f["code"]
    if cur.get("launched"):
        return "unknown", "inference", "outcome_unrecorded"
    return "not_started", "preflight", "interrupted_prelaunch"


def _build_report(st, spec, routes, cur, outcome, phase, code):
    r = _runner()
    policy = spec.get("selection")
    if not isinstance(policy, dict):
        raise _err("route_violation")
    focus = r._v2_focus(spec, st, cur["role"], cur["step_id"])
    resumable = outcome == "not_started" and phase in _RESUMABLE_PHASES
    pins = []
    if resumable or outcome == "unknown":
        pins = routes.options(cur["role"], focus, copy.deepcopy(policy))
        if not isinstance(pins, list) or len(pins) > 16 \
                or any(not isinstance(p, dict) for p in pins):
            raise _err("route_violation")
    target = r._v2_target(policy, cur["role"])
    entries = []
    for i, pin in enumerate(pins):
        req = isinstance(target, dict) and (
            target.get("route") != pin.get("route")
            or target.get("model") != pin.get("model"))
        entries.append({"option_id": "o%d" % i,
                        "route": pin.get("route"),
                        "model": pin.get("model"),
                        "requires_override": bool(req),
                        "pin": copy.deepcopy(pin)})
    report = {"pause_id": uuid.uuid4().hex,
              "task_id": st.get("task_id"),
              "call_id": cur["call_id"],
              "attempt_id": cur["attempt_id"],
              "step_id": cur["step_id"],
              "role": cur["role"],
              "focus": focus,
              "prompt_sha256": cur.get("prompt_sha256"),
              "selection": copy.deepcopy(cur.get("selection")),
              "outcome": outcome,
              "phase": phase,
              "code": code,
              "quota": "unknown",
              "process_outcome":
                  "not_started" if outcome == "not_started" else "unknown",
              "options": entries if resumable else [],
              "candidates": [] if resumable else entries,
              "cancel": True}
    report["report_sha256"] = r.digest(
        r.canonical(report).encode("utf-8"))
    return report


def _raise_pause(j, st, spec, routes, cur):
    if cur.get("failure") is None:
        outcome, phase, code = _failure_view(cur)
        failed = {"step_id": cur["step_id"], "call_id": cur["call_id"],
                  "attempt_id": cur["attempt_id"], "role": cur["role"],
                  "outcome": outcome, "phase": phase, "code": code}
        j.append("call_failed", **failed)
        event(j, st, "call_failed", copy.deepcopy(failed))
    outcome, phase, code = _failure_view(cur)
    report = _build_report(st, spec, routes, cur, outcome, phase, code)
    j.append("route_paused", report=copy.deepcopy(report))
    event(j, st, "route_paused", {"report": copy.deepcopy(report)})
    raise RoutePaused(report)


# ---------------------------------------------------------------- calls

def _cached_output(j, st, cur):
    record = (cur.get("done") or {}).get("output")
    _runner()._check_binding(record, cur["step_id"], cur["attempt_id"])
    text = j.get_text(record)
    if not isinstance(text, str) or not text:
        raise _err("internal_error", "cached_output")
    return text


def _dispatch(j, task_dir, spec, routes, st, step_id, call_id, role,
              prompt, cur, grant):
    r = _runner()
    rec = _ensure(st)
    if not isinstance(prompt, str) or not prompt \
            or len(prompt.encode("utf-8")) > r.MAX_CONTEXT_BYTES:
        raise _err("input_invalid", "prompt")
    pdata = prompt.encode("utf-8")
    prompt_sha = r.digest(pdata)
    if cur is not None and (cur["step_id"] != step_id or cur["role"] != role
                            or cur["prompt_sha256"] != prompt_sha):
        raise _err("call_context_changed")
    policy = spec.get("selection")
    if not isinstance(policy, dict):
        raise _err("route_violation")
    focus = r._v2_focus(spec, st, role, step_id)
    n = 1 if cur is None else cur["n"] + 1
    attempt_id = "%s-a%d" % (call_id, n)
    eff = spec
    if grant is None:
        sel = copy.deepcopy(
            routes.selection(role, focus, copy.deepcopy(policy)))
    else:
        if cur is None:
            _corrupt()
        if grant.get("attempt_id") != cur["attempt_id"] \
                or grant.get("prompt_sha256") != prompt_sha:
            raise _err("call_context_changed")
        offered = grant.get("selection") or {}
        match = None
        for cand in routes.options(role, focus, copy.deepcopy(policy)):
            if isinstance(cand, dict) \
                    and cand.get("route") == offered.get("route") \
                    and cand.get("model") == offered.get("model"):
                match = cand
                break
        if match is None \
                or match.get("measurement_digest") \
                != offered.get("measurement_digest") \
                or match.get("fit") != offered.get("fit"):
            _raise_pause(j, st, spec, routes, cur)
        sel = copy.deepcopy(match)
        prev_sel = cur.get("selection") or {}
        target = r._v2_target(policy, role)
        if sel.get("route") == prev_sel.get("route") \
                and sel.get("model") == prev_sel.get("model"):
            sel["reason"] = "human_retry"
        elif isinstance(target, dict) and (
                target.get("route") != sel.get("route")
                or target.get("model") != sel.get("model")):
            sel["reason"] = "human_override"
        else:
            sel["reason"] = "human_choice"
        eff = copy.deepcopy(spec)
        eff_policy = eff["selection"]
        targets = eff_policy.get("targets")
        if not isinstance(targets, dict):
            targets = {}
            eff_policy["targets"] = targets
        targets[role] = {"route": sel["route"], "model": sel["model"]}
    r._validate_pin(eff, st, role, step_id, sel)
    selection_digest = r.digest(r._pin_data(sel))
    started = {"step_id": step_id, "call_id": call_id,
               "attempt_id": attempt_id, "role": role,
               "prompt_sha256": prompt_sha,
               "prompt_bytes": len(pdata),
               "selection": copy.deepcopy(sel)}
    j.append("call_started", **started)
    event(j, st, "call_started", copy.deepcopy(started))
    r._announce(spec,
                "call %s mode=%s role=%s model=%s route=%s focus=%s "
                "reason=%s usage_reason=%s fit_origin=%s" %
                (attempt_id, sel["mode"], role, sel["model"], sel["route"],
                 sel["focus"], sel["reason"], sel["usage"]["reason"],
                 sel["fit"]["origin"]))
    fired = [0]

    def _before_launch():
        if fired[0]:
            raise _err("route_violation")
        fired[0] += 1
        mark = {"step_id": step_id, "call_id": call_id,
                "attempt_id": attempt_id, "role": role}
        j.append("call_launching", **mark)
        event(j, st, "call_launching", mark)

    try:
        out = routes.infer_selected(
            copy.deepcopy(sel), role, prompt,
            r._call_dir(task_dir, attempt_id),
            timeout=spec["call_timeout"], before_launch=_before_launch)
    except RouteFailure as rf:
        outcome = getattr(rf, "outcome", None)
        phase = getattr(rf, "phase", None)
        code = getattr(rf, "code", None)
        if not _failure_valid(outcome, phase, code, fired[0] == 1):
            raise _err("route_violation")
        failed = {"step_id": step_id, "call_id": call_id,
                  "attempt_id": attempt_id, "role": role,
                  "outcome": outcome, "phase": phase, "code": code}
        j.append("call_failed", **failed)
        event(j, st, "call_failed", copy.deepcopy(failed))
        _raise_pause(j, st, spec, routes, _latest(rec, call_id))
    if fired[0] != 1:
        raise _err("route_violation")
    text = out.get("text") if isinstance(out, dict) else None
    if not isinstance(text, str) or not text:
        raise _err("route_violation")
    if type(out.get("tool_calls")) is not int or out["tool_calls"] != 0:
        raise _err("route_violation")
    if out.get("route") != sel["route"] or out.get("model") != sel["model"]:
        raise _err("route_violation")
    evidence = out.get("evidence")
    if not isinstance(evidence, dict) \
            or evidence.get("measurement_digest") \
            != sel["measurement_digest"] \
            or evidence.get("selection_digest") != selection_digest:
        raise _err("route_violation")
    record = j.put_text(step_id, attempt_id, text)
    done = {"attempt_id": attempt_id, "output": record,
            "model": out["model"], "route": out["route"],
            "evidence": copy.deepcopy(evidence), "tool_calls": 0,
            "selection": copy.deepcopy(sel),
            "text_sha256": r.digest(text.encode("utf-8"))}
    finished = {"step_id": step_id, "call_id": call_id, "role": role}
    finished.update(done)
    j.append("call_done", **finished)
    event(j, st, "call_done", copy.deepcopy(finished))
    return text


def call(j, task_dir, spec, routes, st, step_id, call_id, role,
         prompt=None):
    rec = _ensure(st)
    if rec["cancelled"].get(call_id):
        raise _err("route_decision_cancelled")
    if rec["pending"] is not None:
        raise RoutePaused(copy.deepcopy(rec["pending"]))
    cur = _latest(rec, call_id)
    if cur is not None \
            and (cur["step_id"] != step_id or cur["role"] != role):
        raise _err("call_context_changed")
    if cur is not None and cur["done"] is not None:
        return _cached_output(j, st, cur)
    grant = rec["grants"].get(call_id)
    if cur is not None and grant is None:
        _raise_pause(j, st, spec, routes, cur)
    return _dispatch(j, task_dir, spec, routes, st, step_id, call_id,
                     role, prompt, cur, grant)


# ---------------------------------------------------------------- decisions

def decide(j, st, pause_id, report_sha256, option_id,
           confirm_override=False):
    rec = _ensure(st)
    p = rec.get("pending")
    if type(confirm_override) is not bool:
        raise _err("route_decision_invalid")
    if not isinstance(p, dict) or p.get("pause_id") != pause_id \
            or p.get("report_sha256") != report_sha256 \
            or not _tok(option_id, 128):
        raise _err("route_decision_invalid")
    data = {"pause_id": p["pause_id"],
            "report_sha256": p["report_sha256"],
            "call_id": p["call_id"],
            "attempt_id": p["attempt_id"],
            "confirm_override": False}
    if option_id == "cancel":
        if p.get("cancel") is not True:
            raise _err("route_decision_invalid")
        data.update({"option_id": "cancel", "cancel": True})
    else:
        opt = _find_option(p, option_id)
        req = isinstance(opt, dict) \
            and opt.get("requires_override") is True
        if opt is None or not _resumable_report(p) \
                or (req and confirm_override is not True):
            raise _err("route_decision_invalid")
        data.update({"option_id": option_id, "cancel": False,
                     "confirm_override": confirm_override is True,
                     "route": opt["route"], "model": opt["model"],
                     "selection": copy.deepcopy(opt["pin"])})
    if rec.get("pending") is not p or _decision_target(p, data) is None:
        raise _err("route_decision_invalid")
    j.append("route_decision", **data)
    event(j, st, "route_decision", copy.deepcopy(data))
