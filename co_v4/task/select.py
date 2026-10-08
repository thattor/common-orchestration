"""Native candidate registry (routes2.json) and selection pins.

routes2.json is a private, closed-schema registry kept separate from the
legacy routes.json/config. It records per-(route, model) native measurement
entries plus ordered candidate fit attestations. Malformed registries fail
closed; individually invalid or missing measurements only exclude that
candidate at selection time. Ranking never grants eligibility: fit and a
valid measurement gate every mode, including exact/fixed targets.
"""
from __future__ import annotations

import math
import os
import re
import stat
import time
from pathlib import Path

from .. import catalog
from ..selection import MODES, SelectionCandidate, select_candidates
from . import infer
from .candidate_presets import PRESETS, PROFILE_ID
from .candidate_presets import fit_entries as _preset_fit
from .common import (TaskError, PrivateFileLock as _FileLock, canonical, digest,
                     parse_json, private_dir)

_SCHEMA = "co.routes/2"
_ROUTE_PREFIX = {"claude": "claude-", "devin": "swe-"}
_ORIGINS = frozenset({"prior", "measured"})
_SNAPSHOT_KEYS = frozenset({"remaining_percent", "comparison_group",
                            "low_remaining", "observed_at", "max_age",
                            "source_ref"})
_MAX_CANDIDATES = 16
_MAX_MODEL_LEN = 128
_MAX_ID_LEN = 64
_MAX_REF_LEN = 512
_MAX_GROUP_LEN = 128
_MAX_BYTES = 4 * 1024 * 1024
_MAX_EXCLUDED = 16
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _err(code, detail):
    raise TaskError(code, detail)


def _exact_str(value, limit):
    if type(value) is not str or value != value.strip():
        return False
    try:
        return 0 < len(value.encode("utf-8")) <= limit and value.isprintable()
    except UnicodeEncodeError:
        return False


def _categories():
    return {c for c in catalog.CATEGORIES if c != "other"}


def _check_model(route, model):
    if type(route) is not str or route not in _ROUTE_PREFIX:
        _err("route_invalid", "route must be one of %s" % sorted(_ROUTE_PREFIX))
    if not (_exact_str(model, _MAX_MODEL_LEN) and model.isascii()
            and "/" not in model
            and all(ch.isprintable() and not ch.isspace() for ch in model)
            and model.startswith(_ROUTE_PREFIX[route])):
        _err("model_invalid", "model %r violates the %s identity policy"
             % (model, route))


def _check_fit_entry(entry):
    if (type(entry) is not dict
            or set(entry) != {"category", "degree", "origin", "source_ref"}):
        _err("fit_invalid", "fit entry must be a closed attestation")
    category = entry["category"]
    if type(category) is not str or category not in _categories():
        _err("fit_invalid", "unknown fit category %r" % category)
    degree = entry["degree"]
    if degree is not None and (type(degree) is not int
                               or degree not in (1, 2, 3)):
        _err("fit_invalid", "degree must be an integer 1..3 or null")
    if type(entry["origin"]) is not str or entry["origin"] not in _ORIGINS:
        _err("fit_invalid", "origin must be prior or measured")
    if not _exact_str(entry["source_ref"], _MAX_REF_LEN):
        _err("fit_invalid", "source_ref must be a nonempty bounded reference")


def _check_candidate(cand):
    if type(cand) is not dict or set(cand) != {"route", "model", "fit"}:
        _err("registry_invalid", "candidate must be a closed record")
    _check_model(cand["route"], cand["model"])
    fit = cand["fit"]
    if type(fit) is not list or len(fit) > len(_categories()):
        _err("registry_invalid", "fit must be a bounded list")
    seen = set()
    for entry in fit:
        _check_fit_entry(entry)
        if entry["category"] in seen:
            _err("registry_invalid", "duplicate fit category")
        seen.add(entry["category"])


def _check_reg(reg):
    if (type(reg) is not dict
            or set(reg) != {"schema", "created", "cwd", "measurements",
                            "candidates"}):
        _err("registry_invalid", "registry root must be a closed %s record"
             % _SCHEMA)
    if reg["schema"] != _SCHEMA:
        _err("registry_invalid", "unexpected registry schema %r"
             % reg["schema"])
    if type(reg["created"]) is not int:
        _err("registry_invalid", "created must be an integer")
    if not _exact_str(reg["cwd"], 4096) or not os.path.isabs(reg["cwd"]):
        _err("registry_invalid", "cwd must be an absolute path")
    if (type(reg["candidates"]) is not list
            or len(reg["candidates"]) > _MAX_CANDIDATES):
        _err("registry_invalid", "candidates must be a bounded ordered list")
    seen = set()
    for cand in reg["candidates"]:
        _check_candidate(cand)
        ident = (cand["model"], cand["route"])
        if ident in seen:
            _err("registry_invalid", "duplicate candidate identity")
        seen.add(ident)
    measurements = reg["measurements"]
    if (type(measurements) is not dict
            or len(measurements) > _MAX_CANDIDATES):
        _err("registry_invalid", "measurements must be a bounded mapping")
    for key, entry in measurements.items():
        if type(entry) is not dict:
            _err("registry_invalid", "measurement entry must be an object")
        parts = key.split("/") if type(key) is str else []
        if len(parts) != 2:
            _err("registry_invalid", "measurement key must be route/model")
        _check_model(parts[0], parts[1])
        if (parts[1], parts[0]) not in seen:
            _err("registry_invalid",
                 "measurement %r has no matching candidate" % key)
    for cand in reg["candidates"]:
        entry = measurements.get("%s/%s" % (cand["route"], cand["model"]))
        m_digest = (entry.get("measurement_digest")
                    if type(entry) is dict else None)
        if type(m_digest) is str and any(
                f["source_ref"] == m_digest for f in cand["fit"]):
            _err("registry_invalid",
                 "fit source_ref must not cite the candidate's own "
                 "measurement")
    return reg


def _reg_path(state_dir):
    return os.path.join(state_dir, "routes2.json")


def _private_state(state_dir):
    path = Path(state_dir)
    if not path.is_absolute():
        _err("state_path", "state_dir must be an absolute path")
    if not os.path.lexists(path):
        _err("registry_missing", "state directory is absent")
    try:
        private_dir(path, exist_ok=True)
        return str(path.resolve())
    except OSError as exc:
        raise TaskError("registry_invalid", "state directory is unavailable") from exc


def _read_reg(state_dir):
    state_dir = _private_state(state_dir)
    try:
        fd = os.open(_reg_path(state_dir), os.O_RDONLY | _NOFOLLOW | os.O_NONBLOCK)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        raise TaskError("registry_invalid",
                        "routes2.json cannot be opened safely") from exc
    with os.fdopen(fd, "rb") as handle:
        try:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > _MAX_BYTES):
                _err("registry_invalid",
                     "routes2.json must be an owner-private regular file")
            raw = handle.read(_MAX_BYTES + 1)
        except OSError as exc:
            raise TaskError("registry_invalid",
                            "routes2.json cannot be read") from exc
    if len(raw) > _MAX_BYTES:
        _err("registry_invalid", "routes2.json exceeds the size bound")
    try:
        reg = parse_json(raw.decode("utf-8"))
    except TaskError:
        raise
    except Exception as exc:
        raise TaskError("registry_invalid",
                        "routes2.json is not valid JSON") from exc
    reg = _check_reg(reg)
    cwd = _require_native_cwd(reg["cwd"])
    if cwd != reg["cwd"]:
        _err("registry_invalid", "native cwd is no longer canonical")
    _state_outside(state_dir, cwd)
    return reg


def _write_private_file(path, data):
    tmp = "%s.tmp-%d-%s" % (path, os.getpid(), os.urandom(4).hex())
    fd = os.open(tmp,
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _write_reg(state_dir, reg):
    reg = _check_reg(reg)
    data = canonical(reg).encode("utf-8")
    if len(data) > _MAX_BYTES:
        _err("registry_too_large", "encoded registry exceeds the size bound")
    _write_private_file(_reg_path(state_dir), data)
    dfd = os.open(state_dir, os.O_RDONLY | _NOFOLLOW)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _require_native_cwd(native_cwd):
    cwd = os.path.realpath(native_cwd)
    if not os.path.isdir(cwd):
        _err("cwd_invalid", "native_cwd must be an existing directory")
    return cwd


def _state_outside(state_dir, cwd):
    if Path(state_dir).is_relative_to(cwd):
        _err("state_location", "state_dir must live outside the native cwd")


def _empty_reg(cwd):
    return {"schema": _SCHEMA, "created": int(time.time()), "cwd": cwd,
            "measurements": {}, "candidates": []}


def _reason(exc, state_dir):
    code = getattr(exc, "code", None)
    if (isinstance(code, str) and 0 < len(code) <= _MAX_ID_LEN
            and all(ch.isalnum() or ch in "_-" for ch in code)):
        return code
    return "probe_failed"


def _measure(state_dir, route, model, cwd, timeout):
    token = "%s-%s-%s" % (route, digest(model.encode("utf-8"))[:24],
                          os.urandom(6).hex())
    parent = Path(state_dir) / "native-candidates"
    private_dir(parent, exist_ok=True)
    base = parent / token
    private_dir(base)
    config_path = base / "config.json"
    conf = infer.DEVIN_NO_TOOLS_CONFIG if route == "devin" else {}
    if isinstance(conf, bytes):
        data = conf
    elif isinstance(conf, str):
        data = conf.encode("utf-8")
    else:
        data = canonical(conf).encode("utf-8")
    infer._write_private(config_path, data)
    probe_root = base / "probe"
    private_dir(probe_root)
    return infer._setup_route(route, Path(cwd), infer._child_env(),
                              config_path, probe_root,
                              infer._known_context(Path(cwd)), timeout,
                              {}, model=model)


def _load_or_init(state_dir, cwd):
    reg = _read_reg(state_dir)
    if reg is None:
        return _empty_reg(cwd)
    if reg["cwd"] != cwd:
        _err("cwd_mismatch", "registry belongs to a different native cwd")
    return reg


def setup_candidates(state_dir, native_cwd, timeout=180):
    """Create routes2.json by measuring the known presets; never overwrite."""
    if (isinstance(timeout, bool) or not isinstance(timeout, int)
            or timeout < 1 or timeout > 900):
        _err("timeout_invalid", "timeout must be an int between 1 and 900")
    if not os.path.isabs(state_dir):
        _err("state_path", "state_dir must be an absolute path")
    if os.path.islink(state_dir):
        _err("state_symlink", "state_dir must not be a symlink")
    state_dir = os.path.realpath(state_dir)
    cwd = _require_native_cwd(native_cwd)
    _state_outside(state_dir, cwd)
    private_dir(Path(state_dir), exist_ok=True)
    report = {"schema": "co.setup-report/1", "profile": PROFILE_ID,
              "failures": []}
    with _FileLock(os.path.join(state_dir, "routes2.lock")):
        if os.path.lexists(_reg_path(state_dir)):
            _err("registry_exists", "routes2.json already exists")
        reg = _empty_reg(cwd)
        with _FileLock(os.path.join(state_dir, "infer.lock")):
            for preset in PRESETS:
                route, model = preset["route"], preset["model"]
                try:
                    entry = _measure(state_dir, route, model, cwd, timeout)
                except TaskError as exc:
                    report["failures"].append(
                        {"route": route, "model": model,
                         "reason": _reason(exc, state_dir)})
                    continue
                reg["measurements"]["%s/%s" % (route, model)] = entry
                reg["candidates"].append({"route": route, "model": model,
                                          "fit": _preset_fit(route, model)})
        if report["failures"]:
            _write_private_file(
                os.path.join(state_dir, "setup-report.json"),
                canonical(report).encode("utf-8"))
        if not reg["candidates"]:
            _err("route_unqualified", "no native preset qualified")
        _write_reg(state_dir, reg)
    return reg


def add_candidate(state_dir, native_cwd, route, model, timeout=180,
                  reprobe=False):
    """Measure and register one exact (route, model); reprobe re-measures."""
    if (isinstance(timeout, bool) or not isinstance(timeout, int)
            or timeout < 1 or timeout > 900):
        _err("timeout_invalid", "timeout must be an int between 1 and 900")
    if not isinstance(reprobe, bool):
        _err("reprobe_invalid", "reprobe must be a bool")
    if not os.path.isabs(state_dir):
        _err("state_path", "state_dir must be an absolute path")
    if os.path.islink(state_dir):
        _err("state_symlink", "state_dir must not be a symlink")
    state_dir = os.path.realpath(state_dir)
    cwd = _require_native_cwd(native_cwd)
    _state_outside(state_dir, cwd)
    _check_model(route, model)
    private_dir(Path(state_dir), exist_ok=True)
    with _FileLock(os.path.join(state_dir, "routes2.lock")):
        reg = _load_or_init(state_dir, cwd)
        cand = next((c for c in reg["candidates"]
                     if c["route"] == route and c["model"] == model), None)
        if cand is not None and not reprobe:
            _err("candidate_exists", "candidate already registered")
        if cand is None and len(reg["candidates"]) >= _MAX_CANDIDATES:
            _err("candidate_limit", "candidate capacity reached")
        with _FileLock(os.path.join(state_dir, "infer.lock")):
            try:
                entry = _measure(state_dir, route, model, cwd, timeout)
            except TaskError as exc:
                raise TaskError("route_unqualified",
                                _reason(exc, state_dir)) from exc
            reg["measurements"]["%s/%s" % (route, model)] = entry
            if cand is None:
                reg["candidates"].append({"route": route, "model": model,
                                          "fit": _preset_fit(route, model)})
            _write_reg(state_dir, reg)
    return reg


def set_fit(state_dir, route, model, category, degree=None, origin="prior",
            source_ref=None):
    """Owner attestation for one category; replaces an existing entry."""
    state_dir = _private_state(state_dir)
    _check_model(route, model)
    entry = {"category": category, "degree": degree, "origin": origin,
             "source_ref": source_ref}
    _check_fit_entry(entry)
    with _FileLock(os.path.join(state_dir, "routes2.lock")):
        reg = _read_reg(state_dir)
        if reg is None:
            _err("registry_missing", "routes2.json not found")
        cand = next((c for c in reg["candidates"]
                     if c["route"] == route and c["model"] == model), None)
        if cand is None:
            _err("candidate_unknown", "no such candidate")
        m_entry = reg["measurements"].get("%s/%s" % (route, model))
        m_digest = (m_entry.get("measurement_digest")
                    if type(m_entry) is dict else None)
        if m_digest is not None and m_digest == source_ref:
            _err("fit_invalid",
                 "source_ref must not cite the candidate's own measurement")
        for index, existing in enumerate(cand["fit"]):
            if existing["category"] == category:
                cand["fit"][index] = entry
                break
        else:
            cand["fit"].append(entry)
        _write_reg(state_dir, reg)
    return reg


def show_catalog(state_dir):
    """Sanitized view: schema, candidate fit, measurement digests only."""
    reg = _read_reg(state_dir)
    if reg is None:
        _err("registry_missing", "routes2.json not found")
    return {
        "schema": reg["schema"],
        "candidates": [
            {"route": c["route"], "model": c["model"],
             "fit": [dict(f) for f in c["fit"]]}
            for c in reg["candidates"]
        ],
        "measurements": {
            key: _public_digest(entry.get("measurement_digest"))
            for key, entry in reg["measurements"].items()
        },
    }


def _public_digest(value):
    if type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        return value
    return None


_STEP_ROLES = ("design", "implement", "review")
_ROLES = _STEP_ROLES + ("planner",)
_MAX_PLAN_STEPS = 6


def _finite_nonneg(value):
    """True only for nonnegative real numbers within float range."""
    return (type(value) in (int, float) and abs(value) <= 1e300
            and math.isfinite(value) and value >= 0)


def _iter_pairs(pairs):
    if pairs is None:
        return []
    if type(pairs) is not list or len(pairs) > len(_ROLES):
        _err("target_invalid",
             "targets must be a list of at most %d ROLE=SPEC strings"
             % len(_ROLES))
    seen = set()
    out = []
    for raw in pairs:
        if (type(raw) is not str or raw != raw.strip()
                or len(raw) > _MAX_REF_LEN or "=" not in raw):
            _err("target_invalid",
                 "targets must be ROLE=MODEL or ROLE=ROUTE/MODEL")
        role, spec = raw.split("=", 1)
        if role not in _ROLES:
            _err("role_unknown", "unknown role %r" % role)
        if role in seen:
            _err("target_duplicate", "duplicate role %r" % role)
        seen.add(role)
        if not spec or len(spec) > _MAX_MODEL_LEN + _MAX_ID_LEN:
            _err("target_invalid", "bad target spec for role %r" % role)
        out.append((role, spec))
    return out


def _policy(policy, candidates):
    """Validate a closed {mode, targets} policy and bind its targets."""
    if policy is None:
        return "suitability", {}
    if type(policy) is not dict or set(policy) != {"mode", "targets"}:
        _err("policy_invalid",
             "policy must be a closed {mode, targets} mapping")
    mode = policy["mode"]
    if type(mode) is not str or mode not in MODES:
        _err("selection_mode_unknown", "unknown selection mode")
    raw = policy["targets"]
    if type(raw) is not dict or len(raw) > len(_ROLES):
        _err("policy_invalid", "targets must be a bounded role mapping")
    idents = {(c["model"], c["route"]) for c in candidates}
    targets = {}
    for role, spec in raw.items():
        if type(role) is not str or role not in _ROLES:
            _err("role_unknown", "unknown policy role %r" % (role,))
        if type(spec) is not dict or set(spec) != {"route", "model"}:
            _err("target_invalid",
                 "target must be a closed {route, model} record")
        _check_model(spec["route"], spec["model"])
        if (spec["model"], spec["route"]) not in idents:
            _err("target_unknown", "no candidate %s/%s"
                 % (spec["route"], spec["model"]))
        targets[role] = {"route": spec["route"], "model": spec["model"]}
    return mode, targets


def _plan_steps(plan):
    if type(plan) is not dict or set(plan) != {"schema", "steps"}:
        _err("plan_invalid", "plan must be a closed co.task-plan/2 record")
    if plan["schema"] != "co.task-plan/2":
        _err("plan_invalid", "unexpected plan schema %r" % plan["schema"])
    steps = plan["steps"]
    if type(steps) is not list or not 1 <= len(steps) <= _MAX_PLAN_STEPS:
        _err("plan_invalid",
             "plan steps must be an ordered list of at most %d"
             % _MAX_PLAN_STEPS)
    out = []
    for raw in steps:
        if type(raw) is not dict or set(raw) != {
                "id", "role", "instructions", "inputs", "focus"}:
            _err("plan_invalid",
                 "plan step must have id, role, instructions, inputs and focus")
        role, focus = raw["role"], raw["focus"]
        if type(role) is not str or role not in _STEP_ROLES:
            _err("plan_invalid", "bad plan step role %r" % (role,))
        if type(focus) is not str or focus not in _categories():
            _err("plan_invalid", "plan step needs a known focus")
        out.append((role, focus))
    return out


class NativeCandidates:
    """Registry-backed selection over measured native candidates."""

    def __init__(self, state_dir, usage=None, clock=time.time):
        self.state_dir = _private_state(state_dir)
        self.usage = usage
        self.clock = clock
        self._reg()

    def _now(self):
        return self.clock() if callable(self.clock) else self.clock

    def _reg(self):
        reg = _read_reg(self.state_dir)
        if reg is None:
            _err("registry_missing", "routes2.json not found")
        return reg

    def _valid_entry(self, reg, cand):
        entry = reg["measurements"].get("%s/%s" % (cand["route"],
                                                  cand["model"]))
        if entry is None:
            return None
        try:
            return infer._validate_entry(entry, cand["route"],
                                         cand["model"], reg["cwd"])
        except Exception:
            return None

    def resolve_targets(self, pairs):
        """Resolve ROLE=MODEL or ROLE=ROUTE/MODEL pairs to exact targets."""
        reg = self._reg()
        targets = {}
        for role, spec in _iter_pairs(pairs):
            if "/" in spec:
                route, _, model = spec.partition("/")
                try:
                    _check_model(route, model)
                except TaskError as exc:
                    raise TaskError("target_invalid", str(exc)) from exc
                if not any(c["route"] == route and c["model"] == model
                           for c in reg["candidates"]):
                    _err("target_unknown",
                         "no candidate %s/%s" % (route, model))
                targets[role] = {"route": route, "model": model}
                continue
            if not _exact_str(spec, _MAX_MODEL_LEN):
                _err("target_invalid", "bad model spec for role %r" % role)
            matches = [c for c in reg["candidates"] if c["model"] == spec]
            if not matches:
                _err("target_unknown", "no candidate for model %r" % spec)
            if len(matches) > 1:
                _err("target_ambiguous", "model %r spans routes" % spec)
            targets[role] = {"route": matches[0]["route"], "model": spec}
        return targets

    def _usage(self, model, route):
        base = {"remaining_percent": None, "comparison_group": None,
                "low_remaining": False, "source_ref": None,
                "reason": "native_usage_unsupported"}
        usage = self.usage
        if usage is None or not hasattr(usage, "get"):
            return base
        try:
            snap = usage.get((model, route))
        except Exception:
            snap = None
        if snap is None:
            base["reason"] = "usage_unobserved"
            return base
        ok = type(snap) is dict and set(snap) == _SNAPSHOT_KEYS
        if ok:
            percent = snap["remaining_percent"]
            ok = (
                (percent is None
                 or (type(percent) in (int, float)
                     and 0 <= percent <= 100))
                and (snap["comparison_group"] is None
                     or _exact_str(snap["comparison_group"], _MAX_GROUP_LEN))
                and type(snap["low_remaining"]) is bool
                and _finite_nonneg(snap["observed_at"])
                and _finite_nonneg(snap["max_age"])
                and _exact_str(snap["source_ref"], _MAX_REF_LEN))
        if not ok:
            base["reason"] = "usage_invalid"
            return base
        try:
            now = self._now()
        except Exception:
            now = None
        if not _finite_nonneg(now):
            base["reason"] = "usage_invalid"
            return base
        if snap["observed_at"] > now:
            base["reason"] = "usage_future"
            return base
        if now - snap["observed_at"] > snap["max_age"]:
            base["reason"] = "usage_stale"
            return base
        return {"remaining_percent": snap["remaining_percent"],
                "comparison_group": snap["comparison_group"],
                "low_remaining": snap["low_remaining"],
                "source_ref": snap["source_ref"],
                "reason": "provider_snapshot"}

    def selection(self, role, focus, policy=None):
        """Pin one eligible candidate for a role and focus category."""
        reg = self._reg()
        if type(role) is not str or role not in _ROLES:
            _err("role_invalid", "unknown role %r" % (role,))
        if type(focus) is not str or focus not in _categories():
            _err("focus_unknown", "unknown focus category %r" % (focus,))
        mode, targets = _policy(policy, reg["candidates"])
        exact = None
        if role in targets:
            exact = (targets[role]["model"], targets[role]["route"])
        if mode == "fixed" and exact is None:
            _err("selection_unconfigured",
                 "fixed mode requires a target for role %r" % role)
        options, meta, excluded = [], {}, []
        for cand in reg["candidates"]:
            route, model = cand["route"], cand["model"]
            fit = next((f for f in cand["fit"] if f["category"] == focus),
                       None)
            reason = None
            if fit is None:
                reason = "fit_absent"
            else:
                entry = reg["measurements"].get("%s/%s" % (route, model))
                if entry is None:
                    reason = "not_measured"
                else:
                    try:
                        entry = infer._validate_entry(entry, route, model,
                                                      reg["cwd"])
                    except Exception:
                        reason = "measurement_invalid"
            if reason is not None:
                if len(excluded) < _MAX_EXCLUDED:
                    excluded.append({"route": route, "model": model,
                                     "reason": reason})
                continue
            use = self._usage(model, route)
            options.append(SelectionCandidate(
                key=(model, route), suitability=fit["degree"],
                remaining_percent=use["remaining_percent"],
                comparison_group=use["comparison_group"],
                low_remaining=use["low_remaining"]))
            meta[(model, route)] = (fit, entry, use)
        decision = select_candidates(options, mode=mode, exact_key=exact)
        if decision.selected is None:
            _err("no_exact_replacement" if exact else "no_eligible_route",
                 "no eligible candidate for role %r focus %r"
                 % (role, focus))
        model, route = decision.selected.key
        fit, entry, use = meta[(model, route)]
        if mode == "fixed":
            reason = "fixed_target"
        elif exact is not None:
            reason = "exact_target"
        elif decision.reason == "comparable_usage":
            reason = "comparable_usage"
        elif decision.reason == "low_remaining_avoided":
            reason = "low_remaining_avoided"
        elif mode == "usage":
            reason = ("usage_unknown_then_suitability"
                      if all(o.remaining_percent is None
                             and o.comparison_group is None
                             and not o.low_remaining for o in options)
                      else "usage_incomparable_then_suitability")
        else:
            reason = "suitability_then_stable_order"
        m_digest = entry["measurement_digest"]
        return {
            "route": route,
            "model": model,
            "measurement_digest": m_digest,
            "environment_ref": "native:" + m_digest,
            "mode": mode,
            "reason": reason,
            "focus": focus,
            "fit": {"degree": fit["degree"], "origin": fit["origin"],
                    "source_ref": fit["source_ref"]},
            "usage": {"remaining_percent": use["remaining_percent"],
                      "reason": use["reason"],
                      "comparison_group": use["comparison_group"],
                      "low_remaining": use["low_remaining"],
                      "source_ref": use["source_ref"]},
            "catalog_digest": digest(canonical(reg).encode("utf-8")),
            "excluded": excluded,
        }

    def options(self, role, focus, policy=None):
        """Return the selection pin for each eligible registered candidate.

        Each registry candidate is pinned through `selection` with that
        candidate as the explicit role target of a copied policy, so fit,
        measurement, and in-memory-usage eligibility match a normal pin.
        Candidates that cannot be pinned are omitted; registry order is
        preserved and the caller's policy is never mutated.
        """
        reg = self._reg()
        if type(role) is not str or role not in _ROLES:
            _err("role_invalid", "unknown role %r" % (role,))
        if type(focus) is not str or focus not in _categories():
            _err("focus_unknown", "unknown focus category %r" % (focus,))
        mode, targets = _policy(policy, reg["candidates"])
        pins = []
        for cand in reg["candidates"]:
            route, model = cand["route"], cand["model"]
            copied = {"mode": mode, "targets": dict(targets)}
            copied["targets"][role] = {"model": model, "route": route}
            try:
                pin = self.selection(role, focus, copied)
            except TaskError as exc:
                if exc.code in ("no_exact_replacement", "no_eligible_route"):
                    continue
                raise
            if pin["route"] != route or pin["model"] != model:
                _err("selection_substituted",
                     "selection pinned a different candidate")
            pins.append(pin)
        return pins

    def infer_selected(self, selection, role, prompt, call_dir, timeout=900,
                       before_launch=None):
        """Execute a pin; measurement is reloaded under infer.lock."""
        if type(role) is not str or role not in _ROLES:
            _err("role_invalid", "unknown inference role")
        if type(timeout) is not int or not 1 <= timeout <= 900:
            _err("timeout_invalid", "timeout must be an int between 1 and 900")
        if type(selection) is not dict:
            _err("selection_invalid", "selection must be a pin mapping")
        route = selection.get("route")
        model = selection.get("model")
        m_digest = selection.get("measurement_digest")
        if (not _exact_str(route, _MAX_ID_LEN)
                or not _exact_str(model, _MAX_MODEL_LEN)
                or not _exact_str(m_digest, _MAX_REF_LEN)):
            _err("selection_invalid", "pin lacks route/model/digest")

        def load_entry(load_route, load_model):
            reg = self._reg()
            entry = reg["measurements"].get("%s/%s" % (load_route,
                                                       load_model))
            if type(entry) is not dict:
                _err("measurement_missing", "pinned measurement is gone")
            entry = infer._validate_entry(entry, load_route, load_model,
                                          reg["cwd"])
            if entry.get("measurement_digest") != m_digest:
                _err("measurement_drift",
                     "measurement changed since the pin was issued")
            return entry

        if before_launch is None:
            return infer._infer_pinned(self.state_dir, selection, role,
                                       prompt, call_dir, timeout, load_entry)
        return infer._infer_pinned(self.state_dir, selection, role, prompt,
                                   call_dir, timeout, load_entry,
                                   before_launch=before_launch)

    def supported_focuses(self):
        """Categories with declared fit and a valid measurement, without CLI calls."""
        reg = self._reg()
        return sorted({f["category"] for candidate in reg["candidates"]
                       if self._valid_entry(reg, candidate) is not None
                       for f in candidate["fit"]})

    def validate_plan(self, plan, policy=None):
        """Ensure every actual step has a fit+measured candidate honoring
        targets; fixed mode requires every actual role bound. No ranking."""
        reg = self._reg()
        mode, targets = _policy(policy, reg["candidates"])
        for role, focus in _plan_steps(plan):
            target = targets.get(role)
            if mode == "fixed" and target is None:
                _err("selection_unconfigured",
                     "fixed mode requires a target for role %r" % role)
            for cand in reg["candidates"]:
                if target is not None and (
                        cand["route"] != target["route"]
                        or cand["model"] != target["model"]):
                    continue
                if not any(f["category"] == focus for f in cand["fit"]):
                    continue
                if self._valid_entry(reg, cand) is not None:
                    break
            else:
                if target is not None:
                    _err("no_exact_replacement",
                         "target %s/%s cannot serve role %r focus %r"
                         % (target["route"], target["model"], role, focus))
                _err("plan_unfittable",
                     "no fit+measured candidate for role %r focus %r"
                     % (role, focus))
        return None
