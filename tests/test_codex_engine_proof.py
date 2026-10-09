import dataclasses
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

from co_v4.codex_engine import (ADAPTER, NATIVE_VERSION, CodexTextError,
                                accepted_result, no_turn_proven)
from co_v4.codex_host import CodexHostConfig
from co_v4.contracts import (AttemptRef, ExecutionConditions, ExecuteRequest,
                             Job)
from co_v4.delegation import DelegatedScope

OVERRIDES = ['service_tier="default"', 'features.fast_mode=false']
MISSING = object()


def _apply(base, kw):
    for k, v in kw.items():
        if v is MISSING:
            base.pop(k, None)
        else:
            base[k] = v
    return base


def _request():
    ref = AttemptRef("r1", "j1", "a1")
    cond = ExecutionConditions("m", ADAPTER, "/w", "e1")
    job = Job(run_id="r1", job_id="j1", instructions="i", acceptance_criteria=())
    return ExecuteRequest(ref=ref, job=job, conditions=cond)


def _config(request, **kw):
    return CodexHostConfig(**_apply(dict(
        conditions=request.conditions, executable=Path("/bin/codex"),
        python=Path("/bin/python3"), protected_state=(Path("/p"),),
        credential_files=(Path("/c"),), use_named_permissions=True,
        delegation=DelegatedScope("h1", request.ref, request.conditions.workspace),
        reasoning_effort="high", mode="normal", native_version=NATIVE_VERSION,
        approval_policy="never"), kw))


def _observation(**kw):
    return _apply({
        "native_handoff_verified": True,
        "model_selection": {"model": "m", "requested_effort": "high",
            "effective_effort": "high", "effective_effort_reported": True,
            "native_version": NATIVE_VERSION, "source": "owned_native_model_list"},
        "subscription_precondition": {"account_type": "chatgpt", "plan_type": "pro",
            "ordinary_included_usage_allowed": True, "api_environment_absent": True,
            "additional_payment_or_grant_enabled": False},
        "service_tier_observation": {"requested": "normal",
            "matched_before_turn": True, "sent_config_overrides": OVERRIDES,
            "effective_fast_mode": False, "effective_config": "default",
            "original_thread_response": None, "fast_configuration_verified": False,
            "speed_increase_measured": False}}, kw)


def _observed(**kw):
    return NS(**_apply(dict(
        native_version=NATIVE_VERSION, expected_effort="high", error=None,
        terminal="completed", turn_submissions=1, tool_calls=0,
        turn_rpc_confirmed=True, stopped=True, validated_eof=True,
        drain_clean=True, cleanup_terminated=False, natural_exit=0,
        texts={"f": "x" * 3000}, turn_write_attempt_at=1.0,
        turn_started_at=2.0, turn_completed_at=3.0), kw))


def _call(**kw):
    req = _request()
    cfg = kw.get("config") or _config(req)
    host = kw.get("host") or NS(observation=_observation())
    ob = kw["observed"] if "observed" in kw else _observed()
    return accepted_result(req, cfg, host, ob, source_verified=kw.get("sv", True))


class AcceptedResultTests(unittest.TestCase):
    def _err(self, **kw):
        with self.assertRaises(CodexTextError) as cm:
            _call(**kw)
        return cm.exception

    def _gates(self):
        req = _request()
        cfg = _config(req)
        return {"source_false": {"sv": False},
                "delegation_attempt": {"config": dataclasses.replace(cfg,
                    delegation=DelegatedScope("h", AttemptRef("r", "j", "x"), "/w"))},
                "delegation_intent": {"config": dataclasses.replace(cfg,
                    delegation=DelegatedScope("", req.ref, "/w"))},
                "delegation_capability": {"config": dataclasses.replace(cfg,
                    delegation=DelegatedScope("h", req.ref, "/w", "x"))},
                "conditions": {"config": dataclasses.replace(cfg,
                    conditions=dataclasses.replace(req.conditions, model="z"))},
                "named_permissions": {"config": dataclasses.replace(cfg,
                    use_named_permissions=False)},
                "host_handoff": {"host": NS(observation=_observation(
                    native_handoff_verified=False))},
                "host_subproof": {"host": NS(observation=_observation(
                    subscription_precondition={"account_type": "api"}))},
                "host_missing_sel": {"host": NS(observation=_observation(
                    model_selection=MISSING))},
                "host_attr_fake": {"host": NS(observation=NS(
                    native_handoff_verified=True))}}

    def test_success(self):
        res = _call()
        self.assertEqual(res["text"], "x" * 3000)
        self.assertEqual((res["model"], res["effort"], res["tool_calls"]),
                         ("m", "high", 0))
        ev = res["evidence"]
        self.assertEqual((ev["turn_submissions"], ev["tool_calls"],
                          ev["final_count"], ev["output_bytes"]), (1, 0, 1, 3000))
        self.assertTrue(ev["normal_completion"] and ev["stopped"])
        self.assertTrue(ev["output_sha256"].startswith("sha256:"))
        tier = dict(_observation()["service_tier_observation"],
                    original_thread_response="default")
        res = _call(host=NS(observation=_observation(service_tier_observation=tier)))
        self.assertEqual(res["text"], "x" * 3000)

    def test_gate_failures(self):
        for name, kw in self._gates().items():
            for ob, pair in ((_observed(), ("unknown", "inference")),
                             (_observed(turn_submissions=0),
                              ("not_started", "preflight"))):
                with self.subTest(name, pair=pair):
                    e = self._err(observed=ob, **kw)
                    self.assertEqual(e.code, "route_violation")
                    self.assertEqual((e.outcome, e.phase), pair)
        self.assertTrue(no_turn_proven(_observed(turn_submissions=0)))
        self.assertFalse(no_turn_proven(None))

    def test_no_turn_requires_bound_observer(self):
        bad = dataclasses.replace(_config(_request()), use_named_permissions=False)
        cases = {"none": None,
                 "stop_false": _observed(turn_submissions=0, stopped=False),
                 "stop_int": _observed(turn_submissions=0, stopped=1),
                 "stop_gone": _observed(turn_submissions=0, stopped=MISSING),
                 "count_bool": _observed(turn_submissions=False),
                 "count_str": _observed(turn_submissions="0"),
                 "count_two": _observed(turn_submissions=2),
                 "count_gone": _observed(turn_submissions=MISSING)}
        for name, ob in cases.items():
            with self.subTest(name):
                e = self._err(config=bad, observed=ob)
                self.assertEqual((e.code, e.outcome, e.phase),
                                 ("route_violation", "unknown", "inference"))

    def test_tool_calls(self):
        for name, v in {"gone": MISSING, "bool": True, "str": "0", "neg": -1,
                        "pos": 1}.items():
            with self.subTest(name):
                e = self._err(observed=_observed(tool_calls=v))
                self.assertEqual((e.outcome, e.phase), ("unknown", "inference"))
        e = self._err(observed=_observed(error="x", tool_calls=MISSING))
        self.assertEqual((e.outcome, e.phase), ("unknown", "inference"))
        self.assertEqual(_call()["tool_calls"], 0)

    def test_text_bounds(self):
        for n in (2049, 1 << 20):
            with self.subTest(n=n):
                res = _call(observed=_observed(texts={"f": "y" * n}))
                self.assertEqual(res["evidence"]["output_bytes"], n)
        e = self._err(observed=_observed(texts={"f": "y" * ((1 << 20) + 1)}))
        self.assertEqual((e.code, e.outcome, e.phase),
                         ("route_overflow", "unknown", "inference"))
        e = self._err(observed=_observed(texts={"f": "a" + chr(0xD800) + "b"}))
        self.assertEqual((e.outcome, e.phase), ("unknown", "inference"))

    def test_observer_proofs(self):
        cases = {"error": dict(error="e"), "terminal": dict(terminal="x"),
                 "eof": dict(validated_eof=False), "drain": dict(drain_clean=False),
                 "cleanup": dict(cleanup_terminated=True),
                 "exit": dict(natural_exit=1), "rpc": dict(turn_rpc_confirmed=False),
                 "stopped": dict(stopped=False), "timing": dict(turn_started_at=0.5),
                 "two_texts": dict(texts={"a": "x", "b": "y"}),
                 "empty_text": dict(texts={"f": ""}),
                 "effort": dict(expected_effort="low"),
                 "version": dict(native_version="v")}
        for name, kw in cases.items():
            with self.subTest(name):
                e = self._err(observed=_observed(**kw))
                self.assertEqual((e.outcome, e.phase), ("unknown", "inference"))


if __name__ == "__main__":
    unittest.main()
