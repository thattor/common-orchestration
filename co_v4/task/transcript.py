"""Transcript parsers for measured native CLI output.

Pure functions over raw bytes: no filesystem or process side effects.
Devin ATIF-v1.7 has a strict normal path (zero tool requests) and a
separate qualification-only induction walk; claude uses stream-json.
The caller supplies the measured tools digest on every call.

Imports common only.
"""

import json

from .common import TaskError, canonical, digest


def _atif_header(raw, *, tools_digest):
    try:
        doc = json.loads(raw)
    except ValueError:
        raise TaskError("route_failed")
    if not isinstance(doc, dict):
        raise TaskError("route_failed")
    if doc.get("error") or doc.get("is_error"):
        raise TaskError("route_refused")
    if doc.get("schema_version") != "ATIF-v1.7":
        raise TaskError("route_failed")
    agent = doc.get("agent")
    definitions = agent.get("tool_definitions") if isinstance(agent, dict) else None
    if not isinstance(definitions, list) or digest(canonical(definitions).encode()) != tools_digest:
        raise TaskError("route_unmeasured")
    return doc


def parse_atif_normal(raw, prompt, model, version, *, tools_digest):
    """Strict ATIF-v1.7 for NORMAL calls: zero tool requests accepted -
    a request is a violation even when denied. Exactly one user==prompt;
    every agent step exact model_name + extra.generation_model + explicit
    tool_calls == []; no tool source or unknown source."""
    doc = _atif_header(raw, tools_digest=tools_digest)
    agent = doc.get("agent")
    if not isinstance(agent, dict) or agent.get("version") != version:
        raise TaskError("route_violation")
    steps = doc.get("steps")
    if not isinstance(steps, list):
        raise TaskError("route_failed")
    user_msgs, texts = [], []
    for s in steps:
        if not isinstance(s, dict):
            raise TaskError("route_failed")
        src = s.get("source")
        if src == "tool":
            raise TaskError("route_violation")
        if src not in ("system", "user", "agent"):
            raise TaskError("route_failed")
        if src == "user":
            if not isinstance(s.get("message"), str):
                raise TaskError("route_failed")
            user_msgs.append(s["message"])
        elif src == "agent":
            if s.get("model_name") != model:
                raise TaskError("route_violation")
            extra = s.get("extra")
            if not isinstance(extra, dict) or extra.get("generation_model") != model:
                raise TaskError("route_violation")
            if s.get("tool_calls") != []:
                raise TaskError("route_violation")
            if not isinstance(s.get("message"), str):
                raise TaskError("route_failed")
            texts.append(s["message"])
    if user_msgs != [prompt]:
        raise TaskError("route_failed")
    if not texts or not texts[-1]:
        raise TaskError("route_failed")
    return {"text": texts[-1], "tool_calls": 0}


def parse_atif_qualification(raw, prompt, model, version, *, tools_digest):
    """QUALIFICATION-ONLY ATIF walk: collects tool_call dicts and tool
    observations instead of rejecting them. Never used by normal infer."""
    doc = _atif_header(raw, tools_digest=tools_digest)
    agent = doc.get("agent")
    if not isinstance(agent, dict) or agent.get("version") != version:
        raise TaskError("route_violation")
    steps = doc.get("steps")
    if not isinstance(steps, list):
        raise TaskError("route_failed")
    user_msgs, calls, obs = [], [], []
    for s in steps:
        if not isinstance(s, dict):
            raise TaskError("route_failed")
        src = s.get("source")
        if src not in ("system", "user", "agent"):
            raise TaskError("route_failed")
        if src == "system":
            continue
        if src == "user":
            if not isinstance(s.get("message"), str):
                raise TaskError("route_failed")
            user_msgs.append(s["message"])
        else:
            if s.get("model_name") != model:
                raise TaskError("route_violation")
            extra = s.get("extra")
            if not isinstance(extra, dict) or extra.get("generation_model") != model:
                raise TaskError("route_violation")
            tc = s.get("tool_calls")
            if not isinstance(tc, list):
                raise TaskError("route_failed")
            for c in tc:
                if not isinstance(c, dict):
                    raise TaskError("route_failed")
                calls.append(c)
            observation = s.get("observation")
            if observation is not None:
                results = observation.get("results") if isinstance(observation, dict) else None
                if not isinstance(results, list):
                    raise TaskError("route_failed")
                for result in results:
                    if not isinstance(result, dict) or not isinstance(result.get("source_call_id"), str) \
                            or not isinstance(result.get("content"), str):
                        raise TaskError("route_failed")
                    obs.append(result)
    if user_msgs != [prompt]:
        raise TaskError("route_failed")
    return {"calls": calls, "observations": obs}


def parse_claude_stream(raw, model):
    """Strict stream-json: exactly one init with exact model, explicit
    tools [] and mcp_servers [], apiKeySource 'none'; exactly one success
    result; zero tool_use; every line valid JSON."""
    inits = results = tools = 0
    text = None
    refused = False
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            raise TaskError("route_failed")
        if not isinstance(msg, dict):
            raise TaskError("route_failed")
        t = msg.get("type")
        if t == "system" and msg.get("subtype") == "init":
            inits += 1
            if msg.get("model") != model:
                raise TaskError("route_violation")
            if msg.get("tools") != [] or msg.get("mcp_servers") != []:
                raise TaskError("route_violation")
            if msg.get("apiKeySource") != "none":
                raise TaskError("route_violation")
        elif t == "assistant":
            m = msg.get("message")
            if not isinstance(m, dict):
                raise TaskError("route_failed")
            if isinstance(m.get("model"), str) and m["model"] != model:
                raise TaskError("route_violation")
            for b in m.get("content") or []:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    tools += 1
        elif t == "result":
            results += 1
            text = msg.get("result")
            if msg.get("is_error") or msg.get("subtype") != "success":
                refused = True
    if inits != 1 or results != 1:
        raise TaskError("route_failed")
    if tools:
        raise TaskError("route_violation")
    if refused:
        raise TaskError("route_refused")
    if not isinstance(text, str) or not text:
        raise TaskError("route_failed")
    return {"text": text, "tool_calls": 0, "api_key_source": "none"}
