"""Offline ACP child fixture. No model/auth/network; scenarios are test names."""
import json
import os
import signal
import sys
from pathlib import Path

if sys.argv[1:] == ["version"]:
    print("devin-cessation-fixture 0")
    raise SystemExit

scenario_file = Path(__file__).with_suffix(".scenario")
scenario = scenario_file.read_text() if scenario_file.exists() else "normal"
session = "private-fixture-session"
prompt = None


def emit(message):
    os.write(1, (json.dumps(message) + "\n").encode())


def update(kind, **fields):
    return {"jsonrpc": "2.0", "method": "session/update", "params": {
        "sessionId": session, "update": {"sessionUpdate": kind, **fields}}}


def permission():
    return {"jsonrpc": "2.0", "id": "permission", "method": "session/request_permission",
            "params": {"sessionId": session, "toolCall": {"toolCallId": "tool"}, "options": []}}


def startup_output(**changes):
    return {"jsonrpc": "2.0", "method": "_cognition.ai/output", "params": {
        "channel": "fixture-log", "level": "info", "message": "PRIVATE_NATIVE_LOG",
        "sessionId": None, **changes}}


def turn_telemetry(cause="complete", variant="", cancelled=False):
    thinking = {"sessionId": session, "durationMs": 1, "blockIndex": 0}
    turn = {"sessionId": session, "turnClientMessageId": "private-message-id"}
    stats = {"toolCalls": 0, "filesChanged": 0, "commandsRun": 0, "modelLabel": "fixture"}
    if not cancelled:
        turn.update(turnRequestId="private-turn-id", responseDimensions=[{"label": "PRIVATE_DIMENSION"}])
        stats.update(inputTokens=1, outputTokens=1, ttftMs=1, totalTimeMs=1, tokensPerSec=1.0,
                     requestId="private-turn-id", responseDimensions=[{"label": "PRIVATE_DIMENSION"}])
    stopped = {"sessionId": session, "cause": cause, "stats": stats}
    if variant == "activity": stats["toolCalls"] = 1
    if variant == "missing_activity": del stats["commandsRun"]
    if variant == "bad_type": stats["filesChanged"] = False
    if variant == "nonfinite": stats["tokensPerSec"] = float("inf")
    if variant == "unknown_stats": stats["unknown"] = 0
    if variant == "error": stopped["errorMessage"] = "PRIVATE_NATIVE_ERROR"
    if variant == "foreign": stopped["sessionId"] = "other-session"
    if variant == "bad_thinking": thinking["durationMs"] = -1
    if variant == "bad_turn": turn["turnClientMessageId"] = None
    if not cancelled:
        emit({"jsonrpc": "2.0", "method": "_cognition.ai/thinking_complete", "params": thinking})
    emit({"jsonrpc": "2.0", "method": "_cognition.ai/turn_stats", "params": turn})
    emit({"jsonrpc": "2.0", "method": "_cognition.ai/agent_stopped", "params": stopped})


def terminated(*_):
    if scenario == "late_model":
        emit(update("current_model_update", currentModelId="swe-2-max"))
    elif scenario == "late_model_match":
        emit(update("current_model_update", currentModelId="swe-2-high"))
    elif scenario == "late_model_empty":
        emit(update("current_model_update", currentModelId=""))
    elif scenario == "late_mode":
        emit(update("current_mode_update", currentModeId="bypass"))
    elif scenario == "late_tool":
        emit(update("tool_call", toolCallId="tool", status="completed"))
    elif scenario == "late_permission":
        emit(permission())
    elif scenario == "late_unknown":
        emit({"jsonrpc": "2.0", "id": "callback", "method": "terminal/create",
              "params": {"sessionId": session}})
    elif scenario == "late_wrong_session":
        message = update("agent_message_chunk", content={"type": "text", "text": "x"})
        message["params"]["sessionId"] = "different-session"
        emit(message)
    elif scenario == "late_bad_json":
        os.write(1, b"not-json\n")
    elif scenario == "late_truncated":
        os.write(1, b'{"jsonrpc":"2.0"')
    elif scenario == "late_benign":
        emit(update("agent_message_chunk", content={"type": "text", "text": "last"}))
    elif scenario == "late_log":
        emit(startup_output(sessionId=session))
    elif scenario == "late_log_foreign":
        emit(startup_output(sessionId="other-session"))
    elif scenario == "late_servers_nonempty":
        emit({"jsonrpc": "2.0", "method": "_cognition.ai/mcp/serversChanged", "params": {"servers": []}})
    elif scenario == "late_telemetry_conflict":
        turn_telemetry(cause="cancelled")
    raise SystemExit(0)


signal.signal(signal.SIGTERM, terminated)
for line in sys.stdin:
    message = json.loads(line)
    method = message["method"]
    if method == "initialize":
        if (scenario == "bootstrap_valid" or scenario.startswith("bootstrap_invalid_")
                or scenario in {"metadata_inventory", "metadata_inventory_limit"}):
            emit({"jsonrpc": "2.0", "method": "_cognition.ai/mcp/serversChanged", "params": {}})
            if scenario == "bootstrap_invalid_servers":
                emit({"jsonrpc": "2.0", "method": "_cognition.ai/mcp/serversChanged",
                      "params": {"servers": []}})
            elif scenario == "bootstrap_invalid_session":
                emit(startup_output(sessionId="different-session"))
            elif scenario == "bootstrap_invalid_type":
                emit(startup_output(message={"value": "PRIVATE_NATIVE_LOG"}))
            elif scenario == "bootstrap_invalid_fields":
                emit(startup_output(unrecognized="PRIVATE_NATIVE_LOG"))
            else:
                emit(startup_output())
        if scenario == "bootstrap_notification":
            emit({"jsonrpc": "2.0", "method": "PRIVATE_METHOD_SECRET", "params": {"secret": "SECRET"}})
        result = {"protocolVersion": 1}
    elif method == "session/new":
        if (scenario.startswith("bootstrap_candidate_")
                or scenario in {"metadata_inventory", "metadata_inventory_limit"}):
            emit(startup_output(sessionId=("different-session" if scenario.endswith("mismatch") else session)))
            if scenario.endswith("conflict"):
                emit(startup_output(sessionId="different-session"))
        if scenario in {"bootstrap_unknown", "bootstrap_model"}:
            emit(update("PRIVATE_ARBITRARY_VARIANT" if scenario == "bootstrap_unknown"
                        else "current_model_update", privateValue="SECRET"))
        result = {"sessionId": session, "modes": {
            "currentModeId": "plan", "availableModes": [{"id": "plan"}]}}
        if scenario in {"late_model", "late_model_match", "late_model_empty", "model_advertised"}:
            result["models"] = {"currentModelId": "swe-2-high",
                                "availableModels": [{"modelId": "swe-2-high"}]}
    elif method == "session/prompt":
        prompt = message
        if scenario.startswith("telemetry_"):
            variant = scenario.removeprefix("telemetry_")
            turn_telemetry(cause="cancelled" if variant == "conflict" else "complete", variant=variant)
            if variant == "no_primary": raise SystemExit(0)
        if scenario == "post_prompt_log":
            emit(startup_output(sessionId=session))
        if scenario == "post_prompt_servers":
            emit({"jsonrpc": "2.0", "method": "_cognition.ai/mcp/serversChanged", "params": {}})
        if scenario.startswith("metadata_"):
            emit(startup_output(sessionId=session))
            emit({"jsonrpc": "2.0", "method": "_cognition.ai/mcp/serversChanged", "params": {}})
            if scenario == "metadata_only_exit":
                raise SystemExit(0)
            if scenario == "metadata_with_tool":
                emit(update("tool_call", toolCallId="tool"))
            if scenario == "metadata_with_permission":
                emit(permission())
            if scenario == "metadata_with_mode_drift":
                emit(update("current_mode_update", currentModeId="bypass"))
            if scenario == "metadata_invalid_log":
                emit(startup_output(sessionId=session, unknown="PRIVATE_NATIVE_LOG"))
            if scenario in {"metadata_inventory", "metadata_inventory_limit"}:
                emit({"jsonrpc": "2.0", "method": "_cognition.ai/thinking_complete", "params": {
                    "sessionId": session, "durationMs": 1, "blockIndex": 0}})
                emit({"jsonrpc": "2.0", "method": "PRIVATE_UNKNOWN_METHOD", "params": {
                    "PRIVATE_UNKNOWN_KEY": "PRIVATE_NATIVE_VALUE"}})
                emit({"jsonrpc": "2.0", "method": "_cognition.ai/agent_stopped", "params": {
                    "sessionId": session, "cause": "completed", "stats": {
                        "toolCalls": 0, "filesChanged": 0, "commandsRun": 0, "inputTokens": 7,
                        "PRIVATE_UNKNOWN_KEY": "PRIVATE_NATIVE_VALUE"}}})
                if scenario == "metadata_inventory_limit":
                    for _ in range(70): emit(startup_output(sessionId=session))
        if scenario.startswith("cancel"):
            continue
        if scenario == "exit_only":
            raise SystemExit(0)
        if scenario == "tool":
            emit(update("tool_call", toolCallId="tool", status="completed"))
        if scenario == "permission":
            emit(permission())
        if scenario == "unknown_update":
            emit(update("unknown_activity"))
        if scenario == "unknown_notification":
            emit({"jsonrpc": "2.0", "method": "unrecognized", "params": {}})
        result = {"stopReason": "cancelled" if scenario == "unrequested_cancel" else "end_turn"}
        if scenario == "wrong_session":
            result["sessionId"] = "different-session"
        if scenario == "wrong_rpc":
            message = {**message, "id": "other-rpc"}
    elif method == "session/cancel":
        assert message["params"]["sessionId"] == session
        if scenario == "cancel_silent":
            continue
        if scenario == "cancel_receipt":
            emit({"jsonrpc": "2.0", "id": "cancel-receipt", "result": {}})
            continue
        message = prompt
        if scenario == "cancel_wrong_rpc":
            message = {**message, "id": "cancel-rpc"}
        result = {"stopReason": "end_turn" if scenario == "cancel_end_turn" else "cancelled"}
        if scenario == "cancel_metadata":
            emit(startup_output(sessionId=session))
            emit({"jsonrpc": "2.0", "method": "_cognition.ai/mcp/serversChanged", "params": {}})
        if scenario == "cancel_telemetry":
            turn_telemetry(cause="cancelled", cancelled=True)
        emit(update("agent_message_chunk", content={"type": "text", "text": "pending"}))
    else:
        raise SystemExit(2)
    emit({"jsonrpc": "2.0", "id": message["id"], "result": result})
