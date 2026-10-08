"""Synthetic `devin acp` child-process fixture, NOT a Native capture or isolation test."""
import json
import os
import sys
import time

if sys.argv[1:] == ["version"]:
    print("devin-fixture 0.0.0")
    raise SystemExit

if len(sys.argv) < 2 or sys.argv[1] != "acp":
    raise SystemExit(2)

mode = "accept-edits"

def config_options():
    return [{"id": "mode", "name": "Mode", "type": "select",
             "currentValue": mode, "options": [
                 {"value": value, "name": value}
                 for value in ("accept-edits", "smart", "ask", "plan", "bypass")]}]


def response(message, result):
    return (json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}) + "\n").encode()


for line in sys.stdin.buffer:
    message = json.loads(line)
    if message["method"] == "initialize":
        raw = response(message, {"protocolVersion": 1, "agentCapabilities": {}})
    elif message["method"] == "session/new":
        # Live 3000.11.3 ordering: config notification precedes new result.
        raw = (json.dumps({"jsonrpc": "2.0", "method": "session/update", "params": {
            "sessionId": "fixture-session", "update": {
                "sessionUpdate": "config_option_update", "configOptions": config_options()}}}) + "\n").encode()
        raw += response(message, {"sessionId": "fixture-session", "configOptions": config_options()})
    elif message["method"] == "session/set_config_option":
        assert message["params"]["sessionId"] == "fixture-session"
        assert message["params"]["configId"] == "mode"
        mode = message["params"]["value"]
        assert mode in ("accept-edits", "smart", "ask", "plan", "bypass")
        raw = response(message, {"configOptions": config_options()})
    elif message["method"] == "session/prompt":
        assert message["params"]["sessionId"] == "fixture-session"
        raw = response(message, {"stopReason": "end_turn"})
    elif message["method"] == "malformed":
        raw = b"not-json\n"
    elif message["method"] == "duplicate":
        raw = b'{"id":1,"id":2}\n'
    elif message["method"] == "probe_env":
        # Synthetic marker/env check only; the test supplies its own environ.
        raw = (json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {
            "argv": sys.argv[1:],
            "devin_prefix": sorted(key for key in os.environ
                                   if key.startswith("DEVIN_")),
            "marker": os.environ.get("CO03_MARKER")}}, ensure_ascii=False) + "\n").encode()
    else:
        raw = (json.dumps({"jsonrpc": "2.0", "id": message["id"],
                           "result": message["params"]},
                          ensure_ascii=False) + "\n").encode()
    # Exercise buffering across multiple reads, including UTF-8 payloads.
    os.write(1, raw[:len(raw) // 2])
    time.sleep(.02)
    os.write(1, raw[len(raw) // 2:])
