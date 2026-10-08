"""Synthetic child-process fixture, NOT a Native capture or isolation test."""
import json
import os
import sys
import time

if sys.argv[1:] == ["--version"]:
    print("codex-cli 0.156.1")
    raise SystemExit

for line in sys.stdin.buffer:
    message = json.loads(line)
    if message["method"] == "malformed":
        raw = b"not-json\n"
    elif message["method"] == "duplicate":
        raw = b'{"id":1,"id":2}\n'
    else:
        raw = (json.dumps({"id": message["id"], "result": message["params"]},
                          ensure_ascii=False) + "\n").encode()
    # Exercise buffering across multiple reads, including UTF-8 payloads.
    os.write(1, raw[:len(raw) // 2])
    time.sleep(.02)
    os.write(1, raw[len(raw) // 2:])
