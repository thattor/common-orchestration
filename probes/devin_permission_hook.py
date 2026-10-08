#!/usr/bin/env python3
"""Devin CLI lifecycle-hook relay seam (documented format; synthetic-capable).

Reads one PreToolUse or PermissionRequest event JSON on stdin, as described by
the bundled CLI docs (`extensibility/hooks/*.mdx`), loads a Controller
resolution from --decision-file, and prints the documented decision JSON:

  deny   -> {"decision": "block",   "reason": ...}
  cancel -> {"decision": "block",   "reason": "cancel: ..."}
  allow  -> never relayed: always defers (exit 0, no output)

`allow` is unsupported, on purpose: this hook is not attached to a trusted
host authority that can pin and verify the exact actual target of the call.
Everything the hook can see is a path string, and the target behind it can
drift between decision time and call time — a `workdir` or `file_path`
component can be a retargeted symlink, `git -C` selects a repository the
command string does not name, a persistent shell's cwd is unobservable, and
the decision file itself can be reached through alias paths. No check this
hook can run proves that the operation it would approve is the one the
Controller approved, so an allow resolution is audited and then defers to the
Native permission prompt every time — with Scope present, empty or absent,
and under any path spelling. Only the restrictive resolutions are relayed,
because blocking can never grant authority the Controller did not give.

A decision is relayed ONLY when it is bound to this exact request: session_id,
prompt_id (per-turn; rotated on every user prompt), tool_name and the complete
tool_input must all be byte-exact to the event. Because prompt_id is per turn
rather than per call, binding alone cannot keep a decision single-use: a bound
decision is therefore consumed exactly once, by atomically claiming a
`<realpath(decision-file)>.consumed` marker (O_CREAT|O_EXCL). Anchoring the
marker to the decision file's canonical path means alias spellings and
symlinks to the same decision share one claim — the same content cannot be
spent twice through different path names. Any later call — even a
byte-identical request in the same turn — finds the decision spent, defers
and the duplicate claim attempt is preserved in the audit record. Consumption
applies to allow, deny and cancel alike: each resolution answers one request.

Any missing, mismatched, spent or unverifiable decision defers (exit 0, no
output). Deferral is also the outcome for malformed input, a missing or
unreadable decision file, an unknown resolution, or a marker that cannot be
created (without the marker the one-time guarantee cannot be enforced, so the
hook never proceeds). This hook never manufactures an approval and never
answers for a different request. It is a relay artifact for the #158 Devin
Adapter, not a policy engine: Action/Scope normalization and Judgment stay in
the shared CO modules. It is not yet integrated into that adapter; relayed
output is untested live, and no live integration may turn `allow` into an
approval without a trusted host that binds the exact actual target.

An optional "scope" object on a decision is carried through verbatim and
recorded in the audit record as the claim the Controller issued; it gates
nothing, because no claim this hook could check would make allow safe.

--record appends one JSONL audit line per event, including the relay outcome
(block/defer), whether a parsed decision was bound, the mismatched fields
plus the decision's own claimed target when binding failed, duplicate
consumption attempts with the prior claim, the decision's claimed Scope
verbatim, and the explicit defer_reason recorded for an unsupported allow —
so denied, spent and never-applied decisions stay traceable.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys


HOOK_EVENTS = {'PreToolUse', 'PermissionRequest'}
RESOLUTIONS = {'allow', 'deny', 'cancel'}
# Fields that pin a decision to one exact Native permission request.
BINDING_FIELDS = ('session_id', 'prompt_id', 'tool_name', 'tool_input')


def load_event(text):
    """Strictly validated hook payload; None defers rather than guessing."""
    try:
        event = json.loads(text)
    except ValueError:
        return None
    if not isinstance(event, dict):
        return None
    if event.get('hook_event_name') not in HOOK_EVENTS:
        return None
    if not isinstance(event.get('tool_name'), str) or not event['tool_name']:
        return None
    if not isinstance(event.get('tool_input'), dict):
        return None
    # session_id is documented on every hook payload and correlates the relay.
    if not isinstance(event.get('session_id'), str) or not event['session_id']:
        return None
    return event


def load_decision(path):
    """Controller resolution file; anything unreadable/unknown defers.

    A decision must carry the exact request it answers: nonempty session_id,
    prompt_id and tool_name plus the complete tool_input object. A decision
    without a full binding can never be applied — including deny — because the
    request it was issued for cannot be established. An optional "scope"
    object holds the target claims the Controller approved; it must be a dict
    and is preserved verbatim for audit — it gates nothing, since no claim
    the hook could check would make `allow` safe to relay.
    """
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get('resolution') not in RESOLUTIONS:
        return None
    reason = data.get('reason', '')
    if not isinstance(reason, str):
        return None
    for field in ('session_id', 'prompt_id', 'tool_name'):
        if not isinstance(data.get(field), str) or not data[field]:
            return None
    if not isinstance(data.get('tool_input'), dict):
        return None
    if 'scope' in data and not isinstance(data['scope'], dict):
        return None
    decision = {'resolution': data['resolution'], 'reason': reason,
                'session_id': data['session_id'], 'prompt_id': data['prompt_id'],
                'tool_name': data['tool_name'], 'tool_input': data['tool_input']}
    if 'scope' in data:
        decision['scope'] = data['scope']
    return decision


def mismatched_fields(event, decision):
    """Exact-request binding check; returns the differing field names."""
    return tuple(field for field in BINDING_FIELDS
                 if event.get(field) != decision[field])


def claim_decision(decision_path, event):
    """Atomically consume a bound decision; None when this call won the claim.

    The first caller to create `<realpath(decision-file)>.consumed` owns the
    decision. Resolving the path first anchors the marker to the decision
    itself, not to the spelling used to reach it: symlinks and other alias
    paths for the same decision share the one claim, so the same decision
    cannot be spent twice through different path names. Any later caller —
    same turn, same session, byte-identical request — gets a duplicate report
    with the prior claim for audit, and any other marker failure defers too:
    without the marker the one-time guarantee cannot be enforced, so nothing
    is relayed.
    """
    marker = Path(os.path.realpath(str(decision_path)) + '.consumed')
    claim = json.dumps({
        'consumed_at': datetime.now(timezone.utc).isoformat(),
        'session_id': event['session_id'],
        'prompt_id': event.get('prompt_id'),
        'tool_name': event['tool_name'],
        'tool_input': event['tool_input'],
    }, ensure_ascii=False).encode()
    try:
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        try:
            prior = json.loads(marker.read_text())
        except (OSError, ValueError):
            prior = None
        return {'duplicate': True, 'marker': str(marker), 'prior_claim': prior}
    except OSError as error:
        return {'duplicate': False, 'marker': str(marker),
                'error': f'{type(error).__name__}: {error}'}
    try:
        os.write(fd, claim)
    finally:
        os.close(fd)
    return None


def decide(event, decision, decision_path):
    """Map a bound, unspent Controller resolution to documented hook output.

    Returns (output, meta): output None = defer to the Native permission
    prompt; meta carries audit facts (duplicate consumption, defer reason).
    A decision that does not bind to this exact request (other session, other
    turn, other tool or target, stale prompt_id) is never applied — neither
    its allow nor its deny — and a bound decision is evaluated at most once.
    `allow` is never relayed: no trusted host binds this hook to the call's
    actual target, so an approval can never be proven to name the current
    operation. Only the restrictive resolutions produce output.
    """
    meta = {}
    if event is None or decision is None:
        return None, meta
    if mismatched_fields(event, decision):
        return None, meta
    # Bound to this exact request — spend it before relaying anything.
    claimed = claim_decision(decision_path, event)
    if claimed is not None:
        meta['consumed'] = claimed
        return None, meta
    if decision['resolution'] == 'allow':
        meta['defer_reason'] = 'allow_relay_unsupported'
        return None, meta
    reason = decision['reason']
    if decision['resolution'] == 'cancel':
        reason = f'cancel: {reason}' if reason else 'cancel'
    return {'decision': 'block', 'reason': reason}, meta


def audit_outcome(event, decision, output, meta):
    """Compact audit projection: what was relayed and why a decision was/wasn't."""
    record = {'outcome': output['decision'] if output else 'defer'}
    if decision is None:
        record['decision'] = None
    else:
        mismatched = mismatched_fields(event, decision)
        entry = {'resolution': decision['resolution'],
                 'bound': not mismatched,
                 'mismatched_fields': list(mismatched)}
        if mismatched:
            # Preserve which request the stale/foreign decision was issued for.
            entry['claimed_target'] = {
                'session_id': decision['session_id'],
                'prompt_id': decision['prompt_id'],
                'tool_name': decision['tool_name'],
                'tool_input': decision['tool_input'],
            }
        if 'scope' in decision:
            # The Controller's claim, verbatim: evidence, never a gate.
            entry['claimed_scope'] = decision['scope']
        if 'consumed' in meta:
            entry['consumed'] = meta['consumed']
        if 'defer_reason' in meta:
            entry['defer_reason'] = meta['defer_reason']
        record['decision'] = entry
    return record


def record_capture(path, event, outcome):
    """Append the captured call and relay outcome as JSONL; local file only."""
    line = json.dumps({
        'captured_at': datetime.now(timezone.utc).isoformat(),
        'hook_event_name': event['hook_event_name'],
        'tool_name': event['tool_name'],
        'tool_input': event['tool_input'],
        'session_id': event['session_id'],
        'prompt_id': event.get('prompt_id'),
        **audit_outcome(event, outcome['decision'], outcome['output'],
                        outcome['meta']),
    }, ensure_ascii=False)
    target = Path(path)
    with target.open('a') as stream:
        stream.write(line + '\n')
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--decision-file', type=Path,
                        help='JSON {"resolution": allow|deny|cancel, "reason", '
                             '"session_id", "prompt_id", "tool_name", '
                             '"tool_input", optional "scope"} bound to this '
                             'exact request; consumed once via an atomic '
                             '.consumed marker at the canonical path. allow '
                             'is unsupported and always defers')
    parser.add_argument('--record', type=Path,
                        help='append the captured call and outcome as one '
                             'JSONL audit line')
    args = parser.parse_args(argv)
    event = load_event(sys.stdin.read())
    decision = load_decision(args.decision_file) if args.decision_file else None
    output, meta = decide(event, decision, args.decision_file)
    if event is not None and args.record is not None:
        try:
            record_capture(args.record, event,
                           {'decision': decision, 'output': output,
                            'meta': meta})
        except OSError:
            pass  # Capture failure must never approve or block the action.
    if output is not None:
        print(json.dumps(output, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
