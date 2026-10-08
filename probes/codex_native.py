#!/usr/bin/env python3
"""Bounded direct Native bootstrap probe; no CO runtime imports or model fallback.

No model turn is submitted until the host can initialize. This first probe keeps
schema support separate from live control evidence. Follow-on live action tests
belong to #158 after the bootstrap/isolated control-store blocker is resolved.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


SCHEMAS = {
    'action_capture': 'CommandExecutionRequestApprovalParams.json',
    'confirmation_relay': 'CommandExecutionRequestApprovalResponse.json',
    'stop_request': 'v2/TurnInterruptParams.json',
    'stop_receipt': 'v2/TurnInterruptResponse.json',
    'resume': 'v2/ThreadResumeParams.json',
    'usage': 'v2/GetAccountRateLimitsResponse.json',
}


def run(argv, timeout=10, payload=None):
    """Timeout kills/waits for this process; no orphan model session is started."""
    try:
        p = subprocess.run(argv, input=payload, text=True, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return None, '', 'probe deadline exceeded; child killed and reaped'


def probe(root):
    cli = shutil.which('codex')
    report = {
        'schema_version': 1, 'evidence_kind': 'live_local_bootstrap_and_generated_schema',
        'observed_at': datetime.now(timezone.utc).isoformat(),
        'cli_path': cli, 'requested_model': 'gpt-6-astra',
        'effective_model': None, 'effective_effort': None,
        'model_turn_submitted': False,
        'execution_subject': 'current local user; existing Codex login',
        'account_identity': 'not collected (unnecessary personal data)',
        'usage': None,
        'live_features': {key: 'untested' for key in
                          ('action_capture', 'confirmation_relay', 'stop_request',
                           'stop_confirmation', 'session_resume')},
        'schema_support': {},
        'changes': 'probe-owned files only; no auth, provider, installed CO or Stable changes',
    }
    if not cli:
        report['blocker'] = 'codex executable unavailable'
        return report
    rc, out, _ = run([cli, '--version'])
    report['cli_version'] = out.strip() if rc == 0 else None
    rc, out, err = run([cli, 'login', 'status'])
    report['auth_mode'] = ('existing ChatGPT login' if rc == 0 and
                           'Logged in using ChatGPT' in out + err else 'not verified')
    # Output here is generated public protocol metadata, never credential data.
    with tempfile.TemporaryDirectory(prefix='codex-schema-', dir=root) as tmp:
        rc, _, _ = run([cli, 'app-server', 'generate-json-schema', '--out', tmp])
        report['schema_generation_exit_code'] = rc
        if rc == 0:
            for feature, name in SCHEMAS.items():
                path = Path(tmp) / name
                if path.exists():
                    raw = path.read_bytes()
                    schema = json.loads(raw)
                    report['schema_support'][feature] = {
                        'file': name, 'sha256': hashlib.sha256(raw).hexdigest(),
                        'required': schema.get('required', []),
                        'evidence_kind': 'generated_schema_only',
                    }
    payload = json.dumps({'id': 1, 'method': 'initialize', 'params': {
        'clientInfo': {'name': 'co03_contract_probe', 'version': '0.3.0-dev'}}}) + '\n'
    rc, out, err = run([cli, 'app-server', '--stdio'], timeout=8, payload=payload)
    report['bootstrap'] = {'exit_code': rc, 'initialize_response_seen': False,
                           'stdin_closed_after_initialize': True}
    for line in out.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get('id') == 1 and 'result' in event:
            report['bootstrap']['initialize_response_seen'] = True
    # Do not publish arbitrary stderr/stdout. Preserve only known non-secret
    # diagnostic classes; unknown output remains a precise collection gap.
    if 'failed to initialize sqlite state runtime' in err:
        report['blocker'] = ('app-server exited before initialize: failed to initialize sqlite '
                             'state runtime under the existing ~/.codex in this restricted sandbox')
    elif rc is None:
        report['blocker'] = 'app-server initialize timed out after 8 seconds; child killed and reaped'
    elif not report['bootstrap']['initialize_response_seen']:
        report['blocker'] = 'app-server produced no successful initialize response; inspect host locally'
    else:
        report['blocker'] = None
    report['stderr_diagnostics'] = {
        'path_alias_permission_denied': 'could not create PATH aliases' in err,
        'sqlite_initialization_failed': 'failed to initialize sqlite state runtime' in err,
    }
    report['reachability'] = {
        'worker_started': False,
        'credentials': 'ChatGPT login mode observed; credential contents never read/copied',
        'network': 'not probed by Native worker; no isolation guarantee',
        'filesystem': 'Native bootstrap observed; worker filesystem confinement untested',
        'control_store': 'worker isolation and approval-author impersonation remain unverified',
        'routing_consequence': 'no control capability may be promoted from this probe',
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    checkout = Path(__file__).resolve().parents[3]
    output = args.output.resolve()
    if not output.is_relative_to(checkout) or output.exists():
        parser.error('output must be a new file inside this checkout')
    private = checkout / '.orchestration-runs' / '156-codex-probe'
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(private, 0o700)
    result = probe(private)
    with output.open('x') as stream:
        stream.write(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'output': str(output), 'blocker': result.get('blocker')}))


if __name__ == '__main__':
    main()
