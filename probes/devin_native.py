#!/usr/bin/env python3
"""Bounded Devin route observation probe; no CO runtime imports or model fallback.

Nested `devin` invocation is NOT attempted by default: in this sandboxed host the
CLI's rolling log appender cannot create its file under ~/.local/share/devin
(permission denied, panic exit 101; preserved in `historical_denials`). Pass
--allow-nested-cli on a permitted host to run bounded version checks. Everything
else is bundled-docs interface evidence plus reversible reachability
measurements: no credential contents are read, no auth/provider/permission or
sandbox setting is changed, no destructive action runs, no human is prompted.

Evidence discipline: keys other than `historical_*` are measured or observed in
THIS run only. Fixed observations recorded by the original 2026-09-28 run
(enclosing-session model, the SIGINT stop demonstration, live sandbox denials)
are kept immutable under `historical_*` with their own recorded date/source;
they are never re-stamped with this run's `observed_at`.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import tempfile


# Feature -> bundled docs file and required evidence markers. Docs presence is
# interface evidence only; it never proves interception or live control.
DOCS_SURFACE = {
    'action_capture': {
        'file': 'extensibility/hooks/lifecycle-hooks.mdx',
        'markers': ('PermissionRequest', 'PreToolUse', 'tool_input'),
    },
    'permission_rules': {
        'file': 'reference/permissions.mdx',
        'markers': ('Exec(', 'Write(', 'deny', 'ask'),
    },
    'confirmation_relay': {
        'file': 'extensibility/hooks/overview.mdx',
        'markers': ('"decision"', '"block"', '"approve"'),
    },
    'stop_request': {
        'file': 'essential-commands.mdx',
        'markers': ('Ctrl+C', 'cancel the running agent'),
    },
    'stop_confirmation': {
        'file': 'reference/otel.mdx',
        'markers': ('session_end', 'reason'),
    },
    'session_resume': {
        'file': 'essential-commands.mdx',
        'markers': ('--resume', '/resume <id>', '/ls'),
    },
    'programmatic_stdio': {
        'file': 'reference/commands.mdx',
        'markers': ('devin acp', 'JSON-RPC over stdin/stdout'),
    },
    'sandbox_isolation': {
        'file': 'sandbox.mdx',
        'markers': ('writable paths', 'refuse to start', 'excluded'),
    },
    'usage': {
        'file': 'reference/otel.mdx',
        'markers': ('devin.token.usage',),
    },
}

HISTORICAL_DENIALS = [
    {
        'when': '2026-09-28',
        'scope': 'nested devin CLI state/log write under ~/.local/share/devin',
        'evidence': ('devin auth status and devin list in linked worktree '
                     '/private/tmp/ai-company-03-156-devin-probe panicked rc=101: '
                     'tracing-appender rolling file appender InitError '
                     'PermissionDenied; the noninteractive request_scope for '
                     'that directory was denied in the first attempt'),
        'consequence': ('nested devin CLI cannot run inside this agent sandbox; '
                        'the top-level direct session remains the observation'),
    },
    {
        'when': '2026-09-28',
        'scope': ('git metadata write to outer repository gitdir '
                  '~/Documents/ai-company/repository/.git'),
        'evidence': ('a linked worktree resolved its gitdir outside the sandbox '
                     'and the noninteractive request_scope for it was denied'),
        'consequence': ('resolved by the changed isolation method: this checkout '
                        'keeps a self-contained .git inside the workspace'),
    },
    {
        'when': '2026-09-28',
        'scope': ('agent file-write tool creating probes/devin_native.py inside '
                  'the isolated clone workspace'),
        'evidence': ('a noninteractive write call inside '
                     '/private/tmp/ai-company-03-156-devin-shared was rejected '
                     'by the user/permission review'),
        'consequence': ('probe code ships via sandboxed exec heredocs; the '
                        'denied direct-write call is not retried'),
    },
]

# Fixed observations from the original 2026-09-28 run. Immutable reference
# only: a fresh probe run must NOT re-stamp these as freshly observed. This
# run's own measurements live under the non-historical report keys.
HISTORICAL_OBSERVATIONS = {
    'recorded_at': '2026-09-28',
    'source': ('original #156 probe run; preserved receipt '
               'design/0.3/records/156-devin-native.json'),
    'note': ('reference only - none of these were re-measured or re-observed '
             'in this run'),
    'session': {
        'requested_model': 'swe-2-high',
        'effective_model': 'swe-2-high',
        'effective_model_evidence': ('harness-declared session model; not '
                                     're-verified through the CLI'),
        'model_turn_submitted': True,
        'model_turn_evidence': ('that report was produced inside a live SWE-2 '
                                'High turn; the probe itself submits no model '
                                'turn'),
        'harness': ('OS-level exec sandbox: filesystem writes are confined '
                    'to the workspace plus granted scopes; unlisted '
                    'network domains trigger a user prompt; request_scope '
                    'exists for grants and was denied noninteractively in '
                    'the recorded attempts'),
        'approval_prompts': ('observed live through the denials preserved '
                             'in historical_denials; no prompt was answered '
                             'from inside the noninteractive session'),
        'stop': ('process-level cessation of a devin session observed via '
                 'SIGINT in a sibling attempt (agent child exited signal 2); '
                 'SessionEnd/OTEL cessation evidence is docs-declared only'),
        'resume': ('untested in-session; --resume/--continue and '
                   'devin list are docs-declared'),
        'confirmation_relay': ("untested in-session: that session's "
                               'permission prompts went to the harness '
                               'front-end, not to a CO adapter'),
    },
}

PROBE_FILENAME = '.co03-156-probe-write'


def run(argv, timeout=10, payload=None, env=None):
    """Timeout kills/waits for this process; no orphan model session is started."""
    try:
        p = subprocess.run(argv, input=payload, text=True, capture_output=True,
                           timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return None, '', 'probe deadline exceeded; child killed and reaped'


def sanitize(value):
    """Collapse the local home directory to ~ so the record stays portable."""
    if value is None:
        return None
    home = str(Path.home())
    text = str(value)
    if text == home:
        return '~'
    if text.startswith(home + os.sep):
        return '~' + text[len(home):]
    return text


def detect_versions(state_dir):
    """Read-only listing of installed versions; never opens credential files."""
    versions_dir = state_dir / 'cli' / '_versions'
    try:
        entries = sorted(p.name for p in versions_dir.iterdir())
    except (FileNotFoundError, NotADirectoryError):
        return {'state': 'absent', 'installed': [], 'current': None}
    except PermissionError:
        return {'state': 'unreadable', 'installed': [], 'current': None}
    installed = [name for name in entries
                 if name not in {'current', '_download', '_update.lock'}
                 and (versions_dir / name).is_dir()]
    current = None
    link = versions_dir / 'current'
    try:
        if link.is_symlink():
            current = os.readlink(link)
        elif link.exists():
            resolved = link.resolve()
            current = resolved.name if resolved.name != 'current' else None
    except OSError:
        current = 'unresolved'
    return {'state': 'listed', 'installed': installed, 'current': current}


def docs_evidence(docs_root):
    evidence = {}
    for feature, spec in DOCS_SURFACE.items():
        path = docs_root / spec['file']
        entry = {'file': spec['file'], 'evidence_kind': 'bundled_docs'}
        try:
            raw = path.read_bytes()
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            entry['declared'] = 'unknown'
            entry['markers'] = {m: False for m in spec['markers']}
            evidence[feature] = entry
            continue
        text = raw.decode('utf-8', errors='replace')
        entry['sha256'] = hashlib.sha256(raw).hexdigest()
        entry['markers'] = {m: (m in text) for m in spec['markers']}
        entry['declared'] = all(entry['markers'].values())
        evidence[feature] = entry
    return evidence


def fs_write_probe(target):
    """One exclusive-create attempt; removes the file if it unexpectedly lands."""
    try:
        with open(target, 'x') as stream:
            stream.write('co03-156 reachability probe\n')
    except PermissionError:
        return 'denied'
    except FileNotFoundError:
        return 'unreachable'
    except OSError as exc:
        return f'error:{exc.__class__.__name__}'
    try:
        target.unlink()
    except OSError:
        return 'allowed_cleanup_failed'
    return 'allowed_and_removed'


def network_probe(host='api.github.com', port=443, timeout=2.0):
    """Single TCP connect; nothing is sent. Classifies the outcome only."""
    try:
        conn = socket.create_connection((host, port), timeout=timeout)
    except PermissionError:
        return 'denied'
    except TimeoutError:
        return 'timeout'
    except ConnectionRefusedError:
        return 'refused'
    except OSError as exc:
        return f'error:{exc.__class__.__name__}'
    conn.close()
    return 'connected'


def existence(path):
    try:
        return 'present' if path.exists() else 'absent'
    except OSError:
        return 'unreadable'


def probe(root, state_dir=None, docs_root=None, allow_nested_cli=False,
          session_model=None):
    home = Path.home()
    state_dir = state_dir or home / '.local' / 'share' / 'devin'
    versions = detect_versions(state_dir)
    if docs_root is None:
        current = versions.get('current')
        if current and current != 'unresolved':
            docs_root = (state_dir / 'cli' / '_versions' / current
                         / 'share' / 'devin' / 'docs')
    cli = shutil.which('devin')
    report = {
        'schema_version': 2,
        'evidence_kind': 'bundled_docs_and_bounded_reachability_no_nested_cli',
        'observed_at': datetime.now(timezone.utc).isoformat(),
        # This run's observer context: only an explicit --session-model
        # declaration or a measurement taken now may fill these fields. The
        # 2026-09-28 session's model/turn claims stay in
        # historical_observations and are not restated here.
        'observer': ({
            'route': ('direct top-level Devin CLI session '
                      '(operator-declared for this run)'),
            'requested_model': session_model,
            'effective_model': session_model,
            'effective_model_evidence': ('operator-declared via '
                                         '--session-model for this run; not '
                                         're-verified through the CLI'),
            'model_turn_submitted': True,
            'model_turn_evidence': ('operator declared this report is produced '
                                    'inside a live turn of that model; the '
                                    'probe itself submits no model turn'),
        } if session_model else {
            'route': ('probe run without a declared enclosing session; '
                      'caller context unverified'),
            'requested_model': None,
            'effective_model': None,
            'effective_model_evidence': ('not measured in this run; the prior '
                                         'swe-2-high claim is preserved only '
                                         'under historical_observations'),
            'model_turn_submitted': None,
            'model_turn_evidence': ('the probe itself submits no model turn; '
                                    'no enclosing turn was declared for this '
                                    'run'),
        }),
        'cli_path': sanitize(cli),
        'cli_version': versions.get('current'),
        'cli_versions': versions,
        'bundled_docs_root': sanitize(docs_root) if docs_root else None,
        'nested_cli': {
            'invoked': False,
            'reason': ('noninteractive permission denials preserved in '
                       'historical_denials; without --allow-nested-cli only '
                       'docs and reachability are measured in this run'),
            'opt_in_flag': '--allow-nested-cli',
        },
        'execution_subject': ('current local user; existing Devin account '
                              'inferred from credentials file presence'),
        'auth_plan': 'unverified (devin auth status cannot run nested here)',
        'account_identity': 'not collected (unnecessary personal data)',
        'usage': None,
        'usage_note': ('no remaining-quota or rate-limit endpoint is documented; '
                       'devin.token.usage is an OTLP token counter and '
                       '/session-stats is interactive - neither yields '
                       'Usage.remaining_percent, so Adapter usage() stays empty'),
        'live_features': {
            'action_capture': ('documented_untested_this_run: '
                               'PermissionRequest/PreToolUse hooks and '
                               'Exec/Read/Write/Fetch permission rules are '
                               'docs-declared; this run measured only the '
                               'fs/network outcomes under reachability; '
                               'outer-session denials observed live are '
                               'historical_observations; spawned-worker '
                               'capture untested'),
            'confirmation_relay': ('untested: documented PermissionRequest hook '
                                   'decision output and the ACP stdio surface '
                                   'exist; no live worker confirmation '
                                   'round-trip ran'),
            'stop_request': ('historical_reference_only: SIGINT '
                             'termination of a sibling session was recorded '
                             '2026-09-28 (historical_observations.session.'
                             'stop) and is NOT re-measured by this run; '
                             'graceful in-flight cancel and child-process '
                             'cleanup untested'),
            'stop_confirmation': ('untested: SessionEnd hook and OTLP '
                                  'session_end with reason are docs-declared; '
                                  'no live cessation evidence captured'),
            'session_resume': ('documented_untested: --continue/--resume/'
                               'devin list are docs-declared; the summaries '
                               'dir existence under reachability is measured '
                               'this run; live resume cannot run nested '
                               'here'),
        },
        'declared_surface': {},
        'historical_observations': HISTORICAL_OBSERVATIONS,
        'environment': {
            'platform': f'{platform.system()} {platform.machine()}',
            'DEVIN_SANDBOX': os.environ.get('DEVIN_SANDBOX'),
            'DEVIN_MODEL': os.environ.get('DEVIN_MODEL'),
            'DEVIN_PERMISSION_MODE': os.environ.get('DEVIN_PERMISSION_MODE'),
            'env_finding': ('an inherited DEVIN_SANDBOX=1 breaks nested devin '
                            'CLI parsing (--sandbox expects true|false); a #158 '
                            'adapter spawning devin must scrub DEVIN_* vars '
                            'or pass valid values'),
        },
        'reachability': {},
        'historical_denials': HISTORICAL_DENIALS,
        'blocker': ('nested Devin CLI cannot run inside this sandboxed host '
                    '(state/log write under ~/.local/share/devin denied, '
                    'panic exit 101); action capture, confirmation relay, '
                    'graceful stop and session resume have no live guarantee '
                    'on this route'),
        'changes': ('probe-owned files only; no auth, provider, permission, '
                    'sandbox, installed CO or Stable changes'),
    }
    if docs_root is not None:
        report['declared_surface'] = docs_evidence(docs_root)
    else:
        report['declared_surface'] = {
            feature: {'file': spec['file'], 'declared': 'unknown',
                      'evidence_kind': 'bundled_docs'}
            for feature, spec in DOCS_SURFACE.items()}

    report['reachability'] = {
        'fs_workspace_write': fs_write_probe(Path(root) / PROBE_FILENAME),
        'fs_write_home': fs_write_probe(home / PROBE_FILENAME),
        'fs_write_devin_state_dir': fs_write_probe(state_dir / PROBE_FILENAME),
        'fs_write_user_config_dir': fs_write_probe(
            home / '.config' / 'devin' / PROBE_FILENAME),
        'fs_write_system_tmp': fs_write_probe(
            Path(tempfile.gettempdir()) / PROBE_FILENAME),
        'network_api_github_com_443': network_probe(),
        'credentials_file': existence(state_dir / 'credentials.toml'),
        'config_dir': existence(home / '.config' / 'devin'),
        'session_state_dir': existence(state_dir / 'summaries'),
        'credentials_note': ('existence checks only; credential contents are '
                             'never read or copied'),
        'control_store': ('worker filesystem/credential isolation and '
                          'approval-author impersonation remain unverified; '
                          'the protected CO state store is #157 work'),
        'routing_consequence': ('no control capability may be promoted from '
                                'this probe; Deny/Confirm targets that cannot '
                                'be intercepted need demonstrated '
                                'non-reachability instead'),
    }

    if allow_nested_cli and cli:
        # Minimal env scrub: an inherited DEVIN_SANDBOX=1 breaks --sandbox bool
        # parsing in the nested CLI. Only a bounded version lookup is attempted.
        env = dict(os.environ)
        env.pop('DEVIN_SANDBOX', None)
        env.pop('DEVIN_PERMISSION_MODE', None)
        rc, out, err = run([cli, 'version'], timeout=10, env=env)
        report['nested_cli'].update({
            'invoked': True,
            'version_exit_code': rc,
            'version_stdout_first_line': out.splitlines()[:1],
            'log_write_denied': ('rolling file appender' in err
                                 or 'PermissionDenied' in err),
        })
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-nested-cli', action='store_true',
                        help='run a bounded devin version check; off by default '
                             'because nested CLI is denied in this sandbox')
    parser.add_argument('--session-model', default=None,
                        help='model of the enclosing session running this probe '
                             'right now; omit when not running inside a '
                             'declared model turn so no stale claim is stamped')
    args = parser.parse_args()
    checkout = Path(__file__).resolve().parents[3]
    output = args.output.resolve()
    if not output.is_relative_to(checkout) or output.exists():
        parser.error('output must be a new file inside this checkout')
    private = checkout / '.orchestration-runs' / '156-devin-probe'
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(private, 0o700)
    result = probe(private, allow_nested_cli=args.allow_nested_cli,
                   session_model=args.session_model)
    with output.open('x') as stream:
        stream.write(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'output': str(output),
                      'nested_cli_invoked': result['nested_cli']['invoked']}))


if __name__ == '__main__':
    main()
