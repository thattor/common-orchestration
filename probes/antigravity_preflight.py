"""Current, read-only AGY 1.2.16 metadata for trusted host composition.

This is not a grant, qualification, credential reader, or default launcher.
Root must run the eventual host inside the returned settings-write protection
as well. Ordinary Native context remains trusted; this is not OS containment.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import time
from datetime import datetime, timezone

from co_v4.antigravity_host import _ordinary, HOOK_SHA, SKILL_SHA, ORCA_KEYS
from co_v4.antigravity_profiles import CURRENT_BINARY_SHA, AntigravityRouteProfile

PLAN_SHA = 'dac89e2bc7fa4312ffed5ec1ea44d3990adfc2db64e4c52fbee8bea71dc4b365'
FALLBACK_ENV = ('GEMINI_API_KEY', 'GOOGLE_API_KEY', 'AGY_API_KEY',
                'GOOGLE_GEMINI_BASE_URL')


def parse_config(text):
    rows = [line.split('\t', 1) for line in text.splitlines()]
    if any(len(row) != 2 for row in rows) or len({r[0] for r in rows}) != len(rows):
        raise ValueError('config metadata shape changed')
    values = dict(rows)
    required = {'useG1Credits': 'false', 'disableSlashCommands': 'false',
                'allowNonWorkspaceAccess': 'false', 'toolPermission': 'request-review',
                'modelProvider': '', 'customModelsConfig': '', 'gcp': ''}
    if any(values.get(key) != value for key, value in required.items()):
        raise ValueError('effective credits, slash, permission or provider gate failed')
    return {'credits_off': True, 'local_slash_enabled': True,
            'non_workspace_access': False, 'tool_permission': 'request-review',
            'provider_overrides_empty': True}


def parse_quota(text):
    observed = {}
    for line in text.splitlines():
        cells = line.split('\t')
        if len(cells) != 4 or cells[0] != 'Claude and GPT models':
            continue
        window = {'Weekly Limit Remaining': 'weekly',
                  'Five Hour Limit Remaining': 'five_hour'}.get(cells[1])
        if window is None or window in observed or not cells[2].endswith('%'):
            raise ValueError('quota metadata shape changed')
        try:
            percent = float(cells[2][:-1])
        except ValueError:
            raise ValueError('quota value invalid') from None
        if not 0 < percent <= 100:
            raise ValueError('quota unavailable or exhausted')
        observed[window] = percent
    if set(observed) != {'weekly', 'five_hour'}:
        raise ValueError('current Claude quota unknown')
    return observed


def protection(home):
    """Deny settings/config/trust and updater writes without changing settings."""
    # No user-supplied SB expressions or silent HOME remapping.
    if str(home) != os.environ.get('HOME') or '"' in str(home) or '\n' in str(home):
        raise ValueError('original HOME required')
    paths = (home / '.gemini/config', home / '.gemini/settings.json',
             home / '.gemini/trustedFolders.json', home / '.local/bin',
             home / '.gemini/antigravity-cli/updater',
             home / '.gemini/antigravity-cli/settings.json')
    return '(version 1)\n(allow default)\n(deny file-write* ' + ' '.join(
        '(subpath ' + json.dumps(str(p)) + ')' for p in paths) + ')\n'


def observe(executable, workspace, output, *, route_profile):
    """No inference: source-pinned local reports; fresh private host output only.

    1.2.16 printmode.run checks the persisted DisableSlashCommands field before
    local dispatch. A CLI false flag cannot override persisted true. Inspect the
    two effective config sources before sending any slash command, then require
    the actual /config report too. Parser failures never become launch approval.
    """
    if platform.system() != 'Darwin' or type(route_profile) is not AntigravityRouteProfile or route_profile.native_version != '1.2.16':
        raise ValueError('exact macOS current route required')
    executable, workspace, output = map(Path, (executable, workspace, output))
    if _ordinary(executable) != CURRENT_BINARY_SHA:
        raise ValueError('Native source changed')
    binary = executable.read_bytes()
    if hashlib.sha256(binary[0x327d910:0x327d910 + 3735]).hexdigest() != PLAN_SHA:
        raise ValueError('reviewed builtin plan body changed')
    home = Path(os.environ['HOME'])
    if any(os.environ.get(key) for key in (*FALLBACK_ENV, *ORCA_KEYS)):
        raise ValueError('fallback or hook effect environment present')
    settings = home / '.gemini/antigravity-cli/settings.json'
    user_config = home / '.gemini/config/config.json'
    config_hashes = {str(p): _ordinary(p, maximum=65536) for p in (settings, user_config)}
    saved = json.loads(settings.read_text())
    user = json.loads(user_config.read_text())
    if (type(saved) is not dict or type(user) is not dict
            or saved.get('disableSlashCommands', False) is not False
            or saved.get('useG1Credits', False) is not False
            or any(saved.get(k) for k in ('modelProvider', 'customModelsConfig', 'gcp'))
            or type(user.get('userSettings')) is not dict
            or set(user['userSettings']) - {'remoteControlHostname', 'themeMode'}
            or str(workspace) not in saved.get('trustedWorkspaces', [])):
        raise ValueError('existing local slash or trust source unknown')
    if (not workspace.is_absolute() or any(p.is_symlink() for p in (workspace, *workspace.parents))
            or stat.S_IMODE(workspace.stat().st_mode) != 0o700
            or workspace.stat().st_uid != os.getuid() or any(workspace.iterdir())):
        raise ValueError('existing approved empty workspace required')
    hook = home / '.orca/agent-hooks/antigravity-hook.sh'
    skill = home / '.gemini/antigravity-cli/skills/orx/SKILL.md'
    if _ordinary(hook, maximum=65536) != HOOK_SHA or _ordinary(skill, maximum=65536) != SKILL_SHA:
        raise ValueError('reviewed customization changed')
    if (not output.is_absolute() or any(p.is_symlink() for p in (output.parent, *output.parent.parents))
            or workspace == output or workspace in output.parents):
        raise ValueError('fresh host output outside worker required')
    output.mkdir(mode=0o700, exist_ok=False)
    sb = output / 'settings-protection.sb'
    sb.write_text(protection(home)); sb.chmod(0o600)
    reports = {}
    for command in ('/config', '/usage', '/skills', '/hooks', '/permissions', '/effort', 'models'):
        args = (['models'] if command == 'models' else
                ['--disable-slash-commands=false', '--model', route_profile.model,
                 '--effort', route_profile.effort, '--print-timeout', '30s',
                 '--output-format', 'text', '--print', command])
        # Regular-file output is polled and refused above 64 KiB; it can
        # overshoot between polls. This is not a filesystem size cap. No
        # retries, model prompt, interactive response or grant.
        with (output / (command.lstrip('/') + '.stdout')).open('xb') as stdout, (output / (command.lstrip('/') + '.stderr')).open('xb') as stderr:
            os.chmod(stdout.name, 0o600); os.chmod(stderr.name, 0o600)
            child = subprocess.Popen(['/usr/bin/sandbox-exec', '-f', str(sb), str(executable), *args],
                cwd=workspace, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                start_new_session=True)
            deadline = time.monotonic() + 40
            try:
                while child.poll() is None:
                    if (time.monotonic() > deadline or os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > 65536):
                        raise ValueError('metadata time or output bound exceeded')
                    time.sleep(.05)
                if child.wait(timeout=1) != 0:
                    raise ValueError('local metadata failed')
            finally:
                if child.poll() is None:
                    import signal
                    os.killpg(child.pid, signal.SIGTERM)
                    try: child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=3)
        data = Path(stdout.name).read_bytes()
        if len(data) + Path(stderr.name).stat().st_size > 65536:
            raise ValueError('metadata output bound exceeded')
        if command != 'models' and Path(stderr.name).stat().st_size:
            raise ValueError('local metadata stderr changed')
        reports[command] = data.decode('utf-8')
        if any(_ordinary(Path(p), maximum=65536) != h for p, h in config_hashes.items()):
            raise ValueError('effective config source changed')
    config = parse_config(reports['/config'])
    quota = parse_quota(reports['/usage'])
    if route_profile.model not in {line.split('\t')[0] for line in reports['models'].splitlines()}:
        raise ValueError('exact model not currently offered')
    if reports['/effort'].strip() != route_profile.effort:
        raise ValueError('local requested effort metadata differs')
    result = {'schema': 'co.agy.current-preflight.v1', 'model': route_profile.model,
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'preflight_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'requested_effort': route_profile.effort, 'effective_effort': 'unmeasured',
        'provider_turn_effort_verified': False, 'native_version': '1.2.16',
        'binary_sha256': CURRENT_BINARY_SHA, 'builtin_plan_body_sha256': PLAN_SHA,
        'config': config, 'quota_remaining_percent': quota,
        'report_sha256': {k: hashlib.sha256(v.encode()).hexdigest() for k, v in reports.items()},
        'settings_unchanged': True, 'model_turns': 0, 'new_grants': False,
        'qualified': False, 'settings_protection_sha256': hashlib.sha256(sb.read_bytes()).hexdigest()}
    (output / 'sanitized-preflight.json').write_text(json.dumps(result, indent=2) + '\n')
    (output / 'sanitized-preflight.json').chmod(0o600)
    return result
