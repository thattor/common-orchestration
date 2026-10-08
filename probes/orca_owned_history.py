"""Programmatic Root-operator probe; importing/running this file starts nothing.

Root provides genuine create and exact cleanup operation capabilities. No CLI
entry point enables effects. This verifies only one dedicated test terminal's
marker history and scoped cleanup, never Native/Controller completion.
"""
import json
import re
import shlex
import time

from co_v4.orca_history import HistoryRefused, MAX_BYTES
from co_v4.orca_history_host import CleanupTarget, CreationScope, RootTerminalRegistry


def creation_arguments(scope, marker):
    """Reviewable plan only. Orca's ordinary outer login shell still applies."""
    if (type(scope) is not CreationScope or type(marker) is not str
            or re.fullmatch('CO_ORCA_HISTORY_[0-9a-f]{32}', marker) is None):
        raise HistoryRefused('probe_scope_invalid')
    script = 'printf "%s\\n" ' + shlex.quote(marker) + '; exec /bin/sleep 120'
    command = '/bin/sh -c ' + shlex.quote(script)
    return ('terminal', 'create', '--worktree', 'id:' + scope.worktree_id,
            '--title', scope.title, '--command', command, '--json')


def _json(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise ValueError()
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError()
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def _cleanup_verified(binding, evidence):
    # Root's capability performs close, then exact show. No boolean receipt.
    if type(evidence) is not tuple or len(evidence) != 2:
        return False
    closed, absent = (_json(raw) for raw in evidence)
    close_valid = (type(closed) is dict and closed.get('ok') is True
        and set(closed) == {'id', 'ok', '_meta', 'result'}
        and closed.get('_meta') == {'runtimeId': binding.runtime_id}
        and type(closed.get('result')) is dict and set(closed['result']) == {'close'}
        and type(closed['result']['close']) is dict
        and not set(closed['result']['close']) - {'handle', 'tabId', 'closeMode', 'ptyKilled',
                                                'ptyStopVerdict', 'ptyStopReason'}
        and closed['result']['close'].get('handle') == binding.handle
        and type(binding) is CleanupTarget
        and closed['result']['close'].get('tabId') == binding.tab_id
        and closed['result']['close'].get('ptyKilled') is True
        and 'ptyStopVerdict' not in closed['result']['close'])
    if not close_valid or type(absent) is not dict or absent.get('_meta') != {'runtimeId': binding.runtime_id}:
        return False
    if absent.get('ok') is False:
        return (
        type(absent) is dict and absent.get('ok') is False
        and set(absent) == {'id', 'ok', '_meta', 'error'}
        and absent.get('_meta') == {'runtimeId': binding.runtime_id}
        and type(absent.get('error')) is dict
        and absent['error'].get('code') in {'selector_not_found', 'terminal_handle_stale'})
    if (type(binding) is not CleanupTarget or absent.get('ok') is not True
            or set(absent) != {'id', 'ok', '_meta', 'result'}
            or type(absent.get('result')) is not dict or set(absent['result']) != {'terminal'}):
        return False
    terminal = absent['result']['terminal']
    known = {'handle', 'ptyId', 'incarnationId', 'orphaned', 'worktreeId', 'worktreePath',
        'branch', 'tabId', 'leafId', 'title', 'connected', 'writable', 'lastOutputAt',
        'preview', 'agentIdentity', 'exitCause', 'executionHostId', 'paneRuntimeId',
        'rendererGraphEpoch', 'agentWait'}
    return (type(terminal) is dict and not set(terminal) - known
        and terminal.get('handle') == binding.handle and terminal.get('ptyId') == binding.pty_id
        and terminal.get('incarnationId') == binding.incarnation_id
        and terminal.get('worktreeId') == binding.worktree_id and terminal.get('tabId') == binding.tab_id
        and terminal.get('connected') is False and terminal.get('writable') is False
        and terminal.get('exitCause') == {'kind': 'operator_close'})


def run(scope, marker, *, reader, capture_creation, cleanup_owned):
    """Root only; cleanup callback must recheck exact show before exact close.

    capture_creation(scope) executes creation_arguments(scope, marker) on the
    selected CLI and returns its actual JSON bytes. cleanup_owned(binding)
    returns actual (close JSON, post-close exact-show JSON), preserving
    Root's operation provenance. Neither callback may load a saved snapshot.
    """
    creation_arguments(scope, marker)  # Validate before any operation.
    registry = RootTerminalRegistry(reader, capture_creation=capture_creation)
    report = {'scope': 'owned_test_terminal_history', 'history_ac': 'not_run',
              'cleanup': 'unconfirmed', 'native_completion': 'not_assessed',
              'line_count': 0, 'gap': None, 'atomic_fence': False,
              'failure_phase': None, 'refusal_code': None}
    try:
        history = registry.acquire(scope)
        for poll in range(5):
            page = history.read(history.plan(cursor='0', limit=1000))
            found = marker in page.tail
            complete_page = not (page.gap_before_page or page.truncated or page.limited)
            report.update(history_ac='pass' if found and complete_page else 'fail',
                          line_count=len(page.tail), gap=page.gap_before_page or page.truncated,
                          limited=page.limited, read_count=poll + 1)
            if found or not complete_page:
                break
            if poll < 4:
                time.sleep(0.1)  # Observe startup only; never resend the command.
    except HistoryRefused as error:
        known = {'creation_or_identity_unverified', 'owner_unverified', 'read_unavailable',
                 'response_invalid', 'plan_unbound', 'plan_pending', 'cursor_invalid', 'limit_invalid'}
        report.update(history_ac='blocked', failure_phase=registry.diagnostic()['phase'],
                      refusal_code=str(error) if str(error) in known else 'unclassified_refusal')
    except Exception:
        report['history_ac'] = 'blocked'
        report.update(failure_phase=registry.diagnostic()['phase'], refusal_code='unexpected_exception')
    finally:
        report['diagnostic'] = registry.diagnostic()
        try:
            binding = registry.cleanup_target()  # Fresh exact show or no close.
            evidence = cleanup_owned(binding)
            if _cleanup_verified(binding, evidence):
                report['cleanup'] = 'confirmed_owned_terminal'
        except Exception:
            pass
        registry.revoke()
    return report
