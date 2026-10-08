"""Short operator-owned observational lease for one newly created test terminal.

Root supplies the actual authorized creation operation, never a saved receipt
or a Worker ownership claim. No create/send/close command is implemented here.
Fresh show/read/show checks are observational, NOT atomic incarnation fencing.
"""
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time
from uuid import uuid4

from .orca_history import (HistoryRefused, MAX_BYTES, ORCA_VERSION, OwnedTerminal,
    OwnedTerminalHistory, ReadPlan)


def _deny(*args):
    raise HistoryRefused('creation_authority_unavailable')


def _label(value):
    try:
        return (type(value) is str and 0 < len(value.encode()) <= 1024
                and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    except UnicodeError:
        return False


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _envelope(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise ValueError()
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if (type(value) is not dict or set(value) != {'id', 'ok', 'result', '_meta'}
            or value['ok'] is not True or not _label(value['id'])
            or type(value['_meta']) is not dict or set(value['_meta']) != {'runtimeId'}
            or not _label(value['_meta']['runtimeId'])
            or type(value['result']) is not dict or set(value['result']) != {'terminal'}):
        raise ValueError()
    return value['_meta']['runtimeId'], value['result']['terminal']


@dataclass(frozen=True)
class CreationScope:
    """Nonsecret scope given to Root's creation capability; not authorization."""
    worktree_id: str = field(repr=False)
    title: str = field(repr=False)
    owner_ref: str = field(repr=False)
    workspace: str = field(repr=False)

    def __post_init__(self):
        if (not all(_label(v) for v in (self.worktree_id, self.title, self.owner_ref, self.workspace))
                or not Path(self.workspace).is_absolute()
                or self.worktree_id.split('::', 1)[-1] != self.workspace):
            raise HistoryRefused('creation_scope_invalid')


@dataclass(frozen=True)
class CleanupTarget:
    """Private exact target from the registry's fresh cleanup observation."""
    handle: str = field(repr=False)
    runtime_id: str = field(repr=False)
    pty_id: str = field(repr=False)
    incarnation_id: str = field(repr=False)
    worktree_id: str = field(repr=False)
    tab_id: str = field(repr=False)


class OrcaCliReader:
    """Bounded official CLI reader; no effects, shell, token reads or fallback.

    Trusted Root pins the selected executable's SHA and version. This pins the
    launcher, not a reproducible build of every app dependency. Native trust
    remains the adopted boundary. Constructing this object performs no I/O.
    """
    def __init__(self, executable, executable_sha256, *, cwd, timeout=10):
        if (type(executable) is not str or not Path(executable).is_absolute()
                or type(cwd) is not str or not Path(cwd).is_absolute()
                or type(executable_sha256) is not str
                or re.fullmatch('[0-9a-f]{64}', executable_sha256) is None
                or type(timeout) not in (int, float) or not 0 < timeout <= 30):
            raise HistoryRefused('cli_configuration_invalid')
        self._executable, self._sha, self._cwd, self._timeout = executable, executable_sha256, cwd, timeout
        self._handle = None

    def _run(self, arguments):
        process = None
        try:
            if hashlib.sha256(Path(self._executable).read_bytes()).hexdigest() != self._sha:
                raise ValueError()
            process = subprocess.Popen((self._executable, *arguments), shell=False,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=self._cwd, env=os.environ.copy())
            output = bytearray()
            error_bytes = 0
            deadline = time.monotonic() + self._timeout
            with selectors.DefaultSelector() as selector:
                for stream in (process.stdout, process.stderr):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise ValueError()
                    for key, _ in selector.select(min(left, 0.1)):
                        data = os.read(key.fileobj.fileno(), 16384)
                        if not data:
                            selector.unregister(key.fileobj)
                        elif key.fileobj is process.stdout:
                            output.extend(data)
                            if len(output) > MAX_BYTES:
                                raise ValueError()
                        else:
                            error_bytes += len(data)
                            if error_bytes > 65536:
                                raise ValueError()
            if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                raise ValueError()
            return bytes(output)
        except Exception:
            raise HistoryRefused('cli_read_unavailable') from None
        finally:
            if process is not None:
                if process.poll() is None:
                    try:
                        process.kill()  # Only this owned short-lived CLI process.
                    except OSError:
                        pass
                try:
                    process.wait(timeout=2)
                except (subprocess.TimeoutExpired, OSError):
                    pass
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass

    def admit(self):
        try:
            version = self._run(('--version',)).decode('utf-8').strip()
            if version not in (ORCA_VERSION, 'orca ' + ORCA_VERSION):
                raise ValueError()
        except Exception:
            raise HistoryRefused('cli_version_unverified') from None

    def bind(self, handle):
        if self._handle is not None or not _label(handle) or not handle.startswith('term_'):
            raise HistoryRefused('cli_binding_invalid')
        self._handle = handle

    def show(self):
        if self._handle is None:
            raise HistoryRefused('cli_unbound')
        return self._run(('terminal', 'show', '--terminal', self._handle, '--json'))

    def read(self, plan):
        if type(plan) is not ReadPlan or plan.binding.handle != self._handle:
            raise HistoryRefused('cli_read_unbound')
        # Revalidate at this independent subprocess boundary, before argv use.
        if (type(plan.cursor) is not str or re.fullmatch('0|[1-9][0-9]{0,15}', plan.cursor) is None
                or int(plan.cursor) > 2 ** 53 - 1 or type(plan.limit) is not int
                or not 1 <= plan.limit <= 1000):
            raise HistoryRefused('cli_read_unbound')
        return self._run(plan.arguments)


class RootTerminalRegistry:
    """Own one fresh test terminal's short observational lease, not its process.

    capture_creation(scope) is a trusted Root capability that performs the
    authorized dedicated-terminal creation and returns that invocation's JSON.
    It must not load a saved JSON receipt. Root owns cleanup even if capture or
    initial show fails. No restart/import/rebind path or automatic cleanup exists.
    """
    def __init__(self, reader, *, capture_creation=_deny, clock=time.monotonic, lease_seconds=120):
        if type(lease_seconds) not in (int, float) or not 0 < lease_seconds <= 300:
            raise HistoryRefused('lease_invalid')
        self._reader, self._capture, self._clock, self._duration = reader, capture_creation, clock, lease_seconds
        self._used = self._revoked = False
        self._binding = None
        self._identity = None
        self._expires = None
        self._phase = 'not_started'
        self._checks = {}

    def acquire(self, scope):
        if self._used or type(scope) is not CreationScope:
            raise HistoryRefused('registry_unavailable')
        self._used = True
        try:
            self._phase = 'admission'
            if self._capture is _deny or not Path(scope.workspace).is_dir():
                raise ValueError()
            # Version/read readiness precedes the effect owned by Root.
            self._reader.admit()
            self._phase = 'creation'
            runtime, receipt = _envelope(self._capture(scope))
            self._phase = 'creation_receipt'
            required = {'handle', 'ptyId', 'tabId', 'worktreeId', 'title'}
            allowed = required | {'paneKey', 'executionHostId', 'hostPlatform', 'surface',
                'processId', 'agentSessionDisposition', 'isReattach', 'warning', 'incarnationId', 'ptyId'}
            self._checks = {
                'schema_known': type(receipt) is dict and required <= set(receipt) and not set(receipt) - allowed,
                'surface_known': type(receipt) is dict and receipt.get('surface') in {'background', 'visible'},
                'scope_matches': type(receipt) is dict and receipt.get('worktreeId') == scope.worktree_id
                                 and receipt.get('title') == scope.title,
            }
            if (type(receipt) is not dict or not required <= set(receipt) or set(receipt) - allowed
                    or any(not _label(receipt[k]) for k in required)
                    or not receipt['handle'].startswith('term_')
                    or receipt['worktreeId'] != scope.worktree_id or receipt['title'] != scope.title
                    or 'isReattach' in receipt or 'agentSessionDisposition' in receipt
                    or 'warning' in receipt or receipt.get('surface') not in {'background', 'visible'}
                    or 'ptyId' in receipt and not _label(receipt['ptyId'])):
                raise ValueError()
            self._binding = OwnedTerminal(receipt['handle'], runtime, scope.owner_ref, uuid4().hex)
            self._identity = {k: receipt[k] for k in ('handle', 'ptyId', 'tabId', 'worktreeId')}
            self._reader.bind(receipt['handle'])
            self._expires = self._clock() + self._duration
            self._phase = 'initial_show'
            initial = self._show()
            incarnation = initial.get('incarnationId')
            self._checks.update(incarnation_present=_label(incarnation), pty_present=_label(initial.get('ptyId')))
            if (not _label(incarnation) or not _label(initial.get('ptyId')) or 'incarnationId' in receipt
                    and receipt['incarnationId'] != incarnation):
                raise ValueError()
            self._identity['incarnationId'] = incarnation
            self._identity['ptyId'] = initial['ptyId']
            self._identity['rendererGraphEpoch'] = initial['rendererGraphEpoch']
            self._phase = 'acquired'
            return OwnedTerminalHistory(self._binding, verify_owner=self.verify_owner, client=self._read)
        except Exception:
            self._revoked = True
            raise HistoryRefused('creation_or_identity_unverified') from None

    def _show(self, *, cleanup=False):
        if not cleanup and (self._revoked or self._expires is None or self._clock() >= self._expires):
            raise HistoryRefused('lease_inactive')
        runtime, current = _envelope(self._reader.show())
        known = {'handle', 'ptyId', 'incarnationId', 'orphaned', 'worktreeId', 'worktreePath',
            'branch', 'tabId', 'leafId', 'title', 'connected', 'writable', 'lastOutputAt',
            'preview', 'agentIdentity', 'exitCause', 'executionHostId', 'paneRuntimeId',
            'rendererGraphEpoch', 'agentWait'}
        self._checks = {'runtime_matches': runtime == self._binding.runtime_id,
            'schema_known': type(current) is dict and not set(current) - known,
            'identity_matches': type(current) is dict and all(current.get(k) == v for k,v in self._identity.items()),
            'connected': type(current) is dict and current.get('connected') is True,
            'writable': type(current) is dict and current.get('writable') is True,
            'not_orphaned': type(current) is dict and current.get('orphaned') is False,
            'epoch_known': type(current) is dict and type(current.get('rendererGraphEpoch')) is int}
        if (runtime != self._binding.runtime_id or type(current) is not dict
                or set(current) - known
                or any(current.get(k) != v for k, v in self._identity.items())
                or current.get('connected') is not True or current.get('writable') is not True
                or current.get('orphaned') is not False
                or type(current.get('rendererGraphEpoch')) is not int
                or current['rendererGraphEpoch'] < 0):
            raise HistoryRefused('terminal_identity_changed')
        return current

    def verify_owner(self, binding):
        try:
            self._phase = 'verify_owner'
            if binding is not self._binding:
                raise ValueError()
            self._show()
            if self._clock() >= self._expires:
                raise ValueError()
        except Exception:
            self._revoked = True
            raise HistoryRefused('lease_or_identity_unverified') from None

    def _read(self, plan):
        try:
            self._phase = 'read'
            if plan.binding is not self._binding or self._revoked or self._clock() >= self._expires:
                raise ValueError()
            raw = self._reader.read(plan)
            runtime, terminal = _envelope(raw)
            if (runtime != self._binding.runtime_id or type(terminal) is not dict
                    or terminal.get('handle') != self._binding.handle):
                raise ValueError()
            return raw
        except Exception:
            self._revoked = True
            raise HistoryRefused('read_identity_unverified') from None

    def revoke(self):
        """Revoke read authority; Root separately closes its exact test terminal."""
        self._revoked = True

    def cleanup_target(self):
        """Independent fresh cleanup check; never reopens revoked read authority."""
        try:
            self._phase = 'cleanup_show'
            if self._binding is None or not {'incarnationId', 'rendererGraphEpoch'} <= set(self._identity):
                raise ValueError()
            self._show(cleanup=True)
            return CleanupTarget(self._binding.handle, self._binding.runtime_id,
                self._identity['ptyId'], self._identity['incarnationId'],
                self._identity['worktreeId'], self._identity['tabId'])
        except Exception:
            raise HistoryRefused('cleanup_identity_unknown') from None

    def diagnostic(self):
        """Fixed phase/check labels and booleans only; never raw Native values."""
        return {'phase': self._phase, 'checks': dict(self._checks), 'revoked': self._revoked}
