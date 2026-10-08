"""Exclusive task-owned Codex stdio broker for a scoped T3 host.

The trusted host runs this owner outside T3's process group, supplies a reviewed
executable/argv/environment and disables inherited tools/services. Socket clients
have no launch authority beyond that immutable allowlist. A projection, missing
PID, or JSON file is never a cessation oracle. Shared T3 servers cannot use this
owner. No provider login, settings edits, network connection or Native launch
occurs on import. This is not an OS sandbox or a general descendant supervisor.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
from uuid import uuid4

from .contracts import ExecuteRequest
from .state import body_digest
from .codex_host import DISABLED_FEATURES
from .codex_service_tier import subscription_gate

MAX_FRAME = 1024 * 1024
MAX_OUTPUT = 16 * MAX_FRAME


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _processes():
    # `comm` is the executable name, never argv. Retain only its basename for
    # observed owned descendants; no environment or credentials are inspected.
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,ppid=,pgid=,lstart=,comm='],
                            capture_output=True, text=True, timeout=2, check=True,
                            env={'PATH': os.defpath, 'LC_ALL': 'C'})
    rows = {}
    for line in result.stdout.splitlines():
        match = re.fullmatch(r'\s*(\d+)\s+(\d+)\s+(\d+)\s+'
            r'(\w{3} \w{3} [ \d]\d \d{2}:\d{2}:\d{2} \d{4})(?:\s+(.*))?', line)
        if match:
            pid, parent, group, birth, command = match.groups()
            rows[int(pid)] = (int(parent), int(group), birth, Path(command).name[:128] if command else 'unknown')
    return rows


def _same_birth(row, birth):
    # Parent/group may change during shutdown; neither proves process exit.
    return row is not None and row[2] == birth


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate Native JSON key')
        value[key] = item
    return value


def _read_exact(sock, length):
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise EOFError
        result.extend(chunk)
    return bytes(result)


def _receive(sock):
    header = _read_exact(sock, 5)
    length = struct.unpack('!I', header[1:])[0]
    if length > MAX_FRAME:
        raise ValueError('broker frame exceeds bound')
    return header[:1], _read_exact(sock, length)


def _send(sock, kind, raw):
    if len(raw) > MAX_FRAME:
        raise ValueError('broker frame exceeds bound')
    sock.sendall(kind + struct.pack('!I', len(raw)) + raw)


@dataclass(frozen=True)
class OwnedCessation:
    request_digest: str
    native_thread_id: str
    native_turn_id: str
    evidence_ref: str
    exit_code: int
    forced: bool
    native_completed: bool
    normal_completion: bool


class OwnedCodexBroker:
    """One host-owned experiment, metadata children and at most one model turn.

    ``root`` must be a new directory under a trusted private parent. ``env`` and
    ``argv_allowlist`` are supplied by trusted composition, never Worker input.
    A clean Native configuration without unmanaged helpers is required: any
    observed descendant leaving the owned process group disqualifies proof.
    All children are retained until finish/close; client death does not kill the
    broker or turn an unfinished drain into success. Lifecycle calls serialize
    with host dispatch; do not call finish until the corresponding T3 result.
    """
    def __init__(self, root, *, executable, argv_allowlist, env, cwd, timeout_seconds=180, t3_mcp_url=None, cleared_environment_keys=(), disabled_mcp_servers=()):
        if type(timeout_seconds) not in (int, float) or not 1 <= timeout_seconds <= 180:
            raise ValueError("bounded broker lifetime required")
        self._deadline = time.monotonic() + timeout_seconds
        if t3_mcp_url is not None:
            url = urlsplit(t3_mcp_url)
            if (url.scheme != 'http' or url.hostname not in ('127.0.0.1', 'localhost', '::1')
                    or url.port is None or url.path != '/mcp' or url.query or url.fragment
                    or url.username is not None or url.password is not None):
                raise ValueError('exact owned T3 MCP endpoint required')
        if (type(cleared_environment_keys) is not tuple or len(cleared_environment_keys) > 128
                or any(type(key) is not str or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', key)
                       for key in cleared_environment_keys)
                or len(set(cleared_environment_keys)) != len(cleared_environment_keys)):
            raise ValueError('exact cleared environment key inventory required')
        if (type(disabled_mcp_servers) is not tuple or len(disabled_mcp_servers) > 64
                or any(type(name) is not str or name == 't3-code'
                       or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', name) for name in disabled_mcp_servers)
                or len(set(disabled_mcp_servers)) != len(disabled_mcp_servers)):
            raise ValueError('exact disabled MCP inventory required')
        self.disabled_mcp_servers = disabled_mcp_servers
        self.cleared_environment_keys = cleared_environment_keys
        self.t3_mcp_url = t3_mcp_url
        self.root = Path(root)
        if not self.root.is_absolute() or self.root.exists() or self.root.parent.resolve() != self.root.parent:
            raise ValueError('new absolute broker root required')
        self.executable = str(Path(executable).resolve(strict=True))
        self.argv_allowlist = tuple(tuple(a) for a in argv_allowlist)
        if (not self.argv_allowlist or any(not a or not all(type(x) is str for x in a)
                                          for a in self.argv_allowlist)):
            raise ValueError('exact launch argv allowlist required')
        self.env = dict(env)
        # Minimal text experiment: no provider key, endpoint, header, proxy,
        # injected library or arbitrary credential variables reach the child.
        if (set(self.env) - {'HOME', 'CODEX_HOME', 'PATH', 'LANG', 'TMPDIR',
                'T3CODE_TELEMETRY_ENABLED', 'T3CODE_AUTO_BOOTSTRAP_PROJECT_FROM_CWD'}
                or any(type(k) is not str or type(v) is not str for k, v in self.env.items())):
            raise ValueError('scoped Native environment required')
        self.cwd = str(Path(cwd).resolve(strict=True))
        self._launch_digest = body_digest((self.executable, self.argv_allowlist, self.env, self.cwd, self.t3_mcp_url, self.cleared_environment_keys, self.disabled_mcp_servers))
        self._executable_digest = _digest(Path(self.executable).read_bytes())
        self._lock = threading.RLock()
        self._children = []
        self._closed = False
        self._armed = None
        self._selected = None
        self._thread_child = None
        self._failure = False
        self._proof = None
        self.root.mkdir(mode=0o700)
        self.socket_path = self.root / 'owner.sock'
        if len(os.fsencode(self.socket_path)) > 100:
            raise ValueError('broker socket path exceeds portable bound')
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._listener.bind(str(self.socket_path))
        except Exception:
            self._listener.close()
            raise
        os.chmod(self.socket_path, 0o600)
        self._listener.listen(8)
        self._listener.settimeout(.1)
        module_root = str(Path(__file__).resolve().parents[1])
        self.wrapper_path = self.root / 'codex-client'
        self.wrapper_path.write_text('#!' + sys.executable + ' -B\nimport sys\n'
            + 'sys.path.insert(0, ' + repr(module_root) + ')\n'
            + 'from co_v4.t3code_owned import client_main\n'
            + 'raise SystemExit(client_main(' + repr(str(self.socket_path)) + ', sys.argv[1:]))\n')
        self.wrapper_path.chmod(0o700)
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def arm(self, request, *, prompt, effort, service_tier):
        with self._lock:
            if (self._armed is not None or self._closed or type(request) is not ExecuteRequest
                    or request.conditions.workspace != self.cwd
                    or not isinstance(prompt, str) or not prompt or len(prompt.encode()) > MAX_FRAME
                    or not isinstance(effort, str) or not isinstance(service_tier, str)):
                raise ValueError('one exact owned request required')
            self._armed = (request, _digest(prompt.encode()), effort, service_tier)

    def _accept(self):
        while not self._closed:
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        child = None
        try:
            conn.settimeout(3)
            kind, raw = _receive(conn)
            args = json.loads(raw)
            with self._lock:
                if (self._closed or time.monotonic() >= self._deadline or kind != b'H' or type(args) is not list
                        or tuple(args) not in self.argv_allowlist or len(self._children) >= 16
                        or _digest(Path(self.executable).read_bytes()) != self._executable_digest
                        or body_digest((self.executable, self.argv_allowlist, self.env, self.cwd, self.t3_mcp_url, self.cleared_environment_keys, self.disabled_mcp_servers)) != self._launch_digest):
                    raise ValueError('unbound Native launch')
                process = subprocess.Popen([self.executable, *args], cwd=self.cwd, env=self.env,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                child = _Child(self, process, conn, args[0] == "app-server")
                self._children.append(child)
            child.run()
        except Exception:
            with self._lock:
                self._failure = True
            if child is not None:
                child.close_input()
        finally:
            if child is None:
                conn.close()

    def _admit_turn(self, child, params):
        with self._lock:
            if any(c.escaped for c in self._children):
                child.reject('owned_process_group_escape')
            if (self._armed is None or self._selected is not None or self._closed
                    or child.failed or not child.config_verified or not child.subscription_verified
                    or any(c.failed or c.escaped for c in self._children)):
                raise ValueError('unbound or repeated Native turn')
            request, prompt_hash, effort, tier = self._armed
            pieces = params.get('input')
            if (type(pieces) is not list or len(pieces) != 1 or type(pieces[0]) is not dict
                    or pieces[0].get('type') != 'text' or type(pieces[0].get('text')) is not str
                    or set(pieces[0]) - {'type', 'text', 'text_elements'}
                    or pieces[0].get('text_elements', []) != []
                    or _digest(pieces[0]['text'].encode()) != prompt_hash
                    or params.get('model') != request.conditions.model
                    or params.get('cwd') != self.cwd or params.get('effort') != effort
                    or params.get('serviceTier') != tier
                    or params.get('approvalsReviewer', 'user') != 'user'
                    or params.get('approvalPolicy') != 'untrusted'
                    or params.get('sandboxPolicy') != {'type': 'readOnly'}
                    or params.get('threadId') not in child.threads
                    or child.threads[params['threadId']] != (request.conditions.model, self.cwd)):
                raise ValueError('Native turn binding mismatch')
            self._selected = child
            child.thread_id = params['threadId']

    def finish(self, request, *, native_thread_id, native_turn_id, timeout=8):
        """Drain/reap owned children, then return a process-owned proof or None.

        Forced cessation may be proven but is never normal completion. Even a
        clean exit lacks proof when Native IDs, output/drain, or ownership differ.
        """
        if not 1 <= timeout <= 30:
            raise ValueError('bounded cleanup required')
        with self._lock:
            if self._armed is None or request != self._armed[0]:
                raise ValueError('cross-request cessation denied')
            selected = self._selected
        self.close(timeout=timeout)
        if selected is None:
            return None
        try:
            rows = _processes()
        except Exception:
            return None
        with self._lock:
            valid = (not self._failure and not selected.failed
                     and selected.thread_id == native_thread_id and selected.turn_id == native_turn_id
                     and bool(native_turn_id) and all(c.ceased(rows) for c in self._children))
            if not valid:
                return None
            self._proof = OwnedCessation(body_digest(request), native_thread_id, native_turn_id,
                't3-owned:' + body_digest((self._launch_digest, body_digest(request),
                    selected.process.pid, selected.birth, native_thread_id, native_turn_id)),
                selected.process.returncode, selected.forced, selected.completed,
                selected.completed and selected.process.returncode == 0 and not selected.forced)
            return self._proof

    def observation(self):
        """Sanitized audit only; callers cannot import this dictionary as proof."""
        with self._lock:
            return {'closed': self._closed, 'failed': self._failure,
                'request_digest': body_digest(self._armed[0]) if self._armed else None,
                'launch_digest': self._launch_digest,
                'children': [{'pid': c.process.pid, 'birth': c.birth, 'app_server': c.app_server,
                    'failed': c.failed, 'failure_phase': c.failure_phase, 'failure_code': c.failure_code,
                    'escaped_group': c.escaped, 'forced': c.forced,
                    'stdout_eof': c.stdout_eof, 'stderr_eof': c.stderr_eof,
                    'reaped': c.reaped, 'exit_code': c.process.returncode,
                    'native_thread_id': c.thread_id, 'native_turn_id': c.turn_id,
                    'native_completed': c.completed, 'config_verified': c.config_verified, 'input_shape': c.input_shape,
                    'registered_thread_count': len(c.threads), 'subscription_verified': c.subscription_verified,
                    'thread_mcp_denies_count': c.thread_mcp_denies_count,
                    'descendants': dict(c.descendants),
                    'descendant_metadata': {pid: dict(row) for pid, row in c.descendant_metadata.items()},
                    'done': c.done.is_set()} for c in self._children]}

    def verify_proof(self, proof, request):
        return (proof is not None and proof is self._proof and self._armed is not None
                and request == self._armed[0] and proof.request_digest == body_digest(request))

    def close(self, *, timeout=8):
        with self._lock:
            self._closed = True
            children = tuple(self._children)
        self._listener.close()
        self._thread.join(1)
        deadline = time.monotonic() + timeout
        for child in children:
            child.close_input()
        for child in children:
            child.finish(max(0, deadline - time.monotonic()))
        # Keep protected wrapper/evidence directory for audit, remove only socket.
        self.socket_path.unlink(missing_ok=True)


class _Child:
    def __init__(self, owner, process, conn, app_server):
        self.owner, self.process, self.conn = owner, process, conn
        self.app_server = app_server
        self.forwarding = True
        os.set_blocking(process.stdin.fileno(), False)
        self.lock = threading.RLock()
        self.send_lock = threading.Lock()
        self.input_lock = threading.Lock()
        self.birth = None
        self.descendants = {}
        self.descendant_metadata = {}
        self.escaped = self.failed = self.forced = self.completed = False
        self.failure_phase = self.failure_code = None
        self.incoming_ids = set()
        self.input_shape = None
        self.stdout_eof = self.stderr_eof = self.reaped = False
        self.thread_id = self.turn_id = None
        self.requests, self.threads = {}, {}
        self.config_verified = False
        self.thread_mcp_denies_count = 0
        self.subscription_verified = False
        self.account_id = self.usage_id = None
        self.account_ready, self.usage_ready = threading.Event(), threading.Event()
        self.account_projection = self.usage_projection = None
        self.config_id = None
        self.config_ready = threading.Event()
        self.output_bytes = 0
        self.output_buffer = b''
        self.readers = []
        self.done = threading.Event()
        try:
            self.observe()
        except Exception:
            self.failed = True

    def observe(self):
        rows = _processes()
        row = rows.get(self.process.pid)
        if self.birth is None and row is not None:
            self.birth = row[2]
        owned = {self.process.pid} | {pid for pid, birth in self.descendants.items()
                                      if _same_birth(rows.get(pid), birth)}
        for _ in rows:
            extra = {pid for pid, row in rows.items() if row[0] in owned}
            if extra <= owned:
                break
            owned |= extra
        for pid in owned - {self.process.pid}:
            row = rows.get(pid)
            if row:
                self.descendants[pid] = row[2]
                metadata = self.descendant_metadata.setdefault(pid, {'birth': row[2],
                    'first_ppid': row[0], 'first_pgid': row[1],
                    'input_method': self.input_shape.get('method') if self.input_shape else None})
                metadata.update(ppid=row[0], pgid=row[1], executable=row[3])
                if row[1] != self.process.pid:
                    self.escaped = True
        return rows

    def emit(self, kind, raw):
        if not self.forwarding:
            return
        try:
            with self.send_lock:
                data = kind + struct.pack('!I', len(raw)) + raw
                deadline = time.monotonic() + 1
                while data:
                    if not select.select([], [self.conn], [], max(0, deadline - time.monotonic()))[1]:
                        self.failed = True
                        raise TimeoutError
                    sent = self.conn.send(data, socket.MSG_DONTWAIT)
                    data = data[sent:]
        except OSError:
            self.forwarding = False  # Keep draining after client death.

    def check_config(self, result):
        config = result.get('config') if type(result) is dict else None
        if type(config) is not dict:
            raise ValueError('effective Native config missing')
        # rust-v0.159.2 Config defaults to openai; only a configured openai
        # definition or top-level endpoint override changes that selected route.
        providers = config.get('model_providers')
        if (config.get('model_provider') not in (None, 'openai')
                or type(providers) not in (dict, type(None))
                or (type(providers) is dict and providers.get('openai') not in (None, {}))
                or config.get('openai_base_url') is not None
                or config.get('chatgpt_base_url') not in (None, 'https://chatgpt.com/backend-api/')
                or config.get('forced_login_method') not in (None, 'chatgpt')):
            self.fail('config', 'config_selected_provider_route')
            raise ValueError('stock OpenAI route unverified')
        servers = config.get('mcp_servers')
        features = config.get('features', {})
        policy = config.get('shell_environment_policy', {})
        checks = (
            ('config_mcp_map', isinstance(servers, (dict, type(None)))),
            ('config_features_shape', type(features) is dict),
            ('config_notify', config.get('notify') in (None, [])),
            ('config_web_search', config.get('web_search') == 'disabled'),
            ('config_shell_environment', type(policy) is dict and policy.get('inherit') == 'none'
                and policy.get('include_only') == [] and self.empty_environment(policy.get('set'))),
        )
        for code, valid in checks:
            if not valid:
                self.fail('config', code)
                raise ValueError('effective Native isolation unverified')
        # Codex rust-v0.159.2 shell_snapshot.rs launches a new-session shell;
        # forbid that feature before creating a Native thread, not only a turn.
        for name in (*DISABLED_FEATURES, 'remote_control', 'shell_snapshot'):
            if features.get(name) is not False:
                self.fail('config', 'config_feature_' + name)
                raise ValueError('effective Native feature unverified')
        if 't3-code' in (servers or {}) or set(servers or {}) != set(self.owner.disabled_mcp_servers):
            self.fail('config', 'config_mcp_inventory_mismatch')
            raise ValueError('effective MCP inventory mismatch')
        for name, entry in (servers or {}).items():
            if type(entry) is not dict:
                raise ValueError('invalid Native MCP setting')
            if entry.get('enabled') is False:
                continue
            if (name != 't3-code' or set(entry) - {'url', 'http_headers', 'enabled'}
                    or entry.get('url') != self.owner.t3_mcp_url or self.owner.t3_mcp_url is None):
                raise ValueError('unmanaged Native MCP setting')
            url = urlsplit(entry.get('url', ''))
            if (url.scheme != 'http' or url.hostname not in ('127.0.0.1', 'localhost', '::1')
                    or url.username is not None or url.password is not None or url.port is None):
                raise ValueError('nonlocal T3 MCP setting')
        self.config_verified = True

    def empty_environment(self, values):
        # Same normalization as CodexReadOnlyHost: TOML {} merges inherited
        # keys, so only inventoried keys explicitly neutralized to '' qualify.
        return values is None or (type(values) is dict and all(
            key in self.owner.cleared_environment_keys and type(value) is str and value == ''
            for key, value in values.items()))

    def write_native(self, raw):
        with self.input_lock:
            deadline = time.monotonic() + 2
            while raw:
                if not select.select([], [self.process.stdin], [], max(0, deadline - time.monotonic()))[1]:
                    raise TimeoutError('Native input blocked')
                raw = raw[os.write(self.process.stdin.fileno(), raw):]

    def prepare_thread_wire(self, message):
        owner = self.owner
        if body_digest((owner.executable, owner.argv_allowlist, owner.env, owner.cwd,
                owner.t3_mcp_url, owner.cleared_environment_keys, owner.disabled_mcp_servers)) != owner._launch_digest:
            self.reject('launch_binding_changed')
        config = message['params']['config']
        if 'mcp_servers' in config:
            # Native 0.159.2 app-server config_manager chains request overrides
            # after CLI; overrides.rs replaces the whole runtime MCP table.
            # Preserve T3's local entry and restore only the trusted denies.
            servers = {name: {'enabled': False} for name in owner.disabled_mcp_servers}
            servers.update(config['mcp_servers'])
            self.thread_mcp_denies_count = len(owner.disabled_mcp_servers)
            message = {**message, 'params': {**message['params'], 'config': {**config, 'mcp_servers': servers}}}
        raw = json.dumps(message, separators=(',', ':')).encode() + b'\n'
        if len(raw) > MAX_FRAME:
            self.reject('thread_forward_frame_limit')
        return raw

    def preflight(self):
        if self.config_id is not None:
            raise ValueError('repeated Native preflight')
        self.config_id = 'co-owned-config-' + uuid4().hex
        self.write_native((json.dumps({'id': self.config_id, 'method': 'config/read',
            'params': {'cwd': self.owner.cwd, 'includeLayers': False}}) + '\n').encode())
        if not self.config_ready.wait(5):
            self.fail('config', 'config_response_timeout')
        if not self.config_verified or self.failed:
            self.fail('config', 'config_unverified')
            raise ValueError('effective Native configuration unverified')
        self.account_id, self.usage_id = 'co-owned-account-' + uuid4().hex, 'co-owned-usage-' + uuid4().hex
        for identity, method, params, ready in (
                (self.account_id, 'account/read', {}, self.account_ready),
                (self.usage_id, 'account/rateLimits/read', None, self.usage_ready)):
            self.write_native((json.dumps({'id': identity, 'method': method, 'params': params}) + '\n').encode())
            if not ready.wait(5) or self.failed:
                self.fail('subscription', 'subscription_response_unverified')
                raise ValueError('same-child subscription response unverified')
        try:
            subscription_gate(self.account_projection, self.usage_projection, api_environment_absent=True)
            self.subscription_verified = True
        except Exception:
            self.fail('subscription', 'included_subscription_usage_unverified')
            raise ValueError('same-child subscription unverified') from None
        finally:
            self.account_projection = self.usage_projection = None

    def fail(self, phase, code):
        self.failed = True
        if self.failure_code is None:
            self.failure_phase, self.failure_code = phase, code

    def reject(self, code):
        self.fail('input', code)
        raise ValueError('scoped Native protocol refused')

    def validate_thread_start(self, params):
        with self.owner._lock:
            armed = self.owner._armed
            if (armed is None or self.owner._thread_child is not None
                    or set(params) != {'model', 'cwd', 'config'}
                    or params.get('model') != armed[0].conditions.model
                    or params.get('cwd') != self.owner.cwd):
                self.reject('thread_start_binding')
            config = params['config']
            if (type(config) is not dict or set(config) - {'tools.update_plan.enabled', 'mcp_servers'}
                    or config.get('tools.update_plan.enabled') is not True):
                self.reject('thread_config_layer')
            if 'mcp_servers' in config:
                servers = config['mcp_servers']
                entry = servers.get('t3-code') if type(servers) is dict else None
                if (type(servers) is not dict or set(servers) != {'t3-code'}
                        or type(entry) is not dict or set(entry) != {'url', 'http_headers'}
                        or self.owner.t3_mcp_url is None or entry['url'] != self.owner.t3_mcp_url
                        or type(entry['http_headers']) is not dict
                        or set(entry['http_headers']) != {'Authorization'}):
                    self.reject('thread_mcp_binding')
                token = entry['http_headers']['Authorization']
                if (type(token) is not str or not token.startswith('Bearer ') or not token[7:]
                        or len(token) > 8192 or any(ch.isspace() for ch in token[7:])):
                    self.reject('thread_mcp_credential_shape')
            self.owner._thread_child = self

    def record_input_shape(self, message):
        if type(message) is not dict:
            self.input_shape = {'frame_type': type(message).__name__}
            return
        allowed_methods = {'initialize', 'initialized', 'account/read', 'account/rateLimits/read',
            'skills/list', 'model/list', 'thread/start', 'thread/read', 'thread/unsubscribe',
            'turn/start', 'turn/interrupt'}
        allowed_keys = {'clientInfo', 'capabilities', 'cwds', 'cursor', 'model', 'cwd', 'config',
            'threadId', 'turnId', 'includeTurns', 'effort', 'serviceTier', 'approvalPolicy',
            'approvalsReviewer', 'sandboxPolicy', 'input', 'summary', 'additionalContext', 'collaborationMode'}
        method, params = message.get('method'), message.get('params')
        self.input_shape = {
            'method': method if type(method) is str and method in allowed_methods else 'unknown',
            'params_type': type(params).__name__,
            'known_fields': {key: type(value).__name__ for key, value in params.items() if key in allowed_keys}
                if type(params) is dict else {},
            'unknown_field_count': sum(key not in allowed_keys for key in params) if type(params) is dict else 0,
        }

    def validate_incoming(self, message, method, params):
        # A text-only experiment never approves a server tool request. Even a
        # well-formed response cannot be smuggled through this channel.
        if (type(method) is not str or set(message) - {'jsonrpc', 'id', 'method', 'params'}
                or message.get('jsonrpc', '2.0') != '2.0'):
            self.reject('rpc_or_approval_response')
        if method == 'initialized':
            if 'id' in message or params not in ({}, None):
                self.reject('initialized_shape')
            return
        identity = message.get('id')
        if type(identity) not in (str, int) or str(identity) in self.incoming_ids or len(self.incoming_ids) >= 256:
            self.reject('rpc_identity_or_limit')
        self.incoming_ids.add(str(identity))
        if method == 'account/rateLimits/read':
            if params is not None:
                self.reject('rate_limits_shape')
            return
        if type(params) is not dict:
            self.reject('parameters_shape')
        if method == 'initialize':
            info, caps = params.get('clientInfo'), params.get('capabilities')
            if (set(params) != {'clientInfo', 'capabilities'} or type(info) is not dict
                    or info != {'name': 'T3 Code', 'title': 'T3 Code', 'version': '0.0.45'}
                    or caps not in ({'experimentalApi': True},
                                    {'experimentalApi': True, 'optOutNotificationMethods': ['turn/diff/updated']})):
                self.reject('initialize_source_binding')
        elif method == 'account/read':
            if params != {}:
                self.reject('account_read_shape')
        elif method == 'skills/list':
            if params != {'cwds': [self.owner.cwd]}:
                self.reject('skills_workspace_binding')
        elif method == 'model/list':
            if params != {} and (set(params) != {'cursor'} or type(params['cursor']) is not str
                                 or not 0 < len(params['cursor']) <= 1024):
                self.reject('model_list_shape')
        elif method == 'thread/start':
            self.validate_thread_start(params)
        elif method == 'turn/start':
            allowed = {'threadId', 'model', 'cwd', 'effort', 'serviceTier', 'approvalPolicy',
                'approvalsReviewer', 'sandboxPolicy', 'input', 'summary', 'additionalContext', 'collaborationMode'}
            if set(params) - allowed or params.get('summary', 'detailed') != 'detailed':
                self.reject('turn_control_fields')
            collaboration = params.get('collaborationMode')
            if collaboration is not None:
                settings = collaboration.get('settings') if type(collaboration) is dict else None
                if (type(collaboration) is not dict or set(collaboration) != {'mode', 'settings'}
                        or collaboration['mode'] != 'default' or type(settings) is not dict
                        or set(settings) - {'model', 'reasoning_effort', 'developer_instructions'}
                        or settings.get('model') != params.get('model')
                        or settings.get('reasoning_effort') != params.get('effort')):
                    self.reject('turn_collaboration_policy')
            self.owner._admit_turn(self, params)
        elif method in ('thread/read', 'thread/unsubscribe', 'turn/interrupt'):
            if params.get('threadId') not in self.threads:
                self.reject('control_thread_binding')
            if method == 'thread/read' and (set(params) != {'threadId', 'includeTurns'}
                                           or type(params['includeTurns']) is not bool):
                self.reject('thread_read_shape')
            if method == 'thread/unsubscribe' and set(params) != {'threadId'}:
                self.reject('unsubscribe_shape')
            if method == 'turn/interrupt' and (set(params) != {'threadId', 'turnId'}
                                             or params['turnId'] != self.turn_id or not self.turn_id):
                self.reject('interrupt_binding')
        else:
            self.reject('unknown_rpc')

    def inspect(self, message, incoming):
        if type(message) is not dict:
            raise ValueError('invalid Native frame')
        method, params = message.get('method'), message.get('params', {})
        if incoming:
            self.validate_incoming(message, method, params)
            if method in ('thread/start', 'turn/start'):
                key = str(message.get('id'))
                if key in self.requests:
                    raise ValueError('duplicate Native request identity')
                self.requests[key] = (method, params.get('model'), params.get('cwd'))
        else:
            if type(params) is not dict:
                raise ValueError('invalid Native notification parameters')
            if self.config_id is not None and message.get('id') == self.config_id:
                try:
                    if self.config_ready.is_set():
                        raise ValueError('duplicate owned config response')
                    self.check_config(message.get('result'))
                except Exception:
                    self.fail('config', 'config_invalid_response')
                self.config_ready.set()
                return False
            if message.get('id') in (self.account_id, self.usage_id) and message.get('id') is not None:
                account_reply = message['id'] == self.account_id
                ready = self.account_ready if account_reply else self.usage_ready
                result = message.get('result')
                if ready.is_set() or type(result) is not dict:
                    self.fail('subscription', 'subscription_invalid_response')
                elif account_reply:
                    account = result.get('account')
                    self.account_projection = {'requiresOpenaiAuth': result.get('requiresOpenaiAuth'),
                        'account': {key: account.get(key) for key in ('type', 'planType')}
                            if type(account) is dict else None}
                else:
                    self.usage_projection = {'ordinaryUsageAllowed': result.get('ordinaryUsageAllowed'),
                        'rateLimits': {} if type(result.get('rateLimits')) is dict else None}
                ready.set()
                return False
            if method == 'mcpServer/startupStatus/updated' and params.get('name') != 't3-code':
                self.failed = True
            if method in ('thread/started', 'turn/started') and self.thread_id is not None:
                announced = params.get('threadId', params.get('thread', {}).get('id'))
                if announced not in (None, self.thread_id):
                    self.failed = True
            key = str(message.get('id'))
            if 'method' not in message and key in self.requests:
                kind, model, cwd = self.requests.pop(key)
                result = message.get('result')
                field = 'thread' if kind == 'thread/start' else 'turn'
                native = result.get(field) if type(result) is dict else None
                if type(native) is not dict or type(native.get('id')) is not str or not native['id']:
                    raise ValueError('Native response identity missing')
                if field == 'thread':
                    if result.get('modelProvider') != 'openai':
                        self.fail('output', 'thread_selected_provider')
                        raise ValueError('Native provider route mismatch')
                    if result.get('model') != model or result.get('cwd') != cwd:
                        raise ValueError('Native effective thread mismatch')
                    self.threads[native['id']] = (model, cwd)
                else:
                    if self.turn_id is not None:
                        raise ValueError('Native turn identity changed')
                    self.turn_id = native['id']
            if method in ('item/started', 'item/completed'):
                item = params.get('item', {})
                if item.get('type') not in ('userMessage', 'agentMessage', 'reasoning', 'plan'):
                    self.failed = True
            if method == 'turn/completed':
                turn = params.get('turn', {})
                if (params.get('threadId') != self.thread_id or turn.get('id') != self.turn_id
                        or turn.get('status') != 'completed' or turn.get('error') is not None):
                    self.failed = True
                else:
                    self.completed = True
        return True

    def reader(self, pipe, kind):
        try:
            while raw := os.read(pipe.fileno(), 65536):
                forward = raw
                with self.lock:
                    self.output_bytes += len(raw)
                    if self.output_bytes > MAX_OUTPUT:
                        self.failed = True
                        raise ValueError('Native output limit')
                    if kind == b'O' and self.app_server:
                        forward = b''
                        self.output_buffer += raw
                        if len(self.output_buffer) > MAX_FRAME:
                            raise ValueError('Native line limit')
                        while b'\n' in self.output_buffer:
                            line, self.output_buffer = self.output_buffer.split(b'\n', 1)
                            if self.inspect(json.loads(line, object_pairs_hook=_pairs), False):
                                forward += line + b'\n'
                if forward:
                    self.emit(kind, forward)
            with self.lock:
                if kind == b'O':
                    self.stdout_eof = True
                    if self.output_buffer:
                        self.failed = True
                else:
                    self.stderr_eof = True
        except Exception:
            self.fail('output', 'invalid_or_unbounded_native_output')
        finally:
            pipe.close()

    def close_input(self):
        with self.input_lock:
            if not self.process.stdin.closed:
                self.process.stdin.close()

    def input(self):
        buffer = b''
        try:
            while True:
                kind, raw = _receive(self.conn)
                if kind == b'C':
                    break
                if kind != b'I':
                    raise ValueError('invalid broker input')
                buffer += raw
                if len(buffer) > MAX_FRAME:
                    raise ValueError('Native input limit')
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    message = json.loads(line, object_pairs_hook=_pairs)
                    self.record_input_shape(message)
                    with self.lock:
                        self.inspect(message, True)
                    # Check process-global isolation before thread creation can
                    # start helpers. Reviewed thread overrides cannot undo it.
                    if message.get('method') == 'thread/start':
                        self.preflight()
                        self.write_native(self.prepare_thread_wire(message))
                    else:
                        self.write_native(line + b'\n')
            if buffer:
                self.failed = True
        except EOFError:
            if buffer:
                self.failed = True
        except OSError:
            if buffer:
                self.failed = True
        except Exception:
            self.fail('input', 'invalid_or_unbound_native_input')
        finally:
            self.close_input()

    def run(self):
        # Independent read/write threads preserve full duplex flow and drain after
        # T3 kills its client. The process owner is never inside T3's scope.
        self.conn.settimeout(None)
        for pipe, kind in ((self.process.stdout, b'O'), (self.process.stderr, b'E')):
            thread = threading.Thread(target=self.reader, args=(pipe, kind), daemon=True)
            self.readers.append(thread)
            thread.start()
        input_thread = threading.Thread(target=self.input, daemon=True)
        input_thread.start()
        timed_out_at = None
        try:
            while self.process.poll() is None:
                rows = self.observe()
                if time.monotonic() >= self.owner._deadline:
                    self.failed = self.forced = True
                    self.close_input()
                    if _same_birth(rows.get(self.process.pid), self.birth):
                        if timed_out_at is None:
                            timed_out_at = time.monotonic()
                            os.killpg(self.process.pid, signal.SIGTERM)
                        elif time.monotonic() - timed_out_at >= 1:
                            os.killpg(self.process.pid, signal.SIGKILL)
                time.sleep(.1)
            self.process.wait()
            self.reaped = True
        except Exception:
            self.failed = True
        finally:
            for thread in self.readers:
                thread.join(2)
            if self.reaped:
                self.emit(b'X', str(self.process.returncode).encode())
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.conn.close()
            input_thread.join(2)
            if input_thread.is_alive():
                self.failed = True
            self.done.set()

    def finish(self, timeout):
        until = time.monotonic() + timeout
        if self.done.wait(min(1, timeout)):
            return
        self.forced = True
        try:
            rows = self.observe()
            if self.process.poll() is None and _same_birth(rows.get(self.process.pid), self.birth):
                os.killpg(self.process.pid, signal.SIGTERM)
            if not self.done.wait(max(0, min(1, until - time.monotonic()))):
                rows = self.observe()
                if self.process.poll() is None and _same_birth(rows.get(self.process.pid), self.birth):
                    os.killpg(self.process.pid, signal.SIGKILL)
                self.done.wait(max(0, until - time.monotonic()))
        except Exception:
            self.failed = True

    def ceased(self, rows):
        return (self.birth is not None and self.reaped and self.done.is_set()
                and self.stdout_eof and self.stderr_eof and not self.failed and not self.escaped
                and not _same_birth(rows.get(self.process.pid), self.birth)
                and not any(row[1] == self.process.pid for row in rows.values())
                and all(not _same_birth(rows.get(pid), birth) for pid, birth in self.descendants.items()))


def client_main(socket_path, argv):
    """Transparent disposable T3 child; owns no Native process or proof."""
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.connect(socket_path)
    _send(conn, b'H', json.dumps(argv).encode())
    def forward():
        try:
            while raw := os.read(sys.stdin.fileno(), 65536):
                _send(conn, b'I', raw)
            _send(conn, b'C', b'')
        except OSError:
            pass
    threading.Thread(target=forward, daemon=True).start()
    try:
        while True:
            kind, raw = _receive(conn)
            if kind == b'O':
                sys.stdout.buffer.write(raw); sys.stdout.buffer.flush()
            elif kind == b'E':
                sys.stderr.buffer.write(raw); sys.stderr.buffer.flush()
            elif kind == b'X':
                code = int(raw)
                return code if code >= 0 else 128 - code
            else:
                return 1
    except (OSError, EOFError):
        return 1
    finally:
        conn.close()
