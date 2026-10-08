"""Trusted Claude 2.1.285 text-role launch; existing first-party Pro auth only.

No --bare/API fallback, settings mutation, auth changes, or telemetry changes.
Flags constrain this invocation; they do not prove OS containment. The host
checks the exact request before submit; effective init is observed afterwards.
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
from uuid import UUID

from .adapters.claude import ADAPTER, CLI_VERSION, MAX_BATCH, ClaudeAdapter, NativeUnavailable, command_inventory_shape_valid
from .contracts import ExecutionConditions
from .delegation import DelegatedScope, job_payload

MAX_BYTES = 1048576
MAX_STREAM = 8388608
MAX_PROMPT = 65536
PRIVACY_KEYS = frozenset({'CLAUDE_CODE_ENABLE_TELEMETRY',
    'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY'})
SYSTEM_PROMPT = ('You are a bounded CO text Worker. Use no tools or external context. '
    'Only carry out the supplied Job and context. Never grant permissions or change CO state. '
    'Return out-of-scope needs as text to Controller. Produce only the requested text response.')


# Exact installed 2.1.285 artifact, not a version-string/prefix trust rule.
# Embedded Rbe/Vye registry at byte 191002803, L7 at 176556000 (path/source
# from ea="builtin" at 176352852), CEn init projection at 190339272.
# Only the three-field projection is qualified; version-bearing entries are
# deliberately not inferred. This trusts shipped Native internals, not plugins
# installed by the operator or Worker. See CLAUDE-ADAPTER.md.
BUNDLED_PLUGIN_EXECUTABLE_SHA256 = '51f09bd1e021d9fa8a1864c179799bd37cb39962a937935c5cf6823398e86db4'
BUNDLED_PLUGIN_NAMES = frozenset('cc-plugin-' + name for name in (
    'sec-default', 'agents-md', 'telemetry', 'plugin-authoring', 'mods-guide',
    'tips', 'mermaid', 'responsive-mode', 'diff', 'claude-test'))
BUNDLED_PLUGIN_EVIDENCE = 'claude-2.1.285:embedded-Rbe-L7-CEn:sha256:' + BUNDLED_PLUGIN_EXECUTABLE_SHA256
EFFORT_LEVELS = ('low', 'medium', 'high', 'xhigh', 'max')
# Exact embedded 2.1.285 model registry (byte ~176204000: effort, max_effort,
# xhigh_effort for each entry). Source capability only: not account availability,
# org caps, or applied/effective effort. Aliases never qualify.
EFFORT_SUPPORT = {model: frozenset(EFFORT_LEVELS) for model in (
    'claude-opus-5-5', 'claude-sonnet-5', 'claude-sonnet-5-5')}
EFFORT_MODELS = frozenset(EFFORT_SUPPORT)


class HostUnverified(RuntimeError):
    pass


def launch_environment():
    # Preserve privacy/telemetry exactly. Refuse unknown Native configuration
    # rather than silently scrubbing or changing the user's account/provider.
    env = dict(os.environ)
    for key in env:
        if ((key.startswith(('ANTHROPIC_', 'CLAUDE_', 'CLAUDECODE')) and key not in PRIVACY_KEYS)
                or key in {'NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'BASH_ENV', 'ENV'}
                or key.startswith('DYLD_')):
            raise HostUnverified('native_environment_override_present')
    return env


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _decode(raw):
    value = json.loads(raw, object_pairs_hook=_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if type(value) is not dict:
        raise ValueError('Native object required')
    return value


def _cleanup(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
    else:
        process.wait(timeout=1)


def _probe(executable, arguments, env, cwd):
    """Bounded read-only metadata probe; raw output never logged or retained."""
    process = subprocess.Popen([str(executable), *arguments], cwd=cwd, env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    raw = bytearray()
    try:
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not selector.select(.05):
                continue
            data = os.read(process.stdout.fileno(), 65536)
            if not data:
                code = process.wait(timeout=max(.01, deadline - time.monotonic()))
                return code, bytes(raw)
            raw.extend(data)
            if len(raw) > 65536:
                raise HostUnverified('metadata_probe_overflow')
        raise HostUnverified('metadata_probe_timeout')
    finally:
        selector.close()
        _cleanup(process)
        process.stdout.close()


def plugin_suppression_json(disabled_plugin_ids=()):
    """Trusted host input only; never settings JSON or Worker-supplied IDs."""
    if (type(disabled_plugin_ids) is not tuple or len(disabled_plugin_ids) > 16
            or any(type(value) is not str or not re.fullmatch(
                r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}@[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value)
                for value in disabled_plugin_ids)):
        raise HostUnverified('invalid_plugin_suppression_profile')
    if (len(set(disabled_plugin_ids)) != len(disabled_plugin_ids)
            or any(value.rsplit('@', 1)[1].lower() in {'builtin', 'inline', 'skills-dir', 'synced'}
                   for value in disabled_plugin_ids)):
        raise HostUnverified('invalid_plugin_suppression_profile')
    if not disabled_plugin_ids:
        return None
    return json.dumps({'enabledPlugins': {value: False for value in disabled_plugin_ids}},
                      sort_keys=True, separators=(',', ':'))


def validate_effort(model, effort):
    if effort is not None and (type(effort) is not str or effort not in EFFORT_LEVELS
                               or model not in EFFORT_MODELS):
        raise HostUnverified('unsupported_explicit_effort')


def source_pinned_effort_support(request, effort, executable_sha256):
    """Trusted verifier: exact model/effort pair in the pinned Native source registry.

    Returns None or raises. Proves the pair is declared by the pinned executable,
    not that the account may use it or that Native applied it.
    """
    if (executable_sha256 != BUNDLED_PLUGIN_EXECUTABLE_SHA256 or type(effort) is not str
            or effort not in EFFORT_SUPPORT.get(request.conditions.model, ())):
        raise HostUnverified('effort_support_not_in_pinned_source')


def invocation(executable, model, session, *, disabled_plugin_ids=(), effort=None):
    UUID(session)
    validate_effort(model, effort)
    overlay = plugin_suppression_json(disabled_plugin_ids)
    return [str(executable), '--print', '--input-format', 'text', '--output-format', 'stream-json',
        '--verbose', '--session-id', session, '--model', model, '--max-turns', '1',
        '--safe-mode', '--tools', '', '--disallowedTools', 'mcp__*', '--permission-mode', 'dontAsk',
        '--permission-prompts', 'none', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
        '--disable-slash-commands', '--no-session-persistence', '--no-chrome',
        '--system-prompt', SYSTEM_PROMPT] + (['--settings', overlay] if overlay is not None else []) + (
        ['--effort', effort] if effort is not None else [])


class PrintTransport:
    """Owned one-process NDJSON transport, one prompt, bounded IO and no retries."""
    def __init__(self, executable, workspace, model, session, prompt, env, *, disabled_plugin_ids=(), effort=None):
        raw = prompt.encode('utf-8')
        if len(raw) > MAX_PROMPT:
            raise HostUnverified('prompt_limit')
        self.session = session
        self.prompt_sha256 = hashlib.sha256(raw).hexdigest()
        options = ({'disabled_plugin_ids': disabled_plugin_ids} if disabled_plugin_ids else {})
        if effort is not None:
            options['effort'] = effort
        self.argv = invocation(executable, model, session, **options)
        self._incoming, self._outgoing = bytearray(), bytearray(raw)
        self._eof, self._closed, self._stdin_closed = False, False, False
        self._bytes, self._waited_exit = 0, None
        self._cleanup_reaped = False
        self._process = subprocess.Popen(self.argv, cwd=workspace, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        try:
            os.set_blocking(self._process.stdin.fileno(), False)
            os.set_blocking(self._process.stdout.fileno(), False)
        except Exception:
            self.close()
            raise

    def poll(self):
        if self._closed:
            raise HostUnverified('transport_closed')
        if self._outgoing:
            try:
                count = os.write(self._process.stdin.fileno(), self._outgoing)
                del self._outgoing[:count]
            except BlockingIOError:
                pass
        if not self._outgoing and not self._stdin_closed:
            self._process.stdin.close()
            self._stdin_closed = True
        if not self._eof:
            try:
                chunk = os.read(self._process.stdout.fileno(), 65536)
            except BlockingIOError:
                chunk = None
            if chunk == b'':
                self._eof = True
            elif chunk:
                self._incoming.extend(chunk)
                self._bytes += len(chunk)
        if len(self._incoming) > MAX_BYTES or self._bytes > MAX_STREAM:
            raise HostUnverified('native_output_limit')
        frames = []
        while b'\n' in self._incoming and len(frames) < MAX_BATCH:
            line, _, rest = self._incoming.partition(b'\n')
            self._incoming = bytearray(rest)
            frames.append(_decode(line))
        if self._eof and self._incoming and b'\n' not in self._incoming:
            raise HostUnverified('truncated_native_frame')
        return tuple(frames)

    def drained(self):
        return self._eof and not self._incoming and not self._outgoing and self._stdin_closed

    def wait_owned(self):
        if not self.drained() or self._process.poll() is None:
            return None
        self._waited_exit = self._process.wait(timeout=0)
        return self._waited_exit

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                _cleanup(self._process)
                self._cleanup_reaped = self._process.poll() is not None
            finally:
                self._process.stdin.close()
                self._process.stdout.close()


@dataclass(frozen=True)
class ClaudeHostConfig:
    conditions: ExecutionConditions
    executable: Path
    delegation: DelegatedScope
    expected_version: str = CLI_VERSION
    disabled_plugin_ids: tuple[str, ...] = field(default=(), repr=False)
    effort: str | None = None


def _unverified_policy(*args):
    raise HostUnverified('launch_policy_unverified')


_OWNED_TRANSPORT_TYPE = PrintTransport


class ClaudeTextHost:
    """Trusted single-Attempt composition. No Worker-origin config or handles."""
    def __init__(self, config, *, verify_launch_policy=_unverified_policy,
                 verify_effort_support=_unverified_policy):
        self.config = config
        self._disabled_plugins = config.disabled_plugin_ids
        validate_effort(config.conditions.model, config.effort)
        self._effort = config.effort
        self._effort_support = verify_effort_support
        overlay = plugin_suppression_json(self._disabled_plugins)
        self._policy = verify_launch_policy
        self._request = self._transport = self._binding = self._env = None
        self._payload_sha = None
        self._submitted = False
        self.observation = {'status': 'not_run', 'native_handoff_verified': False,
            'installed_production': False, 'credential_inventory_complete': False,
            'native_internal_isolation_claimed': False, 'remaining_usage': 'unknown',
            'plugin_suppression_count': len(self._disabled_plugins),
            'plugin_suppression_sha256': hashlib.sha256(overlay.encode()).hexdigest() if overlay else None,
            'requested_effort': self._effort,
            'effort_explicitly_selected': self._effort is not None,
            'effort_support_attested': False, 'effective_effort': 'not_recorded',
            'effort_applied_verified': False}

    def launch_arguments(self, session):
        """Trusted composition only: may contain private plugin IDs; never log argv."""
        if self.config.disabled_plugin_ids != self._disabled_plugins or self.config.effort != self._effort:
            raise HostUnverified('plugin_suppression_profile_changed')
        args = (self.config.executable, self.config.conditions.model, session)
        options = ({'disabled_plugin_ids': self._disabled_plugins} if self._disabled_plugins else {})
        if self._effort is not None:
            options['effort'] = self._effort
        return invocation(*args, **options)

    def make_adapter(self):
        return ClaudeAdapter(verify_host=self.verify, transport_factory=self.transport,
                             verify_completion=self.verify_completion,
                             verify_native_plugins=self.verify_native_plugins,
                             verify_native_commands=self.verify_native_commands)

    def verify_native_commands(self, request, session, commands):
        """Trust the fixed Native jq/Pnn builtin marker only on the owned stream.

        jq (byte 183784220) excludes plugin-owned/user/MCP commands; Pnn
        (185818740) exports the marker. AF (177257612) is inventory, not execution.
        """
        self.observation.update(native_commands_verified=False, native_command_count=None,
            native_command_builtin_marked_count=None, native_command_evidence_ref=None,
            native_command_reason='not_checked')
        def reject(reason):
            self.observation['native_command_reason'] = reason
            return False
        if not command_inventory_shape_valid(commands):
            return reject('inventory_schema_rejected')
        self.observation['native_command_count'] = len(commands)
        self.observation['native_command_builtin_marked_count'] = sum(
            command.get('builtin') is True for command in commands)
        if request != self._request or not self._submitted or self._transport is None:
            return reject('request_or_submission_unbound')
        try:
            self._check(request)
        except Exception:
            return reject('host_target_changed_or_unreadable')
        if commands:
            transport = self._transport
            if type(transport) is not _OWNED_TRANSPORT_TYPE:
                return reject('unowned_transport')
            if transport.session != session or transport.prompt_sha256 != self._payload_sha:
                return reject('session_or_payload_unbound')
            if transport.argv != self.launch_arguments(session):
                return reject('invocation_unbound')
            if self._binding[5] != BUNDLED_PLUGIN_EXECUTABLE_SHA256:
                return reject('executable_fingerprint_unqualified')
            if any(command.get('builtin') is not True for command in commands):
                return reject('non_builtin_command')
            self.observation['native_command_evidence_ref'] = (
                'claude-2.1.285:embedded-jq-Pnn-AF:sha256:' + BUNDLED_PLUGIN_EXECUTABLE_SHA256)
        self.observation.update(native_commands_verified=True, native_command_reason='verified')
        return True

    def verify_native_plugins(self, request, session, plugins):
        """Role extension: fully match shipped registry projection; expose no values."""
        diagnostic = {'reason': 'not_checked'}
        self.observation.update(native_plugins_verified=False, native_plugin_count=None,
                                native_plugin_evidence_ref=None, native_plugin_diagnostic=diagnostic)
        def reject(reason):
            diagnostic['reason'] = reason
            return False
        if type(plugins) is not list:
            return reject('list_shape_rejected')
        self.observation['native_plugin_count'] = min(len(plugins), 11)
        # Complete fixed-key counts even when an earlier item fails. Never retain
        # unknown field names, actual names/paths, values, or their repr.
        items = [item for item in plugins if type(item) is dict]
        counts = {'object_count': len(items), 'schema_match_count': 0,
                  'registered_name_count': 0, 'builtin_path_count': 0,
                  'registry_source_count': 0, 'exact_tuple_count': 0,
                  'unknown_field_count': 0}
        for key in ('name', 'path', 'source', 'version'):
            counts[key + '_present_count'] = sum(key in item for item in items)
        for item in items:
            shape = set(item) == {'name', 'path', 'source'}
            name = item.get('name')
            known = type(name) is str and name in BUNDLED_PLUGIN_NAMES
            path = item.get('path') == 'builtin'
            source = known and item.get('source') == name + '@builtin'
            counts['schema_match_count'] += shape
            counts['registered_name_count'] += known
            counts['builtin_path_count'] += path
            counts['registry_source_count'] += source
            counts['exact_tuple_count'] += shape and known and path and source
            counts['unknown_field_count'] += bool(set(item) - {'name', 'path', 'source', 'version'})
        diagnostic.update({key: min(value, 11) for key, value in counts.items()})
        if request != self._request or not self._submitted or self._transport is None:
            return reject('request_or_submission_unbound')
        try:
            self._check(request)
        except Exception:
            return reject('host_target_changed_or_unreadable')
        if plugins:
            transport = self._transport
            if type(transport) is not _OWNED_TRANSPORT_TYPE:
                return reject('unowned_transport')
            if transport.session != session:
                return reject('session_unbound')
            if transport.prompt_sha256 != self._payload_sha:
                return reject('payload_unbound')
            if transport.argv != self.launch_arguments(session):
                return reject('invocation_unbound')
            if self._binding[5] != BUNDLED_PLUGIN_EXECUTABLE_SHA256:
                return reject('executable_fingerprint_unqualified')
            seen = set()
            for plugin in plugins:
                if type(plugin) is not dict:
                    return reject('entry_shape_rejected')
                if 'version' in plugin:
                    return reject('version_field_unqualified')
                if set(plugin) != {'name', 'path', 'source'}:
                    return reject('keys_schema_rejected')
                name = plugin['name']
                if type(name) is not str or name not in BUNDLED_PLUGIN_NAMES:
                    return reject('registry_name_unqualified')
                if name in seen:
                    return reject('duplicate_entry')
                if plugin['path'] != 'builtin':
                    return reject('builtin_path_mismatch')
                if plugin['source'] != name + '@builtin':
                    return reject('registry_source_mismatch')
                seen.add(name)
            self.observation['native_plugin_evidence_ref'] = BUNDLED_PLUGIN_EVIDENCE
        diagnostic['reason'] = 'verified'
        self.observation['native_plugins_verified'] = True
        return True

    def _check(self, request):
        config = self.config
        if config.disabled_plugin_ids != self._disabled_plugins or config.effort != self._effort:
            raise HostUnverified('plugin_suppression_profile_changed')
        validate_effort(request.conditions.model, self._effort)
        config.delegation.validate(request, 'claude.text.only')
        if (request.conditions != config.conditions or request.conditions.adapter != ADAPTER
                or config.expected_version != CLI_VERSION
                or not request.conditions.environment_ref or not request.conditions.control_evidence_refs
                or not re.fullmatch(r'claude-[a-z0-9]+(?:-[a-z0-9]+)+', request.conditions.model)
                or request.conditions.model in {'claude-sonnet', 'claude-opus', 'claude-haiku'}):
            raise HostUnverified('unsupported_host_configuration')
        executable = config.executable
        workspace = Path(request.conditions.workspace)
        if (not executable.is_absolute() or not executable.is_file()
                or not workspace.is_absolute() or workspace.resolve(strict=True) != workspace
                or not workspace.is_dir()):
            raise HostUnverified('invalid_host_target')
        info, directory = executable.stat(), workspace.stat()
        binding = (str(executable.resolve(strict=True)), info.st_dev, info.st_ino,
            info.st_size, info.st_mtime_ns, hashlib.sha256(executable.read_bytes()).hexdigest(),
            directory.st_dev, directory.st_ino)
        if self._binding is not None and self._binding != binding:
            raise HostUnverified('host_target_changed')
        self._binding = binding

    def _check_effort_support(self, request):
        if self._effort is None:
            return
        self.observation['effort_support_attested'] = False
        if self._binding[5] != BUNDLED_PLUGIN_EXECUTABLE_SHA256:
            raise HostUnverified('effort_source_unqualified')
        # Attest the exact model/effort support declaration; a pinned-source
        # verifier is sufficient. Account caps and effective effort need
        # separate evidence and are not established by this support check.
        if self._effort_support(request, self._effort, self._binding[5]) is not None:
            raise HostUnverified('effort_support_not_attested')
        self.observation['effort_support_attested'] = True

    def verify(self, request):
        if self._request is not None:
            raise HostUnverified('host_already_used')
        try:
            self._check(request)
            env = launch_environment()
            code, version = _probe(self.config.executable, ['--version'], env, request.conditions.workspace)
            if code != 0 or version.strip() != (CLI_VERSION + ' (Claude Code)').encode():
                raise HostUnverified('native_version_mismatch')
            code, raw = _probe(self.config.executable, ['auth', 'status'], env, request.conditions.workspace)
            auth = _decode(raw)
            if (code != 0 or auth.get('loggedIn') is not True or auth.get('authMethod') != 'claude.ai'
                    or auth.get('apiProvider') != 'firstParty' or auth.get('subscriptionType') != 'pro'):
                raise NativeUnavailable('existing_pro_auth_unavailable')
            self._policy(request, tuple(self.launch_arguments('00000000-0000-0000-0000-000000000000')), frozenset(env))
            self._check_effort_support(request)
            self._request, self._env = request, env
            self.observation.update(status='launch_preflight_passed', auth_method='claude.ai',
                api_provider='firstParty', subscription_type='pro', native_version=CLI_VERSION,
                credential_values_read=False, effective_session_observed=False)
        except Exception as exc:
            self.observation.update(status='host_preflight_refused', native_handoff_verified=False)
            if isinstance(exc, NativeUnavailable):
                raise NativeUnavailable('existing_pro_auth_unavailable') from None
            raise HostUnverified('host_preflight_refused') from None

    def transport(self, request, session, payload):
        if self._request != request or self._submitted or payload != job_payload(request):
            raise HostUnverified('unbound_native_submission')
        self._check(request)
        if launch_environment() != self._env:
            raise HostUnverified('host_environment_changed')
        self._policy(request, tuple(self.launch_arguments(session)),
                     frozenset(self._env))
        self._check_effort_support(request)
        delegation = self.config.delegation.envelope()
        # Existing shared envelope only special-cases Devin. Override this new
        # role locally; do not broaden the shared Controller Contract.
        delegation['constraints'] = [SYSTEM_PROMPT]
        wrapped = {**payload, 'delegation': delegation}
        prompt = json.dumps(wrapped, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(',', ':'))
        self._payload_sha = hashlib.sha256(prompt.encode()).hexdigest()
        self._submitted = True  # An ambiguous constructor must never permit resubmission.
        self._transport = PrintTransport(self.config.executable, request.conditions.workspace,
            request.conditions.model, session, prompt, self._env,
            **({'disabled_plugin_ids': self._disabled_plugins} if self._disabled_plugins else {}),
            **({'effort': self._effort} if self._effort is not None else {}))
        self.observation['status'] = 'submitted_effective_session_unverified'
        return self._transport

    def diagnostic_observation(self):
        """Owned cleanup facts only, even on terminal error; never cancellation proof."""
        transport = self._transport
        if type(transport) is not _OWNED_TRANSPORT_TYPE:
            return {'owned_process_observed': False}
        return {'owned_process_observed': True, 'owned_pid': transport._process.pid,
            'close_attempted': transport._closed, 'cleanup_reaped': transport._cleanup_reaped,
            'owned_exit_code': transport._process.poll(),
            'stdout_eof_seen': transport._eof, 'stdout_drained': transport.drained(),
            'normal_wait_exit_code': transport._waited_exit,
            'cleanup_certifies_cessation': False}

    def verify_completion(self, request, session, result_uuid):
        self._check(request)
        transport = self._transport
        if type(transport) is not _OWNED_TRANSPORT_TYPE:
            return None  # A fixture transport cannot acquire real process proof.
        if (request != self._request or transport.session != session or transport.prompt_sha256 != self._payload_sha
                or transport.argv != self.launch_arguments(session)
                or not transport.drained() or transport._waited_exit != 0
                or transport._process.poll() != 0):
            raise HostUnverified('owned_completion_unverified')
        proof_data = {'session_sha256': hashlib.sha256(session.encode()).hexdigest(),
            'result_uuid_sha256': hashlib.sha256(result_uuid.encode()).hexdigest(),
            'prompt_sha256': self._payload_sha, 'native_version': CLI_VERSION,
            'attempt': [request.ref.run_id, request.ref.job_id, request.ref.attempt_id],
            'environment_ref': request.conditions.environment_ref, 'owned_exit_code': 0,
            'plugin_suppression_sha256': self.observation['plugin_suppression_sha256'],
            'stdout_eof_validated': True}
        if self._effort is not None:
            proof_data.update(requested_effort=self._effort, effective_effort='not_recorded',
                              effort_applied_verified=False)
        proof = 'claude.print:text-only:' + hashlib.sha256(json.dumps(proof_data, sort_keys=True).encode()).hexdigest()
        self.observation.update(status='text_completed', native_handoff_verified=True,
            effective_session_observed=True, cessation={**proof_data, 'evidence_ref': proof})
        return proof
