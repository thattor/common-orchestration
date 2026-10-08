"""One bounded text-worker acceptance probe; default preflight sends no prompt.

Live use is programmatic trusted-host composition only. Root must supply a
UsageProof verifier backed by existing owner authorization and actual current
usage evidence: the owner's answer or a trusted official read. JSON/flags are
not authorization sources. Never use a constant or synthetic verifier for live.
No Catalog admission, production Controller, Human transaction or Run Goal claim.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import time
from uuid import UUID, uuid4

from co_v4 import claude_host
from co_v4.adapters import claude
from co_v4.contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job, ResultEvent, State
from co_v4.delegation import DelegatedScope

EXPECTED = 'CO_CLAUDE_ACCEPTANCE_OK'
SOURCE_SHA = {
    'adapter': 'c827c05bf337b2812c7a943b062b1790530e2da4ed98d89c027cff5dbf4299c9',
    'host': '5d6e3917bcfdb2bc9b4a446e532e693dbc03d83f93d60ab8461d42e9bf0287e7',
}
ZERO_SESSION = '00000000-0000-0000-0000-000000000000'


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def source_identity():
    observed = {'adapter': _sha(Path(claude.__file__).read_bytes()),
                'host': _sha(Path(claude_host.__file__).read_bytes())}
    if observed != SOURCE_SHA:
        raise ValueError('probe source pin mismatch')
    return {**observed, 'probe': _sha(Path(__file__).read_bytes())}


def cf_policy_present():
    """Only key-list cardinalities, never preference key names or values.

    Must run in the approved actual host context. This API cannot establish
    visibility outside its process privileges; sandbox absence is not reused.
    """
    f = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    pointer = ctypes.c_void_p
    f.CFStringCreateWithCString.argtypes = [pointer, ctypes.c_char_p, ctypes.c_uint32]
    f.CFStringCreateWithCString.restype = pointer
    f.CFPreferencesCopyKeyList.argtypes = [pointer, pointer, pointer]
    f.CFPreferencesCopyKeyList.restype = pointer
    f.CFArrayGetCount.argtypes = [pointer]
    f.CFArrayGetCount.restype = ctypes.c_long
    f.CFRelease.argtypes = [pointer]
    application = f.CFStringCreateWithCString(None, b'com.anthropic.claudecode', 0x08000100)
    if not application:
        raise ValueError('policy domain unavailable')
    found = []
    try:
        for user in ('CurrentUser', 'AnyUser'):
            for host in ('CurrentHost', 'AnyHost'):
                keys = f.CFPreferencesCopyKeyList(application,
                    pointer.in_dll(f, 'kCFPreferences' + user),
                    pointer.in_dll(f, 'kCFPreferences' + host))
                try:
                    count = f.CFArrayGetCount(keys) if keys else 0
                    if count < 0:
                        raise ValueError('policy cardinality unknown')
                    found.append(count > 0)
                finally:
                    if keys:
                        f.CFRelease(keys)
    finally:
        f.CFRelease(application)
    return tuple(found)


def managed_policy_observation():
    if platform.system() != 'Darwin':
        raise ValueError('unsupported metadata host')
    base = Path('/Library/Application Support/ClaudeCode')
    managed = Path('/Library/Managed Preferences')
    username = pwd.getpwuid(os.getuid()).pw_name
    paths = (base / 'managed-settings.json', base / 'managed-settings.d', base / 'managed-mcp.json',
             managed / 'com.anthropic.claudecode.plist',
             managed / username / 'com.anthropic.claudecode.plist')
    present = []
    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            present.append(False)
        else:
            present.append(True)
        # Permission/error other than absence propagates, never means absent.
    preferences = cf_policy_present()
    if len(preferences) != 4 or any(type(item) is not bool for item in preferences):
        raise ValueError('policy observation incomplete')
    if any(present) or any(preferences):
        raise ValueError('existing policy requires targeted review')
    return {'known_managed_sources_present': present, 'preference_scopes_present': list(preferences),
            'preference_values_read': False, 'normal_settings_sources_retained': True}


@dataclass(frozen=True)
class UsageProof:
    """Trusted Root's attestation of authorized, observed usage conditions.

    evidence_ref privately resolves to the actual owner answer or the trusted
    official read confirming credits off and fresh quota, under existing owner
    authorization for this test. The callback verifies provenance, exact
    evidence integrity and freshness on every call. An official read observes
    conditions; it does not itself grant permission. Type/field validation does
    not authenticate the source, and absent/cached/error displays are not proof.
    """
    evidence_ref: str
    extra_credit_off: bool
    quota_available: bool
    valid_until: str


class LaunchPolicy:
    def __init__(self, request, config, *, live=False, authorize_usage=None, claim_directory=None):
        self.request, self.config = request, config
        self._disabled_plugins = config.disabled_plugin_ids
        self._effort = config.effort
        overlay = claude_host.plugin_suppression_json(self._disabled_plugins)
        self.plugin_suppression_sha256 = _sha(overlay.encode()) if overlay else None
        self.live, self.authorize_usage = live, authorize_usage
        self.claim_directory = claim_directory
        self._uid = os.getuid()
        info = Path(request.conditions.workspace).stat()
        self._workspace = (info.st_dev, info.st_ino)
        self._keys = frozenset(os.environ)
        self._sources = source_identity()
        self.calls = 0
        self.observation = None
        self.usage_ref_sha = None

    def __call__(self, request, argv, env_keys):
        if (request != self.request or os.getuid() != self._uid or env_keys != self._keys
                or self.config.disabled_plugin_ids != self._disabled_plugins
                or self.config.effort != self._effort):
            raise ValueError('launch identity changed')
        if frozenset(os.environ) != self._keys or source_identity() != self._sources:
            raise ValueError('launch environment or implementation changed')
        self.config.delegation.validate(request, 'claude.text.only')
        info = Path(request.conditions.workspace).stat()
        if (info.st_dev, info.st_ino) != self._workspace:
            raise ValueError('workspace changed')
        expected = tuple(claude_host.invocation(self.config.executable, request.conditions.model, ZERO_SESSION,
            disabled_plugin_ids=self._disabled_plugins, effort=self._effort))
        actual = list(argv)
        index = expected.index('--session-id') + 1
        session = actual[index]
        UUID(session)
        actual[index] = ZERO_SESSION
        if tuple(actual) != expected:
            raise ValueError('launch arguments changed')
        observed = managed_policy_observation()
        if self.observation is not None and self.observation != observed:
            raise ValueError('policy changed')
        if self.live:
            if self.authorize_usage is None:
                raise ValueError('trusted authorized usage evidence required')
            proof = self.authorize_usage(request)
            if (type(proof) is not UsageProof or proof.extra_credit_off is not True
                    or proof.quota_available is not True or not proof.evidence_ref.strip()):
                raise ValueError('usage authorization missing')
            expires = datetime.fromisoformat(proof.valid_until.replace('Z', '+00:00'))
            if (expires.tzinfo is None or expires.utcoffset().total_seconds() != 0
                    or expires <= datetime.now(timezone.utc)):
                raise ValueError('usage authorization expired')
            self.usage_ref_sha = _sha(proof.evidence_ref.encode())
            if session != ZERO_SESSION and self.claim_directory is not None:
                # The Adapter generated this session for this exact request.
                # Persist the link before returning to actual process creation;
                # a second launch binding is refused by exclusive creation.
                _durable_new(self.claim_directory / 'session-binding.json', {
                    'attempt_ref': {'run_id': request.ref.run_id, 'job_id': request.ref.job_id,
                                    'attempt_id': request.ref.attempt_id},
                    'native_session_sha256': _sha(session.encode()),
                    'source': 'adapter_generated_exact_launch_argument',
                    'plugin_suppression_sha256': self.plugin_suppression_sha256,
                    'submission_claim': 'submission-claim.json',
                    'native_process_creation': 'not_yet_attempted'})
        self.observation = observed
        self.calls += 1


def _durable_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(_bytes(value) + b'\n'); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(output, *, executable, model, live=False, authorize_usage=None, disabled_plugin_ids=(),
        effort=None, verify_effort_support=claude_host.source_pinned_effort_support):
    """Trusted Root only. Live=False never calls Adapter.execute or its factory.

    Live=True requires existing owner authorization plus a callback grounded
    in the actual owner answer or a trusted current official usage read. Callers
    must never convert fixture data or command-line booleans into this authority.
    Root must run the observation in the approved host context, not a sandbox
    whose visibility differs from the eventual Native process.
    """
    if live and authorize_usage is None:
        raise ValueError('live requires trusted usage verifier')
    claude_host.validate_effort(model, effort)
    deadline = time.monotonic() + 120
    output = Path(output).resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    worker = output / 'worker'; worker.mkdir(mode=0o700)
    conditions = ExecutionConditions(model, claude.ADAPTER, str(worker),
                                    'claude-text-probe' + (':effort=' + effort if effort is not None else ''),
                                    ('claude-text-probe:launch-policy',))
    ref = AttemptRef('claude-text-probe-' + uuid4().hex, 'fixed-response', 'one')
    identity = {'run_id': ref.run_id, 'job_id': ref.job_id, 'attempt_id': ref.attempt_id}
    request = ExecuteRequest(ref, Job(ref.run_id, ref.job_id,
        'Return exactly CO_CLAUDE_ACCEPTANCE_OK. Use no tools.', ('Exact fixed text response',)), conditions)
    config = claude_host.ClaudeHostConfig(conditions, Path(executable),
        DelegatedScope('authorized-claude-text-probe', ref, str(worker), 'claude.text.only'),
        disabled_plugin_ids=disabled_plugin_ids, effort=effort)
    policy = LaunchPolicy(request, config, live=live, authorize_usage=authorize_usage,
                          claim_directory=output if live else None)
    host = claude_host.ClaudeTextHost(config, verify_launch_policy=policy,
                                    verify_effort_support=verify_effort_support)
    report = {'schema': 'co.claude-text-worker-probe.v1', 'mode': 'live' if live else 'preflight_only',
        'source_sha256': source_identity(), 'model': model, 'native_version': claude.CLI_VERSION,
        'adapter_version': claude.ADAPTER_VERSION, 'controller_compat': '0.1.0-dev', 'attempt_ref': identity,
        'model_submission_attempts': 0, 'result': 'not_run', 'independent_ac': 'not_run',
        'cessation': 'unconfirmed', 'catalog_promoted': False, 'production_controller': False,
        'run_goal': 'not_evaluated', 'remaining_usage': 'unknown',
        'requested_effort': effort, 'effort_explicitly_selected': effort is not None,
        'effective_effort': 'not_recorded', 'effort_applied_verified': False,
        'effort_qualification': ('not_requested' if effort is None else
                                 'blocked_effective_metadata_unavailable'),
        'environment_ref': conditions.environment_ref}
    adapter = None
    try:
        # Policy metadata/authorization checked before even metadata CLI probes,
        # then repeated by Host.verify and again directly before actual launch.
        policy(request, tuple(host.launch_arguments(ZERO_SESSION)), frozenset(os.environ))
        if not live:
            host.verify(request)
            report['result'] = 'preflight_passed_no_prompt'
        else:
            _durable_new(output / 'submission-claim.json', {'attempt_ref': identity, 'status': 'claimed',
                'native_session': 'not_yet_assigned', 'session_binding_ref': 'session-binding.json',
                'usage_evidence_ref_sha256': policy.usage_ref_sha, 'automatic_retry': False,
                'plugin_suppression_sha256': policy.plugin_suppression_sha256})
            adapter = host.make_adapter()
            reply = adapter.execute(request)
            report['operation'] = reply.status.value
            report['model_submission_attempts'] = 0 if reply.never_started else 1
            result = None
            while time.monotonic() < deadline:
                for event in adapter.events(ref) if reply.never_started is None else ():
                    if isinstance(event, ResultEvent): result = event.result
                if result is not None or reply.never_started is not None:
                    break
                time.sleep(.01)
            if result is None:
                if reply.never_started is None:
                    adapter.stop(ref)
                report['result'] = 'unavailable_or_timed_out'
            else:
                report['result'] = result.status.value
                report['result_reason'] = result.reason
                if result.status == State.COMPLETED:
                    text = adapter.text_output(ref)
                    report['actual_output_sha256'] = _sha(text.encode())
                    report['expected_output_sha256'] = _sha(EXPECTED.encode())
                    report['independent_ac'] = 'pass' if text == EXPECTED else 'fail'
                stop = adapter.stop(ref)
                report['cessation'] = stop.status.value
                report['cessation_evidence_ref'] = stop.evidence_ref
    except Exception:
        report['result'] = 'probe_failed_closed'
    finally:
        if adapter is not None:
            adapter.close()
    report['policy_checks'] = policy.calls
    report['launch_policy'] = policy.observation
    report['usage_evidence_ref_sha256'] = policy.usage_ref_sha
    report['host_observation'] = host.observation
    report['owned_process_diagnostic'] = host.diagnostic_observation()
    report['protocol_diagnostic'] = None
    report['rate_limit_observation'] = None
    report['commands_observation'] = None
    if adapter is not None:
        try:
            report['protocol_diagnostic'] = adapter.protocol_diagnostic(ref)
            report['rate_limit_observation'] = adapter.rate_limit_observation(ref)
            report['commands_observation'] = adapter.commands_observation(ref)
        except ValueError:
            pass  # Pre-transport rejection has no Attempt record.
    _durable_new(output / 'report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight-only', action='store_true', default=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--model', required=True)
    parser.add_argument('--effort', choices=claude_host.EFFORT_LEVELS)
    args = parser.parse_args()
    try:
        report = run(args.output, executable=args.executable, model=args.model, effort=args.effort)
    except Exception:
        parser.exit(2, 'Probe setup refused; no acceptance established.\n')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['result'] == 'preflight_passed_no_prompt' else 1


if __name__ == '__main__':
    raise SystemExit(main())
