"""Root-only fixed-text model/effort Controller acceptance; no default authority or retry.

A reviewed prior exact-model/environment qualification is mandatory. The scoped
normal-completion bridge never upgrades generic Codex cancel/Resume capability.
"""
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import time

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.catalog import Catalog, UseCase
from co_v4.controller import Controller, JobPlan
from co_v4.delegation import DelegatedScope
from co_v4.judgment import TrustedEvidence
from co_v4.state import ControlStore, Limits, body_digest
from co_v4.usage import UsageStore
from co_v4.codex_model_selection import validate_selection
from co_v4.codex_host import CodexHostConfig, CodexReadOnlyHost, HostUnverified
from co_v4.adapters.codex import CodexAdapter
from probes.codex_host_preflight import configured_launch_inventory
from probes.codex_profile_acceptance import (EXPECTED, EFFORT, ObservedTransport,
    subscription_gate, service_tier_overrides, verify_service_tier, select_service_tier, append_service_tier_overrides, result_projection,
    auth_metadata)

MODEL, ADAPTER = 'gpt-6-sol', 'codex.app-server'
USE = UseCase('other', 'fixed-response text')
SOURCE_FILES = ('co_v4/adapters/codex.py', 'co_v4/codex_host.py',
    'co_v4/codex_errors.py', 'co_v4/codex_service_tier.py', 'co_v4/codex_model_selection.py',
    'co_v4/codex_permissions.py', 'co_v4/codex_profile_transport.py',
    'co_v4/delegation.py', 'probes/codex_profile_acceptance.py',
    'probes/codex_profile_metadata_schemas.json')


def _sha(data): return hashlib.sha256(data).hexdigest()
def _digest(value): return _sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def _new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())


def environment_definition(executable, *, model=MODEL, effort=EFFORT, service_tier='default', mode=None):
    """Logical control template, not an alias for a qualification Attempt UUID.

    Root must review original qualification/source/actual controls before this
    reference can appear in a Catalog Verification. Runtime absolute paths,
    random profile names and Attempt IDs are instantiated and checked per Job.
    """
    validate_selection(model, effort)
    service_tier = select_service_tier(mode, service_tier)
    executable = Path(executable).resolve(strict=True)
    base = Path(__file__).resolve().parents[1]
    descriptor = {'schema': 'co.codex.fixed-text-environment.v1',
        'model': model, 'effort': effort, 'service_tier': service_tier,
        'adapter': ADAPTER, 'native_version': 'codex-cli 0.159.2',
        'executable_sha256': _sha(executable.read_bytes()),
        'implementation': {name: _sha((base / name).read_bytes()) for name in SOURCE_FILES},
        'system': platform.system(), 'machine': platform.machine(), 'uid': os.getuid(),
        'use': asdict(USE), 'profile_template': {
            'filesystem_root': 'read', 'exact_current_auth_target_count': 1,
            'exact_owned_control_target_count': 1, 'exact_targets': 'deny',
            'network': False, 'workspace_create': False, 'control_parent_create': False,
            'native_in_process_containment_claimed': False},
        'launch_policy': {'current_mcp_inventory_disabled': True,
            'inherited_child_env_cleared': True, 'remote_control': False,
            'fresh_backend_ordinary_usage_allowed_required': True,
            'single_text_turn': True, 'tool_activity': 'refuse'},
        'response_sha256': _sha(EXPECTED.encode())}
    return 'codex-text-environment:sha256:' + _digest(descriptor), descriptor


@dataclass(frozen=True)
class DispatchAdmission:
    request_digest: str
    state_revision: int
    environment_ref: str
    evidence_ref: str
    phase: str = 'dispatch_admission'
    native_handoff_verified: bool = False


def job_for(run_id):
    return c.Job(run_id, 'fixed-response',
        'Use no tools. Output exactly CO03_ACCEPTANCE_OK with no additional text or whitespace.',
        ('Exact fixed text response.', 'Verified text-only Native completion.',
         'Validated EOF and owned normal exit 0.'))


class ProfileTextSession:
    """Own one actual Adapter/host/observer binding; no JSON completion authority."""
    def __init__(self, request, config, *, service_tier, check_source):
        self.request, self.config, self.tier = request, config, service_tier
        self.check_source = check_source
        self.host = CodexReadOnlyHost(config)
        self.wire = None
        self.result = None
        self.tier_observation = self.subscription = None
        self.claimed = False
        self.adapter = CodexAdapter(verify_host=self._verify, transport_factory=self._transport,
            permission_profile=self.host._profile_name, reasoning_effort=config.reasoning_effort, rpc_timeout=30)

    def _verify(self, request, phase, native):
        if request != self.request:
            raise HostUnverified('controller_request_changed')
        self.check_source()
        self.host.verify(request, phase, native)
        if phase == 'turn':
            try:
                if self.config.mode is not None:
                    self.subscription = self.host.observation['subscription_precondition']
                    self.tier_observation = self.host.observation['service_tier_observation']
                    self.check_source()
                    return
                account = self.host._rpc('account/read', {'refreshToken': False})
                usage = self.host._rpc('account/rateLimits/read', {})
                self.subscription = subscription_gate(account, usage,
                    api_environment_absent=self.api_environment_absent)
                config = self.host._rpc('config/read', {'cwd': request.conditions.workspace, 'includeLayers': False})['config']
                self.tier_observation = verify_service_tier(self.tier, config, native)
                self.check_source()
            except Exception:
                self.host._admitted = False
                raise

    def _transport(self, request):
        if request != self.request or self.wire is not None:
            raise HostUnverified('controller_transport_binding_invalid')
        import co_v4.codex_host as host_module
        original = host_module.StdioTransport
        def factory(*args, **kwargs):
            if self.wire is not None:
                raise HostUnverified('controller_transport_repeated')
            overrides = kwargs.get('config_overrides', ())
            if self.config.mode is None:
                kwargs['config_overrides'] = append_service_tier_overrides(overrides, self.tier)
            elif overrides[-len(service_tier_overrides(self.tier)):] != service_tier_overrides(self.tier):
                raise HostUnverified('controller_tier_override_conflict')
            env = kwargs.get('env')
            self.api_environment_absent = type(env) is dict and not any(key in env for key in
                ('OPENAI_API_KEY', 'OPENAI_ADMIN_KEY', 'CODEX_API_KEY', 'AZURE_OPENAI_API_KEY'))
            self.wire = ObservedTransport(*args, expected_effort=self.config.reasoning_effort, **kwargs)
            return self.wire
        try:
            host_module.StdioTransport = factory
            return self.host.transport(request)
        finally:
            host_module.StdioTransport = original

    def execute(self, request):
        if self.claimed or request != self.request:
            raise ValueError('single exact Controller dispatch required')
        self.claimed = True
        return self.adapter.execute(request)

    def events(self, ref, after=None):
        if ref != self.request.ref:
            raise ValueError('cross Attempt observation')
        events = self.adapter.events(ref, after)
        if any(isinstance(event, c.ResultEvent) for event in events):
            self.result = result_projection(self.adapter.events(ref), ref)
        return events

    def observation(self):
        return {'request_digest': body_digest(self.request),
            'ref': asdict(self.request.ref), 'environment_ref': self.request.conditions.environment_ref,
            'host': self.host.observation, 'native': self.wire.evidence() if self.wire else None,
            'result': self.result, 'subscription': self.subscription, 'service_tier': self.tier_observation}

    def stop(self, ref):
        if ref != self.request.ref:
            raise ValueError('cross Attempt stop')
        observed = self.observation()
        native = observed['native'] or {}
        # These observations come only from this session's exact owned transport,
        # never a supplied receipt/dict. Forced cleanup or a terminal Result alone
        # cannot satisfy the independent original-turn/EOF/normal-wait oracle.
        if (self.claimed and self.result is not None and self.result['state'] == 'completed'
                and self.host.observation.get('native_handoff_verified') is True
                and self.host._request == self.request and self.host._admitted is True
                and self.wire is not None and self.wire._process.poll() == 0
                and self.wire.thread == self.host._native_thread_id
                and type(self.wire.turn) is str and bool(self.wire.turn)
                and native.get('turn_submissions') == 1
                and native.get('original_turn_rpc_confirmed') is True
                and native.get('native_terminal') == 'completed'
                and native.get('validated_eof') is True and native.get('owned_wait_exit') == 0
                and native.get('cleanup_terminated') is False and native.get('unfinished_items') == 0
                and native.get('scoped_completion_evidence_complete') is True
                and self.subscription is not None and self.tier_observation is not None):
            self.check_source()
            return c.StopReply(ref, c.StopStatus.CONFIRMED, 'scoped_normal_text_completion',
                'codex-normal-text:sha256:' + _digest(observed))
        return self.adapter.stop(ref)

    def respond(self, response): return self.adapter.respond(response)
    def close(self): self.adapter.close()


def run(root, *, run_id, human_intent, human_intent_ref, origin_verifier,
        evidence_resolver, executable, catalog, environment_ref, check_source,
        model=MODEL, effort=EFFORT, service_tier='default', mode=None, timeout=120):
    """Actual Root provenance/policy callbacks and reviewed Catalog are mandatory."""
    if (not all(callable(v) for v in (origin_verifier, evidence_resolver, check_source))
            or type(catalog) is not Catalog or type(timeout) not in (int, float) or not 1 <= timeout <= 180):
        raise ValueError('actual callbacks, reviewed Catalog and bounded timeout required')
    validate_selection(model, effort)
    service_tier = select_service_tier(mode, service_tier)
    check_source()
    expected_ref, descriptor = environment_definition(executable, model=model, effort=effort, service_tier=service_tier)
    if expected_ref != environment_ref:
        raise ValueError('qualified environment differs')
    entry = next((entry for entry in catalog.entries if entry.key == (model, ADAPTER)), None)
    if entry is None or entry.verification(USE, environment_ref) is None:
        raise ValueError('reviewed exact-use qualification required')
    credential = (Path.home() / '.codex/auth.json').resolve(strict=True)
    auth_before = auth_metadata(credential)
    root = Path(root).resolve()
    root.mkdir(mode=0o700, exist_ok=False)
    worker, control = root / 'worker', root / 'control'
    worker.mkdir(mode=0o700); control.mkdir(mode=0o700)
    owner = os.open(control / 'owner.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
    _new(control / 'environment.json', {'environment_ref': environment_ref, 'descriptor': descriptor})
    conditions = c.ExecutionConditions(model, ADAPTER, str(worker), environment_ref,
        ('codex:checked-launch', 'service-tier:' + service_tier, 'reasoning-effort:' + (effort if effort is not None else 'inherit')))
    action = c.Action('native.text.response', c.Scope((('adapter', ADAPTER),
        ('workspace', str(worker)), ('environment', environment_ref),
        ('response_sha256', _sha(EXPECTED.encode()))), True))
    job = job_for(run_id)
    store = state = bound = session = config = None
    observations, checks = {}, []
    submitted = False
    report = {'schema': 'co.codex-controller-acceptance.v1', 'model': model, 'effort': effort,
        'requested_service_tier': service_tier, 'mode': service_tier if mode is not None else None, 'environment_ref': environment_ref,
        'controller_exercised': False, 'human_gateway_exercised': False,
        'catalog_promoted': False, 'production_installed': False, 'accepted': False,
        'automatic_retry': False, 'remaining_usage': 'unknown', 'generic_stop_qualified': False,
        'sol_llm_planner_qualified': False}

    def resolve(snapshot, request):
        nonlocal bound, config
        if (request.conditions != conditions or request.action != action
                or request.method != 'bounded-fixed-response' or request.proposed_job not in (None, job)
                or request.confirmation is not None):
            raise ValueError('unbound judgment')
        admission = None
        if request.proposed_job is None:
            if submitted: raise ValueError('dispatch already claimed')
            check_source()
            if environment_definition(executable, model=model, effort=effort, service_tier=service_tier) != (environment_ref, descriptor):
                raise ValueError('environment changed')
            ref = c.AttemptRef(run_id, job.job_id, request.ref.attempt_id or 'metadata-assessment')
            execution = c.ExecuteRequest(ref, job, conditions)
            mcp, keys = configured_launch_inventory(Path(executable).resolve(), worker)
            candidate = CodexHostConfig(conditions, Path(executable).resolve(), Path(sys.executable).resolve(),
                (control / 'control.db',), (credential,), DelegatedScope(human_intent_ref, ref, str(worker)),
                disabled_mcp_servers=mcp, cleared_environment_keys=keys,
                use_named_permissions=True, reasoning_effort=effort, mode=service_tier if mode is not None else None)
            preflight = CodexReadOnlyHost(candidate)
            preflight.verify(execution, 'launch', None)  # No Worker/session or positive Native handoff.
            evidence_id = 'codex-dispatch:sha256:' + _digest({
                'request': body_digest(request), 'revision': snapshot.revision, 'environment': environment_ref})
            admission = DispatchAdmission(body_digest(request), snapshot.revision, environment_ref, evidence_id)
            if request.ref.attempt_id:
                if bound is not None and bound != execution: raise ValueError('second Attempt refused')
                bound, config = execution, candidate
            path = control / (evidence_id.split(':')[-1] + '.json')
            if not path.exists(): _new(path, asdict(admission))
        evidence = evidence_resolver(snapshot, request, admission)
        if (type(evidence) is not TrustedEvidence or evidence.request_digest != body_digest(request)
                or (admission is not None and admission.evidence_ref not in evidence.evidence_refs)):
            raise ValueError('host evidence must bind actual admission')
        return evidence

    class Observe:
        def execute(self, request):
            nonlocal session, submitted
            if submitted or request != bound or config is None or len(state.attempts(run_id)) != 1:
                raise ValueError('unbound or repeated dispatch')
            submitted = True
            _new(control / 'submission-claim.json', {'attempt_ref': asdict(request.ref),
                'request_digest': body_digest(request), 'automatic_retry': False})
            session = ProfileTextSession(request, config, service_tier=service_tier, check_source=check_source)
            return session.execute(request)
        def events(self, ref, after=None):
            events = session.events(ref, after)
            if any(isinstance(event, c.ResultEvent) for event in events) and ref not in observations:
                observations[ref] = session.observation()
                _new(control / 'observation.json', observations[ref])
            return events
        def stop(self, ref): return session.stop(ref)
        def respond(self, response): return session.respond(response)

    def inspect(request):
        refs = [request.result.ref] if request.result else [job.result.ref for job in request.jobs]
        criteria = [False] * 3
        if len(refs) == 1 and refs[0] in observations:
            observed = observations[refs[0]]
            if json.loads((control / 'observation.json').read_bytes()) != observed:
                raise ValueError('retained observation changed')
            native = observed['native'] or {}
            criteria = [native.get('observed_sha256') == _sha(EXPECTED.encode())
                and native.get('observed_utf8_bytes') == len(EXPECTED.encode()),
                observed['host'].get('native_handoff_verified') is True
                and observed['environment_ref'] == environment_ref
                and native.get('scoped_completion_evidence_complete') is True,
                native.get('validated_eof') is True and native.get('owned_wait_exit') == 0
                and native.get('cleanup_terminated') is False]
        verdict = 'pass' if all(criteria) else 'fail'
        path = control / ('check-' + str(len(checks)) + '.json')
        _new(path, {'kind': request.kind, 'request_digest': body_digest(request),
            'criteria_passed': criteria, 'verdict': verdict,
            'observation_sha256': _sha((control / 'observation.json').read_bytes()) if observations else None})
        checks.append(verdict)
        finding = Finding(verdict, (str(path.relative_to(root)),))
        return CheckEvidence(body_digest(request), finding, tuple(
            Finding('pass' if value else 'fail', finding.evidence_refs) for value in criteria)
            if request.kind == 'job' else ())

    try:
        store = ControlStore(control / 'control.db', verifier=origin_verifier, evidence=resolve)
        state = store.controller()
        store.intake().create_run(run_id, human_intent, human_intent_ref)
        state.set_limits(run_id, Limits(jobs=1, attempts_per_job=1, attempts_per_pair=1), state.get_run(run_id).revision)
        controller = Controller(run_id, state=state, judgment=store.judgment(), catalog=catalog,
            usage=UsageStore(), adapters={ADAPTER: Observe()}, acceptance=Acceptance(inspect),
            planner=lambda *_: JobPlan(job, action, 'bounded-fixed-response', USE, (conditions,),
                explicit_model=model, explicit_adapter=ADAPTER))
        report['controller_exercised'] = True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            progress = controller.step()
            if progress.state in c.TERMINAL or progress.state == c.State.WAITING_HUMAN: break
            time.sleep(.01)
        else:
            report['timeout'] = True
            if bound is not None and session is not None:
                state.record_stop(session.stop(bound.ref), state.get_attempt(bound.ref).revision)
        current = state.get_run(run_id)
        report.update(controller_state=current.state.value,
            accepted=current.state == c.State.COMPLETED and not report.get('timeout', False),
            attempts=len(state.attempts(run_id)), routing_records=len(state.history(run_id, 'routing_history')),
            job_goal_count=len(state.history(run_id, 'job_goals')), run_goal_count=len(state.history(run_id, 'run_goals')))
    except Exception:
        report['failure'] = 'controller_probe_failed_closed'
    finally:
        try:
            try:
                if session is not None: session.close()
                check_source()
                report['source_verified_after_cleanup'] = True
            except Exception:
                report['source_verified_after_cleanup'] = False
                report['accepted'] = False
                report['failure'] = 'cleanup_or_source_unconfirmed'
            report.update(submission_claimed=submitted,
                check_verdicts=checks, observation=session.observation() if session else None,
                workspace_entries=len(list(worker.iterdir())),
                authentication_metadata_unchanged=auth_before == auth_metadata(credential))
            if report['workspace_entries'] != 0: report['accepted'] = False
            _new(root / 'report.json', report)
        finally:
            try:
                if store is not None: store.close()
            finally:
                os.close(owner)
    return report
