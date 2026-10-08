"""Actual Controller acceptance after prior exact-use Native qualification.

Trusted Root provides provenance/evidence/policy and an honestly qualified
private Catalog. No default approval, retry, new workspace Trust or promotion.
"""
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import time
from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.catalog import Catalog, UseCase
from co_v4.antigravity_host import AntigravityHostConfig, AntigravityTextHost, MODEL, CAPABILITY, BINARY_SHA, HOOK_SHA, SKILL_SHA
from co_v4.adapters.antigravity import ADAPTER, ADAPTER_VERSION, CLI_VERSION
from co_v4.antigravity_profiles import AntigravityRouteProfile, LEGACY_ROUTE
from co_v4.controller import Controller, JobPlan
from co_v4.delegation import DelegatedScope
from co_v4.judgment import TrustedEvidence
from co_v4.state import ControlStore, Limits, body_digest
from co_v4.usage import UsageStore
from probes.antigravity_text_worker import EXPECTED, job_for, source_identity, durable_new as _durable_new, durable_bytes

USE = UseCase('other', 'fixed-response text')


def _sha(value): return hashlib.sha256(value).hexdigest()
def _digest(value): return _sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def environment_definition(executable, hook_source, skill_source, workspace, *, route_profile=LEGACY_ROUTE):
    if type(route_profile) is not AntigravityRouteProfile:
        raise ValueError('exact AGY route profile required')
    from co_v4.antigravity_host import _ordinary, ORCA_KEYS, invocation
    observed = {'executable':_ordinary(Path(executable)), 'hook':_ordinary(Path(hook_source), maximum=65536),
                'skill':_ordinary(Path(skill_source), maximum=65536)}
    if observed != {'executable':route_profile.binary_sha256, 'hook':HOOK_SHA, 'skill':SKILL_SHA} or any(os.environ.get(k) for k in ORCA_KEYS):
        raise ValueError('qualified source/effect profile changed')
    sources = source_identity()
    info = Path(workspace).stat()
    descriptor = {'schema':'co.agy.fixed-text-environment.v1', 'model':route_profile.model,
        'adapter':ADAPTER,'adapter_version':ADAPTER_VERSION,'native_version':route_profile.native_version,
        'requested_effort':route_profile.effort,'effective_effort':'unmeasured', 'source':observed,
        'implementation':{k:sources[k] for k in ('adapter','host','route_profiles')},
        'argv_template_sha256':_digest(invocation(executable,'BOUND_JOB',route_profile)),
        'workspace_path_sha256':_sha(str(workspace).encode()), 'workspace_inode': [info.st_dev,info.st_ino],
        'system':platform.system(),'machine':platform.machine(),'uid':os.getuid(),
        'orca_effect_vars_nonempty': [False]*4, 'capability':CAPABILITY,'use':asdict(USE)}
    return 'agy-text-environment:sha256:' + _digest(descriptor), descriptor


@dataclass(frozen=True)
class DispatchAdmission:
    request_digest: str
    state_revision: int
    environment_ref: str
    evidence_ref: str
    phase: str = 'dispatch_admission'
    native_handoff_verified: bool = False


def run(root, *, workspace, run_id, human_intent, human_intent_ref, origin_verifier,
        evidence_resolver, policy_factory, executable, hook_source, skill_source, catalog, environment_ref,
        timeout=120, route_profile=LEGACY_ROUTE):
    """Run only under Root's actual origin, policy/protection and usage authority.

    evidence_resolver(snapshot, JudgmentRequest, admission) returns genuine
    TrustedEvidence. admission is None only for Job derivation; dispatch receipts
    assert checked launch readiness, never Human identity or an observed session.
    Root keeps these handles outside the Worker envelope. Fresh directory, file
    lock, durable claim and one-Job/Attempt limits prohibit ambiguous resend.
    """
    if type(route_profile) is not AntigravityRouteProfile:
        raise ValueError('exact AGY route profile required')
    model = route_profile.model
    if (not all(callable(v) for v in (origin_verifier, evidence_resolver, policy_factory))
            or type(catalog) is not Catalog or type(timeout) not in (int, float) or not 1 <= timeout <= 180):
        raise ValueError('actual host callbacks, reviewed Catalog and bounded timeout required')
    current_ref, descriptor = environment_definition(executable, hook_source, skill_source, workspace, route_profile=route_profile)
    if current_ref != environment_ref:
        raise ValueError('qualified environment differs')
    entry = next((e for e in catalog.entries if e.key == (model, ADAPTER)), None)
    if entry is None or entry.verification(USE, environment_ref) is None:
        raise ValueError('reviewed exact-use qualification required before Controller')
    root = Path(root).resolve()
    root.mkdir(mode=0o700, exist_ok=False)
    worker, control = Path(workspace), root / 'control'
    if worker == root or worker in root.parents:
        raise ValueError('control state must be outside Native workspace')
    control.mkdir(mode=0o700)
    owner = os.open(control / 'owner.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
    _durable_new(control / 'environment.json', {'environment_ref': environment_ref, 'descriptor': descriptor})
    conditions = c.ExecutionConditions(model, ADAPTER, str(worker), environment_ref, ('antigravity:checked-launch',))
    job = job_for(run_id)
    action = c.Action('native.text.response', c.Scope((('adapter', ADAPTER),
        ('workspace', str(worker)), ('environment', environment_ref),
        ('response_sha256', _sha(EXPECTED.encode()))), True))
    state = store = None
    host = adapter = policy = bound = None
    submitted = False
    observations, checks = {}, []
    report = {'schema': 'co.agy-controller-acceptance.v1', 'model': model,
        'effort': route_profile.effort, 'effort_explicitly_selected': True, 'effective_effort': 'unmeasured',
        'native_version': route_profile.native_version, 'environment_ref': environment_ref,
        'controller_exercised': False, 'human_gateway_exercised': False,
        'catalog_promoted': False, 'production_installed': False, 'accepted': False,
        'submission_claimed': False, 'automatic_retry': False, 'remaining_usage': 'unknown',
        'source_sha256': {**source_identity(), 'controller_probe': _sha(Path(__file__).read_bytes())}}

    def resolve(snapshot, request):
        nonlocal bound, host, policy
        if (request.conditions != conditions or request.action != action
                or request.method != 'bounded-fixed-response' or request.proposed_job not in (None, job)
                or request.confirmation is not None):
            raise ValueError('unbound judgment')
        admission = None
        if request.proposed_job is None:
            if submitted:
                raise ValueError('dispatch already claimed')
            if environment_definition(executable, hook_source, skill_source, workspace, route_profile=route_profile) != (environment_ref, descriptor):
                raise ValueError('environment changed')
            # A metadata-only assessment has no reserved Attempt/session. Recheck
            # with the Controller's actual Attempt before state reservation.
            ref = c.AttemptRef(run_id, job.job_id, request.ref.attempt_id or 'metadata-assessment')
            execution = c.ExecuteRequest(ref, job, conditions)
            config = AntigravityHostConfig(conditions, Path(executable).resolve(),
                DelegatedScope(human_intent_ref, ref, str(worker), CAPABILITY), Path(hook_source), Path(skill_source), route_profile)
            checked_policy = policy_factory(execution)
            if not callable(checked_policy):
                raise ValueError('trusted launch policy missing')
            preflight = AntigravityTextHost(config, execution, verify_launch_policy=checked_policy)
            preflight.verify(execution, preflight.profile)  # Pinned source/effects and actual launch policy; no model prompt.
            evidence_id = 'agy-dispatch:sha256:' + _digest({
                'request': body_digest(request), 'revision': snapshot.revision, 'environment': environment_ref})
            admission = DispatchAdmission(body_digest(request), snapshot.revision, environment_ref, evidence_id)
            if request.ref.attempt_id:
                if bound is not None and bound != execution:
                    raise ValueError('second Attempt refused')
                bound, policy = execution, checked_policy
                # Adapter.execute must independently perform its own Host.verify.
                host = AntigravityTextHost(config, execution, verify_launch_policy=checked_policy)
            path = control / (evidence_id.split(':')[-1] + '.json')
            if not path.exists():
                _durable_new(path, asdict(admission))
        evidence = evidence_resolver(snapshot, request, admission)
        if (type(evidence) is not TrustedEvidence or evidence.request_digest != body_digest(request)
                or (admission is not None and admission.evidence_ref not in evidence.evidence_refs)):
            raise ValueError('host evidence must bind actual admission')
        return evidence  # Never overwrite deny/unknown/protection/intent fields.

    class Observe:
        def execute(self, request):
            nonlocal adapter, submitted
            if submitted or request != bound or host is None or len(state.attempts(run_id)) != 1:
                raise ValueError('unbound or repeated dispatch')
            submitted = True
            _durable_new(control / 'submission-claim.json', {'attempt_ref': asdict(request.ref),
                'request_digest': body_digest(request), 'automatic_retry': False,
                'source_sha256': source_identity()})
            adapter = host.make_adapter()
            return adapter.execute(request)

        def events(self, ref, after=None):
            events = adapter.events(ref, after)
            if any(isinstance(e, c.ResultEvent) for e in events) and ref not in observations:
                try:
                    raw = adapter.text_output(ref).encode('utf-8')
                except ValueError:
                    raw = None
                observation = {'ref': asdict(ref), 'actual_sha256': _sha(raw) if raw is not None else None,
                    'actual_utf8_bytes': len(raw) if raw is not None else None,
                    'native_handoff_verified': host.observation.get('native_handoff_verified'),
                    'cessation': host.observation.get('cessation'),
                    'process': host.process_facts()}
                if raw == EXPECTED.encode():
                    wire = host.verified_native_stream(EXPECTED)
                    durable_bytes(control / 'verified-native.ndjson', wire)
                    observation['verified_native_sha256'] = _sha(wire)
                observations[ref] = observation
                _durable_new(control / 'observation.json', observation)
            return events

        def stop(self, ref): return adapter.stop(ref)
        def respond(self, response): return adapter.respond(response)

    def inspect(request):
        refs = [request.result.ref] if request.result else [j.result.ref for j in request.jobs]
        criteria = [False, False, False]
        if len(refs) == 1 and refs[0] in observations:
            observed = observations[refs[0]]
            raw = (control / 'observation.json').read_bytes()
            if json.loads(raw) != observed:
                raise ValueError('retained observation changed')
            ceased, process = observed.get('cessation'), observed['process']
            criteria = [observed['actual_sha256'] == _sha(EXPECTED.encode())
                and observed['actual_utf8_bytes'] == len(EXPECTED.encode()),
                observed['native_handoff_verified'] is True and ceased == 'confirmed',
                process.get('streams_eof') is True and process.get('normal_exit_zero') is True
                and process.get('owned_process_reaped') is True]
        verdict = 'pass' if all(criteria) else 'fail'
        path = control / ('check-' + str(len(checks)) + '.json')
        _durable_new(path, {'kind': request.kind, 'request_digest': body_digest(request),
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
            if progress.state in c.TERMINAL or progress.state == c.State.WAITING_HUMAN:
                break
            time.sleep(.01)
        else:
            report['timeout'] = True
            if bound is not None and adapter is not None:
                stop = adapter.stop(bound.ref)
                state.record_stop(stop, state.get_attempt(bound.ref).revision)
        current = state.get_run(run_id)
        report.update(controller_state=current.state.value,
            accepted=current.state == c.State.COMPLETED and not report.get('timeout', False),
            attempts=len(state.attempts(run_id)), routing_records=len(state.history(run_id, 'routing_history')),
            job_goal_count=len(state.history(run_id, 'job_goals')), run_goal_count=len(state.history(run_id, 'run_goals')))
    except Exception:
        report['failure'] = 'controller_probe_failed_closed'
    finally:
        try:
            if adapter is not None:
                adapter.close()
            report.update(submission_claimed=submitted, check_verdicts=checks,
                host_observation=host.observation if host is not None else None,
                process=host.process_facts() if host is not None else None,
                launch_policy_supplied=policy is not None)
            if adapter is not None and bound is not None:
                try:
                    report['protocol_diagnostic'] = adapter.diagnostic(bound.ref)
                    report['structural_observation'] = host.structural_observation()
                except ValueError:
                    report['protocol_diagnostic'] = None
            _durable_new(root / 'report.json', report)
        finally:
            try:
                if store is not None:
                    store.close()
            finally:
                os.close(owner)
    return report
