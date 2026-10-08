"""One authorized fixed-text Controller run; programmatic trusted host only.

No default authorization, UsageProof, Catalog, auth change or automatic retry.
The prior Native qualification must already cover the exact environment/use.
This harness adds Controller -> Job -> independent AC -> Run Goal evidence.
"""
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import time

from co_v4 import contracts as c, delegation
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.catalog import Catalog, UseCase
from co_v4.claude_host import ClaudeHostConfig, ClaudeTextHost, invocation, plugin_suppression_json
from co_v4.controller import Controller, JobPlan
from co_v4.delegation import DelegatedScope
from co_v4.judgment import TrustedEvidence
from co_v4.state import ControlStore, Limits, body_digest
from co_v4.usage import UsageStore
from probes.claude_text_worker import (EXPECTED, ZERO_SESSION, LaunchPolicy,
    _durable_new, managed_policy_observation, source_identity)
from co_v4.adapters.claude import ADAPTER, ADAPTER_VERSION, CLI_VERSION

MODEL = 'claude-opus-5-5'
MODELS = (MODEL, 'claude-sonnet-5')


def _checked_model(model):
    if type(model) is not str or model not in MODELS:
        raise ValueError('reviewed exact Claude text model required')
    return model
USE = UseCase('other', 'fixed-response text')


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _digest(value):
    return _sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def environment_definition(executable, *, disabled_plugin_ids=(), model=MODEL):
    """Observe current nonsecret profile facts; this does not qualify a model.

    Root must compare the prior original qualification/AC with this descriptor
    before supplying a reviewed Catalog. A generic old environment label is
    never promoted into this immutable reference by the harness.
    """
    model = _checked_model(model)
    executable = Path(executable).resolve(strict=True)
    sources = source_identity()
    overlay = plugin_suppression_json(disabled_plugin_ids)
    # Hash private argv/IDs; never retain them in the descriptor/report.
    argv = invocation(executable, model, ZERO_SESSION, disabled_plugin_ids=disabled_plugin_ids)
    descriptor = {'schema': 'co.claude.fixed-text-environment.v1', 'model': model,
        'adapter': ADAPTER, 'adapter_version': ADAPTER_VERSION, 'native_version': CLI_VERSION,
        'effort': 'not_recorded', 'effort_explicitly_selected': False,
        'executable_sha256': _sha(executable.read_bytes()),
        'implementation': {key: sources[key] for key in ('adapter', 'host')},
        'delegation_sha256': _sha(Path(delegation.__file__).read_bytes()),
        'argv_template_sha256': _digest(argv), 'plugin_suppression_sha256': _sha(overlay.encode()) if overlay else None,
        'system': platform.system(), 'machine': platform.machine(), 'uid': os.getuid(),
        'policy_metadata': managed_policy_observation(),
        'capability': 'claude.text.only', 'use': asdict(USE)}
    return 'claude-text-environment:sha256:' + _digest(descriptor), descriptor


@dataclass(frozen=True)
class DispatchAdmission:
    request_digest: str
    state_revision: int
    environment_ref: str
    evidence_ref: str
    phase: str = 'dispatch_admission'
    native_handoff_verified: bool = False


def job_for(run_id):
    return c.Job(run_id, 'fixed-response', 'Return exactly ' + EXPECTED + '. Use no tools.',
        ('Exact fixed text response.', 'Verified text-only Native completion.',
         'Validated EOF and owned normal exit 0.'))


def run(root, *, run_id, human_intent, human_intent_ref, origin_verifier,
        evidence_resolver, authorize_usage, executable, catalog, environment_ref,
        disabled_plugin_ids=(), timeout=120, model=MODEL):
    """Run only under Root's actual origin, policy/protection and usage authority.

    evidence_resolver(snapshot, JudgmentRequest, admission) returns genuine
    TrustedEvidence. admission is None only for Job derivation; dispatch receipts
    assert checked launch readiness, never Human identity or an observed session.
    Root keeps these handles outside the Worker envelope. Fresh directory, file
    lock, durable claim and one-Job/Attempt limits prohibit ambiguous resend.
    """
    model = _checked_model(model)
    if (not all(callable(v) for v in (origin_verifier, evidence_resolver, authorize_usage))
            or type(catalog) is not Catalog or type(timeout) not in (int, float) or not 1 <= timeout <= 180):
        raise ValueError('actual host callbacks, reviewed Catalog and bounded timeout required')
    current_ref, descriptor = environment_definition(executable, disabled_plugin_ids=disabled_plugin_ids, model=model)
    if current_ref != environment_ref:
        raise ValueError('qualified environment differs')
    entry = next((e for e in catalog.entries if e.key == (model, ADAPTER)), None)
    if entry is None or entry.verification(USE, environment_ref) is None:
        raise ValueError('reviewed exact-use qualification required before Controller')
    root = Path(root).resolve()
    root.mkdir(mode=0o700, exist_ok=False)
    worker, control = root / 'worker', root / 'control'
    worker.mkdir(mode=0o700); control.mkdir(mode=0o700)
    owner = os.open(control / 'owner.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
    _durable_new(control / 'environment.json', {'environment_ref': environment_ref, 'descriptor': descriptor})
    conditions = c.ExecutionConditions(model, ADAPTER, str(worker), environment_ref, ('claude:checked-launch',))
    job = job_for(run_id)
    action = c.Action('native.text.response', c.Scope((('adapter', ADAPTER),
        ('workspace', str(worker)), ('environment', environment_ref),
        ('response_sha256', _sha(EXPECTED.encode()))), True))
    state = store = None
    host = adapter = policy = bound = None
    submitted = False
    observations, checks = {}, []
    report = {'schema': 'co.claude-controller-acceptance.v1', 'model': model,
        'effort': 'not_recorded', 'effort_explicitly_selected': False,
        'native_version': CLI_VERSION, 'environment_ref': environment_ref,
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
            if environment_definition(executable, disabled_plugin_ids=disabled_plugin_ids, model=model) != (environment_ref, descriptor):
                raise ValueError('environment changed')
            # A metadata-only assessment has no reserved Attempt/session. Recheck
            # with the Controller's actual Attempt before state reservation.
            ref = c.AttemptRef(run_id, job.job_id, request.ref.attempt_id or 'metadata-assessment')
            execution = c.ExecuteRequest(ref, job, conditions)
            config = ClaudeHostConfig(conditions, Path(executable).resolve(),
                DelegatedScope(human_intent_ref, ref, str(worker), 'claude.text.only'),
                disabled_plugin_ids=disabled_plugin_ids)
            checked_policy = LaunchPolicy(execution, config, live=True,
                authorize_usage=authorize_usage, claim_directory=control if request.ref.attempt_id else None)
            preflight = ClaudeTextHost(config, verify_launch_policy=checked_policy)
            checked_policy(execution, tuple(preflight.launch_arguments(ZERO_SESSION)), frozenset(os.environ))
            preflight.verify(execution)  # Version/auth/actual launch policy; no model prompt.
            evidence_id = 'claude-dispatch:sha256:' + _digest({
                'request': body_digest(request), 'revision': snapshot.revision, 'environment': environment_ref})
            admission = DispatchAdmission(body_digest(request), snapshot.revision, environment_ref, evidence_id)
            if request.ref.attempt_id:
                if bound is not None and bound != execution:
                    raise ValueError('second Attempt refused')
                bound, policy = execution, checked_policy
                # Adapter.execute must independently perform its own Host.verify.
                host = ClaudeTextHost(config, verify_launch_policy=checked_policy)
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
                'usage_evidence_ref_sha256': policy.usage_ref_sha})
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
                    'process': host.diagnostic_observation()}
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
            ceased, process = observed.get('cessation') or {}, observed['process']
            criteria = [observed['actual_sha256'] == _sha(EXPECTED.encode())
                and observed['actual_utf8_bytes'] == len(EXPECTED.encode()),
                observed['native_handoff_verified'] is True and ceased.get('environment_ref') == environment_ref
                and ceased.get('attempt') == [refs[0].run_id, refs[0].job_id, refs[0].attempt_id],
                ceased.get('stdout_eof_validated') is True and ceased.get('owned_exit_code') == 0
                and process.get('stdout_drained') is True and process.get('normal_wait_exit_code') == 0]
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
                process=host.diagnostic_observation() if host is not None else None,
                usage_checks=policy.calls if policy is not None else 0,
                usage_evidence_ref_sha256=policy.usage_ref_sha if policy is not None else None)
            if adapter is not None and bound is not None:
                try:
                    report['protocol_diagnostic'] = adapter.protocol_diagnostic(bound.ref)
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
