"""Programmatic one-turn real Controller acceptance; no authentication CLI.

The authorized host supplies actual origin and protection resolvers plus a
reviewed, use-specific Catalog. There are deliberately no default positive
receipts, invented verification refs, login commands or model fallbacks.
Call run() only after that host authorizes the one fixed-response Native turn.
"""
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import time
from uuid import uuid4

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.catalog import Catalog, UseCase
from co_v4.controller import Controller, JobPlan
from co_v4.devin_selection import resolve_model, selection
from co_v4.devin_host import DevinLaunchTemplate
from co_v4.devin_route import DevinTextRoute, environment_definition
from co_v4.judgment import JudgmentRequest, TrustedEvidence
from co_v4.state import ControlStore, Limits, body_digest
from co_v4.trace import canonical
from co_v4.usage import UsageStore

EXPECTED = 'CO03_CONTROLLER_GOAL_OK'
USE = UseCase('other', 'fixed-response text')


def job_for(run_id):
    return c.Job(run_id, 'fixed-response',
        'Return exactly ' + EXPECTED + '. Use no tools. Do not read files, access the network, or change state.',
        ('Return the exact fixed response.', 'No observed tool activity.',
         'Confirm the exact requested model from Native session evidence.',
         'Confirm the bound text turn and owned CLI have ceased.'))


def _write_once(path, value):
    raw = canonical(value) + '\n'
    if path.exists():
        if path.read_text() != raw: raise ValueError('retained evidence identity changed')
    else:
        with path.open('x') as stream: stream.write(raw)


def run(root, *, run_id, human_intent, human_intent_ref, origin_verifier,
        evidence_resolver, executable, native_version, model, credential_files,
        catalog: Catalog | None, environment_ref, control_evidence_refs, policy_ref, timeout=120,
        _qualification=False, effort=None):
    """Use real host callbacks; no Native turn without independent policy evidence.

    origin_verifier resolves actual authenticated provenance for create_run.
    evidence_resolver(run, JudgmentRequest, DispatchAdmission) returns real
    TrustedEvidence, separately checking Human authorization and host-owned
    control state. It must cite the supplied retained dispatch admission. That
    admission is launch readiness; it never asserts a checked Native session.
    root must be a fresh, host-owned directory. Credential paths are metadata
    inventory only and remain in place. No credential value is read or copied.
    """
    model = resolve_model(model, effort)
    if (not callable(origin_verifier) or not callable(evidence_resolver)
            or (type(catalog) is not Catalog and not (_qualification and catalog is None))
            or not 1 <= timeout <= 180):
        raise ValueError('actual host resolvers, Catalog and bounded timeout required')
    root = Path(root).resolve()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    worker, control = root / 'worker', root / 'control'
    worker.mkdir(mode=0o700); control.mkdir(mode=0o700)
    for name in ('admissions', 'observations', 'checks'):
        (control / name).mkdir(mode=0o700)
    conditions = c.ExecutionConditions(model, 'devin.acp', str(worker), environment_ref or 'qualification:unmeasured',
                                       tuple(control_evidence_refs))
    job = job_for(run_id)
    action = c.Action('native.text.response', c.Scope((('workspace', str(worker)),
        ('environment', environment_ref), ('adapter', 'devin.acp'),
        ('response_sha256', hashlib.sha256(EXPECTED.encode()).hexdigest())), True))
    route = None
    def resolve(run_snapshot, request):
        if (request.conditions != conditions or request.action != action
                or request.method != 'bounded-fixed-response'
                or request.proposed_job not in (None, job)):
            raise ValueError('unbound acceptance judgment')
        admission = (route.bind(c.ExecuteRequest(c.AttemptRef(request.ref.run_id,
            request.ref.job_id, request.ref.attempt_id), job, conditions), run_snapshot.revision)
            if request.ref.attempt_id else route.assess(job, conditions, run_snapshot.revision))
        _write_once(control / 'admissions' / (admission.evidence_ref.split(':')[-1] + '.json'),
                    asdict(admission))
        evidence = evidence_resolver(run_snapshot, request, admission)
        if (type(evidence) is not TrustedEvidence or evidence.request_digest != body_digest(request)
                or admission.evidence_ref not in evidence.evidence_refs):
            raise ValueError('host evidence must bind current admission')
        return evidence
    store = ControlStore(control / 'control.db', verifier=origin_verifier, evidence=resolve)
    state = store.controller()
    template = DevinLaunchTemplate(conditions, Path(executable).resolve(), native_version,
        (control / 'control.db',), tuple(Path(p).resolve() for p in credential_files))
    descriptor_ref, descriptor = environment_definition(template, policy_ref=policy_ref)
    if environment_ref is not None and environment_ref != descriptor_ref:
        store.close()
        raise ValueError('exact measured environment definition required')
    if not _qualification and environment_ref is None:
        store.close()
        raise ValueError('Controller needs a previously qualified exact environment')
    environment_ref = descriptor_ref
    conditions = replace(conditions, environment_ref=descriptor_ref)
    action = replace(action, scope=c.Scope(tuple((key, descriptor_ref if key == 'environment' else value)
                                               for key, value in action.scope.dimensions), True))
    template = replace(template, conditions=conditions)
    _write_once(control / 'environment.json', {'environment_ref': descriptor_ref, 'descriptor': descriptor})
    route = DevinTextRoute(template, job, human_intent_ref=human_intent_ref, state=state,
                          expected_response=EXPECTED)
    result = {'evidence_kind': ('devin_use_qualification' if _qualification else
                               'devin_real_controller_acceptance'), 'run_id': run_id,
        'controller_exercised': not _qualification, 'catalog_promoted': False,
        'model': model, 'selection': selection(model), 'native_version': native_version, 'environment_ref': environment_ref,
        'installed_production': False, 'credential_values_read': False,
        'accepted': False, 'timeout': False, 'controller_state': None,
        'native_internal_isolation_claimed': False}

    class RetainObservation:
        # Delegation is the same product route; this observer changes no events,
        # request, judgments or permission. Only allowlisted host data is copied.
        def execute(self, request): return route.execute(request)
        def events(self, ref, after=None):
            events = route.events(ref, after)
            if any(isinstance(event, c.ResultEvent) for event in events):
                observation = route.observation(ref)
                safe = {key: observation.get(key) for key in
                        ('native_handoff_verified', 'fixed_response', 'cessation')}
                safe['ref'] = asdict(ref)
                _write_once(control / 'observations' / (ref.attempt_id + '.json'), safe)
            return events
        def stop(self, ref): return route.stop(ref)
        def respond(self, response): return route.respond(response)

    checks = []
    def inspect(check):
        refs = [check.result.ref] if check.result else [j.result.ref for j in check.jobs]
        observations = []
        for ref in refs:
            path = control / 'observations' / (ref.attempt_id + '.json')
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
                raise ValueError('bounded independent observation required')
            raw = path.read_bytes()
            observation = json.loads(raw)
            if observation.get('ref') != asdict(ref): raise ValueError('observation identity mismatch')
            observations.append((str(path.relative_to(root)), hashlib.sha256(raw).hexdigest(), observation))
        criteria = []
        for _, _, observed in observations:
            fixed, ceased = observed.get('fixed_response') or {}, observed.get('cessation') or {}
            criteria.extend((
                fixed.get('validated_eof') is True and fixed.get('overflow_or_unbound') is False
                    and fixed.get('observed_sha256') == hashlib.sha256(EXPECTED.encode()).hexdigest()
                    and fixed.get('observed_utf8_bytes') == len(EXPECTED.encode()),
                observed.get('native_handoff_verified') is True and ceased.get('tool_events') == 0,
                ceased.get('effective_model_verified') is True
                    and ceased.get('effective_model') == conditions.model
                    and ceased.get('requested_model') == conditions.model
                    and ceased.get('selection') == selection(conditions.model),
                ceased.get('native_stop_reason') == 'end_turn' and ceased.get('stdout_eof_validated') is True
                    and ceased.get('owned_exit_code') is not None and ceased.get('pending_permissions') == 0
                    and ceased.get('environment_ref') == conditions.environment_ref))
        passed = len(observations) == 1 and all(criteria)
        verdict = 'pass' if passed else 'fail'
        relative = 'control/checks/' + str(len(checks)) + '.json'
        receipt = {'kind': check.kind, 'request_digest': body_digest(check),
            'observations': observations, 'criteria_passed': criteria, 'verdict': verdict}
        _write_once(root / relative, receipt)
        checks.append(receipt)
        finding = Finding(verdict, (relative,))
        return CheckEvidence(body_digest(check), finding,
            tuple(Finding('pass' if value else 'fail', (relative,)) for value in criteria)
            if check.kind == 'job' else ())

    try:
        store.intake().create_run(run_id, human_intent, human_intent_ref)
        state.set_limits(run_id, Limits(jobs=1, attempts_per_job=1, attempts_per_pair=1),
                         state.get_run(run_id).revision)
        observer = RetainObservation()
        acceptance = Acceptance(inspect)
        if _qualification:
            # Qualification deliberately precedes Catalog promotion. The host
            # selects this exact bounded route; no Catalog/Controller selection
            # is claimed. Use real Judgment, host gates, state and independent AC.
            decision = store.judgment().judge(JudgmentRequest(c.QuestionRef(run_id, job.job_id),
                action, 'bounded-fixed-response', conditions, proposed_job=job))
            state.add_job(job, decision.decision_id, decision.state_revision)
            ref = c.AttemptRef(run_id, job.job_id, uuid4().hex)
            request = c.ExecuteRequest(ref, job, conditions)
            decision = store.judgment().judge(JudgmentRequest(c.QuestionRef(run_id, job.job_id, ref.attempt_id),
                action, 'bounded-fixed-response', conditions))
            state.begin_attempt(request, decision.decision_id, decision.state_revision)
            reply = observer.execute(request)
            state.record_execute(reply, state.get_attempt(ref).revision)
            deadline, cursor = time.monotonic() + timeout, None
            while reply.status == c.OperationStatus.ACCEPTED and time.monotonic() < deadline:
                events = observer.events(ref, cursor)
                for event in events:
                    state.record_event(event, state.get_attempt(ref).revision)
                    cursor = event.event_id
                attempt = state.get_attempt(ref)
                if attempt.result is not None:
                    stop = observer.stop(ref)
                    state.record_stop(stop, attempt.revision)
                    if stop.status != c.StopStatus.CONFIRMED: break
                    snapshot = state.get_run(run_id)
                    outcome = acceptance.job(snapshot, job, attempt.result)
                    state.record_job_goal(outcome, snapshot.revision)
                    result['accepted'] = outcome.completed
                    # The independent AC is the qualification result. Do not
                    # manufacture a Controller or Run Goal acceptance here.
                    result['qualification_ac'] = outcome.ac.verdict
                    break
                time.sleep(.025)
            else:
                if reply.status == c.OperationStatus.ACCEPTED:
                    result['timeout'] = True
                    stop = observer.stop(ref)
                    state.record_stop(stop, state.get_attempt(ref).revision)
                    result['timeout_stop_status'] = stop.status.value
        else:
            controller = Controller(run_id, state=state, judgment=store.judgment(), catalog=catalog,
                usage=UsageStore(), adapters={'devin.acp': observer}, acceptance=acceptance,
                planner=lambda *_: JobPlan(job, action, 'bounded-fixed-response', USE, (conditions,),
                                           explicit_model=model, explicit_adapter='devin.acp'))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                progress = controller.step()
                result['controller_state'] = progress.state.value
                if progress.state in c.TERMINAL or progress.state == c.State.WAITING_HUMAN: break
                time.sleep(.025)
            else:
                result['timeout'] = True
                if progress.active is not None:
                    stop = route.stop(progress.active)
                    state.record_stop(stop, state.get_attempt(progress.active).revision)
                    result['timeout_stop_status'] = stop.status.value
        current = state.get_run(run_id)
        result['controller_state'] = current.state.value
        result['accepted'] = (result['accepted'] if _qualification else
                              not result['timeout'] and current.state == c.State.COMPLETED)
        result['attempts'] = len(state.attempts(run_id))
        result['routing_records'] = len(state.history(run_id, 'routing_history'))
        result['job_goal_count'] = len(state.history(run_id, 'job_goals'))
        result['run_goal_count'] = len(state.history(run_id, 'run_goals'))
        result['check_verdicts'] = [check['verdict'] for check in checks]
    except Exception:
        result['failure'] = 'controller_acceptance_failed'
    finally:
        try:
            route.close()
        except Exception:
            result['accepted'] = False
            result['cleanup_failure'] = 'owned_route_cleanup_unconfirmed'
        result['model_turns_submitted'] = sum(int(host._transport is not None and host._transport.submitted)
                                              for _, _, host, _ in route._bound.values())
        result['owned_cli_reaped'] = all(host._transport is None or not host._transport.alive()
                                         for _, _, host, _ in route._bound.values())
        result['host_observations'] = [route.observation(ref) for ref in route._bound]
        store.close()
        _write_once(root / 'evidence.json', result)
    return result


def qualify(root, **host_inputs):
    """One explicitly authorized measurement + independent AC before Catalog.

    The caller must retain and review this result and its immutable environment
    definition. Successful qualification does not create a Catalog entry. Use
    its actual retained measurement/AC refs only in a later Controller run.
    """
    return run(root, **host_inputs, catalog=None, _qualification=True)


def reopen(root, run_id):
    """Separate-process readback of a terminal candidate; all new dispatch denied."""
    def refuse(*_): raise ValueError('reopen may not authorize or dispatch')
    store = ControlStore(Path(root) / 'control/control.db', verifier=refuse, evidence=refuse)
    try:
        state = store.controller()
        if state.get_run(run_id).state not in c.TERMINAL:
            raise ValueError('only terminal acceptance may be reopened without live attachment')
        controller = Controller(run_id, state=state, judgment=store.judgment(), catalog=Catalog(),
            usage=UsageStore(), adapters={}, acceptance=Acceptance(refuse), planner=refuse)
        progress = controller.step()
        return {'state': progress.state.value, 'routing_records': len(state.history(run_id, 'routing_history')),
                'ac_records': len(state.history(run_id, 'ac_history')),
                'run_goals': len(state.history(run_id, 'run_goals')), 'new_dispatches': 0}
    finally:
        store.close()
