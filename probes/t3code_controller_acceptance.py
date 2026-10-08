"""Private, one-Job Controller verification after reviewed real T3 qualification.

The host operator supplies the prior measurement hash and authorization reference.
These are trusted host attestations, never Worker-provided credentials or grants.
This exercises Controller ingestion, not an external Human Gateway integration.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.adapter_capacity import NativeAdapterPools, PRIMARY_ADAPTERS, MAX_CONCURRENT
from co_v4.adapters.t3code import ADAPTER
from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.controller import Controller, JobPlan
from co_v4.judgment import TrustedEvidence
from co_v4.state import ControlStore, IngressReceipt, Limits, body_digest, create_run_body
from co_v4.usage import UsageStore

USE = UseCase('other', 'owned T3 fixed-response text')
EXPECTED = 'T3_NATIVE_OK'


def reviewed_qualification(path, expected_sha, environment_ref, descriptor):
    raw = Path(path).read_bytes()
    if len(raw) > 2 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError('reviewed qualification hash differs')
    value = json.loads(raw)
    if (value.get('environment_ref') != environment_ref
            or value.get('environment_descriptor') != descriptor
            or value.get('status') != 'passed' or value.get('result_state') != 'completed'
            or value.get('text') != EXPECTED or value.get('stop_status') != 'confirmed'
            or value.get('native_completed') is not True or value.get('server_reaped') is not True
            or value.get('local_service_auth_state_deleted') is not True
            or not value.get('cessation_evidence_ref')):
        raise ValueError('prior exact-environment Native qualification missing')
    children = value.get('owner', {}).get('children', [])
    selected = [v for v in children if v.get('native_turn_id')]
    if (len(selected) != 1 or not selected[0].get('config_verified')
            or not selected[0].get('subscription_verified') or not selected[0].get('native_completed') or not children
            or any(v.get('failed') or v.get('escaped_group') or not all(v.get(k) is True
                for k in ('stdout_eof', 'stderr_eof', 'reaped', 'done')) for v in children)):
        raise ValueError('prior original Native lifecycle or effective controls missing')
    return value


def run(*, root, request, make_adapter, admission, owner, qualification_path,
        qualification_sha256, descriptor, authorization_ref):
    if not isinstance(authorization_ref, str) or not authorization_ref.strip():
        raise ValueError('actual trusted host authorization reference required')
    qualification = reviewed_qualification(qualification_path, qualification_sha256,
        request.conditions.environment_ref, descriptor)
    conditions, job = request.conditions, request.job
    if len(job.acceptance_criteria) != 3:
        raise ValueError('three independently checked criteria required')
    control = root / 'control'
    control.mkdir(mode=0o700)
    measurement = 'sha256:' + qualification_sha256
    verification = Verification(conditions.model, ADAPTER, USE, conditions.environment_ref,
        't3-source:' + descriptor['source_revision'],
        'implementation:' + body_digest(descriptor['implementation']), measurement,
        'reviewed-owned-text-criteria:' + qualification_sha256)
    catalog = Catalog((CatalogEntry(conditions.model, ADAPTER, {USE: 1}, (verification,)),))
    action = c.Action('native.text.response', c.Scope((('adapter', ADAPTER),
        ('workspace', conditions.workspace), ('environment', conditions.environment_ref),
        ('response_sha256', hashlib.sha256(EXPECTED.encode()).hexdigest())), True))
    intent = 'Verify one owned T3 fixed-response Native turn through Controller and release its capacity only after original process cessation.'
    ingress = 'trusted-host-invocation:' + authorization_ref
    receipt = IngressReceipt('authorized-local-host-operator', authorization_ref,
        body_digest(create_run_body(job.run_id, intent)), datetime.now(timezone.utc).isoformat(),
        Limits(jobs=1, attempts_per_job=1, attempts_per_pair=1))
    checks, bound, child = [], None, None
    report = {'controller_exercised': False, 'human_gateway_exercised': False,
        'catalog_promoted': False, 'authorization_ref': authorization_ref,
        'qualification_sha256': qualification_sha256, 'capacity_limit': MAX_CONCURRENT,
        'capacity_peak': 0, 'accepted': False}
    def resolve(snapshot, judgment):
        if (judgment.conditions != conditions or judgment.action != action
                or judgment.method != 'bounded-fixed-response'
                or judgment.proposed_job not in (None, job) or judgment.confirmation is not None
                or not admission()):
            raise ValueError('unbound or unverified dispatch admission')
        return TrustedEvidence(body_digest(judgment), ingress,
            (measurement, conditions.environment_ref, 'owned-broker:mandatory-before-first-turn'),
            operation_key='owned-t3-fixed-response:' + body_digest(action),
            intent_contained=True, intent_authorizes=True,
            conditions_verified=True, protection_verified=True)
    store = ControlStore(control / 'control.db', verifier=lambda ref: receipt if ref == ingress else None,
        evidence=resolve)
    state = store.controller()
    def factory(execution):
        nonlocal bound, child
        if bound is not None or execution.job != job or execution.conditions != conditions:
            raise ValueError('one exact Controller Attempt required')
        bound = execution
        report['capacity_peak'] = pools.ledger.count(ADAPTER)
        child = make_adapter(execution)
        return child
    def disabled_factory(_):
        raise ValueError('other Native providers are disabled in this probe')
    pools = NativeAdapterPools(canonical_ledger=control / 'capacity.sqlite',
        factories={**{name: disabled_factory for name in PRIMARY_ADAPTERS}, ADAPTER: factory})
    def inspect(check):
        refs = [check.result.ref] if check.result else [j.result.ref for j in check.jobs]
        criteria = [False, False, False]
        if bound is not None and refs == [bound.ref] and child is not None:
            stopped = child.stop(bound.ref)
            facts = owner.observation()
            selected = [v for v in facts['children'] if v['native_turn_id']]
            try:
                criteria[0] = child.text_output(bound.ref) == EXPECTED
            except ValueError:
                pass
            criteria[1] = (len(selected) == 1 and selected[0]['config_verified']
                and selected[0]['subscription_verified'] and selected[0]['native_completed'] and not selected[0]['failed'])
            criteria[2] = (stopped.status == c.StopStatus.CONFIRMED
                and bool(stopped.evidence_ref) and bool(facts['children'])
                and all(v['stdout_eof'] and v['stderr_eof'] and v['reaped']
                    and v['done'] and not v['escaped_group'] for v in facts['children']))
        verdict = 'pass' if all(criteria) else 'fail'
        path = control / ('ac-' + str(len(checks)) + '.json')
        path.write_text(json.dumps({'request_digest': body_digest(check), 'kind': check.kind,
            'criteria': criteria, 'verdict': verdict}) + '\n')
        checks.append(verdict)
        finding = Finding(verdict, (str(path),))
        return CheckEvidence(body_digest(check), finding,
            tuple(Finding('pass' if x else 'fail', finding.evidence_refs) for x in criteria)
            if check.kind == 'job' else ())
    try:
        store.intake().create_run(job.run_id, intent, ingress)
        state.set_limits(job.run_id, Limits(1, 1, 1), state.get_run(job.run_id).revision)
        controller = Controller(job.run_id, state=state, judgment=store.judgment(), catalog=catalog,
            usage=UsageStore(), adapters=pools, acceptance=Acceptance(inspect),
            planner=lambda *_: JobPlan(job, action, 'bounded-fixed-response', USE, (conditions,),
                explicit_model=conditions.model, explicit_adapter=ADAPTER))
        report['controller_exercised'] = True
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            progress = controller.step()
            if progress.state in c.TERMINAL or progress.state == c.State.WAITING_HUMAN:
                break
            time.sleep(.05)
        else:
            report['timeout'] = True
        report.update(controller_state=state.get_run(job.run_id).state.value,
            controller_reason=state.get_run(job.run_id).final_reason,
            last_progress_reason=progress.reason,
            attempts=len(state.attempts(job.run_id)),
            job_goal_count=len(state.history(job.run_id, 'job_goals')),
            run_goal_count=len(state.history(job.run_id, 'run_goals')),
            check_verdicts=checks, capacity_final=pools.ledger.count(ADAPTER),
            other_capacity={name: pools.ledger.count(name) for name in PRIMARY_ADAPTERS})
        report['accepted'] = (report['controller_state'] == 'completed'
            and report['attempts'] == report['job_goal_count'] == report['run_goal_count'] == 1
            and checks == ['pass', 'pass'] and report['capacity_peak'] == 1
            and report['capacity_final'] == 0 and not report.get('timeout'))
        if bound is not None and child is not None:
            stopped = child.stop(bound.ref)
            terminal = next((e.result for e in child.events(bound.ref) if isinstance(e, c.ResultEvent)), None)
            report.update(result_state=terminal.status.value if terminal else None,
                stop_status=stopped.status.value, stop_reason=stopped.reason,
                cessation_evidence_ref=stopped.evidence_ref, text=child.text_output(bound.ref))
        return report
    finally:
        pools.close()
        store.close()
        (control / 'controller-result.json').write_text(json.dumps(report, indent=2) + '\n')
