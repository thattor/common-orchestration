"""Read-only human summary of terminal, trusted Controller state.

This optional presentation does not judge acceptance or change a Contract.
Only fixed labels and counts leave the store: even identifiers, reasons and
evidence references can carry sensitive text. The host owns publication and
must serialize this read with state writes, as for other Controller views.
"""
from collections import Counter
from dataclasses import replace

from . import contracts as c
from .ac import CheckRequest
from .state import ControllerState, body_digest


_REASONS = {
    'human_goal_verified': 'independent Run Goal verified',
    'run_job_limit': 'Run Job limit reached',
    'job_attempt_limit': 'Job Attempt limit reached',
    'no_plan_for_unmet_goal': 'no plan for the unmet Goal',
    'no_eligible_route_or_pair_limit': 'no eligible route or pair limit reached',
    'controller_error': 'Controller error',
    'human_stop': 'human stop requested',
    'human_confirmation_timeout': 'human confirmation timed out (not a rejection)',
    'integrity_violation': 'integrity violation',
    'native_constraint': 'Native constraint',
    'relay_not_accepted': 'confirmation relay not accepted',
    'output_unavailable': 'required Run output unavailable',
    'output_integrity_failure': 'output integrity failure',
    'output_policy_failure': 'output policy failure',
}
_VERDICTS = ('pass', 'fail', 'incomplete', 'blocked', 'not_run',
             'not_applicable', 'missing')


def render_run_summary(state: ControllerState, run_id: str) -> str:
    """Return five lines derived from a persisted Completed/Failed/Error Run.

    Raises ValueError for a nonterminal Run; store read failures propagate.
    No execution, verification, state mutation, Trace export, or network IO.
    Worker Results and independent AC/Goals remain distinct. Counts include
    all Attempts, including unsuccessful retries, rather than only the last.
    Retained evidence references are counted, never interpreted or published;
    their presence does not establish live verification or resolve artifacts.
    """
    run = state.get_run(run_id)
    if type(run.state) is not c.State or run.state not in c.TERMINAL:
        raise ValueError('terminal Run required for summary')
    attempts = state.attempts(run_id)
    jobs = state.history(run_id, 'job_goals')
    goals = state.history(run_id, 'run_goals')
    results = Counter(a.result.status for a in attempts if a.result is not None)
    # Settlement comes only from the state-owned predicate ('never_started',
    # 'native' or None/held); absence of a Result alone is not settlement.
    settlements = [state.attempt_settlement(a.ref) for a in attempts]
    not_started = settlements.count('never_started')
    # A NeverStarted Attempt never enters AC; it is 'not_applicable' in the
    # Checks tally, not 'missing' or a fabricated verdict.
    acs = Counter(a.ac.verdict if a.ac is not None else
                ('not_applicable' if settled == 'never_started' else 'missing')
                for a, settled in zip(attempts, settlements))
    # attempts() preserves reservation order, not mutable update revisions.
    latest = {a.ref.job_id: a for a in attempts}
    accepted = set()
    for finding in jobs:
        attempt = latest.get(finding.job.job_id)
        if (finding.completed and finding.job in run.derived_interpretation
                and attempt is not None and finding.result == attempt.result
                and finding.ac == attempt.ac and finding.ac.ref == attempt.ref
                and finding.ac.evidence_refs and finding.goal.evidence_refs
                and attempt.stop_reply is not None
                and attempt.stop_reply.status == c.StopStatus.CONFIRMED):
            accepted.add(finding.job.job_id)
    goal = goals[-1] if goals else None
    # finalize_run adds one revision. Revision alone is insufficient: some
    # public store methods allow later writes to a terminal Run. Bind the
    # digest to a pre-final, nonterminal snapshot, never a post-terminal check.
    checked_jobs = tuple(g for g in jobs if g.completed)
    current_goal = (goal is not None and goal.run_id == run.run_id
                    and goal.revision == run.revision - 1 and any(
        goal.request_digest == body_digest(CheckRequest('run', replace(
            run, state=previous, revision=goal.revision, final_reason=None,
            cessation_confirmed=None, output_selection=None), jobs=checked_jobs))
        for previous in (c.State.PENDING, c.State.RUNNING, c.State.WAITING_HUMAN)))
    goal_label = ('missing' if goal is None else
                  goal.finding.verdict if current_goal else 'stale')
    goal_evidence = len(goal.finding.evidence_refs) if goal is not None else 0
    ac_evidence = sum(len(a.ac.evidence_refs) for a in attempts if a.ac is not None)
    ac_label = ', '.join(f'{verdict}={acs[verdict]}' for verdict in _VERDICTS
                         if acs[verdict]) or 'none recorded'

    cautions = []
    if run.state != c.State.COMPLETED:
        cautions.append('Run did not complete')
    if (any(a.result is None or a.ac is None or a.ac.verdict != 'pass' for a in attempts)
            or len(accepted) != len(run.job_ids)):
        cautions.append('unaccepted work remains in the history')
    if (not current_goal or not goal_evidence
            or any(a.ac is not None and a.ac.verdict == 'pass'
                   and not a.ac.evidence_refs for a in attempts)):
        cautions.append('acceptance evidence missing or stale')
    if (any(value is None for value in settlements)
            or run.cessation_confirmed is False):
        cautions.append('cessation unconfirmed')
    if run.stop_requested:
        cautions.append('stop requested')
    if run.state == c.State.COMPLETED and (
            goal_label != 'pass' or len(accepted) != len(run.job_ids) or not jobs):
        cautions.append('stored completion lacks matching acceptance')
    caution_label = '; '.join(cautions) or 'none indicated by retained records'
    reason = _REASONS.get(run.final_reason, 'reason retained in protected state')
    return '\n'.join((
        f'Run: {run.state.value.capitalize()} — {reason}.',
        f'Work: {len(run.job_ids)} Jobs; {len(attempts)} Attempts; '
        f'{len(accepted)} Jobs with independent AC and Goal pass.',
        f'Worker Results: completed={results[c.State.COMPLETED]}, '
        f'failed={results[c.State.FAILED]}, error={results[c.State.ERROR]}, '
        f'not_started={not_started}, '
        f'missing={sum(a.result is None for a in attempts) - not_started} (not AC verdicts).',
        f'Checks: Attempt AC {ac_label}; Run Goal={goal_label}; '
        f'retained evidence refs: AC={ac_evidence}, Run Goal={goal_evidence}.',
        f'Cautions: {caution_label}.',
    ))
