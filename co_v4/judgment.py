"""One conservative judgment path for preflight and Native confirmations.

TrustedEvidence is resolved by host code, never supplied by a Worker or model.
The resolver owns policy, intent containment and actual protection observations;
this module cannot infer those facts from prose, file modes or evidence IDs.
"""
from dataclasses import dataclass
from uuid import uuid4

from . import contracts as c
from .state import (Conflict, InvalidTransition, StoreUnavailable, _id,
                    _immutable, _never_started, _ref, _time, body_digest)


@dataclass(frozen=True)
class JudgmentRequest:
    ref: c.QuestionRef
    action: c.Action
    method: str
    conditions: c.ExecutionConditions
    confirmation: c.Confirmation | None = None
    proposed_job: c.Job | None = None

    def __post_init__(self):
        _immutable(self)
        _ref(self.ref); _id(self.method)
        for value in (self.conditions.model, self.conditions.adapter,
                      self.conditions.workspace, self.conditions.environment_ref):
            _id(value)
        if type(self.conditions.control_evidence_refs) is not tuple:
            raise ValueError('immutable evidence refs required')
        if self.confirmation is not None:
            callback = self.confirmation
            _id(callback.request_id)
            if type(callback.decision) is not c.Decision or type(callback.can_respond) is not bool:
                raise ValueError('typed Native decision and response capability required')
            if (self.ref != c.QuestionRef(callback.ref.run_id, callback.ref.job_id, callback.ref.attempt_id)
                    or callback.requested_action != self.action or self.proposed_job is not None):
                raise ValueError('callback correlation mismatch')
        if self.proposed_job is not None:
            job = self.proposed_job
            if (self.ref != c.QuestionRef(job.run_id, job.job_id)
                    or type(job.acceptance_criteria) is not tuple):
                raise ValueError('proposed Job correlation/immutability mismatch')


@dataclass(frozen=True)
class JudgmentRecord:
    decision_id: str
    decision: c.Decision
    ref: c.QuestionRef
    action: c.Action
    method: str
    reason: str
    evidence_refs: tuple[str, ...]
    state_revision: int


@dataclass(frozen=True)
class TrustedEvidence:
    """Host resolver receipt, bound to the entire request and current policy.

    operation_key identifies semantic effect/target across renamed Jobs, models,
    routes and execution environments. It must come from a trusted normalizer,
    not method text or a caller-chosen label. Unknown facts default closed.
    protection_verified includes authenticated ingress, role-owned CO state
    commands and the effective controls required at this route's current phase.
    Before execution, trusted dispatch admission must bind the exact Job,
    conditions and revision to the checked host owner and mandatory Native gates.
    This permits dispatch through that bound route; it does not attest a Native
    session that has not started. The exact-session verifier must still pass
    before the first prompt, and only then is native_handoff_verified true.
    Dispatch admission alone supplies neither Human authority nor the other
    required protection evidence. Under NATIVE-HANDOFF.md, 0.3 does not require
    complete OS containment of Native internal tools. A synthetic resolver proves
    only policy mechanics.
    """
    request_digest: str
    policy_ref: str
    evidence_refs: tuple[str, ...] = ()
    operation_key: str | None = None
    hard_deny: bool = False
    requires_confirmation: bool = False
    intent_contained: bool | None = None
    intent_authorizes: bool = False
    conditions_verified: bool = False
    protection_verified: bool = False


def evaluate(store, data, request, decision_id):
    run = data['run']
    try:
        evidence = store._evidence(run, request)
        if (type(evidence) is not TrustedEvidence or evidence.request_digest != body_digest(request)
                or not evidence.policy_ref or type(evidence.evidence_refs) is not tuple
                or any(not isinstance(v, str) or not v for v in evidence.evidence_refs)
                or any(type(v) is not bool for v in (evidence.hard_deny,
                    evidence.requires_confirmation, evidence.intent_authorizes,
                    evidence.conditions_verified, evidence.protection_verified))
                or (evidence.intent_contained is not None and type(evidence.intent_contained) is not bool)):
            raise ValueError('unbound or malformed trusted evidence')
    except Exception as exc:
        raise StoreUnavailable('trusted judgment evidence unavailable') from exc

    refs = (evidence.policy_ref,) + evidence.evidence_refs

    def result(decision, reason, extra=()):
        return (JudgmentRecord(decision_id, decision, request.ref, request.action,
                               request.method, reason, refs + extra, run.revision), evidence)

    callback = request.confirmation
    # Absolute prohibitions precede approvals and unresolved target checks.
    if evidence.hard_deny or (callback and callback.decision == c.Decision.DENY):
        return result(c.Decision.DENY, 'hard_deny')
    if callback and not callback.can_respond:
        return result(c.Decision.DENY, 'native_constraint')
    if run.stop_requested:
        return result(c.Decision.DENY, 'run_stop_requested')
    if (not request.action.scope.known or not isinstance(evidence.operation_key, str)
            or not evidence.operation_key.strip()):
        return result(c.Decision.UNDETERMINED, 'unresolved_target')

    if request.proposed_job is not None:
        if evidence.intent_contained is not True:
            return result(c.Decision.UNDETERMINED, 'job_containment_unproven')
        return result(c.Decision.NORMAL, 'job_contained', (run.authenticated_origin_ref,))

    store._job(data, request.ref)
    if not evidence.conditions_verified or not evidence.protection_verified or not evidence.evidence_refs:
        return result(c.Decision.UNDETERMINED, 'environment_or_protection_unproven')
    if callback:
        if data['callbacks'].get(callback.request_id) != callback:
            raise Conflict('callback has not been recorded with this identity')
        attempt = store._attempt(data, callback.ref)
        if attempt.conditions != request.conditions:
            raise Conflict('callback environment differs from Attempt')
        if (attempt.result is not None or attempt.stop_reply is not None
                or _never_started(data, attempt)):
            return result(c.Decision.UNDETERMINED, 'attempt_not_resumable')
        waiting = data['waits'].get(callback.request_id)
        if waiting and (waiting['closed'] == 'timeout'
                        or (waiting['closed'] is None and _time(store.now()) >= _time(waiting['wait'].deadline))):
            return result(c.Decision.UNDETERMINED, 'human_confirmation_timeout')
    elif request.ref.attempt_id is not None:
        # A preflight request for an already reserved Attempt must not dispatch it again.
        from .state import _attempt_key
        if _attempt_key(request.ref) in data['attempts']:
            return result(c.Decision.UNDETERMINED, 'attempt_already_reserved')

    for rejection, operation in data['rejections']:
        if operation == evidence.operation_key or c.same_target(rejection.action, request.action):
            return result(c.Decision.UNDETERMINED, 'human_rejected_operation', (rejection.human_response_ref,))
    unanswered = [(timeout, data['waits'][timeout.request_id]['timeout_revision'])
                  for timeout, operation in data['timeouts']
                  if operation == evidence.operation_key or c.same_target(timeout.action, request.action)]
    # An unanswered question cannot be bypassed by starting a renamed Job/route.
    for waiting in data['waits'].values():
        if waiting['closed'] is None and (waiting['operation_key'] == evidence.operation_key
                or c.same_target(waiting['wait'].action, request.action)):
            return result(c.Decision.CONFIRM, 'awaiting_human', (waiting['wait'].request_id,))

    for approval, conditions in reversed(data['approvals']):
        answer = data['answers'].get(approval.human_response_ref)
        if (answer and answer[2].disposition == 'applied'
                and answer[0].answer == c.HumanAnswer.APPROVE
                and answer[2].approval_id == approval.approval_id
                and conditions == request.conditions
                and all(answer[2].revision > revision for _, revision in unanswered)
                and approval.covers(run.run_id, request.action)):
            return result(c.Decision.NORMAL, 'authenticated_approval', (approval.approval_id, approval.human_response_ref))
    if unanswered:
        return result(c.Decision.UNDETERMINED, 'unanswered_operation', tuple(t.request_id for t, _ in unanswered))
    if evidence.requires_confirmation:
        return result(c.Decision.CONFIRM, 'policy_confirmation_required')
    if evidence.intent_authorizes:
        return result(c.Decision.NORMAL, 'authenticated_intent', (run.authenticated_origin_ref,) +
                      tuple(r.response_id for r in run.human_instructions))
    return result(c.Decision.UNDETERMINED, 'intent_authorization_unproven')


class Judgment:
    def __init__(self, store): self._store = store

    def judge(self, request: JudgmentRequest) -> JudgmentRecord:
        if type(request) is not JudgmentRequest:
            raise ValueError('JudgmentRequest required')
        s = self._store
        with s._tx(request.ref.run_id) as data:
            if data['run'].state in c.TERMINAL:
                raise InvalidTransition('run_terminal')
            record, evidence = evaluate(s, data, request, str(uuid4()))
            data['decisions'][record.decision_id] = (request, record, evidence)
            return record
