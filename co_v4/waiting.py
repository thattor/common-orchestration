"""Human waiting orchestration through #157's trusted public handles only."""
from datetime import datetime, timedelta, timezone

from . import contracts as c
from .state import Conflict, NotFound
from .trace import Link, digest


def utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError('UTC timestamp required')
    return parsed


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def wait_link(ref, request_id):
    return "waiting:" + digest([ref.run_id, ref.job_id, ref.attempt_id, request_id])


class WaitingService:
    def __init__(self, controller, scheduler, *, clock, trace):
        self.controller, self.scheduler = controller, scheduler
        self.clock, self.trace = clock, trace

    def open(self, ref: c.QuestionRef, request_id: str, action: c.Action,
             decision: c.Decision, reason: str, method: str, *, expected_revision: int,
             deadline: str | None = None, judgment_ref: str) -> c.WaitingHuman:
        # A retry uses the original deadline. Never extend an existing request.
        try:
            previous = self.controller.get_wait(ref, request_id)
        except NotFound:
            previous = None
        deadline = deadline or (previous.deadline if previous else
                               timestamp(utc(self.clock()) + timedelta(hours=24)))
        utc(deadline)
        wait = c.WaitingHuman(ref, request_id, action, decision, reason, deadline)
        if previous is not None and previous != wait:
            raise Conflict('waiting request changed')
        summary = {'request_id': request_id, 'target': c.approval_target(ref.run_id, action),
                   'decision': decision.value, 'reason': reason, 'deadline': deadline}
        # Reject unsafe publication before opening anything through this helper.
        self.trace.policy.check(summary)
        result = self.controller.open_wait(wait, method, expected_revision, judgment_ref)
        self.trace.append(wait_link(ref, request_id), 'waiting', ref,
            at=self._observed_at(wait_link(ref, request_id)),
            summary=summary, links=(Link('judgment', judgment_ref),))
        return result

    def _observed_at(self, record_id):
        for record in self.trace.records():
            if record['record_id'] == record_id:
                return record['at']
        return timestamp(utc(self.clock()))

    def expire(self, ref: c.QuestionRef, request_id: str, *, expected_revision: int):
        result = self.scheduler.expire_wait(ref, request_id, expected_revision)
        if result is None:  # A committed timely receipt was applied instead.
            return None
        self.trace.append('timeout:' + wait_link(ref, request_id), 'timeout', ref,
            at=self._observed_at('timeout:' + wait_link(ref, request_id)),
            summary={'deadline': result.deadline, 'reason': 'human_confirmation_timeout',
                     'approval': False, 'rejection': False},
            links=(Link('waiting', wait_link(ref, request_id)),))
        return result
