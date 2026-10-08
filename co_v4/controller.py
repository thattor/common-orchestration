"""Finite, single-owner Controller over the public #157/#158/#159 APIs.

Host code supplies planning, independent verification and execution conditions.
Call step() serially: one bounded poll or planning/dispatch operation per call.
No background loop or development orchestration is installed here.

Protected checkpoints and public state journals support serialized host restart.
Ambiguous dispatch/relay is reconciled through cessation, never automatic resend.
The host must reattach an Adapter able to address the same Attempt; unsupported
Native recovery stays blocked and does not create another execution.
"""
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Callable, Mapping
from uuid import uuid4

from . import contracts as c
from .failures import GLOBAL_FAILURES
from .ac import Acceptance, JobGoal, RunGoal
from .adapter_capacity import (CHILD_LACKS_COLLECTOR, CapacityError,
                               PooledAdapter)
from .catalog import Catalog, UseCase
from .judgment import Judgment, JudgmentRequest
from .output_store import IntegrityError, OutputRejected
from .routing import Assessment, select_route
from .state import (ControllerState, Conflict, DigestConflict,
                    IntegrityViolation, InvalidTransition, RoutingRecord,
                    body_digest, commit_execute_receipt)
from .trace import canonical
from .usage import UsageStore


POLICY_TERMINAL_REASONS = frozenset(
    {'provider_refusal', 'content_filter', 'protocol_violation'})

# Host-side NeverStarted evidence for an Attempt admitted and then stopped
# before any Native wire call; matches the pool-ledger receipt shape.
STOPPED_BEFORE_EXECUTE = 'controller:stopped-before-execute'


@dataclass(frozen=True)
class JobPlan:
    job: c.Job
    action: c.Action
    method: str
    use_case: UseCase
    conditions: tuple[c.ExecutionConditions, ...]
    explicit_model: str | None = None
    explicit_adapter: str | None = None
    usage_window: str | None = None

    def __post_init__(self):
        if (not self.method.strip() or type(self.conditions) is not tuple
                or not self.conditions or type(self.job.acceptance_criteria) is not tuple
                or any(not isinstance(v, str) or not v.strip()
                       for v in self.job.acceptance_criteria)
                or len({(v.model, v.adapter) for v in self.conditions}) != len(self.conditions)):
            raise ValueError("immutable Job and distinct execution combinations required")


@dataclass(frozen=True)
class Progress:
    run_id: str
    state: c.State
    reason: str
    jobs: tuple[JobGoal, ...]
    goal: RunGoal | None
    active: c.AttemptRef | None
    cessation_confirmed: bool | None = None


@dataclass(frozen=True)
class Transition:
    kind: str
    ref: c.AttemptRef
    previous: c.AttemptRef | None = None


@dataclass(frozen=True)
class ControllerCheckpoint:
    plan: JobPlan | None
    active: c.AttemptRef | None
    cursor: str | None
    callbacks: tuple[c.Confirmation, ...]
    answered: tuple[str, ...]
    waits: tuple[tuple[str, str], ...]
    stopping: str | None
    halted: str | None
    handled_waits: tuple[str, ...]
    replans: int
    pending_io: str | None
    lifecycle_ref: str | None = None


class Controller:
    """Trusted host composition only, never construct from Worker JSON.

    planner(run, completed_jobs, latest_run_goal) returns a new JobPlan or None.
    All inserted Jobs are required. Failed AC can retry/reroute that same Job;
    after passing a Job, an unmet Run Goal can cause a different next Job.
    Blocked/not_run AC hands off without spending another Worker Attempt.
    replanner(run, current_plan, wait_details) may change method/conditions/action
    while preserving the exact required Job. Without it, planner is called again.
    Each Job has at most limits.attempts_per_job continuation planning calls;
    these calls do not reset execution budgets or create human authority.
    Authenticated human intake and timeout scheduling remain with #157/#160.
    The host must serialize intake/stop/dispatch with actual Native IO; a Python
    lock and a Judgment receipt alone are not OS isolation or a distributed lease.
    """
    def __init__(self, run_id: str, *, state: ControllerState, judgment: Judgment,
                 catalog: Catalog, usage: UsageStore, adapters: Mapping[str, c.Adapter],
                 acceptance: Acceptance, planner: Callable, replanner: Callable | None = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 max_usage_age: timedelta = timedelta(minutes=5),
                 output_store=None):
        run = state.get_run(run_id)
        if max_usage_age < timedelta(0):
            raise ValueError("nonnegative Usage age required")
        self.run_id, self.state, self.judgment = run_id, state, judgment
        self.catalog, self.usage, self.adapters = catalog, usage, dict(adapters)
        self._lifecycle_policy = catalog.lifecycle
        self._lifecycle_ref = catalog.lifecycle.ref if catalog.lifecycle else None
        pools = [(key, adapter) for key, adapter in self.adapters.items() if isinstance(adapter, PooledAdapter)]
        if (any(key != adapter.adapter for key, adapter in pools)
                or len({adapter.ledger.path for _, adapter in pools}) > 1):
            raise ValueError("all pooled Adapters must share the canonical host ledger")
        self.acceptance, self.planner, self.replanner = acceptance, planner, replanner
        self.clock, self.max_usage_age = clock, max_usage_age
        self.output_store = output_store
        self._lock = Lock()
        self._plan = None
        self._attempts: list[c.AttemptRef] = []
        self._jobs: list[JobGoal] = []
        self._goal = None
        self._active = None
        self._cursor = None
        self._callbacks: dict[str, c.Confirmation] = {}
        self._answered: set[str] = set()
        self._waits: dict[str, str] = {}
        self._records = []
        self._stopping = None
        self._terminal = None
        self._halted = None
        self._handled_waits = set()
        self._replans = 0
        self._pending_io = None
        self._unsaved_label = None
        self._recover(run)
        # Pin before any plan/Attempt can survive a crash. Existing checkpoints
        # keep their original policy identity, including through cleanup.
        if self._lifecycle_ref is not None and self.state.checkpoint(self.run_id) is None:
            self._save()

    def _save(self):
        snapshot = ControllerCheckpoint(self._plan, self._active, self._cursor,
            tuple(self._callbacks.values()), tuple(sorted(self._answered)),
            tuple(sorted(self._waits.items())), self._stopping, self._halted,
            tuple(sorted(self._handled_waits)), self._replans, self._pending_io, self._lifecycle_ref)
        self.state.save_checkpoint(self.run_id, snapshot, self.state.get_run(self.run_id).revision)
        self._unsaved_label = None

    def _recover(self, run):
        saved = self.state.checkpoint(self.run_id)
        outcomes = self.state.history(self.run_id, 'job_goals')
        self._jobs = [g for g in outcomes if g.completed]
        goals = self.state.history(self.run_id, 'run_goals')
        self._goal = goals[-1] if goals else None
        if run.state in c.TERMINAL:
            self._terminal = Progress(self.run_id, run.state, run.final_reason,
                                      tuple(self._jobs), self._goal, None, run.cessation_confirmed)
            # Class-O journal: checkpoints are non-authoritative, so a stale
            # or tampered checkpoint is replaced with canonical content
            # derived from committed Run state (O2/O3). The pinned lifecycle
            # identity is preserved; no proof-domain field changes.
            pinned = saved.lifecycle_ref if saved is not None else self._lifecycle_ref
            snapshot = ControllerCheckpoint(None, None, None, (), (), (),
                None, None, (), 0, None, pinned)
            if saved != snapshot:
                try:
                    self.state.save_checkpoint(self.run_id, snapshot, run.revision)
                except Conflict:
                    pass  # A committed write won; the next open replaces it.
            return
        if saved:
            self._lifecycle_ref = saved.lifecycle_ref
            self._plan, self._active, self._cursor = saved.plan, saved.active, saved.cursor
            self._callbacks = {c.request_id: c for c in saved.callbacks}
            self._answered, self._waits = set(saved.answered), dict(saved.waits)
            self._stopping, self._halted = saved.stopping, saved.halted
            self._handled_waits, self._replans = set(saved.handled_waits), saved.replans
            self._pending_io = saved.pending_io
        complete = {g.job.job_id for g in self._jobs}
        if self._plan is not None and self._plan.job.job_id in complete:
            self._plan = None
        if self._plan is None:
            plans = [p for p in self.state.plans(self.run_id) if p.job.job_id not in complete]
            self._plan = plans[-1] if plans else None
        if run.job_ids and self._plan is None and set(run.job_ids) != complete:
            raise InvalidTransition('recovery requires a persisted plan for every unfinished Job')
        attempts = self.state.attempts(self.run_id)
        checked = {g.result.ref for g in outcomes}
        checked |= {f.result.ref for f in self.state.history(
            self.run_id, 'job_failures')}
        released = set(self.state.history(self.run_id, 'released_attempts'))
        # Same authority as every settlement read: the committed request-
        # matched receipt predicate, not raw history field presence.
        unstarted = {a.ref for a in attempts
                     if self.state.attempt_settlement(a.ref) == 'never_started'}
        unresolved = [a for a in attempts if a.ref not in checked and a.ref not in released
                      and a.ref not in unstarted]
        if len(unresolved) > 1:
            raise InvalidTransition('single-owner recovery found multiple unresolved Attempts')
        if unresolved:
            if self._active != unresolved[-1].ref:
                # The restored cursor/callbacks bound the previously tracked
                # Attempt; a different unresolved admission starts with a
                # clean per-Attempt drain state, same as _dispatch.
                self._cursor, self._callbacks, self._answered = None, {}, set()
            self._active = unresolved[-1].ref
        elif self._active in checked or self._active in released or self._active in unstarted:
            if self._active in released and self._stopping in ('human_continuation', 'human_confirmation_timeout'):
                self._stopping = None
            self._active = None
        if self._plan and self._halted != 'integrity_violation':
            # L2: a restored fatal latch is never overwritten by recovery.
            latest = next((g for g in reversed(outcomes) if g.job == self._plan.job), None)
            if latest is not None and latest.ac.verdict in ('blocked', 'not_run'):
                self._halted = 'job_ac_' + latest.ac.verdict
        if self._plan:
            self._attempts = [a.ref for a in attempts if a.ref.job_id == self._plan.job.job_id]
        if self._active:
            # Authoritative event journal covers a crash after recording an event
            # but before checkpointing the cursor/callbacks.
            events = [e for e in self.state.history(self.run_id, 'events') if e.ref == self._active]
            if events:
                self._cursor = events[-1].event_id
                self._callbacks.update((e.confirmation.request_id, e.confirmation)
                                       for e in events if isinstance(e, c.ConfirmationEvent))
            receipt = self.state.execute_receipt(self._active)
            if (receipt is None or (self._pending_io and self._pending_io != 'execute')
                    or (receipt.status != c.OperationStatus.ACCEPTED
                        and self.state.attempt_settlement(self._active) != 'never_started')):
                self._stopping = 'recovery_ambiguous_send'
            self._pending_io = None
        for wait in self.state.waits(self.run_id):
            if wait.request_id not in self._waits.values() and wait.request_id not in self._handled_waits:
                self._waits['recovered:' + wait.request_id] = wait.request_id
            if self.state.wait_details(wait.ref, wait.request_id).disposition is None:
                key = wait.request_id if wait.ref.attempt_id else ('preflight:' + wait.ref.job_id + ':' +
                    body_digest(self.state.wait_details(wait.ref, wait.request_id).conditions))
                self._waits[key] = wait.request_id

    def _continuation(self):
        if self._plan is None:
            return None
        for request_id in self._waits.values():
            for wait in self.state.waits(self.run_id):
                if wait.request_id != request_id or wait.ref.job_id != self._plan.job.job_id:
                    continue
                details = self.state.wait_details(wait.ref, request_id)
                answers = [r.answer for r, receipt in details.responses if receipt.disposition == 'applied']
                if request_id not in self._handled_waits and (
                        details.disposition == 'timeout' or any(a in (c.HumanAnswer.INSTRUCT, c.HumanAnswer.REJECT) for a in answers)):
                    return details
        return None

    def _replan(self, details):
        # One consumed, durable planning slot per authenticated disposition. A
        # crash during planning halts instead of silently repeating the callback.
        self._handled_waits.add(details.wait.request_id)
        if self._replans >= self.state.get_run(self.run_id).limits.attempts_per_job:
            self._halted = 'replan_limit'
            return self._view(c.State.WAITING_HUMAN, self._halted)
        self._replans += 1
        self._halted = 'replan_interrupted'
        self._save()
        run = self.state.get_run(self.run_id)
        plan = (self.replanner(run, self._plan, details) if self.replanner else
                self.planner(run, tuple(self._jobs), self._goal))
        if plan is None:
            self._halted = 'no_alternative_plan'
            return self._view(c.State.WAITING_HUMAN, self._halted)
        # A new method may serve the same required Goal. It cannot discard or
        # rewrite the Job, original intent, context or acceptance criteria.
        if type(plan) is not JobPlan or plan.job != self._plan.job:
            self._halted = 'replan_changed_required_job'
            return self._view(c.State.WAITING_HUMAN, self._halted)
        decision = self.judgment.judge(JudgmentRequest(c.QuestionRef(self.run_id, plan.job.job_id),
            plan.action, plan.method, plan.conditions[0], proposed_job=plan.job))
        self._records.append(decision)
        if decision.decision != c.Decision.NORMAL:
            self._halted = 'replan_containment_not_normal'
            return self._view(c.State.WAITING_HUMAN, self._halted)
        self._plan, self._halted = plan, None
        self._waits = {k: v for k, v in self._waits.items() if v != details.wait.request_id}
        return self._view(c.State.PENDING, 'replanned')

    @property
    def records(self) -> tuple:
        """Trusted local audit, not a sanitized public Trace or durable journal."""
        return tuple(self._records)

    def _view(self, status, reason, cessation=None):
        return Progress(self.run_id, status, reason, tuple(self._jobs), self._goal,
                        self._active, cessation)

    def _stop_label(self):
        """Controller label from the committed stop origin; first origin wins."""
        origin = self.state.stop_origin(self.run_id)
        return (origin if origin in ('projection_decided', 'approval_required')
                else 'human_stop')

    def _finish(self, status, reason, cessation=None, revision=None):
        if revision is None:
            revision = self.state.get_run(self.run_id).revision
        try:
            run = self.state.finalize_run(self.run_id, status, reason,
                                          revision, cessation)
        except Conflict:
            # A committed concurrent write (e.g. stop intake) wins; the next
            # step observes it and this transition re-runs or is superseded.
            return self._view(c.State.PENDING, 'finalization_snapshot_changed')
        self._terminal = self._view(run.state, run.final_reason,
                                  run.cessation_confirmed)
        self._save_terminal(run.revision)
        return self._terminal

    def _save_terminal(self, revision):
        """Class-O operational write: canonical checkpoint content only.

        No Run revision bump and no proof-domain field. A stale CAS means a
        later committed write exists; the next open replaces the checkpoint,
        which is non-authoritative.
        """
        try:
            self.state.save_checkpoint(self.run_id,
                ControllerCheckpoint(None, None, None, (), (), (), None, None,
                                     (), 0, None, self._lifecycle_ref),
                revision)
        except Conflict:
            pass

    def _now(self):
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("aware Controller clock required")
        return now.astimezone(timezone.utc)

    def _persist_latch(self):
        """L1: persist the fatal latch before anything else; bounded CAS.

        Each _save re-reads the committed revision and retries, so a
        concurrent committed write is never swallowed silently. If every
        observation still conflicts, the in-memory latch remains and no
        durability is claimed; a later step retries the save.
        """
        for _ in range(3):
            try:
                self._save()
                return
            except Conflict:
                continue

    def _attempts_settled(self):
        """The closed predicate: every committed Attempt is settled by a
        request-matched NeverStarted receipt or a real Result plus
        CONFIRMED cessation. It is never relaxed."""
        return all(self.state.attempt_settlement(a.ref) is not None
                   for a in self.state.attempts(self.run_id))

    def _fatal(self):
        """Fatal integrity gate: real cleanup only, then FAILED finalization.

        No admission, evaluation, collection, replan, retry or dispatch can
        run on this path. A still-held Attempt gets only the real stop/drain
        below; anything else stays held and surfaced honestly.
        """
        self._persist_latch()
        if not self._attempts_settled() and self._active is not None:
            self._fatal_cleanup()
        if self._attempts_settled():
            if self._active is not None:
                # Capacity frees only on committed confirmed/NeverStarted
                # settlement; release_attempt itself rejects otherwise.
                self.state.release_attempt(self._active)
            try:
                return self._finish(c.State.FAILED, 'integrity_violation', True)
            except InvalidTransition:
                # A committed write won the finalization race; the terminal
                # record supersedes the latch and the next open reconciles.
                pass
        return self._fatal_hold_view()

    def _fatal_hold_view(self):
        """Honest held projection: cessation and settlement are separate.

        A committed CONFIRMED StopReply reports cessation True under
        integrity_violation_result_missing — the committed reply is the
        adapter-side capacity proof, while state.release_attempt still
        requires full settlement. Without it the slot stays held under
        integrity_violation_stop_unconfirmed and cessation False. The
        northbound error code is integrity_violation in both cases.
        """
        cessation = False
        if self._active is not None:
            try:
                reply = self.state.get_attempt(self._active).stop_reply
            except GLOBAL_FAILURES:
                raise
            except Exception:
                reply = None
            cessation = (reply is not None
                         and reply.status == c.StopStatus.CONFIRMED)
        return self._view(c.State.RUNNING,
            'integrity_violation_result_missing' if cessation
            else 'integrity_violation_stop_unconfirmed', cessation)

    def _fatal_cleanup(self):
        """L4: real evidence for the held Attempt, never a fabricated Result.

        The real StopReply and real Adapter events commit under a bounded
        CAS retry on a freshly re-read revision. Only a commit, an exact
        committed replay, or a permanent IntegrityViolation rejection
        advances the cursor; a stale CAS or a refused transition holds the
        cursor and stops the drain, so a real Result can never be skipped.
        No AC, output, Goal, JobFailure or controller-authored Result is
        written, and no unconfirmed capacity is released.
        """
        if self.state.attempt_settlement(self._active) is not None:
            return
        attempt = self.state.get_attempt(self._active)
        if (attempt.stop_reply is None
                or attempt.stop_reply.status != c.StopStatus.CONFIRMED):
            reply = self._adapter().stop(self._active)
            if reply.ref != self._active:
                raise ValueError("stop identity mismatch")
            for _ in range(3):
                try:
                    self.state.record_stop(
                        reply, self.state.get_attempt(self._active).revision)
                except IntegrityViolation:
                    # Permanent rejection; the committed record wins.
                    self._records.append(
                        ("integrity_violation_stop", self._active))
                    break
                except Conflict:
                    continue  # Stale snapshot: re-read, retry same reply.
                else:
                    self._records.append(reply)
                    break
        for event in self._adapter().events(self._active, self._cursor):
            if event.ref != self._active:
                raise ValueError("cross-Attempt event")
            for _ in range(3):
                try:
                    self.state.record_event(
                        event, self.state.get_attempt(self._active).revision)
                except IntegrityViolation:
                    # Permanent rejection; the committed record wins.
                    self._records.append(("integrity_violation_event",
                                          self._active, event.event_id))
                    break
                except Conflict:
                    continue  # Stale snapshot: re-read, retry same event.
                except InvalidTransition:
                    # run_terminal supersedes the latch; every other refusal
                    # is held, never skipped — stop draining, keep cursor.
                    self._records.append(
                        ("drain_held", self._active, event.event_id))
                    return
                else:
                    if isinstance(event, c.ConfirmationEvent):
                        self._callbacks[event.confirmation.request_id] = (
                            event.confirmation)
                    break
            else:
                # Bounded CAS retries exhausted: the cursor stays at the
                # last advanced event and the next step resumes the drain.
                return
            self._cursor = event.event_id

    def step(self) -> Progress:
        if not self._lock.acquire(blocking=False):
            raise InvalidTransition("Controller calls must be serialized")
        global_failed = False
        try:
            try:
                if self._terminal is not None:
                    return self._terminal
                run = self.state.get_run(self.run_id)
                if self._halted == 'integrity_violation':
                    # Fatal gate before stop/continuation/halt: the closed
                    # reason and the held Attempt are never superseded.
                    return self._fatal()
                if run.stop_requested:
                    self._stopping = self._stop_label()
                if self._stopping:
                    return self._stop()
                continuation = self._continuation()
                if continuation is not None:
                    if self._active is not None:
                        self._stopping = 'human_continuation'
                        return self._stop()
                    return self._replan(continuation)
                if self._halted:
                    return self._view(c.State.WAITING_HUMAN, self._halted)
                if self._active is not None:
                    return self._poll()
                if self._plan is None:
                    return self._plan_next(run)
                return self._dispatch(run)
            except GLOBAL_FAILURES:
                raise
            except IntegrityViolation:
                # Fatal latch: a write contradicted a committed record. Keep the
                # held Attempt for real cleanup (L3), persist the latch (L1) and
                # let the fatal gate run; only committed FAILED/integrity_violation
                # supersedes it (L2). Never CAS-retry, re-execute or dispatch.
                self._records.append(("integrity_violation", self._active))
                self._halted = 'integrity_violation'
                try:
                    return self._fatal()
                except GLOBAL_FAILURES:
                    raise
                except Exception:
                    # Cleanup failed after latching: stay latched, hold the
                    # Attempt and retry on the next step; never dispatch.
                    self._records.append(("integrity_cleanup_error", self._active))
                    return self._fatal_hold_view()
            except Exception:
                if self._halted == 'integrity_violation':
                    # L2: the fatal latch supersedes recoverable controller_error
                    # handling; stay latched and retry cleanup on later steps.
                    self._records.append(
                        ("controller_error_after_latch", self._active))
                    return self._fatal_hold_view()
                # A failed send/check can leave Native work alive. Never infer an
                # empty successful run or launch another Attempt after that failure.
                self._records.append(("controller_error", self._active))
                if (self._stopping is None
                        and self.state.get_run(self.run_id).stop_requested):
                    # A stop committed mid-step is decisive: the committed
                    # origin labels the outcome, never controller_error. A
                    # global failure in this read propagates unchanged.
                    self._stopping = self._stop_label()
                # The first decisive stop reason wins; a later timer/channel or
                # controller failure never overwrites a committed stop decision.
                self._stopping = self._stopping or "controller_error"
                if self._active is None:
                    return self._finish(c.State.ERROR
                        if self._stopping == "controller_error"
                        else c.State.FAILED, self._stopping)
                return self._view(c.State.RUNNING, "controller_error_stop_required", False)
        except GLOBAL_FAILURES:
            global_failed = True
            raise
        finally:
            try:
                if self._terminal is None and not global_failed:
                    try:
                        self._save()
                    except IntegrityViolation:
                        raise
                    except Conflict:
                        # A committed write won the checkpoint CAS. The
                        # checkpoint is non-authoritative; the next step or
                        # open rewrites it. Never mask the step's Progress.
                        # Edge-triggered audit: one record per loss run. A
                        # successful _save resets _unsaved_label, so the
                        # next loss run is recorded again; the fatal latch
                        # keeps its distinct label.
                        label = ('fatal_latch_checkpoint_unsaved'
                                 if self._halted == 'integrity_violation'
                                 else 'checkpoint_unsaved')
                        if label != self._unsaved_label:
                            self._records.append((label, self._active))
                        self._unsaved_label = label
            finally:
                self._lock.release()

    def _plan_next(self, run):
        if self._jobs:
            self._goal = self.acceptance.run(run, tuple(self._jobs))
            self._records.append(self._goal)
            # A verifier/host callback may have ingested a stop or instruction.
            if self.state.get_run(self.run_id).revision != run.revision:
                return self._view(c.State.PENDING, "goal_snapshot_changed")
            try:
                self.state.record_run_goal(self._goal, run.revision)
            except Conflict:
                return self._view(c.State.PENDING, "goal_snapshot_changed")
            if self._goal.finding.verdict == "pass":
                return self._finish(c.State.COMPLETED, "human_goal_verified")
            if self._goal.finding.verdict in {"blocked", "not_run"}:
                self._halted = "run_goal_" + self._goal.finding.verdict
                return self._view(c.State.WAITING_HUMAN, self._halted)
        if len(run.job_ids) >= run.limits.jobs:
            return self._finish(c.State.FAILED, "run_job_limit")
        plan = self.planner(run, tuple(self._jobs), self._goal)
        if plan is None:
            return self._finish(c.State.FAILED, "no_plan_for_unmet_goal")
        if type(plan) is not JobPlan or plan.job.run_id != self.run_id:
            raise ValueError("planner returned invalid Job")
        if plan.job.job_id in run.job_ids:
            raise ValueError("next Job must have a new identity")
        request = JudgmentRequest(c.QuestionRef(self.run_id, plan.job.job_id),
                                  plan.action, plan.method, plan.conditions[0],
                                  proposed_job=plan.job)
        decision = self.judgment.judge(request)
        self._records.append(decision)
        if decision.decision != c.Decision.NORMAL:
            if run.profile is not None:
                # A profile Run has no Human channel: a non-NORMAL Job
                # judgment ends it before any wait or Attempt. Settlement
                # is already enforced — begin_attempt admits only onto a
                # fully settled journal, and finalize_run re-checks it.
                return self._finish(c.State.FAILED, 'approval_required')
            self._halted = "job_containment_not_normal"
            return self._view(c.State.WAITING_HUMAN, self._halted)
        try:
            self.state.add_job(plan.job, decision.decision_id,
                               decision.state_revision, plan=plan)
        except IntegrityViolation:
            raise
        except Conflict:
            # A committed stop/concurrent write wins; next step re-reads.
            return self._view(c.State.PENDING, 'job_snapshot_changed')
        self._plan, self._attempts = plan, []
        self._replans = 0
        return self._view(c.State.PENDING, "next_job")

    def _routing_record(self, route, plan, now, revision, decisions, *, ref=None, decision=None):
        """Retain only reviewed routing inputs, never plans, workspace or extras."""
        def option(value):
            verification, usage = value.verification, value.usage
            sample = usage.sample
            return {
                'model': value.entry.model, 'adapter': value.entry.adapter,
                'recommendation': value.entry.recommended_for.get(plan.use_case),
                'judgment_ref': value.assessment.decision_ref,
                'catalog_verification': {
                    'environment_ref': verification.environment_ref,
                    'auth_route': verification.auth_route,
                    'lifecycle_policy_ref': self._lifecycle_policy.ref if self._lifecycle_policy else None,
                    'official_ref': verification.official_ref,
                    'implementation_ref': verification.implementation_ref,
                    'measurement_ref': verification.measurement_ref,
                    'ac_ref': verification.ac_ref},
                'usage': {'reason': usage.reason,
                    'remaining_percent': usage.remaining_percent,
                    'sample': None if sample is None else {
                        'remaining_percent': sample.remaining_percent,
                        'updated_at': sample.updated_at, 'source_ref': sample.source_ref,
                        'window': sample.window}}}
        selected = route.selected
        summary = {
            'use_case': {'category': plan.use_case.category,
                         'other': plan.use_case.other, 'role': plan.use_case.role},
            'explicit_model': plan.explicit_model, 'explicit_adapter': plan.explicit_adapter,
            'usage_window': plan.usage_window,
            'max_usage_age_seconds': self.max_usage_age.total_seconds(),
            'selected': None if selected is None else {
                'model': selected.entry.model, 'adapter': selected.entry.adapter},
            'reason': route.reason, 'eligible': [option(o) for o in route.eligible],
            'assessments': [{'model': conditions.model, 'adapter': conditions.adapter,
                'environment_ref': conditions.environment_ref,
                'judgment_ref': judgment.decision_id, 'decision': judgment.decision.value}
                for conditions, judgment in decisions],
            'excluded': [{'model': e.model, 'adapter': e.adapter, 'reason': e.reason}
                         for e in route.excluded]}
        return RoutingRecord(uuid4().hex, ref or c.QuestionRef(self.run_id, plan.job.job_id),
            revision, now.isoformat(), canonical(summary),
            decision.decision_id if decision is not None else None)

    def _dispatch(self, run):
        if (self.catalog.lifecycle is not self._lifecycle_policy
                or (self._lifecycle_policy.ref if self._lifecycle_policy else None) != self._lifecycle_ref):
            return self._view(c.State.PENDING, "model_lifecycle_policy_changed")
        plan = self._plan
        if len(self._attempts) >= run.limits.attempts_per_job:
            return self._finish(c.State.FAILED, "job_attempt_limit")
        assessments, decisions = [], []
        pair_counts = {}
        for ref in self._attempts:
            conditions = self.state.get_attempt(ref).conditions
            pair = (conditions.model, conditions.adapter)
            pair_counts[pair] = pair_counts.get(pair, 0) + 1
        # Committed never_started receipts are the per-Job route exclusion
        # ledger; the evidence constant and request are matched exactly.
        collector_denied = set()
        if plan.job.output_candidate:
            for receipt in self.state.history(self.run_id, 'execute_history'):
                started = receipt.never_started
                if (started is None
                        or self.state.attempt_settlement(receipt.ref)
                        != 'never_started'
                        or started.evidence_ref != CHILD_LACKS_COLLECTOR
                        or started.request.job.job_id != plan.job.job_id):
                    continue
                denied = started.request.conditions
                collector_denied.add(
                    (denied.model, denied.adapter, denied.environment_ref))
        for conditions in plan.conditions:
            pair = (conditions.model, conditions.adapter)
            if conditions.adapter not in self.adapters:
                continue
            if ((conditions.model, conditions.adapter,
                 conditions.environment_ref) in collector_denied):
                continue
            if pair_counts.get(pair, 0) >= run.limits.attempts_per_pair:
                continue
            if (run.profile is not None and
                    (conditions.model, conditions.adapter,
                     conditions.environment_ref) not in run.profile.routes):
                continue
            if (plan.job.output_candidate and
                    (self.output_store is None or not isinstance(
                        self.adapters[conditions.adapter], c.OutputCollector))):
                continue
            decision = self.judgment.judge(JudgmentRequest(
                c.QuestionRef(self.run_id, plan.job.job_id), plan.action,
                plan.method, conditions))
            self._records.append(decision)
            decisions.append((conditions, decision))
            # Normal from current #157 execution judgment necessarily includes
            # trusted conditions AND protection evidence. No caller boolean.
            assessments.append(Assessment(plan.job, conditions, decision.decision,
                decision.decision_id, decision.decision == c.Decision.NORMAL))
        now = self._now()
        route = select_route(self.catalog, plan.job, plan.use_case, assessments,
            self.usage, now=now, max_usage_age=self.max_usage_age,
            usage_window=plan.usage_window, explicit_model=plan.explicit_model,
            explicit_adapter=plan.explicit_adapter)
        self._records.append(route)
        if (self.state.get_run(self.run_id).revision != run.revision or
                any(d.state_revision != run.revision for _, d in decisions)):
            return self._view(c.State.PENDING, 'routing_snapshot_changed')
        if route.selected is None:
            try:
                self.state.record_routing(self._routing_record(
                    route, plan, now, run.revision, decisions))
            except IntegrityViolation:
                raise
            except Conflict:
                return self._view(c.State.PENDING, 'routing_snapshot_changed')
            # A catalog entry does not authorize a waiting/denied action. Open
            # one concrete pre-execution wait only for an otherwise verified
            # explicitly eligible combination; never fabricate an Attempt.
            for conditions, decision in decisions:
                if ((plan.explicit_model and plan.explicit_model != conditions.model)
                        or (plan.explicit_adapter and plan.explicit_adapter != conditions.adapter)):
                    continue
                entry = next((e for e in self.catalog.entries
                    if e.key == (conditions.model, conditions.adapter)), None)
                if entry is None or entry.verification(plan.use_case, conditions.environment_ref) is None:
                    continue
                if decision.decision in {c.Decision.CONFIRM, c.Decision.UNDETERMINED}:
                    if run.profile is not None:
                        # No Human channel on a profile Run: an unresolved
                        # preflight decision ends it — no wait, no Attempt.
                        return self._finish(c.State.FAILED, 'approval_required')
                    key = "preflight:" + plan.job.job_id + ":" + body_digest(conditions)
                    if key not in self._waits:
                        try:
                            self._open_wait(decision, plan.method, key)
                        except IntegrityViolation:
                            raise
                        except Conflict:
                            return self._view(
                                c.State.PENDING, 'routing_snapshot_changed')
                    return self._view(c.State.WAITING_HUMAN, decision.reason)
            if (plan.job.output_candidate and run.profile is not None
                    and run.profile.requires_output):
                # Required output cannot be produced by any remaining route.
                return self._finish(c.State.FAILED, 'output_unavailable')
            return self._finish(c.State.FAILED, "no_eligible_route_or_pair_limit")
        conditions = route.selected.assessment.conditions
        ref = c.AttemptRef(self.run_id, plan.job.job_id, uuid4().hex)
        request = c.ExecuteRequest(ref, plan.job, conditions)
        adapter = self.adapters[conditions.adapter]
        pool = adapter if isinstance(adapter, PooledAdapter) else None
        if pool is not None and not pool.reserve(request):
            return self._view(c.State.PENDING, "adapter_capacity_full")
        begun = False
        try:
            decision = self.judgment.judge(JudgmentRequest(
                c.QuestionRef(ref.run_id, ref.job_id, ref.attempt_id),
                plan.action, plan.method, conditions))
            self._records.append(decision)
            if decision.state_revision != run.revision:
                return self._view(c.State.PENDING, 'routing_snapshot_changed')
            if decision.decision != c.Decision.NORMAL:
                try:
                    self.state.record_routing(self._routing_record(
                        route, plan, now, run.revision, decisions,
                        decision=decision))
                except IntegrityViolation:
                    raise
                except Conflict:
                    return self._view(c.State.PENDING,
                                      'routing_snapshot_changed')
                if run.profile is not None:
                    # No Human channel on a profile Run: a non-NORMAL
                    # dispatch rejudgment ends it before admission — no
                    # wait, no Attempt, no retry loop. Settlement already
                    # holds: begin_attempt admits only onto a fully settled
                    # journal, and finalize_run re-checks it.
                    return self._finish(c.State.FAILED, 'approval_required')
                return self._view(c.State.PENDING, "dispatch_rejudgment_not_normal")
            # Recheck after rejudgment/capacity wait, immediately before Attempt
            # admission. This never gates an existing Attempt or its cleanup.
            if (self.catalog.lifecycle is not self._lifecycle_policy
                    or (self._lifecycle_policy.ref if self._lifecycle_policy else None) != self._lifecycle_ref):
                return self._view(c.State.PENDING, "model_lifecycle_policy_changed")
            if self._lifecycle_policy is not None:
                reason = self._lifecycle_policy.admission_reason(conditions.model, conditions.adapter,
                    route.selected.verification.auth_route, now=self._now())
                if reason:
                    return self._view(c.State.PENDING, reason)
            routing = self._routing_record(route, plan, now, run.revision, decisions,
                                           ref=decision.ref, decision=decision)
            try:
                self.state.begin_attempt(request, decision.decision_id,
                                         decision.state_revision, routing=routing)
            except IntegrityViolation:
                # A committed-record contradiction is integrity, never a CAS
                # retry: propagate to the Run-ending integrity path.
                raise
            except Conflict:
                # A committed stop/concurrent write wins; the finally below
                # releases the reservation and the next step re-reads.
                return self._view(c.State.PENDING, 'routing_snapshot_changed')
            begun = True
        finally:
            if pool is not None and not begun:
                pool.cancel_reservation(request)
        previous = self._attempts[-1] if self._attempts else None
        # The committed Attempt is tracked before any fallible journal read:
        # a transient failure in the kind classification below must not leave
        # the admitted Attempt invisible to this Controller until reopen.
        self._attempts.append(ref)
        self._active, self._cursor = ref, None
        self._callbacks, self._answered = {}, set()
        kind = "execute"
        if previous:
            old = self.state.get_attempt(previous).conditions
            kind = "retry" if (old.model, old.adapter) == (conditions.model, conditions.adapter) else "reroute"
        self._records.append(Transition(kind, ref, previous))
        # begin_attempt revalidates the evidence and reserves the slot. Host
        # dispatch/ingress serialization and Adapter preflight remain required.
        self._pending_io = "execute"
        self._save()
        if self.state.get_run(self.run_id).stop_requested:
            # Admission committed, then a stop landed before any Native call.
            # Persist the pool-ledger-shaped host NeverStarted receipt for the
            # exact admitted request — zero Native calls — release the
            # reserved lease, and let the next step take the human_stop path.
            reply = c.OperationReply(ref, c.OperationStatus.UNAVAILABLE,
                'stop committed before dispatch',
                never_started=c.NeverStarted(request, STOPPED_BEFORE_EXECUTE))
            self._record_execute_receipt(ref, reply)
            self.state.release_attempt(ref)
            if pool is not None:
                pool.cancel_reservation(request)
            self._pending_io = None
            self._records.append(("execute_receipt", ref, reply.status))
            self._active = None
            return self._view(c.State.PENDING, 'execute_never_started')
        reply = adapter.execute(request)
        if reply.ref != ref:
            raise ValueError("execute receipt identity mismatch")
        # Secrets remain with AdapterBridge; this receipt is a public journal.
        self._record_execute_receipt(ref, reply)
        self._pending_io = None
        self._records.append(("execute_receipt", ref, reply.status))
        if reply.never_started is not None:
            # The exact committed receipt is the release evidence; the ledger
            # marks the slot consumed only for a settled Attempt.
            self.state.release_attempt(ref)
            self._active = None
            return self._view(c.State.PENDING, "execute_never_started")
        # No resume bytes are put into records. This slice does not resume.
        if reply.status != c.OperationStatus.ACCEPTED:
            self._stopping = "execute_not_accepted"
        return self._view(c.State.RUNNING, "execute_receipt")

    def _record_execute_receipt(self, ref, reply):
        """Persist the admitted Attempt's execute receipt exactly once.

        Delegates to the shared state.commit_execute_receipt so the
        Controller and startup admission recovery use identical CAS
        handling; an exact replay returns, divergence is integrity.
        """
        commit_execute_receipt(self.state, reply)

    def _open_wait(self, decision, method, key, request_id=None):
        wait = c.WaitingHuman(decision.ref, request_id or uuid4().hex,
            decision.action, decision.decision, decision.reason,
            (self._now() + timedelta(hours=24)).isoformat())
        self.state.open_wait(wait, method, decision.state_revision, decision.decision_id)
        self._waits[key] = wait.request_id
        self._records.append(wait)

    def _adapter(self):
        attempt = self.state.get_attempt(self._active)
        return self.adapters[attempt.conditions.adapter]

    def _events(self):
        events = self._adapter().events(self._active, self._cursor)
        for event in events:
            if event.ref != self._active:
                raise ValueError("cross-Attempt event")
            attempt = self.state.get_attempt(self._active)
            if attempt.result is not None and isinstance(
                    event, (c.StatusEvent, c.ConfirmationEvent)):
                # A committed Result cannot be resurrected by a late Native
                # status or confirmation, but the journal still decides
                # identity: an exact committed replay is safe, a duplicate
                # event_id whose content contradicts the committed record is
                # a fatal IntegrityViolation, and only a genuinely new
                # terminal-era event is skipped rather than applied.
                try:
                    self.state.record_event(event, attempt.revision)
                except InvalidTransition:
                    self._records.append(("post_terminal_event_discarded",
                                          self._active, event.event_id))
                self._cursor = event.event_id
                continue
            self.state.record_event(event, attempt.revision)
            self._cursor = event.event_id
            if isinstance(event, c.ConfirmationEvent):
                self._callbacks[event.confirmation.request_id] = event.confirmation
                if self.state.get_run(self.run_id).profile is not None:
                    # A profile Run has no Human channel: latch the durable
                    # approval_required barrier at the committed evidence, so
                    # a ResultEvent later in the same drain — and any result
                    # processing — can never precede the committed stop. The
                    # callbacks-loop fallback covers a crash before this line.
                    self.state.request_internal_stop(self.run_id, 'approval_required')

    def _poll(self):
        attempt = self.state.get_attempt(self._active)
        if self.state.attempt_settlement(self._active) == 'never_started':
            self._active = None
            return self._view(c.State.PENDING, 'execute_never_started')
        if attempt.result is None:
            self._events()
        attempt = self.state.get_attempt(self._active)
        if attempt.result is not None:
            if attempt.result.reason == "human_confirmation_timeout":
                self._stopping = "human_confirmation_timeout"
                return self._stop()
            just_ceased = False
            # A terminal Native turn can leave child processes alive. Require
            # explicit cessation before accepting/retrying/rerouting, including
            # completed + failed AC. #158 Codex currently cannot prove this
            # after a submitted turn, so that live path remains blocked.
            if attempt.stop_reply is None or attempt.stop_reply.status != c.StopStatus.CONFIRMED:
                reply = self._adapter().stop(self._active)
                if reply.ref != self._active:
                    raise ValueError("stop identity mismatch")
                try:
                    attempt = self.state.record_stop(reply, attempt.revision)
                except IntegrityViolation:
                    raise
                except Conflict:
                    # A committed write (e.g. stop intake) wins; the next
                    # step re-reads the Attempt/Run and reconciles.
                    return self._view(c.State.PENDING, 'stop_snapshot_changed')
                self._records.append(reply)
                if reply.status != c.StopStatus.CONFIRMED:
                    record = c.ACRecord(self._active, "blocked", ())
                    try:
                        self.state.record_ac(record, attempt.revision)
                    except IntegrityViolation:
                        raise
                    except Conflict:
                        return self._view(c.State.PENDING, 'stop_snapshot_changed')
                    return self._view(c.State.RUNNING, "terminal_cessation_unconfirmed", False)
                just_ceased = True
            if attempt.collection_failure is not None:
                # Persisted controller-owned outcome; never reaches AC again.
                return self._failure_view(attempt.collection_failure.kind)
            run = self.state.get_run(self.run_id)
            if run.stop_requested:
                # A committed stop wins over policy/output/AC writes; the
                # in-transaction CAS still closes the remaining window.
                self._stopping = self._stop_label()
                return self._stop()
            if (attempt.result.status != c.State.COMPLETED
                    and attempt.result.reason in POLICY_TERMINAL_REASONS):
                # Exact reason only: no AC, no JobFailure, no collection, no
                # retry/reroute/replan/WAITING_HUMAN — the whole Run ends.
                return self._finish(c.State.FAILED, attempt.result.reason, True,
                                    revision=run.revision)
            if (self._plan.job.output_candidate
                    and attempt.result.status == c.State.COMPLETED
                    and attempt.output is None):
                # A committed boundary between cessation and persistence;
                # collection replays safely after a host restart.
                if just_ceased:
                    return self._view(c.State.RUNNING, "cessation_confirmed", True)
                return self._persist_output(attempt)
            output = (c.OutputRef(attempt.ref, attempt.output.digest)
                      if attempt.output is not None else None)
            try:
                outcome = self.acceptance.job(run, self._plan.job, attempt.result,
                                              output=output)
            except IntegrityError:
                # Persisted bytes no longer match committed identity; fail
                # closed. Output and Result stay as written; no record.
                return self._finish(c.State.FAILED, 'output_integrity_failure',
                                    True, revision=run.revision)
            if self.state.get_run(self.run_id).revision != run.revision:
                return self._view(c.State.PENDING, "ac_snapshot_changed")
            try:
                self.state.record_job_goal(outcome, run.revision)
            except IntegrityViolation:
                raise
            except Conflict:
                # CAS/stop guard rejected the write; next step re-evaluates.
                return self._view(c.State.PENDING, "ac_snapshot_changed")
            self._records.append(outcome)
            self._active = None
            if outcome.completed:
                self._jobs.append(outcome)
                self._plan = None
                return self._view(c.State.PENDING, "job_goal_verified")
            if run.profile is not None and run.profile.effect_class == 'effectful':
                # An effectful northbound Run has no Human channel and never
                # auto-retries: any evaluated failure ends approval_required.
                return self._finish(c.State.FAILED, 'approval_required', True)
            if outcome.ac.verdict in {"blocked", "not_run"}:
                self._halted = "job_ac_" + outcome.ac.verdict
                return self._view(c.State.WAITING_HUMAN, self._halted)
            return self._view(c.State.PENDING, "job_goal_unmet")
        for key, callback in self._callbacks.items():
            if key in self._answered:
                continue
            if self.state.get_run(self.run_id).profile is not None:
                # The committed ConfirmationEvent stays as evidence only;
                # latch the durable approval_required barrier, then the real
                # stop/drain holds until a genuine Result plus CONFIRMED
                # cessation. No wait, no relay, no Native respond().
                self.state.request_internal_stop(self.run_id, 'approval_required')
                self._stopping = self._stop_label()
                return self._stop()
            decision = self.judgment.judge(JudgmentRequest(
                c.QuestionRef(self.run_id, callback.ref.job_id, callback.ref.attempt_id),
                callback.requested_action, self._plan.method, attempt.conditions,
                confirmation=callback))
            self._records.append(decision)
            if decision.decision in {c.Decision.CONFIRM, c.Decision.UNDETERMINED}:
                if key not in self._waits:
                    try:
                        self._open_wait(decision, self._plan.method, key, key)
                    except IntegrityViolation:
                        raise
                    except Conflict:
                        return self._view(c.State.PENDING,
                                          'wait_snapshot_changed')
                return self._view(c.State.WAITING_HUMAN, decision.reason)
            if not callback.can_respond:
                self._stopping = "native_constraint"
                return self._stop()
            response = c.ConfirmationResponse(callback.ref, key, callback.requested_action,
                c.Resolution.ALLOW if decision.decision == c.Decision.NORMAL else c.Resolution.DENY,
                decision.decision_id)
            self.state.validate_relay(response)
            # Latch before IO; ambiguous deliveries cannot trigger repeated sends.
            self._answered.add(key)
            self._pending_io = "relay"
            self._save()
            reply = self._adapter().respond(response)
            if reply.ref != self._active:
                raise ValueError("relay identity mismatch")
            self._records.append(("relay_receipt", callback.ref, key, reply.status))
            self._pending_io = None
            if reply.status != c.OperationStatus.ACCEPTED:
                self._stopping = "relay_not_accepted"
            return self._view(c.State.RUNNING, "relay_receipt")
        return self._view(attempt.state, "awaiting_native_event")

    def _persist_output(self, attempt):
        """Bounded collection step; one outcome per Attempt, never a verdict.

        Only declared error classes map to a controller-owned failure;
        anything else escapes to controller_error and fails closed. A stale
        revision Conflict re-reads and re-runs; a different digest for the
        same Attempt is integrity, never a CAS retry.
        """
        ref = attempt.ref
        try:
            if self.output_store is None:
                raise c.CollectionError('output store unavailable')
            output = self.output_store.put(ref, self._adapter().collect_output(ref))
            self.state.record_attempt_output(ref, output, attempt.revision)
        except DigestConflict:
            return self._collect_failed(attempt, 'integrity_failure',
                                        ('output:integrity:DigestConflict',))
        except IntegrityError as exc:
            return self._collect_failed(attempt, 'integrity_failure',
                                        ('output:integrity:' + type(exc).__name__,))
        except IntegrityViolation:
            raise
        except Conflict:
            return self._view(c.State.RUNNING, 'output_snapshot_changed')
        except OutputRejected as exc:
            return self._collect_failed(attempt, 'policy_failure',
                                        ('output:policy:' + type(exc).__name__,))
        except (CapacityError, c.CollectionError, OSError) as exc:
            return self._collect_failed(attempt, 'collection_unavailable',
                                        ('output:collect:' + type(exc).__name__,))
        return self._view(c.State.RUNNING, 'output_persisted', True)

    def _collect_failed(self, attempt, kind, evidence_refs):
        failure = c.JobFailure(self._plan.job, attempt.result, kind, evidence_refs)
        try:
            self.state.record_job_failure(failure, attempt.revision)
        except IntegrityViolation:
            raise
        except Conflict:
            return self._view(c.State.RUNNING, 'output_snapshot_changed')
        return self._failure_view(kind)

    def _failure_view(self, kind):
        """Classify a recorded collection failure; the Attempt is consumed."""
        self._active = None
        run = self.state.get_run(self.run_id)
        if run.stop_requested:
            # A committed stop wins over any failure classification write.
            self._stopping = self._stop_label()
            return self._stop()
        profile = run.profile
        if profile is not None and profile.effect_class == 'effectful':
            # Northbound has no Human channel; one supervised execution only.
            return self._finish(c.State.FAILED, 'approval_required', True,
                                revision=run.revision)
        if (kind == 'collection_unavailable' and profile is not None
                and profile.effect_class == 'pure'):
            # Confirmed cessation already holds; a pure Job may retry.
            return self._view(c.State.PENDING, 'job_output_collect_unavailable')
        if profile is not None and profile.requires_output:
            return self._finish(c.State.FAILED, 'output_unavailable'
                if kind == 'collection_unavailable' else 'output_' + kind,
                True, revision=run.revision)
        self._halted = 'job_output_' + kind
        return self._view(c.State.WAITING_HUMAN, self._halted)

    def _stop(self):
        if self._active is None:
            return self._finish(c.State.ERROR if self._stopping == "controller_error"
                                else c.State.FAILED, self._stopping)
        attempt = self.state.get_attempt(self._active)
        reply = attempt.stop_reply
        if reply is None or reply.status != c.StopStatus.CONFIRMED:
            # Only a real StopReply is evidence; a committed CONFIRMED reply
            # is never re-requested or re-recorded.
            reply = self._adapter().stop(self._active)
            if reply.ref != self._active:
                raise ValueError("stop identity mismatch")
            attempt = self.state.record_stop(reply, attempt.revision)
            self._records.append(reply)
        # Poll only after latching stop, so a Codex bootstrap cannot start a turn.
        try:
            self._events()
        except IntegrityViolation:
            # A committed-record contradiction is a fatal integrity signal,
            # never an opaque channel error: propagate to the latch so no
            # controller-authored Result or ERROR finalization can run.
            raise
        except GLOBAL_FAILURES:
            raise
        except Exception:
            # A broken event channel is audit only: not a Result and never a
            # reason to overwrite the first decisive stop reason. The real
            # drain resumes from the persisted cursor on later steps and on
            # host restart.
            self._records.append(("stopped_event_channel_error", self._active))
        if reply.status != c.StopStatus.CONFIRMED:
            return self._view(c.State.RUNNING, "stop_unconfirmed", False)
        attempt = self.state.get_attempt(self._active)
        details = self._continuation() if self._stopping in ('human_continuation', 'human_confirmation_timeout') else None
        if attempt.result is None:
            # Confirmed cessation and settlement are distinct facts. With no
            # real Result nothing is synthesized — no ResultEvent, AC,
            # output, goal or JobFailure — and nothing finalizes, replans or
            # dispatches. The Attempt, cursor and decisive stop reason stay
            # held; an applied continuation persists but cannot run until a
            # real Result arrives. A later real Result, even COMPLETED,
            # settles without AC/output and takes the existing stop terminal
            # or the settled continuation. Northbound projects this held
            # state under the M3 monotonic rules; that mapping is persisted
            # as rules only, not claimed tested here.
            return self._view(c.State.RUNNING, 'stop_result_missing', True)
        self._active = None
        if details is not None:
            self.state.release_attempt(attempt.ref)
            self._stopping = None
            return self._replan(details)
        return self._finish(c.State.ERROR if self._stopping == "controller_error"
                            else c.State.FAILED, self._stopping, True)
