"""Shared, in-process contracts. Trusted CO code constructs control records.

These types are not a deserializer or a security boundary. Worker JSON must not
be instantiated as Approval/HumanResponse; authenticated ingress owns that step.
"""
from dataclasses import dataclass, field
from enum import Enum
import json
import math
from typing import Protocol, runtime_checkable


class Decision(str, Enum):
    NORMAL = "normal"
    CONFIRM = "confirm"
    DENY = "deny"
    UNDETERMINED = "undetermined"


class State(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING_HUMAN = "waiting_human"
    COMPLETED = "completed"
    FAILED = "failed"
    ERROR = "error"


TERMINAL = frozenset({State.COMPLETED, State.FAILED, State.ERROR})


@dataclass(frozen=True)
class Scope:
    """Exact semantic target and conditions, normalized by the Adapter.

    None is unknown (never a wildcard). Omit only inapplicable dimensions.
    complete requires evidence that no relevant target/condition is omitted.
    No prefix, glob, path, URL, branch, or case folding happens here.
    """
    dimensions: tuple[tuple[str, str | None], ...]
    complete: bool = False

    def __post_init__(self):
        pairs = tuple(sorted(self.dimensions))
        keys = [key for key, _ in pairs]
        if len(set(keys)) != len(keys) or any(not key for key in keys):
            raise ValueError("scope keys must be unique and nonempty")
        if any(value is not None and (not isinstance(value, str) or not value)
               for _, value in pairs):
            raise ValueError("scope values must be nonempty strings or unknown")
        if type(self.complete) is not bool:
            raise ValueError("complete must be bool")
        object.__setattr__(self, "dimensions", pairs)

    @property
    def known(self) -> bool:
        return self.complete and bool(self.dimensions) and all(
            value is not None for _, value in self.dimensions)


@dataclass(frozen=True)
class Action:
    """Name describes the effect, independently of Native tool/route/Job name."""
    name: str
    scope: Scope

    def __post_init__(self):
        if not self.name or self.name != self.name.strip():
            raise ValueError("action name must be nonempty and exact")


def same_target(left: Action, right: Action) -> bool:
    return (left.scope.known and right.scope.known and left == right)


def approval_target(run_id: str, action: Action) -> dict:
    """Single projection for human presentation and exact approval matching.

    The caller must ensure scope fields are suitable for human publication.
    Secret-bearing requests stay local; do not redact then approve a broader key.
    """
    return {"run_id": run_id, "action": action.name,
            "scope": dict(action.scope.dimensions),
            "scope_complete": action.scope.known,
            "reuse": "same Run + exact Action + exact Scope; across Jobs/Attempts"}


def approval_key(run_id: str, action: Action) -> str | None:
    if not run_id or not action.scope.known:
        return None
    return json.dumps(approval_target(run_id, action), sort_keys=True,
                      ensure_ascii=False, separators=(",", ":"))


@dataclass(frozen=True)
class AttemptRef:
    run_id: str
    job_id: str
    attempt_id: str

    def __post_init__(self):
        if not all((self.run_id, self.job_id, self.attempt_id)):
            raise ValueError("all attempt correlation IDs are required")


@dataclass(frozen=True)
class Job:
    run_id: str
    job_id: str
    instructions: str
    acceptance_criteria: tuple[str, ...]
    # JSON serialized context avoids mutable nested shared state.
    context_json: str = "{}"
    # True marks this Job's persisted output as the Run output candidate.
    output_candidate: bool = False

    def __post_init__(self):
        if not self.run_id or not self.job_id or not self.instructions:
            raise ValueError("job identity and instructions are required")
        if not isinstance(json.loads(self.context_json), dict):
            raise ValueError("context must be a JSON object")
        if type(self.output_candidate) is not bool:
            raise ValueError("output_candidate must be bool")


@dataclass(frozen=True)
class ExecutionConditions:
    model: str
    adapter: str
    workspace: str
    # References to Controller-owned preflight evidence/configuration, not
    # Worker claims. #158 resolves them; #157/#159 determine adequacy.
    environment_ref: str
    control_evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecuteRequest:
    ref: AttemptRef
    job: Job
    conditions: ExecutionConditions

    def __post_init__(self):
        if (self.ref.run_id, self.ref.job_id) != (self.job.run_id, self.job.job_id):
            raise ValueError("job/attempt mismatch")


@dataclass(frozen=True)
class ResumeState:
    adapter: str
    ref: AttemptRef
    # Secret: do not use dataclasses.asdict, JSON, logs, GitHub or email on this.
    opaque: bytes = field(repr=False)


class OperationStatus(str, Enum):
    ACCEPTED = "accepted"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    INVALID_STATE = "invalid_state"
    ERROR = "error"


@dataclass(frozen=True)
class NeverStarted:
    """Trusted Adapter attestation, issued only before any transport creation.

    This is not inferred from an error string or a Worker claim. The exact
    request and sanitized local observation remain available as evidence.
    Factory/send exceptions are ambiguous and must not produce this receipt.
    """
    request: ExecuteRequest
    evidence_ref: str

    def __post_init__(self):
        if not self.evidence_ref.strip():
            raise ValueError("never-started evidence required")


@dataclass(frozen=True)
class OperationReply:
    ref: AttemptRef
    status: OperationStatus
    reason: str
    # Accepted execute/resume means receipt, not running/completed.
    resume_state: ResumeState | None = field(default=None, repr=False)
    never_started: NeverStarted | None = None

    def __post_init__(self):
        if self.resume_state and self.resume_state.ref != self.ref:
            raise ValueError("resume state belongs to another attempt")
        if self.never_started is not None and (
                type(self.never_started) is not NeverStarted
                or self.never_started.request.ref != self.ref
                or self.status == OperationStatus.ACCEPTED or self.resume_state is not None):
            raise ValueError("invalid never-started receipt")


@dataclass(frozen=True)
class Approval:
    approval_id: str
    run_id: str
    action: Action
    human_response_ref: str

    def covers(self, run_id: str, action: Action) -> bool:
        # Only authenticated ingress may create this record; IDs are not proof.
        return bool(self.human_response_ref and self.approval_id
                    and self.run_id == run_id
                    and approval_key(run_id, action) is not None
                    and same_target(self.action, action))


@dataclass(frozen=True)
class Confirmation:
    ref: AttemptRef
    request_id: str  # Unique CO callback ID, not just Native item/turn ID.
    decision: Decision
    requested_action: Action
    reason: str
    native_source: str
    # False for Native hard constraints; Normal cannot override these.
    can_respond: bool


class HumanAnswer(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    INSTRUCT = "instruct"
    STOP_RUN = "stop_run"


@dataclass(frozen=True)
class QuestionRef:
    """Pre-execution questions deliberately have no invented Attempt."""
    run_id: str
    job_id: str
    attempt_id: str | None = None


@dataclass(frozen=True)
class HumanResponse:
    response_id: str
    ref: QuestionRef
    request_id: str
    action: Action
    answer: HumanAnswer
    authenticated_source_ref: str
    detail: str = ""


class Resolution(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    CANCEL = "cancel"


@dataclass(frozen=True)
class ConfirmationResponse:
    """Controller resolution, not a new human approval.

    decision_ref links to rejudgment and any reused approval or human response.
    instruct/stop_run are handled by Controller, not blindly mapped to allow.
    """
    ref: AttemptRef
    request_id: str
    action: Action
    resolution: Resolution
    decision_ref: str


def validate_response(request: Confirmation, response: ConfirmationResponse) -> None:
    if (request.ref != response.ref or request.request_id != response.request_id
            or request.requested_action != response.action or not response.decision_ref):
        raise ValueError("response does not bind to this confirmation")
    if not request.can_respond:
        raise ValueError("Native constraint cannot be answered")
    if response.resolution == Resolution.ALLOW and (
            request.decision == Decision.DENY or not response.action.scope.known):
        raise ValueError("cannot allow Native deny or unresolved scope")


class StopStatus(str, Enum):
    REQUESTED = "requested"  # Native acknowledged the request only.
    CONFIRMED = "confirmed"  # Execution cessation observed with evidence.
    UNCONFIRMED = "unconfirmed"  # May still be running; do not retry yet.
    UNSUPPORTED = "unsupported"
    ERROR = "error"


@dataclass(frozen=True)
class StopReply:
    ref: AttemptRef
    status: StopStatus
    reason: str
    evidence_ref: str | None = None

    def __post_init__(self):
        if self.status == StopStatus.CONFIRMED and not self.evidence_ref:
            raise ValueError("confirmed stop requires cessation evidence")


@dataclass(frozen=True)
class Usage:
    model: str
    adapter: str
    remaining_percent: float
    updated_at: str
    source_ref: str
    # Different buckets/windows must not be silently compared.
    window: str

    def __post_init__(self):
        if (not math.isfinite(self.remaining_percent)
                or not 0 <= self.remaining_percent <= 100):
            raise ValueError("invalid remaining percentage")
        if not all((self.model, self.adapter, self.updated_at, self.source_ref, self.window)):
            raise ValueError("usage needs identity, time, source and window")


@dataclass(frozen=True)
class Result:
    ref: AttemptRef
    status: State
    reason: str | None = None
    detail: str = ""
    artifact_refs: tuple[str, ...] = ()

    def __post_init__(self):
        if self.status not in TERMINAL:
            raise ValueError("Result must be terminal")
        if self.status != State.COMPLETED and not self.reason:
            raise ValueError("unsuccessful Result requires reason")
        if self.reason == "ac_unmet":
            raise ValueError("AC verdict belongs in a separate record")


@dataclass(frozen=True)
class ACRecord:
    ref: AttemptRef
    verdict: str
    evidence_refs: tuple[str, ...]
    # Exact persisted output digest the check was bound to; None means no output.
    output_digest: str | None = None

    def __post_init__(self):
        if self.verdict not in {"pass", "fail", "incomplete", "blocked", "not_run"}:
            raise ValueError("invalid AC verdict")
        if self.output_digest is not None and not _is_digest(self.output_digest):
            raise ValueError("invalid output digest")


@dataclass(frozen=True)
class StatusEvent:
    ref: AttemptRef
    event_id: str
    state: State
    evidence_ref: str | None = None


@dataclass(frozen=True)
class ConfirmationEvent:
    ref: AttemptRef
    event_id: str
    confirmation: Confirmation

    def __post_init__(self):
        if self.ref != self.confirmation.ref:
            raise ValueError("confirmation/attempt mismatch")


@dataclass(frozen=True)
class ResultEvent:
    ref: AttemptRef
    event_id: str
    result: Result

    def __post_init__(self):
        if self.ref != self.result.ref:
            raise ValueError("result/attempt mismatch")


AdapterEvent = StatusEvent | ConfirmationEvent | ResultEvent


class Adapter(Protocol):
    """Nonblocking receipt + bounded poll. Calls serialized per Attempt.

    IDs/order are stable across repeated polls; Controller deduplicates event_id.
    Infrastructure failures use error replies/results, never empty success.
    Implementations reject stale/cross-Adapter states and terminal resumes.
    """
    def execute(self, request: ExecuteRequest) -> OperationReply: ...
    def events(self, ref: AttemptRef, after: str | None = None) -> tuple[AdapterEvent, ...]: ...
    def respond(self, response: ConfirmationResponse) -> OperationReply: ...
    def resume(self, state: ResumeState) -> OperationReply: ...
    def stop(self, ref: AttemptRef) -> StopReply: ...
    def status(self, ref: AttemptRef) -> StatusEvent: ...
    def usage(self) -> tuple[Usage, ...]: ...  # Empty means unavailable, never 0/100.


@dataclass(frozen=True)
class Rejection:
    ref: QuestionRef
    action: Action
    method: str  # Semantic approach, independent of Worker/route/Job display name.
    human_response_ref: str


@dataclass(frozen=True)
class ConfirmationTimeout:
    ref: QuestionRef
    request_id: str
    action: Action
    deadline: str  # UTC RFC3339; this is neither Approval nor Rejection.


@dataclass(frozen=True)
class WaitingHuman:
    ref: QuestionRef
    request_id: str
    action: Action
    decision: Decision
    reason: str
    deadline: str
    # Resume secrets are stored separately in a protected CO state store.
    resume_state_ref: str | None = None


def _is_digest(value) -> bool:
    """Exact 'sha256:<64 lowercase hex>' identity; no decoding elsewhere."""
    return (type(value) is str and len(value) == 71
            and value.startswith('sha256:')
            and all(ch in '0123456789abcdef' for ch in value[7:]))


@dataclass(frozen=True)
class TaskProfile:
    """Host-owned task profile pinned at Run creation; never client-supplied.

    routes enumerates the exact (model, adapter, environment_ref) identities
    this profile revision may dispatch to, bound inside revision_digest. A
    pure profile's route list must be reviewed to cover only verified
    text-only/no-tools/no-write environments for that revision.
    """
    profile_id: str
    # sha256:<hex> of the reviewed host profile entry revision.
    revision_digest: str
    effect_class: str
    requires_output: bool = False
    routes: tuple[tuple[str, str, str], ...] = ()

    def __post_init__(self):
        if not isinstance(self.profile_id, str) or not self.profile_id.strip():
            raise ValueError("pinned profile identity required")
        if not _is_digest(self.revision_digest):
            raise ValueError("pinned sha256 profile revision required")
        if self.effect_class not in {"pure", "effectful"}:
            raise ValueError("unknown effect class")
        if type(self.requires_output) is not bool:
            raise ValueError("requires_output must be bool")
        routes = tuple(self.routes)
        if (any(type(r) is not tuple or len(r) != 3
                or any(not isinstance(v, str) or not v.strip() for v in r)
                for r in routes) or len(set(routes)) != len(routes)):
            raise ValueError("exact unique route identities required")
        object.__setattr__(self, "routes", routes)


OUTPUT_MEDIA_TYPES = frozenset({'text/plain', 'text/markdown'})


@dataclass(frozen=True)
class OutputItem:
    """Transient collector return; output text is never persisted in control state."""
    index: int
    media_type: str
    text: str

    def __post_init__(self):
        if type(self.index) is not int or self.index < 0:
            raise ValueError("item index must be a nonnegative integer")
        if self.media_type not in OUTPUT_MEDIA_TYPES:
            raise ValueError("unsupported output media type")
        if not isinstance(self.text, str):
            raise ValueError("text output must be str")


@dataclass(frozen=True)
class OutputItemMeta:
    """Persisted ordered metadata for one exact UTF-8 output blob."""
    index: int
    media_type: str
    blob_digest: str
    size: int

    def __post_init__(self):
        if type(self.index) is not int or self.index < 0:
            raise ValueError("item index must be a nonnegative integer")
        if self.media_type not in OUTPUT_MEDIA_TYPES:
            raise ValueError("unsupported output media type")
        if not _is_digest(self.blob_digest):
            raise ValueError("invalid blob digest")
        if type(self.size) is not int or self.size < 0:
            raise ValueError("item size must be a nonnegative integer")


@dataclass(frozen=True)
class OutputRef:
    """Binds a content-only output digest to the exact producing Attempt."""
    attempt_ref: AttemptRef
    digest: str

    def __post_init__(self):
        if type(self.attempt_ref) is not AttemptRef:
            raise ValueError("typed AttemptRef required")
        if not _is_digest(self.digest):
            raise ValueError("invalid output digest")


@dataclass(frozen=True)
class AttemptOutput:
    """Persisted output identity for an Attempt; bodies live as content blobs.

    created_at is owned and stamped by control state on first commit; the
    store never sets it and it is not part of the content digest.
    """
    attempt_ref: AttemptRef
    digest: str
    items: tuple[OutputItemMeta, ...]
    total_bytes: int
    created_at: str | None = None

    def __post_init__(self):
        if type(self.attempt_ref) is not AttemptRef:
            raise ValueError("typed AttemptRef required")
        if not _is_digest(self.digest):
            raise ValueError("invalid output digest")
        items = tuple(self.items)
        if (any(type(item) is not OutputItemMeta for item in items)
                or tuple(item.index for item in items) != tuple(range(len(items)))):
            raise ValueError("ordered item metadata required")
        if (type(self.total_bytes) is not int or self.total_bytes < 0
                or self.total_bytes != sum(item.size for item in items)):
            raise ValueError("total_bytes must equal the item size sum")
        if self.created_at is not None and (
                not isinstance(self.created_at, str) or not self.created_at.strip()):
            raise ValueError("created_at must be None or nonempty")
        object.__setattr__(self, "items", items)


@dataclass(frozen=True)
class RunOutputSelection:
    """Committed single accepted output candidate; immutable with the terminal Run."""
    run_id: str
    job_id: str
    attempt_ref: AttemptRef
    output_digest: str
    selected_at: str

    def __post_init__(self):
        if (type(self.attempt_ref) is not AttemptRef
                or (self.attempt_ref.run_id, self.attempt_ref.job_id)
                != (self.run_id, self.job_id)
                or not self.run_id or not self.job_id):
            raise ValueError("selection must bind the exact Job attempt")
        if not _is_digest(self.output_digest):
            raise ValueError("invalid output digest")
        if not isinstance(self.selected_at, str) or not self.selected_at.strip():
            raise ValueError("selection time required")


COLLECTION_FAILURE_KINDS = frozenset(
    {"collection_unavailable", "integrity_failure", "policy_failure"})


class CollectionError(RuntimeError):
    """Collector-declared recoverable unavailability; never a verdict."""


@dataclass(frozen=True)
class JobFailure:
    """Controller-owned collection outcome for a ceased Attempt.

    Distinct from ACRecord: this is not an independent verifier finding and
    carries only a closed kind plus opaque evidence references, never
    exception text or Native content.
    """
    job: Job
    result: Result
    kind: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self):
        if self.kind not in COLLECTION_FAILURE_KINDS:
            raise ValueError("unknown collection failure kind")
        if (type(self.job) is not Job or type(self.result) is not Result
                or (self.result.ref.run_id, self.result.ref.job_id)
                != (self.job.run_id, self.job.job_id)):
            raise ValueError("failure must bind the stored Job and Result")
        if (type(self.evidence_refs) is not tuple or not self.evidence_refs
                or any(not isinstance(r, str) or not r.strip()
                       for r in self.evidence_refs)):
            raise ValueError("opaque evidence references required")


@runtime_checkable
class OutputCollector(Protocol):
    """Optional post-cessation output collection; absence means unverified.

    Implementations raise CollectionError for recoverable unavailability.
    """
    def collect_output(self, ref: AttemptRef) -> tuple[OutputItem, ...]: ...
