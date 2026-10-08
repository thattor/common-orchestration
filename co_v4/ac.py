"""Independent, host-composed checks; Worker completion is never acceptance.

The verifier must actually inspect artifacts/tests or obtain a trusted review.
These in-process receipts bind those findings, but do not authenticate them.
No default verifier, shell execution, or provider-specific logic is supplied.
"""
from dataclasses import dataclass
from typing import Callable

from .contracts import ACRecord, Job, OutputRef, Result
from .state import RunSnapshot, body_digest

VERDICTS = frozenset({"pass", "fail", "incomplete", "blocked", "not_run"})


@dataclass(frozen=True)
class Finding:
    verdict: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self):
        if (self.verdict not in VERDICTS or type(self.evidence_refs) is not tuple
                or any(not isinstance(r, str) or not r.strip() for r in self.evidence_refs)
                or (self.verdict == "pass" and not self.evidence_refs)):
            raise ValueError("valid verdict and evidence for pass required")


@dataclass(frozen=True)
class JobGoal:
    job: Job
    result: Result
    ac: ACRecord
    goal: Finding

    @property
    def completed(self) -> bool:
        return self.ac.verdict == "pass" and self.goal.verdict == "pass"


CHECK_SCHEMA = "co.check/2"


@dataclass(frozen=True)
class CheckRequest:
    kind: str
    run: RunSnapshot
    job: Job | None = None
    result: Result | None = None
    jobs: tuple[JobGoal, ...] = ()
    # Exact persisted output the evaluation is bound to; None for unbound checks.
    output: OutputRef | None = None
    # Fixed Contract schema, always serialized into body_digest; never omitted.
    schema: str = CHECK_SCHEMA

    def __post_init__(self):
        if self.schema != CHECK_SCHEMA:
            raise ValueError("check request schema must be co.check/2")
        if self.output is not None and type(self.output) is not OutputRef:
            raise ValueError("typed OutputRef required")


@dataclass(frozen=True)
class CheckEvidence:
    request_digest: str
    goal: Finding
    # Ordered one-for-one with the immutable Job.acceptance_criteria.
    criteria: tuple[Finding, ...] = ()


@dataclass(frozen=True)
class RunGoal:
    run_id: str
    revision: int
    request_digest: str
    finding: Finding


def _aggregate(findings: tuple[Finding, ...]) -> Finding:
    verdict = next((v for v in ("fail", "blocked", "not_run", "incomplete")
                    if any(f.verdict == v for f in findings)), "pass")
    return Finding(verdict, tuple(dict.fromkeys(
        r for finding in findings for r in finding.evidence_refs)))


class Acceptance:
    def __init__(self, verifier: Callable[[CheckRequest], CheckEvidence]):
        self._verify = verifier

    def _check(self, request: CheckRequest, count: int) -> CheckEvidence:
        evidence = self._verify(request)
        if (type(evidence) is not CheckEvidence
                or evidence.request_digest != body_digest(request)
                or type(evidence.goal) is not Finding
                or type(evidence.criteria) is not tuple
                or len(evidence.criteria) != count
                or any(type(f) is not Finding for f in evidence.criteria)):
            raise ValueError("unbound or incomplete independent check")
        return evidence

    def job(self, run: RunSnapshot, job: Job, result: Result,
            output: OutputRef | None = None) -> JobGoal:
        if (job.run_id != run.run_id or job not in run.derived_interpretation
                or (result.ref.run_id, result.ref.job_id) != (job.run_id, job.job_id)):
            raise ValueError("check identity mismatch")
        if output is not None and output.attempt_ref != result.ref:
            raise ValueError("output binds a different Attempt")
        request = CheckRequest("job", run, job, result, output=output)
        evidence = self._check(request, len(job.acceptance_criteria))
        # Empty AC is not evidence of completion; the Job Goal still needs proof.
        verdict = _aggregate(evidence.criteria + (evidence.goal,))
        record = ACRecord(result.ref, verdict.verdict, verdict.evidence_refs,
                          output_digest=output.digest if output is not None else None)
        return JobGoal(job, result, record, evidence.goal)

    def run(self, run: RunSnapshot, jobs: tuple[JobGoal, ...]) -> RunGoal:
        if type(jobs) is not tuple:
            raise ValueError("immutable Job findings required")
        for job in jobs:
            if (type(job) is not JobGoal or job.ac.ref != job.result.ref
                    or (job.result.ref.run_id, job.result.ref.job_id)
                    != (job.job.run_id, job.job.job_id)):
                raise ValueError("Job findings must bind to the same Attempt")
        request = CheckRequest("run", run, jobs=jobs)
        digest = body_digest(request)
        # Every inserted Job is required in this minimal controller. Superseding
        # a required Job needs a separate explicit design, never silent omission.
        if (not jobs or tuple(j.job for j in jobs) != run.derived_interpretation
                or any(not j.completed for j in jobs) or run.stop_requested):
            return RunGoal(run.run_id, run.revision, digest, Finding("incomplete"))
        evidence = self._check(request, 0)
        return RunGoal(run.run_id, run.revision, digest, evidence.goal)
