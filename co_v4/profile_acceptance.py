"""Deterministic profile AC verifier (#190 M3 sections 2-3).

Pure predicate evaluation over committed, rehashed output bytes. Every check
re-resolves the Run's pinned registry entry, loads the exact committed
AttemptOutput from control state, and runs the mandatory OutputStore.get
rehash. IntegrityError propagates to the Controller as
output_integrity_failure; binding mismatches produce a fail verdict, never
a pass and never fabricated evidence. No output text, semantic judgment,
extra LLM call or human gate exists here.
"""
import hashlib

from . import contracts as c
from .ac import CHECK_SCHEMA, CheckEvidence, CheckRequest, Finding, JobGoal
from .profile_registry import ProfileRegistry, canonical
from .state import (AttemptSnapshot, NotFound, RunSnapshot, body_digest)


def _evidence(request_digest, output_digest, predicate_id, passed):
    """Deterministic proof-free evidence ref; carries no output text."""
    return 'ac:sha256:' + hashlib.sha256(canonical({
        'request_digest': request_digest, 'output_digest': output_digest,
        'predicate_id': predicate_id, 'passed': passed})).hexdigest()


def _finding(request_digest, output_digest, predicate_id, passed):
    return Finding('pass' if passed else 'fail',
                   (_evidence(request_digest, output_digest,
                              predicate_id, passed),))


def _predicate(predicate, ac, texts, committed):
    """One closed AC predicate on exact rehashed texts; no normalization."""
    if predicate == 'ac:media_types':
        return all(item.media_type in ac.media_types
                   for item in committed.items)
    if predicate == 'ac:max_bytes':
        return (committed.total_bytes <= ac.max_bytes
                and sum(len(text.encode('utf-8')) for text in texts)
                    == committed.total_bytes)
    if predicate == 'ac:non_whitespace':
        return any(not ch.isspace() for text in texts for ch in text)
    if predicate == 'ac:no_forbidden_literals':
        return not any(literal in text
                       for literal in ac.forbidden_literals
                       for text in texts)
    if predicate == 'ac:exact':
        return (ac.exact_any is not None and len(texts) == 1
                and texts[0] in ac.exact_any)
    return False                      # unknown criterion: fail closed


def _run_evidence(request_digest, job_id, passed):
    return 'ac:sha256:' + hashlib.sha256(canonical({
        'request_digest': request_digest, 'job_id': job_id,
        'passed': passed})).hexdigest()


class ProfileVerifier:
    """Callable verifier for Acceptance(verifier); host-composed only.

    state is the trusted control-state handle (get_attempt); output_store
    is the host OutputStore. Neither is reachable from Worker content.
    """

    def __init__(self, registry, state, output_store):
        if (type(registry) is not ProfileRegistry
                or not callable(getattr(state, 'get_attempt', None))
                or not callable(getattr(state, 'attempts', None))
                or not callable(getattr(output_store, 'get', None))):
            raise ValueError('registry, state handle and OutputStore required')
        self._registry = registry
        self._state = state
        self._store = output_store

    def __call__(self, request):
        if type(request) is not CheckRequest or request.schema != CHECK_SCHEMA:
            raise ValueError('typed co.check/2 request required')
        if request.kind == 'job':
            return self._job(request)
        if request.kind == 'run':
            return self._run(request)
        raise ValueError('unknown check kind')

    def _entry(self, run):
        """Resolve the Run's pinned revision on every check; the entry binds
        only when every field the pinned TaskProfile carries matches it
        exactly, so a corrupt profile under the same id/digest fails."""
        profile = getattr(run, 'profile', None)
        if type(profile) is not c.TaskProfile:
            return None
        entry = self._registry.get(profile.profile_id,
                                   profile.revision_digest)
        return (entry if entry is not None
                and profile.effect_class == entry.effect_class
                and profile.requires_output == entry.requires_output
                and tuple(profile.routes) == entry.routes else None)

    def _attempt(self, ref):
        """Exact committed AttemptSnapshot; an absent Attempt is a binding
        miss, while unreadable control state propagates as store
        integrity, never as a verdict."""
        try:
            attempt = self._state.get_attempt(ref)
        except NotFound:
            return None
        return attempt if type(attempt) is AttemptSnapshot else None

    def _job(self, request):
        digest = body_digest(request)
        job, result, run = request.job, request.result, request.run
        output = request.output
        bound = (type(run) is RunSnapshot and type(job) is c.Job
                 and type(result) is c.Result
                 and result.status is c.State.COMPLETED
                 and job.run_id == run.run_id
                 and not run.stop_requested
                 and job in run.derived_interpretation
                 and (result.ref.run_id, result.ref.job_id)
                     == (job.run_id, job.job_id)
                 and type(output) is c.OutputRef
                 and output.attempt_ref == result.ref
                 and request.jobs == ())
        attempt = self._attempt(result.ref) if bound else None
        committed = getattr(attempt, 'output', None)
        bound = (bound and attempt is not None
                 and attempt.result == result
                 and type(committed) is c.AttemptOutput
                 and committed.digest == output.digest)
        entry = self._entry(run) if bound else None
        bound = bound and entry is not None
        criteria = tuple(getattr(job, 'acceptance_criteria', ()) or ())
        bound = bound and criteria == entry.job_criteria
        # Mandatory rehash; IntegrityError propagates, never a verdict.
        texts = self._store.get(output, committed) if bound else None
        out_digest = output.digest if type(output) is c.OutputRef else None
        findings = tuple(_finding(
            digest, out_digest, predicate,
            bool(bound and _predicate(predicate, entry.ac, texts, committed)))
            for predicate in criteria)
        passed = bool(findings) and all(f.verdict == 'pass'
                                        for f in findings)
        refs = tuple(r for f in findings for r in f.evidence_refs)
        return CheckEvidence(digest, Finding('pass' if passed else 'fail',
                                             refs), findings)

    def _run(self, request):
        """RunGoal: every JobGoal completed, bound, and Job ids equal the
        Run's Job set; each AC output_digest equals the committed digest.
        No output body is read and no semantic judgment is made."""
        digest = body_digest(request)
        run, jobs = request.run, request.jobs
        bound = (type(run) is RunSnapshot
                 and request.job is None and request.result is None
                 and request.output is None
                 and type(jobs) is tuple and bool(jobs)
                 and not run.stop_requested
                 and self._entry(run) is not None)
        refs, ok = [], bound
        jobs = jobs if type(jobs) is tuple else ()
        latest = {}
        if bound:
            for attempt in self._state.attempts(run.run_id):
                # Immutable original admission order; last write per Job
                # wins, so the map holds only each Job's latest Attempt.
                if type(attempt) is AttemptSnapshot:
                    latest[attempt.ref.job_id] = attempt
        for goal in jobs:
            job = getattr(goal, 'job', None)
            passed = (type(goal) is JobGoal
                      and type(goal.ac) is c.ACRecord
                      and type(goal.goal) is Finding
                      and type(goal.result) is c.Result
                      and type(goal.ac.ref) is c.AttemptRef
                      and type(goal.result.ref) is c.AttemptRef
                      and goal.ac.verdict == 'pass'
                      and goal.goal.verdict == 'pass'
                      and goal.ac.ref == goal.result.ref
                      and goal.result.status is c.State.COMPLETED
                      and type(job) is c.Job
                      and type(run) is RunSnapshot
                      and job.run_id == run.run_id
                      and (goal.result.ref.run_id, goal.result.ref.job_id)
                          == (job.run_id, job.job_id))
            attempt = latest.get(getattr(job, 'job_id', '')) if passed else None
            committed = getattr(attempt, 'output', None)
            passed = (passed and attempt is not None
                      and attempt.ref == goal.result.ref
                      and attempt.result == goal.result
                      and attempt.ac == goal.ac
                      and type(committed) is c.AttemptOutput
                      and committed.digest == goal.ac.output_digest)
            refs.append(_run_evidence(
                digest, getattr(job, 'job_id', ''), passed))
            ok = ok and passed
        goal_jobs = tuple(getattr(g, 'job', None) for g in jobs)
        ok = (ok
              and goal_jobs == tuple(
                  getattr(run, 'derived_interpretation', None) or ())
              and tuple(getattr(j, 'job_id', None) for j in goal_jobs)
                  == tuple(getattr(run, 'job_ids', None) or ())
              and len({getattr(j, 'job_id', None) for j in goal_jobs})
                  == len(jobs))
        return CheckEvidence(digest,
                             Finding('pass' if ok else 'fail', tuple(refs)),
                             ())
