"""Host-only northbound Gateway seam on the control store (#190 M3).

One BEGIN IMMEDIATE per submit covers authentication, claim replay,
idempotency-key lookup, bounded local profile resolution, shared Run
creation, the gateway rows and exactly one ingress claim. Projection,
cancel, HTTP mapping, driver and GC are separate later chunks; northbound
serialization must be allowlist-only and never emit run_id. Keys are
retained indefinitely in this chunk (satisfies the >=24h floor); expiry
is a later chunk.
The driver-only project() additionally derives bound expiry through the
pinned bound_resolver callback and applies the shared durable stop
barrier (origin 'projection_decided') atomically with a new decisive
failed row on a non-terminal Run. Registry loading, minimum-bound
validation and startup ProfileRegistryMismatch refusal remain a later
composition chunk, not claimed here.
"""
from dataclasses import dataclass
from datetime import timedelta
import json
import math
import secrets
from uuid import uuid4

from . import contracts as c
from .responses_input import MAX_BODY_BYTES, RequestRejected, TaskIntent, parse
from .state import (Conflict, IntegrityViolation, NotFound, RoutingRecord,
                    RunSnapshot, UntrustedInput,
                    _accepted_candidates, _goal_binds_latest,
                    _latest_attempts, _never_started, _request_stop_locked,
                    _settled, _time, _unpack)

MAX_CANONICAL_BYTES = MAX_BODY_BYTES + 4096

# Decisive statuses are write-once in gateway_projections; reads/cancel never
# persist them. Closed failure codes; anything else maps to run_failed.
DECISIVE = frozenset({'completed', 'failed', 'cancelled'})
PROJECTION_CODES = frozenset({
    'provider_refusal', 'content_filter', 'protocol_violation',
    'output_unavailable', 'approval_required', 'integrity_violation',
    'cessation_unconfirmed', 'cancellation_unconfirmed', 'run_failed'})
class GatewayRejected(Exception):
    """Fixed-code northbound rejection; never echoes client bytes."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Submission:
    """Gateway result; run_id is host-internal and never serialized north."""
    response_id: str
    run_id: str
    alias: str
    created: bool


@dataclass(frozen=True)
class RequestContext:
    """Trusted serializer context for the authenticated HTTP surface.

    intent is reparsed from the persisted canonical original_intent and
    created_at is the epoch of gateway_responses.created_at — the trusted
    store clock captured at original submit, durable across restarts and
    broker replays, never metadata or client-supplied time. Carries no
    run/attempt ids and adds no wire fields.
    """
    response_id: str
    intent: TaskIntent
    created_at: int


def submit_body(request_digest: str, idempotency_key) -> dict:
    return {'operation': 'gateway_submit', 'request_digest': request_digest,
            'idempotency_key': idempotency_key}


def lookup_body(response_id: str) -> dict:
    return {'operation': 'gateway_lookup', 'response_id': response_id}


def cancel_body(response_id: str) -> dict:
    return {'operation': 'gateway_cancel', 'response_id': response_id}


@dataclass(frozen=True)
class Projection:
    """Northbound Run view; run_id is host-internal and never present."""
    response_id: str
    status: str               # queued|in_progress|completed|failed|cancelled
    code: 'str | None'        # closed PROJECTION_CODES; only when failed
    run_revision: int
    decided: bool             # True only for the persisted write-once row
    output: 'tuple | None'    # (OutputRef, AttemptOutput) when completed


def _selection(data):
    """Committed-data selection check; (OutputRef, AttemptOutput) or None."""
    sel = data['run'].output_selection
    if (type(sel) is not c.RunOutputSelection
            or sel.run_id != data['run'].run_id
            or data['run'].state is not c.State.COMPLETED
            or data['run'].stop_requested):
        return None
    accepted = _accepted_candidates(data)
    if len(accepted) != 1:
        return None
    job, attempt, _goal = next(iter(accepted.values()))
    if (job.job_id, attempt.ref, attempt.output.digest) != (
            sel.job_id, sel.attempt_ref, sel.output_digest):
        return None
    if attempt.ac.output_digest != sel.output_digest:
        return None
    latest = _latest_attempts(data)
    bound = {g.job.job_id for g in data.get('job_goals', [])
             if g.completed and _goal_binds_latest(g, latest)}
    if bound != set(data['jobs']):
        return None
    goals = data.get('run_goals', [])
    if (not goals or goals[-1].finding.verdict != 'pass'
            or goals[-1].revision >= data['run'].revision):
        return None
    return c.OutputRef(sel.attempt_ref, sel.output_digest), attempt.output


def _cancel_settled(data, attempt):
    """Monotonic cancel fact: CONFIRMED cessation or exact NeverStarted."""
    return (_never_started(data, attempt)
            or (attempt.stop_reply is not None
                and attempt.stop_reply.status == c.StopStatus.CONFIRMED))


def _attempt_question(attempt):
    """Exact full QuestionRef identifying this Attempt for committed
    RoutingRecord and WaitingHuman correlation; never a bare id."""
    ref = attempt.ref
    return c.QuestionRef(ref.run_id, ref.job_id, ref.attempt_id)


def _admitted_at(data, attempt):
    """Committed admission stamp: the unique routing_history RoutingRecord
    whose ref is this Attempt's exact QuestionRef and whose
    execution_decision_ref is not None, parsed by trusted _time. Missing,
    non-unique, wrong-typed, malformed, naive or non-string entries mean
    no bound: the Attempt stays undecided, never an exception."""
    ref = _attempt_question(attempt)
    matches = [r for r in data.get('routing_history', {}).values()
               if type(r) is RoutingRecord and r.ref == ref
               and r.execution_decision_ref is not None]
    if len(matches) != 1:
        return None
    try:
        return _time(matches[0].at)
    except Exception:
        return None


def _bound_elapsed(data, attempt, bound, now):
    """admitted_at + bound <= now. No valid admission stamp means never
    elapsed; a naive/aware mismatch or a near-max timestamp sum that
    overflows means undecided, never an exception."""
    admitted = _admitted_at(data, attempt)
    if admitted is None:
        return False
    try:
        return admitted + bound <= now
    except (TypeError, OverflowError):
        return False


def _attempt_waits(data, attempt):
    """Committed wait records bound to this Attempt, open or closed."""
    ref = _attempt_question(attempt)
    return [w for w in data.get('waits', {}).values()
            if getattr(w.get('wait'), 'ref', None) == ref]


def _has_open_wait(data, attempt):
    return any(w.get('closed') is None for w in _attempt_waits(data, attempt))


def _expired_unsettled(data, bound, now):
    """Unsettled Attempts (unchanged _settled) whose committed admission
    bound has elapsed; an open wait on the Attempt excludes it entirely."""
    return [a for a in data['attempts'].values()
            if not _settled(data, a)
            and not _has_open_wait(data, a)
            and _bound_elapsed(data, a, bound, now)]


def _derive(data, bound=None, now=None):
    """Derive (status, code, output) from committed state; first match wins.
    bound/now are supplied only by project(): read() and cancel() pass
    neither and never decide expiry."""
    run = data['run']
    if run.state in c.TERMINAL:
        if run.state is c.State.COMPLETED:
            if run.stop_requested:
                return 'failed', 'integrity_violation', None
            if run.output_selection is None:
                return 'failed', 'output_unavailable', None
            selected = _selection(data)
            if selected is None:
                return 'failed', 'integrity_violation', None
            return 'completed', None, selected
        if run.final_reason == 'integrity_violation':
            return 'failed', 'integrity_violation', None
        if run.stop_requested:
            if data.get('stop_origin') == 'approval_required':
                return 'failed', 'approval_required', None
            return 'cancelled', None, None
        if run.final_reason in PROJECTION_CODES:
            return 'failed', run.final_reason, None
        return 'failed', 'run_failed', None
    checkpoint = data.get('controller_checkpoint')
    if getattr(checkpoint, 'halted', None) == 'integrity_violation':
        return 'failed', 'integrity_violation', None
    if run.stop_requested and data.get('stop_origin') == 'approval_required':
        # The committed barrier already makes success impossible: decisive
        # immediately, whatever the cessation state.
        return 'failed', 'approval_required', None
    expired = (() if bound is None or now is None
               else _expired_unsettled(data, bound, now))
    if run.stop_requested:
        if all(_cancel_settled(data, a) for a in data['attempts'].values()):
            return 'cancelled', None, None
        if any(not _cancel_settled(data, a) for a in expired):
            return 'failed', 'cancellation_unconfirmed', None
    elif expired:
        if any(a.stop_reply is None
               or a.stop_reply.status != c.StopStatus.CONFIRMED
               for a in expired):
            return 'failed', 'cessation_unconfirmed', None
        if all(a.result is None and not _attempt_waits(data, a)
               for a in expired):
            return 'failed', 'run_failed', None
    if not data['attempts']:
        return 'queued', None, None
    return 'in_progress', None, None


def _row_view(response_id, data, row):
    """Fail-closed validation of a persisted write-once projection row."""
    status, code, run_revision, _at = row
    if (status not in DECISIVE
            or (status == 'failed') != (code is not None)
            or (code is not None and code not in PROJECTION_CODES)
            or type(run_revision) is not int
            or run_revision < 0 or run_revision > data['run'].revision):
        raise IntegrityViolation('invalid persisted projection')
    output = None
    if status == 'completed':
        output = _selection(data)
        if output is None:
            raise IntegrityViolation('persisted completion lacks valid selection')
    elif (status == 'cancelled'
          and (not data['run'].stop_requested
               or data.get('stop_origin') not in ('intake', 'gateway_cancel'))):
        raise IntegrityViolation('persisted cancel without committed cancel stop')
    elif (status == 'failed' and code == 'approval_required'
          and data['run'].state not in c.TERMINAL
          and data.get('stop_origin') != 'approval_required'):
        raise IntegrityViolation('persisted approval failure without approval origin')
    elif (data['run'].state not in c.TERMINAL
          and not data['run'].stop_requested):
        raise IntegrityViolation('persisted decision without committed stop')
    return Projection(response_id, status, code, run_revision, True, output)


class Gateway:
    def __init__(self, store, bound_resolver=None):
        """bound_resolver: trusted host callback
        (profile_id, revision_digest) -> unconfirmed_after_seconds | None,
        pinned per Run by revision_digest. A missing resolver, profile or
        entry means no expiry bound; registry load validation and startup
        mismatch refusal are a later composition chunk."""
        self._store = store
        self._bound_resolver = bound_resolver

    @staticmethod
    def _key_valid(key):
        return (type(key) is str and 1 <= len(key) <= 255
                and all(0x21 <= ord(ch) <= 0x7E for ch in key))

    @staticmethod
    def _verified(intent):
        """Reparse canonical bytes; a forged or drifted TaskIntent writes
        nothing and fails as UntrustedInput before authentication."""
        if type(intent) is not TaskIntent:
            raise UntrustedInput('typed parsed TaskIntent required')
        try:
            reparsed = parse(intent.canonical_body, limit=MAX_CANONICAL_BYTES)
        except RequestRejected:
            raise UntrustedInput('request does not reparse to intent') from None
        if reparsed != intent:
            raise UntrustedInput('request does not reparse to intent')

    def _response(self, response_id, created):
        row = self._store._db.execute(
            'SELECT run_id, alias FROM gateway_responses WHERE response_id=?',
            (response_id,)).fetchone()
        if row is None:
            raise IntegrityViolation('claim references missing response')
        return Submission(response_id, row[0], row[1], created)

    def _resolve(self, alias):
        try:
            profile = self._store._profile_resolver(alias)
        except Exception:
            raise GatewayRejected('model_not_found') from None
        if type(profile) is not c.TaskProfile:
            raise GatewayRejected('model_not_found')
        return profile

    def submit(self, intent: TaskIntent, idempotency_key,
               ingress_ref: str) -> Submission:
        self._verified(intent)
        if idempotency_key is not None and not self._key_valid(idempotency_key):
            raise GatewayRejected('invalid_idempotency_key')
        s = self._store
        with s._tx():
            receipt = s._auth(ingress_ref,
                submit_body(intent.body_hash, idempotency_key), s.now())
            principal = receipt.principal
            claimed = s._claimed(receipt)
            if claimed is not None:
                if (type(claimed) is tuple and len(claimed) == 4
                        and claimed[0] == 'gateway_submit'
                        and claimed[2] == intent.body_hash
                        and claimed[3] == idempotency_key):
                    return self._response(claimed[1], created=False)
                raise Conflict('source event already consumed')
            if idempotency_key is not None:
                row = s._db.execute(
                    'SELECT request_digest, response_id FROM gateway_keys'
                    ' WHERE principal=? AND key=?',
                    (principal, idempotency_key)).fetchone()
                if row is not None:
                    if row[0] == intent.body_hash:
                        s._claim_ingress(receipt, ('gateway_submit', row[1],
                            intent.body_hash, idempotency_key))
                        return self._response(row[1], created=False)
                    raise Conflict('idempotency_conflict')
            profile = self._resolve(intent.model)
            if profile.effect_class == 'effectful':
                if idempotency_key is None:
                    raise GatewayRejected('idempotency_key_required')
                if not intent.background:
                    raise GatewayRejected('background_required')
            response_id = 'resp_' + secrets.token_urlsafe(32)
            run, _created = s._create_run_locked(
                'run_' + uuid4().hex, intent.canonical_body.decode('utf-8'),
                ingress_ref, receipt, profile)
            now = s.now()
            s._db.execute('INSERT INTO gateway_responses VALUES (?,?,?,?,?,?)',
                (response_id, principal, run.run_id, intent.body_hash,
                 intent.model, now))
            if idempotency_key is not None:
                s._db.execute('INSERT INTO gateway_keys VALUES (?,?,?,?)',
                    (principal, idempotency_key, intent.body_hash, response_id))
            s._db.execute('INSERT INTO gateway_work VALUES (?,?)',
                          (run.run_id, now))
            s._claim_ingress(receipt, ('gateway_submit', response_id,
                intent.body_hash, idempotency_key))
            return Submission(response_id, run.run_id, intent.model, True)

    def lookup(self, response_id: str, ingress_ref: str) -> Submission:
        """Principal-scoped read: no claim, no write, indistinguishable 404."""
        s = self._store
        with s._lock:
            receipt = s._auth(ingress_ref, lookup_body(response_id), s.now())
            row = s._db.execute(
                'SELECT run_id, alias, principal FROM gateway_responses'
                ' WHERE response_id=?', (response_id,)).fetchone()
            if row is None or row[2] != receipt.principal:
                raise NotFound('response not found')
            return Submission(response_id, row[0], row[1], False)

    def pending_work(self) -> tuple:
        """Enqueued run_ids whose Run is not terminal, in enqueue order."""
        s = self._store
        with s._lock:
            return tuple(run_id for (run_id,) in s._db.execute(
                    'SELECT run_id FROM gateway_work'
                    ' ORDER BY enqueued_at, run_id')
                if self._work_entry(run_id)[1]['run'].state
                not in c.TERMINAL)

    def _work_entry(self, run_id):
        """Verified (response_id, data) for an enqueued Run. Any missing
        row, untyped or mismatched Run, or unreadable aggregate is a
        global failure, never per-Run."""
        s = self._store
        resp = s._db.execute(
            'SELECT response_id FROM gateway_responses WHERE run_id=?',
            (run_id,)).fetchone()
        if resp is None:
            raise IntegrityViolation('gateway work lacks response row')
        try:
            data, _before = s._load_locked(run_id)
        except NotFound:
            raise IntegrityViolation(
                'gateway work references missing Run') from None
        run = data.get('run')
        if type(run) is not RunSnapshot or run.run_id != run_id:
            raise IntegrityViolation('gateway work Run binding mismatch')
        return resp[0], data

    def all_work(self) -> tuple:
        """Every enqueued run_id in enqueue order; each entry's Run and
        response row verified, so driver start() validation sees real
        work-list integrity failures instead of skipping them."""
        s = self._store
        with s._lock:
            work = []
            for (run_id,) in s._db.execute(
                    'SELECT run_id FROM gateway_work'
                    ' ORDER BY enqueued_at, run_id'):
                self._work_entry(run_id)
                work.append(run_id)
            return tuple(work)

    def unprojected_work(self) -> tuple:
        """Enqueued run_ids with no projection row, in enqueue order."""
        s = self._store
        with s._lock:
            pending = []
            for (run_id,) in s._db.execute(
                    'SELECT run_id FROM gateway_work'
                    ' ORDER BY enqueued_at, run_id'):
                response_id, _data = self._work_entry(run_id)
                if s._db.execute(
                        'SELECT 1 FROM gateway_projections WHERE response_id=?',
                        (response_id,)).fetchone() is None:
                    pending.append(run_id)
            return tuple(pending)

    def _view(self, response_id, data):
        """Persisted row if any (validated), else a non-decisive derivation.

        Northbound surfaces never persist a decisive status: until the driver
        projects, a decisive derivation is reported as in_progress.
        """
        row = self._store._db.execute(
            'SELECT status, code, run_revision, at FROM gateway_projections'
            ' WHERE response_id=?', (response_id,)).fetchone()
        if row is not None:
            return _row_view(response_id, data, row)
        status, code, output = _derive(data)
        if status in DECISIVE:
            status, code, output = 'in_progress', None, None
        return Projection(response_id, status, code, data['run'].revision,
                          False, output)

    def _row_for(self, response_id, receipt):
        row = self._store._db.execute(
            'SELECT run_id, principal FROM gateway_responses'
            ' WHERE response_id=?', (response_id,)).fetchone()
        if row is None or row[1] != receipt.principal:
            raise NotFound('response not found')
        return row[0]

    def _bound(self, data):
        """Pinned expiry bound as timedelta, or None for missing resolver,
        profile or registry entry. A malformed callback value (bool,
        non-numeric, non-finite, negative, overflowing timedelta) is a
        fixed ValueError raised before any projection write."""
        resolver = self._bound_resolver
        profile = data['run'].profile
        if resolver is None or profile is None:
            return None
        seconds = resolver(profile.profile_id, profile.revision_digest)
        if seconds is None:
            return None
        if (type(seconds) is bool or type(seconds) not in (int, float)
                or (type(seconds) is float and not math.isfinite(seconds))
                or seconds < 0):
            raise ValueError('invalid unconfirmed bound')
        try:
            return timedelta(seconds=seconds)
        except OverflowError:
            raise ValueError('invalid unconfirmed bound') from None

    def read_context(self, response_id: str,
                     ingress_ref: str) -> RequestContext:
        """Principal-scoped serializer context in one BEGIN IMMEDIATE.

        Same one-shot lookup-body authentication as read(); foreign or
        absent response_id is the identical indistinguishable NotFound
        before any Run load. The original submit receipt is never
        re-authenticated — IngressBroker pops one-shot refs. created_at
        is the durable gateway_responses.created_at (trusted store clock
        at submit). Drifted canonical bytes, a digest/alias/Run binding
        mismatch or an invalid stored timestamp are IntegrityViolation.
        """
        s = self._store
        with s._tx():
            receipt = s._auth(ingress_ref, lookup_body(response_id), s.now())
            row = s._db.execute(
                'SELECT run_id, principal, request_digest, alias, created_at'
                ' FROM gateway_responses WHERE response_id=?',
                (response_id,)).fetchone()
            if row is None or row[1] != receipt.principal:
                raise NotFound('response not found')
            data, _before = s._load_locked(row[0])
            run = data['run']
            original = getattr(run, 'original_intent', None)
            if (type(run) is not RunSnapshot or run.run_id != row[0]
                    or type(original) is not str):
                raise IntegrityViolation('response Run binding mismatch')
            try:
                raw = original.encode('utf-8')
                intent = parse(raw, limit=MAX_CANONICAL_BYTES)
            except (UnicodeEncodeError, RequestRejected):
                raise IntegrityViolation(
                    'stored request does not reparse') from None
            if (intent.canonical_body != raw or intent.body_hash != row[2]
                    or intent.model != row[3]):
                raise IntegrityViolation('stored request binding mismatch')
            try:
                epoch = _time(row[4]).timestamp()
            except Exception:
                raise IntegrityViolation('stored created_at invalid') from None
            if not math.isfinite(epoch) or epoch < 0:
                raise IntegrityViolation('stored created_at invalid')
            return RequestContext(response_id, intent, int(epoch))

    def read(self, response_id: str, ingress_ref: str) -> Projection:
        """Principal-scoped write-free projection read (lookup auth body)."""
        s = self._store
        with s._tx():
            receipt = s._auth(ingress_ref, lookup_body(response_id), s.now())
            data, _before = s._load_locked(self._row_for(response_id, receipt))
            return self._view(response_id, data)

    def cancel(self, response_id: str, ingress_ref: str) -> Projection:
        """Authenticated principal cancel in one BEGIN IMMEDIATE.

        Exactly one claim and one revision bump on the first applied stop;
        absent/foreign is an indistinguishable NotFound before any write;
        terminal or already-stopped is a write-free no-op returning the
        non-decisive view. No HumanResponse is fabricated.
        """
        s = self._store
        with s._tx():
            receipt = s._auth(ingress_ref, cancel_body(response_id), s.now())
            run_id = self._row_for(response_id, receipt)
            data, before = s._load_locked(run_id)
            if _request_stop_locked(s, data, 'gateway_cancel'):
                s._claim_ingress(receipt, ('gateway_cancel', response_id))
                s._store_locked(run_id, data, before)
            return self._view(response_id, data)

    def project(self, run_id: str) -> Projection:
        """Host-driver sole writer: INSERT the first decisive derivation.

        An existing row is verified against committed state and returned,
        never updated; a later latch, contradiction or CONFIRMED upgrade
        never rewrites it. Non-decisive derivations are never persisted.
        Sole expiry-deciding surface: a resolver/entry miss or a malformed
        admission stamp leaves the Run undecided, and callback validation
        failures raise before any write. A newly decisive failed row on a
        non-terminal Run commits with the existing stop barrier in the
        same BEGIN IMMEDIATE, so no retry can be admitted after the
        public decision; the row records the bumped revision.
        """
        s = self._store
        with s._tx():
            row = s._db.execute(
                'SELECT response_id FROM gateway_responses WHERE run_id=?',
                (run_id,)).fetchone()
            if row is None:
                raise NotFound('response not found')
            response_id = row[0]
            data, before = s._load_locked(run_id)
            existing = s._db.execute(
                'SELECT status, code, run_revision, at FROM gateway_projections'
                ' WHERE response_id=?', (response_id,)).fetchone()
            if existing is not None:
                return _row_view(response_id, data, existing)
            bound = None
            now = None
            if data['run'].state not in c.TERMINAL:
                bound = self._bound(data)
                if bound is not None:
                    now = _time(s.now())
            status, code, output = _derive(data, bound, now)
            decided = status in DECISIVE
            if decided:
                if (status == 'failed'
                        and data['run'].state not in c.TERMINAL):
                    _request_stop_locked(s, data, 'projection_decided')
                    s._store_locked(run_id, data, before)
                s._db.execute(
                    'INSERT INTO gateway_projections VALUES (?,?,?,?,?)',
                    (response_id, status, code, data['run'].revision, s.now()))
            return Projection(response_id, status, code,
                              data['run'].revision, decided, output)
