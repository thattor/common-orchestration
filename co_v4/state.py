"""Transactional CO control state, for trusted host composition only.

SQLite and these handles are NOT a sandbox. The host must keep the database,
verifier, evidence resolver and handles outside Worker reach. No wire decoding
or host isolation is implemented here. Resume bytes never enter public history.
"""
from contextlib import contextmanager
from dataclasses import dataclass, fields, is_dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import hashlib
from functools import cache
import json
from pathlib import Path
import sqlite3
from threading import RLock, get_ident
from typing import Callable
from uuid import uuid4

from . import contracts as c


class NotFound(Exception): pass
class Conflict(Exception): pass
class InvalidTransition(Exception): pass
class UntrustedInput(Exception): pass
class LimitExceeded(Exception): pass
class StoreUnavailable(Exception): pass

class DigestConflict(Conflict): pass

class IntegrityViolation(Conflict): pass


CONTRACT_MARKER = 'co.controller/4'
# Controller release version. Its major is the contract marker's
# generation: a contract change requires a new major, so 4.0.0 pins the
# contract this code implements. Release tooling reads this constant;
# the contract itself is unchanged.
CONTROLLER_VERSION = '4.0.0'

# Host-only northbound gateway seam: created and required together; a marked
# store missing any table refuses StoreUnavailable, never migrates in place.
GATEWAY_TABLES = frozenset({'gateway_responses', 'gateway_keys',
                            'gateway_work', 'gateway_projections'})


def _id(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("nonempty string ID required")


def _immutable(value):
    """Keep trusted in-process inputs deeply immutable; this is not a wire parser."""
    if is_dataclass(value):
        if not value.__dataclass_params__.frozen:
            raise ValueError('frozen control record required')
        for f in fields(value):
            _immutable(getattr(value, f.name))
    elif type(value) is tuple:
        for item in value:
            _immutable(item)
    elif value is not None and not isinstance(value, (str, int, float, bool, bytes, Enum)):
        raise ValueError('mutable control input is not supported')


def _time(value):
    if not isinstance(value, str) or not value.endswith(('Z', '+00:00')):
        raise ValueError("UTC RFC3339 time required")
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None or 'T' not in value:
        raise ValueError("UTC RFC3339 time required")
    return parsed


def _now():
    return datetime.now(timezone.utc).isoformat()


def _pack(value):
    if isinstance(value, Enum):
        return {'enum': type(value).__name__, 'value': value.value}
    if is_dataclass(value):
        return {'type': type(value).__name__, 'fields': {
            f.name: _pack(getattr(value, f.name)) for f in fields(value)}}
    if isinstance(value, tuple):
        return {'tuple': [_pack(v) for v in value]}
    if isinstance(value, dict):
        return {k: _pack(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_pack(v) for v in value]
    if value is None or type(value) in (str, int, bool, float):
        return value
    raise ValueError("unsupported control value (resume bytes require bridge)")


@cache
def _types():
    # Fixed local type registry. Never import or execute a type named by input.
    from . import judgment, ac, controller, catalog
    types = {obj.__name__: obj for module in (c, judgment, ac, controller, catalog)
             for obj in vars(module).values()
             if isinstance(obj, type) and (is_dataclass(obj) or issubclass(obj, Enum))}
    types.update({obj.__name__: obj for obj in (
        Limits, RunSnapshot, AttemptSnapshot, AnswerReceipt, IngressReceipt, WaitDetails, RoutingRecord)})
    return types


def _unpack(value):
    if isinstance(value, list):
        return [_unpack(v) for v in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {'enum', 'value'}:
        return _types()[value['enum']](value['value'])
    if set(value) == {'type', 'fields'}:
        return _types()[value['type']](**{k: _unpack(v) for k, v in value['fields'].items()})
    if set(value) == {'tuple'}:
        return tuple(_unpack(v) for v in value['tuple'])
    return {k: _unpack(v) for k, v in value.items()}


def _json(value):
    return json.dumps(_pack(value), ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def body_digest(value) -> str:
    """Canonical binding for #160 verifier; value is create_run_body or response."""
    return hashlib.sha256(_json(value).encode()).hexdigest()


def create_run_body(run_id: str, original_intent: str) -> dict:
    return {'operation': 'create_run', 'run_id': run_id, 'original_intent': original_intent}


@dataclass(frozen=True)
class Limits:
    jobs: int = 20
    attempts_per_job: int = 5
    attempts_per_pair: int = 2
    # Only a verifier's create-run receipt can grant these ranges.
    minimums: tuple[int, int, int] = (1, 1, 1)
    ceilings: tuple[int, int, int] = (20, 5, 2)

    def __post_init__(self):
        if (type(self.minimums) is not tuple or type(self.ceilings) is not tuple
                or len(self.minimums) != 3 or len(self.ceilings) != 3):
            raise ValueError('three immutable limit bounds required')
        for value, low, high in zip(self.values, self.minimums, self.ceilings):
            if any(type(n) is not int for n in (value, low, high)) or not 1 <= low <= value <= high:
                raise ValueError('invalid limits')

    @property
    def values(self):
        return self.jobs, self.attempts_per_job, self.attempts_per_pair


@dataclass(frozen=True)
class IngressReceipt:
    principal: str
    source_event: str
    body_digest: str
    received_at: str
    limits: Limits | None = None


@dataclass(frozen=True)
class RunSnapshot:
    run_id: str
    original_intent: str
    authenticated_origin_ref: str
    human_instructions: tuple[c.HumanResponse, ...] = ()
    derived_interpretation: tuple[c.Job, ...] = ()
    state: c.State = c.State.PENDING
    stop_requested: bool = False
    limits: Limits = Limits()
    job_ids: tuple[str, ...] = ()
    revision: int = 0
    final_reason: str | None = None
    cessation_confirmed: bool | None = None
    # Host-pinned profile; None means internal use: effectful, no output duty.
    profile: c.TaskProfile | None = None
    # Committed only inside the terminal transition; never set mid-run.
    output_selection: c.RunOutputSelection | None = None


@dataclass(frozen=True)
class AttemptSnapshot:
    ref: c.AttemptRef
    conditions: c.ExecutionConditions
    state: c.State = c.State.PENDING
    started_at: str | None = None
    ended_at: str | None = None
    result: c.Result | None = None
    ac: c.ACRecord | None = None
    stop_reply: c.StopReply | None = None
    revision: int = 0
    # Mutually exclusive per-Attempt collection outcomes.
    output: c.AttemptOutput | None = None
    collection_failure: c.JobFailure | None = None


@dataclass(frozen=True)
class AnswerReceipt:
    response_id: str
    request_id: str
    disposition: str
    human_response_ref: str
    approval_id: str | None
    revision: int


@dataclass(frozen=True)
class WaitDetails:
    wait: c.WaitingHuman
    judgment_ref: str | None
    conditions: c.ExecutionConditions
    disposition: str | None
    responses: tuple[tuple[c.HumanResponse, AnswerReceipt], ...]


@dataclass(frozen=True)
class RoutingRecord:
    """Host-owned routing evidence; an immutable allowlisted JSON snapshot.

    state_revision is the Run revision observed by selection, before reservation.
    execution_decision_ref identifies the final dispatch rejudgment, if made.
    An Attempt ref is committed atomically with its reservation. This is evidence, never
    execution authority or publication clearance. No Native output is retained.
    """
    record_id: str
    ref: c.QuestionRef
    state_revision: int
    at: str
    summary_json: str
    execution_decision_ref: str | None = None


@dataclass(frozen=True)
class JudgmentView:
    """Detached read-only Judgment evidence view.

    gateway is None or the committed (request_digest, alias, created_at)
    tuple; jobs is the committed Job tuple in add order. Frozen, typed and
    detached: no connection, cursor, aggregate or authority value escapes.
    """
    gateway: tuple | None
    jobs: tuple


def _ref(ref):
    _id(ref.run_id); _id(ref.job_id)
    if ref.attempt_id is not None:
        _id(ref.attempt_id)
    return _json(ref)


def _attempt_key(ref):
    _ref(ref)
    return _json((ref.job_id, ref.attempt_id))


def _cas(actual, expected):
    if type(expected) is not int or actual != expected:
        raise Conflict('stale revision; read and rejudge')


def _live(data):
    """New writes reject on a terminal Run; identical replays return earlier."""
    if data['run'].state in c.TERMINAL:
        raise InvalidTransition('run_terminal')


def _unstopped(data):
    """Post-stop evaluation writes reject with a CAS-distinct closed reason."""
    if data['run'].stop_requested:
        raise Conflict('stop_requested')


def _never_started(data, attempt):
    """Committed request-matched NeverStarted receipt; the only such proof.

    The receipt commits under 'execute:<attempt key>' in the same aggregate
    transaction as every other Attempt record, and record_execute rejects a
    receipt whose request differs from the admitted one. Re-verifying that
    binding here keeps authority with the immutable journal entry: a receipt
    minted for another request can never settle this Attempt.
    """
    receipt = data['writes'].get('execute:' + _attempt_key(attempt.ref))
    return (receipt is not None and receipt[0].never_started is not None
            and receipt[0].never_started.request
            == data['requests'].get(_attempt_key(attempt.ref)))


def _settled(data, attempt):
    """Committed settlement: request-bound NeverStarted receipt, or a terminal
    Result plus CONFIRMED cessation. Anything else is held, never retried."""
    return (_never_started(data, attempt)
            or (attempt.result is not None and attempt.stop_reply is not None
                and attempt.stop_reply.status == c.StopStatus.CONFIRMED))


def _admission_order(data):
    """Live Attempts ordered solely by the immutable original admission write.

    Each 'attempt:' journal entry keeps the exact admitted ExecuteRequest and
    the original AttemptSnapshot; only that original revision is the ordering
    authority. Live snapshot revisions mutate and persisted JSON object key
    order is not admission order. A live Attempt with no matching original, an
    original that does not bind the exact ref/request/conditions/Job/Run, or a
    non-unique, non-positive or future original revision is an integrity
    contradiction: it is never re-ordered, guessed or silently skipped.
    """
    writes = {key[len('attempt:'):]: value for key, value in data['writes'].items()
              if key.startswith('attempt:')}
    if set(writes) != set(data['attempts']):
        raise IntegrityViolation('live Attempts and original admissions diverge')
    ordered, revisions = [], set()
    for key, attempt in data['attempts'].items():
        record = writes[key]
        if type(record) is not tuple or len(record) != 2:
            raise IntegrityViolation('malformed original admission record')
        request, original = record
        try:
            bound = (type(attempt) is AttemptSnapshot
                     and type(attempt.ref) is c.AttemptRef
                     and _attempt_key(attempt.ref) == key
                     and attempt.ref.run_id == data['run'].run_id
                     and type(original) is AttemptSnapshot
                     and type(original.ref) is c.AttemptRef
                     and type(request) is c.ExecuteRequest
                     and type(request.ref) is c.AttemptRef
                     and type(request.job) is c.Job
                     and original.ref == attempt.ref
                     and request.ref == attempt.ref
                     and request.ref.run_id == data['run'].run_id
                     and request.job.run_id == data['run'].run_id
                     and request.job.job_id == attempt.ref.job_id
                     and original.conditions == attempt.conditions
                     and request.conditions == attempt.conditions
                     and request.job == data['jobs'].get(attempt.ref.job_id)
                     and data['requests'].get(key) == request)
        except (AttributeError, TypeError, ValueError):
            bound = False
        if not bound:
            raise IntegrityViolation('admission record does not bind live Attempt')
        revision = original.revision
        if (type(revision) is not int or revision <= 0
                or revision > data['run'].revision):
            raise IntegrityViolation('invalid original admission revision')
        if revision in revisions:
            raise IntegrityViolation('duplicate original admission revision')
        revisions.add(revision)
        ordered.append((revision, attempt))
    return tuple(attempt for _, attempt in sorted(ordered, key=lambda pair: pair[0]))


class ControlStore:
    """Host-only factory. Give each trusted component only its dedicated handle.

    verifier(ref) resolves authenticated provenance; evidence(run, request)
    resolves current policy/intent/environment. Both fail closed on exceptions.
    One aggregate per Run keeps cross-record mutations in a single transaction.
    SQLite BEGIN IMMEDIATE also serializes separate store instances/processes.
    """
    def __init__(self, path: str | Path, *, verifier: Callable,
                 evidence: Callable, clock: Callable = _now,
                 profile_resolver: Callable = None,
                 guard: Callable | None = None):
        self._verifier, self._evidence, self._clock = verifier, evidence, clock
        self._profile_resolver = profile_resolver
        self._guard = guard
        self._lock = RLock()
        # Set only by _tx under this lock, for exactly the BEGIN span.
        self._tx_thread = None
        # Ownership precedes the first connection and any schema mutation;
        # a refused host leaves no new database file behind.
        if guard is not None:
            guard()
        db = None
        try:
            db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA foreign_keys=ON')
            # Ownership is verified under the write lock; BEGIN IMMEDIATE
            # serializes concurrent initializers and never writes pages, so a
            # refused legacy or foreign store is left byte-identical.
            db.execute('BEGIN IMMEDIATE')
            try:
                tables = {row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                if not tables:
                    # Fresh store: marker and schema commit atomically.
                    db.execute("CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), contract TEXT NOT NULL)")
                    db.execute('INSERT INTO meta VALUES (1, ?)', (CONTRACT_MARKER,))
                    db.execute('CREATE TABLE runs (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
                    db.execute('CREATE TABLE ingress (event TEXT PRIMARY KEY, binding TEXT NOT NULL)')
                    db.execute('''CREATE TABLE resumes (
                        id TEXT PRIMARY KEY, run TEXT NOT NULL, attempt TEXT NOT NULL,
                        adapter TEXT NOT NULL, revision INTEGER NOT NULL, opaque BLOB NOT NULL)''')
                    db.execute('''CREATE TABLE gateway_responses (
                        response_id TEXT PRIMARY KEY, principal TEXT NOT NULL,
                        run_id TEXT NOT NULL UNIQUE, request_digest TEXT NOT NULL,
                        alias TEXT NOT NULL, created_at TEXT NOT NULL)''')
                    db.execute('''CREATE TABLE gateway_keys (
                        principal TEXT NOT NULL, key TEXT NOT NULL,
                        request_digest TEXT NOT NULL, response_id TEXT NOT NULL UNIQUE,
                        PRIMARY KEY(principal, key))''')
                    db.execute('''CREATE TABLE gateway_work (
                        run_id TEXT PRIMARY KEY, enqueued_at TEXT NOT NULL)''')
                    db.execute('''CREATE TABLE gateway_projections (
                        response_id TEXT PRIMARY KEY, status TEXT NOT NULL,
                        code TEXT, run_revision INTEGER NOT NULL, at TEXT NOT NULL)''')
                else:
                    # Existing store: prove marker/schema before any write.
                    if 'meta' not in tables:
                        raise StoreUnavailable('unmarked control store')
                    row = db.execute('SELECT contract FROM meta WHERE id=1').fetchone()
                    if row != (CONTRACT_MARKER,):
                        raise StoreUnavailable('control store contract mismatch')
                    if not {'runs', 'ingress', 'resumes'} | GATEWAY_TABLES <= tables:
                        raise StoreUnavailable('incomplete control store schema')
                db.commit()
            except BaseException:
                try:
                    db.rollback()
                except sqlite3.Error:
                    pass
                raise
        except BaseException as exc:
            if db is not None:
                try:
                    db.close()
                except sqlite3.Error:
                    pass
            if isinstance(exc, sqlite3.Error):
                raise StoreUnavailable('control store unavailable') from exc
            raise
        self._db = db

    def close(self):
        with self._lock:
            self._db.close()

    def intake(self): return Intake(self)
    def controller(self): return ControllerState(self)
    def scheduler(self): return Scheduler(self)
    def bridge(self, adapter: str):
        _id(adapter)
        return AdapterBridge(self, adapter)

    def gateway(self):
        """Host-only northbound submission handle; needs a bounded local
        profile_resolver, never network I/O. No factory without one."""
        if not callable(self._profile_resolver):
            raise StoreUnavailable('gateway requires a profile resolver')
        from .gateway_store import Gateway
        return Gateway(self)

    def judgment(self):
        from .judgment import Judgment
        return Judgment(self)

    def judgment_view(self, run_id: str) -> JudgmentView:
        """Detached read-only evidence view inside the active transaction.

        Usable only while the calling thread actually holds this store's
        lock inside an open _tx — the existing Judgment/evidence evaluation.
        Any other context refuses immediately: never a nested BEGIN, a new
        connection, a lock wait, a write, a claim, a revision bump or
        re-authentication. Read-only SELECTs through the owned connection.
        """
        if (self._tx_thread != get_ident()
                or not self._db.in_transaction):
            raise StoreUnavailable('judgment_view requires active transaction')
        _id(run_id)
        data, _before = self._load_locked(run_id)
        row = self._db.execute(
            'SELECT request_digest, alias, created_at FROM gateway_responses'
            ' WHERE run_id=?', (run_id,)).fetchone()
        gateway = None
        if row is not None:
            digest, alias, created_at = row
            if (type(digest) is not str or len(digest) != 64
                    or any(ch not in '0123456789abcdef' for ch in digest)
                    or type(alias) is not str or not 1 <= len(alias) <= 128
                    or any(not 0x21 <= ord(ch) <= 0x7E for ch in alias)
                    or type(created_at) is not str):
                raise IntegrityViolation('malformed gateway response row')
            try:
                _time(created_at)
            except ValueError:
                raise IntegrityViolation(
                    'malformed gateway response row') from None
            gateway = (digest, alias, created_at)
        jobs = getattr(data['run'], 'derived_interpretation', None)
        ids = getattr(data['run'], 'job_ids', None)
        if (type(jobs) is not tuple or type(ids) is not tuple
                or len(jobs) != len(ids) or len(set(ids)) != len(ids)
                or any(type(job) is not c.Job or job.run_id != run_id
                       or job.job_id != ids[i]
                       for i, job in enumerate(jobs))
                or {job.job_id for job in jobs} != set(data['jobs'])
                or any(data['jobs'].get(job.job_id) != job for job in jobs)):
            raise IntegrityViolation('malformed committed Job records')
        return JudgmentView(gateway, jobs)

    def now(self):
        try:
            value = self._clock()
            _time(value)
            return value
        except Exception as exc:
            raise StoreUnavailable('trusted clock unavailable') from exc

    def _load_locked(self, run_id):
        """Load one Run aggregate inside the caller's transaction; returns
        (data, before) where before is the canonical JSON for change checks."""
        row = self._db.execute('SELECT body FROM runs WHERE id=?', (run_id,)).fetchone()
        if row is None:
            raise NotFound('Run not found')
        try:
            data = _unpack(json.loads(row[0]))
        except Exception as exc:
            raise StoreUnavailable('invalid persisted control state') from exc
        return data, _json(data)

    def _store_locked(self, run_id, data, before):
        """Persist a loaded aggregate iff it changed; caller's transaction."""
        after = _json(data)
        if after != before:
            self._db.execute('UPDATE runs SET body=? WHERE id=?', (after, run_id))

    @contextmanager
    def _tx(self, run_id=None):
        with self._lock:
            # Outside the conversion try: a guard failure propagates its own
            # exception type unchanged, never wrapped as StoreUnavailable.
            if self._guard is not None:
                self._guard()
            try:
                self._db.execute('BEGIN IMMEDIATE')
                self._tx_thread = get_ident()
                try:
                    data = None
                    if run_id is not None:
                        data, before = self._load_locked(run_id)
                    else:
                        before = None
                    yield data
                    if data is not None:
                        self._store_locked(run_id, data, before)
                    self._db.commit()
                finally:
                    self._tx_thread = None
            except BaseException as exc:
                try:
                    self._db.rollback()
                except sqlite3.Error:
                    pass
                if isinstance(exc, sqlite3.Error):
                    raise StoreUnavailable('control transaction failed') from exc
                raise

    def _auth(self, ingress_ref, body, now):
        _id(ingress_ref)
        try:
            receipt = self._verifier(ingress_ref)
            if type(receipt) is not IngressReceipt:
                raise ValueError('missing verified receipt')
            _id(receipt.principal); _id(receipt.source_event)
            if receipt.body_digest != body_digest(body) or _time(receipt.received_at) > _time(now):
                raise ValueError('receipt binding mismatch')
            return receipt
        except Exception as exc:
            raise UntrustedInput('authenticated ingress binding required') from exc

    def _claim_ingress(self, receipt, binding):
        key = _json((receipt.principal, receipt.source_event))
        row = self._db.execute('SELECT binding FROM ingress WHERE event=?', (key,)).fetchone()
        encoded = _json(binding)
        if row and row[0] != encoded:
            raise Conflict('source event already consumed')
        self._db.execute('INSERT OR IGNORE INTO ingress VALUES (?,?)', (key, encoded))

    def _claimed(self, receipt):
        """Committed ingress binding for a verified receipt, or None.

        Read-only for the future Gateway seam: replays a claim journal row
        without writing; it grants no authority by itself.
        """
        key = _json((receipt.principal, receipt.source_event))
        row = self._db.execute('SELECT binding FROM ingress WHERE event=?',
                               (key,)).fetchone()
        return _unpack(json.loads(row[0])) if row else None

    def _create_run_locked(self, run_id, original_intent, origin_ref,
                           receipt, profile):
        """Shared Run creation inside the caller's transaction; never claims.

        Arguments are already trusted (verified receipt, typed profile).
        Returns (initial RunSnapshot, created); the trusted caller claims its
        own binding exactly once when created, and identical replays never
        claim. No nested _tx: callers must already hold the transaction.
        """
        row = self._db.execute('SELECT body FROM runs WHERE id=?', (run_id,)).fetchone()
        if row:
            data = _unpack(json.loads(row[0]))
            if data['creation'] != (original_intent, origin_ref, receipt, profile):
                raise Conflict('Run ID already used')
            return data['initial'], False
        limits = receipt.limits or Limits()
        if type(limits) is not Limits:
            raise UntrustedInput('invalid authenticated limits grant')
        run = RunSnapshot(run_id, original_intent, origin_ref, limits=limits,
                          profile=profile)
        data = dict(run=run, initial=run,
                    creation=(original_intent, origin_ref, receipt, profile),
                    jobs={}, attempts={}, requests={}, decisions={}, writes={}, waits={},
                    callbacks={}, answers={}, approvals=[], rejections=[], timeouts=[],
                    events=[], ac_history=[], stop_history=[], limit_history=[])
        self._db.execute('INSERT INTO runs VALUES (?,?)', (run_id, _json(data)))
        return run, True

    def _bump(self, data, **changes):
        data['run'] = replace(data['run'], revision=data['run'].revision + 1, **changes)
        return data['run'].revision

    def _attempt(self, data, ref):
        try:
            return data['attempts'][_attempt_key(ref)]
        except KeyError:
            raise NotFound('Attempt not found') from None

    def _job(self, data, ref):
        _ref(ref)
        if ref.run_id != data['run'].run_id:
            raise Conflict('wrong Run')
        try:
            return data['jobs'][ref.job_id]
        except KeyError:
            raise NotFound('Job not found') from None

    def _replay(self, data, key, payload):
        old = data['writes'].get(key)
        if old:
            if old[0] != payload:
                raise Conflict('ID reused with different content')
            return old[1]
        return None

    def _write(self, data, key, payload):
        """Guarded record write: identical commits return the stored record;
        anything new or different on a terminal Run rejects permanently."""
        old = data['writes'].get(key)
        if old is not None:
            if old[0] == payload:
                return old[1]
            if data['run'].state in c.TERMINAL:
                raise InvalidTransition('run_terminal')
            raise IntegrityViolation('ID reused with different content')
        if data['run'].state in c.TERMINAL:
            raise InvalidTransition('run_terminal')
        return None

    def _save(self, data, key, payload, result):
        data['writes'][key] = (payload, result)
        return result

    def _decision(self, data, decision_id):
        from .judgment import evaluate
        try:
            request, record, evidence = data['decisions'][decision_id]
        except KeyError:
            raise NotFound('Judgment not found') from None
        if record.state_revision != data['run'].revision:
            raise Conflict('Judgment state changed')
        current, current_evidence = evaluate(self, data, request, decision_id)
        if current != record or current_evidence != evidence:
            raise Conflict('Judgment conditions/evidence changed')
        return request, record, evidence


class Intake:
    def __init__(self, store): self._store = store

    def create_run(self, run_id: str, original_intent: str, ingress_ref: str,
                   profile=None) -> RunSnapshot:
        _id(run_id); _id(original_intent)
        if profile is not None and type(profile) is not c.TaskProfile:
            raise ValueError('pinned typed TaskProfile required')
        s = self._store
        with s._tx():
            receipt = s._auth(ingress_ref, create_run_body(run_id, original_intent), s.now())
            run, created = s._create_run_locked(run_id, original_intent,
                                                ingress_ref, receipt, profile)
            if created:
                s._claim_ingress(receipt, ('create', run_id, original_intent))
            return run

    def record_receipt(self, response: c.HumanResponse, ingress_ref: str) -> IngressReceipt:
        """Authenticate and durably receive before application/CAS.

        The control-store transaction is the receipt/expiry ordering boundary.
        Transport verifier timestamps are evidence only: time spent fetching,
        authenticating or waiting for this lock cannot backdate CO receipt.
        A successful receipt survives an application conflict or host restart.
        Only trusted intake has this handle; no caller supplies received_at.
        """
        s = self._store
        _immutable(response)
        _id(response.response_id); _id(response.request_id); _ref(response.ref)
        if type(response.answer) is not c.HumanAnswer:
            raise UntrustedInput('typed HumanAnswer required')
        with s._tx(response.ref.run_id) as data:
            source = s._auth(ingress_ref, response, s.now())
            if response.authenticated_source_ref != ingress_ref:
                raise UntrustedInput('response source mismatch')
            payload = (response, ingress_ref, source)
            # Preserve already applied records from the previous runtime too.
            replay = s._replay(data, 'answer:' + response.response_id, payload)
            if replay is not None:
                return data['answers'][response.response_id][1]
            receipts = data.setdefault('human_receipts', {})
            previous = receipts.get(response.response_id)
            if previous is not None:
                if previous[0] != payload:
                    raise Conflict('receipt ID reused with different content')
                return previous[1]
            _live(data)
            waiting = _wait(data, response.ref, response.request_id)
            wait = waiting['wait']
            if response.action != wait.action:
                raise Conflict('answer target mismatch')
            if response.answer == c.HumanAnswer.APPROVE and not wait.action.scope.known:
                raise UntrustedInput('unknown scope cannot be approved')
            if response.answer == c.HumanAnswer.INSTRUCT and not response.detail.strip():
                raise ValueError('instruction detail required')
            if waiting['closed'] == 'answered' or waiting.get('receipt_id') is not None:
                raise Conflict('question already has an authenticated response')
            s._claim_ingress(source, ('answer', response))
            received = replace(source, received_at=s.now())
            receipts[response.response_id] = (payload, received)
            if waiting['closed'] is None and _time(received.received_at) <= _time(wait.deadline):
                waiting['receipt_id'] = response.response_id
            return received

    def record_answer(self, response: c.HumanResponse, ingress_ref: str,
                      expected_revision: int) -> AnswerReceipt:
        # Receipt must commit even if the subsequent state application loses CAS.
        self.record_receipt(response, ingress_ref)
        s = self._store
        with s._tx(response.ref.run_id) as data:
            old = data['answers'].get(response.response_id)
            if old is not None:
                return old[2]
            _live(data)
            _cas(data['run'].revision, expected_revision)
            return _apply_answer(s, data, response.response_id)

    def record_stop_request(self, run_id: str, ingress_ref: str) -> RunSnapshot:
        """Authenticated, wait-independent Run stop intake (northbound cancel seam).

        Linearized by the same control-store transaction as finalization; a
        terminal or already-stopped Run replays unchanged. No HumanResponse
        is fabricated.
        """
        _id(run_id)
        s = self._store
        body = {'operation': 'stop_run', 'run_id': run_id}
        with s._tx(run_id) as data:
            receipt = s._auth(ingress_ref, body, s.now())
            s._claim_ingress(receipt, ('stop', run_id))
            _request_stop_locked(s, data)   # default origin 'intake'
            return data['run']


def _apply_answer(s, data, response_id):
    """Apply a committed, authenticated receipt under the control-store lock."""
    _live(data)
    payload, auth = data['human_receipts'][response_id]
    response, ingress_ref, _ = payload
    waiting = _wait(data, response.ref, response.request_id)
    wait = waiting['wait']
    key = 'answer:' + response.response_id
    now = s.now()
    terminal = data['run'].state in c.TERMINAL
    if wait.ref.attempt_id is not None:
        attempt = s._attempt(data, c.AttemptRef(wait.ref.run_id, wait.ref.job_id, wait.ref.attempt_id))
        terminal = (terminal or attempt.result is not None
                    or _never_started(data, attempt))
    # Closure and deadline expiry are different facts. A stopped or
    # terminal execution must never acquire a fabricated timeout.
    if waiting['closed'] is None:
        if terminal:
            waiting['closed'] = 'terminal'
        elif data['run'].stop_requested:
            waiting['closed'] = 'stopped'
        elif _time(auth.received_at) > _time(wait.deadline):
            _expire(s, data, waiting, now)
    late = waiting['closed'] is not None
    approval_id = None
    if not late:
        waiting['closed'] = 'answered'
        if response.answer == c.HumanAnswer.APPROVE:
            approval_id = str(uuid4())
            approval = c.Approval(approval_id, response.ref.run_id, response.action, response.response_id)
            data['approvals'].append((approval, waiting['conditions']))
        elif response.answer == c.HumanAnswer.REJECT:
            rejection = c.Rejection(response.ref, response.action, waiting['method'], response.response_id)
            data['rejections'].append((rejection, waiting['operation_key']))
        elif response.answer == c.HumanAnswer.INSTRUCT:
            if not response.detail.strip():
                raise ValueError('instruction detail required')
            data['run'] = replace(data['run'], human_instructions=data['run'].human_instructions + (response,))
    # A late answer grants no approval, but an authenticated Run stop
    # still prevents dispatch and requires Native cessation handling.
    if response.answer == c.HumanAnswer.STOP_RUN:
        data['run'] = replace(data['run'], stop_requested=True)
        data.setdefault('stop_origin', 'intake')
        for other in data['waits'].values():
            if other['closed'] is None:
                other['closed'] = 'stopped'
    revision = s._bump(data)
    _progress(data)
    result = AnswerReceipt(response.response_id, response.request_id,
                           'late' if late else 'applied', response.response_id,
                           approval_id, revision)
    data['answers'][response.response_id] = (response, auth, result)
    return s._save(data, key, payload, result)


STOP_ORIGINS = frozenset({'intake', 'gateway_cancel', 'projection_decided',
                         'approval_required'})


def _request_stop_locked(store, data, origin='intake'):
    """Apply an authenticated Run stop inside the caller's transaction.

    origin is a closed attribution token validated before any mutation and
    stored once under 'stop_origin' — only on the transition that actually
    applied the stop, so a late replay never rewrites the first origin.
    False on a terminal or already-stopped Run: no write and no claim.
    No HumanResponse is fabricated.
    """
    if origin not in STOP_ORIGINS:
        raise ValueError('closed stop origin required')
    if data['run'].state in c.TERMINAL or data['run'].stop_requested:
        return False
    data['run'] = replace(data['run'], stop_requested=True)
    data.setdefault('stop_origin', origin)
    for waiting in data['waits'].values():
        if waiting['closed'] is None:
            waiting['closed'] = 'stopped'
    store._bump(data)
    _progress(data)
    return True


def _latest_attempts(data):
    """Latest Attempt per Job, ordered by immutable original admission."""
    latest = {}
    for attempt in _admission_order(data):
        latest[attempt.ref.job_id] = attempt
    return latest


def _goal_binds_latest(goal, latest):
    """A JobGoal counts only while it binds the Job's latest exact state."""
    attempt = latest.get(goal.job.job_id)
    return (attempt is not None and attempt.result is not None
            and attempt.result == goal.result and attempt.ac == goal.ac)


def _accepted_candidates(data):
    """Accepted output candidates bound to each Job's latest Attempt.

    A completed JobGoal for a superseded Attempt is never accepted, so a
    historical pass cannot hide a later failed or unaccepted Attempt.
    """
    latest = _latest_attempts(data)
    accepted = {}
    for job_id, job in data['jobs'].items():
        attempt = latest.get(job_id) if job.output_candidate else None
        if attempt is None:
            continue
        goal = next((g for g in reversed(data.get('job_goals', []))
                     if g.job.job_id == job_id and g.result == attempt.result
                     and g.ac == attempt.ac), None)
        if (goal is None or not goal.completed
                or attempt.result.status != c.State.COMPLETED
                or attempt.stop_reply is None
                or attempt.stop_reply.status != c.StopStatus.CONFIRMED
                or attempt.ac is None or attempt.ac.output_digest is None
                or attempt.output is None
                or attempt.output.digest != attempt.ac.output_digest
                or not any(item.size > 0 for item in attempt.output.items)):
            continue
        accepted[job_id] = (job, attempt, goal)
    return accepted


class ControllerState:
    def __init__(self, store): self._store = store

    @property
    def storage_path(self) -> Path:
        """Actual file-backed state identity for trusted host ownership locks.

        This read is safe during an existing Judgment transaction; it does not
        start a nested transaction or expose the database handle to Workers.
        """
        with self._store._lock:
            rows = self._store._db.execute('PRAGMA database_list').fetchall()
            filename = next((row[2] for row in rows if row[1] == 'main'), '')
            if not filename:
                raise StoreUnavailable('file-backed control state required')
            return Path(filename).resolve(strict=True)

    def get_run(self, run_id: str) -> RunSnapshot:
        with self._store._tx(run_id) as data:
            return data['run']

    def get_attempt(self, ref: c.AttemptRef) -> AttemptSnapshot:
        with self._store._tx(ref.run_id) as data:
            return self._store._attempt(data, ref)

    def attempts(self, run_id: str) -> tuple[AttemptSnapshot, ...]:
        with self._store._tx(run_id) as data:
            # Reservation order, independent of sorted JSON object keys.
            return _admission_order(data)

    def admitted_request(self, ref: c.AttemptRef):
        """Exact committed ExecuteRequest for an admitted Attempt, or None.

        Read-only, one _tx; the committed journal object is returned
        verbatim, never reconstructed. An absent Run raises NotFound —
        callers decide store membership before calling, never through
        this path. _admission_order validates admission writes, live
        Attempts and requests first; an orphan request or 'attempt:'
        write for an unadmitted key is corruption, not "not admitted".
        """
        if type(ref) is not c.AttemptRef:
            raise ValueError('typed AttemptRef required')
        key = _attempt_key(ref)
        with self._store._tx(ref.run_id) as data:
            _admission_order(data)      # before anything else
            if key not in data['attempts']:
                if (key in data['requests']
                        or ('attempt:' + key) in data['writes']):
                    raise IntegrityViolation('orphan admission record')
                return None
            request = data['requests'].get(key)
            if (type(request) is not c.ExecuteRequest or request.ref != ref
                    or request.job.run_id != ref.run_id
                    or request.job.job_id != ref.job_id):
                raise IntegrityViolation('corrupt admitted request record')
            return request

    def wait_details(self, ref: c.QuestionRef, request_id: str):
        """Exact authority binding and authenticated disposition for host use."""
        with self._store._tx(ref.run_id) as data:
            w = _wait(data, ref, request_id)
            responses = tuple((response, receipt) for response, _, receipt in data['answers'].values()
                              if response.request_id == request_id and response.ref == ref)
            return WaitDetails(w['wait'], w.get('judgment_ref'), w['conditions'],
                               w['closed'], responses)

    def waits(self, run_id: str) -> tuple[c.WaitingHuman, ...]:
        with self._store._tx(run_id) as data:
            return tuple(w['wait'] for w in data['waits'].values())

    def checkpoint(self, run_id: str):
        with self._store._tx(run_id) as data:
            return data.get('controller_checkpoint')

    def save_checkpoint(self, run_id: str, checkpoint, expected_revision: int):
        from .controller import ControllerCheckpoint
        if type(checkpoint) is not ControllerCheckpoint:
            raise ValueError('typed Controller checkpoint required')
        _immutable(checkpoint)
        with self._store._tx(run_id) as data:
            _cas(data['run'].revision, expected_revision)
            data['controller_checkpoint'] = checkpoint

    def plans(self, run_id: str) -> tuple:
        with self._store._tx(run_id) as data:
            return tuple(data.get('plans', ()))

    def execute_receipt(self, ref: c.AttemptRef) -> c.OperationReply | None:
        with self._store._tx(ref.run_id) as data:
            self._store._attempt(data, ref)
            value = data['writes'].get('execute:' + _attempt_key(ref))
            return value[0] if value else None

    def attempt_settlement(self, ref: c.AttemptRef) -> str | None:
        """Committed Attempt outcome: 'never_started', 'native' or None (held).

        One authority for the shared settlement predicate — a request-matched
        committed NeverStarted receipt, or a terminal Result plus CONFIRMED
        cessation — for trusted Controller reads, release and recovery.
        """
        with self._store._tx(ref.run_id) as data:
            attempt = self._store._attempt(data, ref)
            if _never_started(data, attempt):
                return 'never_started'
            if (attempt.result is not None and attempt.stop_reply is not None
                    and attempt.stop_reply.status == c.StopStatus.CONFIRMED):
                return 'native'
            return None

    def record_execute(self, reply: c.OperationReply, expected_revision: int):
        """Keep dispatch evidence. Only exact pre-transport refusal is terminal.

        Ordinary errors, unknown Attempts and failed sends are not cessation.
        Resume bytes belong to AdapterBridge, never this public audit record.
        """
        s = self._store
        if (type(reply) is not c.OperationReply or type(reply.status) is not c.OperationStatus
                or reply.resume_state is not None):
            raise ValueError('sanitized typed execute receipt required')
        _immutable(reply)
        with s._tx(reply.ref.run_id) as data:
            key = 'execute:' + _attempt_key(reply.ref)
            replay = s._write(data, key, reply)
            if replay is not None: return replay
            attempt = s._attempt(data, reply.ref)
            # Integrity precedes CAS: a committed-record contradiction is a
            # known integrity violation, never masked as a stale revision.
            if reply.never_started is not None and (
                    reply.never_started.request != data['requests'][_attempt_key(reply.ref)]
                    or attempt.result is not None or attempt.started_at is not None
                    or attempt.stop_reply is not None or attempt.ac is not None
                    or attempt.output is not None
                    or attempt.collection_failure is not None
                    or any(e.ref == reply.ref for e in data['events'])):
                raise IntegrityViolation(
                    'never-started receipt contradicts committed records')
            _cas(attempt.revision, expected_revision)
            # Admission plus receipt only: no Result, AC, stop or event is
            # fabricated; ended_at is the host commit time.
            changes = (dict(ended_at=s.now())
                       if reply.never_started is not None else {})
            data.setdefault('execute_history', []).append(reply)
            attempt = replace(attempt, revision=s._bump(data), **changes)
            data['attempts'][_attempt_key(reply.ref)] = attempt
            # Commit the receipt to writes before _progress: the settlement
            # predicate reads writes, so a later save would leave the settled
            # NeverStarted Attempt reported active and the Run RUNNING.
            s._save(data, key, reply, attempt)
            _progress(data)
            return attempt

    def release_attempt(self, ref: c.AttemptRef):
        """Mark a ceased continuation Attempt consumed, without changing Result."""
        with self._store._tx(ref.run_id) as data:
            attempt = self._store._attempt(data, ref)
            if not _settled(data, attempt):
                raise InvalidTransition('release requires committed Attempt settlement')
            released = data.setdefault('released_attempts', [])
            if ref not in released: released.append(ref)

    def record_job_goal(self, outcome, expected_revision: int):
        from .ac import JobGoal
        if type(outcome) is not JobGoal:
            raise ValueError('typed Job Goal required')
        _immutable(outcome)
        s = self._store
        with s._tx(outcome.job.run_id) as data:
            attempt = s._attempt(data, outcome.result.ref)
            if _never_started(data, attempt):
                raise IntegrityViolation('Goal contradicts committed never-started receipt')
            key = 'job-goal:' + body_digest(outcome)
            # The first committed Job Goal ends re-evaluation for this
            # Attempt: the identical Goal replays through its committed write
            # key, and any different outcome — verdict, digest or completed
            # flag — contradicts immutable proof. Checked before _live/_cas,
            # so even a terminal Run reports integrity, never run_terminal.
            if any(goal.result.ref == attempt.ref
                   for goal in data.get('job_goals', [])):
                old = data['writes'].get(key)
                if old is not None and old[0] == outcome:
                    return outcome
                raise IntegrityViolation('Job Goal already committed for this Attempt')
            if s._write(data, key, outcome) is not None: return outcome
            _cas(data['run'].revision, expected_revision)
            _unstopped(data)
            if (s._job(data, attempt.ref) != outcome.job or attempt.result != outcome.result
                    or outcome.ac.ref != attempt.ref or attempt.stop_reply is None
                    or attempt.stop_reply.status != c.StopStatus.CONFIRMED):
                raise InvalidTransition('Goal requires exact stored Result and cessation')
            if attempt.output is None:
                if outcome.ac.output_digest is not None:
                    raise InvalidTransition('AC binds unpersisted output')
            elif outcome.ac.output_digest != attempt.output.digest:
                raise InvalidTransition('AC output binding mismatch')
            if (outcome.job.output_candidate and outcome.completed
                    and outcome.ac.output_digest is None):
                raise InvalidTransition('accepted output candidate requires bound output')
            data['ac_history'].append((attempt.result, outcome.ac))
            data.setdefault('job_goals', []).append(outcome)
            data['attempts'][_attempt_key(attempt.ref)] = replace(
                attempt, ac=outcome.ac, revision=s._bump(data))
            return s._save(data, key, outcome, outcome)

    def record_run_goal(self, goal, expected_revision: int):
        from .ac import RunGoal, CheckRequest
        if type(goal) is not RunGoal or goal.revision != expected_revision:
            raise ValueError('typed current Run Goal required')
        _immutable(goal)
        with self._store._tx(goal.run_id) as data:
            history = data.setdefault('run_goals', [])
            if goal in history:
                return goal
            _live(data)
            _cas(data['run'].revision, expected_revision)
            _unstopped(data)
            latest = _latest_attempts(data)
            jobs = tuple(g for g in data.get('job_goals', [])
                         if g.completed and _goal_binds_latest(g, latest))
            if goal.request_digest != body_digest(CheckRequest('run', data['run'], jobs=jobs)):
                raise InvalidTransition('Run Goal evidence does not bind current Run and Job findings')
            history.append(goal)

    def finalize_run(self, run_id, status, reason, expected_revision, cessation=None):
        if status not in c.TERMINAL or not reason:
            raise ValueError('terminal state and reason required')
        s = self._store
        with s._tx(run_id) as data:
            if data['run'].state in c.TERMINAL:
                if (data['run'].state, data['run'].final_reason) != (status, reason):
                    raise InvalidTransition('run_terminal')
                return data['run']
            _cas(data['run'].revision, expected_revision)
            if any(not _settled(data, a) for a in data['attempts'].values()):
                raise InvalidTransition('cannot finalize with unresolved execution')
            selection = None
            if status == c.State.COMPLETED:
                goals = data.get('run_goals', [])
                latest = _latest_attempts(data)
                jobs = {g.job.job_id for g in data.get('job_goals', [])
                        if g.completed and _goal_binds_latest(g, latest)}
                if (data['run'].stop_requested or not goals or goals[-1].finding.verdict != 'pass'
                        or goals[-1].revision != expected_revision or jobs != set(data['jobs'])):
                    raise InvalidTransition('current independent Run and all required Job Goals needed')
                accepted = _accepted_candidates(data)
                if len(accepted) == 1:
                    job, attempt, _ = next(iter(accepted.values()))
                    selection = c.RunOutputSelection(run_id, job.job_id, attempt.ref,
                                                   attempt.output.digest, s.now())
                elif data['run'].profile is not None and data['run'].profile.requires_output:
                    # Zero or multiple accepted candidates fail closed.
                    status, reason = c.State.FAILED, 'output_unavailable'
            # A terminal Run leaves no open questions for the scheduler.
            for waiting in data['waits'].values():
                if waiting['closed'] is None:
                    waiting['closed'] = 'terminal'
            s._bump(data, state=status, final_reason=reason, cessation_confirmed=cessation,
                    output_selection=selection)
            return data['run']

    def get_job(self, run_id: str, job_id: str) -> c.Job:
        with self._store._tx(run_id) as data:
            return self._store._job(data, c.QuestionRef(run_id, job_id))

    def stop_origin(self, run_id: str) -> str | None:
        """Committed attribution of the applied Run stop, or None."""
        with self._store._tx(run_id) as data:
            return data.get('stop_origin')

    def request_internal_stop(self, run_id: str, origin: str) -> bool:
        """Durable internal stop barrier for trusted Controller use.

        Only the closed internal origins are accepted; intake/gateway_cancel
        remain ingress-owned. One aggregate transaction applies the shared
        locked helper: no ingress claim and no fabricated HumanResponse.
        Idempotent — an already-stopped or terminal Run writes nothing and
        keeps the first committed origin.
        """
        if origin not in ('projection_decided', 'approval_required'):
            raise ValueError('internal stop origin required')
        _id(run_id)
        with self._store._tx(run_id) as data:
            return _request_stop_locked(self._store, data, origin)

    # Closed driver audit categories and exception-derived type codes; the
    # journal is class-O operational evidence, bounded and deduplicated,
    # written without a revision bump and still allowed on a terminal Run.
    DRIVER_AUDIT_LIMIT = 64
    DRIVER_AUDIT_CATEGORIES = frozenset(
        {'driver_step_error', 'driver_project_error', 'controller_factory_error'})
    DRIVER_AUDIT_CODES = frozenset({'integrity', 'conflict', 'invalid_transition',
                                    'capacity', 'collection', 'value', 'other'})

    def record_driver_event(self, run_id: str, category: str, type_code: str):
        """Append a sanitized driver audit entry: (category, type_code,
        run_revision, now). Never exception text, never a proof field."""
        s = self._store
        if (category not in self.DRIVER_AUDIT_CATEGORIES
                or type_code not in self.DRIVER_AUDIT_CODES):
            raise ValueError('closed driver audit category and code required')
        with s._tx(run_id) as data:
            audit = data.setdefault('driver_audit', [])
            revision = data['run'].revision
            if any(e[:3] == (category, type_code, revision) for e in audit):
                return
            if len(audit) >= self.DRIVER_AUDIT_LIMIT:
                data['driver_audit_suppressed'] = (
                    data.get('driver_audit_suppressed', 0) + 1)
                return
            audit.append((category, type_code, revision, s.now()))

    def history(self, run_id: str, kind: str) -> tuple:
        """Trusted Controller-only audit view; never includes resume bytes."""
        if kind not in {'events', 'ac_history', 'stop_history', 'limit_history',
                        'rejections', 'timeouts', 'approvals', 'answers',
                        'execute_history', 'job_goals', 'run_goals', 'released_attempts', 'human_receipts',
                        'routing_history', 'job_failures', 'driver_audit'}:
            raise ValueError('unsupported history')
        with self._store._tx(run_id) as data:
            value = data.get(kind, [])
            return tuple(value.values()) if isinstance(value, dict) else tuple(value)

    def add_job(self, job: c.Job, intent_decision_ref: str, expected_revision: int, *, plan=None) -> RunSnapshot:
        s = self._store
        _immutable(job)
        _id(job.run_id); _id(job.job_id)
        # Shared dataclasses are in-process; reject mutable collections at intake.
        if type(job.acceptance_criteria) is not tuple:
            raise ValueError('immutable acceptance criteria required')
        with s._tx(job.run_id) as data:
            key = 'job:' + job.job_id
            replay = s._write(data, key, job)
            if replay is not None: return replay
            _cas(data['run'].revision, expected_revision)
            _unstopped(data)
            request, decision, _ = s._decision(data, intent_decision_ref)
            if (request.proposed_job != job or decision.decision != c.Decision.NORMAL
                    or data['run'].state in c.TERMINAL):
                raise InvalidTransition('current contained Job judgment required')
            if len(data['jobs']) >= data['run'].limits.jobs:
                raise LimitExceeded('Run Job limit')
            if plan is not None:
                _immutable(plan)
                if plan.job != job: raise ValueError('plan Job mismatch')
                data.setdefault('plans', []).append(plan)
            data['jobs'][job.job_id] = job
            s._bump(data, job_ids=data['run'].job_ids + (job.job_id,),
                    derived_interpretation=data['run'].derived_interpretation + (job,))
            return s._save(data, key, job, data['run'])

    def record_routing(self, routing: RoutingRecord):
        """Retain a no-dispatch decision at its exact Run/Job revision."""
        if routing.ref.attempt_id is not None:
            raise InvalidTransition('Attempt routing must be reserved atomically')
        with self._store._tx(routing.ref.run_id) as data:
            self._retain_routing(data, routing)

    def _retain_routing(self, data, routing):
        from .trace import PublicationPolicy
        if type(routing) is not RoutingRecord:
            raise ValueError('typed routing record required')
        _immutable(routing)
        _id(routing.record_id); _time(routing.at)
        history = data.setdefault('routing_history', {})
        old = history.get(routing.record_id)
        if old is not None:
            if old == routing:
                return
            _live(data)
            raise Conflict('routing identity already has different content')
        _live(data)
        self._store._job(data, routing.ref)
        _cas(data['run'].revision, routing.state_revision)
        summary = json.loads(routing.summary_json)
        for assessment in summary['assessments']:
            try:
                judged, decision, _ = data['decisions'][assessment['judgment_ref']]
            except KeyError:
                raise InvalidTransition('retained routing Judgment required') from None
            if (judged.ref != c.QuestionRef(routing.ref.run_id, routing.ref.job_id)
                    or decision.state_revision != routing.state_revision
                    or decision.decision.value != assessment['decision']
                    or (judged.conditions.model, judged.conditions.adapter,
                        judged.conditions.environment_ref) != (assessment['model'],
                        assessment['adapter'], assessment['environment_ref'])):
                raise InvalidTransition('routing assessment snapshot mismatch')
        # Defense in depth for protected retention, not outbound clearance.
        PublicationPolicy.check_content({
            'record_id': routing.record_id, 'run_id': routing.ref.run_id,
            'job_id': routing.ref.job_id, 'attempt_id': routing.ref.attempt_id,
            'execution_judgment_ref': routing.execution_decision_ref,
            'summary': summary})
        history[routing.record_id] = routing

    def begin_attempt(self, request: c.ExecuteRequest, decision_ref: str,
                      expected_revision: int, *, routing: RoutingRecord | None = None) -> AttemptSnapshot:
        """Reserve execution and optional Controller routing evidence atomically.

        Direct trusted hosts may still reserve without a routing record. The
        product Controller always supplies one; it cannot be replayed with a
        different Attempt, selected combination, judgment or state revision.
        """
        s = self._store
        _immutable(request)
        with s._tx(request.ref.run_id) as data:
            key = 'attempt:' + _attempt_key(request.ref)
            replay = s._write(data, key, request)
            if replay is not None:
                if routing is not None and (
                        routing.ref != c.QuestionRef(request.ref.run_id, request.ref.job_id, request.ref.attempt_id)
                        or routing.execution_decision_ref != decision_ref
                        or routing.state_revision != expected_revision
                        or data.get('routing_history', {}).get(routing.record_id) != routing):
                    raise Conflict('Attempt routing replay mismatch')
                return replay
            _cas(data['run'].revision, expected_revision)
            _unstopped(data)
            job = s._job(data, request.ref)
            judged, decision, _ = s._decision(data, decision_ref)
            if (job != request.job or judged.ref != c.QuestionRef(request.ref.run_id, request.ref.job_id, request.ref.attempt_id)
                    or judged.conditions != request.conditions or judged.confirmation is not None
                    or judged.proposed_job is not None or decision.decision != c.Decision.NORMAL
                    or data['run'].state in c.TERMINAL):
                raise InvalidTransition('current execution judgment required')
            prior = [a for a in data['attempts'].values() if a.ref.job_id == request.ref.job_id]
            if any(not _settled(data, a) for a in prior):
                raise InvalidTransition('prior Attempt may still be running')
            limits = data['run'].limits
            pair = (request.conditions.model, request.conditions.adapter)
            if len(prior) >= limits.attempts_per_job:
                raise LimitExceeded('Job Attempt limit')
            if sum((a.conditions.model, a.conditions.adapter) == pair for a in prior) >= limits.attempts_per_pair:
                raise LimitExceeded('Model/Adapter Attempt limit')
            if routing is not None:
                if (routing.ref != judged.ref or routing.execution_decision_ref != decision_ref
                        or routing.state_revision != expected_revision
                        or json.loads(routing.summary_json)['selected'] != {
                            'model': pair[0], 'adapter': pair[1]}):
                    raise InvalidTransition('routing must match reserved execution')
                self._retain_routing(data, routing)
            revision = s._bump(data, state=c.State.RUNNING)
            attempt = AttemptSnapshot(request.ref, request.conditions, revision=revision)
            data['attempts'][_attempt_key(request.ref)] = attempt
            data['requests'][_attempt_key(request.ref)] = request
            _progress(data)
            return s._save(data, key, request, attempt)

    def record_event(self, event: c.AdapterEvent, expected_revision: int) -> AttemptSnapshot:
        s = self._store
        _immutable(event)
        if type(event) not in (c.StatusEvent, c.ConfirmationEvent, c.ResultEvent):
            raise ValueError('Adapter event required')
        _id(event.event_id)
        with s._tx(event.ref.run_id) as data:
            key = 'event:' + event.event_id
            # An exact committed event replays before any guard, even on a
            # terminal Run. A committed event ID reused with different
            # content is a committed-record contradiction — integrity on
            # live and terminal Runs alike, same rule as Result
            # immutability and the Job Goal freeze — checked before the
            # Attempt lookup and the never-started/_live/_cas guards.
            old = data['writes'].get(key)
            if old is not None and old[0] == event:
                return old[1]
            if old is not None:
                raise IntegrityViolation(
                    'event ID reused with different content')
            attempt = s._attempt(data, event.ref)
            if _never_started(data, attempt):
                raise IntegrityViolation('event contradicts committed never-started receipt')
            if (isinstance(event, c.ResultEvent) and attempt.result is not None
                    and attempt.result != event.result):
                # Every committed Result is immutable, including a real Native
                # Result whose reason is the former synthetic timeout token; a
                # different terminal Result under a new event ID contradicts
                # immutable proof like a reused ID — checked before _live/_cas
                # so a terminal Run still reports integrity — never journaled.
                raise IntegrityViolation('terminal Result is immutable')
            replay = s._write(data, key, event)
            if replay is not None: return replay
            _cas(attempt.revision, expected_revision)
            changes = {}
            now = s.now()
            if isinstance(event, c.ResultEvent):
                if type(event.result.status) is not c.State:
                    raise ValueError('typed Result state required')
                if attempt.result is None:
                    changes.update(result=event.result, state=event.result.status, ended_at=now)
                    for waiting in data['waits'].values():
                        if (waiting['closed'] is None and waiting['wait'].ref == c.QuestionRef(
                                event.ref.run_id, event.ref.job_id, event.ref.attempt_id)):
                            waiting['closed'] = 'terminal'
            elif isinstance(event, c.StatusEvent):
                if type(event.state) is not c.State:
                    raise ValueError('typed state required')
                if attempt.result is not None:
                    raise InvalidTransition('terminal Attempt cannot change status')
                # Native terminal status is observation only; Result is required.
                if event.state not in c.TERMINAL:
                    if attempt.state != c.State.PENDING and event.state == c.State.PENDING:
                        raise InvalidTransition('cannot return to pending')
                    changes['state'] = event.state
                    if event.state == c.State.RUNNING and attempt.started_at is None:
                        changes['started_at'] = now
            else:
                if attempt.result is not None:
                    raise InvalidTransition('terminal Attempt cannot confirm')
                confirmation = event.confirmation
                _id(confirmation.request_id)
                old = data['callbacks'].get(confirmation.request_id)
                if old is not None and old != confirmation:
                    raise Conflict('callback ID already bound')
                waiting = data['waits'].get(confirmation.request_id)
                if waiting and (waiting['wait'].ref != c.QuestionRef(event.ref.run_id, event.ref.job_id, event.ref.attempt_id)
                                or waiting['wait'].action != confirmation.requested_action):
                    raise Conflict('request ID already bound')
                data['callbacks'][confirmation.request_id] = confirmation
                changes['state'] = c.State.WAITING_HUMAN
            data['events'].append(event)
            attempt = replace(attempt, revision=s._bump(data), **changes)
            data['attempts'][_attempt_key(event.ref)] = attempt
            _progress(data)
            return s._save(data, key, event, attempt)

    def record_stop(self, reply: c.StopReply, expected_revision: int) -> AttemptSnapshot:
        s = self._store
        _immutable(reply)
        if type(reply.status) is not c.StopStatus:
            raise ValueError('typed StopStatus required')
        with s._tx(reply.ref.run_id) as data:
            key = 'stop:' + body_digest(reply)
            replay = s._replay(data, key, reply)
            if replay is not None: return replay
            attempt = s._attempt(data, reply.ref)
            if _never_started(data, attempt):
                raise IntegrityViolation('stop receipt contradicts never-started receipt')
            if data['run'].state in c.TERMINAL:
                # Sole post-terminal write: observed cessation may still move
                # non-CONFIRMED -> CONFIRMED, releasing capacity. It never
                # touches AC, goals, output or selection; regressions reject.
                if (reply.status != c.StopStatus.CONFIRMED
                        or (attempt.stop_reply is not None
                            and attempt.stop_reply.status == c.StopStatus.CONFIRMED)):
                    raise InvalidTransition('run_terminal')
            _cas(attempt.revision, expected_revision)
            data['stop_history'].append(reply)
            # A later receipt cannot erase earlier observed cessation.
            latest = attempt.stop_reply
            if latest is None or latest.status != c.StopStatus.CONFIRMED:
                latest = reply
            attempt = replace(attempt, stop_reply=latest, revision=s._bump(data))
            data['attempts'][_attempt_key(reply.ref)] = attempt
            _progress(data)
            return s._save(data, key, reply, attempt)

    def record_ac(self, record: c.ACRecord, expected_revision: int) -> AttemptSnapshot:
        s = self._store
        _immutable(record)
        with s._tx(record.ref.run_id) as data:
            attempt = s._attempt(data, record.ref)
            if _never_started(data, attempt):
                raise IntegrityViolation('AC contradicts committed never-started receipt')
            # The first committed Job Goal makes the Attempt's AC final.
            # Finality precedes the digest replay: a superseded placeholder's
            # committed write key must not return its stale AC after the Goal.
            if any(goal.result.ref == attempt.ref
                   for goal in data.get('job_goals', [])):
                if record == attempt.ac:
                    return attempt
                raise IntegrityViolation('AC is final after committed Job Goal')
            key = 'ac:' + body_digest(record)
            replay = s._write(data, key, record)
            if replay is not None: return replay
            _cas(attempt.revision, expected_revision)
            _unstopped(data)
            if attempt.result is None:
                raise InvalidTransition('AC requires stored Result')
            data['ac_history'].append((attempt.result, record))
            attempt = replace(attempt, ac=record, revision=s._bump(data))
            data['attempts'][_attempt_key(record.ref)] = attempt
            return s._save(data, key, record, attempt)

    def record_attempt_output(self, ref: c.AttemptRef, output: c.AttemptOutput,
                              expected_revision: int) -> AttemptSnapshot:
        """Bind an immutable AttemptOutput to its Attempt; state owns created_at.

        A same-digest replay is a no-op; a different digest for the same
        Attempt is DigestConflict (integrity), not a stale-revision Conflict.
        Mutually exclusive with a recorded collection failure.
        """
        s = self._store
        if (type(output) is not c.AttemptOutput or output.attempt_ref != ref
                or output.created_at is not None):
            raise ValueError('unstamped output bound to this Attempt required')
        _immutable(output)
        with s._tx(ref.run_id) as data:
            attempt = s._attempt(data, ref)
            if (attempt.output is not None and attempt.output.digest == output.digest
                    and attempt.output.items == output.items):
                return attempt
            _live(data)
            if _never_started(data, attempt):
                raise IntegrityViolation('output contradicts committed never-started receipt')
            if attempt.output is not None:
                raise DigestConflict('conflicting output for committed Attempt')
            if attempt.collection_failure is not None:
                raise InvalidTransition('collection failure already recorded')
            if (attempt.result is None or attempt.result.status != c.State.COMPLETED
                    or attempt.stop_reply is None
                    or attempt.stop_reply.status != c.StopStatus.CONFIRMED):
                raise InvalidTransition('output requires successful Result and cessation')
            _cas(attempt.revision, expected_revision)
            _unstopped(data)
            stamped = replace(output, created_at=s.now())
            attempt = replace(attempt, output=stamped, revision=s._bump(data))
            data['attempts'][_attempt_key(ref)] = attempt
            _progress(data)
            return s._save(data, 'output:' + _attempt_key(ref), stamped, attempt)

    def record_job_failure(self, failure: c.JobFailure, expected_revision: int) -> AttemptSnapshot:
        """Record a controller-owned collection failure; never an AC verdict."""
        s = self._store
        if type(failure) is not c.JobFailure:
            raise ValueError('typed JobFailure required')
        _immutable(failure)
        ref = failure.result.ref
        with s._tx(ref.run_id) as data:
            attempt = s._attempt(data, ref)
            if (attempt.collection_failure is not None
                    and attempt.collection_failure == failure):
                return attempt
            _live(data)
            if _never_started(data, attempt):
                raise IntegrityViolation('failure contradicts committed never-started receipt')
            if attempt.collection_failure is not None:
                raise Conflict('collection outcome already recorded')
            if attempt.output is not None:
                raise InvalidTransition('attempt output already persisted')
            if (s._job(data, attempt.ref) != failure.job or attempt.result is None
                    or attempt.result != failure.result or attempt.stop_reply is None
                    or attempt.stop_reply.status != c.StopStatus.CONFIRMED):
                raise InvalidTransition('failure requires stored Job, terminal Result and cessation')
            _cas(attempt.revision, expected_revision)
            _unstopped(data)
            data.setdefault('job_failures', []).append(failure)
            attempt = replace(attempt, collection_failure=failure, revision=s._bump(data))
            data['attempts'][_attempt_key(ref)] = attempt
            _progress(data)
            return s._save(data, 'job-failure:' + _attempt_key(ref), failure, attempt)

    def set_limits(self, run_id: str, limits: Limits, expected_revision: int) -> RunSnapshot:
        s = self._store
        if type(limits) is not Limits:
            raise ValueError('Limits required')
        with s._tx(run_id) as data:
            key = 'limits:' + str(expected_revision)
            replay = s._write(data, key, limits)
            if replay is not None:
                return replay
            _cas(data['run'].revision, expected_revision)
            grant = data['initial'].limits
            if limits.minimums != grant.minimums or limits.ceilings != grant.ceilings:
                raise UntrustedInput('caller cannot change authenticated limit grant')
            data['limit_history'].append((data['run'].limits, limits))
            s._bump(data, limits=limits)
            return s._save(data, key, limits, data['run'])

    def open_wait(self, wait: c.WaitingHuman, method: str, expected_revision: int,
                  judgment_ref: str | None = None) -> c.WaitingHuman:
        s = self._store
        _immutable(wait)
        _id(wait.request_id); _id(method); _time(wait.deadline)
        if wait.decision not in (c.Decision.CONFIRM, c.Decision.UNDETERMINED):
            raise InvalidTransition('only unresolved decisions can wait')
        with s._tx(wait.ref.run_id) as data:
            key = 'wait:' + wait.request_id
            replay = s._replay(data, key, (wait, method, judgment_ref))
            if replay is not None: return replay
            _cas(data['run'].revision, expected_revision)
            s._job(data, wait.ref)
            if data['run'].state in c.TERMINAL or data['run'].stop_requested or _time(wait.deadline) <= _time(s.now()):
                raise InvalidTransition('stopped Run or expired new wait')
            if wait.ref.attempt_id is not None:
                attempt = s._attempt(data, c.AttemptRef(wait.ref.run_id, wait.ref.job_id, wait.ref.attempt_id))
                if attempt.result is not None or _never_started(data, attempt):
                    raise InvalidTransition('terminal Attempt cannot wait')
            callback = data['callbacks'].get(wait.request_id)
            if judgment_ref is None:
                raise InvalidTransition('exact Judgment ID required')
            request, record, evidence = s._decision(data, judgment_ref)
            if (request.ref != wait.ref or request.action != wait.action
                    or request.method != method or request.confirmation != callback
                    or request.proposed_job is not None or record.decision != wait.decision
                    or record.reason != wait.reason):
                raise InvalidTransition('current exact matching Judgment required')
            if wait.ref.attempt_id is not None and callback is None:
                raise InvalidTransition('active wait requires recorded Native callback')
            if wait.resume_state_ref is not None:
                row = s._db.execute('SELECT run,attempt FROM resumes WHERE id=?', (wait.resume_state_ref,)).fetchone()
                if not row or tuple(row) != (wait.ref.run_id, _attempt_key(wait.ref)):
                    raise Conflict('resume reference mismatch')
            data['waits'][wait.request_id] = dict(wait=wait, method=method, closed=None,
                                                conditions=request.conditions, judgment_ref=judgment_ref, operation_key=evidence.operation_key)
            revision = s._bump(data, state=c.State.WAITING_HUMAN)
            if wait.ref.attempt_id is not None:
                data['attempts'][_attempt_key(wait.ref)] = replace(attempt, state=c.State.WAITING_HUMAN, revision=revision)
            return s._save(data, key, (wait, method, judgment_ref), wait)

    def get_wait(self, ref: c.QuestionRef, request_id: str) -> c.WaitingHuman:
        with self._store._tx(ref.run_id) as data:
            return _wait(data, ref, request_id)['wait']

    def validate_relay(self, response: c.ConfirmationResponse) -> None:
        """Call immediately before serialized Adapter.respond; no Native IO here."""
        s = self._store
        _immutable(response)
        if type(response.resolution) is not c.Resolution:
            raise ValueError('typed Resolution required')
        with s._tx(response.ref.run_id) as data:
            request, record, _ = s._decision(data, response.decision_ref)
            confirmation = data['callbacks'].get(response.request_id)
            if confirmation is None or request.confirmation != confirmation:
                raise Conflict('Judgment belongs to another callback')
            c.validate_response(confirmation, response)
            if response.resolution == c.Resolution.ALLOW and record.decision != c.Decision.NORMAL:
                raise InvalidTransition('current Normal required for relay')


def _wait(data, ref, request_id):
    try:
        waiting = data['waits'][request_id]
    except KeyError:
        raise NotFound('question not found') from None
    if waiting['wait'].ref != ref:
        raise Conflict('question identity mismatch')
    return waiting


def _progress(data):
    if data['run'].state in c.TERMINAL:
        return
    # #159 owns final Goal judgment. A quiescent Run is not automatically success.
    active = [a for a in data['attempts'].values() if not _settled(data, a)]
    waiting = any(w['closed'] is None for w in data['waits'].values())
    state = c.State.WAITING_HUMAN if waiting else c.State.RUNNING if active else c.State.PENDING
    data['run'] = replace(data['run'], state=state)


def _expire(store, data, waiting, now):
    """A timeout is a fact about the wait, never about the Attempt.

    Writes only the closed wait, its ConfirmationTimeout record, history
    entry and the Run revision. No Attempt result, state or ended_at; no
    ResultEvent, StopReply, AC, output or JobFailure — no fabricated
    Native fact and no inferred cessation. A committed real Result is
    preserved byte-identically; a genuine later Result commits without
    conflict because there is no fake Result to conflict with. Open
    sibling waits on the same Attempt close 'stopped' — the question
    channel closed because the Attempt is being stopped — never
    'terminal', which belongs to real Run finalization only. Waits of
    other Attempts and Job-preflight waits are untouched.
    """
    wait = waiting['wait']
    timeout = c.ConfirmationTimeout(wait.ref, wait.request_id, wait.action, wait.deadline)
    waiting['closed'] = 'timeout'
    waiting['timeout'] = timeout
    data['timeouts'].append((timeout, waiting['operation_key']))
    revision = store._bump(data)
    waiting['timeout_revision'] = revision
    if wait.ref.attempt_id is not None:
        for other in data['waits'].values():
            if other['closed'] is None and other['wait'].ref == wait.ref:
                other['closed'] = 'stopped'
    _progress(data)
    return timeout


class Scheduler:
    def __init__(self, store): self._store = store

    def expire_wait(self, ref: c.QuestionRef, request_id: str,
                    expected_revision: int) -> c.ConfirmationTimeout | None:
        """Close at deadline, applying a committed timely receipt if present.

        None means receipt application won; no timeout occurred. No network
        discovery or indefinite grace period is part of deadline scheduling.
        """
        s = self._store
        with s._tx(ref.run_id) as data:
            waiting = _wait(data, ref, request_id)
            if waiting['closed'] == 'timeout': return waiting['timeout']
            if data['run'].state in c.TERMINAL:
                # Scheduler/finalize race: after terminal it never writes or
                # raises; the committed wait state is returned unchanged.
                return waiting.get('timeout')
            _cas(data['run'].revision, expected_revision)
            if waiting['closed'] is not None:
                raise InvalidTransition('question already answered')
            now = s.now()
            if _time(now) < _time(waiting['wait'].deadline):
                raise InvalidTransition('deadline not reached')
            if waiting.get('receipt_id') is not None:
                _apply_answer(s, data, waiting['receipt_id'])
                return None
            return _expire(s, data, waiting, now)


class AdapterBridge:
    def __init__(self, store, adapter): self._store, self._adapter = store, adapter

    def put_resume(self, state: c.ResumeState, expected_revision: int) -> str:
        s = self._store
        _immutable(state)
        if state.adapter != self._adapter or type(state.opaque) is not bytes:
            raise UntrustedInput('bridge adapter/opaque mismatch')
        with s._tx(state.ref.run_id) as data:
            attempt = s._attempt(data, state.ref)
            self._active(data, attempt, state.adapter)
            row = s._db.execute('SELECT id,revision,opaque FROM resumes WHERE run=? AND attempt=? ORDER BY rowid DESC LIMIT 1',
                                (state.ref.run_id, _attempt_key(state.ref))).fetchone()
            if row and row[1] == attempt.revision and row[2] == state.opaque:
                return row[0]
            _cas(attempt.revision, expected_revision)
            handle = str(uuid4())
            # A new opaque state invalidates earlier handles. No secret in aggregate.
            revision = s._bump(data)
            data['attempts'][_attempt_key(state.ref)] = replace(attempt, revision=revision)
            s._db.execute('INSERT INTO resumes VALUES (?,?,?,?,?,?)',
                          (handle, state.ref.run_id, _attempt_key(state.ref), state.adapter, revision, state.opaque))
            return handle

    def _active(self, data, attempt, adapter):
        if adapter != self._adapter or adapter != attempt.conditions.adapter:
            raise UntrustedInput('bridge adapter mismatch')
        if (attempt.result is not None or attempt.stop_reply is not None
                or _never_started(data, attempt) or data['run'].stop_requested):
            raise InvalidTransition('stopped/terminal Attempt cannot resume')

    def get_resume(self, ref: c.AttemptRef, adapter: str, resume_state_ref: str) -> c.ResumeState:
        s = self._store
        with s._tx(ref.run_id) as data:
            attempt = s._attempt(data, ref)
            self._active(data, attempt, adapter)
            row = s._db.execute('SELECT id,adapter,opaque FROM resumes WHERE run=? AND attempt=? ORDER BY rowid DESC LIMIT 1',
                                (ref.run_id, _attempt_key(ref))).fetchone()
            if not row or row[0] != resume_state_ref or row[1] != adapter:
                raise Conflict('stale or mismatched resume handle')
            return c.ResumeState(adapter, ref, row[2])

def commit_execute_receipt(state, reply):
    """Shared execute-receipt commit for Controller and admission recovery.

    Resume bytes are stripped; an identical committed receipt returns, a
    different committed receipt is IntegrityViolation, and a stale
    revision re-reads and retries at most 3 times before
    InvalidTransition. IntegrityViolation precedes Conflict in the retry
    guard because it subclasses it.
    """
    receipt = replace(reply, resume_state=None)
    for _ in range(3):
        existing = state.execute_receipt(receipt.ref)
        if existing is not None:
            if existing == receipt:
                return
            raise IntegrityViolation('conflicting execute receipt committed')
        try:
            state.record_execute(receipt,
                                 state.get_attempt(receipt.ref).revision)
            return
        except IntegrityViolation:
            raise
        except Conflict:
            continue
    raise InvalidTransition('execute receipt could not be committed')
