"""Trusted host's durable, per-Adapter admission. No expiry or Native authority.

All service Runs must use the same canonical host ledger, outside every Worker
workspace. Separate ledgers describe separate hosts, not extra capacity for the
same host. Factories construct one request-bound child; they never submit work.
"""
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import os
import sqlite3
import stat
from threading import RLock
from uuid import uuid4

from . import contracts as c
from .failures import GLOBAL_FAILURES
from .state import body_digest

PRIMARY_ADAPTERS = frozenset(('codex.app-server', 'claude.print', 'devin.acp'))
ADAPTERS = (PRIMARY_ADAPTERS | {'antigravity.text.only',
    't3code.orchestration-v2', 'openai.responses', 'openai.chat'})
MAX_CONCURRENT = 12
CHILD_LACKS_COLLECTOR = 'capacity:child-lacks-collector'


class CapacityError(RuntimeError):
    pass


def _key(ref):
    return body_digest((ref.run_id, ref.job_id, ref.attempt_id))


@dataclass(frozen=True)
class LeaseSnapshot:
    """Recovery identity only: no prompt, credentials or Native handles."""
    ref: c.AttemptRef
    adapter: str
    request_digest: str
    phase: str


class CapacityLedger:
    """One canonical protected SQLite ledger, shared across instances/processes.

    Keep the file and its private parent in every child host's protected-state
    inventory. Host configuration supplies this path once, never from a Run,
    model, Worker message, or request workspace. Deleted/replaced ledgers are an
    operator recovery boundary, not a supported means of resetting slots.
    """
    def __init__(self, canonical_path):
        path = Path(canonical_path)
        if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
            raise CapacityError('canonical host ledger path required')
        parent = path.parent.stat()
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
            raise CapacityError('private host ledger directory required')
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise CapacityError('protected regular ledger required')
        self.path, self._identity = path, (info.st_dev, info.st_ino)
        with self._tx() as db:
            db.execute('CREATE TABLE IF NOT EXISTS capacity_config (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, maximum INTEGER NOT NULL)')
            db.execute('INSERT OR IGNORE INTO capacity_config VALUES (1, 2, ?)', (MAX_CONCURRENT,))
            if db.execute('SELECT version, maximum FROM capacity_config WHERE id=1').fetchone() != (2, MAX_CONCURRENT):
                raise CapacityError('capacity configuration mismatch')
            db.execute('''CREATE TABLE IF NOT EXISTS adapter_leases (
                attempt_key TEXT PRIMARY KEY, run_id TEXT NOT NULL, job_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL, adapter TEXT NOT NULL, request_digest TEXT NOT NULL,
                owner TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('reserved','executing','released')),
                evidence_ref TEXT)''')

    def _check(self):
        info = self.path.lstat()
        if ((info.st_dev, info.st_ino) != self._identity or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise CapacityError('host ledger identity changed')

    @contextmanager
    def _tx(self):
        self._check()
        db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=10, isolation_level=None)
        try:
            db.execute('BEGIN IMMEDIATE')
            self._check()
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def reserve(self, request, owner):
        adapter = request.conditions.adapter
        if adapter not in ADAPTERS:
            raise CapacityError('unsupported capacity adapter')
        key, digest = _key(request.ref), body_digest(request)
        with self._tx() as db:
            prior = db.execute('SELECT adapter, request_digest, owner, phase FROM adapter_leases WHERE attempt_key=?', (key,)).fetchone()
            if prior is not None:
                if prior != (adapter, digest, owner, 'reserved'):
                    raise CapacityError('Attempt reservation already used or rebound')
                return True
            count = db.execute("SELECT count(*) FROM adapter_leases WHERE adapter=? AND phase!='released'", (adapter,)).fetchone()[0]
            if count >= MAX_CONCURRENT:
                return False
            db.execute('INSERT INTO adapter_leases VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)',
                (key, request.ref.run_id, request.ref.job_id, request.ref.attempt_id, adapter, digest, owner, 'reserved'))
            return True

    def claim(self, request, owner):
        with self._tx() as db:
            changed = db.execute("UPDATE adapter_leases SET phase='executing' WHERE attempt_key=? AND adapter=? AND request_digest=? AND owner=? AND phase='reserved'",
                (_key(request.ref), request.conditions.adapter, body_digest(request), owner)).rowcount
            if changed != 1:
                raise CapacityError('unbound or repeated Adapter dispatch')

    def release_reserved(self, request, owner):
        # This transaction races safely against claim: after claim it cannot free
        # capacity. No factory or Native IO can run before the durable claim.
        with self._tx() as db:
            return db.execute("UPDATE adapter_leases SET phase='released', evidence_ref='capacity:reservation-never-dispatched' WHERE attempt_key=? AND request_digest=? AND owner=? AND phase='reserved'",
                (_key(request.ref), body_digest(request), owner)).rowcount == 1

    def release(self, request, owner, evidence):
        with self._tx() as db:
            changed = db.execute("UPDATE adapter_leases SET phase='released', evidence_ref=? WHERE attempt_key=? AND adapter=? AND request_digest=? AND owner=? AND phase='executing'",
                (evidence, _key(request.ref), request.conditions.adapter, body_digest(request), owner)).rowcount
            if changed != 1:
                row = db.execute('SELECT phase, request_digest, owner FROM adapter_leases WHERE attempt_key=?', (_key(request.ref),)).fetchone()
                if row != ('released', body_digest(request), owner):
                    raise CapacityError('release does not bind the exact owned Attempt')

    def row(self, ref, adapter):
        with self._tx() as db:
            row = db.execute('SELECT request_digest, owner, phase, evidence_ref FROM adapter_leases WHERE attempt_key=? AND adapter=?', (_key(ref), adapter)).fetchone()
        return row

    def attach(self, request, owner):
        # Trusted recovery only. The host must stop/serialize the previous owner
        # and reattach the exact Native handle; this never authorizes execute.
        with self._tx() as db:
            row = db.execute('SELECT request_digest, phase FROM adapter_leases WHERE attempt_key=? AND adapter=?', (_key(request.ref), request.conditions.adapter)).fetchone()
            if row != (body_digest(request), 'executing'):
                raise CapacityError('only exact unresolved execution can be reattached')
            db.execute('UPDATE adapter_leases SET owner=? WHERE attempt_key=?', (owner, _key(request.ref)))

    def recover_reserved(self, request, owner):
        # Atomic cancellation is proof of no dispatch: claim is committed before
        # any factory call and cannot succeed once this transition wins.
        with self._tx() as db:
            changed = db.execute("UPDATE adapter_leases SET owner=?, phase='released', evidence_ref='capacity:reservation-never-dispatched' WHERE attempt_key=? AND adapter=? AND request_digest=? AND phase='reserved'",
                (owner, _key(request.ref), request.conditions.adapter, body_digest(request))).rowcount
            if changed != 1:
                raise CapacityError('reservation already dispatched or request mismatch')

    def unresolved(self):
        """Enumerate durable identities even if Controller never saved the UUID."""
        with self._tx() as db:
            rows = db.execute("SELECT run_id, job_id, attempt_id, adapter, request_digest, phase FROM adapter_leases WHERE phase!='released' ORDER BY rowid").fetchall()
        return tuple(LeaseSnapshot(c.AttemptRef(*row[:3]), *row[3:]) for row in rows)

    def cancel_unstarted(self, snapshot):
        """Cancel only this exact, still-undispatched durable reservation.

        Does not need the original request, which may not yet exist in the
        Controller journal. CAS races safely against claim; executing rows are
        never released, including when a caller supplies an old snapshot.
        """
        if type(snapshot) is not LeaseSnapshot or snapshot.phase != 'reserved':
            raise CapacityError('exact reserved lease snapshot required')
        ref = snapshot.ref
        with self._tx() as db:
            changed = db.execute("UPDATE adapter_leases SET phase='released', evidence_ref='capacity:reservation-never-dispatched' WHERE attempt_key=? AND run_id=? AND job_id=? AND attempt_id=? AND adapter=? AND request_digest=? AND phase='reserved'",
                (_key(ref), ref.run_id, ref.job_id, ref.attempt_id, snapshot.adapter, snapshot.request_digest)).rowcount
            if changed != 1:
                raise CapacityError('reservation already dispatched or snapshot mismatch')
        return c.StopReply(ref, c.StopStatus.CONFIRMED, 'durable reservation never dispatched',
            'capacity:reservation-never-dispatched')

    def count(self, adapter):
        with self._tx() as db:
            return db.execute("SELECT count(*) FROM adapter_leases WHERE adapter=? AND phase!='released'", (adapter,)).fetchone()[0]


class PooledAdapter:
    """Adapter-compatible routing to one child per exact Attempt.

    reserve/cancel_reservation are host admission APIs, not Adapter Contract
    fields. Controller uses them before spending an Attempt. Locks only serialize
    calls for this pool; SQLite owns the cross-instance/process capacity limit.
    """
    def __init__(self, adapter, *, ledger, canonical_ledger, factory):
        if adapter not in ADAPTERS or not callable(factory):
            raise CapacityError('known Adapter and request-bound child factory required')
        if Path(canonical_ledger) != ledger.path:
            raise CapacityError('pool differs from canonical host ledger')
        self.adapter, self.ledger, self.factory = adapter, ledger, factory
        self._owner, self._lock = uuid4().hex, RLock()
        self._requests, self._children, self._receipts = {}, {}, {}
        self._stops = {}

    def reserve(self, request):
        if request.conditions.adapter != self.adapter:
            raise CapacityError('cross-Adapter request')
        with self._lock:
            accepted = self.ledger.reserve(request, self._owner)
            if accepted:
                self._requests[request.ref] = request
            return accepted

    def cancel_reservation(self, request):
        with self._lock:
            return self.ledger.release_reserved(request, self._owner)

    def execute(self, request):
        with self._lock:
            if request.ref in self._receipts:
                return c.OperationReply(request.ref, c.OperationStatus.INVALID_STATE, 'Attempt already dispatched')
            if request.ref not in self._requests and not self.reserve(request):
                return c.OperationReply(request.ref, c.OperationStatus.UNAVAILABLE, 'Adapter capacity full',
                    never_started=c.NeverStarted(request, 'capacity:full-before-child-factory'))
            self.ledger.claim(request, self._owner)
            self._receipts[request.ref] = None  # Factory/execute exceptions stay ambiguous.
            try:
                child = self.factory(request)
                if request.job.output_candidate and not isinstance(child, c.OutputCollector):
                    # Checked after a side-effect-free factory and before
                    # child.execute. The request-bound proof is retained
                    # BEFORE the fallible ledger write — a failed release
                    # (global or not) never discards the honest receipt.
                    reply = c.OperationReply(request.ref, c.OperationStatus.UNAVAILABLE,
                        'route adapter lacks verified output collector',
                        never_started=c.NeverStarted(request, CHILD_LACKS_COLLECTOR))
                    self._receipts[request.ref] = reply
                    self.ledger.release(request, self._owner,
                                        CHILD_LACKS_COLLECTOR)
                    return reply
                self._children[request.ref] = child
                reply = child.execute(request)
                if type(reply) is not c.OperationReply or reply.ref != request.ref:
                    raise CapacityError('child execute identity mismatch')
                if reply.never_started is not None:
                    if reply.never_started.request != request:
                        raise CapacityError('child never-started request mismatch')
                    self._receipts[request.ref] = reply
                    self.ledger.release(request, self._owner, reply.never_started.evidence_ref)
                    return reply
                self._receipts[request.ref] = reply
                return reply
            except GLOBAL_FAILURES:
                # StoreUnavailable/OwnerUnavailable/sqlite3.Error cross
                # the Controller/Driver boundary unchanged — the host
                # latch owns them; never a per-Attempt ERROR receipt.
                raise
            except Exception:
                return c.OperationReply(request.ref, c.OperationStatus.ERROR, 'child dispatch unconfirmed')

    def reattach(self, request, child):
        """Trusted host supplies the original Attempt's Native recovery adapter.

        Never call the execution factory here. Owner serialization and original
        handle validation remain the host's responsibility, like Controller
        restart. Unsupported Native recovery remains blocked with slots held.
        """
        if request.conditions.adapter != self.adapter:
            raise CapacityError('cross-Adapter recovery')
        with self._lock:
            self.ledger.attach(request, self._owner)
            self._requests[request.ref], self._children[request.ref] = request, child
            self._receipts[request.ref] = None

    def recover_unstarted(self, request):
        """Cancel or reproduce the receipt for an exact reservation that
        provably never reached its factory; idempotent across restarts.

        A still-reserved row cancels via recover_reserved; a row already
        released with never-dispatched evidence and the same request
        digest reproduces the identical reply with no ledger write — the
        crash window between ledger release and receipt commit. Anything
        else is no proof of non-dispatch and fails closed.
        """
        if request.conditions.adapter != self.adapter:
            raise CapacityError('cross-Adapter recovery')
        with self._lock:
            row = self.ledger.row(request.ref, self.adapter)
            if (row is None or row[0] != body_digest(request)
                    or (row[2] != 'reserved'
                        and (row[2], row[3]) != ('released',
                            'capacity:reservation-never-dispatched'))):
                raise CapacityError(
                    'reservation already dispatched or request mismatch')
            if row[2] == 'reserved':
                self.ledger.recover_reserved(request, self._owner)
            self._requests[request.ref] = request
            reply = c.OperationReply(request.ref, c.OperationStatus.UNAVAILABLE,
                'reservation recovered before dispatch', never_started=c.NeverStarted(
                    request, 'capacity:reservation-never-dispatched'))
            self._receipts[request.ref] = reply
            return reply

    def _child(self, ref):
        child = self._children.get(ref)
        request = self._requests.get(ref)
        row = self.ledger.row(ref, self.adapter)
        if (child is None or request is None or row is None
                or row[0] != body_digest(request) or row[1] != self._owner):
            raise CapacityError('exact child unavailable; trusted recovery required')
        return child

    def stop(self, ref):
        with self._lock:
            row = self.ledger.row(ref, self.adapter)
            if row is None:
                return c.StopReply(ref, c.StopStatus.UNCONFIRMED, 'Attempt lease unavailable')
            if row[2] == 'released':
                return c.StopReply(ref, c.StopStatus.CONFIRMED, 'retained cessation evidence', row[3])
            request = self._requests.get(ref)
            if request is not None and self.cancel_reservation(request):
                return c.StopReply(ref, c.StopStatus.CONFIRMED, 'reservation never dispatched', 'capacity:reservation-never-dispatched')
            # Retained exact-request proofs settle a lease whose release
            # write failed on a global fault — no child factory/execute,
            # no invented Result. Every guard is exact: a foreign,
            # wrong-ref, wrong-type or non-CONFIRMED value never frees
            # the slot.
            proof = self._receipts.get(ref)
            if (request is not None
                    and type(proof) is c.OperationReply
                    and proof.ref == ref
                    and proof.never_started is not None
                    and proof.never_started.request == request):
                self.ledger.release(request, self._owner,
                                    proof.never_started.evidence_ref)
                return c.StopReply(ref, c.StopStatus.CONFIRMED,
                    'retained never-started dispatch proof',
                    proof.never_started.evidence_ref)
            stopped = self._stops.get(ref)
            if (request is not None
                    and type(stopped) is c.StopReply
                    and stopped.ref == ref
                    and stopped.status == c.StopStatus.CONFIRMED):
                self.ledger.release(request, self._owner,
                                    stopped.evidence_ref)
                return stopped
            try:
                reply = self._child(ref).stop(ref)
                if type(reply) is not c.StopReply or reply.ref != ref:
                    raise CapacityError('child stop identity mismatch')
                if reply.status == c.StopStatus.CONFIRMED:
                    # Proof retained BEFORE the fallible ledger write.
                    self._stops[ref] = reply
                    self.ledger.release(request, self._owner, reply.evidence_ref)
                return reply
            except GLOBAL_FAILURES:
                raise
            except Exception:
                return c.StopReply(ref, c.StopStatus.UNCONFIRMED, 'child cessation unconfirmed')

    def events(self, ref, after=None):
        with self._lock:
            events = self._child(ref).events(ref, after)
            if any(event.ref != ref for event in events):
                raise CapacityError('child event identity mismatch')
            return events

    def status(self, ref):
        with self._lock:
            event = self._child(ref).status(ref)
            if event.ref != ref:
                raise CapacityError('child status identity mismatch')
            return event

    def respond(self, response):
        with self._lock:
            row = self.ledger.row(response.ref, self.adapter)
            if row is None or row[2] != 'executing':
                return c.OperationReply(response.ref, c.OperationStatus.INVALID_STATE, 'no active capacity reservation')
            reply = self._child(response.ref).respond(response)
            if reply.ref != response.ref:
                raise CapacityError('child response identity mismatch')
            return reply

    def resume(self, state):
        with self._lock:
            row = self.ledger.row(state.ref, self.adapter)
            if state.adapter != self.adapter or row is None or row[2] != 'executing':
                return c.OperationReply(state.ref, c.OperationStatus.INVALID_STATE, 'no active capacity reservation')
            reply = self._child(state.ref).resume(state)
            if reply.ref != state.ref:
                raise CapacityError('child resume identity mismatch')
            return reply

    def collect_output(self, ref):
        """Forward collection to the child owning this exact Attempt.

        The child is retained after confirmed cessation releases its capacity
        lease; a missing collector is CapacityError, never an empty output.
        """
        with self._lock:
            child = self._child(ref)
            if not isinstance(child, c.OutputCollector):
                raise CapacityError('child lacks output collector')
            return child.collect_output(ref)

    def usage(self):
        # Host UsageStore ingestion remains explicit. Do not synthesize or merge
        # account percentages from independently scoped child observations.
        return ()

    def close(self):
        with self._lock:
            for child in self._children.values():
                close = getattr(child, 'close', None)
                if close is not None:
                    try:
                        close()
                    except Exception:
                        pass
            # Cleanup alone is not evidence of cessation; leases remain intact.


class NativeAdapterPools(Mapping):
    """Production host composition; reuse this mapping for every service Run.

    Independent instances MUST receive the same canonical host-configured path.
    The constructor supplies that exact ledger to all three factories' pools.
    Single Native probes may continue using bare adapters outside this service.
    """
    def __init__(self, *, canonical_ledger, factories):
        if not PRIMARY_ADAPTERS <= set(factories) or not set(factories) <= ADAPTERS:
            raise CapacityError('one factory for each of the three Native Adapters required')
        self.ledger = CapacityLedger(canonical_ledger)
        self._pools = {adapter: PooledAdapter(adapter, ledger=self.ledger,
            canonical_ledger=canonical_ledger, factory=factories[adapter]) for adapter in factories}

    def __getitem__(self, adapter): return self._pools[adapter]
    def __iter__(self): return iter(self._pools)
    def __len__(self): return len(self._pools)
    def close(self):
        for pool in self._pools.values(): pool.close()
