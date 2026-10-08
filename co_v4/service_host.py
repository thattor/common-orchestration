"""co_v4/service_host.py — host lifecycle composition (#190 M3 §1/§4).

Exact startup order, no skipped steps:

1. ServiceOwner.acquire(root) — first, always.
2. build(owner, retain) — the trusted composition seam constructs
   ControlStore / OutputStore guard-bound to owner.check plus ledger,
   adapters, registry and factories; retain() registers each
   handle-owning object (the ControlStore and every PooledAdapter)
   immediately at construction so a partial build still unwinds in order
   with the owner last. OutputStore is descriptor-free (per-operation
   fds only) — verified as a component, never retained as a resource.
   This module never evals config, parses requests or supplies
   endpoints.
3. owner.bind_stores(store, output_store) and gateway/store binding —
   inventory assertion; the Components gateway must be the store's own.
4. check_store — pinned-revision validation; the returned set is the
   initial quarantine; a missing revision refuses startup.
5. recovery_scan — F2 admission recovery before any Controller exists.
6. ServiceDriver(initial_quarantine) — audits each quarantined Run once.
7. driver.start() — every enqueued row validated/projected BEFORE any
   listener can be constructed or bound.
8. One bounded driver thread at a fixed interval.
9. http_factory(available) — an UNSTARTED listener object (no socket, no
   thread); the host owns the reference before calling service.start(),
   so any start failure is already drain-reachable by close().

Latch: a global driver failure flips `unavailable`; the thread stops
ticking and every HTTP endpoint maps `not available()` to 503. Leases
stay held; pools are never released on the latch path.

Shutdown/close: http.close() (stop accepts, bounded handler join; its
contract returns 'stopped' or 'host_stop_unconfirmed' — anything else,
False or an exception is unconfirmed) -> stop and join the driver thread
bounded -> driver/adapters close (no cessation claim) -> stores.close()
-> owner.close() LAST. If handlers or the thread are not confirmed, or a
resource close raises, nothing is freed underneath live writers: owner,
stores and every ambiguous lease are retained, close() reports
'host_stop_unconfirmed', and a later close() retries the same ordered
teardown — every step is idempotent so retry never double-frees.
start() is single-shot; no restart after any attempt. No process kill,
no Native approval, no lease force-free; fixed codes only, no exception
text is retained or reported.
"""
from dataclasses import dataclass
import math
import os
from pathlib import Path
from threading import Event, Thread

from .admission_recovery import recovery_scan
from .output_store import OutputStore
from .profile_registry import check_store
from .service_driver import ServiceDriver
from .service_owner import ServiceOwner

DEFAULT_TICK_S = 0.1
JOIN_BOUND_S = 10.0
STOPPED = 'stopped'
STOP_UNCONFIRMED = 'host_stop_unconfirmed'


@dataclass(frozen=True)
class Components:
    """Typed host-built pieces; stores are already guard-bound to owner."""
    store: object                     # ControlStore
    gateway: object                   # this store's own Gateway
    output_store: object              # OutputStore
    ledger: object                    # CapacityLedger
    adapters: object                  # Mapping adapter -> Adapter/pool
    registry: object                  # ProfileRegistry
    http_factory: object              # callable(available) -> closeable
    controller_factory: object        # callable(run_id, RunSnapshot)


def _close(resource):
    closer = getattr(resource, 'close', None)
    if closer is not None:
        closer()


def _close_adapters(adapters):
    closer = getattr(adapters, 'close', None)
    if closer is not None:
        closer()
        return
    for pool in getattr(adapters, 'values', lambda: ())():
        _close(pool)


def _bound(value):
    """Finite positive real bound; bool, NaN and infinity are rejected."""
    return (type(value) in (int, float) and math.isfinite(value)
            and value > 0)


class ServiceHost:
    """Single-shot bounded owner/driver/listener lifecycle.

    close() is retryable: an unconfirmed result retains everything and a
    later call repeats the drain then releases — never a double free and
    never a release underneath a writer that was not confirmed stopped.
    """

    def __init__(self, root, build, *, tick_interval=DEFAULT_TICK_S,
                 join_bound=JOIN_BOUND_S):
        if (not callable(build) or not _bound(tick_interval)
                or not _bound(join_bound)):
            raise ValueError('host build and finite positive bounds required')
        self._root, self._build = root, build
        self._interval, self._join_bound = tick_interval, join_bound
        self._owner = self._comp = self._driver = self._http = None
        self._thread = None
        self._stop, self._unavailable = Event(), Event()
        self._attempted = self._released = False
        self._result = None
        self._retained = []          # pre-Components close order, identity only
        self._building = False       # retain() is valid only inside build

    def _retain(self, resource):
        """build()-scoped close-ordering registration; identity only, no
        other authority. Duplicate identity is an explicit error —
        closing the same handle twice is never silent."""
        if (not self._building
                or not callable(getattr(resource, 'close', None))
                or any(existing is resource
                       for existing in self._retained)):
            raise ValueError('invalid retained resource')
        self._retained.append(resource)
        return resource

    def available(self):
        """HTTP 503 latch input: False once a global failure is latched."""
        return self._http is not None and not self._unavailable.is_set()

    def _run(self):
        try:
            while not self._stop.wait(self._interval):
                self._driver.tick()
        except Exception:
            # Global failure classes only propagate out of tick(); per-Run
            # exceptions are already audited by the driver. Latch, stop
            # ticking, leases stay held; no extra abort or release.
            self._unavailable.set()

    def _drain(self):
        """Stop accepts + join handlers/thread, bounded. False means a
        writer may still be live; its handle is kept for the next try."""
        confirmed = True
        http = self._http
        if http is not None:
            try:
                closed = http.close()
            except Exception:
                closed = None
            if closed == STOPPED:
                self._http = None
            else:
                confirmed = False       # explicit unconfirmed or failure
        self._stop.set()
        thread = self._thread
        if thread is not None:
            if thread.is_alive():
                # join() on a never-started thread raises RuntimeError —
                # only a spawned writer is joined. A thread whose start()
                # raised before spawning is not a writer and is dropped;
                # one that spawned stays alive and keeps us unconfirmed.
                thread.join(self._join_bound)
            if thread.is_alive():
                confirmed = False
            else:
                self._thread = None
        return confirmed

    def _release(self):
        """Ordered idempotent teardown; owner always last. A raised close
        retains whatever was not yet released for a later retry."""
        driver = self._driver
        if driver is not None:
            _close(driver)
            self._driver = None
        retained = self._retained
        while retained:
            # Pre-Components partial-build path only: reverse registration
            # order (pools, then the store). A
            # close that raises stops the sequence here: the failing
            # object and everything after it stay retained, the owner is
            # never freed under an unconfirmed handle, and the next
            # close() retries from exactly this point.
            _close(retained[-1])
            retained.pop()
        comp = self._comp
        if comp is not None:
            # Post-handoff order: pools (construction order), then the
            # store, then the owner last — no cessation claim.
            _close_adapters(comp.adapters)      # no cessation claim
            _close(comp.store)
            self._comp = None
        owner = self._owner
        if owner is not None:
            owner.close()                       # always last
            self._owner = None

    def _teardown(self):
        """Drain then release. True only when every writer was confirmed
        stopped and every resource released; otherwise owner, stores and
        ambiguous leases stay held and the latch is set."""
        if not self._drain():
            self._unavailable.set()
            return False
        try:
            self._release()
        except Exception:
            self._unavailable.set()
            return False
        self._released = True
        return True

    def start(self):
        """Ordered startup, once. Any failure runs the same teardown:
        unconfirmed writers retain the owner, otherwise it is released."""
        if self._attempted:
            raise ValueError('host is single-shot')
        self._attempted = True
        owner = ServiceOwner.acquire(self._root)
        self._owner = owner
        try:
            self._building = True
            try:
                comp = self._build(owner, self._retain)
            finally:
                self._building = False
            # The Gateway must belong to THIS ControlStore; bind_stores
            # verifies store paths only, never the gateway's own binding.
            if type(comp) is not Components:
                raise ValueError('invalid host Components')
            # Accepted only when the retained set is EXACTLY {store} ∪
            # pools by identity and every pool is a DISTINCT object (an
            # aliased pool would be closed twice through adapters). An
            # unretained or extra handle unwinds via the pre-Components
            # ordered close.
            pools = list(getattr(comp.adapters, 'values', lambda: ())())
            retained_ids = {id(r) for r in self._retained}
            if (len({id(p) for p in pools}) != len(pools)
                    or retained_ids != ({id(comp.store)}
                                        | {id(p) for p in pools})
                    or len(self._retained) != len(retained_ids)
                    or id(comp.output_store) in retained_ids):
                raise ValueError('invalid host Components')
            # OutputStore is verified, not retained: exact type, the bound
            # owner guard (bound-method ==, None rejected), and the real
            # owner-root path — checked here so a foreign component is a
            # ValueError before bind_stores' own structural check runs
            # unchanged.
            try:
                out_ok = (
                    type(comp.output_store) is OutputStore
                    and getattr(comp.output_store, '_guard', None)
                    is not None
                    and comp.output_store._guard == owner.check
                    and os.path.realpath(comp.output_store.root)
                    == os.path.realpath(Path(self._root) / 'outputs'))
            except (OSError, ValueError):
                out_ok = False
            if not out_ok:
                raise ValueError('invalid host Components')
            # Retain the typed Components before the binding check so the
            # owned store/adapters are reachable by ordered _release on
            # refusal; the foreign Gateway's store is never touched. The
            # retained list hands off to comp here — no double close.
            self._comp = comp
            self._retained = []
            if (not callable(comp.http_factory)
                    or not callable(comp.controller_factory)
                    or getattr(comp.gateway, '_store', None) is not comp.store):
                raise ValueError('invalid host Components')
            owner.bind_stores(comp.store, comp.output_store)
            state = comp.store.controller()
            quarantine = check_store(comp.registry, comp.gateway, state)
            quarantine = recovery_scan(comp.gateway, state, comp.ledger,
                                       comp.adapters, quarantine)
            self._driver = ServiceDriver(
                owner, comp.store, comp.gateway,
                controller_factory=comp.controller_factory,
                initial_quarantine=set(quarantine))
            # Every row validates before any listener can exist; a failure
            # here means no socket and no Controller for quarantined Runs.
            self._driver.start()
            self._thread = Thread(target=self._run, daemon=True,
                                  name='co-service-driver')
            self._thread.start()
            # Own the unstarted service before start(): a start failure
            # then unwinds through _teardown -> _drain -> http.close()
            # like every other retained resource.
            self._http = comp.http_factory(self.available)
            self._http.start()
        except BaseException:
            self._teardown()
            raise
        return self

    def close(self):
        """Bounded ordered shutdown; returns a fixed code and is retryable:
        'stopped' once fully released, else 'host_stop_unconfirmed'."""
        if self._released:
            return STOPPED
        self._result = STOPPED if self._teardown() else STOP_UNCONFIRMED
        return self._result
