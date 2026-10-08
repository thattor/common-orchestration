"""co_v4/service_driver.py — bounded service driver (Opus C + §2 ruling).

start() calls project() for every enqueued Run once per process, so every
persisted row — including terminal ones — is re-validated. tick() steps
each pending non-quarantined Run once in enqueue order, then projects,
then projects any terminal Run still lacking a row. controller_factory is
(run_id, committed RunSnapshot); one cached Controller per Run, evicted
only on committed terminal state — the step's return value is never
trusted. Per-run factory/step/project failures are audited as sanitized
closed codes (deduped, bounded 64, no exception text); a per-run
IntegrityViolation from project() quarantines the Run for the process
lifetime — no further step, and restart re-detects it deterministically.
Missing Run/response rows, unreadable aggregates, StoreUnavailable and
OwnerUnavailable are global and propagate, stopping the driver.
"""
from . import contracts as c
from .adapter_capacity import CapacityError
from .failures import GLOBAL_FAILURES
from .state import (Conflict, IntegrityViolation, InvalidTransition,
                    NotFound)

# Closed exception -> audit type_code map; IntegrityViolation subclasses
# Conflict, so it must be matched first.
_TYPE_MAP = ((IntegrityViolation, 'integrity'), (Conflict, 'conflict'),
             (InvalidTransition, 'invalid_transition'),
             (CapacityError, 'capacity'), (c.CollectionError, 'collection'),
             (ValueError, 'value'))


class ServiceDriver:
    def __init__(self, owner, store, gateway, *, controller_factory,
                 initial_quarantine=()):
        self._owner, self._store, self._gateway = owner, store, gateway
        self._factory = controller_factory
        self._controllers = {}
        self._quarantined = set(initial_quarantine)
        for run_id in self._quarantined:
            # Startup quarantine (registry field drift or recovery
            # contradiction): audit once, never step; project() still
            # validates its row, and dedupe keeps one entry per revision.
            store.controller().record_driver_event(
                run_id, 'driver_project_error', 'integrity')

    @staticmethod
    def _type_code(exc):
        for typ, code in _TYPE_MAP:
            if isinstance(exc, typ):
                return code
        return 'other'

    def _audit(self, run_id, category, exc):
        self._store.controller().record_driver_event(
            run_id, category, self._type_code(exc))

    def _step(self, run_id):
        """One Controller step; factory/step failures are per-run audits."""
        ctrl = self._store.controller()
        controller = self._controllers.get(run_id)
        if controller is None:
            try:
                controller = self._factory(run_id, ctrl.get_run(run_id))
            except GLOBAL_FAILURES:
                raise
            except NotFound:
                raise
            except Exception as exc:
                self._audit(run_id, 'controller_factory_error', exc)
                return
            self._controllers[run_id] = controller
        try:
            controller.step()
        except GLOBAL_FAILURES:
            raise
        except NotFound:
            raise
        except Exception as exc:
            self._audit(run_id, 'driver_step_error', exc)
            return
        if ctrl.get_run(run_id).state in c.TERMINAL:
            self._controllers.pop(run_id, None)

    def _project(self, run_id):
        """Validate the persisted row or insert the decisive derivation.

        A per-run IntegrityProjection — a row failing _row_view, including
        the committed-stop invariant — audits once and quarantines the Run
        for the process lifetime. NotFound on a known work row is global
        queue corruption and propagates, as do store/owner failures.
        """
        try:
            return self._gateway.project(run_id)
        except GLOBAL_FAILURES:
            raise
        except NotFound:
            raise
        except IntegrityViolation as exc:
            self._quarantined.add(run_id)
            self._controllers.pop(run_id, None)
            self._audit(run_id, 'driver_project_error', exc)
            return None
        except Exception as exc:
            self._audit(run_id, 'driver_project_error', exc)
            return None

    def start(self) -> tuple:
        """Validate/project every enqueued Run; never calls the factory."""
        self._owner.check()
        return tuple(p for p in (self._project(run_id)
                                 for run_id in self._gateway.all_work())
                     if p is not None)

    def tick(self) -> tuple:
        """Each pending non-quarantined Run steps once in enqueue order and
        projects; terminal Runs lacking a row then project. Quarantined
        Runs are never stepped."""
        self._owner.check()
        results = []
        pending = self._gateway.pending_work()
        for run_id in pending:
            if run_id in self._quarantined:
                continue
            self._step(run_id)
            results.append(self._project(run_id))
        stepped = set(pending)
        for run_id in self._gateway.unprojected_work():
            if run_id not in stepped:
                results.append(self._project(run_id))
        return tuple(p for p in results if p is not None)

    def close(self):
        self._controllers.clear()
        self._quarantined.clear()
