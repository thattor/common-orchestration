"""co_v4/admission_recovery.py — F2 admission recovery before Controllers.

Runs once at startup, after check_store and before any Controller or
listener. Scope is this store's gateway_work only: those run_ids are
server-generated and unique across hosts, so no foreign or internal
Intake lease is ever touched. A provably never-dispatched reservation
gets a genuine NeverStarted receipt through the shared commit helper;
ambiguous or executing leases stay held. A CapacityError is global and
refuses startup; store/owner failures propagate. No Controller is built.
"""
from .adapter_capacity import PooledAdapter
from .state import (Conflict, IntegrityViolation, InvalidTransition,
                    body_digest, commit_execute_receipt)

NEVER_DISPATCHED = 'capacity:reservation-never-dispatched'


def _recover_attempt(attempt, state, ledger, pool):
    ref = attempt.ref
    if (state.attempt_settlement(ref) is not None
            or state.execute_receipt(ref) is not None):
        return
    request = state.admitted_request(ref)
    if request is None:
        # A listed Attempt with no committed request is a contradiction.
        raise IntegrityViolation('listed Attempt has no committed request')
    row = ledger.row(ref, pool.adapter)
    if (row is None or row[0] != body_digest(request)
            or row[2] == 'executing'                 # held, never released
            or (row[2] == 'released' and row[3] != NEVER_DISPATCHED)):
        return                              # no proof of non-dispatch
    reply = pool.recover_unstarted(request)  # the pool mints the receipt
    try:
        commit_execute_receipt(state, reply)
    except IntegrityViolation:
        raise                                # contradiction: quarantine
    except (Conflict, InvalidTransition):
        pass                                 # CAS window; next start retries


def recovery_scan(gateway, state, ledger, adapters, initial_quarantine):
    """Scan A (state) and Scan B (ledger); returns the quarantine union.

    Quarantined Runs are skipped by both scans and nothing is written for
    them. An integrity contradiction quarantines only its Run; CapacityError
    and store/owner failures refuse startup globally.
    """
    quarantine = set(initial_quarantine)
    work = set(gateway.all_work())           # this store's members, verified
    for run_id in gateway.pending_work():    # Scan A: nonterminal, not held
        if run_id in quarantine:
            continue
        try:
            for attempt in state.attempts(run_id):
                adapter = adapters.get(attempt.conditions.adapter)
                if not isinstance(adapter, PooledAdapter):
                    continue                 # unpooled: ambiguous, held
                _recover_attempt(attempt, state, ledger, adapter)
        except IntegrityViolation:
            quarantine.add(run_id)
    for snapshot in ledger.unresolved():     # Scan B: ledger-driven
        if (snapshot.phase != 'reserved'     # executing stays held
                or snapshot.ref.run_id not in work   # foreign/internal
                or snapshot.ref.run_id in quarantine):
            continue
        try:
            request = state.admitted_request(snapshot.ref)
        except IntegrityViolation:
            quarantine.add(snapshot.ref.run_id)
            continue
        if request is not None:
            continue                         # admitted Attempt: Scan A owns it
        # Crash window reserve -> begin_attempt; a terminal Run cannot
        # admit afterwards, so cancel is safe for it too. The exact
        # snapshot CAS releases; no journal write is needed or possible.
        ledger.cancel_unstarted(snapshot)
    return frozenset(quarantine)
