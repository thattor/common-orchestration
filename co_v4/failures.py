"""co_v4/failures.py — the single closed global-failure tuple (#190 M3).

StoreUnavailable, OwnerUnavailable and raw sqlite3.Error mean the store
or the owner cannot be trusted: they cross the Controller/Driver
boundary unchanged — no controller_error finalization, no checkpoint
save, no Native stop or capacity release. NotFound is deliberately not
here (the Controller keeps its per-Run handling; the Driver handles it
separately). Leaf module: it must never import Controller/ServiceDriver,
and state.py/service_owner.py must never import it."""
import sqlite3

from .service_owner import OwnerUnavailable
from .state import StoreUnavailable

GLOBAL_FAILURES = (StoreUnavailable, OwnerUnavailable, sqlite3.Error)
