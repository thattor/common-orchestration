"""co_v4/host_runtime.py — trusted build seam for ServiceHost (#190 M3).

Public surface: build(config) -> builder(owner, retain) -> Components.

Exact order (owner already acquired by ServiceHost):
  1. build_routes(config)            — Phase B per route; refused here
     never opens a credential file and never binds a socket.
  2. load_registry(protected BYTES, catalog, route_configs).
  3. ControlStore(state_root/'control.sqlite', guard=owner.check) handed
     to retain() at construction; OutputStore(state_root/'outputs',
     guard=owner.check) constructed right after — descriptor-free,
     per-operation fds; verified as a component, never retained.
  4. Canonical ledger + one PooledAdapter per adapter id, each pool
     retained iteratively the moment it exists.
  5. Gateway(store, bound_resolver=registry.unconfirmed_after_seconds).
  6. controller_factory(run_id, snapshot).
  7. http_factory — returns an UNSTARTED HttpService; ServiceHost holds
     the object before calling start(), after driver.start() validated
     every enqueued row.

retain() is the Host's reverse-order close seam: the builder registers
handle-owning objects and never closes or suppresses a close itself —
on any error it simply raises and the Host releases in reverse
registration order, owner last. The retained set is exactly the
ControlStore and each PooledAdapter. The ledger (per-transaction
connections), registry, broker, auth, Gateway and OutputStore own no
persistent handle and are not retained. The evidence resolver is a late-bound lexical closure:
the ControlStore evidence callable exists at construction, and
make_evidence is installed only after the store exists, inside the same
thread — never invoked earlier, never a private setter. Usage stays
EMPTY; co:text-profile is shared with planner and child factories.
"""
from datetime import datetime, timezone

from .ac import Acceptance
from .adapter_capacity import CapacityLedger, PooledAdapter
from .controller import Controller
from .gateway_store import Gateway
from .host_config import HostConfig
from .host_policy import make_evidence
from .host_routes import TEXT_WORKSPACE, build_routes, read_protected
from .http_auth import IngressBroker, load_principals
from .http_service import HttpService
from .output_store import OutputStore
from .profile_acceptance import ProfileVerifier
from .profile_planner import ProfilePlanner
from .profile_registry import load_registry
from .service_host import Components
from .state import ControlStore, RunSnapshot
from .usage import UsageStore

CONTROL_DB = 'control.sqlite'
OUTPUT_DIR = 'outputs'


def _utc_string():
    """One shared UTC string clock for ControlStore and IngressBroker."""
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def build(config):
    """Validate the closed config once; return the owned builder."""
    if type(config) is not HostConfig or config.bind_host != '127.0.0.1':
        raise ValueError('closed host configuration required')
    db_path = config.state_root + '/' + CONTROL_DB
    out_path = config.state_root + '/' + OUTPUT_DIR

    def builder(owner, retain):
        """Compose on the acquired owner; retain each handle at birth.

        Any error propagates untouched: nothing here closes a resource,
        swallows a close, or fakes a fixture.
        """
        bundle = build_routes(config)            # Phase B, every route
        registry = load_registry(
            read_protected(config.registry_file),
            catalog=bundle.catalog, routes=bundle.route_configs)
        broker = IngressBroker(_utc_string)
        auth = load_principals(config.principals_file)
        # Late-bound evidence closure: callable at store construction;
        # the resolver is installed only once the store exists.
        resolve = {}
        def evidence(run, request):
            return resolve['fn'](run, request)
        store = retain(ControlStore(db_path, verifier=broker.verifier,
            evidence=evidence, clock=_utc_string,
            profile_resolver=registry.resolve, guard=owner.check))
        resolve['fn'] = make_evidence(store, registry, bundle)
        output_store = OutputStore(out_path, guard=owner.check)
        ledger = CapacityLedger(config.ledger_path)
        pools = {}
        for adapter in bundle.factories:         # iterative: a partial
            pools[adapter] = retain(PooledAdapter(   # pool is retained
                adapter, ledger=ledger,              # the moment it is
                canonical_ledger=config.ledger_path, # constructed
                factory=bundle.factories[adapter]))
        gateway = Gateway(
            store, bound_resolver=registry.unconfirmed_after_seconds)
        state = store.controller()
        usage = UsageStore()                     # empty: never fabricated
        acceptance = Acceptance(
            ProfileVerifier(registry, state, output_store))
        planner = ProfilePlanner(registry, bundle.route_configs,
                                 TEXT_WORKSPACE)

        def controller_factory(run_id, snapshot):
            # snapshot pins the committed Run the caller examined; the
            # Controller re-reads state itself — a mismatched or foreign
            # snapshot is refused, never substituted.
            if (type(run_id) is not str
                    or type(snapshot) is not RunSnapshot
                    or snapshot.run_id != run_id):
                raise ValueError('run_id and committed RunSnapshot')
            return Controller(
                run_id, state=state, judgment=store.judgment(),
                catalog=bundle.catalog, usage=usage, adapters=pools,
                acceptance=acceptance, planner=planner,
                clock=lambda: datetime.now(timezone.utc),
                output_store=output_store)

        def http_factory(available):
            """Construct+validate only. UNSTARTED: ServiceHost holds the
            service before calling start(), so a start failure already
            has the owned handle for bounded close/retry. Nothing is
            bound or spawned here."""
            return HttpService(
                gateway=gateway, broker=broker, auth=auth,
                registry=registry, output_store=output_store,
                available=available, port=config.bind_port,
                sync_timeout=config.sync_wait_s,
                max_body_bytes=config.max_body_bytes)

        return Components(
            store=store, gateway=gateway, output_store=output_store,
            ledger=ledger, adapters=pools, registry=registry,
            http_factory=http_factory,
            controller_factory=controller_factory)

    return builder
