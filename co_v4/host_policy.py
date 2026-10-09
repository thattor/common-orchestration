"""Host TrustedEvidence resolver for pinned text-profile Runs (#190 M3).

make_evidence composes the ControlStore evidence callback used by the
trusted host. It is pure over the committed snapshot, the frozen registry
and the Phase-B-qualified route table; its only store access is the public
read-only judgment_view inside the caller's existing transaction — never
_db/_tx/private state, never a nested BEGIN, never re-authentication of
the consumed receipt, never a Native call.

Every per-Run semantic or integrity failure returns hard_deny with fixed
evidence refs — the existing profile rule ends the Run
FAILED/approval_required (or latches the approval barrier plus real stop
on a live callback) with no wait and no new Approval, while other Runs
continue. Only the closed exception set (ValueError, RequestRejected,
ProfileRegistryMismatch, IntegrityViolation) raised inside the checks is
converted; structural failures — store/sqlite/owner unavailability,
facade misuse, a corrupt route table or any unexpected exception such as
TypeError/AttributeError — propagate unchanged to evaluate's existing
global fail-closed rule (503 latch, driver stopped, owner held).

This attests static route qualification only. The QualifiedRouteGate
still owns every pre-POST process, file and probe check; an empty child
environment is a code contract of the owned launcher, not verified here.
"""
from dataclasses import replace

from . import contracts as c
from .gateway_store import MAX_CANONICAL_BYTES
from .host_routes import TEXT_WORKSPACE
from .judgment import TrustedEvidence
from .profile_planner import ProfilePlanner
from .profile_registry import (ADAPTERS, NativeRouteConfig,
                               ProfileRegistry, ProfileRegistryMismatch,
                               RouteConfig)
from .responses_input import RequestRejected, parse
from .state import IntegrityViolation, body_digest

POLICY_REF = 'host-policy:qualified-text-route/1'
# Closed per-Run failure classes only; bugs and infrastructure propagate.
_PER_RUN = (ValueError, RequestRejected, ProfileRegistryMismatch,
            IntegrityViolation)


def make_evidence(store, registry, route_bundle):
    """Bind the resolver to immutable host objects.

    Missing or mistyped registry/route tables raise here at composition —
    a global startup refusal, never a per-Run outcome. Returns
    evidence(run, request) for ControlStore's trusted evidence seam.
    """
    if type(registry) is not ProfileRegistry:
        raise ValueError('profile registry required')
    routes = tuple(route_bundle.route_configs)
    if any(type(config) not in (RouteConfig, NativeRouteConfig)
           for config in routes):
        raise ValueError('host RouteConfig sequence required')
    contexts = route_bundle.contexts
    native = {}
    for config in routes:
        if type(config) is NativeRouteConfig:
            key = (config.model, config.adapter, config.environment_ref)
            ctx = contexts.get(key)
            if type(ctx) is not NativeRouteConfig or ctx != config:
                raise ValueError('native route context required')
            native[key] = config
    planner = ProfilePlanner(registry, routes, TEXT_WORKSPACE)

    def evidence(run, request):
        for key, config in native.items():
            ctx = contexts.get(key)
            if type(ctx) is not NativeRouteConfig or ctx != config:
                raise TypeError('native route context changed')
        # operation_key is safe before any per-Run check: a missing or
        # malformed profile must deny, never AttributeError into global.
        profile = getattr(run, 'profile', None)
        pid = getattr(profile, 'profile_id', '')
        rdigest = getattr(profile, 'revision_digest', '')
        operation_key = ('text.generate|'
                         + (pid if type(pid) is str else '') + '|'
                         + (rdigest if type(rdigest) is str else '')
                         + '|' + TEXT_WORKSPACE)

        def denied():
            return TrustedEvidence(
                request_digest=body_digest(request),
                policy_ref=POLICY_REF,
                operation_key=operation_key,
                hard_deny=True)

        def refs(ctx):
            if type(ctx) is NativeRouteConfig:
                return ('registry:' + rdigest,
                        'native-measurement:' + ctx.measurement_digest,
                        ctx.environment_ref)
            return ('registry:' + rdigest,
                    'route-profile:' + ctx.profile.profile_digest,
                    ctx.environment_ref,
                    'manifest:' + ctx.manifest_sha256)

        try:
            # Membership inside the caller's existing transaction only.
            view = store.judgment_view(run.run_id)
            gateway = view.gateway
            if gateway is None:
                raise ValueError('no committed gateway membership')
            digest, alias, _created = gateway
            original = run.original_intent
            if type(original) is not str:
                raise ValueError('committed intent canonical text required')
            blob = original.encode('utf-8')
            intent = parse(blob, limit=MAX_CANONICAL_BYTES)
            # The existing Gateway binding (read_context): canonical
            # bytes, the DOMAIN-prefixed body_hash from responses_input,
            # and intent.model == row alias all re-verify here; the
            # consumed ingress receipt is never re-authenticated.
            if (intent.canonical_body != blob
                    or intent.body_hash != digest
                    or intent.model != alias):
                raise ValueError('gateway row does not bind the intent')
            if (type(run.authenticated_origin_ref) is not str
                    or not run.authenticated_origin_ref.strip()):
                raise ValueError('missing authenticated origin reference')
            if type(profile) is not c.TaskProfile:
                raise ValueError('pinned TaskProfile required')
            entry = registry.get(profile.profile_id, rdigest)
            if entry is None:
                raise ProfileRegistryMismatch()
            if entry.task_profile() != profile:
                raise ValueError('pinned profile fields differ from entry')
            # Deterministic pure recomputation on the creation view:
            # empty job_ids replays the fixed single-Job plan unchanged.
            plan = planner(replace(run, job_ids=()), (), None)
        except _PER_RUN:
            # All checks above are per-Run facts: deny this Run only.
            return denied()

        if request.confirmation is not None:
            # Any live Native confirmation on a noninteractive profile Run:
            # hard_deny -> the existing profile rule latches the real stop.
            return denied()

        if request.proposed_job is not None:
            conditions = plan.conditions[0]
            ctx = contexts.get((conditions.model, conditions.adapter,
                                conditions.environment_ref))
            if (ctx is None or request.proposed_job != plan.job
                    or request.action != plan.action
                    or request.method != plan.method
                    or request.conditions != conditions):
                return denied()
            return TrustedEvidence(
                request_digest=body_digest(request),
                policy_ref=POLICY_REF,
                evidence_refs=refs(ctx),
                operation_key=operation_key,
                intent_contained=True,
                intent_authorizes=True,
                conditions_verified=True,
                protection_verified=True)

        conditions = request.conditions
        key = (conditions.model, conditions.adapter,
               conditions.environment_ref)
        ctx = contexts.get(key)
        job = next((j for j in view.jobs
                    if j.job_id == request.ref.job_id), None)
        if (ctx is None or job != plan.job
                or request.action != plan.action
                or request.method != plan.method
                or conditions not in plan.conditions
                or (conditions.adapter not in ADAPTERS
                    and key not in native)):
            return denied()
        return TrustedEvidence(
            request_digest=body_digest(request),
            policy_ref=POLICY_REF,
            evidence_refs=refs(ctx),
            operation_key=operation_key,
            intent_authorizes=True,
            conditions_verified=True,
            protection_verified=True)

    return evidence
