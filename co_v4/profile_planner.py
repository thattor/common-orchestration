"""Deterministic single-Job planner for pinned task-profile Runs (#190 M3).

Host-composed and pure: one fixed Job per pinned profile revision, driven by
the exact registry entry under (profile_id, revision_digest) -- never by the
mutable alias map -- with the client request carried verbatim as Job context
only. original_intent is reparsed through the real subset parser and must
equal its canonical bytes exactly; any mismatch fails closed. At plan time
every pinned-field, pin-identity, intent or route-table disagreement is
committed-state corruption -- the registry and route table are immutable
for the life of the process and check_store validated them at startup --
so these facts raise IntegrityViolation (the Controller's per-Run fatal
latch), never ValueError and never ProfileRegistryMismatch (that refusal
is startup-only). Host-constructor and route-table shape errors remain
ValueError: they are composition facts, not committed tampering. The
planner makes no authorization decision, executes nothing, accepts no
client-supplied criteria, routes or metadata, and emits no second Job.
"""
from . import contracts as c
from .catalog import UseCase
from .controller import JobPlan
from .gateway_store import MAX_CANONICAL_BYTES
from .profile_registry import (NativeRouteConfig, ProfileRegistry,
                               RouteConfig, canonical)
from .responses_input import RequestRejected, parse
from .state import IntegrityViolation

JOB_ID = 'job-1'
ACTION_NAME = 'text.generate'
METHOD = 'text.generate'


def _wire_input(items):
    """Exact client input shape: the string, or ordered role/fragment items."""
    if type(items) is str:
        return items
    return [{'type': 'message', 'role': item.role,
             'content': item.content if type(item.content) is str else
                 [{'type': f.kind, 'text': f.text} for f in item.content]}
            for item in items]


def _context_json(intent):
    """Host instructions stay on Job.instructions; client instructions and the
    exact input are context. metadata is never admitted."""
    return canonical({'instructions': intent.instructions,
                      'input': _wire_input(intent.input)}).decode('utf-8')


class ProfilePlanner:
    """planner(run, completed_jobs, run_goal) for profile Runs.

    Composed with the loaded registry, the host's resolved RouteConfig
    sequence and the fixed text workspace constant. Immutable; no state is
    kept between calls, so a crash-safe reentry replays identically.
    """
    def __init__(self, registry, routes, workspace):
        if (type(registry) is not ProfileRegistry
                or type(workspace) is not str or not workspace.strip()):
            raise ValueError('registry and fixed workspace required')
        route_map = {}
        for config in routes:
            if (type(config) is not RouteConfig
                    and type(config) is not NativeRouteConfig):
                raise ValueError('host RouteConfig required')
            key = (config.model, config.adapter, config.environment_ref)
            if key in route_map:
                raise ValueError('duplicate route configuration')
            route_map[key] = config
        self._registry, self._routes = registry, route_map
        self._workspace = workspace

    def _reparse(self, run):
        """Revalidate committed intent; tampering raises, never plans.

        RunSnapshot.original_intent is str: the canonical request body decoded
        at submit. Re-encode strict UTF-8 (a surrogate raises UnicodeEncodeError
        and fails closed) and reparse under the Gateway bound, which admits
        canonical expansion of a valid near-limit client body."""
        original = run.original_intent
        if type(original) is not str:
            raise IntegrityViolation(
                'original_intent canonical text required')
        try:
            blob = original.encode('utf-8')
            intent = parse(blob, limit=MAX_CANONICAL_BYTES)
        except (RequestRejected, UnicodeEncodeError):
            raise IntegrityViolation(
                'original_intent does not reparse') from None
        if intent.canonical_body != blob:
            raise IntegrityViolation(
                'original_intent differs from canonical request')
        return intent

    def __call__(self, run, completed_jobs, run_goal):
        if run.job_ids:
            # One fixed Job ever: the canonical ('job-1',) returns None so the
            # persisted plan and pure retry/budget rules own its continuation;
            # any other identity set is corrupt pinned state, never skipped.
            if run.job_ids != (JOB_ID,):
                raise IntegrityViolation(
                    'unexpected Job identity on single-Job Run')
            return None
        profile = run.profile
        if type(profile) is not c.TaskProfile:
            raise IntegrityViolation('pinned TaskProfile required')
        # The bound revision drives everything; resolve() is for new
        # submissions only, so an alias move can never rebind this Run.
        entry = self._registry.get(profile.profile_id, profile.revision_digest)
        if entry is None:
            # Absent at RUNTIME is committed corruption (startup validated);
            # the startup-only ProfileRegistryMismatch class is never raised
            # here.
            raise IntegrityViolation('pinned revision absent from registry')
        # check_store guards startup only; the committed pin must still match
        # its entry field-for-field at plan time (same semantics, fail closed).
        if (profile.effect_class != entry.effect_class
                or profile.requires_output != entry.requires_output
                or profile.routes != entry.routes):
            raise IntegrityViolation(
                'pinned profile fields differ from registry entry')
        intent = self._reparse(run)
        conditions = []
        seen = set()
        for model, adapter, env in entry.routes:
            if (model, adapter) in seen:
                raise IntegrityViolation(
                    'pinned routes need unique model/adapter pairs')
            seen.add((model, adapter))
            config = self._routes.get((model, adapter, env))
            if config is None:
                raise IntegrityViolation(
                    'pinned route missing host configuration')
            if type(config) is NativeRouteConfig:
                conditions.append(c.ExecutionConditions(
                    model, adapter, config.native_cwd,
                    config.environment_ref,
                    ('native-measurement:' + config.measurement_digest,)))
            else:
                conditions.append(c.ExecutionConditions(
                    model, adapter, self._workspace, env,
                    ('route-profile:' + config.profile.profile_digest,)))
        job = c.Job(run.run_id, JOB_ID, entry.job_instructions,
                    entry.job_criteria, context_json=_context_json(intent),
                    output_candidate=True)
        action = c.Action(ACTION_NAME, c.Scope((
            ('profile', entry.profile_id),
            ('profile_revision', entry.revision_digest),
            ('workspace', self._workspace)), True))
        return JobPlan(job, action, METHOD, UseCase(category=entry.use_case),
                       tuple(conditions))
