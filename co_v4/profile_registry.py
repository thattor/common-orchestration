"""Host-owned task profile registry (#190 M3).

A closed JSON document of immutable entries keyed by
(profile_id, revision_digest) plus an alias list used only to resolve new
submissions and build /v1/models. Loading validates the wire shape and the
host's non-secret resolved route configuration; it never executes code,
accepts client-supplied criteria or credentials, and never proves provider
identity -- dispatch still requires the real QualifiedRouteGate binding.
"""
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import json
from types import MappingProxyType

from . import contracts as c
from .catalog import (CATEGORIES, Catalog, CatalogEntry, UseCase,
                      Verification)
from .openai_transport import Deadlines, strict_json
from .protocol_profile import RouteProtocolProfile, environment_ref

REGISTRY_SCHEMA = 'co.task-profile-registry/1'
DIGEST_DOMAIN = b'co.task-profile/1\n'
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_ENTRIES = 256
MAX_ALIASES = 256
MAX_ROUTES = 64
MAX_LITERALS = 64
MAX_MEDIA = 32
ADAPTERS = frozenset({'openai.responses', 'openai.chat'})
BASE_CRITERIA = ('ac:media_types', 'ac:max_bytes', 'ac:non_whitespace',
                 'ac:no_forbidden_literals')
ENTRY_KEYS = frozenset({'profile_id', 'effect_class', 'requires_output',
    'routes', 'route_bounds', 'unconfirmed_after_seconds', 'use_case',
    'job_instructions', 'job_criteria', 'ac'})
AC_REQUIRED = frozenset({'media_types', 'max_bytes', 'non_whitespace',
    'forbidden_literals'})
AC_KEYS = AC_REQUIRED | frozenset({'exact_any'})
BOUND_KEYS = frozenset({'route', 'total_s', 'max_drain_s'})
ALIAS_KEYS = frozenset({'alias', 'profile_id', 'revision_digest'})
PINNED_FIELDS = ('effect_class', 'requires_output', 'routes', 'route_bounds',
                 'unconfirmed_after_seconds', 'use_case',
                 'job_instructions', 'job_criteria')
# Fields TaskProfile actually carries; absent on a typed profile = mismatch.
REQUIRED_FIELDS = frozenset({'effect_class', 'requires_output', 'routes'})
# This registry admits standard categories only; 'other' needs free text
# a UseCase cannot express here.
STANDARD_USE_CASES = CATEGORIES - {'other'}
_MISSING = object()


class ProfileRegistryInvalid(ValueError):
    """Registry wire/config refusal; fixed code, never raw content."""
    code = 'profile_registry_invalid'

    def __init__(self):
        super().__init__(self.code)


class ProfileRegistryMismatch(RuntimeError):
    """A non-terminal Run pins a revision absent from the registry."""
    code = 'profile_registry_mismatch'

    def __init__(self):
        super().__init__(self.code)


def _int(value):
    return type(value) is int


def _text(value, limit=1024):
    """Bounded nonempty text that encodes as strict UTF-8 (no surrogates)."""
    if type(value) is not str or not 0 < len(value) <= limit:
        return False
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def _ref(value):
    return (_text(value, 128) and value.isprintable() and ' ' not in value)


def _digest(value):
    return (type(value) is str and value.startswith('sha256:') and
            len(value) == 71 and
            all(ch in '0123456789abcdef' for ch in value[7:]))


def _alias(value):
    return (type(value) is str and 1 <= len(value) <= 128
            and all(0x21 <= ord(ch) <= 0x7E for ch in value))


def _sorted_unique(items):
    return items == sorted(items) and len(set(items)) == len(items)


def canonical(obj):
    """Canonical JSON bytes: sorted keys, compact, strict UTF-8, ints only."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
        allow_nan=False, separators=(',', ':')).encode('utf-8')


def revision_digest(entry):
    """Digest over the canonical JSON of the validated wire entry."""
    return 'sha256:' + hashlib.sha256(
        DIGEST_DOMAIN + canonical(entry)).hexdigest()


@dataclass(frozen=True)
class ACDeclaration:
    """Closed AC declaration data; predicates are evaluated elsewhere."""
    media_types: tuple
    max_bytes: int
    forbidden_literals: tuple
    exact_any: 'tuple | None' = None


@dataclass(frozen=True)
class RegistryEntry:
    """One immutable revision; routes and bounds are aligned and sorted."""
    profile_id: str
    revision_digest: str
    effect_class: str
    requires_output: bool
    routes: tuple                       # tuple[(model, adapter, env_ref)]
    route_bounds: tuple                 # tuple[(total_s, max_drain_s)]
    unconfirmed_after_seconds: int
    use_case: str
    job_instructions: str
    job_criteria: tuple
    ac: ACDeclaration

    def task_profile(self):
        """The pinned TaskProfile this revision binds for new Runs."""
        return c.TaskProfile(
            profile_id=self.profile_id,
            revision_digest=self.revision_digest,
            effect_class=self.effect_class,
            requires_output=self.requires_output,
            routes=self.routes)


@dataclass(frozen=True)
class RouteConfig:
    """Explicit closed non-secret host route configuration.

    Construction or static validation is never route qualification: a
    resolved config only proves shape, catalog evidence and bound headroom.
    """
    model: str
    adapter: str
    environment_ref: str
    endpoint: str                       # non-secret
    auth_ref: str                       # credential reference name only
    deadlines: Deadlines
    max_drain_s: int
    profile: RouteProtocolProfile

    def __post_init__(self):
        if (not _text(self.model) or not _text(self.adapter)
                or not _text(self.environment_ref)
                or not _text(self.endpoint) or not _ref(self.auth_ref)
                or type(self.deadlines) is not Deadlines
                or not _int(self.max_drain_s)
                or not 1 <= self.max_drain_s <= 600
                or type(self.profile) is not RouteProtocolProfile):
            raise ValueError('invalid route configuration')


def _validate_ac(ac):
    if type(ac) is not dict or not AC_REQUIRED <= set(ac) <= AC_KEYS:
        raise ProfileRegistryInvalid()
    media = ac['media_types']
    if (type(media) is not list or not 1 <= len(media) <= MAX_MEDIA
            or any(type(m) is not str or m not in c.OUTPUT_MEDIA_TYPES
                   for m in media) or not _sorted_unique(media)):
        raise ProfileRegistryInvalid()
    if not _int(ac['max_bytes']) or not 1 <= ac['max_bytes'] <= 262144:
        raise ProfileRegistryInvalid()
    if ac['non_whitespace'] is not True:
        raise ProfileRegistryInvalid()
    literals = ac['forbidden_literals']
    if (type(literals) is not list or not 1 <= len(literals) <= MAX_LITERALS
            or any(type(s) is not str or not s for s in literals)
            or not _sorted_unique(literals)
            or not {'<think>', '</think>'} <= set(literals)):
        raise ProfileRegistryInvalid()
    if 'exact_any' in ac:
        exact = ac['exact_any']
        if (type(exact) is not list or not 1 <= len(exact) <= 8
                or any(type(s) is not str for s in exact)
                or not _sorted_unique(exact)):
            raise ProfileRegistryInvalid()


def _validate_entry(entry):
    """Closed-schema wire validation; raises ProfileRegistryInvalid."""
    if type(entry) is not dict or set(entry) != ENTRY_KEYS:
        raise ProfileRegistryInvalid()
    if (not _text(entry['profile_id'])
            or entry['effect_class'] != 'pure'
            or entry['requires_output'] is not True):
        raise ProfileRegistryInvalid()
    routes = entry['routes']
    if (type(routes) is not list or not 1 <= len(routes) <= MAX_ROUTES
            or any(type(r) is not list or len(r) != 3
                   or any(not _text(part) for part in r) for r in routes)
            or routes != sorted(routes)
            or len({tuple(r) for r in routes}) != len(routes)):
        raise ProfileRegistryInvalid()
    bounds = entry['route_bounds']
    if type(bounds) is not list or len(bounds) != len(routes):
        raise ProfileRegistryInvalid()
    for bound, route in zip(bounds, routes):
        if (type(bound) is not dict or set(bound) != BOUND_KEYS
                or bound['route'] != route
                or not _int(bound['total_s']) or bound['total_s'] < 0
                or not _int(bound['max_drain_s']) or bound['max_drain_s'] < 0):
            raise ProfileRegistryInvalid()
    unconfirmed = entry['unconfirmed_after_seconds']
    if (not _int(unconfirmed)
            or unconfirmed
            < max(b['total_s'] + b['max_drain_s'] for b in bounds) + 30):
        raise ProfileRegistryInvalid()
    # The bound feeds Gateway's bound_resolver into timedelta(); a value
    # that cannot be represented there is invalid now, before any listener.
    try:
        timedelta(seconds=unconfirmed)
    except OverflowError:
        raise ProfileRegistryInvalid() from None
    if (type(entry['use_case']) is not str
            or entry['use_case'] not in STANDARD_USE_CASES
            or not _text(entry['job_instructions'])):
        raise ProfileRegistryInvalid()
    _validate_ac(entry['ac'])
    criteria = (list(BASE_CRITERIA)
                + (['ac:exact'] if 'exact_any' in entry['ac'] else []))
    if type(entry['job_criteria']) is not list or entry['job_criteria'] != criteria:
        raise ProfileRegistryInvalid()


def _route_map(routes):
    result = {}
    for config in routes:
        if type(config) is not RouteConfig:
            raise ProfileRegistryInvalid()
        key = (config.model, config.adapter, config.environment_ref)
        if key in result:
            raise ProfileRegistryInvalid()
        result[key] = config
    return result


def _has_collect_verification(catalog, use_case, model, adapter, env):
    """Exact typed Catalog evidence for the route: one real Verification
    whose model, adapter, UseCase, environment_ref and output_mode=collect
    all match. Duck-typed stand-ins are not evidence."""
    if type(catalog) is not Catalog:
        return False
    for entry in catalog.entries:
        if type(entry) is not CatalogEntry or entry.key != (model, adapter):
            continue
        for v in entry.verifications:
            if (type(v) is Verification and v.model == model
                    and v.adapter == adapter and v.use_case == use_case
                    and v.environment_ref == env
                    and v.output_mode == 'collect'):
                return True
    return False


def _check_route(route, bound, use_case, catalog, route_map):
    """Static route resolvability; never provider qualification."""
    model, adapter, env = route
    if adapter not in ADAPTERS:
        raise ProfileRegistryInvalid()
    host = route_map.get(route)
    if host is None:
        raise ProfileRegistryInvalid()
    if not _has_collect_verification(catalog, use_case, model, adapter, env):
        raise ProfileRegistryInvalid()
    if host.deadlines.total > bound[0] or host.max_drain_s > bound[1]:
        raise ProfileRegistryInvalid()
    # Every pinned route is a qualified route: an exact profile whose
    # protocol and model match and whose digest derives the pinned
    # environment_ref from the host's non-secret endpoint/auth_ref.
    profile = host.profile
    if (profile.protocol != adapter.rsplit('.', 1)[1]
            or profile.model != model
            or environment_ref(host.endpoint, host.auth_ref,
                               profile.profile_digest) != env):
        raise ProfileRegistryInvalid()


def _freeze(wire, digest, catalog, route_map):
    routes = tuple(tuple(r) for r in wire['routes'])
    bounds = tuple((b['total_s'], b['max_drain_s'])
                   for b in wire['route_bounds'])
    use_case = UseCase(category=wire['use_case'])
    for route, bound in zip(routes, bounds):
        _check_route(route, bound, use_case, catalog, route_map)
    ac = wire['ac']
    return RegistryEntry(
        profile_id=wire['profile_id'], revision_digest=digest,
        effect_class=wire['effect_class'],
        requires_output=wire['requires_output'], routes=routes,
        route_bounds=bounds,
        unconfirmed_after_seconds=wire['unconfirmed_after_seconds'],
        use_case=wire['use_case'],
        job_instructions=wire['job_instructions'],
        job_criteria=tuple(wire['job_criteria']),
        ac=ACDeclaration(
            media_types=tuple(ac['media_types']),
            max_bytes=ac['max_bytes'],
            forbidden_literals=tuple(ac['forbidden_literals']),
            exact_any=(tuple(ac['exact_any']) if 'exact_any' in ac else None)))


def _decode(document):
    if type(document) is bytes:
        blob = document
    elif type(document) is str:
        try:
            blob = document.encode('utf-8')
        except UnicodeEncodeError:
            raise ProfileRegistryInvalid() from None
    else:
        raise ProfileRegistryInvalid()
    if not blob or len(blob) > MAX_REGISTRY_BYTES:
        raise ProfileRegistryInvalid()
    try:
        return blob.decode('utf-8')
    except UnicodeDecodeError:
        raise ProfileRegistryInvalid() from None


def load_registry(document, *, catalog, routes):
    """Parse and fully validate the registry; any failure refuses startup."""
    try:
        data = strict_json(_decode(document))
    except ProfileRegistryInvalid:
        raise
    except Exception:
        raise ProfileRegistryInvalid() from None
    if (type(data) is not dict
            or set(data) != {'schema', 'entries', 'aliases'}
            or data['schema'] != REGISTRY_SCHEMA):
        raise ProfileRegistryInvalid()
    items, names = data['entries'], data['aliases']
    if (type(items) is not list or len(items) > MAX_ENTRIES
            or type(names) is not list or len(names) > MAX_ALIASES):
        raise ProfileRegistryInvalid()
    try:
        route_map = _route_map(routes)
    except ProfileRegistryInvalid:
        raise
    except Exception:
        raise ProfileRegistryInvalid() from None
    entries = {}
    for item in items:
        if (type(item) is not dict
                or set(item) != {'revision_digest', 'entry'}
                or not _digest(item['revision_digest'])):
            raise ProfileRegistryInvalid()
        wire = item['entry']
        declared = item['revision_digest']
        # Narrow wrap: surrogate strings or type slips inside validation,
        # canonicalization or freezing surface as the fixed refusal code.
        try:
            _validate_entry(wire)
            if revision_digest(wire) != declared:
                raise ProfileRegistryInvalid()
            key = (wire['profile_id'], declared)
            if key in entries:
                raise ProfileRegistryInvalid()
            entries[key] = _freeze(wire, declared, catalog, route_map)
        except ProfileRegistryInvalid:
            raise
        except Exception:
            raise ProfileRegistryInvalid() from None
    aliases = {}
    for item in names:
        if (type(item) is not dict or set(item) != ALIAS_KEYS
                or not _alias(item['alias'])
                or not _text(item['profile_id'])
                or not _digest(item['revision_digest'])
                or item['alias'] in aliases):
            raise ProfileRegistryInvalid()
        key = (item['profile_id'], item['revision_digest'])
        if key not in entries:
            raise ProfileRegistryInvalid()
        aliases[item['alias']] = key
    return ProfileRegistry(entries, aliases)


class ProfileRegistry:
    """Frozen registry; lookups never fall back and never execute code."""

    def __init__(self, entries, aliases):
        self._entries = MappingProxyType(dict(entries))
        self._aliases = MappingProxyType(dict(aliases))

    def get(self, profile_id, revision_digest):
        """The exact pinned revision entry, or None."""
        return self._entries.get((profile_id, revision_digest))

    def resolve(self, alias):
        """Alias -> pinned TaskProfile for new submissions only, or None."""
        key = self._aliases.get(alias)
        return None if key is None else self._entries[key].task_profile()

    def unconfirmed_after_seconds(self, profile_id, revision_digest):
        """Gateway bound_resolver seam; None when the revision is absent."""
        entry = self.get(profile_id, revision_digest)
        return None if entry is None else entry.unconfirmed_after_seconds

    @property
    def aliases(self):
        """Sorted alias names for /v1/models; aliases never move pinned Runs."""
        return tuple(sorted(self._aliases))


def _norm_bounds(value):
    if isinstance(value, Mapping):
        return tuple((b['total_s'], b['max_drain_s'])
                     for _route, b in sorted(value.items()))
    return tuple(tuple(b) for b in value)


def _field_equal(name, value, entry):
    if name == 'routes':
        return tuple(tuple(r) for r in value) == entry.routes
    if name == 'route_bounds':
        return _norm_bounds(value) == entry.route_bounds
    if name == 'job_criteria':
        return tuple(value) == entry.job_criteria
    return value == getattr(entry, name)


def _fields_differ(profile, entry):
    for name in PINNED_FIELDS:
        value = getattr(profile, name, _MISSING)
        if value is _MISSING:
            if name in REQUIRED_FIELDS:
                return True
            continue
        try:
            same = _field_equal(name, value, entry)
        except Exception:
            same = False
        if not same:
            return True
    return False


def check_store(registry, gateway, state):
    """Startup validation over committed gateway_work.

    gateway.all_work() verifies every enqueued row and aggregate;
    unreadable work rows or aggregates propagate as global store-integrity
    failures. Only non-terminal pinned Runs need an entry: an absent
    (profile_id, revision_digest) refuses startup with
    ProfileRegistryMismatch before any driver tick or listener. A Run
    whose pinned TaskProfile fields differ from its entry is returned in
    the immutable quarantine set without mutating the control store; the
    host applies audits and quarantine before stepping.
    """
    if type(registry) is not ProfileRegistry:
        raise ProfileRegistryInvalid()
    quarantine = set()
    for run_id in gateway.all_work():
        run = state.get_run(run_id)
        if run.state in c.TERMINAL:
            continue
        profile = run.profile
        # A non-terminal gateway_work Run without an exact pinned
        # TaskProfile is corrupt pinned metadata: per-Run quarantine,
        # never a profile=None dispatch path.
        if type(profile) is not c.TaskProfile:
            quarantine.add(run_id)
            continue
        entry = registry.get(profile.profile_id, profile.revision_digest)
        if entry is None:
            raise ProfileRegistryMismatch()
        if _fields_differ(profile, entry):
            quarantine.add(run_id)
    return frozenset(quarantine)
