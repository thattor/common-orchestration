"""co_v4/host_routes.py — qualified route construction for #190 M3.

build_routes(config) runs INSIDE the ServiceHost build seam, after
ServiceOwner.acquire: per RouteSpec it performs Phase B in the ruled
order (protected manifest read -> verify_manifest -> issue_profile ->
prefixed wire digest -> model -> auth_ref -> environment_ref ->
--api-key-file argv binding) and ONLY THEN opens the credential file —
a bad manifest never touches its secret. Suppliers dedup by canonical
credential_file; a second route reusing the file with a divergent
auth_ref refuses, never clones. One QualifiedRouteGate per
environment_ref is shared by every pooled child of that route; the
gate performs real manifest rehash, launch attestation and the /models
probe at dispatch — nothing here is Native/Provider qualification.

NativeRouteSpec declarations never touch the wire path: when any are
configured, build_routes requires both trusted Python composition
hooks (native_phase_b per spec -> exact NativeRouteConfig checked
against the declaration by _native_catalog, native_factory bound at
NATIVE_ADAPTER and never called during construction) to be callable
before any wire or Native work. The seam composes already-declared
configuration only — it establishes no measurement, availability,
qualification, auth or execution authority.

Two bounded readers, distinct contracts:
- read_protected: 0600/uid/single-link/regular/NOFOLLOW — manifest and
  registry documents only;
- read_evidence: canonical path, NOFOLLOW, uid-owned regular file, module
  bound — qualification captures; permissions are never forced past
  contract (external captures may be 0664).
"""
from dataclasses import dataclass
import os
import stat
from types import MappingProxyType
from typing import Mapping

from . import contracts as c
from .adapters.openai_chat import OpenAIChatAdapter
from .adapters.openai_responses import OpenAIResponsesAdapter
from .catalog import Catalog, CatalogEntry, UseCase, Verification
from .host_config import CredentialSupplier, HostConfig, NativeRouteSpec
from .launch_attestation import (LaunchAttestor, RouteUnqualified,
                                 make_models_probe)
from .openai_transport import (HttpSseTransport, OpenAIRoute,
                               payload_digest, strict_json)
from .profile_registry import (NATIVE_ADAPTER, NativeRouteConfig,
                               RouteConfig)
from .protocol_profile import (ProfileError, environment_ref,
                               issue_profile, verify_manifest)
from .qualified_route import QualifiedRouteGate

TEXT_WORKSPACE = 'co:text-profile'
TEXT_ROUTE_RECOMMENDATION = 1
AUTH_KIND = 'api-key'             # closed Verification kind, not auth_ref
MAX_DOC_BYTES = 1 << 20
MAX_EVIDENCE_BYTES = 8 << 20      # module constant; captures bound anyway
ADAPTERS = {'openai.responses': OpenAIResponsesAdapter,
            'openai.chat': OpenAIChatAdapter}
URL_PATHS = {'openai.responses': '/responses',
             'openai.chat': '/chat/completions'}


def _open_checked(path, protected):
    """Shared fd-guard: canonical path, NONBLOCK (no FIFO open hang),
    NOFOLLOW regular uid-owned file. protected adds 0600 + single link."""
    try:
        ok = (type(path) is str and os.path.isabs(path)
              and os.path.realpath(path) == path)
    except (OSError, ValueError):
        ok = False
    if not ok:
        raise RouteUnqualified('route_unqualified')
    flags = (os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
             | getattr(os, 'O_NOFOLLOW', 0))
    try:
        fd = os.open(path, flags)
    except OSError:
        raise RouteUnqualified('route_unqualified') from None
    try:
        try:
            info = os.fstat(fd)
        except OSError:
            raise RouteUnqualified('route_unqualified') from None
        ok = (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
              and (not protected
                   or (stat.S_IMODE(info.st_mode) == 0o600
                       and info.st_nlink == 1)))
        if not ok:
            raise RouteUnqualified('route_unqualified')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_protected(path, maximum=MAX_DOC_BYTES):
    """Bounded read of a 0600 host-owned document; no content in errors."""
    if type(maximum) is not int or not 1 <= maximum <= MAX_DOC_BYTES:
        raise RouteUnqualified('route_unqualified')
    fd = _open_checked(path, protected=True)
    try:
        with os.fdopen(fd, 'rb') as handle:
            fd = -1
            blob = handle.read(maximum + 1)
    except OSError:
        raise RouteUnqualified('route_unqualified') from None
    finally:
        if fd >= 0:
            os.close(fd)
    if len(blob) > maximum:
        raise RouteUnqualified('route_unqualified')
    return blob


def read_evidence(path):
    """Gate/probe evidence reader: bounded trusted regular file; mode is
    not forced past contract."""
    fd = _open_checked(path, protected=False)
    try:
        with os.fdopen(fd, 'rb') as handle:
            fd = -1
            blob = handle.read(MAX_EVIDENCE_BYTES + 1)
    except OSError:
        raise RouteUnqualified('route_unqualified') from None
    finally:
        if fd >= 0:
            os.close(fd)
    if len(blob) > MAX_EVIDENCE_BYTES:
        raise RouteUnqualified('route_unqualified')
    return blob


def _protected_doc(path):
    try:
        return strict_json(read_protected(path).decode('utf-8'))
    except RouteUnqualified:
        raise
    except Exception:
        raise RouteUnqualified('route_unqualified') from None


def _manifest_loader(path):
    """loader(digest) -> the parsed manifest doc INCLUDING its declared
    manifest_sha256 field (verified.manifest excludes it). The declared
    digest must equal the requested one; the gate's verify_manifest
    still recomputes every hash at qualify time."""
    def loader(digest):
        doc = _protected_doc(path)
        if (type(doc) is not dict
                or doc.get('manifest_sha256') != digest):
            raise ProfileError('manifest digest mismatch')
        verify_manifest(doc, read_evidence)
        return doc
    return loader


class UnconfiguredResponsesAdapter(OpenAIResponsesAdapter):
    """Route-table miss / wrong workspace: genuine protocol-level refusal.

    Constructed like any child; execute() returns a request-bound
    NeverStarted('route:unconfigured') with zero dispatch and zero
    transport, so the pool's release protocol frees the claim cleanly —
    never an ambiguous lease. Collector contract stays supported."""
    def execute(self, request):
        return c.OperationReply(
            request.ref, c.OperationStatus.UNSUPPORTED,
            'route unconfigured',
            never_started=c.NeverStarted(request, 'route:unconfigured'))

    def collect_output(self, ref):
        raise c.CollectionError('route unconfigured')


class UnconfiguredChatAdapter(OpenAIChatAdapter):
    """Same refusal semantics on the chat protocol identity."""
    def execute(self, request):
        return c.OperationReply(
            request.ref, c.OperationStatus.UNSUPPORTED,
            'route unconfigured',
            never_started=c.NeverStarted(request, 'route:unconfigured'))

    def collect_output(self, ref):
        raise c.CollectionError('route unconfigured')


REFUSERS = {'openai.responses': UnconfiguredResponsesAdapter,
            'openai.chat': UnconfiguredChatAdapter}


@dataclass(frozen=True)
class RouteContext:
    """One Phase-B-qualified route and its bound, non-secret resources.

    supplier/gate/loader/verify/transport are live objects shared by every
    pooled child of this route; constructing the context is not dispatch
    and not Native qualification — the gate attests before every POST."""
    model: str
    adapter: str
    endpoint: str
    auth_ref: str
    environment_ref: str
    profile: object                 # issued RouteProtocolProfile
    manifest_sha256: str
    store_param: str
    deadlines: object               # Deadlines
    max_drain_s: int
    verification: tuple             # (use_case, official, impl, meas, ac)
    supplier: CredentialSupplier
    gate: QualifiedRouteGate
    loader: object
    verify: object
    transport: object


def _key_file_bound(argv, credential_file):
    """--api-key-file exactly once, immediately followed by the path."""
    if argv.count('--api-key-file') != 1:
        return False
    index = argv.index('--api-key-file')
    return index + 1 < len(argv) and argv[index + 1] == credential_file


def _verify_factory(ctx_values):
    """Attest-or-raise host verifier: exact request/model/env/profile/auth/
    workspace binding. None on success, raise on mismatch — never a flag."""
    def verify(request, route):
        conditions = request.conditions
        if (route.request is not request
                or type(route) is not OpenAIRoute
                or route.endpoint != ctx_values['endpoint']
                or route.auth_ref != ctx_values['auth_ref']
                or route.profile != ctx_values['profile']
                or conditions.model != ctx_values['model']
                or conditions.adapter != ctx_values['adapter']
                or conditions.environment_ref
                != ctx_values['environment_ref']
                or conditions.workspace != TEXT_WORKSPACE):
            raise ValueError('route unbound')
        return None
    return verify


def _phase_b(spec, suppliers, gates):
    """Phase B for one RouteSpec; only RouteUnqualified propagates.

    The credential file opens only after manifest/issue/digest/model/
    auth/env/argv checks all pass for THIS route."""
    try:
        doc = _protected_doc(spec.manifest_file)
        verified = verify_manifest(doc, read_evidence)
        issued = issue_profile(verified, spec.profile.protocol,
            index_mode=spec.profile.index_mode,
            sequence_mode=spec.profile.sequence_mode,
            inert_fields=dict(spec.profile.inert_fields))
        manifest = verified.manifest
        if ('sha256:' + issued.profile_digest != spec.profile_digest
                or issued.model != spec.model
                or spec.auth_ref != manifest['auth']['credential_ref']
                or environment_ref(spec.endpoint, spec.auth_ref,
                                   issued.profile_digest)
                != spec.environment_ref
                or not _key_file_bound(manifest['launch']['argv'],
                                       spec.credential_file)):
            raise RouteUnqualified('route_unqualified')
    except RouteUnqualified:
        raise
    except Exception:
        raise RouteUnqualified('route_unqualified') from None
    supplier = suppliers.get(spec.credential_file)
    if supplier is None:
        try:
            supplier = CredentialSupplier(spec.credential_file,
                                          spec.auth_ref)
        except Exception:
            raise RouteUnqualified('route_unqualified') from None
        suppliers[spec.credential_file] = supplier
    elif supplier.credential_ref != spec.auth_ref:
        raise RouteUnqualified('route_unqualified')
    gate = gates.get(spec.environment_ref)
    if gate is None:
        gate = QualifiedRouteGate(
            read_evidence=read_evidence,
            probe_identity=make_models_probe(spec.endpoint, supplier,
                                             spec.model),
            launch_attested=LaunchAttestor(spec.launch_record,
                                           spec.credential_file))
        gates[spec.environment_ref] = gate
    ctx_values = {'model': spec.model, 'adapter': spec.adapter,
                  'endpoint': spec.endpoint, 'auth_ref': spec.auth_ref,
                  'environment_ref': spec.environment_ref,
                  'profile': issued}

    def transport(request, body, route, _s=supplier, _d=spec.deadlines):
        return HttpSseTransport(url=route.endpoint + URL_PATHS[spec.adapter],
                                body=body, auth_supplier=_s,
                                deadlines=_d)

    return RouteContext(
        model=spec.model, adapter=spec.adapter, endpoint=spec.endpoint,
        auth_ref=spec.auth_ref, environment_ref=spec.environment_ref,
        profile=issued, manifest_sha256=verified.manifest_sha256,
        store_param=spec.store_param, deadlines=spec.deadlines,
        max_drain_s=spec.max_drain_s, verification=spec.verification,
        supplier=supplier, gate=gate,
        loader=_manifest_loader(spec.manifest_file),
        verify=_verify_factory(ctx_values), transport=transport)


def _catalog(routes):
    """One CatalogEntry per (model, adapter) merging every configured
    (use_case, environment_ref) Verification; each verified use case gets
    recommended_for degree TEXT_ROUTE_RECOMMENDATION — ordering only."""
    if AUTH_KIND != 'api-key':
        raise RouteUnqualified('route_unqualified')
    merged = {}
    for ctx in routes:
        use = UseCase(category=ctx.verification[0])
        key = (ctx.model, ctx.adapter)
        verification = Verification(
            ctx.model, ctx.adapter, use, ctx.environment_ref,
            ctx.verification[1], ctx.verification[2],
            ctx.verification[3], ctx.verification[4],
            auth_route=AUTH_KIND, output_mode='collect')
        item = merged.get(key)
        if item is None:
            item = merged[key] = {'uses': set(), 'vs': []}
        if any(v.use_case == use
               and v.environment_ref == ctx.environment_ref
               for v in item['vs']):
            raise RouteUnqualified('route_unqualified')
        item['vs'].append(verification)
        item['uses'].add(use)
    return Catalog(tuple(
        CatalogEntry(model, adapter,
                     {use: TEXT_ROUTE_RECOMMENDATION
                      for use in merged[(model, adapter)]['uses']},
                     tuple(merged[(model, adapter)]['vs']))
        for model, adapter in merged))


def _native_catalog(specs, configs):
    """Project trusted Native declarations into an existing Catalog.

    Pure projection over already-accepted maintainer declarations, not
    evidence discovery and not live, measurement, account, tool or
    launch qualification: no filesystem, credential, wire, host or
    runtime work happens here and no authority is granted beyond the
    recorded refs."""
    if type(specs) not in (list, tuple) or type(configs) not in (list, tuple) \
            or len(specs) != len(configs):
        raise RouteUnqualified('route_unqualified')
    fields = ('model', 'adapter', 'environment_ref', 'measurement_state_dir',
              'measurement_key', 'measurement_digest', 'native_cwd', 'effort',
              'total_s', 'max_drain_s', 'max_output_bytes')
    grouped = {}
    for spec, config in zip(specs, configs):
        if type(spec) is not NativeRouteSpec or type(config) is not NativeRouteConfig:
            raise RouteUnqualified('route_unqualified')
        ver = spec.verification
        if spec.kind != 'native' or type(ver) is not tuple or len(ver) != 5 \
                or any(type(ref) is not str for ref in ver) \
                or any(type(getattr(spec, f)) is not type(getattr(config, f))
                       or getattr(spec, f) != getattr(config, f) for f in fields):
            raise RouteUnqualified('route_unqualified')
        try:
            use_case = UseCase(category=ver[0])
            verification = Verification(
                model=spec.model, adapter=spec.adapter, use_case=use_case,
                environment_ref=spec.environment_ref, official_ref=ver[1],
                implementation_ref=ver[2], measurement_ref=ver[3], ac_ref=ver[4],
                auth_route='chatgpt', output_mode='collect')
        except (TypeError, ValueError):
            raise RouteUnqualified('route_unqualified') from None
        key = (spec.model, spec.adapter)
        verifications, recommendations, scopes = grouped.setdefault(
            key, ([], {}, set()))
        scope = (use_case, spec.environment_ref)
        if scope in scopes:
            raise RouteUnqualified('route_unqualified')
        scopes.add(scope)
        verifications.append(verification)
        recommendations[use_case] = TEXT_ROUTE_RECOMMENDATION
    try:
        return Catalog(entries=tuple(
            CatalogEntry(model=key[0], adapter=key[1], recommended_for=recs,
                         verifications=tuple(vers))
            for key, (vers, recs, scopes) in grouped.items()))
    except (TypeError, ValueError):
        raise RouteUnqualified('route_unqualified') from None


def _child_factory(contexts, adapter):
    """Pooled child factory: request-bound protocol adapter only.

    Lookup is the exact (conditions.model, factory adapter,
    conditions.environment_ref) key plus the TEXT_WORKSPACE sentinel; a
    miss constructs the refusing child — never raises into an ambiguous
    lease, never opens a socket, never calls the provider."""
    refuser = REFUSERS[adapter]
    cls = ADAPTERS[adapter]

    def factory(request):
        conditions = request.conditions
        if conditions.adapter != adapter:
            return refuser()
        ctx = contexts.get((conditions.model, adapter,
                            conditions.environment_ref))
        if ctx is None or conditions.workspace != TEXT_WORKSPACE:
            return refuser()
        sequence = ('absent' if ctx.profile.sequence_mode == 'absent'
                    else 'required')
        route = OpenAIRoute(
            request=request, endpoint=ctx.endpoint, model=ctx.model,
            store_param=ctx.store_param,
            payload_sha256=payload_digest(request),
            confirmed_statuses=(), sequence=sequence,
            allow_terminal_done=False, profile=ctx.profile,
            auth_ref=ctx.auth_ref)
        return cls(verify_host=ctx.verify, transport_factory=ctx.transport,
                   route=route, max_drain=ctx.max_drain_s,
                   qualification_gate=ctx.gate,
                   manifest_loader=ctx.loader,
                   auth_supplier=ctx.supplier)

    return factory


@dataclass(frozen=True)
class RouteBundle:
    """The build seam's route layer; immutable keys and views only.

    catalog        -> Controller catalog kwarg;
    route_configs  -> load_registry(routes=...) and ProfilePlanner routes;
    contexts       -> MappingProxyType[(model, adapter, env), RouteContext]
                      for the TrustedEvidence resolver's route table;
    factories      -> MappingProxyType[adapter_id, child factory] feeding
                      one PooledAdapter per adapter id (ledger wiring lives
                      in host_runtime)."""
    catalog: Catalog
    route_configs: tuple
    contexts: Mapping
    factories: Mapping


def build_routes(config, *, native_phase_b=None, native_factory=None):
    """Phase B for every declared route; refused startup is fixed-coded.

    native_phase_b/native_factory are trusted Python composition kwargs
    only — never config fields, environment lookups or user input. When
    any exact NativeRouteSpec is declared both must be callable before
    any wire or Native Phase B work; native_phase_b(spec) is called
    once per Native spec in configured order and must return an exact
    NativeRouteConfig, which _native_catalog field-checks against the
    declaration. native_factory is bound at NATIVE_ADAPTER and never
    called during construction. Wire-only builds are unchanged."""
    if type(config) is not HostConfig:
        raise ValueError('closed host configuration required')
    keys = [(s.model, s.adapter, s.environment_ref)
            for s in config.routes]
    if len(set(keys)) != len(keys):
        raise RouteUnqualified('route_unqualified')
    if (any(type(s) is NativeRouteSpec for s in config.routes)
            and not (callable(native_phase_b)
                     and callable(native_factory))):
        raise RouteUnqualified('route_unqualified')
    suppliers, gates, contexts = {}, {}, {}
    wire_routes, sequence = [], []
    native_specs, native_configs = [], []
    for spec in config.routes:
        if type(spec) is NativeRouteSpec:
            try:
                ctx = native_phase_b(spec)
                _native_catalog((spec,), (ctx,))
            except Exception:
                raise RouteUnqualified('route_unqualified') from None
            native_specs.append(spec)
            native_configs.append(ctx)
        else:
            ctx = _phase_b(spec, suppliers, gates)
            wire_routes.append(ctx)
        sequence.append(ctx)
        contexts[(ctx.model, ctx.adapter, ctx.environment_ref)] = ctx
    configs = tuple(
        item if type(item) is NativeRouteConfig else RouteConfig(
            item.model, item.adapter, item.environment_ref, item.endpoint,
            item.auth_ref, item.deadlines, item.max_drain_s, item.profile)
        for item in sequence)
    catalog = _catalog(wire_routes)
    if native_specs:
        catalog = Catalog(
            catalog.entries
            + _native_catalog(native_specs, native_configs).entries)
    factories = {adapter: _child_factory(contexts, adapter)
                 for adapter in ADAPTERS
                 if any(s.adapter == adapter for s in config.routes)}
    if native_specs:
        factories[NATIVE_ADAPTER] = native_factory
    return RouteBundle(catalog, configs, MappingProxyType(contexts),
                       MappingProxyType(factories))
