"""#190 M3: trusted Python Native injection seam on build_routes.

Offline composition tests only: synthetic temp dirs, recording spies and
directly constructed specs/configs — no model/process/network/auth IO,
no real Native Phase B and no fabricated qualification. Wire fixtures
reuse the same manifest/capture/credential shapes as test_host_routes.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4 import host_routes as hr
from co_v4.adapters.openai_responses import OpenAIResponsesAdapter
from co_v4.catalog import Catalog, UseCase
from co_v4.host_config import (HostConfig, NativeRouteSpec, ProfileSpec,
                               RouteSpec)
from co_v4.launch_attestation import RouteUnqualified
from co_v4.openai_transport import Deadlines
from co_v4.profile_registry import (NATIVE_ADAPTER, NativeRouteConfig,
                                    RouteConfig)
from co_v4.protocol_profile import (ASSERTIONS, canonical,
                                    environment_ref, issue_profile,
                                    verify_manifest)

COMMIT = 'd81235049384534c167caea52b85a694f6103d14'
MODEL = 'co04-qwen3-06b'
RESPONSES = 'openai.responses'
ENDPOINT, AUTH_REF = 'http://127.0.0.1:50353/v1', 'prov-key'
DIGEST = 'sha256:' + 'a' * 64
ENV = 'native:' + DIGEST
VER = ('general', 'r:o', 'r:i', 'r:m', 'r:a')
NATIVE_FIELDS = ('model', 'adapter', 'environment_ref',
                 'measurement_state_dir', 'measurement_key',
                 'measurement_digest', 'native_cwd', 'effort',
                 'total_s', 'max_drain_s', 'max_output_bytes')


def write(path, data, mode=0o600):
    path.write_bytes(
        data if type(data) is bytes else json.dumps(data).encode())
    os.chmod(path, mode)
    return path


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_dict(tmp, cred, **over):
    r_cap, c_cap, src = tmp / 'cap.sse', tmp / 'chat.sse', tmp / 'task.cpp'
    r_cap.write_bytes(b'data: r\n\n')
    c_cap.write_bytes(b'data: c\n\n')
    src.write_bytes(b'// serializer source\n')
    m = {'schema': 'co.provider-manifest/1', 'provider_build': 'b11429',
         'provider_commit': COMMIT, 'model_sha256': '9' * 64,
         'model_id': MODEL,
         'launch': {'argv': ['llama-server', '-m', '/m/m.gguf',
            '--chat-template-file', '/t/t.jinja',
            '--api-key-file', str(cred)], 'chat_template_sha256': 'a' * 64,
            'slots': 1, 'threads': 2, 'bind': '127.0.0.1:50353'},
         'auth': {'mode': 'api_key_file', 'credential_ref': AUTH_REF},
         'qualification': {'sdk_version': '3.24.0',
            'auth_results': {'missing': 401, 'wrong': 401, 'valid': 200}},
         'captures': [
            {'protocol': 'responses', 'path': str(r_cap),
             'sha256': _sha(r_cap)},
            {'protocol': 'chat', 'path': str(c_cap),
             'sha256': _sha(c_cap)}],
         'assertions': {n: {'passed': True} for n in ASSERTIONS},
         'multipart': {'kind': 'source_evidence', 'sha256': _sha(src),
                       'path': str(src), 'commit': COMMIT}}
    m.update(over)
    m['manifest_sha256'] = hashlib.sha256(canonical(
        {k: v for k, v in m.items() if k != 'manifest_sha256'})).hexdigest()
    return m


class _PhaseBSpy:
    """Recording offline stand-in for the trusted native_phase_b hook.
    Serves queued results or raises a queued error; never does IO."""
    def __init__(self, results=(), error=None):
        self.calls = []
        self._results = list(results)
        self._error = error

    def __call__(self, spec):
        self.calls.append(spec)
        if self._error is not None:
            raise self._error
        return self._results[len(self.calls) - 1]


class _FactorySpy:
    """Recording stand-in for native_factory; must never be invoked."""
    def __init__(self):
        self.calls = []

    def __call__(self, request):
        self.calls.append(request)
        return None


class NativeInjectionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(os.path.realpath(self._tmp.name))
        self.cwd = str(self.base / 'cwd')
        self.state = str(self.base / 'state')
        os.mkdir(self.cwd)
        os.mkdir(self.state)
        self._seq = 0

    def _mk(self):
        return Path(tempfile.mkdtemp(dir=str(self.base)))

    def _native_fields(self, **kw):
        fields = dict(model='m', adapter=NATIVE_ADAPTER,
                      environment_ref=ENV,
                      measurement_state_dir=self.state,
                      measurement_key='codex/m',
                      measurement_digest=DIGEST, native_cwd=self.cwd,
                      effort='high', total_s=60, max_drain_s=1,
                      max_output_bytes=1024)
        fields.update(kw)
        return fields

    def _nspec(self, **kw):
        verification = kw.pop('verification', VER)
        return NativeRouteSpec(kind='native', verification=verification,
                               **self._native_fields(**kw))

    def _nconfig(self, **kw):
        return NativeRouteConfig(**self._native_fields(**kw))

    def cred(self, tmp):
        return write(tmp / 'cred', secrets.token_hex(32).encode())

    def spec_for(self, tmp, cred, mpath, endpoint=ENDPOINT,
                 auth_ref=AUTH_REF, adapter=RESPONSES, **over):
        doc = json.loads(Path(mpath).read_text())
        protocol = adapter.rsplit('.', 1)[1]
        prof = issue_profile(verify_manifest(doc, hr.read_evidence),
                             protocol)
        launch = tmp / 'launch.json'
        if not launch.exists():
            write(launch, {})
        kw = dict(model=MODEL, adapter=adapter, endpoint=endpoint,
            auth_ref=auth_ref, credential_file=str(cred),
            manifest_file=str(mpath), launch_record=str(launch),
            profile=ProfileSpec(protocol, 'present', 'present', ()),
            profile_digest='sha256:' + prof.profile_digest,
            environment_ref=environment_ref(endpoint, auth_ref,
                                            prof.profile_digest),
            store_param='omit', deadlines=Deadlines(
                connect=5, first_byte=10, idle=30, total=60),
            max_drain_s=30,
            verification=('general', 'r:o', 'r:i', 'r:m', 'r:a'))
        kw.update(over)
        return RouteSpec(**kw)

    def config(self, tmp, routes, cred):
        return HostConfig(str(tmp), str(tmp / 'cap.db'), '127.0.0.1',
                          18000, str(cred), str(cred), 4096, 5, routes)

    def world(self, manifest_over=None, **over):
        tmp = self._mk()
        cred = self.cred(tmp)
        mpath = write(tmp / 'manifest.json',
                      manifest_dict(tmp, cred, **(manifest_over or {})))
        spec = self.spec_for(tmp, cred, mpath, **over)
        return self.config(tmp, (spec,), cred), spec, cred

    def req(self, spec, **cond):
        self._seq += 1
        kw = dict(model=MODEL, adapter=RESPONSES,
                  workspace=hr.TEXT_WORKSPACE,
                  environment_ref=spec.environment_ref)
        kw.update(cond)
        ref = c.AttemptRef('run', 'job', 'att-%d' % self._seq)
        return c.ExecuteRequest(ref, c.Job(
            'run', 'job', 'goal', ('ac',), '{}', True),
            c.ExecutionConditions(**kw))

    def test_wire_only_hooks_never_called_and_children_unchanged(self):
        """Wire-only config: the default path is unchanged, the Native
        hooks are never invoked and no codex.app-server factory exists."""
        cfg, spec, _ = self.world()
        phase_b = _PhaseBSpy(results=[self._nconfig()])
        factory = _FactorySpy()
        bundle = hr.build_routes(cfg, native_phase_b=phase_b,
                                 native_factory=factory)
        self.assertEqual(phase_b.calls, [])
        self.assertEqual(factory.calls, [])
        self.assertEqual(set(bundle.factories), {RESPONSES})
        (rc,) = bundle.route_configs
        self.assertIs(type(rc), RouteConfig)
        ctx = bundle.contexts[(MODEL, RESPONSES, spec.environment_ref)]
        child = bundle.factories[RESPONSES](self.req(spec))
        self.assertIs(type(child), OpenAIResponsesAdapter)
        self.assertIs(child._gate, ctx.gate)
        self.assertIs(child._auth_supplier, ctx.supplier)
        self.assertIs(child._route.profile, ctx.profile)
        self.assertEqual(child._route.confirmed_statuses, ())

    def test_hooks_must_be_callable_before_any_work(self):
        """A declared Native route with missing or noncallable hooks is
        refused with the fixed code before any wire Phase B IO or
        credential open."""
        tmp = self._mk()
        cred = self.cred(tmp)
        mpath = write(tmp / 'manifest.json', manifest_dict(tmp, cred))
        wire = self.spec_for(tmp, cred, mpath)
        cfg = self.config(tmp, (wire, self._nspec()), cred)
        cases = ({},
                 {'native_factory': _FactorySpy()},
                 {'native_phase_b': _PhaseBSpy()},
                 {'native_phase_b': None, 'native_factory': _FactorySpy()},
                 {'native_phase_b': object(),
                  'native_factory': _FactorySpy()},
                 {'native_phase_b': _PhaseBSpy(), 'native_factory': None},
                 {'native_phase_b': _PhaseBSpy(), 'native_factory': 17})
        for kwargs in cases:
            with self.subTest(kwargs=sorted(kwargs)):
                with patch.object(hr, '_protected_doc') as doc_trap, \
                        patch.object(hr, 'CredentialSupplier') as cred_trap:
                    with self.assertRaises(RouteUnqualified) as ctx:
                        hr.build_routes(cfg, **kwargs)
                self.assertEqual(str(ctx.exception), 'route_unqualified')
                doc_trap.assert_not_called()
                cred_trap.assert_not_called()

    def test_native_only_bundle_order_and_identity(self):
        """Two Native specs: hook called once each in configured order,
        contexts and route_configs hold the exact returned configs,
        Catalog has only Native entries and the factory is bound
        uncalled under codex.app-server."""
        digest2 = 'sha256:' + 'b' * 64
        env2 = 'native:' + digest2
        s1 = self._nspec()
        s2 = self._nspec(model='n', measurement_key='codex/n',
                         measurement_digest=digest2, environment_ref=env2,
                         verification=('review',) + VER[1:])
        c1 = self._nconfig()
        c2 = self._nconfig(model='n', measurement_key='codex/n',
                           measurement_digest=digest2,
                           environment_ref=env2)
        phase_b = _PhaseBSpy(results=[c1, c2])
        factory = _FactorySpy()
        bundle = hr.build_routes(
            self.config(self.base, (s1, s2), self.base / 'cred'),
            native_phase_b=phase_b, native_factory=factory)
        self.assertEqual(len(phase_b.calls), 2)
        self.assertIs(phase_b.calls[0], s1)
        self.assertIs(phase_b.calls[1], s2)
        self.assertIs(bundle.contexts[('m', NATIVE_ADAPTER, ENV)], c1)
        self.assertIs(bundle.contexts[('n', NATIVE_ADAPTER, env2)], c2)
        self.assertEqual(len(bundle.route_configs), 2)
        self.assertIs(bundle.route_configs[0], c1)
        self.assertIs(bundle.route_configs[1], c2)
        self.assertIs(type(bundle.catalog), Catalog)
        self.assertEqual(
            [(e.model, e.adapter) for e in bundle.catalog.entries],
            [('m', NATIVE_ADAPTER), ('n', NATIVE_ADAPTER)])
        v = bundle.catalog.entries[0].verifications[0]
        self.assertEqual((v.auth_route, v.output_mode, v.environment_ref),
                         ('chatgpt', 'collect', ENV))
        self.assertEqual(
            bundle.catalog.entries[0].recommended_for,
            {UseCase('general'): hr.TEXT_ROUTE_RECOMMENDATION})
        self.assertIs(bundle.factories[NATIVE_ADAPTER], factory)
        self.assertEqual(tuple(bundle.factories), (NATIVE_ADAPTER,))
        self.assertEqual(factory.calls, [])

    def test_mixed_route_order_catalog_and_factories(self):
        """Wire + Native: hook runs once for the Native spec only,
        route_configs follow configured order, Catalog is wire entries
        then Native entries, and the wire child factory is unchanged."""
        tmp = self._mk()
        cred = self.cred(tmp)
        mpath = write(tmp / 'manifest.json', manifest_dict(tmp, cred))
        wire = self.spec_for(tmp, cred, mpath)
        native = self._nspec()
        ncfg = self._nconfig()
        for routes in ((wire, native), (native, wire)):
            with self.subTest(first=type(routes[0]).__name__):
                phase_b = _PhaseBSpy(results=[ncfg])
                factory = _FactorySpy()
                bundle = hr.build_routes(
                    self.config(tmp, routes, cred),
                    native_phase_b=phase_b, native_factory=factory)
                self.assertEqual(len(phase_b.calls), 1)
                self.assertIs(phase_b.calls[0], native)
                self.assertEqual(factory.calls, [])
                if routes[0] is wire:
                    self.assertIs(type(bundle.route_configs[0]),
                                  RouteConfig)
                    self.assertIs(bundle.route_configs[1], ncfg)
                else:
                    self.assertIs(bundle.route_configs[0], ncfg)
                    self.assertIs(type(bundle.route_configs[1]),
                                  RouteConfig)
                self.assertEqual(
                    [(e.model, e.adapter)
                     for e in bundle.catalog.entries],
                    [(MODEL, RESPONSES), ('m', NATIVE_ADAPTER)])
                self.assertIs(
                    bundle.contexts[('m', NATIVE_ADAPTER, ENV)], ncfg)
                self.assertIn((MODEL, RESPONSES, wire.environment_ref),
                              bundle.contexts)
                self.assertIs(bundle.factories[NATIVE_ADAPTER], factory)
                child = bundle.factories[RESPONSES](self.req(wire))
                self.assertIs(type(child), OpenAIResponsesAdapter)
                self.assertIs(child._route.request is not None, True)

    def test_wrong_return_type_and_subclass_refuse(self):
        """Anything that is not an exact NativeRouteConfig — including a
        subclass instance — is refused with the fixed code."""
        cfg = self.config(self.base, (self._nspec(),),
                          self.base / 'cred')
        subclass = type('Sub', (NativeRouteConfig,), {})
        bad_returns = (None, 'text', self._nspec(), {'model': 'm'},
                       subclass(**self._native_fields()))
        for bad in bad_returns:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(RouteUnqualified) as ctx:
                    hr.build_routes(
                        cfg,
                        native_phase_b=lambda s, _b=bad: _b,
                        native_factory=_FactorySpy())
                self.assertEqual(str(ctx.exception), 'route_unqualified')

    def test_every_shared_field_mismatch_refuses(self):
        """Each of the eleven shared fields is checked for type and
        value equality against the spec by _native_catalog."""
        spec = self._nspec()
        cfg = self.config(self.base, (spec,), self.base / 'cred')
        wrong = {
            'model': 'other-model',
            'adapter': 'openai.chat',
            'environment_ref': 'native:sha256:' + 'c' * 64,
            'measurement_state_dir': self.cwd,
            'measurement_key': 'codex/other',
            'measurement_digest': 'sha256:' + 'c' * 64,
            'native_cwd': self.state,
            'effort': 7,
            'total_s': '60',
            'max_drain_s': True,
            'max_output_bytes': 2048.0,
        }
        self.assertEqual(set(wrong), set(NATIVE_FIELDS))
        for field in NATIVE_FIELDS:
            with self.subTest(field=field):
                config = self._nconfig()
                object.__setattr__(config, field, wrong[field])
                with self.assertRaises(RouteUnqualified) as ctx:
                    hr.build_routes(
                        cfg,
                        native_phase_b=lambda s, _c=config: _c,
                        native_factory=_FactorySpy())
                self.assertEqual(str(ctx.exception), 'route_unqualified')

    def test_ordinary_hook_error_is_fixed_refusal_without_payload(self):
        """An ordinary hook exception surfaces only as the fixed code;
        no raw payload is chained or carried."""
        cfg = self.config(self.base, (self._nspec(),),
                          self.base / 'cred')
        phase_b = _PhaseBSpy(error=RuntimeError('raw payload xyzzy'))
        with self.assertRaises(RouteUnqualified) as ctx:
            hr.build_routes(cfg, native_phase_b=phase_b,
                            native_factory=_FactorySpy())
        err = ctx.exception
        self.assertEqual(str(err), 'route_unqualified')
        self.assertIsNone(err.__cause__)
        self.assertTrue(err.__suppress_context__)
        self.assertNotIn('xyzzy', str(err))
        self.assertNotIn('xyzzy', repr(err))
        self.assertEqual(len(phase_b.calls), 1)

    def test_keyboard_interrupt_and_system_exit_propagate_identical(self):
        """KeyboardInterrupt/SystemExit are never mapped: the original
        object propagates unchanged."""
        cfg = self.config(self.base, (self._nspec(),),
                          self.base / 'cred')
        for err in (KeyboardInterrupt('halt'), SystemExit(3)):
            with self.subTest(err=type(err).__name__):
                phase_b = _PhaseBSpy(error=err)
                with self.assertRaises(type(err)) as ctx:
                    hr.build_routes(cfg, native_phase_b=phase_b,
                                    native_factory=_FactorySpy())
                self.assertIs(ctx.exception, err)

    def test_wire_failure_keeps_fixed_refusal_and_call_order(self):
        """A wire Phase B refusal stays the fixed RouteUnqualified in a
        mixed config; hook invocation follows configured route order."""
        tmp = self._mk()
        cred = self.cred(tmp)
        mpath = write(tmp / 'manifest.json', manifest_dict(tmp, cred))
        wire = self.spec_for(tmp, cred, mpath)
        os.remove(mpath)                # unreadable manifest -> Phase B refuse
        native = self._nspec()
        ncfg = self._nconfig()
        phase_b = _PhaseBSpy(results=[ncfg])
        with self.assertRaises(RouteUnqualified) as ctx:
            hr.build_routes(self.config(tmp, (wire, native), cred),
                            native_phase_b=phase_b,
                            native_factory=_FactorySpy())
        self.assertEqual(str(ctx.exception), 'route_unqualified')
        self.assertEqual(phase_b.calls, [])
        phase_b = _PhaseBSpy(results=[ncfg])
        with self.assertRaises(RouteUnqualified) as ctx:
            hr.build_routes(self.config(tmp, (native, wire), cred),
                            native_phase_b=phase_b,
                            native_factory=_FactorySpy())
        self.assertEqual(str(ctx.exception), 'route_unqualified')
        self.assertEqual(len(phase_b.calls), 1)
        self.assertIs(phase_b.calls[0], native)

    def test_unhashable_identity_fields_refuse_before_contexts(self):
        """Regression: a returned config whose model, adapter or
        environment_ref is an unhashable value ([]/{}/set()) is refused
        with the fixed code inside the Native branch — before contexts
        key hashing and before the following wire spec's Phase B runs."""
        tmp = self._mk()
        cred = self.cred(tmp)
        mpath = write(tmp / 'manifest.json', manifest_dict(tmp, cred))
        wire = self.spec_for(tmp, cred, mpath)
        for field in ('model', 'adapter', 'environment_ref'):
            for bad in ([], {}, set()):
                with self.subTest(field=field, bad=type(bad).__name__):
                    native = self._nspec()
                    config = self._nconfig()
                    object.__setattr__(config, field, bad)
                    phase_b = _PhaseBSpy(results=[config])
                    factory = _FactorySpy()
                    with patch.object(hr, '_phase_b') as wire_trap:
                        with self.assertRaises(RouteUnqualified) as ctx:
                            hr.build_routes(
                                self.config(tmp, (native, wire), cred),
                                native_phase_b=phase_b,
                                native_factory=factory)
                    err = ctx.exception
                    self.assertEqual(str(err), 'route_unqualified')
                    self.assertIsNone(err.__cause__)
                    self.assertTrue(err.__suppress_context__)
                    wire_trap.assert_not_called()
                    self.assertEqual(len(phase_b.calls), 1)
                    self.assertIs(phase_b.calls[0], native)
                    self.assertEqual(factory.calls, [])


if __name__ == '__main__':
    unittest.main()
