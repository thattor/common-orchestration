import contextlib
import os
import tempfile
import unittest
from unittest import mock
import co_v4.profile_registry as profile_registry
from co_v4 import host_routes as hr
from co_v4.catalog import Catalog
from co_v4.host_config import CredentialSupplier
from co_v4.launch_attestation import RouteUnqualified
from co_v4.host_config import NativeRouteSpec
from co_v4.profile_registry import NativeRouteConfig
DIGEST = 'sha256:' + 'a' * 64
ENV = 'native:' + DIGEST
VER = ('general', 'r:o', 'r:i', 'r:m', 'r:a')

def _boom(*args, **kwargs): raise AssertionError('IO/qualification attempted during projection')

class NativeCatalogTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = os.path.realpath(tmp.name)
        self.cwd = os.path.join(root, 'cwd')
        self.state = os.path.join(root, 'state')
        os.mkdir(self.cwd)
        os.mkdir(self.state)

    def _fields(self, **kw):
        fields = dict(model='m', adapter='codex.app-server', environment_ref=ENV,
                    measurement_state_dir=self.state, measurement_key='codex/m',
                    measurement_digest=DIGEST, native_cwd=self.cwd, effort='high',
                    total_s=60, max_drain_s=1, max_output_bytes=1024)
        fields.update(kw)
        return fields

    def _config(self, **kw): return NativeRouteConfig(**self._fields(**kw))

    def _spec(self, kind='native', verification=VER, **kw): return NativeRouteSpec(kind=kind, verification=verification, **self._fields(**kw))

    def _run(self, specs, configs):
        traps = [mock.patch('builtins.open', _boom), mock.patch('os.stat', _boom),
                 mock.patch('pathlib.Path.resolve', _boom),
                 mock.patch.object(profile_registry, '_dir', _boom),
                 mock.patch.object(hr, '_phase_b', _boom),
                 mock.patch.object(hr, '_catalog', _boom),
                 mock.patch.object(CredentialSupplier, '__init__', _boom)]
        with contextlib.ExitStack() as stack:
            for trap in traps:
                stack.enter_context(trap)
            return hr._native_catalog(specs, configs)

    def test_projection(self):
        spec, config = self._spec(), self._config()
        specs, configs = [spec], [config]
        cat = self._run(specs, configs)
        self.assertIsInstance(cat, Catalog)
        self.assertIsNone(cat.lifecycle)
        self.assertEqual(self._run([], []).entries, ())
        (entry,) = cat.entries
        self.assertEqual((entry.model, entry.adapter, dict(entry.extra)),
                         ('m', 'codex.app-server', {}))
        (v,) = entry.verifications
        self.assertEqual((v.auth_route, v.output_mode, v.environment_ref),
                         ('chatgpt', 'collect', ENV))
        self.assertEqual((v.official_ref, v.implementation_ref,
                          v.measurement_ref, v.ac_ref), VER[1:])
        self.assertEqual((v.use_case.category, v.use_case.role), ('general', 'worker'))
        self.assertEqual(entry.recommended_for, {v.use_case: 1})
        self.assertIs(specs[0], spec); self.assertIs(configs[0], config)

    def test_merge_and_order(self):
        digest2 = 'sha256:' + 'b' * 64
        env2 = 'native:' + digest2
        s2 = self._spec(environment_ref=env2, measurement_digest=digest2, verification=('review',) + VER[1:])
        c2 = self._config(environment_ref=env2, measurement_digest=digest2)
        cat = self._run([self._spec(model='n', measurement_key='codex/n'), self._spec(), s2],
                        [self._config(model='n', measurement_key='codex/n'), self._config(), c2])
        merged = cat.entries[1]
        self.assertEqual([e.model for e in cat.entries], ['n', 'm'])
        self.assertEqual([v.environment_ref for v in merged.verifications], [ENV, env2])
        self.assertEqual({u.category: d for u, d in merged.recommended_for.items()},
                         {'general': 1, 'review': 1})

    def test_rejections(self):
        spec, config = self._spec(), self._config()
        sub = type('Sub', (NativeRouteSpec,), {})(kind='native', verification=VER, **self._fields())
        duck = type('Duck', (), dict(self._fields(), kind='native', verification=VER))()
        cases = [([spec], []), ('x', [config]), ([spec], [spec]), ([sub], [config]),
                 ([duck], [config]), ([self._spec(kind='wire')], [config]),
                 ([self._spec(verification=list(VER))], [config]),
                 ([self._spec(verification=VER[:4])], [config]),
                 ([self._spec(verification=('bogus',) + VER[1:])], [config]),
                 ([self._spec(effort='low')], [config]), ([self._spec(max_drain_s=True)], [config]),
                 ([spec], [self._config(max_drain_s=2)]),
                 ([spec, self._spec()], [config, self._config()])]
        for specs, configs in cases:
            with self.subTest(specs=specs), self.assertRaises(RouteUnqualified) as ctx:
                self._run(specs, configs)
            self.assertEqual(str(ctx.exception), 'route_unqualified')
