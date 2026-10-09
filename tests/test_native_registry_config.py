import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.openai_transport import Deadlines
from co_v4.profile_registry import (
    NativeRouteConfig, ProfileRegistryInvalid, RouteConfig, _check_route,
    _route_map, canonical, load_registry, revision_digest)
from co_v4.protocol_profile import RouteProtocolProfile

DIGEST = 'sha256:' + 'ab' * 32
MODEL, ADAPTER, ENV = 'm', 'codex.app-server', 'native:' + DIGEST
UC = UseCase(category='general')


class NativeRouteConfigTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = os.path.realpath(self._tmp.name)
        self.cwd, self.state = (os.path.join(root, d)
                                for d in ('cwd', 'state'))
        self.sub = os.path.join(self.cwd, 'sub')
        for d in (self.cwd, self.state, self.sub):
            os.mkdir(d)

    def tearDown(self):
        self._tmp.cleanup()

    def kwargs(self, **over):
        args = dict(model=MODEL, adapter=ADAPTER, environment_ref=ENV,
                    measurement_state_dir=self.state, native_cwd=self.cwd,
                    measurement_key='codex/' + MODEL,
                    measurement_digest=DIGEST, effort='high', total_s=900,
                    max_drain_s=5, max_output_bytes=1024)
        args.update(over)
        return args

    def cfg(self, **over):
        return NativeRouteConfig(**self.kwargs(**over))

    def catalog(self, **ver):
        ev = dict(model=MODEL, adapter=ADAPTER, use_case=UC,
                  environment_ref=ENV, official_ref='o',
                  implementation_ref='i', measurement_ref='r', ac_ref='a',
                  output_mode='collect')
        ev.update(ver)
        return Catalog(entries=(CatalogEntry(
            model=MODEL, adapter=ADAPTER, recommended_for={},
            verifications=(Verification(**ev),)),))

    def test_shape_frozen_no_wire_fields(self):
        cfg = self.cfg()
        self.assertEqual(('model', 'adapter', 'environment_ref',
            'measurement_state_dir', 'measurement_key', 'measurement_digest',
            'native_cwd', 'effort', 'total_s', 'max_drain_s',
            'max_output_bytes'), tuple(cfg.__dataclass_fields__))
        for name in ('endpoint', 'auth_ref', 'deadlines', 'profile'):
            self.assertFalse(hasattr(cfg, name))
        self.assertRaises(AttributeError, setattr, cfg, 'model', 'x')

    def test_malformed(self):
        bad = ({'model': ''}, {'model': 'auto'}, {'model': 'x y'},
               {'model': 'x' * 257}, {'adapter': 'openai.responses'},
               {'environment_ref': 'other:' + DIGEST},
               {'measurement_key': 'codex/other'},
               {'measurement_key': 'codex:' + MODEL},
               {'measurement_digest': DIGEST.upper()},
               {'measurement_digest': DIGEST[:-1]}, {'effort': 'default'},
               {'effort': 'e' * 65}, {'effort': 5}, {'total_s': 0},
               {'total_s': 901}, {'total_s': True}, {'total_s': 1.5},
               {'max_drain_s': 0}, {'max_drain_s': 6},
               {'max_output_bytes': 0}, {'max_output_bytes': 1048577},
               {'max_output_bytes': 2.0},
               {'measurement_state_dir': self.cwd},
               {'measurement_state_dir': self.sub},
               {'measurement_state_dir': os.path.dirname(self.cwd)},
               {'measurement_state_dir': self.state + '/'},
               {'measurement_state_dir': 'relative/dir'},
               {'measurement_state_dir': self.state + '/missing'},
               {'native_cwd': self.cwd + '/.'})
        for over in bad:
            with self.subTest(**over):
                self.assertRaises(ValueError, self.cfg, **over)
        for ok in ({'total_s': 1}, {'total_s': 900}, {'max_drain_s': 1},
                   {'max_drain_s': 5}, {'max_output_bytes': 1},
                   {'max_output_bytes': 1048576}):
            self.cfg(**ok)

    def test_route_map_exact_types_and_duplicates(self):
        cfg = self.cfg()
        self.assertIs(cfg, _route_map([cfg])[(MODEL, ADAPTER, ENV)])

        class Sub(NativeRouteConfig):
            pass

        duck = SimpleNamespace(model=MODEL, adapter=ADAPTER,
                               environment_ref=ENV)
        for routes in ([Sub(**self.kwargs())], [duck], [cfg, cfg],
                       [object()]):
            self.assertRaises(ProfileRegistryInvalid, _route_map, routes)

    def test_check_route_native(self):
        route, cat = (MODEL, ADAPTER, ENV), self.catalog()
        routes = _route_map([self.cfg()])
        with mock.patch('co_v4.profile_registry.environment_ref',
                        side_effect=AssertionError('wire-only')):
            _check_route(route, (900, 5), UC, cat, routes)
        for bound in ((899, 5), (900, 4)):
            self.assertRaises(ProfileRegistryInvalid, _check_route, route,
                              bound, UC, cat, routes)
        for c in (Catalog(), self.catalog(output_mode='none'),
                  self.catalog(environment_ref='native:sha256:' + '0' * 64)):
            self.assertRaises(ProfileRegistryInvalid, _check_route, route,
                              (900, 5), UC, c, routes)
        for rmap in ({}, {route: object()}):
            self.assertRaises(ProfileRegistryInvalid, _check_route, route,
                              (900, 5), UC, cat, rmap)

    def test_wire_codex_route_still_refused(self):
        wire = RouteConfig(model=MODEL, adapter=ADAPTER, environment_ref='e',
            endpoint='https://e.test', auth_ref='a', deadlines=Deadlines(),
            max_drain_s=1, profile=RouteProtocolProfile(
                'responses', 'present', 'present', {}, MODEL, DIGEST[7:]))
        self.assertRaises(ProfileRegistryInvalid, _check_route,
                          (MODEL, ADAPTER, 'e'), (600, 5), UC,
                          self.catalog(), _route_map([wire]))

    def test_load_registry_native_roundtrip(self):
        route = [MODEL, ADAPTER, ENV]
        entry = {'profile_id': 'co-native', 'effect_class': 'pure',
                 'requires_output': True, 'routes': [route],
                 'route_bounds': [{'route': route, 'total_s': 900,
                                   'max_drain_s': 5}],
                 'unconfirmed_after_seconds': 935, 'use_case': 'general',
                 'job_instructions': 'Do the task.',
                 'job_criteria': ['ac:media_types', 'ac:max_bytes',
                                  'ac:non_whitespace',
                                  'ac:no_forbidden_literals'],
                 'ac': {'media_types': ['text/plain'], 'max_bytes': 4096,
                        'non_whitespace': True,
                        'forbidden_literals': ['</think>', '<think>']}}
        digest = revision_digest(entry)
        doc = {'schema': 'co.task-profile-registry/1',
               'entries': [{'revision_digest': digest, 'entry': entry}],
               'aliases': [{'alias': 'co-native', 'profile_id': 'co-native',
                            'revision_digest': digest}]}
        reg = load_registry(canonical(doc), catalog=self.catalog(),
                            routes=[self.cfg()])
        got = reg.get('co-native', digest)
        self.assertIsNotNone(got)
        self.assertEqual([route], [list(r) for r in got.routes])


if __name__ == '__main__':
    unittest.main()
