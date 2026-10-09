"""Phase A parser tests for the declared Native route leaf."""
import dataclasses
import os
import tempfile
import unittest
from unittest import mock

from co_v4 import host_config as hc

DIG = 'sha256:' + 'c' * 64
VERIFY = {'use_case': 'general', 'official_ref': 'r:o',
          'implementation_ref': 'r:i', 'measurement_ref': 'r:m',
          'ac_ref': 'r:a', 'output_mode': 'collect'}


class NativeRouteSpecTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = os.path.realpath(tmp.name)
        self.cwd = os.path.join(root, 'work')
        self.state = os.path.join(root, 'state')
        os.mkdir(self.cwd)
        os.mkdir(self.state)
        self.f = os.path.join(root, 'f')
        with open(self.f, 'w') as fh:
            fh.write('x')

    def route(self, **kw):
        r = {'kind': 'native', 'model': 'm1', 'adapter': 'codex.app-server',
             'environment_ref': 'native:' + DIG, 'measurement_digest': DIG,
             'measurement_state_dir': self.state,
             'measurement_key': 'codex/m1', 'native_cwd': self.cwd,
             'effort': 'high', 'total_s': 60, 'max_drain_s': 3,
             'max_output_bytes': 1024, 'verification': dict(VERIFY)}
        r.update(kw)
        return r

    def bad(self, **kw):
        self.assertRaises(hc.HostConfigInvalid, hc._native_route,
                          self.route(**kw))

    def wire(self, **kw):
        r = {'model': 'm', 'adapter': 'openai.responses',
             'endpoint': 'http://127.0.0.1:8081/v1', 'auth_ref': 'cred-a',
             'credential_file': self.f, 'manifest_file': self.f,
             'launch_record': self.f,
             'profile': {'protocol': 'responses', 'index_mode': 'present',
                         'sequence_mode': 'present', 'inert_fields': {}},
             'profile_digest': DIG,
             'environment_ref': 'env:sha256:' + 'b' * 64,
             'store_param': 'send_false',
             'deadlines': {'connect_s': 5, 'first_byte_s': 10,
                           'idle_s': 30, 'total_s': 60},
             'max_drain_s': 20, 'verification': dict(VERIFY)}
        r.update(kw)
        return r

    def test_valid(self):
        r = self.route()
        s = hc._native_route(r)
        self.assertIs(type(s), hc.NativeRouteSpec)
        self.assertEqual((s.kind, s.model, s.adapter, s.effort),
                         ('native', 'm1', 'codex.app-server', 'high'))
        self.assertEqual((s.measurement_key, s.measurement_digest),
                         ('codex/m1', DIG))
        self.assertEqual(s.environment_ref, 'native:' + DIG)
        self.assertEqual((s.native_cwd, s.measurement_state_dir),
                         (self.cwd, self.state))
        self.assertEqual((s.total_s, s.max_drain_s, s.max_output_bytes),
                         (60, 3, 1024))
        r['verification']['use_case'] = 'coding'
        self.assertEqual(s.verification,
                         ('general', 'r:o', 'r:i', 'r:m', 'r:a'))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            s.model = 'x'

    def test_exact_key_set(self):
        self.assertEqual(len(hc.NATIVE_ROUTE_KEYS), 13)
        for k in hc.NATIVE_ROUTE_KEYS:
            r = self.route()
            del r[k]
            self.assertRaises(hc.HostConfigInvalid, hc._native_route, r)
        self.bad(endpoint='http://x', auth_ref='a', extra=1)
        self.assertRaises(hc.HostConfigInvalid, hc._native_route, [])

    def test_fixed_strings_and_pins(self):
        self.bad(kind='wire')
        self.bad(adapter='openai.responses')
        for m in ('auto', 'default', 'a b', '', 'x' * 257, 'a\ud800'):
            self.bad(model=m)
        for e in ('auto', 'default', 'a b', '', 'x' * 65):
            self.bad(effort=e)
        self.bad(measurement_digest='sha256:' + 'C' * 64)
        self.bad(measurement_digest='c' * 64)
        self.bad(measurement_key='codex/other')
        self.bad(environment_ref='env:' + DIG)
        self.bad(environment_ref='native:' + 'd' * 64)

    def test_int_bounds(self):
        for k, ok, bad in (('total_s', (1, 900), (0, 901, True, 1.5, '5')),
                           ('max_drain_s', (1, 5), (0, 6, False, 2.0)),
                           ('max_output_bytes', (1, 1048576),
                            (0, 1048577, True))):
            for v in ok:
                hc._native_route(self.route(**{k: v}))
            for v in bad:
                self.bad(**{k: v})

    def test_dirs(self):
        self.bad(measurement_state_dir=self.cwd)
        inner = os.path.join(self.cwd, 'sub')
        os.mkdir(inner)
        self.bad(measurement_state_dir=inner)
        self.bad(measurement_state_dir=os.path.dirname(self.cwd))
        sib = os.path.join(os.path.dirname(self.cwd), 'work2')
        os.mkdir(sib)
        hc._native_route(self.route(measurement_state_dir=sib))
        self.bad(native_cwd='rel/dir')
        self.bad(native_cwd=os.path.join(self.cwd, 'missing'))
        self.bad(measurement_state_dir=self.f)
        link = os.path.join(os.path.dirname(self.cwd), 'ln')
        os.symlink(self.cwd, link)
        self.bad(native_cwd=link)
        with mock.patch.object(os.path, 'realpath', side_effect=OSError):
            self.bad()
        with mock.patch.object(os.path, 'commonpath', side_effect=ValueError):
            self.bad()

    def test_no_file_open_or_wire_builder(self):
        with mock.patch.object(hc, '_endpoint') as ep, \
                mock.patch.object(hc, '_profile') as pf, \
                mock.patch('os.open', side_effect=AssertionError) as op:
            hc._native_route(self.route())
        ep.assert_not_called()
        pf.assert_not_called()
        op.assert_not_called()

    def test_route_dispatch_unchanged(self):
        self.assertIs(type(hc._route(self.wire())), hc.RouteSpec)
        self.assertRaises(hc.HostConfigInvalid, hc._route,
                          self.wire(adapter='codex.app-server'))
        self.assertRaises(hc.HostConfigInvalid, hc._route, self.route())


if __name__ == '__main__':
    unittest.main()
