"""Models-probe tests for make_models_probe (#190 M3).

Bound checks of GET /v1/models against an owned loopback
ThreadingHTTPServer with a fresh per-test CredentialSupplier token.
Fixed-code failures only: assertion messages and server logs never echo
the Authorization header, token, hashes or env. No provider
qualification is claimed — this is transport/binding behavior only."""
import hashlib
import hmac
import http.server
import json
import os
import secrets
import tempfile
import threading
import unittest
import urllib.request
from unittest import mock

from co_v4.host_config import CredentialSupplier
from co_v4.launch_attestation import (MAX_PROBE_BYTES, ProbeFailed,
                                      RouteUnqualified,
                                      make_models_probe)

MODEL = 'co04-qwen3-06b'
OK = lambda: (200, json.dumps({'data': [{'id': MODEL}]}).encode(), {})


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        st = self.server.state
        st['hits'] += 1
        st['path'] = self.path
        got = self.headers.get('Authorization')
        st['auth_ok'] = (got is not None and hmac.compare_digest(
            got, 'Bearer ' + st['token']))
        code, body, extra = st['respond']()
        try:
            self.send_response(code)
            for k, v in extra.items():
                self.send_header(k, v)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass        # bounded probe read may close before flush


class ProbeTests(unittest.TestCase):
    def _server(self, respond):
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0),
                                              _Handler)
        srv.daemon_threads = True
        srv.block_on_close = False
        srv.state = {'hits': 0, 'auth_ok': False, 'path': None,
                     'token': self.token, 'respond': respond}
        t = threading.Thread(target=srv.serve_forever,
                             kwargs={'poll_interval': 0.05},
                             daemon=True)
        t.start()
        def stop(s=srv, t=t):
            s.shutdown()
            s.server_close()
            t.join(5)
            if t.is_alive():
                raise AssertionError('server thread did not stop')
        self.addCleanup(stop)
        return srv

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = os.path.realpath(tmp.name)
        self.token = secrets.token_hex(32)
        key_path = os.path.join(base, 'key')
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(self.token.encode('ascii'))
        self.supplier = CredentialSupplier(key_path, 'test:prov')
        self.server = self._server(OK)
        self.endpoint = ('http://127.0.0.1:%d/v1'
                         % self.server.server_port)

    def probe(self, **kw):
        return make_models_probe(
            kw.pop('endpoint', self.endpoint),
            kw.pop('supplier', self.supplier),
            kw.pop('model', MODEL), **kw)

    def test_positive_and_fresh_supplier_dict(self):
        a, b = self.supplier(), self.supplier()
        self.assertIsNot(a, b)
        self.assertEqual(set(a), {'Authorization'})
        probe = self.probe()
        self.assertEqual(probe(), {'model': MODEL})
        st = self.server.state
        self.assertEqual(st['hits'], 1)
        self.assertEqual(st['path'], '/v1/models')
        self.assertTrue(st['auth_ok'], 'credential header mismatch')
        self.server.state['respond'] = lambda: (200, json.dumps(
            {'data': [{'id': 'vendor-x'}, {'id': MODEL}],
             'build': 'b11429', 'commit': 'c' * 40}).encode(), {})
        self.assertEqual(probe(), {'model': MODEL, 'build': 'b11429',
                                   'commit': 'c' * 40})

    def test_proxyhandler_empty_and_no_env_reads(self):
        seen = []
        real = urllib.request.build_opener
        def spy(*handlers):
            seen.extend(handlers)
            return real(*handlers)
        with mock.patch('urllib.request.build_opener', spy):
            probe = self.probe()
        proxies = [h for h in seen
                   if isinstance(h, urllib.request.ProxyHandler)]
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0].proxies, {})
        self.assertEqual(probe(), {'model': MODEL})

    def test_redirect_never_followed(self):
        second = self._server(OK)
        self.server.state['respond'] = lambda: (
            302, b'', {'Location': 'http://127.0.0.1:%d/v1/models'
                                   % second.server_port})
        with self.assertRaises(ProbeFailed):
            self.probe()()
        self.assertEqual(second.state['hits'], 0)

    def test_status_and_size_bounds(self):
        for code in (401, 403, 404, 500):
            self.server.state['respond'] = lambda c=code: (c, b'x', {})
            with self.assertRaises(ProbeFailed):
                self.probe()()
        big = b' ' * (MAX_PROBE_BYTES + 1)
        self.server.state['respond'] = lambda: (200, big, {})
        with self.assertRaises(ProbeFailed):
            self.probe()()
        inner = json.dumps([{'id': MODEL}]).encode()
        exact = (b'{"data": '
                 + b' ' * (MAX_PROBE_BYTES - len(inner) - 10)
                 + inner + b'}')
        self.assertEqual(len(exact), MAX_PROBE_BYTES)
        self.server.state['respond'] = lambda: (200, exact, {})
        self.assertEqual(self.probe()(), {'model': MODEL})

    def test_strict_json_and_model_id(self):
        docs = [b'not json', b'{"data": NaN}',
                b'{"data": [], "data": []}',
                b'{"data": "x"}', b'{"data": [{"id": 1}]}',
                b'{"data": [{"id": "other-model"}]}',
                b'{"data": []}']
        for body in docs:
            self.server.state['respond'] = lambda b=body: (200, b, {})
            with self.subTest(body=body[:16]):
                with self.assertRaises(ProbeFailed):
                    self.probe()()
        self.server.state['respond'] = OK
        self.assertEqual(self.probe()(), {'model': MODEL})

    def test_supplier_and_request_boundary_fixed(self):
        canary = secrets.token_hex(32)
        def boom():
            raise RuntimeError('leak-' + canary)
        try:
            self.probe(supplier=boom)()
        except ProbeFailed as exc:
            self.assertEqual(exc.code, 'probe transport failed')
            self.assertFalse(canary in str(exc),
                             'fixed code leaked detail')
        else:
            self.fail('expected ProbeFailed')
        for bad in (lambda: 'Bearer x', lambda: {}, lambda: None,
                    lambda: {'Authorization': ''},
                    lambda: {'Authorization': None},
                    lambda: {'Authorization': 7},
                    lambda: {'Authorization': 'x', 'E': 'y'}):
            with self.subTest(kind=type(bad()).__name__):
                with self.assertRaises(ProbeFailed) as ctx:
                    self.probe(supplier=bad)()
                self.assertEqual(ctx.exception.code,
                                 'credential unavailable')
        probe = self.probe()
        with mock.patch('co_v4.launch_attestation.'
                        'urllib.request.Request',
                        side_effect=ValueError('leak-' + canary)):
            try:
                probe()
            except ProbeFailed as exc:
                self.assertFalse(canary in str(exc),
                                 'fixed code leaked detail')
            else:
                self.fail('expected ProbeFailed')

    def test_factory_argument_validation(self):
        for endpoint in ('https://127.0.0.1:8000/v1',
                         'http://localhost:8000/v1',
                         'http://127.0.0.1/v1',
                         'http://127.0.0.1:8000/v2',
                         'http://127.0.0.1:8000/v1?q=1',
                         'http://u:p@127.0.0.1:8000/v1', None, 7):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(RouteUnqualified):
                    self.probe(endpoint=endpoint)
        with self.assertRaises(RouteUnqualified):
            self.probe(supplier='x')
        for model in ('', None, 1):
            with self.assertRaises(RouteUnqualified):
                self.probe(model=model)
        for t in (0, -1, 61, True, False, '5', float('nan'),
                  float('inf'), None):
            with self.subTest(timeout=repr(t)[:8]):
                with self.assertRaises(RouteUnqualified):
                    self.probe(timeout_seconds=t)
        self.assertTrue(callable(self.probe(timeout_seconds=60)))


if __name__ == '__main__':
    unittest.main()
