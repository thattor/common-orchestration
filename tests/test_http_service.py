# tests/test_http_service.py
"""#190 M3 HttpService: real loopback listener, real broker/gateway.

Real ControlStore/Gateway/OutputStore/ProfileRegistry/IngressBroker with
fresh CSPRNG tokens in an owned 0600 principals file; the OpenAI SDK is a
real client on the loopback base_url. No provider or Adapter starts:
created Runs honestly stay queued/in_progress and decisive rows come only
from the real gateway.project(). No fabricated AC/completion/NeverStarted.
"""
from hashlib import sha256
from pathlib import Path
from unittest import mock
import errno
import http.client
import json
import secrets
import socket
import tempfile
import threading
import time
import unittest

from co_v4.http_auth import IngressBroker, load_principals
import co_v4.http_service as hs
from co_v4.http_service import HttpService
from co_v4.output_store import OutputStore
from co_v4.profile_registry import (ACDeclaration, BASE_CRITERIA,
                                    ProfileRegistry, RegistryEntry)
from co_v4.responses_input import MAX_BODY_BYTES
from co_v4.service_owner import OwnerUnavailable
from co_v4.state import (ControlStore, IntegrityViolation,
                         StoreUnavailable)

try:
    import openai
    from openai import APIStatusError, OpenAI
    from openai.types.responses import Response
except ImportError:
    openai = APIStatusError = OpenAI = Response = None

NOW = '2026-10-06T00:00:00Z'
DIG = 'sha256:' + 'ab' * 32
ENTRY = RegistryEntry('co-task', DIG, 'pure', True,
    (('m', 'openai.responses', 'env:x'),), ((120, 30),), 180,
    'general', 'Produce the answer text.', BASE_CRITERIA,
    ACDeclaration(('text/plain',), 4096, ('<think>', '</think>')))
ERR = {400: ('invalid_request_error', 'invalid_request',
             'the request is not valid for this endpoint'),
       401: ('authentication_error', 'unauthorized',
             'authentication failed'),
       404: ('invalid_request_error', 'not_found',
             'the requested resource was not found'),
       405: ('invalid_request_error', 'method_not_allowed',
             'the method is not allowed'),
       409: ('invalid_request_error', 'conflict',
             'the request conflicts with committed state'),
       413: ('invalid_request_error', 'request_too_large',
             'the request body exceeds the host byte limit'),
       500: ('server_error', 'server_error',
             'the request failed an internal check'),
       503: ('server_error', 'service_unavailable',
             'the service is unavailable')}


def envelope(status):
    kind, code, message = ERR[status]
    return json.dumps({'error': {'message': message, 'type': kind,
        'param': None, 'code': code}}, separators=(',', ':'),
        ensure_ascii=False).encode('utf-8')


class HttpServiceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        self.assertIsNotNone(
            OpenAI, 'openai SDK 3.24.0 must be installed: mandatory')
        self.assertIsNotNone(Response)
        self.assertEqual(openai.__version__, '3.24.0')
        self.tokens = {'p1': secrets.token_urlsafe(24),
                       'p2': secrets.token_urlsafe(24)}
        auth_file = self.dir / 'principals.json'
        auth_file.write_text(json.dumps([
            {'principal': p,
             'token_sha256': sha256(t.encode('ascii')).hexdigest()}
            for p, t in self.tokens.items()]))
        auth_file.chmod(0o600)
        self.auth = load_principals(auth_file)
        self.broker = IngressBroker(lambda: NOW)
        self.registry = ProfileRegistry(
            {('co-task', DIG): ENTRY}, {'co-auto': ('co-task', DIG)})
        self.store = ControlStore(
            self.dir / 'control.sqlite', verifier=self.broker.verifier,
            evidence=lambda *_: None, clock=lambda: NOW,
            profile_resolver=self.registry.resolve)
        self.gateway = self.store.gateway()
        self.out = OutputStore(self.dir / 'outputs')
        self.up = True
        self.service = HttpService(
            gateway=self.gateway, broker=self.broker, auth=self.auth,
            registry=self.registry, output_store=self.out,
            available=lambda: self.up, sync_timeout=0.5)
        self.url = self.service.start()
        self.port = int(self.url.rsplit(':', 1)[1])
        self.client = OpenAI(api_key=self.tokens['p1'],
                             base_url=self.url + '/v1',
                             max_retries=0, timeout=10.0)
        self.addCleanup(self.client.close)
        self.addCleanup(self._down)

    def _down(self):
        try:
            self.service.close()
        finally:
            self.store.close()

    def http(self, method, path, body=None, token=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port,
                                          timeout=10)
        heads = {'Authorization': 'Bearer '
                 + (token or self.tokens['p1'])}
        if body is not None:
            heads['Content-Type'] = 'application/json'
            body = json.dumps(body).encode('utf-8')
        try:
            conn.request(method, path, body=body, headers=heads)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def raw(self, request, port=None):
        sock = socket.create_connection(('127.0.0.1', port or self.port),
                                        timeout=10)
        try:
            sock.sendall(request)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError as exc:
                # Truncated bodies need EOF; a peer may already have closed
                # after queuing its response. Other shutdown errors stay fatal.
                if exc.errno != errno.ENOTCONN:
                    raise
            out, need, want = b'', None, 0
            method = request.split(b' ', 1)[0]
            while need is None or len(out) < need:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                out += chunk
                if need is None:
                    end = out.find(b'\r\n\r\n')
                    if end >= 0:
                        want = self._body_length(out[:end], method)
                        need = end + 4 + want
        finally:
            sock.close()
        head, sep, blob = out.partition(b'\r\n\r\n')
        if not sep:
            raise IndexError('truncated response headers: %r' % out)
        if len(blob) < want:
            raise http.client.IncompleteRead(blob, want)
        if len(blob) > want:
            raise ValueError('response carries %d bytes beyond '
                             'Content-Length' % (len(blob) - want))
        return int(head.split(b' ')[1]), head, blob

    @staticmethod
    def _body_length(head, method):
        lengths = []
        for line in head.split(b'\r\n')[1:]:
            name, _, value = line.partition(b':')
            if name.strip().lower() != b'content-length':
                continue
            value = value.strip()
            if not value.isdigit():
                raise ValueError('malformed Content-Length: %r' % value)
            lengths.append(int(value))
        if len(set(lengths)) > 1:
            raise ValueError('conflicting Content-Length: %r' % lengths)
        if method == b'HEAD':
            return 0
        if not lengths:
            raise ValueError('response carries no Content-Length')
        return lengths[0]

    def post(self, path, headers, payload):
        blob = (payload if type(payload) is bytes
                else json.dumps(payload).encode('utf-8'))
        return ('POST %s HTTP/1.1\r\nHost: x\r\n%sContent-Length: %d\r\n\r\n'
                % (path, headers, len(blob))).encode() + blob

    def create_raw(self, body=None, key=None, token=None):
        headers = ('Authorization: Bearer %s\r\nContent-Type: '
                   'application/json\r\n' % (token or self.tokens['p1']))
        if key is not None:
            headers += 'Idempotency-Key: %s\r\n' % key
        return self.raw(self.post('/v1/responses', headers,
            body or {'model': 'co-auto', 'input': 'x',
                     'background': True}))[::2]

    def run_id(self, response_id):
        return self.store._db.execute(
            'SELECT run_id FROM gateway_responses WHERE response_id=?',
            (response_id,)).fetchone()[0]

    def test_sdk_models_create_retrieve_and_sync_poll(self):
        self.assertEqual({m.id for m in self.client.models.list().data},
                         {'co-auto'})
        created = self.client.responses.create(
            model='co-auto', input='x', background=True)
        self.assertTrue(created.id.startswith('resp_'))
        self.assertIn(self.client.responses.retrieve(created.id).status,
                      ('queued', 'in_progress'))
        # Fresh receipt per call: submit + read + >=1 poll + context.
        minted, broker = [0], self.broker.receipt_ref
        def counting(principal, body):
            minted[0] += 1
            return broker(principal, body)
        self.broker.receipt_ref = counting
        sync = self.client.responses.create(model='co-auto', input='x')
        self.broker.receipt_ref = broker
        self.assertIn(sync.status, ('queued', 'in_progress'))
        self.assertGreaterEqual(minted[0], 3)
        self.assertEqual(self.broker._pending, {})
        run = self.store.controller().get_run(self.run_id(sync.id))
        self.assertEqual(run.job_ids, ())

    def test_cancel_zero_attempts_then_real_projection(self):
        created = self.client.responses.create(
            model='co-auto', input='x', background=True)
        reply = self.client.responses.cancel(created.id)
        self.assertEqual(reply.status, 'in_progress')  # non-decisive view
        run_id = self.run_id(created.id)
        run = self.store.controller().get_run(run_id)
        self.assertTrue(run.stop_requested)
        self.assertEqual(run.job_ids, ())
        projected = self.gateway.project(run_id)
        self.assertEqual((projected.status, projected.decided),
                         ('cancelled', True))
        self.assertEqual(self.client.responses.retrieve(created.id).status,
                         'cancelled')

    def test_idempotency_replay_conflict_and_foreign_key_scope(self):
        self.assertEqual(self.create_raw(key='k1')[0], 200)
        status, body = self.create_raw(key='k1')
        self.assertEqual(status, 200)
        rid = json.loads(body)['id']
        status, body = self.create_raw(
            {'model': 'co-auto', 'input': 'y', 'background': True},
            key='k1')
        self.assertEqual((status, body), (409, envelope(409)))
        status, body = self.create_raw(key='k1', token=self.tokens['p2'])
        self.assertEqual(status, 200)
        self.assertNotEqual(json.loads(body)['id'], rid)
        self.assertEqual(self.store._db.execute(
            'SELECT COUNT(*) FROM runs').fetchone()[0], 2)

    def test_concurrent_same_key_one_run(self):
        barrier, results = threading.Event(), []
        def post():
            barrier.wait(10)
            results.append(self.create_raw(key='kc'))
        threads = [threading.Thread(target=post) for _ in range(32)]
        for t in threads:
            t.start()
        barrier.set()
        for t in threads:
            t.join(30)
        self.assertFalse(any(t.is_alive() for t in threads))
        ids = {json.loads(b)['id'] for s, b in results}
        self.assertEqual((len(results), len(ids)), (32, 1))
        self.assertEqual(self.store._db.execute(
            'SELECT COUNT(*) FROM runs').fetchone()[0], 1)
        self.assertEqual(self.store._db.execute(
            'SELECT COUNT(*) FROM gateway_keys').fetchone()[0], 1)
        self.assertEqual(self.store._db.execute(
            'SELECT COUNT(*) FROM ingress').fetchone()[0], 32)

    def test_auth_failures_and_indistinguishable_404(self):
        self.assertEqual(self.http('GET', '/v1/models')[0], 200)
        self.assertEqual(self.http('GET', '/v1/models', token='w')[::2],
                         (401, envelope(401)))
        self.assertEqual(self.raw(
            b'GET /v1/models HTTP/1.1\r\nHost: x\r\n\r\n')[0], 401)
        rid = json.loads(self.create_raw()[1])['id']
        foreign = self.http('GET', '/v1/responses/' + rid,
                            token=self.tokens['p2'])
        absent = self.http('GET', '/v1/responses/resp_absent',
                           token=self.tokens['p2'])
        self.assertEqual((foreign[0], absent[0]), (404, 404))
        self.assertEqual((foreign[2], absent[2]),
                         (envelope(404), envelope(404)))
        bad = OpenAI(api_key='w', base_url=self.url + '/v1',
                     max_retries=0)
        self.addCleanup(bad.close)
        with self.assertRaises(APIStatusError) as ei:
            bad.models.list()
        self.assertEqual(ei.exception.status_code, 401)

    def test_wire_rejects_and_head(self):
        rid = json.loads(self.create_raw()[1])['id']
        auth = 'Authorization: Bearer %s\r\n' % self.tokens['p1']
        ct = 'Content-Type: application/json\r\n'
        good = {'model': 'co-auto', 'input': 'x', 'background': True}
        base = 'POST /v1/responses HTTP/1.1\r\nHost: x\r\n' + auth + ct
        cancel = '/v1/responses/%s/cancel' % rid
        cases = (
            (self.post('/v1/responses', auth + auth + ct, good), 401),
            (self.post('/v1/responses', auth + ct +
                'Idempotency-Key: a\r\nIdempotency-Key: b\r\n', good), 400),
            (self.post('/v1/responses', auth + ct +
                'Transfer-Encoding: chunked\r\n', good), 400),
            (self.post('/v1/responses', auth + ct +
                'Content-Encoding: gzip\r\n', good), 400),
            (self.post('/v1/responses', auth + ct + ct, good), 400),
            ((base + 'Content-Length: -1\r\n\r\n').encode(), 400),
            ((base + 'Content-Length: +7\r\n\r\n').encode(), 400),
            ((base + 'Content-Length: 1_0\r\n\r\n').encode(), 400),
            ((base + 'Content-Length: ' + '9' * 5000
              + '\r\n\r\n').encode(), 413),
            ((base + 'Content-Length: %d\r\nContent-Length: %d\r\n\r\n'
              % (3, 3)).encode() + b'{"a', 400),
            ((base + 'Content-Length: 64\r\n\r\n').encode() + b'{"a":', 400),
            ((base + 'Content-Length: %d\r\n\r\n'
              % (MAX_BODY_BYTES + 1)).encode(), 413),
            (('PUT /v1/models HTTP/1.1\r\nHost: x\r\n' + auth
              + '\r\n').encode(), 405),
            (('PATCH /v1/responses HTTP/1.1\r\nHost: x\r\n' + auth
              + '\r\n').encode(), 405),
            (b'garbage line\r\n\r\n', 400),
            (self.post('/v1/responses', auth + ct,
                {'model': 'co-auto', 'input': 'x', 'stream': True}), 400),
            (self.post('/v1/responses', auth + ct,
                {'model': 'co-auto', 'input': 'x', 'bogus': 1}), 400),
            (self.post('/v1/responses', auth + ct,
                {'model': 'missing', 'input': 'x'}), 400),
            (self.post('/v1/responses', auth + ct, b'"scalar"'), 400),
            (self.post(cancel, auth + ct, 'x'.encode('utf-16')), 400),
            (self.post(cancel, auth + ct, b'{"x":1,"x":2}'), 400),
            (self.post(cancel, auth + ct, {'x': 1}), 400),
            # Duplicate Content-Type rejected even for a zero-length body;
            (self.post(cancel, auth + ct + ct, b''), 400),
        )
        for request, expected in cases:
            with self.subTest(request=request[:48]):
                status, _, blob = self.raw(request)
                self.assertEqual((status, blob),
                                 (expected, envelope(expected)))
        # A truly headerless empty cancel body is legal; the 200 payload
        # is validated by the real SDK Response model, not the error
        # envelope table.
        status, _, blob = self.raw(self.post(cancel, auth, b''))
        self.assertEqual(status, 200)
        view = Response.model_validate(json.loads(blob))
        self.assertEqual((view.id, view.status), (rid, 'in_progress'))
        # Parser failure is a real HTTP/1.1 400, not a bare HTTP/0.9 body.
        status, head, blob = self.raw(b'garbage line\r\n\r\n')
        self.assertTrue(head.startswith(b'HTTP/1.1 400'))
        self.assertEqual((status, blob), (400, envelope(400)))
        status, headers, blob = self.http('HEAD', '/v1/models')
        self.assertEqual(status, 405)
        self.assertEqual(blob, b'')
        self.assertEqual(headers.get('Content-Length'),
                         str(len(envelope(405))))

    def test_serialization_echo_and_no_internal_leaks(self):
        status, body = self.create_raw(
            {'model': 'co-auto', 'input': 'do the thing',
             'instructions': 'INST-CANARY-EXACT',
             'metadata': {'k': 'META-EXACT-7'}, 'background': True})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('instructions'), 'INST-CANARY-EXACT')
        self.assertEqual(data.get('metadata'), {'k': 'META-EXACT-7'})
        rid = data['id']
        self.assertTrue(rid.startswith('resp_'))
        text = body.decode('utf-8')
        for canary in (self.run_id(rid), 'run_', self.tokens['p1'],
                       'openai.responses', 'env:x', 'control.sqlite'):
            self.assertNotIn(canary, text)

    def test_unavailable_is_503_write_free(self):
        before = self.store._db.total_changes
        self.up = False
        for method, path in (('GET', '/v1/models'),
                             ('GET', '/v1/responses/resp_x'),
                             ('POST', '/v1/responses'),
                             ('POST', '/v1/responses/resp_x/cancel')):
            status, _, blob = self.http(method, path)
            self.assertEqual((status, blob), (503, envelope(503)))
        # A down service rejects unknown methods and HEAD as the fixed
        # 503 too (HEAD carries honest length and no body).
        auth = 'Authorization: Bearer %s\r\n' % self.tokens['p1']
        status, _, blob = self.raw(('BREW /v1/models HTTP/1.1\r\n'
            'Host: x\r\n' + auth + '\r\n').encode())
        self.assertEqual((status, blob), (503, envelope(503)))
        status, headers, blob = self.http('HEAD', '/v1/models')
        self.assertEqual((status, blob), (503, b''))
        self.assertEqual(headers.get('Content-Length'),
                         str(len(envelope(503))))
        self.assertEqual(self.store._db.total_changes, before)
        self.up = True

    def test_internal_failures_fixed_envelopes(self):
        rid = json.loads(self.create_raw()[1])['id']
        path = '/v1/responses/' + rid
        read = self.gateway.read
        try:
            for exc, expected in (
                    (IntegrityViolation('SECRET-detail'), 500),
                    (StoreUnavailable('SECRET-detail'), 503),
                    (OwnerUnavailable('SECRET-detail'), 503)):
                def boom(*a, _e=exc):
                    raise _e
                self.gateway.read = boom
                status, _, blob = self.http('GET', path)
                self.assertEqual(status, expected)
                self.assertEqual(blob, envelope(expected))
                self.assertNotIn('SECRET', blob.decode('utf-8'))
            self.assertNotEqual(status, 409)
        finally:
            self.gateway.read = read

    def test_slot_saturation_and_bounded_close(self):
        rid = json.loads(self.create_raw()[1])['id']
        gate, cond, count = threading.Event(), threading.Condition(), [0]
        read = self.service._read
        def blocking(*a):
            with cond:
                count[0] += 1
                cond.notify_all()
            gate.wait(30)
            return read(*a)
        self.service._read = blocking
        request = ('GET /v1/responses/%s HTTP/1.1\r\nHost: x\r\n'
                   'Authorization: Bearer %s\r\n\r\n'
                   % (rid, self.tokens['p1'])).encode()
        socks = []
        try:
            for _ in range(32):
                sock = socket.create_connection(
                    ('127.0.0.1', self.port), timeout=10)
                sock.sendall(request)
                socks.append(sock)
            with cond:
                self.assertTrue(
                    cond.wait_for(lambda: count[0] == 32, timeout=20))
            status, head, blob = self.raw(request)       # 33rd refused
            self.assertTrue(head.startswith(b'HTTP/1.1 503'))
            self.assertEqual((status, blob), (503, envelope(503)))
            wait, hs.STOP_WAIT = hs.STOP_WAIT, 0.2       # unit-bound patch
            try:
                self.assertEqual(self.service.close(),
                                 'host_stop_unconfirmed')
                self.assertIsNotNone(self.service._server)
            finally:
                hs.STOP_WAIT = wait
            gate.set()                                   # handlers finish
            self.assertEqual(self.service.close(), 'stopped')
            self.assertIsNone(self.service._server)
        finally:
            gate.set()
            for sock in socks:
                try:
                    sock.close()
                except OSError:
                    pass
            self.service._read = read

    def test_configured_body_cap_boundary_and_constructor(self):
        for bad in (0, -1, 262145, True, 1.0, '64', None):
            with self.assertRaises(ValueError):
                HttpService(
                    gateway=self.gateway, broker=self.broker,
                    auth=self.auth, registry=self.registry,
                    output_store=self.out, available=lambda: self.up,
                    max_body_bytes=bad)
        capped = HttpService(
            gateway=self.gateway, broker=self.broker, auth=self.auth,
            registry=self.registry, output_store=self.out,
            available=lambda: self.up, sync_timeout=0.5,
            max_body_bytes=64)
        self.addCleanup(capped.close)
        port = int(capped.start().rsplit(':', 1)[1])
        auth = ('Authorization: Bearer %s\r\nContent-Type: '
                'application/json\r\n' % self.tokens['p1'])
        body = {'model': 'co-auto', 'input': '', 'background': True}
        body['input'] = 'x' * (64 - len(json.dumps(body).encode()))
        exact = json.dumps(body).encode()
        self.assertEqual(len(exact), 64)            # one value, both seams
        status, _, _ = self.raw(
            self.post('/v1/responses', auth, exact), port)
        self.assertEqual(status, 200)               # exactly at cap accepts
        over = json.dumps(dict(body, input=body['input'] + 'x')).encode()
        self.assertEqual(len(over), 65)
        status, _, blob = self.raw(
            self.post('/v1/responses', auth, over), port)
        self.assertEqual((status, blob), (413, envelope(413)))


class RawHelperTests(unittest.TestCase):
    """raw() half-close edge cases: mock socket, no listener/SDK."""

    @staticmethod
    def _raw(sock, request=b'req'):
        with mock.patch.object(socket, 'create_connection',
                               return_value=sock):
            return HttpServiceTests.raw(mock.Mock(
                port=1, _body_length=HttpServiceTests._body_length), request)

    def test_enotconn_still_reads_queued_response(self):
        blob = envelope(503)
        response = (b'HTTP/1.1 503 Service Unavailable\r\n'
                    b'Content-Length: ' + str(len(blob)).encode('ascii')
                    + b'\r\n\r\n' + blob)
        sock = mock.Mock()
        sock.recv.side_effect = [response, b'']
        sock.shutdown.side_effect = OSError(errno.ENOTCONN,
                                            'Socket is not connected')
        status, head, body = self._raw(sock)
        self.assertTrue(head.startswith(b'HTTP/1.1 503'))
        self.assertEqual((status, body), (503, blob))
        sock.close.assert_called_once_with()

    def test_other_shutdown_oserror_propagates(self):
        sock = mock.Mock()
        sock.shutdown.side_effect = OSError(errno.EPIPE, 'Broken pipe')
        with self.assertRaises(OSError) as ctx:
            self._raw(sock)
        self.assertIs(ctx.exception, sock.shutdown.side_effect)
        self.assertEqual(ctx.exception.errno, errno.EPIPE)
        sock.close.assert_called_once_with()

    def test_enotconn_without_response_still_fails(self):
        sock = mock.Mock()
        sock.recv.return_value = b''
        sock.shutdown.side_effect = OSError(errno.ENOTCONN,
                                            'Socket is not connected')
        with self.assertRaises(IndexError):
            self._raw(sock)
        sock.close.assert_called_once_with()

    def test_complete_response_needs_no_second_recv(self):
        blob = envelope(503)
        response = (b'HTTP/1.0 503 Service Unavailable\r\n'
                    b'Content-Length: ' + str(len(blob)).encode('ascii')
                    + b'\r\n\r\n' + blob)
        sock = mock.Mock()
        sock.recv.side_effect = [response, ConnectionResetError(
            errno.ECONNRESET, 'reset after complete response')]
        status, head, body = self._raw(sock)
        self.assertTrue(head.startswith(b'HTTP/1.0 503'))
        self.assertEqual((status, body), (503, blob))
        sock.recv.assert_called_once_with(65536)
        sock.close.assert_called_once_with()

    def test_fragmented_response_assembles_one_frame(self):
        blob = envelope(409)
        response = (b'HTTP/1.1 409 Conflict\r\nContent-Length: '
                    + str(len(blob)).encode('ascii') + b'\r\n\r\n' + blob)
        cut = response.find(b'\r\n\r\n') + 2
        sock = mock.Mock()
        sock.recv.side_effect = [response[:5], response[5:cut],
                                 response[cut:], ConnectionResetError(
                                     errno.ECONNRESET, 'late reset')]
        status, _, body = self._raw(sock)
        self.assertEqual((status, body), (409, blob))
        self.assertEqual(sock.recv.call_count, 3)
        sock.close.assert_called_once_with()

    def test_reset_before_complete_frame_propagates(self):
        blob = envelope(503)
        response = (b'HTTP/1.1 503 Service Unavailable\r\n'
                    b'Content-Length: ' + str(len(blob)).encode('ascii')
                    + b'\r\n\r\n' + blob)
        sock = mock.Mock()
        sock.recv.side_effect = [response[:-3], ConnectionResetError(
            errno.ECONNRESET, 'reset mid-body')]
        with self.assertRaises(ConnectionResetError):
            self._raw(sock)
        sock.close.assert_called_once_with()

    def test_eof_before_complete_body_refused(self):
        sock = mock.Mock()
        sock.recv.side_effect = [b'HTTP/1.1 503 Service Unavailable\r\n'
                                 b'Content-Length: 90\r\n\r\n{}', b'']
        with self.assertRaises(http.client.IncompleteRead):
            self._raw(sock)
        sock.close.assert_called_once_with()

    def test_eof_inside_headers_refused(self):
        sock = mock.Mock()
        sock.recv.side_effect = [b'HTTP/1.1 503 Service Unavailable\r\n'
                                 b'Content-Leng', b'']
        with self.assertRaises(IndexError):
            self._raw(sock)
        sock.close.assert_called_once_with()

    def test_missing_content_length_refused(self):
        sock = mock.Mock()
        sock.recv.side_effect = [b'HTTP/1.1 200 OK\r\n\r\n{}', b'']
        with self.assertRaises(ValueError):
            self._raw(sock)
        sock.close.assert_called_once_with()

    def test_malformed_content_length_refused(self):
        sock = mock.Mock()
        sock.recv.return_value = (b'HTTP/1.1 200 OK\r\nContent-Length: '
                                  b'two\r\n\r\n{}')
        with self.assertRaises(ValueError):
            self._raw(sock)
        sock.close.assert_called_once_with()

    def test_conflicting_content_length_refused(self):
        sock = mock.Mock()
        sock.recv.return_value = (b'HTTP/1.1 200 OK\r\nContent-Length: 2'
                                  b'\r\nContent-Length: 5\r\n\r\n{}')
        with self.assertRaises(ValueError):
            self._raw(sock)
        sock.close.assert_called_once_with()

    def test_bytes_beyond_content_length_refused(self):
        sock = mock.Mock()
        sock.recv.return_value = (b'HTTP/1.1 200 OK\r\nContent-Length: 2'
                                  b'\r\n\r\n{}TRAILING')
        with self.assertRaises(ValueError):
            self._raw(sock)
        sock.close.assert_called_once_with()

    def test_head_response_reads_headers_only(self):
        response = (b'HTTP/1.1 405 Method Not Allowed\r\nContent-Length: '
                    + str(len(envelope(405))).encode('ascii')
                    + b'\r\n\r\n')
        sock = mock.Mock()
        sock.recv.side_effect = [response, ConnectionResetError(
            errno.ECONNRESET, 'close after headers')]
        status, _, body = self._raw(
            sock, b'HEAD /v1/models HTTP/1.1\r\nHost: x\r\n\r\n')
        self.assertEqual((status, body), (405, b''))
        sock.recv.assert_called_once_with(65536)
        sock.close.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
