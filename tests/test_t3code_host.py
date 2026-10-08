"""Local fake peer tests only: no T3 install, provider, grant or model calls."""
import base64
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import socket
import struct
import threading
import time
from types import SimpleNamespace
import unittest

from co_v4.t3code_host import T3CodeHost, T3CodeHostConfig, T3CodeTransport, SOURCE_REVISION


class Peer(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.server.auth.append((self.path, self.headers.get('Authorization')))
        body = b'{"ticket":"private-ticket"}'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.paths.append(self.path)
        key = self.headers['Sec-WebSocket-Key']
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        self.send_response(101)
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', accept)
        self.end_headers()
        self.connection.settimeout(3)
        try:
            while True:
                head = self.rfile.read(2)
                if len(head) != 2 or head[0] & 15 == 8:
                    return
                size = head[1] & 127
                if size == 126:
                    size = struct.unpack('!H', self.rfile.read(2))[0]
                elif size == 127:
                    size = struct.unpack('!Q', self.rfile.read(8))[0]
                mask = self.rfile.read(4)
                raw = self.rfile.read(size)
                data = json.loads(bytes(value ^ mask[i % 4] for i, value in enumerate(raw)))
                self.server.requests.append(data)
                output = self.server.reply(data)
                if output is None:
                    continue
                encoded = output.encode() if isinstance(output, str) else json.dumps(output).encode()
                frame = bytes([0x81, len(encoded)]) if len(encoded) < 126 else (bytes([0x81, 126]) + struct.pack('!H', len(encoded)) if len(encoded) < 65536 else bytes([0x81, 127]) + struct.pack('!Q', len(encoded)))
                self.wfile.write(frame + encoded)
                self.wfile.flush()
        except (OSError, ValueError):
            return


def request(identifier='1', tag='orchestration.launchThread', payload=None):
    return {'_tag': 'Request', 'id': identifier, 'tag': tag, 'payload': payload or {'threadId': 'thread-1'}, 'headers': []}


@unittest.skipUnless(shutil.which('node'), 'Node global WebSocket required')
class TransportTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Peer)
        self.server.auth, self.server.paths, self.server.requests = [], [], []
        self.server.reply = lambda r: {'_tag': 'Exit', 'requestId': r['id'], 'exit': {'_tag': 'Success', 'value': {'ok': True}}}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.config = T3CodeHostConfig(f'http://127.0.0.1:{self.server.server_port}', lambda: 'private-bearer', timeout_seconds=1)
        self.transport = None

    def tearDown(self):
        if self.transport:
            self.transport.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def open(self):
        self.transport = T3CodeTransport(self.config, {'threadId': 'thread-1'})
        return self.transport

    def await_frames(self, transport):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            frames = transport.poll()
            if frames:
                return frames
            if not transport.alive():
                return ()
            time.sleep(.01)
        self.fail('bridge deadline')

    def test_real_effect_wire_ticket_and_serialized_requests(self):
        transport = self.open()
        transport.send(request())
        transport.send(request('2', 'orchestration.getThreadProjection'))
        frames = list(self.await_frames(transport))
        while len(frames) < 2:
            frames.extend(self.await_frames(transport))
        self.assertEqual([f['requestId'] for f in frames], ['1', '2'])
        self.assertEqual(self.server.auth, [('/api/auth/websocket-ticket', 'Bearer private-bearer')])
        self.assertIn('orchestrationProtocol=2', self.server.paths[0])
        self.assertIn('wsTicket=private-ticket', self.server.paths[0])
        self.assertEqual(self.server.requests[0], request())
        transport.close()
        self.assertFalse(transport.alive())
        self.assertIsNotNone(transport.process.returncode)
        # The externally owned peer remains available.
        with socket.create_connection(self.server.server_address, timeout=1):
            pass

    def test_reject_mismatched_response_and_raw_failure(self):
        for reply in (
            lambda r: {'_tag': 'Exit', 'requestId': 'other', 'exit': {'_tag': 'Success', 'value': 'private-bearer'}},
            lambda r: {'_tag': 'Exit', 'requestId': r['id'], 'exit': {'_tag': 'Failure', 'cause': 'private-bearer'}},
            lambda r: '{malformed private-bearer',
        ):
            self.server.reply = reply
            transport = self.open()
            transport.send(request())
            self.assertEqual(self.await_frames(transport), ())
            self.assertFalse(transport.alive())
            transport.close()

    def test_pending_request_deadline_closes_only_helper(self):
        self.server.reply = lambda r: None
        transport = self.open()
        transport.send(request())
        self.assertEqual(self.await_frames(transport), ())
        self.assertFalse(transport.alive())

    def test_duplicate_json_keys_rejected(self):
        self.server.reply = lambda r: '{"_tag":"Exit","requestId":"1","exit":{"_tag":"Success","value":{"a":1,"a":2}}}'
        transport = self.open()
        transport.send(request())
        with self.assertRaisesRegex(ValueError, 'invalid T3 bridge output'):
            self.await_frames(transport)

    def test_large_valid_projection_drains_without_truncation(self):
        self.server.reply = lambda r: {'_tag': 'Exit', 'requestId': r['id'], 'exit': {'_tag': 'Success', 'value': 'x' * 200000}}
        transport = self.open()
        transport.send(request())
        frames = self.await_frames(transport)
        self.assertEqual(len(frames[0]['exit']['value']), 200000)
        self.assertTrue(transport.alive())

    def test_launch_and_thread_binding(self):
        transport = self.open()
        with self.assertRaises(ValueError):
            transport.send(request(payload={'threadId': 'other'}))
        transport.send(request())
        with self.assertRaises(ValueError):
            transport.send(request())
        with self.assertRaises(ValueError):
            transport.send(request('2', 'orchestration.getThreadProjection', {'threadId': 'other'}))
        with self.assertRaises(ValueError):
            transport.send(request('3', 'server.getConfig'))


class HostTests(unittest.TestCase):
    def test_owned_cessation_maps_exact_projection_and_rejects_foreign_proof(self):
        from copy import deepcopy
        from co_v4.t3code_owned import OwnedCodexBroker, OwnedCessation
        from co_v4.contracts import AttemptRef, StopStatus
        req = SimpleNamespace(ref=AttemptRef('run', 'job', 'attempt'))
        profile = SimpleNamespace(provider_instance_id='instance', model_selection=lambda: {'model': 'exact'})
        owner = object.__new__(OwnedCodexBroker)
        proof = OwnedCessation('request', 'native-thread', 'native-turn', 'owned:evidence', 0, False, True, True)
        calls = []
        def finish(request, **ids):
            calls.append(ids)
            return proof
        owner.finish = finish
        owner.verify_proof = lambda value, request: value is proof and request is req
        host = T3CodeHost(T3CodeHostConfig('http://127.0.0.1:1234', lambda: 'secret', owned_codex=owner))
        host._owned_binding = (req, profile, 'thread')
        projection = {'thread': {'id': 'thread'}, 'runs': [{'id': 'run', 'threadId': 'thread',
            'providerInstanceId': 'instance', 'modelSelection': {'model': 'exact'},
            'providerThreadId': 'provider-thread', 'activeAttemptId': 'attempt', 'rootNodeId': 'root'}],
            'providerThreads': [{'id': 'provider-thread', 'appThreadId': 'thread',
                'providerInstanceId': 'instance', 'nativeThreadRef': {'driver': 'codex',
                    'nativeId': 'native-thread', 'strength': 'strong'}}],
            'providerTurns': [{'providerThreadId': 'provider-thread', 'runAttemptId': 'attempt',
                'nodeId': 'root', 'nativeTurnRef': {'driver': 'codex',
                    'nativeId': 'native-turn', 'strength': 'strong'}}]}
        reply = host.confirm_cessation(req, profile, 'thread', 'run', projection)
        self.assertEqual(reply.status, StopStatus.CONFIRMED)
        self.assertEqual(calls, [{'native_thread_id': 'native-thread', 'native_turn_id': 'native-turn'}])
        for field in ('runAttemptId', 'providerThreadId', 'nodeId'):
            changed = deepcopy(projection)
            changed['providerTurns'][0][field] = 'other'
            self.assertIsNone(host.confirm_cessation(req, profile, 'thread', 'run', changed))
        changed = deepcopy(projection)
        changed['providerThreads'][0]['nativeThreadRef']['strength'] = 'weak'
        self.assertIsNone(host.confirm_cessation(req, profile, 'thread', 'run', changed))
        self.assertIsNone(host.confirm_cessation(req, profile, 'other', 'run', projection))
        owner.verify_proof = lambda *args: False
        self.assertIsNone(host.confirm_cessation(req, profile, 'thread', 'run', projection))

    def test_untrusted_endpoint_rejected(self):
        for endpoint in ('http://localhost:1234', 'https://127.0.0.1:1234', 'http://127.0.0.1:1234/a',
                         'http://user:password@127.0.0.1:1234', 'http://127.0.0.1:1234?token=secret', 'http://example.com:1234'):
            with self.assertRaises(ValueError):
                T3CodeHost(T3CodeHostConfig(endpoint, lambda: 'secret'))

    def test_default_refuse_and_profile_binding(self):
        host = T3CodeHost(T3CodeHostConfig('http://127.0.0.1:1234', lambda: 'secret'))
        profile = SimpleNamespace(request='request', source_revision=SOURCE_REVISION, runtime_mode='approval-required')
        with self.assertRaisesRegex(ValueError, 'verifier required'):
            host.verify_host('request', profile)
        with self.assertRaises(ValueError):
            host.open_transport('request', {'threadId': 'thread-1'})

    def test_verifier_none_is_not_trust(self):
        host = T3CodeHost(T3CodeHostConfig('http://127.0.0.1:1234', lambda: 'secret', lambda *args: None))
        profile = SimpleNamespace(request='request', source_revision=SOURCE_REVISION, runtime_mode='approval-required')
        with self.assertRaisesRegex(ValueError, 'not attested'):
            host.verify_host('request', profile)
