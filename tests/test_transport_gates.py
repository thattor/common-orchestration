"""Real-socket transport gate tests; loopback only, no provider/auth/network.

Every fixture binds 127.0.0.1 and serves one scripted SSE response over a
real socket. Covers the accepted gates: bounded backpressure with no drops
(including the terminal frame), resource caps as non-policy
output_limit_exceeded with discard-drain to the real terminal, and the three
stop timings where exactly one of NeverStarted or Result is recorded.
"""
import http.client
import json
import socket
import threading
import time
import unittest

from co_v4.contracts import (AttemptRef, ExecutionConditions, ExecuteRequest,
    Job, OperationStatus, ResultEvent, State, StopStatus)
from co_v4.openai_transport import (Deadlines, HttpSseTransport,
    OpenAISSEAdapter, OpenAIRoute, SseMessage, StreamCapped, StreamEnded,
    StreamFailed, StreamStarted, payload_digest, sse_object)

TERMINAL = (State.COMPLETED, State.FAILED, State.ERROR)
HEAD = (b'HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n'
        b'connection: close\r\n\r\n')


def sse(*frames):
    return b''.join(b'data: ' + json.dumps(f).encode('utf-8') + b'\n\n'
                    for f in frames)


class SseServer(threading.Thread):
    """One-shot loopback responder; counts connections, captures errors."""

    def __init__(self, respond):
        super().__init__(daemon=True, name='test-sse-server')
        self.respond = respond
        self.connections = 0
        self.request_head = self.error = None
        self._ready = threading.Event()

    def run(self):
        try:
            lsock = socket.socket()
            lsock.bind(('127.0.0.1', 0))
            lsock.listen(1)
            self._port = lsock.getsockname()[1]
            self._ready.set()
            conn, _ = lsock.accept()
            self.connections += 1
            conn.settimeout(30)
            head = b''
            while b'\r\n\r\n' not in head:
                head += conn.recv(4096)
                if not head:
                    return
            self.request_head, _, rest = head.partition(b'\r\n\r\n')
            # Consume the request body before responding: http.client sends
            # headers and body as separate segments, and closing a socket
            # with unread received bytes resets the connection, truncating
            # the response mid-stream.
            length = 0
            for line in self.request_head.split(b'\r\n'):
                if line.lower().startswith(b'content-length:'):
                    length = int(line.split(b':', 1)[1].strip())
            while len(rest) < length:
                block = conn.recv(4096)
                if not block:
                    return
                rest += block
            self.respond(conn, rest[length:])
            conn.close()
            lsock.close()
        except Exception as exc:
            self.error = exc

    def port(self):
        self._ready.wait(5)
        return self._port


class GateAdapter(OpenAISSEAdapter):
    """Test-local protocol seam: {"delta": str} frames then {"done": true}.

    Exists only so transport gates are observable through the Attempt
    settlement path without touching the real protocol modules.
    """
    ADAPTER_ID = 'test.gate'

    def _body(self, request, route):
        return json.dumps({'model': route.model,
                           'stream': True}).encode('utf-8')

    def _sse(self, attempt, event, data):
        proto = attempt.proto
        if attempt.outcome is not None:
            if data == proto.get('term_data'):
                return
            self._violate(attempt, 'activity_after_terminal')
        obj = sse_object(data)
        if obj.get('done') is True:
            attempt.parts = (''.join(proto.get('acc', [])),)
            attempt.outcome = (State.COMPLETED, None)
            attempt.terminal_seen = True
            proto['term_data'] = data
            return
        delta = obj.get('delta')
        if type(delta) is not str:
            self._violate(attempt, 'bad_frame')
        proto['n'] = proto.get('n', 0) + 1
        proto.setdefault('acc', []).append(delta)


def make(server, transport_kw=None, adapter_kw=None, deadlines=None,
         transport=None, transport_factory=None):
    """Build adapter+transport bound to a fresh server."""
    endpoint = 'http://127.0.0.1:%d/x' % server.port()
    req = ExecuteRequest(AttemptRef('run', 'job', 'att'),
        Job('run', 'job', 'goal', ('ac',), '{}'),
        ExecutionConditions('m', GateAdapter.ADAPTER_ID, '/w', 'env:x'))
    rt = OpenAIRoute(request=req, endpoint=endpoint, model='m',
        store_param='omit', payload_sha256=payload_digest(req))
    kw = {'url': endpoint, 'body': b'{}',
          'deadlines': deadlines or Deadlines(total=30, idle=10)}
    kw.update(transport_kw or {})
    transport = transport or HttpSseTransport(**kw)
    adapter = GateAdapter(verify_host=lambda *a: None, route=rt,
        transport_factory=transport_factory or (lambda r, b, t: transport),
        **(adapter_kw or {}))
    return adapter, req, transport


def pump_until_terminal(adapter, ref, limit=400):
    for _ in range(limit):
        status = adapter.status(ref)
        if status.state in TERMINAL:
            return status.state
        time.sleep(0.005)
    raise AssertionError('no terminal state')


def results(adapter, ref):
    return [e for e in adapter.events(ref) if type(e) is ResultEvent]


def feed_split(transport, payload, size):
    """Drive transport._feed with fixed-size chunks; returns emitted events.

    Worker-thread seams are set directly so _cap()/poll work without open().
    """
    transport._started = time.monotonic()
    transport._opened = True
    out = []
    for i in range(0, len(payload), size):
        out += transport._feed(payload[i:i + size])
    return out


class BackpressureGateTests(unittest.TestCase):
    def test_tiny_deltas_slow_consumer_exact_confirmed(self):
        n = 20000
        server = SseServer(lambda conn, rest: conn.sendall(
            HEAD + sse(*([{'delta': 'x'}] * n + [{'done': True}]))))
        server.start()
        adapter, req, transport = make(server)
        adapter.execute(req)
        # Slow consumer: bounded polls fill the queue so TCP backpressure
        # slows the server; nothing may be dropped.
        while adapter.status(req.ref).state not in TERMINAL:
            time.sleep(0.01)
        attempt = adapter._attempts[req.ref]
        self.assertEqual(attempt.proto['n'], n)
        self.assertEqual(attempt.parts, ('x' * n,))
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        self.assertIsNone(server.error)

    def test_terminal_delivered_when_queue_full(self):
        n = 2000
        server = SseServer(lambda conn, rest: conn.sendall(
            HEAD + sse(*([{'delta': 'x'}] * n + [{'done': True}]))))
        server.start()
        adapter, req, transport = make(server)
        adapter.execute(req)
        time.sleep(0.5)   # let the worker fill the queue and block in put
        self.assertFalse(transport._queue.empty())
        self.assertEqual(pump_until_terminal(adapter, req.ref),
                         State.COMPLETED)
        attempt = adapter._attempts[req.ref]
        self.assertEqual(attempt.proto['n'], n)     # terminal not dropped
        self.assertTrue(attempt.terminal_seen)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_consumer_stall_deadline_unconfirmed(self):
        gate = threading.Event()
        def respond(conn, rest):
            conn.sendall(HEAD + sse(*[{'delta': 'x'}] * 500))
            gate.wait(30)   # hold the stream open past the total deadline
        server = SseServer(respond)
        server.start()
        adapter, req, transport = make(server,
            deadlines=Deadlines(connect=2, first_byte=2, idle=2, total=2))
        adapter.execute(req)
        time.sleep(3)     # consumer stalls past the total deadline
        state = pump_until_terminal(adapter, req.ref)
        gate.set()
        self.assertEqual(state, State.ERROR)
        self.assertEqual(results(adapter, req.ref)[0].result.reason,
                         'transport_queue_deadline')
        # Queued frames were delivered intact before the stall; the dropped
        # terminal claim is reported, not faked.
        # The 256-slot queue held StreamStarted + 255 delta frames.
        self.assertEqual(adapter._attempts[req.ref].proto['n'], 255)
        self.assertTrue(transport.dropped_terminal)
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)


class ResourceCapGateTests(unittest.TestCase):
    def test_stream_cap_drain_terminal_confirmed(self):
        server = SseServer(lambda conn, rest: conn.sendall(
            HEAD + sse(*([{'delta': 'x' * 100}] * 20 + [{'done': True}]))))
        server.start()
        adapter, req, _ = make(server, transport_kw={'max_stream': 512})
        adapter.execute(req)
        self.assertEqual(pump_until_terminal(adapter, req.ref), State.FAILED)
        res = results(adapter, req.ref)[0].result
        self.assertEqual(res.reason, 'output_limit_exceeded')
        self.assertTrue(adapter.diagnostic(req.ref)['limited'])
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_stream_cap_drain_deadline_unconfirmed(self):
        gate = threading.Event()
        def respond(conn, rest):
            conn.sendall(HEAD + sse(*[{'delta': 'x' * 100}] * 20))
            gate.wait(10)
        server = SseServer(respond)
        server.start()
        adapter, req, _ = make(server, transport_kw={'max_stream': 512},
            deadlines=Deadlines(connect=2, first_byte=2, idle=2, total=2))
        adapter.execute(req)
        self.assertEqual(pump_until_terminal(adapter, req.ref), State.FAILED)
        gate.set()
        res = results(adapter, req.ref)[0].result
        self.assertEqual(res.reason, 'output_limit_exceeded')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_oversized_frame_discard_resync_terminal(self):
        server = SseServer(lambda conn, rest: conn.sendall(
            HEAD + sse({'delta': 'y' * 4000}, {'done': True})))
        server.start()
        adapter, req, _ = make(server, transport_kw={'max_event': 1024})
        adapter.execute(req)
        self.assertEqual(pump_until_terminal(adapter, req.ref), State.FAILED)
        res = results(adapter, req.ref)[0].result
        # Regression: no resource-cap path may emit protocol_violation.
        self.assertEqual(res.reason, 'output_limit_exceeded')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)


class StopTimingGateTests(unittest.TestCase):
    def test_stop_before_execute_returns_never_started_only(self):
        server = SseServer(lambda conn, rest: conn.sendall(
            HEAD + sse({'done': True})))
        server.start()
        box = {}
        def tf(r, b, t):
            box['adapter']._attempts[r.ref].stop_requested = True
            return box['transport']
        box['transport'] = HttpSseTransport(
            url='http://127.0.0.1:%d/x' % server.port(), body=b'{}',
            deadlines=Deadlines(total=30, idle=10))
        adapter, req, transport = make(server, transport=box['transport'],
                                       transport_factory=tf)
        box['adapter'] = adapter
        reply = adapter.execute(req)
        self.assertIsNotNone(reply.never_started)
        self.assertIn('stopped-before-connect',
                      reply.never_started.evidence_ref)
        self.assertEqual(results(adapter, req.ref), [])   # no ResultEvent
        self.assertEqual(server.connections, 0)           # zero wire effects
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_stop_after_accepted_before_connect_result_confirmed(self):
        proceed = threading.Event()
        def factory(host, port, timeout=None):
            proceed.wait(10)
            return http.client.HTTPConnection(host, port, timeout=timeout)
        server = SseServer(lambda conn, rest: conn.sendall(
            HEAD + sse({'done': True})))
        server.start()
        adapter, req, transport = make(server, adapter_kw={'max_drain': 5},
            transport_kw={'connection_factory': factory})
        reply = adapter.execute(req)
        self.assertEqual(reply.status, OperationStatus.ACCEPTED)
        threading.Timer(0.2, proceed.set).start()
        stop = adapter.stop(req.ref)
        self.assertIsNone(reply.never_started)
        self.assertEqual(stop.status, StopStatus.CONFIRMED)
        res = results(adapter, req.ref)
        self.assertEqual(len(res), 1)                     # exactly one proof
        self.assertEqual((res[0].result.status, res[0].result.reason),
                         (State.FAILED, 'stopped_before_transmit'))
        self.assertEqual(server.connections, 0)

    def test_stop_midwire_drains_real_terminal(self):
        release = threading.Event()
        def respond(conn, rest):
            conn.sendall(HEAD + sse({'delta': 'x'}))
            release.wait(10)
            conn.sendall(sse({'done': True}))
        server = SseServer(respond)
        server.start()
        adapter, req, transport = make(server, adapter_kw={'max_drain': 5})
        adapter.execute(req)
        adapter.events(req.ref)          # pump: RUNNING + first delta
        threading.Timer(0.2, release.set).start()
        stop = adapter.stop(req.ref)
        self.assertEqual(stop.status, StopStatus.CONFIRMED)
        res = results(adapter, req.ref)
        self.assertEqual(len(res), 1)
        self.assertEqual((res[0].result.status, res[0].result.reason),
                         (State.FAILED, 'stopped_midrequest'))
        self.assertEqual(server.connections, 1)

    def test_stop_midwire_forced_timeout_unconfirmed(self):
        hold = threading.Event()
        def respond(conn, rest):
            conn.sendall(HEAD + sse({'delta': 'x'}))
            hold.wait(10)
        server = SseServer(respond)
        server.start()
        adapter, req, transport = make(server, adapter_kw={'max_drain': 0.3},
            deadlines=Deadlines(total=30, idle=30))
        adapter.execute(req)
        adapter.events(req.ref)
        stop = adapter.stop(req.ref)
        hold.set()
        self.assertEqual(stop.status, StopStatus.UNCONFIRMED)
        res = results(adapter, req.ref)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].result.status, State.ERROR)
        self.assertIn(res[0].result.reason,
                      ('stop_cessation_unconfirmed', 'transport_eof'))


def gate_transport(max_event=1024):
    return HttpSseTransport(url='http://127.0.0.1:9/x', body=b'{}',
                            max_event=max_event)


class FramePhaseGateTests(unittest.TestCase):
    """A capped frame must lose only its own span: valid frames emitted
    before the overflow and any real terminal after it must survive, on
    whole-chunk and arbitrary-split delivery alike."""

    def payload(self):
        return sse({'delta': 'a'}, {'delta': 'y' * 4000}, {'done': True})

    def test_valid_frames_before_overflow_and_terminal_same_chunk(self):
        transport = gate_transport()
        events = feed_split(transport, self.payload(), 10 ** 6)
        data = [e.data for e in events if type(e) is SseMessage]
        self.assertEqual(data, [json.dumps({'delta': 'a'}),
                                json.dumps({'done': True})])
        self.assertTrue(transport._capped)
        self.assertEqual([type(o) for o in transport.poll()], [StreamCapped])

    def test_valid_frames_before_overflow_and_terminal_arbitrary_chunks(self):
        for size in (1, 7, 64):
            with self.subTest(size=size):
                transport = gate_transport()
                events = feed_split(transport, self.payload(), size)
                data = [e.data for e in events if type(e) is SseMessage]
                self.assertEqual(data, [json.dumps({'delta': 'a'}),
                                        json.dumps({'done': True})])
                self.assertTrue(transport._capped)

    def test_midframe_event_cap_resyncs_offending_frame_only(self):
        # A multi-data-line event that breaches max_event on its second
        # line: the line was consumed, so the tail must be discard-scanned
        # and only the following frame decoded.
        big = b'data: ' + b'x' * 900 + b'\ndata: ' + b'y' * 900 + b'\n\n'
        payload = sse({'delta': 'a'}) + big + sse({'done': True})
        for size in (10 ** 6, 5):
            with self.subTest(size=size):
                transport = gate_transport()
                events = feed_split(transport, payload, size)
                data = [e.data for e in events if type(e) is SseMessage]
                self.assertEqual(data, [json.dumps({'delta': 'a'}),
                                        json.dumps({'done': True})])

    def test_dispatch_cap_consumes_only_offending_frame(self):
        # An over-limit event: name fails SseMessage construction at the
        # blank line, so the frame is fully consumed and the NEXT frame
        # (the terminal) must be decoded, never swallowed by a resync.
        bad = b'event: ' + b'n' * 300 + b'\ndata: {}\n\n'
        transport = gate_transport()
        events = feed_split(transport, bad + sse({'done': True}), 10 ** 6)
        data = [e.data for e in events if type(e) is SseMessage]
        self.assertEqual(data, [json.dumps({'done': True})])
        self.assertTrue(transport._capped)

    def test_oversized_terminal_frame_never_trusted(self):
        payload = sse({'delta': 'x'}, {'done': True, 'pad': 'y' * 4000})
        transport = gate_transport()
        events = feed_split(transport, payload, 10 ** 6)
        data = [e.data for e in events if type(e) is SseMessage]
        # The oversized terminal is skipped: no minted SseMessage, no proof.
        self.assertEqual(data, [json.dumps({'delta': 'x'})])
        self.assertTrue(transport._capped)


class RouteFlagGateTests(unittest.TestCase):
    def test_route_evidence_flags_frozen(self):
        req = ExecuteRequest(AttemptRef('run', 'job', 'att'),
            Job('run', 'job', 'goal', ('ac',), '{}'),
            ExecutionConditions('m', GateAdapter.ADAPTER_ID, '/w', 'env:x'))
        kw = dict(request=req, endpoint='http://127.0.0.1:9/x', model='m',
                  store_param='omit', payload_sha256=payload_digest(req))
        rt = OpenAIRoute(**kw, sequence='absent', allow_terminal_done=True)
        self.assertEqual((rt.sequence, rt.allow_terminal_done),
                         ('absent', True))
        with self.assertRaises(ValueError):
            OpenAIRoute(**kw, sequence='bogus')
        with self.assertRaises(ValueError):
            OpenAIRoute(**kw, allow_terminal_done=1)


if __name__ == '__main__':
    unittest.main()
