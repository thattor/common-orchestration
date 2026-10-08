"""Loopback-only fixtures; no external provider, network or auth is contacted."""
import http.server
import threading
import time
import unittest

from co_v4.openai_transport import (Deadlines, HttpSseTransport, SseDecoder,
    SseMessage, StreamEnded, StreamFailed, StreamStarted, TransportOpenError)


def decode(chunks):
    decoder = SseDecoder()
    out = []
    for chunk in chunks:
        out.extend(decoder.feed(chunk))
    out.extend(decoder.finish())
    return out


class DecoderTests(unittest.TestCase):
    def test_unterminated_tail_byte_accounting(self):
        # Q8: the pre-termination buffer cap is byte-accurate. 300 four-byte
        # characters are 300 chars (< max_line) but 1200 bytes (> max_line):
        # must cap early as a discard-to-resync _CapHit.
        with self.assertRaises(ValueError) as ctx:
            SseDecoder(max_line=1024).feed(
                '\U00010000'.encode('utf-8') * 300)
        self.assertTrue(getattr(ctx.exception, 'discard', False))
        # Boundary: 256 four-byte chars is exactly max_line bytes — no cap.
        SseDecoder(max_line=1024).feed(
            '\U00010000'.encode('utf-8') * 256)
        # ASCII at exactly max_line bytes: no cap; over by one caps.
        SseDecoder(max_line=1024).feed(b'x' * 1024)
        with self.assertRaises(ValueError):
            SseDecoder(max_line=1024).feed(b'x' * 1025)
        # Terminated lines, split CRLF and resync behavior are unchanged and
        # pinned by the tests above.

    def test_multiline_data_comment_and_crlf(self):
        events = decode([b': keep-alive\r\n',
            b'event: response.output_text.delta\r\n',
            b'data: {"a":1}\r\n', b'data: {"b":2}\n\n', b'data: tail\r\n\r\n'])
        self.assertEqual([(e.event, e.data) for e in events],
            [('response.output_text.delta', '{"a":1}\n{"b":2}'),
             ('message', 'tail')])

    def test_fragmented_utf8_byte_by_byte(self):
        payload = 'event: t\ndata: café ☃\n\n'.encode('utf-8')
        events = decode([payload[i:i + 1] for i in range(len(payload))])
        self.assertEqual([(e.event, e.data) for e in events], [('t', 'café ☃')])

    def test_bare_cr_and_discarded_partial_event(self):
        events = decode([b'data: one\r\r', b'data: pending'])
        self.assertEqual([e.data for e in events], ['one'])

    def test_dispatch_rules_and_invalid_bytes(self):
        self.assertEqual(decode([b'event: x\n\n']), [])
        self.assertEqual(decode([b'id: 9\nretry: 5\n\n']), [])
        self.assertEqual(decode([b'data:\n\n']),
                         [SseMessage('message', '')])
        with self.assertRaises(UnicodeDecodeError):
            decode([b'\xff\xfe\n'])
        with self.assertRaises(ValueError):
            SseDecoder(max_line=1024).feed(b'x' * 3000)
        with self.assertRaises(ValueError):
            SseDecoder(max_event=1024).feed(b'data:' + b'x' * 2000 + b'\n')


class _Scenario(http.server.BaseHTTPRequestHandler):
    scenario = {}
    requests = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        type(self).requests.append({'path': self.path,
            'headers': {k.lower(): v for k, v in self.headers.items()}})
        self.rfile.read(int(self.headers.get('content-length') or 0))
        scenario = type(self).scenario
        mode = scenario.get('mode', 'ok')
        if mode == 'drop':
            self.connection.close()
            return
        if mode == 'stall':
            time.sleep(scenario.get('sleep', 5))
            self.connection.close()
            return
        self.send_response(scenario.get('status', 200))
        self.send_header('content-type', 'text/event-stream')
        self.end_headers()
        if mode == 'http_error':
            return
        for piece in scenario.get('pieces', []):
            if piece == 'sleep':
                time.sleep(scenario.get('gap', 1))
            else:
                self.wfile.write(piece)
                self.wfile.flush()


def serve(scenario):
    class Handler(_Scenario):
        pass
    Handler.scenario, Handler.requests = scenario, []
    httpd = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=httpd.serve_forever,
                     kwargs={'poll_interval': 0.05}, daemon=True).start()
    return httpd, Handler.requests


def drain(transport, limit=200):
    obs = []
    for _ in range(limit):
        obs.extend(transport.poll())
        if any(type(o) in (StreamEnded, StreamFailed) for o in obs):
            break
        time.sleep(0.01)
    return obs


class TransportTests(unittest.TestCase):
    def serve(self, scenario):
        httpd, requests = serve(scenario)
        self.addCleanup(httpd.shutdown)
        self.addCleanup(httpd.server_close)
        return httpd, requests

    def make(self, httpd, **kw):
        options = {'url': 'http://127.0.0.1:%d/v1/responses' % httpd.server_port,
                   'body': b'{"fixture":true}',
                   'deadlines': Deadlines(connect=2, first_byte=1.5,
                                          idle=0.75, total=4)}
        options.update(kw)
        return HttpSseTransport(**options)

    def test_exactly_one_request_and_event_stream(self):
        pieces = [b'event: response.created\ndata: {"id":"r1"}\n\n',
                  'data: ☃\n\n'.encode('utf-8'), b'data: [DONE]\n\n']
        httpd, requests = self.serve({'pieces': pieces})
        transport = self.make(httpd)
        transport.open()
        obs = drain(transport)
        self.assertEqual([r['path'] for r in requests], ['/v1/responses'])
        self.assertEqual(obs[0].status, 200)
        self.assertIs(type(obs[-1]), StreamEnded)
        self.assertEqual([o.data for o in obs if type(o) is SseMessage],
                         ['{"id":"r1"}', '☃', '[DONE]'])

    def test_fragmented_utf8_across_socket_chunks(self):
        payload = 'data: café ☃\n\n'.encode('utf-8')
        httpd, requests = self.serve({'pieces': [payload[:4], payload[4:7],
                                                 payload[7:]]})
        transport = self.make(httpd)
        transport.open()
        obs = drain(transport)
        self.assertEqual([o.data for o in obs if type(o) is SseMessage],
                         ['café ☃'])

    def test_http_500_transmits_exactly_once(self):
        httpd, requests = self.serve({'status': 500, 'mode': 'http_error'})
        transport = self.make(httpd)
        transport.open()
        obs = drain(transport)
        self.assertEqual(len(requests), 1)
        failure = next(o for o in obs if type(o) is StreamFailed)
        self.assertEqual((obs[0].status, failure.category, failure.sent_state),
                         (500, 'http_status', 'sent'))

    def test_midstream_idle_timeout_never_retries(self):
        httpd, requests = self.serve({'pieces': [b'data: x\n\n', 'sleep'],
                                      'gap': 2})
        transport = self.make(httpd)
        transport.open()
        obs = drain(transport)
        self.assertEqual(len(requests), 1)
        self.assertEqual((obs[-1].category, obs[-1].sent_state),
                         ('idle_timeout', 'sent'))

    def test_first_byte_deadline_and_provable_not_sent(self):
        httpd, requests = self.serve({'mode': 'stall', 'sleep': 3})
        transport = self.make(httpd)
        transport.open()
        obs = drain(transport)
        self.assertEqual(obs[-1].category, 'first_byte_timeout')
        self.assertEqual(len(requests), 1)
        refused = self.make(httpd, url='http://127.0.0.1:1/none')
        refused.open()
        failure = drain(refused)[-1]
        # Connect failure is asynchronous on the worker: the proof rides the
        # StreamFailed observation, never an open() exception.
        self.assertIs(type(failure), StreamFailed)
        self.assertEqual((failure.category, failure.sent_state),
                         ('connect_failed', 'not_sent'))

    def test_disconnect_counts_one_request(self):
        httpd, requests = self.serve({'mode': 'drop'})
        transport = self.make(httpd)
        transport.open()
        obs = drain(transport)
        self.assertEqual(len(requests), 1)
        self.assertIs(type(obs[-1]), StreamFailed)
        self.assertIn(obs[-1].category, ('eof', 'read_failed'))

    def test_auth_supplier_injected_and_failures_not_sent(self):
        httpd, requests = self.serve({'pieces': [b'data: x\n\n']})
        calls = []
        transport = self.make(httpd, auth_supplier=(
            lambda: calls.append(1) or {'authorization': 'Bearer fixture'}))
        transport.open()
        drain(transport)
        self.assertEqual(calls, [1])
        self.assertEqual(requests[0]['headers'].get('authorization'),
                         'Bearer fixture')
        def bad():
            raise RuntimeError('PRIVATE_CANARY')
        with self.assertRaises(TransportOpenError) as ctx:
            self.make(httpd, auth_supplier=bad).open()
        self.assertEqual((ctx.exception.category, ctx.exception.sent_state),
                         ('auth_unavailable', 'not_sent'))
        for supplied in ({'x-bad\nname': 'v'}, {'x': 'v\r\ninjected'},
                         {'content-length': '1'}, {'host': 'evil'}):
            with self.subTest(supplied=supplied):
                with self.assertRaises(TransportOpenError):
                    self.make(httpd, auth_supplier=lambda: supplied).open()
        self.assertEqual(len(requests), 1)

    def test_endpoint_policy_and_no_reopen(self):
        for url in ('http://example.com/v1', 'https://user:pw@h/v1',
                    'ftp://h/', 'notaurl', 'https://h:99999/'):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    HttpSseTransport(url=url, body=b'{}')
        for url in ('https://api.example/v1/responses', 'http://127.0.0.1:9/x'):
            HttpSseTransport(url=url, body=b'{}')
        httpd, requests = self.serve({'pieces': []})
        transport = self.make(httpd)
        transport.open()
        with self.assertRaises(TransportOpenError):
            transport.open()
        drain(transport)   # worker thread must land the single POST first
        self.assertEqual(len(requests), 1)


if __name__ == '__main__':
    unittest.main()
