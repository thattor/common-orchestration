"""Qualified-dispatch preflight tests; injected hosts only.

FakeTransport never opens a socket; the single loopback case proves the
real HttpSseTransport builds headers from the same supplier object. No
provider qualification is claimed from fixtures.
"""
import hashlib
import http.server
import threading
import time
import unittest

from co_v4.adapters.openai_responses import OpenAIResponsesAdapter
from co_v4.contracts import (AttemptRef, ExecutionConditions, ExecuteRequest,
    Job, OperationStatus, ResultEvent)
from co_v4.openai_transport import (Deadlines, HttpSseTransport, OpenAIRoute,
    payload_digest)
from co_v4.protocol_profile import (ASSERTIONS, MANIFEST_SCHEMA, ProfileError,
    canonical, environment_ref, issue_profile, verify_manifest)
from co_v4.qualified_route import QualifiedBinding, QualifiedRouteGate

BLOBS = {'/cap/responses.sse': b'data: r\n\n', '/cap/chat.sse': b'data: c\n\n',
         '/src/task.cpp': b'// serializer source\n'}
ENDPOINT, AUTH_REF = 'http://127.0.0.1:50353/v1', 'prov-key'
COMMIT = 'd81235049384534c167caea52b85a694f6103d14'


def manifest(**over):
    m = {'schema': MANIFEST_SCHEMA, 'provider_build': 'b11429',
         'provider_commit': COMMIT, 'model_sha256': '9' * 64,
         'model_id': 'co04-qwen3-06b',
         'launch': {'argv': ['llama-server', '--parallel', '1'],
                    'chat_template_sha256': 'a' * 64, 'slots': 1,
                    'threads': 2, 'bind': '127.0.0.1:50353'},
         'auth': {'mode': 'api_key_file', 'credential_ref': 'prov-key'},
         'qualification': {'sdk_version': '3.24.0',
             'auth_results': {'missing': 401, 'wrong': 401, 'valid': 200}},
         'captures': [{'protocol': 'responses', 'path': '/cap/responses.sse'},
                      {'protocol': 'chat', 'path': '/cap/chat.sse'}],
         'assertions': {name: {'passed': True} for name in ASSERTIONS},
         'multipart': {'kind': 'source_evidence',
                       'sha256': hashlib.sha256(BLOBS['/src/task.cpp'])
                       .hexdigest(), 'path': '/src/task.cpp',
                       'commit': COMMIT}}
    for cap in m['captures']:
        cap['sha256'] = hashlib.sha256(BLOBS[cap['path']]).hexdigest()
    m.update(over)
    m['manifest_sha256'] = hashlib.sha256(canonical(
        {k: v for k, v in m.items() if k != 'manifest_sha256'})).hexdigest()
    return m


def make_profile():
    return issue_profile(verify_manifest(manifest(), BLOBS.__getitem__),
        'responses', index_mode='absent_single_part', sequence_mode='absent',
        inert_fields={'response.completed': ('timings',)})


def env_for(prof, endpoint=ENDPOINT, auth_ref=AUTH_REF):
    return environment_ref(endpoint, auth_ref, prof.profile_digest)


def request(env, model='co04-qwen3-06b'):
    ref = AttemptRef('run', 'job', 'att')
    return ExecuteRequest(ref, Job('run', 'job', 'goal', ('ac',), '{}'),
        ExecutionConditions(model, 'openai.responses', '/w', env))


def gate(**kw):
    args = dict(read_evidence=BLOBS.__getitem__,
                probe_identity=lambda: {'model': 'co04-qwen3-06b'},
                launch_attested=lambda f, e, a: True)
    args.update(kw)
    return QualifiedRouteGate(**args)


def qroute(req, prof, endpoint=ENDPOINT):
    return OpenAIRoute(request=req, endpoint=endpoint, model=prof.model,
        store_param='send_false', payload_sha256=payload_digest(req),
        sequence='absent', profile=prof, auth_ref=AUTH_REF)


class Supplier:
    """Host auth supplier object: callable for headers plus the non-secret
    credential reference name — the same object given to the transport."""
    credential_ref = AUTH_REF

    def __call__(self):
        return {'authorization': 'Bearer fixture'}


class OtherRefSupplier(Supplier):
    credential_ref = 'other-ref'


class RaisingRefSupplier(Supplier):
    @property
    def credential_ref(self):
        raise RuntimeError('PRIVATE_CANARY')


class CallableRefSupplier(Supplier):
    credential_ref = staticmethod(lambda: AUTH_REF)


class FakeTransport:
    def __init__(self, auth_supplier=None, sent_state='not_sent'):
        self.auth_supplier = auth_supplier
        self.sent_state = sent_state
        self.open_calls = self.cancel_calls = 0
        self.responded = self.closed = self.done = False
        self.dropped_terminal = False
        self.deadline = 10 ** 9

    def open(self):
        self.open_calls += 1
        self.sent_state, self.responded = 'sent', True

    def cancel(self):
        self.cancel_calls += 1
        return True

    def poll(self):
        return ()

    def close(self):
        self.closed = True


class LyingCloseTransport(FakeTransport):
    """close() rewrites sent_state: the snapshot must be pre-close."""
    def close(self):
        self.closed = True
        self.sent_state = 'not_sent'


def build(req, rt, g=None, loader=None, supplier=None, transport=None):
    transport = transport if transport is not None else FakeTransport(supplier)
    adapter = OpenAIResponsesAdapter(verify_host=lambda *a: None,
        transport_factory=lambda r, b, t: transport, route=rt,
        qualification_gate=g, manifest_loader=loader,
        auth_supplier=supplier)
    return adapter, transport


def results(adapter, ref):
    return [e.result for e in adapter.events(ref)
            if type(e) is ResultEvent]


class RouteFieldTests(unittest.TestCase):
    def test_profile_requires_matching_route_fields(self):
        prof = make_profile()
        req = request(env_for(prof))
        base = dict(request=req, endpoint=ENDPOINT, model=prof.model,
            store_param='send_false', payload_sha256=payload_digest(req))
        for kw in (dict(sequence='required'),
                   dict(sequence='absent', allow_terminal_done=True),
                   dict(sequence='absent', auth_ref=None),
                   dict(sequence='absent', auth_ref=''),
                   dict(sequence='absent', profile=object())):
            with self.subTest(kw=kw):
                args = dict(profile=prof, auth_ref=AUTH_REF)
                args.update(kw)
                with self.assertRaises(ValueError):
                    OpenAIRoute(**base, **args)
        rt = OpenAIRoute(**base, sequence='absent', profile=prof,
                         auth_ref=AUTH_REF)
        self.assertIs(rt.profile, prof)
        OpenAIRoute(**base)          # generic route unchanged


class PreflightTests(unittest.TestCase):
    def test_missing_wiring_never_started_zero_io(self):
        prof = make_profile()
        req = request(env_for(prof))
        rt = qroute(req, prof)
        for g, loader, supplier in (
                (None, None, None),
                (gate(), lambda sha: manifest(), None)):
            with self.subTest(wired=g is not None):
                adapter, transport = build(req, rt, g, loader, supplier)
                reply = adapter.execute(req)
                self.assertEqual(reply.status, OperationStatus.UNSUPPORTED)
                self.assertEqual(reply.never_started.evidence_ref,
                                 'route:unqualified')
                self.assertEqual(transport.open_calls, 0)

    def test_gate_loader_pairing_and_type(self):
        req = request(env_for(make_profile()))
        rt = qroute(req, make_profile())
        for kw in (dict(qualification_gate=gate()),
                   dict(manifest_loader=lambda sha: manifest()),
                   dict(qualification_gate=object(),
                        manifest_loader=lambda sha: manifest())):
            with self.subTest(kw=kw):
                with self.assertRaises(ValueError):
                    OpenAIResponsesAdapter(route=rt, **kw)

    def test_valid_qualification_accepts_once(self):
        prof = make_profile()
        req = request(env_for(prof))
        seen = []
        adapter, transport = build(req, qroute(req, prof), gate(),
            lambda sha: seen.append(sha) or manifest(), Supplier())
        reply = adapter.execute(req)
        self.assertEqual(reply.status, OperationStatus.ACCEPTED)
        self.assertEqual(seen, [prof.provider_manifest_sha256])
        self.assertEqual(transport.open_calls, 1)      # exactly one POST
        binding = adapter._attempts[req.ref].binding
        self.assertIs(type(binding), QualifiedBinding)
        self.assertEqual(binding.profile.index_mode, 'absent_single_part')
        self.assertIs(transport.auth_supplier is not None, True)

    def test_preflight_failures_fixed_and_sticky(self):
        prof = make_profile()
        req = request(env_for(prof))
        rt = qroute(req, prof)
        for loader, supplier in (
                (lambda sha: 1 / 0, Supplier()),
                (lambda sha: manifest(), OtherRefSupplier()),
                (lambda sha: manifest(), RaisingRefSupplier())):
            with self.subTest(supplier=type(supplier).__name__):
                g = gate()
                adapter, transport = build(req, rt, g, loader, supplier)
                reply = adapter.execute(req)
                self.assertIsNotNone(reply.never_started)
                self.assertEqual(reply.never_started.evidence_ref,
                                 'route:qualification_failed')
                self.assertNotIn('PRIVATE_CANARY', repr(reply))
                self.assertEqual(transport.open_calls, 0)
                # Sticky: a fresh pooled child on the same shared gate is
                # refused with zero sockets and no requalification.
                adapter2, transport2 = build(req, rt, g,
                    lambda sha: manifest(), Supplier())
                self.assertIsNotNone(adapter2.execute(req).never_started)
                self.assertEqual(transport2.open_calls, 0)
        # A callable credential_ref attribute resolves identically.
        adapter, transport = build(req, rt, gate(), lambda sha: manifest(),
                                   CallableRefSupplier())
        self.assertEqual(adapter.execute(req).status, OperationStatus.ACCEPTED)
        # A gate-side failure (bad probe) latches inside qualify() itself.
        g = gate(probe_identity=lambda: {'model': 'other'})
        adapter, transport = build(req, rt, g, lambda sha: manifest(),
                                   Supplier())
        self.assertEqual(adapter.execute(req).never_started.evidence_ref,
                         'route:qualification_failed')
        self.assertEqual(transport.open_calls, 0)
        adapter2, t2 = build(req, rt, g, lambda sha: manifest(), Supplier())
        self.assertIsNotNone(adapter2.execute(req).never_started)
        self.assertEqual(t2.open_calls, 0)

    def test_endpoint_binding_drift(self):
        prof = make_profile()
        req = request(env_for(prof))
        rt = qroute(req, prof, endpoint='http://127.0.0.1:9/v1')
        adapter, transport = build(req, rt, gate(), lambda sha: manifest(),
                                   Supplier())
        reply = adapter.execute(req)
        self.assertEqual(reply.never_started.evidence_ref,
                         'route:qualification_failed')
        self.assertEqual(transport.open_calls, 0)

    def test_transport_supplier_identity_mismatch(self):
        prof = make_profile()
        req = request(env_for(prof))
        rt = qroute(req, prof)
        g = gate()
        supplier = Supplier()
        adapter, transport = build(req, rt, g, lambda sha: manifest(),
            supplier, transport=FakeTransport(Supplier()))  # other object
        reply = adapter.execute(req)
        self.assertEqual(reply.never_started.evidence_ref,
                         'route:qualification_failed')
        self.assertEqual(transport.open_calls, 0)
        self.assertTrue(transport.closed)
        self.assertNotIn(req.ref, adapter._attempts)   # reservation removed
        adapter2, t2 = build(req, rt, g, lambda sha: manifest(), supplier)
        self.assertIsNotNone(adapter2.execute(req).never_started)
        self.assertEqual(t2.open_calls, 0)
        # A transport lying about sent_state cannot mint a NeverStarted.
        g = gate()
        adapter, transport = build(req, rt, g, lambda sha: manifest(),
            supplier, transport=FakeTransport(Supplier(), sent_state='sent'))
        reply = adapter.execute(req)
        self.assertIsNone(reply.never_started)
        self.assertEqual(reply.status, OperationStatus.ERROR)
        self.assertTrue(transport.closed)
        self.assertEqual(transport.open_calls, 0)

    def test_close_cannot_rewrite_transmit_proof(self):
        prof = make_profile()
        req = request(env_for(prof))
        rt = qroute(req, prof)
        supplier = Supplier()
        for claim in ('sent', 'unknown'):
            with self.subTest(claim=claim):
                # close() flips sent_state to not_sent; the pre-close
                # snapshot must still deny NeverStarted.
                adapter, transport = build(req, rt, gate(),
                    lambda sha: manifest(), supplier,
                    transport=LyingCloseTransport(Supplier(),
                                                  sent_state=claim))
                reply = adapter.execute(req)
                self.assertIsNone(reply.never_started)
                self.assertEqual(reply.status, OperationStatus.ERROR)
                self.assertEqual(transport.open_calls, 0)
                self.assertTrue(transport.closed)
                self.assertEqual(transport.sent_state, 'not_sent')
                self.assertEqual(results(adapter, req.ref)[0].reason,
                                 'provider_submission_unknown')
        # Honest not_sent mismatch still yields NS, reservation removed.
        adapter, transport = build(req, rt, gate(), lambda sha: manifest(),
            supplier, transport=FakeTransport(Supplier()))
        reply = adapter.execute(req)
        self.assertEqual(reply.never_started.evidence_ref,
                         'route:qualification_failed')
        self.assertNotIn(req.ref, adapter._attempts)
        self.assertEqual(transport.open_calls, 0)
        self.assertTrue(transport.closed)

    def test_generic_route_never_calls_gate(self):
        req = request('env:sha256:' + '0' * 64, model='test-model')
        rt = OpenAIRoute(request=req,
            endpoint='https://provider.example/v1/x', model='test-model',
            store_param='send_false', payload_sha256=payload_digest(req))
        g = gate()
        calls = []
        orig = g.qualify
        g.qualify = lambda **kw: calls.append(kw) or orig(**kw)
        adapter, transport = build(req, rt, g, lambda sha: manifest(),
                                   Supplier())
        reply = adapter.execute(req)
        self.assertEqual(reply.status, OperationStatus.ACCEPTED)
        self.assertEqual(calls, [])
        self.assertEqual(transport.open_calls, 1)

    def test_exclude_is_idempotent_no_reset(self):
        g = gate()
        g.exclude('env:sha256:' + '0' * 64)
        g.exclude('env:sha256:' + '0' * 64)
        g.exclude(None)
        prof = make_profile()
        req = request('env:sha256:' + '0' * 64)
        with self.assertRaises(ProfileError) as ctx:
            g.qualify(profile=prof, manifest=manifest(), endpoint=ENDPOINT,
                      auth_ref=AUTH_REF, request=req)
        self.assertEqual(str(ctx.exception), 'route excluded')


class SupplierTransportTests(unittest.TestCase):
    def test_real_transport_supplier_identity_and_headers(self):
        supplier = Supplier()
        requests = []
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass
            def do_POST(self):
                requests.append({k.lower(): v
                                 for k, v in self.headers.items()})
                self.rfile.read(int(self.headers.get('content-length') or 0))
                self.send_response(200)
                self.send_header('content-type', 'text/event-stream')
                self.end_headers()
                self.wfile.write(b'data: x\n\n')
        httpd = http.server.HTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        self.addCleanup(httpd.server_close)
        transport = HttpSseTransport(
            url='http://127.0.0.1:%d/v1' % httpd.server_port, body=b'{}',
            auth_supplier=supplier,
            deadlines=Deadlines(connect=2, first_byte=2, idle=2, total=4))
        self.assertIs(transport.auth_supplier, supplier)
        transport.open()
        for _ in range(100):
            if requests:
                break
            time.sleep(0.01)
        transport.close()
        self.assertEqual(requests[0].get('authorization'),
                         'Bearer fixture')
        self.assertEqual(supplier.credential_ref, AUTH_REF)


if __name__ == '__main__':
    unittest.main()
