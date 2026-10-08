"""Strict qualified-route adapter integration; injected hosts only.

Every binding is issued by the real QualifiedRouteGate through preflight —
fixture evidence, never provider qualification. Stream dicts mirror the
absent_single_part wire shape: no indices, no sequence_number.
"""
import copy
import hashlib
import json
import unittest

from co_v4.adapters.openai_responses import MAX_TEXT, OpenAIResponsesAdapter
from co_v4.contracts import (AttemptRef, CollectionError, ExecutionConditions,
    ExecuteRequest, Job, OperationStatus, ResultEvent, State, StopStatus)
from co_v4.openai_transport import (OpenAIRoute, SseMessage, StreamCapped,
    StreamEnded, StreamFailed, StreamStarted, payload_digest)
from co_v4.protocol_profile import (ASSERTIONS, MANIFEST_SCHEMA, canonical,
    environment_ref, issue_profile, verify_manifest)
from co_v4.qualified_route import QualifiedRouteGate

BLOBS = {'/cap/responses.sse': b'data: r\n\n', '/cap/chat.sse': b'data: c\n\n',
         '/src/task.cpp': b'// serializer source\n'}
ENDPOINT, AUTH_REF = 'http://127.0.0.1:50353/v1', 'prov-key'
COMMIT = 'd81235049384534c167caea52b85a694f6103d14'
RID, IID = 'resp_x', 'msg_x'
TERMINALS = (State.COMPLETED, State.FAILED, State.ERROR)


def manifest():
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
    m['manifest_sha256'] = hashlib.sha256(canonical(
        {k: v for k, v in m.items() if k != 'manifest_sha256'})).hexdigest()
    return m


def profile():
    return issue_profile(verify_manifest(manifest(), BLOBS.__getitem__),
        'responses', index_mode='absent_single_part', sequence_mode='absent',
        inert_fields={'response.completed': ('timings',)})


def stream():
    return [
        {'type': 'response.created', 'response': {
            'id': RID, 'object': 'response', 'status': 'in_progress'}},
        {'type': 'response.output_item.added', 'item': {
            'content': [], 'id': IID, 'role': 'assistant',
            'status': 'in_progress', 'type': 'message'}},
        {'type': 'response.content_part.added', 'item_id': IID,
         'part': {'type': 'output_text', 'text': ''}},
        {'type': 'response.output_text.delta', 'item_id': IID, 'delta': '4'},
        {'type': 'response.output_text.done', 'item_id': IID, 'text': '4'},
        {'type': 'response.content_part.done', 'item_id': IID, 'part': {
            'type': 'output_text', 'annotations': [], 'logprobs': [],
            'text': '4'}},
        {'type': 'response.output_item.done', 'item': {
            'type': 'message', 'status': 'completed', 'id': IID,
            'content': [{'type': 'output_text', 'annotations': [],
                         'logprobs': [], 'text': '4'}],
            'role': 'assistant'}},
        {'type': 'response.completed', 'response': {
            'id': RID, 'object': 'response', 'created_at': 1791299437,
            'status': 'completed', 'model': 'co04-qwen3-06b',
            'output': [{'type': 'message', 'status': 'completed', 'id': IID,
                        'content': [{'type': 'output_text', 'annotations': [],
                                     'logprobs': [], 'text': '4'}],
                        'role': 'assistant'}],
            'usage': {'input_tokens': 23, 'output_tokens': 2,
                      'total_tokens': 25}},
         'timings': {}}]


def frame(ev, name=None):
    return SseMessage(name if name is not None else ev['type'],
                      json.dumps(ev, ensure_ascii=True,
                                 separators=(',', ':')))


def frames(evs):
    return [frame(e) for e in evs]


class Supplier:
    credential_ref = AUTH_REF

    def __call__(self):
        return {'authorization': 'Bearer fixture'}


class FakeTransport:
    def __init__(self, script, supplier):
        self.script = [tuple(b) for b in script]
        self.auth_supplier = supplier
        self.open_calls = 0
        self.sent_state, self.responded = 'not_sent', False
        self.closed = self.done = self.dropped_terminal = False
        self.deadline = 10 ** 9

    def open(self):
        self.open_calls += 1
        self.sent_state, self.responded = 'sent', True

    def cancel(self):
        return True

    def poll(self):
        if self.script:
            return self.script.pop(0)
        return (StreamFailed('total_timeout', self.sent_state),)

    def close(self):
        self.closed = True


def build(script):
    prof = profile()
    ref = AttemptRef('run', 'job', 'att')
    req = ExecuteRequest(ref, Job('run', 'job', 'goal', ('ac',), '{}'),
        ExecutionConditions(prof.model, 'openai.responses', '/w',
            environment_ref(ENDPOINT, AUTH_REF, prof.profile_digest)))
    supplier = Supplier()
    transport = FakeTransport([[StreamStarted(200)] + script], supplier)
    rt = OpenAIRoute(request=req, endpoint=ENDPOINT, model=prof.model,
        store_param='send_false', payload_sha256=payload_digest(req),
        sequence='absent', profile=prof, auth_ref=AUTH_REF)
    adapter = OpenAIResponsesAdapter(verify_host=lambda *a: None,
        transport_factory=lambda r, b, t: transport, route=rt,
        qualification_gate=QualifiedRouteGate(
            read_evidence=BLOBS.__getitem__,
            probe_identity=lambda: {'model': 'co04-qwen3-06b'},
            launch_attested=lambda f, e, a: True),
        manifest_loader=lambda sha: manifest(), auth_supplier=supplier)
    return adapter, req, transport


def aux(etype, status, **resp):
    if etype == 'error':
        return {'type': 'error', 'code': 'x', 'message': 'm', 'param': None}
    resp.update(id=RID, object='response', status=status, output=[])
    return {'type': etype, 'response': resp}


class StrictAdapterTests(unittest.TestCase):
    def check(self, script):
        adapter, req, _ = build(script)
        self.assertEqual(adapter.execute(req).status,
                         OperationStatus.ACCEPTED)
        for _ in range(60):
            state = adapter.status(req.ref).state
            if state in TERMINALS:
                return adapter, req, state
        raise AssertionError('no terminal state')

    def result(self, adapter, ref):
        return next(e.result for e in adapter.events(ref)
                    if type(e) is ResultEvent)

    def test_clean_completed_collects_exact_one_post(self):
        adapter, req, state = self.check(frames(stream()) + [StreamEnded()])
        self.assertEqual((state, self.result(adapter, req.ref).reason),
                         (State.COMPLETED, None))
        self.assertEqual([i.text for i in adapter.collect_output(req.ref)],
                         ['4'])
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_aux_terminals_classified_no_output(self):
        terms = [(aux('response.failed', 'failed', error=None),
                  'provider_failed'),
                 (aux('response.incomplete', 'incomplete',
                      incomplete_details={'reason': 'max_output_tokens'}),
                  'output_truncated'),
                 (aux('error', None), 'provider_error')]
        for term, reason in terms:
            with self.subTest(term=term['type']):
                adapter, req, _ = self.check(
                    frames(stream()[:4] + [term]) + [StreamEnded()])
                self.assertEqual(self.result(adapter, req.ref).reason,
                                 reason)
                self.assertEqual(adapter.stop(req.ref).status,
                                 StopStatus.CONFIRMED)
                with self.assertRaises(CollectionError):
                    adapter.collect_output(req.ref)
        term = aux('response.incomplete', 'incomplete',
                   incomplete_details={'reason': 'content_filter'})
        adapter, req, _ = self.check(
            frames(stream()[:4] + [term]) + [StreamEnded()])
        self.assertEqual(self.result(adapter, req.ref).reason,
                         'content_filter')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_shape_failures_unconfirmed(self):
        for fn in (lambda t: t.update(debug={}),
                   lambda t: t.pop('response'),
                   lambda t: t['response'].pop('id'),
                   lambda t: t['response'].update(id='resp_o'),
                   lambda t: t['response'].update(id='x\ud800'),
                   lambda t: t['response'].update(model='m2'),
                   lambda t: t['response'].update(status='in_progress')):
            with self.subTest(fn=fn):
                evs = copy.deepcopy(stream())
                fn(evs[-1])
                adapter, req, state = self.check(frames(evs)
                                                 + [StreamEnded()])
                self.assertNotEqual(state, State.COMPLETED)
                self.assertEqual(adapter.stop(req.ref).status,
                                 StopStatus.UNCONFIRMED)
                with self.assertRaises(CollectionError):
                    adapter.collect_output(req.ref)

    def test_semantic_marks_confirm_terminal(self):
        for index, fn in ((3, lambda e: e.update(sequence_number=1)),
                          (4, lambda e: e.update(output_index=0)),
                          (4, lambda e: e.update(item_id='msg_o')),
                          (3, lambda e: e.update(delta='x\ud800')),
                          (7, lambda e: e.update(sequence_number=9))):
            with self.subTest(index=index):
                evs = copy.deepcopy(stream())
                fn(evs[index])
                adapter, req, _ = self.check(frames(evs) + [StreamEnded()])
                self.assertEqual(self.result(adapter, req.ref).reason,
                                 'protocol_violation')
                self.assertEqual(adapter.stop(req.ref).status,
                                 StopStatus.CONFIRMED)
                with self.assertRaises(CollectionError):
                    adapter.collect_output(req.ref)
        evs = copy.deepcopy(stream())
        del evs[4]                                   # missing text.done
        adapter, req, _ = self.check(frames(evs) + [StreamEnded()])
        self.assertEqual(self.result(adapter, req.ref).reason,
                         'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_failure_content_surrogates_semantic_confirmed(self):
        terms = [aux('response.failed', 'failed',
                     error={'code': None, 'message': 'x\ud800'}),
                 aux('error', None, ),
                 aux('response.incomplete', 'incomplete',
                     incomplete_details={'reason': 'z\ud800'})]
        terms[1]['message'] = 'y\ud800'
        for term in terms:
            with self.subTest(term=term['type']):
                adapter, req, _ = self.check(
                    frames(stream()[:4] + [term]) + [StreamEnded()])
                self.assertEqual(self.result(adapter, req.ref).reason,
                                 'protocol_violation')
                self.assertEqual(adapter.stop(req.ref).status,
                                 StopStatus.CONFIRMED)

    def test_streamcapped_drop_unverifiable_no_output(self):
        cap = StreamCapped('output_limit_exceeded')
        adapter, req, _ = self.check(   # created dropped: rid adopts
            [cap] + frames(stream()[1:]) + [StreamEnded()])
        self.assertEqual(self.result(adapter, req.ref).reason,
                         'output_limit_exceeded')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        with self.assertRaises(CollectionError):
            adapter.collect_output(req.ref)
        adapter, req, _ = self.check(   # item.added dropped: id binds
            frames(stream()[:1]) + [cap] + frames(stream()[2:])
            + [StreamEnded()])
        self.assertEqual(self.result(adapter, req.ref).reason,
                         'output_limit_exceeded')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        wrong = dict(stream()[4], item_id='msg_o')
        adapter, req, _ = self.check(   # observed mismatch still marks
            frames(stream()[:4]) + [cap] + frames([wrong] + stream()[5:])
            + [StreamEnded()])
        self.assertEqual(self.result(adapter, req.ref).reason,
                         'protocol_violation')

    def test_cap_and_first_policy_orders(self):
        big = dict(stream()[3], delta='x' * (MAX_TEXT + 1))
        adapter, req, _ = self.check(
            frames(stream()[:3] + [big] + stream()[4:]) + [StreamEnded()])
        self.assertEqual(self.result(adapter, req.ref).reason,
                         'output_limit_exceeded')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)
        with self.assertRaises(CollectionError):
            adapter.collect_output(req.ref)
        refusal = {'type': 'response.refusal.done', 'item_id': IID,
                   'refusal': 'x'}
        adapter, req, _ = self.check(
            frames(stream()[:3] + [refusal, big] + stream()[4:])
            + [StreamEnded()])
        self.assertEqual(self.result(adapter, req.ref).reason,
                         'provider_refusal')
        bad = {'type': 'response.refusal.done', 'item_id': IID,
               'refusal': 'x\ud800'}
        adapter, req, _ = self.check(   # corrupt signal: not a policy win
            frames(stream()[:3] + [bad] + stream()[3:]) + [StreamEnded()])
        self.assertEqual(self.result(adapter, req.ref).reason,
                         'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status, StopStatus.CONFIRMED)

    def test_repeat_name_consistency_and_named_done(self):
        for name in ('', 'message', 'response.completed'):
            with self.subTest(name=name):
                adapter, req, state = self.check(
                    frames(stream())
                    + [frame(stream()[-1], name=name), StreamEnded()])
                self.assertEqual(state, State.COMPLETED)
        adapter, req, _ = self.check(
            frames(stream())
            + [frame(stream()[-1], name='response.failed'), StreamEnded()])
        self.assertEqual(self.result(adapter, req.ref).reason,
                         'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status,
                         StopStatus.UNCONFIRMED)
        named = SseMessage('response.completed', '[DONE]')
        adapter, req, _ = self.check(frames(stream()) + [named,
                                                       StreamEnded()])
        self.assertEqual(self.result(adapter, req.ref).reason,
                         'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status,
                         StopStatus.UNCONFIRMED)


if __name__ == '__main__':
    unittest.main()
