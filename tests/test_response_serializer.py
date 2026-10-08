"""response_serializer allowlist tests: real OutputStore blobs, real
openai==3.24 Response.model_validate roundtrip for every status and
every closed failure code, leak canaries, and closed contract guards.
HTTP error mapping is a separate module and not covered here."""
import json
import tempfile
import unittest
import typing
from pathlib import Path

from co_v4 import contracts as c
from co_v4.gateway_store import PROJECTION_CODES, Projection
from co_v4.output_store import IntegrityError, OutputStore
from co_v4.response_serializer import serialize_response
from co_v4.responses_input import parse

try:
    import openai
    from openai.types.responses import Response as SDKResponse
    from openai.types.responses import ResponseError
except ImportError:
    openai = None
    SDKResponse = None
    ResponseError = None

GOLDEN_MESSAGES = {
    'provider_refusal':
        'provider_refusal: the model provider refused the request',
    'content_filter':
        'content_filter: the response was blocked by a content filter',
    'protocol_violation':
        'protocol_violation: the provider reply violated the protocol',
    'output_unavailable':
        'output_unavailable: the run completed without a usable output',
    'approval_required':
        'approval_required: the request requires approval',
    'integrity_violation':
        'integrity_violation: stored state failed an integrity check',
    'cessation_unconfirmed':
        'cessation_unconfirmed: execution cessation was not confirmed',
    'cancellation_unconfirmed':
        'cancellation_unconfirmed: the cancellation was not confirmed',
    'run_failed': 'run_failed: the run failed',
}
REF = c.AttemptRef('RUN-CANARY', 'JOB-CANARY', 'ATTEMPT-CANARY')
CANARIES = ('RUN-CANARY', 'JOB-CANARY', 'ATTEMPT-CANARY',
            'provider.endpoint.test', 'sk-token-CANARY',
            'NativeError-CANARY', 'context-CANARY', 'INPUT-CANARY')
ALLOWED = frozenset({'id', 'object', 'created_at', 'status', 'model',
                     'output', 'error', 'incomplete_details',
                     'instructions', 'metadata', 'background', 'tools',
                     'tool_choice', 'parallel_tool_calls', 'text',
                     'usage'})


def intent(**over):
    body = {'model': 'co-text',
            'input': 'INPUT-CANARY never emitted',
            'instructions': 'café 日本語', 'background': True,
            'metadata': {'k1': 'v1', 'k2': 'v2'}}
    body.update(over)
    return parse(json.dumps(body).encode('utf-8'))


class _GetSpy:
    """Records get() calls and delegates to the real OutputStore."""

    def __init__(self, store):
        self._store = store
        self.calls = []

    def get(self, ref, committed):
        self.calls.append((ref, committed))
        return self._store.get(ref, committed)


class SerializerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = OutputStore(Path(self.tmp.name) / 'outputs')
        self.spy = _GetSpy(self.store)

    def proj(self, status, code=None, decided=False, output=None):
        return Projection('resp_1', status, code, 3, decided, output)

    def sdk(self, body):
        self.assertIsNotNone(SDKResponse,
                             'openai SDK required for roundtrip')
        if SDKResponse is not None:
            self.assertEqual(openai.__version__, '3.24.0')
        return SDKResponse.model_validate(body)

    def check(self, body, status):
        model = self.sdk(body)
        self.assertEqual(set(body), ALLOWED)
        self.assertEqual((model.id, model.object, model.status),
                         ('resp_1', 'response', status))
        self.assertEqual(model.model, 'co-text')
        self.assertIs(body['background'], True)
        self.assertEqual(body['instructions'], 'café 日本語')
        self.assertEqual(body['metadata'], {'k1': 'v1', 'k2': 'v2'})
        self.assertEqual(body['tools'], [])
        self.assertEqual(body['tool_choice'], 'none')
        self.assertIs(body['parallel_tool_calls'], False)
        self.assertEqual(body['text'], {'format': {'type': 'text'}})
        self.assertIsNone(model.usage)
        self.assertIsNone(model.incomplete_details)
        dumped = json.dumps(body)
        for canary in CANARIES:
            self.assertNotIn(canary, dumped)
        return model

    def completed(self, texts=('café 日本語\n', 'second ítem ✓', '')):
        items = tuple(c.OutputItem(i, 'text/plain', t)
                      for i, t in enumerate(texts))
        committed = self.store.put(REF, items)
        return c.OutputRef(REF, committed.digest), committed

    def test_sdk_available_pinned(self):
        self.assertIsNotNone(SDKResponse,
                             'openai SDK required for roundtrip')
        if SDKResponse is not None:
            self.assertEqual(openai.__version__, '3.24.0')
            self.assertIsNotNone(ResponseError)
            code_literal = ResponseError.model_fields['code'].annotation
            self.assertIs(typing.get_origin(code_literal), typing.Literal)
            literal_args = typing.get_args(code_literal)
            self.assertIn('server_error', literal_args)
            self.assertNotIn('run_failed', literal_args)

    def test_noncompleted_statuses_roundtrip(self):
        for status, decided in (('queued', False),
                                ('in_progress', False),
                                ('in_progress', True),
                                ('cancelled', True)):
            with self.subTest(status=status, decided=decided):
                body = serialize_response(
                    self.proj(status, decided=decided), intent(),
                    1700000000, self.spy)
                model = self.check(body, status)
                self.assertEqual(model.output, [])
                self.assertIsNone(body['error'])
                self.assertIsNone(model.error)
        self.assertEqual(self.spy.calls, [])

    def test_failed_all_closed_codes(self):
        self.assertEqual(frozenset(GOLDEN_MESSAGES), PROJECTION_CODES)
        prefixes = [m.split(': ', 1)[0] for m in GOLDEN_MESSAGES.values()]
        self.assertEqual(sorted(prefixes), sorted(PROJECTION_CODES))
        self.assertEqual(len(set(GOLDEN_MESSAGES.values())), 9)
        self.assertEqual(len(set(prefixes)), 9)
        for code in sorted(PROJECTION_CODES):
            with self.subTest(code=code):
                body = serialize_response(
                    self.proj('failed', code, True), intent(),
                    1700000000, self.spy)
                model = self.check(body, 'failed')
                self.assertEqual(body['error'],
                                 {'code': 'server_error',
                                  'message': GOLDEN_MESSAGES[code]})
                self.assertEqual(model.error.code, 'server_error')
                self.assertEqual(model.error.message,
                                 GOLDEN_MESSAGES[code])
                self.assertEqual(
                    body['error']['message'].split(': ', 1)[0], code)
        self.assertEqual(self.spy.calls, [])

    def test_completed_multi_item_exact_utf8(self):
        texts = ('café 日本語\n', 'second ítem ✓', '')
        ref, committed = self.completed(texts)
        body = serialize_response(
            self.proj('completed', decided=True,
                      output=(ref, committed)),
            intent(), 1700000000, self.spy)
        model = self.check(body, 'completed')
        self.assertEqual(self.spy.calls, [(ref, committed)])
        msg, = body['output']
        self.assertEqual(msg['id'], 'msg_' + ref.digest[7:])
        self.assertEqual((msg['type'], msg['role'], msg['status']),
                         ('message', 'assistant', 'completed'))
        self.assertEqual([p['type'] for p in msg['content']],
                         ['output_text'] * 3)
        self.assertEqual([p['text'] for p in msg['content']],
                         list(texts))
        self.assertEqual([p['annotations'] for p in msg['content']],
                         [[], [], []])
        out, = model.output
        self.assertEqual([p.text for p in out.content], list(texts))
        self.assertIsNone(body['error'])

    def test_integrity_failures(self):
        ref, committed = self.completed(('x',))
        good = self.proj('completed', decided=True,
                         output=(ref, committed))
        blob = (self.store.root / 'blobs'
                / committed.items[0].blob_digest[7:])
        blob_good = blob.read_bytes()
        blob.write_bytes(b'tampered')
        with self.assertRaises(IntegrityError):
            serialize_response(good, intent(), 1, self.spy)
        blob.write_bytes(blob_good)
        manifest = (self.store.root / 'manifests'
                    / committed.digest[7:])
        manifest_good = manifest.read_bytes()
        manifest.write_bytes(b'{"corrupt":true}')
        with self.assertRaises(IntegrityError):
            serialize_response(good, intent(), 1, self.spy)
        manifest.write_bytes(manifest_good)
        reached = len(self.spy.calls)  # only real get() attempts so far
        for proj in (self.proj('completed', decided=True),
                     self.proj('completed', decided=False,
                               output=(ref, committed)),
                     self.proj('in_progress',
                               output=(ref, committed)),
                     self.proj('cancelled', decided=True,
                               output=(ref, committed)),
                     self.proj('completed', decided=True, output='x'),
                     self.proj('completed', decided=True, output=(ref,)),
                     self.proj('completed', decided=True,
                               output=(ref, committed, ref)),
                     self.proj('completed', decided=True,
                               output=('x', committed)),
                     self.proj('completed', decided=True,
                               output=(ref, 'y'))):
            with self.assertRaises(IntegrityError):
                serialize_response(proj, intent(), 1, self.spy)
        self.assertEqual(len(self.spy.calls), reached)  # never read

    def test_contract_guards(self):
        good = self.proj('queued')
        i = intent()
        for args in ((None, i, 1), (good, None, 1), (good, i, True),
                     (good, i, -1), (good, i, 'x')):
            with self.assertRaises(ValueError):
                serialize_response(*args, self.spy)
        for proj in (self.proj('bogus'), self.proj([]),
                     self.proj('queued', decided='yes'),
                     Projection(123, 'queued', None, 0, False, None)):
            with self.assertRaises(ValueError):
                serialize_response(proj, i, 1, self.spy)
        for proj in (self.proj('queued', code='run_failed'),
                     self.proj('failed', 'bogus_code', True),
                     self.proj('failed', None, True),
                     self.proj('failed', [], True)):
            with self.assertRaises(IntegrityError):
                serialize_response(proj, i, 1, self.spy)
        self.assertEqual(self.spy.calls, [])

    def test_minimal_intent_echoes_nulls(self):
        bare = parse(json.dumps({'model': 'co-text',
                                 'input': 'x'}).encode())
        body = serialize_response(self.proj('queued'), bare, 1,
                                  self.spy)
        self.sdk(body)
        self.assertIsNone(body['instructions'])
        self.assertEqual(body['metadata'], {})
        self.assertIs(body['background'], False)


if __name__ == '__main__':
    unittest.main()
