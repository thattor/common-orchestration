"""Pure-value unit tests for co_v4.codex_text_validation (no transport I/O)."""

import copy
import unittest

from co_v4.adapters.codex import MAX_BYTES
from co_v4.codex_text_validation import (ValidationError, checked_item,
                                         checked_terminal, frame_kind,
                                         rpc_key, text_bytes)
from co_v4.codex_text_validation import DEFINITIONS, _schema_valid

USER = {'id': 'u1', 'type': 'userMessage',
        'content': [{'type': 'text', 'text': 'job'}]}
REASON = {'id': 'r1', 'type': 'reasoning', 'summary': ['sample'], 'content': []}
FINAL = {'id': 'a1', 'type': 'agentMessage', 'phase': 'final_answer',
         'text': '\n答え ' + ('あ' * 900) + ' \n'}
COMPLETED = {'u1': USER, 'r1': REASON, 'a1': FINAL}
FULL = {'id': 't1', 'status': 'completed', 'error': None,
        'items': [USER, REASON, FINAL], 'itemsView': 'full'}
SUMMARY = {'id': 't1', 'status': 'completed', 'items': [FINAL], 'itemsView': 'summary'}
UNLOADED = {'id': 't1', 'status': 'completed', 'items': [], 'itemsView': 'notLoaded'}


class RpcKeyTests(unittest.TestCase):
    def test_valid_typed_ids(self):
        self.assertEqual(rpc_key(1), ('int', 1))
        self.assertEqual(rpc_key('1'), ('str', '1'))
        self.assertNotEqual(rpc_key(1), rpc_key('1'))
        self.assertEqual(rpc_key(-(2 ** 63)), ('int', -(2 ** 63)))
        self.assertEqual(rpc_key(2 ** 63 - 1), ('int', 2 ** 63 - 1))
        self.assertEqual(rpc_key('x' * 1024), ('str', 'x' * 1024))

    def test_invalid_ids(self):
        for bad in (True, False, 2 ** 63, -(2 ** 63) - 1, '', None, 1.5,
                    'x' * 1025, 'abc\ud800', b'1'):
            with self.subTest(kind=type(bad).__name__):
                self.assertRaises(ValidationError, rpc_key, bad)


class FrameKindTests(unittest.TestCase):
    def test_response(self):
        self.assertEqual(frame_kind({'id': 'r', 'result': {}}), 'response')
        self.assertEqual(frame_kind({'id': 1, 'result': None, 'jsonrpc': '2.0'}), 'response')

    def test_bad_envelope(self):
        cases = [{'result': {}}, {'id': 1}, {'id': 1, 'result': {}, 'error': {}},
                 {'id': 1, 'result': {}, 'extra': 1},
                 {'id': 1, 'result': {}, 'jsonrpc': '1.0'},
                 {'id': True, 'result': {}}, {'id': 1, 'result': {}, 'params': {}},
                 'x', [], None]
        for c in cases:
            with self.subTest(case=c):
                self.assertRaises(ValidationError, frame_kind, c)

    def test_error_response_fixed_code_no_payload(self):
        with self.assertRaises(ValidationError) as ctx:
            frame_kind({'id': 1, 'error': {'code': -1, 'message': 'leak-me'}})
        self.assertNotIn('leak-me', str(ctx.exception))

    def test_native_request_always_denied(self):
        for method in ('tools/call', 'approval/request', 'question/ask',
                       'item/started', 'bogus/method'):
            with self.subTest(method=method):
                self.assertRaises(ValidationError, frame_kind,
                                  {'id': 7, 'method': method, 'params': {}})
        self.assertRaises(ValidationError, frame_kind,
                          {'id': 'bad id !!', 'method': 'x', 'params': {}})

    def test_notifications(self):
        for m in ('account/updated', 'thread/started', 'turn/completed',
                  'item/agentMessage/delta', 'warning',
                  'remoteControl/status/changed'):
            with self.subTest(method=m):
                self.assertEqual(frame_kind({'method': m, 'params': {'threadId': 'h'}}),
                                 'notification')
        ok = {'method': 'warning', 'params': {}, 'jsonrpc': '2.0',
              'emittedAtMs': -(2 ** 63)}
        self.assertEqual(frame_kind(ok), 'notification')
        self.assertEqual(frame_kind({**ok, 'emittedAtMs': 2 ** 63 - 1}),
                         'notification')

    def test_bad_notifications(self):
        cases = [{'method': 'unknown/x', 'params': {}},
                 {'method': 'warning'},
                 {'method': 'warning', 'params': []},
                 {'method': 'warning', 'params': {}, 'trace': 1},
                 {'method': 'warning', 'params': {}, 'jsonrpc': '2'},
                 {'method': 'warning', 'params': {}, 'emittedAtMs': True},
                 {'method': 'warning', 'params': {}, 'emittedAtMs': 2 ** 63},
                 {'method': 'warning', 'params': {}, 'emittedAtMs': None},
                 {'method': 5, 'params': {}}]
        for c in cases:
            with self.subTest(case=c):
                self.assertRaises(ValidationError, frame_kind, c)


class TextBytesTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(text_bytes('', 1), 0)
        self.assertEqual(text_bytes(' x ', 10), 3)
        self.assertEqual(text_bytes('abc', 3), 3)
        self.assertEqual(text_bytes('あ' * 3000, MAX_BYTES), 9000)
        self.assertEqual(text_bytes('x' * MAX_BYTES, MAX_BYTES), MAX_BYTES)

    def test_invalid(self):
        cases = [('abcd', 3), ('\ud800', 100), (b'x', 10), (None, 10), (5, 10),
                 ('x', True), ('x', 0), ('x', MAX_BYTES + 1), ('x', 1.5),
                 ('x', '3'), ('x', -2)]
        for value, cap in cases:
            with self.subTest(kind=type(value).__name__, cap=cap):
                self.assertRaises(ValidationError, text_bytes, value, cap)


class CheckedItemTests(unittest.TestCase):
    def test_canonical_defaults_and_no_mutation(self):
        user = {'id': 'u', 'type': 'userMessage',
                'content': [{'type': 'text', 'text': 'hi'}]}
        before = copy.deepcopy(user)
        out = checked_item(user, max_output_bytes=MAX_BYTES)
        self.assertEqual(user, before)
        self.assertEqual(out, {'id': 'u', 'type': 'userMessage', 'clientId': None,
                               'content': [{'type': 'text', 'text': 'hi',
                                            'text_elements': []}]})
        reason = checked_item({'id': 'r', 'type': 'reasoning'},
                              max_output_bytes=MAX_BYTES)
        self.assertEqual(reason, {'id': 'r', 'type': 'reasoning',
                                  'content': [], 'summary': []})
        agent = checked_item({'id': 'a', 'type': 'agentMessage', 'text': '',
                              'phase': None}, max_output_bytes=1, completed=False)
        self.assertEqual(agent, {'id': 'a', 'type': 'agentMessage', 'text': '',
                                 'phase': None, 'delivery': None,
                                 'memoryCitation': None, 'questions': None})
        full = checked_item(copy.deepcopy(FINAL), max_output_bytes=MAX_BYTES)
        self.assertEqual(full['phase'], 'final_answer')
        self.assertEqual(full['text'], FINAL['text'])

    def test_phase_rules(self):
        base = {'id': 'a', 'type': 'agentMessage', 'text': ''}
        checked_item(base, max_output_bytes=1, completed=False)
        self.assertRaises(ValidationError, checked_item, base,
                          max_output_bytes=1, completed=True)
        commentary = {**base, 'phase': 'commentary'}
        for completed in (False, True):
            with self.subTest(completed=completed):
                self.assertRaises(ValidationError, checked_item, commentary,
                                  max_output_bytes=MAX_BYTES, completed=completed)

    def test_refusals(self):
        cases = [
            'not-a-dict',
            {'id': 'x', 'type': 'commandExecution', 'command': 'ls'},
            {'id': 'x', 'type': 'plan'},
            {'id': 'x', 'type': 'bogus'},
            {'id': '', 'type': 'reasoning'},
            {'id': 'x' * 1025, 'type': 'reasoning'},
            {'id': 'r', 'type': 'reasoning', 'mystery': 1},
            {'id': 'r', 'type': 'reasoning', 'summary': ['s'] * 129},
            {'id': 'a', 'type': 'agentMessage', 'text': 'hi', 'questions': [{'q': 1}]},
            {'id': 'a', 'type': 'agentMessage', 'text': 'hi', 'memoryCitation': 'x'},
            {'id': 'a', 'type': 'agentMessage', 'text': 'hi', 'delivery': 'x'},
            {'id': 'u', 'type': 'userMessage', 'clientId': 'c' * 1025,
             'content': [{'type': 'text', 'text': 't'}]},
            {'id': 'u', 'type': 'userMessage',
             'content': [{'type': 'image', 'text': 't'}]},
            {'id': 'u', 'type': 'userMessage',
             'content': [{'type': 'text', 'text': 't', 'text_elements': [{'e': 1}]}]},
            {'id': 'a', 'type': 'agentMessage', 'text': 'x' * (MAX_BYTES + 1)},
        ]
        for c in cases:
            with self.subTest(case=str(c)[:40]):
                self.assertRaises(ValidationError, checked_item, c,
                                  max_output_bytes=MAX_BYTES)
        self.assertRaises(ValidationError, checked_item, copy.deepcopy(FINAL),
                          max_output_bytes=10)
        self.assertRaises(ValidationError, checked_item, copy.deepcopy(FINAL),
                          max_output_bytes=True)


class CheckedTerminalTests(unittest.TestCase):
    def setUp(self):
        self.completed = copy.deepcopy(COMPLETED)
        self.full = copy.deepcopy(FULL)
        self.summary = copy.deepcopy(SUMMARY)
        self.unloaded = copy.deepcopy(UNLOADED)

    def test_full_inventory(self):
        inv = checked_terminal(self.full, self.completed, max_output_bytes=MAX_BYTES)
        self.assertEqual(set(inv), {'view', 'terminal_count', 'completed_count',
                                    'terminal_types', 'completed_types',
                                    'matched_id_count', 'unique_ids',
                                    'agent_texts_match_observed'})
        self.assertEqual(inv['view'], 'full')
        self.assertEqual((inv['terminal_count'], inv['completed_count'],
                          inv['matched_id_count']), (3, 3, 3))
        counts = {'userMessage': 1, 'reasoning': 1, 'agentMessage': 1}
        self.assertEqual(inv['terminal_types'], counts)
        self.assertEqual(inv['completed_types'], counts)
        self.assertTrue(inv['unique_ids'])
        self.assertTrue(inv['agent_texts_match_observed'])
        self.assertNotIn('a1', repr(inv))
        self.assertNotIn('答え', repr(inv))

    def test_summary_not_loaded_and_default_view(self):
        inv = checked_terminal(self.summary, self.completed,
                               max_output_bytes=MAX_BYTES)
        self.assertEqual((inv['view'], inv['matched_id_count']), ('summary', 1))
        inv = checked_terminal(self.unloaded, self.completed,
                               max_output_bytes=MAX_BYTES)
        self.assertEqual((inv['view'], inv['terminal_count'],
                          inv['matched_id_count']), ('notLoaded', 0, 0))
        no_view = {'id': 't', 'status': 'completed',
                   'items': [copy.deepcopy(FINAL)]}
        inv = checked_terminal(no_view, {'a1': copy.deepcopy(FINAL)},
                               max_output_bytes=MAX_BYTES)
        self.assertEqual(inv['view'], 'full')

    def test_failures(self):
        altered = copy.deepcopy(FULL)
        altered['items'][2]['text'] = 'tampered'
        dup = dict(FULL, items=[copy.deepcopy(USER), copy.deepcopy(USER),
                                copy.deepcopy(FINAL)])
        bad_key = copy.deepcopy(COMPLETED)
        bad_key['zz'] = bad_key.pop('a1')
        no_final = {'u1': copy.deepcopy(USER), 'r1': copy.deepcopy(REASON)}
        agent2 = {'id': 'a2', 'type': 'agentMessage',
                  'phase': 'final_answer', 'text': 'x'}
        two_final_map = copy.deepcopy(COMPLETED)
        two_final_map['a2'] = copy.deepcopy(agent2)
        two_final_turn = copy.deepcopy(FULL)
        two_final_turn['items'].append(agent2)
        big_map = {'k%d' % i: {'id': 'k%d' % i, 'type': 'reasoning'}
                   for i in range(129)}
        cases = [
            (dict(FULL, status='failed'), copy.deepcopy(COMPLETED)),
            (dict(FULL, status='inProgress'), copy.deepcopy(COMPLETED)),
            (dict(FULL, error={'code': 1}), copy.deepcopy(COMPLETED)),
            (dict(FULL, itemsView='bogus'), copy.deepcopy(COMPLETED)),
            (dict(FULL, itemsView=''), copy.deepcopy(COMPLETED)),
            (dict(FULL, rogue=1), copy.deepcopy(COMPLETED)),
            (altered, copy.deepcopy(COMPLETED)),
            (dup, copy.deepcopy(COMPLETED)),
            (dict(FULL, items=copy.deepcopy(FULL['items'][:2])), self.completed),
            (dict(FULL, items=copy.deepcopy(FULL['items']) +
                  [{'id': 'z', 'type': 'reasoning'}]), self.completed),
            (dict(SUMMARY, items=[copy.deepcopy(USER)]), self.completed),
            (dict(SUMMARY, items=[copy.deepcopy(FINAL), agent2]), two_final_map),
            (dict(UNLOADED, items=[copy.deepcopy(FINAL)]), self.completed),
            (self.full, bad_key),
            (self.full, no_final),
            (two_final_turn, two_final_map),
            (self.full, []),
            (self.full, {'a1': copy.deepcopy(FINAL)}),
            (self.full, big_map),
            ('x', self.completed),
        ]
        for turn, items in cases:
            with self.subTest(turn=str(turn)[:50]):
                self.assertRaises(ValidationError, checked_terminal, turn, items,
                                  max_output_bytes=MAX_BYTES)
        self.assertRaises(ValidationError, checked_terminal, self.full,
                          self.completed, max_output_bytes=True)


class StrictBoundaryTests(unittest.TestCase):
    @staticmethod
    def agent(text):
        return {'id': 'a', 'type': 'agentMessage', 'phase': 'final_answer', 'text': text}

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(ValidationError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.args, (code,))

    def test_lifted_text_limit_through_item_and_all_terminal_views(self):
        texts = ('x' * 65537, 'x' * MAX_BYTES,
                 'あ' * (MAX_BYTES // 3) + 'x' * (MAX_BYTES % 3))
        for text in texts:
            with self.subTest(bytes=len(text.encode('utf-8'))):
                agent = self.agent(text)
                self.assertEqual(checked_item(agent, max_output_bytes=MAX_BYTES)['text'], text)
                user = {'id': 'u', 'type': 'userMessage',
                        'content': [{'type': 'text', 'text': text}]}
                self.assertEqual(checked_item(user, max_output_bytes=MAX_BYTES)['content'][0]['text'], text)
                for view in ('full', 'summary', 'notLoaded'):
                    turn = {'id': 't', 'status': 'completed', 'itemsView': view,
                            'items': [] if view == 'notLoaded' else [agent]}
                    inventory = checked_terminal(turn, {'a': agent}, max_output_bytes=MAX_BYTES)
                    self.assertEqual(inventory['completed_count'], 1)
                    self.assertEqual(inventory['matched_id_count'], 0 if view == 'notLoaded' else 1)

    def test_text_byte_ceiling_and_caller_cap_remain_enforced(self):
        text = 'あ' * (MAX_BYTES // 3) + 'x' * (MAX_BYTES % 3)
        for oversized in ('x' * (MAX_BYTES + 1), text + 'x'):
            with self.subTest(bytes=len(oversized.encode('utf-8'))):
                agent = self.agent(oversized)
                self.assert_code('item_invalid', checked_item, agent, max_output_bytes=MAX_BYTES)
                user = {'id': 'u', 'type': 'userMessage', 'content': [{'type': 'text', 'text': oversized}]}
                self.assert_code('item_invalid', checked_item, user, max_output_bytes=MAX_BYTES)
                self.assert_code('terminal_invalid', checked_terminal,
                                 {'id': 't', 'status': 'completed', 'items': [agent]},
                                 {'a': agent}, max_output_bytes=MAX_BYTES)
        self.assert_code('text_output_invalid', checked_item, self.agent(text), max_output_bytes=MAX_BYTES - 1)

    def test_default_string_ceiling_and_explicit_character_limit(self):
        reason = {'id': 'r', 'type': 'reasoning', 'content': ['x' * 65536]}
        checked_item(reason, max_output_bytes=MAX_BYTES)
        reason['content'] = ['x' * 65537]
        self.assert_code('item_invalid', checked_item, reason, max_output_bytes=MAX_BYTES)
        self.assertFalse(_schema_valid('xx', {'type': 'string', 'maxUtf8Bytes': MAX_BYTES, 'maxLength': 1}))

    def test_turn_timestamps_use_strict_signed64_and_fixed_refusals(self):
        agent = self.agent('x')
        for field in ('startedAt', 'completedAt', 'durationMs'):
            for value in (None, -(2 ** 63), 0, 2 ** 63 - 1):
                turn = {'id': 't', 'status': 'completed', 'items': [agent], field: value}
                checked_terminal(turn, {'a': agent}, max_output_bytes=MAX_BYTES)
            for value in (True, False, 1.0, float('nan'), float('inf'), -float('inf'),
                          2 ** 63, -(2 ** 63) - 1, 10 ** 400, -(10 ** 400)):
                with self.subTest(field=field, type=type(value).__name__):
                    turn = {'id': 't', 'status': 'completed', 'items': [agent], field: value}
                    self.assert_code('terminal_invalid', checked_terminal, turn,
                                     {'a': agent}, max_output_bytes=MAX_BYTES)

    def test_refs_only_resolve_exact_literal_defined_roots(self):
        ref = {'$ref': '#/definitions/MessagePhase'}
        self.assertTrue(_schema_valid('final_answer', ref, DEFINITIONS))
        self.assertFalse(_schema_valid('x', {'type': 'future'}))
        for value in ('#/definitions/Unknown', '#/definitions/Unknown/path/MessagePhase',
                      '#/definitions//MessagePhase', '#/definitions/MessagePhase/',
                      '#/definitions/MessagePhase~1', 'MessagePhase',
                      'https://fixture.invalid/MessagePhase', None, 1, []):
            with self.subTest(ref_type=type(value).__name__):
                self.assertFalse(_schema_valid('final_answer', {'$ref': value}, DEFINITIONS))
        alternate = {'Unknown': {'type': 'string'}, 'MessagePhase': {'type': 'string'}}
        self.assertFalse(_schema_valid('x', {'$ref': '#/definitions/Unknown'}, alternate))
        self.assertFalse(_schema_valid('spoof', ref, alternate))
        self.assertTrue(_schema_valid('final_answer', ref, alternate))

    def test_completed_flag_is_an_exact_boolean(self):
        started = {'id': 'a', 'type': 'agentMessage', 'text': '', 'phase': None}
        checked_item(started, max_output_bytes=1, completed=False)
        self.assert_code('item_invalid', checked_item, started, max_output_bytes=1, completed=True)
        for flag in (0, 1, None, '', 'false', [], {}):
            with self.subTest(flag_type=type(flag).__name__):
                self.assert_code('item_invalid', checked_item, started,
                                 max_output_bytes=1, completed=flag)
                self.assert_code('item_invalid', checked_item, self.agent('x'),
                                 max_output_bytes=1, completed=flag)


if __name__ == '__main__':
    unittest.main()
