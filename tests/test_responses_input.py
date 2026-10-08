"""Strict northbound request-surface contract tests (#190 M3).

Hard-pinned to installed openai SDK 3.24.0 type definitions; imports types
only, with no network or provider call and no skip/fallback.
"""
import hashlib
import json
import unittest
from typing import get_args

from openai.types.responses.easy_input_message_param import EasyInputMessageParam
from openai.types.responses.response_create_params import (
    ResponseCreateParams, ResponseCreateParamsBase)
from openai.types.responses.response_input_text_param import ResponseInputTextParam
from openai.types.responses.response_output_text_param import ResponseOutputTextParam

from co_v4.responses_input import (DOMAIN, FIELDS, ITEM_KEYS, KNOWN_UNSUPPORTED,
                                   MAX_BODY_BYTES, PART_INERT, PART_KEYS,
                                   Fragment, Item, RequestRejected, parse)


def body(**kw):
    return json.dumps(kw, ensure_ascii=False).encode('utf-8')


def sdk_keys():
    keys = set(ResponseCreateParamsBase.__annotations__)
    for member in get_args(ResponseCreateParams):
        keys.update(member.__annotations__)
    return frozenset(keys)


class ResponsesInputTests(unittest.TestCase):
    def reject(self, raw, code, param=None):
        with self.assertRaises(RequestRejected) as caught:
            parse(raw if type(raw) is bytes else
                  json.dumps(raw, ensure_ascii=False).encode('utf-8'))
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.param, param)

    def test_sdk_param_tables_are_pinned(self):
        self.assertEqual(sdk_keys(), FIELDS | KNOWN_UNSUPPORTED)
        self.assertEqual(frozenset(EasyInputMessageParam.__annotations__),
                         ITEM_KEYS)
        self.assertEqual(frozenset(ResponseInputTextParam.__annotations__),
                         PART_KEYS['input_text'])
        self.assertEqual(frozenset(ResponseOutputTextParam.__annotations__),
                         PART_KEYS['output_text'])
        self.assertEqual(PART_INERT['input_text'], frozenset())
        self.assertEqual(PART_INERT['output_text'],
                         frozenset({'annotations', 'logprobs'}))
        self.assertLessEqual(PART_INERT['output_text'], PART_KEYS['output_text'])

    def test_minimal_request_and_canonical_golden(self):
        task = parse(body(model='co-auto', input='do the thing'))
        self.assertEqual((task.model, task.input), ('co-auto', 'do the thing'))
        self.assertIsNone(task.instructions)
        self.assertFalse(task.background)
        self.assertTrue(task.store)
        self.assertEqual(task.metadata, ())
        self.assertEqual(task.canonical_body,
            b'{"background":false,"input":"do the thing",'
            b'"model":"co-auto","store":true}')
        self.assertEqual(task.body_hash,
            hashlib.sha256(DOMAIN + task.canonical_body).hexdigest())

    def test_null_empty_and_inert_equivalence(self):
        bare = parse(body(model='co-auto', input='x'))
        nulled = parse(body(model='co-auto', input='x', instructions=None,
            background=None, stream=None, metadata=None, store=None,
            tools=None, tool_choice=None, text=None,
            **{key: None for key in KNOWN_UNSUPPORTED}))
        self.assertEqual(bare.canonical_body, nulled.canonical_body)
        spelled = parse(body(model='co-auto', input='x', stream=False,
            store=True, tools=[], background=False, metadata={}, include=[],
            text={'format': {'type': 'text'}}))
        self.assertEqual(bare.body_hash, spelled.body_hash)

    def test_known_unsupported_non_null_values_rejected(self):
        for key in sorted(KNOWN_UNSUPPORTED):
            with self.subTest(key=key):
                self.reject({'model': 'm', 'input': 'x', key: 'v'},
                            'unsupported_field', key)
        self.reject({'model': 'm', 'input': 'x', 'include': ['x']},
                    'unsupported_field', 'include')
        self.reject({'model': 'm', 'input': 'x', 'include': {}},
                    'unsupported_field', 'include')

    def test_truly_unknown_field_rejected_even_when_null(self):
        self.reject({'model': 'm', 'input': 'x', 'made_up_field': None},
                    'unknown_field', 'made_up_field')
        self.reject({'model': 'm', 'input': 'x', 'bad field': 1},
                    'unknown_field', None)

    def test_easy_message_without_type_matches_typed_digest(self):
        easy: EasyInputMessageParam = {'role': 'user', 'content': 'hi'}
        easy_task = parse(body(model='co-auto', input=[dict(easy)]))
        typed = parse(body(model='co-auto', input=[
            {'type': 'message', 'role': 'user', 'content': 'hi'}]))
        null_type = parse(body(model='co-auto', input=[
            {'type': None, 'role': 'user', 'content': 'hi'}]))
        self.assertEqual(easy_task.body_hash, typed.body_hash)
        self.assertEqual(easy_task.body_hash, null_type.body_hash)
        self.assertEqual(easy_task.input[0], Item('user', 'hi'))

    def test_assistant_string_and_part_key_rules(self):
        out_part: ResponseOutputTextParam = {
            'type': 'output_text', 'text': 'prior', 'annotations': []}
        in_part: ResponseInputTextParam = {'type': 'input_text', 'text': 'a'}
        task = parse(body(model='co-auto', input=[
            {'role': 'assistant', 'content': 'prior answer'},
            {'role': 'assistant', 'content': [dict(out_part)]},
            {'role': 'user', 'content': [dict(in_part)]}]))
        self.assertEqual(task.input[0].content, 'prior answer')
        self.assertEqual(task.input[1].content,
                         (Fragment('output_text', 'prior'),))
        self.assertNotIn(b'annotations', task.canonical_body)
        for empty in (None, []):
            for key in ('annotations', 'logprobs'):
                task = parse(body(model='m', input=[
                    {'role': 'assistant', 'content': [
                        {'type': 'output_text', 'text': 'x', key: empty}]}]))
                self.assertNotIn(key.encode(), task.canonical_body)
        task = parse(body(model='m', input=[
            {'role': 'user', 'content': [
                {'type': 'input_text', 'text': 'x',
                 'prompt_cache_breakpoint': None}]}]))
        self.assertNotIn(b'prompt_cache', task.canonical_body)

    def test_round_tripped_output_and_unknown_part_keys(self):
        self.reject({'model': 'm', 'input': [
            {'type': 'message', 'role': 'assistant', 'id': 'msg_1',
             'status': 'completed', 'content': 'x'}]},
            'unsupported_field', 'input')
        self.reject({'model': 'm', 'input': [
            {'role': 'assistant', 'content': 'x', 'phase': 'commentary'}]},
            'unsupported_field', 'input')
        for value in (None, []):
            self.reject({'model': 'm', 'input': [
                {'role': 'user', 'content': [
                    {'type': 'input_text', 'text': 'x',
                     'annotations': value}]}]},
                'unsupported_field', 'input')
        self.reject({'model': 'm', 'input': [
            {'role': 'user', 'content': [
                {'type': 'input_text', 'text': 'x', 'logprobs': None}]}]},
            'unsupported_field', 'input')
        self.reject({'model': 'm', 'input': [
            {'role': 'assistant', 'content': [
                {'type': 'output_text', 'text': 'x',
                 'annotations': [{'type': 'url_citation'}]}]}]},
            'unsupported_field', 'input')
        self.reject({'model': 'm', 'input': [
            {'role': 'assistant', 'content': [
                {'type': 'output_text', 'text': 'x', 'logprobs': [{}]}]}]},
            'unsupported_field', 'input')
        self.reject({'model': 'm', 'input': [
            {'role': 'user', 'content': [
                {'type': 'input_text', 'text': 'x',
                 'prompt_cache_breakpoint': {'mode': 'explicit'}}]}]},
            'unsupported_field', 'input')
        self.reject({'model': 'm', 'input': [
            {'type': 'output', 'role': 'assistant', 'content': 'x'}]},
            'unsupported_field', 'input')

    def test_ordered_roles_fragments_and_distinct_instructions(self):
        task = parse(body(model='co-auto', instructions='tone', input=[
            {'role': 'system', 'content': 'rules'},
            {'role': 'user', 'content': [{'type': 'input_text', 'text': 'a'},
                                         {'type': 'input_text', 'text': 'b'}]},
            {'role': 'assistant', 'content': [
                {'type': 'output_text', 'text': 'prior'}]}]))
        self.assertEqual([i.role for i in task.input],
                         ['system', 'user', 'assistant'])
        self.assertEqual(task.input[1].content,
            (Fragment('input_text', 'a'), Fragment('input_text', 'b')))
        self.assertEqual(task.instructions, 'tone')

    def test_order_and_alias_are_digest_significant(self):
        first = parse(body(model='co-auto', input=[
            {'role': 'system', 'content': 's'},
            {'role': 'user', 'content': 'u'}]))
        swapped = parse(body(model='co-auto', input=[
            {'role': 'user', 'content': 'u'},
            {'role': 'system', 'content': 's'}]))
        other = parse(body(model='co-other', input='x'))
        self.assertNotEqual(first.body_hash, swapped.body_hash)
        self.assertNotEqual(first.body_hash, other.body_hash)

    def test_exact_unicode_without_normalization(self):
        composed = parse(body(model='co-auto', input='café'))
        decomposed = parse(body(model='co-auto', input='café'))
        self.assertNotEqual(composed.body_hash, decomposed.body_hash)
        self.assertEqual(composed.input, 'café')
        self.assertEqual(decomposed.input, 'café')

    def test_metadata_echoed_not_authority(self):
        task = parse(body(model='co-auto', input='x',
                          metadata={'b': '2', 'a': '1'}))
        self.assertEqual(task.metadata, (('a', '1'), ('b', '2')))
        self.assertIn(b'"metadata":{"a":"1","b":"2"}', task.canonical_body)

    def test_metadata_bounds(self):
        pairs = {f'k{i}': 'v' for i in range(17)}
        self.reject({'model': 'm', 'input': 'x', 'metadata': pairs},
                    'invalid_field_value', 'metadata')
        self.reject({'model': 'm', 'input': 'x', 'metadata': {'k' * 65: 'v'}},
                    'invalid_field_value', 'metadata')
        self.reject({'model': 'm', 'input': 'x', 'metadata': {'k': 'v' * 513}},
                    'invalid_field_value', 'metadata')
        self.reject({'model': 'm', 'input': 'x', 'metadata': {'k': 1}},
                    'invalid_field_type', 'metadata')
        self.reject({'model': 'm', 'input': 'x', 'metadata': ['k']},
                    'invalid_field_type', 'metadata')

    def test_type_exact_flags(self):
        for bad in (0, '', [], 0.0):
            self.reject({'model': 'm', 'input': 'x', 'stream': bad},
                        'invalid_field_value', 'stream')
        for bad in (0, 1, 'yes', []):
            self.reject({'model': 'm', 'input': 'x', 'background': bad},
                        'invalid_field_type', 'background')
        for bad in (0, 1, 'true', 'false', []):
            self.reject({'model': 'm', 'input': 'x', 'store': bad},
                        'invalid_field_value', 'store')
        self.reject({'model': 'm', 'input': 'x', 'tools': 0},
                    'unsupported_field', 'tools')
        self.reject({'model': 'm', 'input': 'x', 'tools': {}},
                    'unsupported_field', 'tools')

    def test_unsupported_values(self):
        self.reject({'model': 'm', 'input': 'x', 'stream': True},
                    'invalid_field_value', 'stream')
        self.reject({'model': 'm', 'input': 'x', 'store': False},
                    'invalid_field_value', 'store')
        self.reject({'model': 'm', 'input': 'x',
                     'text': {'format': {'type': 'json_schema'}}},
                    'unsupported_field', 'text')
        self.reject({'model': 'm', 'input': 'x', 'text': 5},
                    'invalid_field_type', 'text')
        self.reject({'model': 'm', 'input': 'x', 'tool_choice': 'required'},
                    'unsupported_field', 'tool_choice')

    def test_required_and_typed_bounds(self):
        self.reject({'input': 'x'}, 'missing_required_field', 'model')
        self.reject({'model': 'm'}, 'missing_required_field', 'input')
        self.reject({'model': 'm', 'input': None},
                    'missing_required_field', 'input')
        self.reject({'model': 'm', 'input': []},
                    'invalid_field_value', 'input')
        self.reject({'model': 'm', 'input': 5},
                    'invalid_field_type', 'input')
        self.reject({'model': '', 'input': 'x'},
                    'invalid_field_value', 'model')
        self.reject({'model': 'has space', 'input': 'x'},
                    'invalid_field_value', 'model')
        self.reject({'model': 'm' * 129, 'input': 'x'},
                    'invalid_field_value', 'model')
        self.reject({'model': 'm', 'input': 'x', 'instructions': 3},
                    'invalid_field_type', 'instructions')

    def test_total_input_text_must_be_nonempty(self):
        self.reject({'model': 'm', 'input': ''},
                    'invalid_field_value', 'input')
        self.reject({'model': 'm', 'input': [
            {'role': 'user', 'content': ''}]},
            'invalid_field_value', 'input')
        self.reject({'model': 'm', 'input': [
            {'role': 'user', 'content': []}]},
            'invalid_field_value', 'input')
        self.reject({'model': 'm', 'input': [
            {'role': 'user', 'content': []},
            {'role': 'user', 'content': ''}]},
            'invalid_field_value', 'input')
        self.reject({'model': 'm', 'input': '', 'instructions': 'x'},
                    'invalid_field_value', 'input')
        task = parse(body(model='m', input=[
            {'role': 'user', 'content': []},
            {'role': 'user', 'content': [
                {'type': 'input_text', 'text': ''},
                {'type': 'input_text', 'text': 'real'}]}]))
        self.assertEqual(task.input[0].content, ())
        self.assertIn(b'"content":[]', task.canonical_body)
        self.assertEqual(task.input[1].content,
            (Fragment('input_text', ''), Fragment('input_text', 'real')))
        task = parse(body(model='m', input='x', instructions=''))
        self.assertEqual(task.instructions, '')

    def test_unhashable_and_nonstring_values_rejected_cleanly(self):
        for bad in ([], {}, 1, True):
            self.reject({'model': 'm', 'input': [
                {'role': bad, 'content': 'x'}]},
                'invalid_field_type', 'input')
            self.reject({'model': 'm', 'input': [
                {'type': bad, 'role': 'user', 'content': 'x'}]},
                'invalid_field_type', 'input')
            self.reject({'model': 'm', 'input': [
                {'role': 'user', 'content': [
                    {'type': 'input_text', 'text': bad}]}]},
                'invalid_field_type', 'input')
        # Only RequestRejected may escape, for arbitrary JSON anywhere.
        cases = {
            'model': [0, True, [], {}, {'a': 1}],
            'input': [0, True, {}, {'a': 1}, [['x']], None],
            'instructions': [0, [], {}],
            'metadata': [0, True, [], [['x']], {'a': [1]}],
            'stream': [0, True, '', [], {}],
            'background': [0, 1, 'x', [], {}],
            'store': [0, 1, 'x', [], {}],
            'tools': [0, 'x', {}, [1]],
            'tool_choice': ['x', 0, {}],
            'text': [0, 'x', []],
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(RequestRejected):
                        parse(json.dumps({'model': 'm', 'input': 'x',
                                          field: value},
                                         ensure_ascii=False).encode('utf-8'))

    def test_deep_nesting_maps_to_invalid_json(self):
        depth = 10 ** 5
        nested = b'[' * depth + b']' * depth
        raw = b'{"model":"m","input":"x","metadata":' + nested + b'}'
        self.assertLess(len(raw), MAX_BODY_BYTES)
        self.reject(raw, 'invalid_json')
        self.reject(nested, 'invalid_json')

    def test_strict_json_decoder(self):
        self.reject(b'{"model":"m","model":"n","input":"x"}',
                    'duplicate_key', 'model')
        self.reject(b'{"model":"m","input":"x","background":NaN}',
                    'invalid_json')
        self.reject(b'{"model":"m","input":"\xff\xfe"}', 'invalid_utf8')
        self.reject(b'{"model":"m","input":"\\ud800"}',
                    'invalid_field_value', 'input')
        self.reject(b'["model","input"]', 'invalid_request_body')
        self.reject(b'{"model":"m","input":"' + b'x' * MAX_BODY_BYTES + b'"}',
                    'body_too_large')

    def test_canonical_golden_vector(self):
        task = parse(body(model='co-auto', instructions='be terse',
            background=True, metadata={'b': '2', 'a': '1'}, input=[
            {'role': 'system', 'content': 'rules'},
            {'type': 'message', 'role': 'user', 'content': [
                {'type': 'input_text', 'text': 'u1'},
                {'type': 'input_text', 'text': 'u2'}]},
            {'role': 'assistant', 'content': 'prior'}]))
        expected = (
            '{"background":true,"input":['
            '{"content":"rules","role":"system","type":"message"},'
            '{"content":[{"text":"u1","type":"input_text"},'
            '{"text":"u2","type":"input_text"}],'
            '"role":"user","type":"message"},'
            '{"content":"prior","role":"assistant","type":"message"}],'
            '"instructions":"be terse","metadata":{"a":"1","b":"2"},'
            '"model":"co-auto","store":true}')
        self.assertEqual(task.canonical_body, expected.encode('utf-8'))
        self.assertEqual(task.body_hash,
            hashlib.sha256(DOMAIN + task.canonical_body).hexdigest())


if __name__ == '__main__':
    unittest.main()
