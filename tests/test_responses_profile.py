"""Strict absent_single_part checker tests.

RAW is the exact public llama.cpp SSE task capture (9 events); its sha256
is asserted and it is decoded with the real SseDecoder + strict_json.
All other fixtures are DERIVED mutations — not proof or qualification.
Injected dicts only; no SDK, provider, network or IO here.
"""
import copy
import hashlib
import unittest

from co_v4.openai_transport import SseDecoder, strict_json
from co_v4.protocol_profile import ProfileError, RouteProtocolProfile
from co_v4.responses_profile import MAX_TEXT, ProfileCap, SinglePartChecker

RID = 'resp_fZVxXK88XVg7akORRHay3EZjQ4CvMTJT'
IID = 'msg_RKQ2lRIFOrXwxVqen2MKuD6BvPr03Qo4'
RAW = b'''event: response.created
data: {"type":"response.created","response":{"id":"resp_fZVxXK88XVg7akORRHay3EZjQ4CvMTJT","object":"response","status":"in_progress"}}

event: response.in_progress
data: {"type":"response.in_progress","response":{"id":"resp_fZVxXK88XVg7akORRHay3EZjQ4CvMTJT","object":"response","status":"in_progress"}}

event: response.output_item.added
data: {"type":"response.output_item.added","item":{"content":[],"id":"msg_RKQ2lRIFOrXwxVqen2MKuD6BvPr03Qo4","role":"assistant","status":"in_progress","type":"message"}}

event: response.content_part.added
data: {"type":"response.content_part.added","item_id":"msg_RKQ2lRIFOrXwxVqen2MKuD6BvPr03Qo4","part":{"type":"output_text","text":""}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_RKQ2lRIFOrXwxVqen2MKuD6BvPr03Qo4","delta":"4"}

event: response.output_text.done
data: {"type":"response.output_text.done","item_id":"msg_RKQ2lRIFOrXwxVqen2MKuD6BvPr03Qo4","text":"4"}

event: response.content_part.done
data: {"type":"response.content_part.done","item_id":"msg_RKQ2lRIFOrXwxVqen2MKuD6BvPr03Qo4","part":{"type":"output_text","annotations":[],"logprobs":[],"text":"4"}}

event: response.output_item.done
data: {"type":"response.output_item.done","item":{"type":"message","status":"completed","id":"msg_RKQ2lRIFOrXwxVqen2MKuD6BvPr03Qo4","content":[{"type":"output_text","annotations":[],"logprobs":[],"text":"4"}],"role":"assistant"}}

event: response.completed
data: {"type":"response.completed","response":{"id":"resp_fZVxXK88XVg7akORRHay3EZjQ4CvMTJT","object":"response","created_at":1791299437,"status":"completed","model":"co04-qwen3-06b","output":[{"type":"message","status":"completed","id":"msg_RKQ2lRIFOrXwxVqen2MKuD6BvPr03Qo4","content":[{"type":"output_text","annotations":[],"logprobs":[],"text":"4"}],"role":"assistant"}],"usage":{"input_tokens":23,"output_tokens":2,"total_tokens":25,"input_tokens_details":{"cached_tokens":22}}},"timings":{"cache_n":22,"prompt_n":1,"prompt_ms":39.679,"prompt_per_token_ms":39.679,"prompt_per_second":25.202248040525213,"predicted_n":2,"predicted_ms":11.428,"predicted_per_token_ms":11.428,"predicted_per_second":87.50437521876093}}

'''
RAW_SHA = '27ea06ad61ee40f11282a7d1f301f3f0327be725d898f5a2844f59fe12b6103c'


def profile(**kw):
    args = dict(protocol='responses', index_mode='absent_single_part',
        sequence_mode='absent',
        inert_fields={'response.completed': ('timings',)},
        model='co04-qwen3-06b', provider_manifest_sha256='9' * 64)
    args.update(kw)
    return RouteProtocolProfile(**args)


def events():   # DERIVED from RAW, deep-copied per call
    dec = SseDecoder()
    msgs = dec.feed(RAW) + list(dec.finish())
    return [strict_json(m.data) for m in msgs]


def run(evs, prof=None):
    c = SinglePartChecker(prof or profile())
    out = None
    for e in copy.deepcopy(evs):
        out = c.feed(e)
    return out, c


def mutate(index, fn):
    evs = events()
    fn(evs[index])
    return evs


class CheckerConstructionTests(unittest.TestCase):
    def test_only_qualified_profile_admitted(self):
        for bad in (dict(protocol='chat', index_mode='present',
                         sequence_mode='present'),
                    dict(index_mode='present'),
                    dict(sequence_mode='present')):
            with self.subTest(bad=bad):
                with self.assertRaises(ProfileError):
                    SinglePartChecker(profile(**bad))
        with self.assertRaises(ProfileError):
            SinglePartChecker(object())


class StrictOrderTests(unittest.TestCase):
    def test_exact_raw_capture_hash_and_pass(self):
        self.assertEqual(hashlib.sha256(RAW).hexdigest(), RAW_SHA)
        out, c = run(events())
        self.assertEqual(out, ('4',))
        self.assertTrue(c.terminal)

    def test_optional_in_progress_and_zero_deltas(self):
        evs = events()
        del evs[1]                          # in_progress optional
        out, _ = run(evs)
        self.assertEqual(out, ('4',))
        evs = events()
        del evs[4]                          # zero deltas: all surfaces ''
        evs[4]['text'] = ''
        evs[5]['part']['text'] = ''
        evs[6]['item']['content'][0]['text'] = ''
        evs[7]['response']['output'][0]['content'][0]['text'] = ''
        out, _ = run(evs)
        self.assertEqual(out, ('',))

    def test_order_violations_reject(self):
        cases = [mutate(1, lambda e: e.update(type='response.queued')),
                 events()[:5] + events()[6:],        # missing text.done
                 events()[:6] + events()[7:8] + events()[6:7] + events()[8:],
                 events() + [events()[0]],           # feed after terminal
                 events()[:3] + events()[2:3] + events()[3:],
                 events()[:2] + events()[1:2] + events()[2:]]   # dup prog
        for evs in cases:
            with self.subTest(evs=[e['type'] for e in evs]):
                with self.assertRaises(ProfileError):
                    run(evs)


class IdentityAndShapeTests(unittest.TestCase):
    def test_identity_bindings(self):
        for index, fn in (
            (4, lambda e: e.update(item_id='msg_other')),
            (7, lambda e: e['item'].update(id='msg_other')),
            (8, lambda e: e['response'].update(id='resp_other')),
            (8, lambda e: e['response'].update(model='other-model')),
            (0, lambda e: e['response'].update(model='other-model')),
            (0, lambda e: e['response'].update(status='queued')),
        ):
            with self.subTest(index=index):
                with self.assertRaises(ProfileError):
                    run(mutate(index, fn))
        # A validly-mismatched served model constructs but fails on wire.
        with self.assertRaises(ProfileError):
            run(events(), profile(model='other-model'))

    def test_forbidden_and_required_keys(self):
        for index in (2, 3, 4, 5, 7, 8):
            with self.subTest(index=index):
                with self.assertRaises(ProfileError):
                    run(mutate(index, lambda e: e.update(output_index=0)))
        for fn in (lambda e: e.update(sequence_number=1),
                   lambda e: e.pop('item_id'), lambda e: e.pop('delta')):
            with self.subTest(fn=fn):
                with self.assertRaises(ProfileError):
                    run(mutate(4, fn))
        # Forbidden keys reject even when pinned in the allowlist.
        prof = profile(inert_fields={'response.output_text.delta':
                                     ('output_index',)})
        with self.assertRaises(ProfileError):
            run(mutate(4, lambda e: e.update(output_index=0)), prof)
        with self.assertRaises(ProfileError):   # unhashable event type
            run([{'type': ['x']}])

    def test_nontext_and_second_reject(self):
        evs = events()
        evs[3]['part'] = {'type': 'refusal', 'refusal': 'x'}
        with self.assertRaises(ProfileError):
            run(evs)
        evs = events()
        evs[3]['part']['text'] = 'prefilled'    # prefix not from deltas
        with self.assertRaises(ProfileError):
            run(evs)
        evs = events()
        evs[8]['response']['output'][0]['content'].append(
            {'type': 'output_text', 'text': '4'})
        with self.assertRaises(ProfileError):
            run(evs)
        evs = events()
        evs[8]['response']['output'].append(
            dict(evs[8]['response']['output'][0]))
        with self.assertRaises(ProfileError):
            run(evs)
        evs = events()
        evs[8]['response']['output'][0]['type'] = 'function_call'
        with self.assertRaises(ProfileError):
            run(evs)


class NestedShapeTests(unittest.TestCase):
    def test_nonfinite_and_negative_reject(self):
        for index, fn in (
            (8, lambda e: e['response'].update(created_at=1e400)),
            (8, lambda e: e['response'].update(temperature=-1.5)),
            (8, lambda e: e['response'].update(top_p=float('inf'))),
            (8, lambda e: e['response'].update(
                usage={'input_tokens': -5})),
            (8, lambda e: e['response'].update(max_output_tokens=-1)),
        ):
            with self.subTest(index=index):
                with self.assertRaises(ProfileError):
                    run(mutate(index, fn))

    def test_huge_integer_numeric_bounded(self):
        # Mathematically finite ints are exact: no float coercion, no
        # OverflowError, accepted by the closed numeric shape.
        out, _ = run(mutate(8, lambda e: e['response'].update(
            created_at=10 ** 1000)))
        self.assertEqual(out, ('4',))
        with self.assertRaises(ProfileError):
            run(mutate(8, lambda e: e['response'].update(
                created_at=-(10 ** 1000))))

    def test_closed_nested_values(self):
        for index, fn in (
            (8, lambda e: e['response'].update(usage={'alien': 'x'})),
            (8, lambda e: e['response'].update(
                usage={'input_tokens': 1, 'extra': 1})),
            (8, lambda e: e['response'].update(tools=[{'type': 'x'}])),
            (8, lambda e: e['response'].update(reasoning={'effort': 'x'})),
            (8, lambda e: e['response'].update(metadata={1: 'x'})),
            (8, lambda e: e['response'].update(alien=1)),
            (7, lambda e: e['item'].update(alien=1)),
            (5, lambda e: e.update(text=5)),
        ):
            with self.subTest(index=index):
                with self.assertRaises(ProfileError):
                    run(mutate(index, fn))
        evs = events()   # standard harmless fields still admitted
        evs[8]['response'].update(metadata={'k': 'v'}, tool_choice='none',
                                  tools=[])
        out, _ = run(evs)
        self.assertEqual(out, ('4',))


class TextAgreementTests(unittest.TestCase):
    def test_all_four_surfaces_must_equal_deltas(self):
        for index, fn in (
            (5, lambda e: e.update(text='5')),
            (6, lambda e: e['part'].update(text='5')),
            (7, lambda e: e['item']['content'][0].update(text='5')),
            (8, lambda e: e['response']['output'][0]['content'][0]
                .update(text='5')),
        ):
            with self.subTest(index=index):
                with self.assertRaises(ProfileError):
                    run(mutate(index, fn))

    def test_utf8_exact(self):
        evs = events()
        evs[4] = dict(evs[4], delta='caf')
        evs.insert(5, dict(evs[4], delta='é ☃'))   # clone the DELTA event
        evs[6]['text'] = 'café ☃'
        evs[7]['part']['text'] = 'café ☃'
        evs[8]['item']['content'][0]['text'] = 'café ☃'
        evs[9]['response']['output'][0]['content'][0]['text'] = 'café ☃'
        out, _ = run(evs)
        self.assertEqual(out, ('café ☃',))
        evs[6]['text'] = 'café ☃'   # combining acute: different bytes
        with self.assertRaises(ProfileError):
            run(evs)

    def test_surrogate_text_rejects(self):
        for index, fn in (
            (4, lambda e: e.update(delta='\ud800')),
            (5, lambda e: e.update(text='\ud800')),
        ):
            with self.subTest(index=index):
                with self.assertRaises(ProfileError):
                    run(mutate(index, fn))

    def test_text_cap_is_nonpolicy(self):
        with self.assertRaises(ProfileCap):
            run(mutate(4, lambda e: e.update(delta='x' * (MAX_TEXT + 1))))


class InertKeyTests(unittest.TestCase):
    def test_allowlist_is_per_event(self):
        out, _ = run(events())               # timings allowed on completed
        self.assertEqual(out, ('4',))
        for index in (0, 4, 7):
            with self.subTest(index=index):
                with self.assertRaises(ProfileError):
                    run(mutate(index, lambda e: e.update(timings={})))


if __name__ == '__main__':
    unittest.main()
