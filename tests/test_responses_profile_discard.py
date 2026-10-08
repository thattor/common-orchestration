"""Discard / unverifiable / auxiliary-terminal checker tests.

Fixtures are DERIVED synthetic envelopes — not provider proof or
qualification. Injected dicts only; no SDK, provider, network or IO.
Adapter-level terminal recognition, policy classification and the shared
_terminal_shape are owned separately and are not exercised here; the
existing strict tests in test_responses_profile.py remain mandatory.
"""
import unittest

from co_v4.protocol_profile import ProfileError, RouteProtocolProfile
from co_v4.responses_profile import MAX_TEXT, ProfileCap, SinglePartChecker

MODEL = 'co04-qwen3-06b'
RID = 'resp_fZVxXK88XVg7akORRHay3EZjQ4CvMTJT'
IID = 'msg_RKQ2lRIFOrXwxVqen2MKuD6BvPr03Qo4'


def profile(**kw):
    args = dict(protocol='responses', index_mode='absent_single_part',
                sequence_mode='absent', inert_fields={}, model=MODEL,
                provider_manifest_sha256='9' * 64)
    args.update(kw)
    return RouteProtocolProfile(**args)


def _item(text='4', status='completed'):
    return {'type': 'message', 'status': status, 'id': IID,
            'role': 'assistant',
            'content': [{'type': 'output_text', 'text': text}]}


def base_events():
    """Canonical successful one-part stream (DERIVED, not a capture)."""
    return [
        {'type': 'response.created', 'response': {
            'id': RID, 'object': 'response', 'status': 'in_progress'}},
        {'type': 'response.output_item.added', 'item': {
            'type': 'message', 'status': 'in_progress', 'id': IID,
            'role': 'assistant', 'content': []}},
        {'type': 'response.content_part.added', 'item_id': IID,
         'part': {'type': 'output_text', 'text': ''}},
        {'type': 'response.output_text.delta', 'item_id': IID,
         'delta': '4'},
        {'type': 'response.output_text.done', 'item_id': IID,
         'text': '4'},
        {'type': 'response.content_part.done', 'item_id': IID,
         'part': {'type': 'output_text', 'text': '4'}},
        {'type': 'response.output_item.done', 'item': _item()},
        {'type': 'response.completed', 'response': {
            'id': RID, 'object': 'response', 'status': 'completed',
            'model': MODEL, 'output': [_item()]}},
    ]


def failed(rid=RID, **kw):
    resp = {'id': rid, 'object': 'response', 'status': 'failed',
            'output': []}
    resp.update(kw)
    return {'type': 'response.failed', 'response': resp}


def incomplete(rid=RID, reason='max_output_tokens'):
    return {'type': 'response.incomplete', 'response': {
        'id': rid, 'object': 'response', 'status': 'incomplete',
        'output': [], 'incomplete_details': {'reason': reason}}}


def error_event(**kw):
    ev = {'type': 'error', 'code': 'server_error', 'message': 'boom',
          'param': None}
    ev.update(kw)
    return ev


def snapshot(c):
    return (c.terminal, c._phase, bytes(c._acc), c._rid, c._iid,
            c._in_progress, c._discard, c._unverifiable)


class AtomicCapTests(unittest.TestCase):
    def test_cap_atomic_then_discard_refeed_advances(self):
        c = SinglePartChecker(profile())
        for e in base_events()[:3]:
            c.feed(e)
        big = {'type': 'response.output_text.delta', 'item_id': IID,
               'delta': 'x' * (MAX_TEXT + 1)}
        before = snapshot(c)
        with self.assertRaises(ProfileCap):
            c.feed(big)
        self.assertEqual(before, snapshot(c))
        with self.assertRaises(ProfileCap):   # repeat cap, still clean
            c.feed(big)
        self.assertEqual(before, snapshot(c))
        self.assertIsNone(c.feed(big, discard=True))
        for e in base_events()[4:]:
            self.assertIsNone(c.feed(e))
        self.assertTrue(c.terminal)


class DiscardModeTests(unittest.TestCase):
    def test_discard_permanent_no_output(self):
        c = SinglePartChecker(profile())
        for i, e in enumerate(base_events()):
            self.assertIsNone(c.feed(e, discard=i == 0))
        self.assertTrue(c.terminal)

    def test_discard_skips_equality_keeps_structure(self):
        c = SinglePartChecker(profile())
        evs = base_events()
        for e in evs[:3]:
            c.feed(e)
        c.feed(evs[3], discard=True)
        for fn in (lambda e: e.update(alien=1),
                   lambda e: e.update(output_index=0),
                   lambda e: e.update(sequence_number=2),
                   lambda e: e.update(item_id='msg_other'),
                   lambda e: e.update(text=5)):
            bad = dict(evs[4])
            fn(bad)
            with self.assertRaises(ProfileError):
                c.feed(bad)
        evs[4]['text'] = 'ZZZ'   # byte inequality ignored in discard
        evs[5]['part']['text'] = 'ZZZ'
        evs[6]['item']['content'][0]['text'] = 'ZZZ'
        evs[7]['response']['output'][0]['content'][0]['text'] = 'ZZZ'
        for e in evs[4:]:
            self.assertIsNone(c.feed(e))
        self.assertTrue(c.terminal)

    def test_discard_strict_utf8_still_enforced(self):
        c = SinglePartChecker(profile())
        evs = base_events()
        for e in evs[:3]:
            c.feed(e)
        c.feed(evs[3], discard=True)
        for bad in ({'type': 'response.output_text.delta',
                     'item_id': IID, 'delta': '\ud800'},
                    {'type': 'response.output_text.done',
                     'item_id': IID, 'text': '\udfff'}):
            with self.assertRaises(ProfileError):
                c.feed(bad)
        self.assertEqual(c._phase, 3)   # rejected done did not advance
        self.assertIsNone(c.feed(evs[4]))


class UnverifiableTests(unittest.TestCase):
    def test_dropped_item_added_adopts_iid_then_mismatch(self):
        c = SinglePartChecker(profile())
        c.mark_unverifiable()
        evs = base_events()
        self.assertIsNone(c.feed(evs[2]))   # part.added adopts iid
        self.assertIsNone(c.feed(evs[3]))
        with self.assertRaises(ProfileError):   # known iid now enforced
            c.feed({'type': 'response.output_text.delta',
                    'item_id': 'msg_other', 'delta': 'x'})

    def test_dropped_created_adopts_rid_then_mismatch(self):
        c = SinglePartChecker(profile())
        c.mark_unverifiable()
        self.assertIsNone(c.feed({'type': 'response.in_progress',
            'response': {'id': 'resp_a', 'status': 'in_progress'}}))
        with self.assertRaises(ProfileError):
            c.feed(failed(rid='resp_b'))
        self.assertFalse(c.terminal)

    def test_missing_phases_ok_earlier_phase_and_index_fail(self):
        evs = base_events()
        c = SinglePartChecker(profile())
        c.mark_unverifiable()
        # item.added and text.done dropped: not violations per se
        for e in (evs[0], evs[2], evs[3], evs[5], evs[6], evs[7]):
            self.assertIsNone(c.feed(e))
        self.assertTrue(c.terminal)

        c = SinglePartChecker(profile())
        c.mark_unverifiable()
        for e in evs[:6]:
            c.feed(e)
        with self.assertRaises(ProfileError):   # earlier-phase delta
            c.feed(evs[3])
        with self.assertRaises(ProfileError):   # second part.added
            c.feed(dict(evs[2]))
        bad = dict(evs[3])
        bad['output_index'] = 0                 # positive observed index
        with self.assertRaises(ProfileError):
            c.feed(bad)

    def test_unverifiable_strict_utf8_still_enforced(self):
        c = SinglePartChecker(profile())
        c.mark_unverifiable()
        evs = base_events()
        for e in evs[:4]:
            c.feed(e)
        for bad in ({'type': 'response.output_text.delta',
                     'item_id': IID, 'delta': '\ud800'},
                    {'type': 'response.output_text.done',
                     'item_id': IID, 'text': '\udfff'}):
            with self.assertRaises(ProfileError):
                c.feed(bad)
        self.assertEqual(c._phase, 3)   # rejected done did not advance
        self.assertIsNone(c.feed(evs[4]))         # real done advances
        with self.assertRaises(ProfileError):     # part.done surrogate
            c.feed({'type': 'response.content_part.done',
                    'item_id': IID,
                    'part': {'type': 'output_text', 'text': '\ud800'}})
        self.assertIsNone(c.feed(evs[5]))
        for e in evs[6:]:
            self.assertIsNone(c.feed(e))
        self.assertTrue(c.terminal)


class AuxTerminalTests(unittest.TestCase):
    def test_valid_aux_terminals_at_phase1(self):
        cases = [
            failed(),
            failed(error={'code': 'server_error', 'message': 'boom'}),
            failed(error=None),
            incomplete(),
            incomplete(reason='content_filter'),
            incomplete(reason='max_tool_calls'),
            {'type': 'response.incomplete', 'response': {
                'id': RID, 'status': 'incomplete', 'output': [],
                'incomplete_details': None}},
            error_event(),
            error_event(code=None, param='temperature'),
        ]
        for term in cases:
            with self.subTest(term=term):
                c = SinglePartChecker(profile())
                c.feed(base_events()[0])
                self.assertIsNone(c.feed(term))
                self.assertTrue(c.terminal)
                with self.assertRaises(ProfileError):   # no replay
                    c.feed(term)

    def test_aux_at_phase0_needs_unverifiable(self):
        for term in (failed(), incomplete(), error_event()):
            with self.subTest(term=term['type']):
                with self.assertRaises(ProfileError):
                    SinglePartChecker(profile()).feed(term)
                c = SinglePartChecker(profile())
                c.mark_unverifiable()
                self.assertIsNone(c.feed(term))
                self.assertTrue(c.terminal)

    def test_aux_output_item_shape(self):
        ok = {'type': 'message', 'id': IID, 'role': 'assistant',
              'status': 'incomplete',
              'content': [{'type': 'refusal', 'refusal': 'no'}]}
        c = SinglePartChecker(profile())
        for e in base_events()[:2]:
            c.feed(e)
        self.assertIsNone(c.feed(failed(output=[ok])))
        self.assertTrue(c.terminal)
        bad_items = [
            [ok, ok],                                  # second item
            [dict(ok, status='queued')],
            [dict(ok, role='user')],
            [dict(ok, id='msg_other')],
            [dict(ok, content=[{'type': 'output_text', 'text': 'a'},
                               {'type': 'output_text', 'text': 'b'}])],
            [dict(ok, content=[{'type': 'refusal',
                               'refusal': '\ud800'}])],
            [dict(ok, content=[{'type': 'output_text',
                               'text': '\ud800'}])],
            [dict(ok, content=[{'type': 'function_call'}])],
        ]
        for out in bad_items:
            with self.subTest(out=out):
                c = SinglePartChecker(profile())
                for e in base_events()[:2]:
                    c.feed(e)
                with self.assertRaises(ProfileError):
                    c.feed(failed(output=out))
                self.assertFalse(c.terminal)

    def test_error_message_utf8_on_all_carriers(self):
        # error.message is strict-UTF8 even on a non-failed status
        c = SinglePartChecker(profile())
        with self.assertRaises(ProfileError):
            c.feed({'type': 'response.created', 'response': {
                'id': RID, 'status': 'in_progress',
                'error': {'code': 'x', 'message': '\ud800'}}})
        self.assertFalse(c.terminal)
        c = SinglePartChecker(profile())
        c.feed(base_events()[0])
        with self.assertRaises(ProfileError):
            c.feed(failed(error={'code': 'x', 'message': '\ud800'}))
        self.assertFalse(c.terminal)
        c = SinglePartChecker(profile())
        c.feed(base_events()[0])
        with self.assertRaises(ProfileError):
            c.feed(error_event(message='\ud800'))
        self.assertFalse(c.terminal)

    def test_malformed_aux_never_terminal(self):
        cases = [
            failed(error='boom'),
            failed(error={'code': 1, 'message': 'm'}),
            failed(error={'message': 5}),
            failed(error={'code': None, 'message': 'm', 'alien': 1}),
            dict(failed(), response={'id': RID, 'status': 'incomplete',
                                     'output': []}),
            failed(rid='resp_other'),
            failed(model='other-model'),
            failed(output={}),
            incomplete(reason='bogus_reason'),
            incomplete(reason=None),
            {'type': 'response.incomplete', 'response': {
                'id': RID, 'status': 'incomplete', 'output': [],
                'incomplete_details': 'x'}},
            {'type': 'response.failed', 'response': 'x'},
            {'type': 'error', 'code': 'c', 'message': 5, 'param': None},
            {'type': 'error', 'code': 'c', 'message': 'm'},
            {'type': 'error', 'code': 'c', 'message': 'm', 'param': 1},
            dict(error_event(), alien=1),
        ]
        for term in cases:
            with self.subTest(term=term):
                c = SinglePartChecker(profile())
                c.feed(base_events()[0])
                with self.assertRaises(ProfileError):
                    c.feed(term)
                self.assertFalse(c.terminal)

    def test_forbidden_presence_on_aux(self):
        for term in (dict(failed(), sequence_number=1),
                     dict(failed(), output_index=0),
                     dict(error_event(), content_index=0)):
            with self.subTest(term=term['type']):
                c = SinglePartChecker(profile())
                c.feed(base_events()[0])
                with self.assertRaises(ProfileError):
                    c.feed(term)
                self.assertFalse(c.terminal)
        prof = profile(inert_fields={'response.failed': ('timings',)})
        c = SinglePartChecker(prof)
        c.feed(base_events()[0])
        self.assertIsNone(c.feed(dict(failed(), timings={})))
        self.assertTrue(c.terminal)
        c = SinglePartChecker(profile())
        c.feed(base_events()[0])
        with self.assertRaises(ProfileError):   # unlisted key rejects
            c.feed(dict(failed(), timings={}))

    def test_ordinary_part_stays_exactly_typed(self):
        c = SinglePartChecker(profile())
        evs = base_events()
        for e in evs[:5]:
            c.feed(e)
        with self.assertRaises(ProfileError):   # refusal part off-vocab
            c.feed({'type': 'response.content_part.done',
                    'item_id': IID,
                    'part': {'type': 'refusal', 'refusal': 'x'}})


if __name__ == '__main__':
    unittest.main()
