"""Terminal-proof matrix across strict qualified and generic edges.

Strict frames reuse the qualified absent_single_part fixture through the
real QualifiedRouteGate; generic frames reuse the pinned openai==3.24.0
SDK models. No binding profile is hand-assigned in this file.
"""
import copy
import unittest

try:
    import test_openai_adapters as G
    import test_strict_responses_adapter as S
except ImportError:                                # package test layout
    from tests import test_openai_adapters as G
    from tests import test_strict_responses_adapter as S


class StrictTerminalMatrixTests(unittest.TestCase):
    def check(self, script):
        adapter, req, transport = S.build(script)
        self.assertEqual(adapter.execute(req).status,
                         S.OperationStatus.ACCEPTED)
        for _ in range(60):
            state = adapter.status(req.ref).state
            if state in S.TERMINALS:
                return adapter, req, transport, state
        raise AssertionError('no terminal state')

    def reason(self, adapter, req):
        return next(e.result.reason for e in adapter.events(req.ref)
                    if type(e) is S.ResultEvent)

    def drain(self, term):
        return self.check(S.frames(S.stream()[:4] + [term])
                          + [S.StreamEnded()])

    def test_failure_strings_surrogates_semantic_confirmed(self):
        terms = []
        for key in ('code', 'param', 'message'):
            term = S.aux('error', None)
            term[key] = 'x\ud800'
            terms.append(term)
        terms += [S.aux('response.failed', 'failed',
                        error={'code': 'x\ud800', 'message': 'm'}),
                  S.aux('response.failed', 'failed',
                        error={'code': None, 'message': 'x\ud800'}),
                  S.aux('response.incomplete', 'incomplete',
                        incomplete_details={'reason': 'x\ud800'})]
        for index, term in enumerate(terms):
            with self.subTest(index=index):
                adapter, req, _, _ = self.drain(term)
                self.assertEqual(self.reason(adapter, req),
                                 'protocol_violation')
                self.assertEqual(adapter.stop(req.ref).status,
                                 S.StopStatus.CONFIRMED)
                with self.assertRaises(S.CollectionError):
                    adapter.collect_output(req.ref)

    def test_malformed_terminal_core_unconfirmed(self):
        bad_code = S.aux('error', None); bad_code['code'] = 7
        no_param = S.aux('error', None); del no_param['param']
        bad_err = S.aux('response.failed', 'failed',
                        error={'code': 7, 'message': 'm'})
        bad_out = S.aux('response.failed', 'failed')
        bad_out['response']['output'] = 'x'
        bad_det = S.aux('response.incomplete', 'incomplete',
                        incomplete_details={'reason': 7})
        alien = S.aux('response.failed', 'failed'); alien['alien'] = 1
        terms = (bad_code, no_param, bad_err, bad_out, bad_det, alien)
        for index, term in enumerate(terms):
            with self.subTest(index=index):
                adapter, req, _, _ = self.drain(term)
                self.assertEqual(self.reason(adapter, req),
                                 'protocol_violation')
                self.assertEqual(adapter.stop(req.ref).status,
                                 S.StopStatus.UNCONFIRMED)
                with self.assertRaises(S.CollectionError):
                    adapter.collect_output(req.ref)

    def test_identity_surrogates_core_unconfirmed(self):
        for key in ('id', 'model'):
            evs = copy.deepcopy(S.stream())
            evs[-1]['response'][key] = 'x\ud800'
            adapter, req, _, state = self.check(
                S.frames(evs) + [S.StreamEnded()])
            self.assertEqual((state, self.reason(adapter, req)),
                             (S.State.FAILED, 'protocol_violation'))
            self.assertEqual(adapter.stop(req.ref).status,
                             S.StopStatus.UNCONFIRMED)
            with self.assertRaises(S.CollectionError):
                adapter.collect_output(req.ref)

    def test_strict_ordinary_one_post_poll_stop(self):
        adapter, req, transport, state = self.check(
            S.frames(S.stream()) + [S.StreamEnded()])
        self.assertEqual(state, S.State.COMPLETED)
        adapter.status(req.ref)
        adapter.events(req.ref)
        self.assertEqual(adapter.stop(req.ref).status,
                         S.StopStatus.CONFIRMED)
        self.assertEqual(transport.open_calls, 1)

    def test_profile_cap_atomic_permanent_no_output(self):
        big = dict(S.stream()[3], delta='x' * (S.MAX_TEXT + 1))
        adapter, req, _, _ = self.check(
            S.frames(S.stream()[:3] + [big] + S.stream()[4:])
            + [S.StreamEnded()])
        self.assertEqual(self.reason(adapter, req),
                         'output_limit_exceeded')
        self.assertEqual(adapter.stop(req.ref).status,
                         S.StopStatus.CONFIRMED)
        with self.assertRaises(S.CollectionError):
            adapter.collect_output(req.ref)
        attempt = adapter._attempts[req.ref]
        self.assertTrue(attempt.proto['limited'])
        self.assertIsNone(attempt.proto.get('strict_parts'))
        checker = attempt.proto['checker']
        self.assertEqual(checker._acc, bytearray())
        self.assertTrue(checker._discard)
        self.assertTrue(checker.terminal)

    def test_drop_then_wrong_rid_unconfirmed(self):
        term = copy.deepcopy(S.stream()[-1])
        term['response']['id'] = 'resp_o'
        adapter, req, _, _ = self.check(
            S.frames(S.stream()[:3])
            + [S.StreamCapped('output_limit_exceeded')]
            + S.frames(S.stream()[4:7] + [term]) + [S.StreamEnded()])
        self.assertEqual(self.reason(adapter, req),
                         'protocol_violation')
        self.assertEqual(adapter.stop(req.ref).status,
                         S.StopStatus.UNCONFIRMED)
        with self.assertRaises(S.CollectionError):
            adapter.collect_output(req.ref)


class GenericTerminalMatrixTests(unittest.TestCase):
    def exercise(self, script, **kw):
        adapter, req, _, _ = G.build(G.OpenAIResponsesAdapter, script, **kw)
        self.assertEqual(adapter.execute(req).status,
                         G.OperationStatus.ACCEPTED)
        return adapter, req, G.finish(adapter, req.ref)

    def term(self, s, **kw):
        return {'type': 'response.completed', 'sequence_number': s.n(),
                'response': G.resp('completed',
                                   output=[G.message([G.text_part('x')])],
                                   **kw).model_dump()}

    def expect_protocol_confirmed(self, adapter, req, state):
        self.assertEqual((state, G.result(adapter, req.ref).reason),
                         (G.State.FAILED, 'protocol_violation'))
        self.assertEqual(adapter.stop(req.ref).status,
                         G.StopStatus.CONFIRMED)
        with self.assertRaises(G.CollectionError):
            adapter.collect_output(req.ref)

    def test_terminal_sequence_marked_never_shape(self):
        s = G.Script()          # violation lands on the terminal itself
        adapter, req, state = self.exercise(
            [[G.StreamStarted(200), s.created(seq=2),
              s.completed(output=[G.message([G.text_part('x')])], seq=1),
              G.StreamEnded()]])
        self.expect_protocol_confirmed(adapter, req, state)
        s = G.Script()          # field wholly absent on a required route
        noseq = G.ev_noseq(G.R.ResponseCompletedEvent(
            response=G.resp('completed',
                            output=[G.message([G.text_part('x')])]),
            sequence_number=0, type='response.completed'))
        adapter, req, state = self.exercise(
            [[G.StreamStarted(200), s.created(), noseq, G.StreamEnded()]])
        self.expect_protocol_confirmed(adapter, req, state)
        s = G.Script()          # mistyped field on the terminal frame
        bad = self.term(s); bad['sequence_number'] = 'nine'
        adapter, req, state = self.exercise(
            [[G.StreamStarted(200), s.created(),
              G.raw('response.completed', bad), G.StreamEnded()]])
        self.expect_protocol_confirmed(adapter, req, state)

    def test_terminal_nested_surrogate_confirmed_no_output(self):
        s = G.Script()
        term = self.term(s)
        term['response']['output'][0]['content'][0]['text'] = 'x\ud800'
        adapter, req, state = self.exercise(
            [[G.StreamStarted(200), s.created(),
              G.raw('response.completed', term), G.StreamEnded()]])
        self.expect_protocol_confirmed(adapter, req, state)

    def test_terminal_core_surrogates_unconfirmed(self):
        for key in ('id', 'model'):
            s = G.Script()
            term = self.term(s)
            term['response'][key] = 'x\ud800'
            adapter, req, state = self.exercise(
                [[G.StreamStarted(200), s.created(),
                  G.raw('response.completed', term), G.StreamEnded()]])
            self.assertEqual((state, G.result(adapter, req.ref).reason),
                             (G.State.FAILED, 'protocol_violation'))
            self.assertEqual(adapter.stop(req.ref).status,
                             G.StopStatus.UNCONFIRMED)

    def test_terminal_done_name_and_count(self):
        for name in ('', 'message'):
            s = G.Script()
            _, req_unused, state = self.exercise(
                [[G.StreamStarted(200),
                  s.completed(output=[G.message([G.text_part('x')])]),
                  G.SseMessage(name, '[DONE]'), G.StreamEnded()]],
                allow_done=True)
            self.assertEqual(state, G.State.COMPLETED)
        for tail in ([G.SseMessage('response.completed', '[DONE]')],
                     [G.SseMessage('', '[DONE]'),
                      G.SseMessage('', '[DONE]')]):
            s = G.Script()
            adapter, req, _ = self.exercise(
                [[G.StreamStarted(200),
                  s.completed(output=[G.message([G.text_part('x')])])]
                 + tail + [G.StreamEnded()]], allow_done=True)
            self.assertEqual(G.result(adapter, req.ref).reason,
                             'protocol_violation')
            self.assertEqual(adapter.stop(req.ref).status,
                             G.StopStatus.UNCONFIRMED)


class ChatDoneMatrixTests(unittest.TestCase):
    def test_missing_done_or_finish_no_completed_no_output(self):
        for tail in ([], [G.SseMessage('message', '[DONE]')]):
            adapter, req, _, _ = G.build(
                G.OpenAIChatAdapter,
                [[G.StreamStarted(200), G.chunk({'content': 'x'})]
                 + list(tail) + [G.StreamEnded()]])
            self.assertEqual(adapter.execute(req).status,
                             G.OperationStatus.ACCEPTED)
            self.assertEqual(G.finish(adapter, req.ref), G.State.ERROR)
            self.assertEqual(G.result(adapter, req.ref).reason,
                             'transport_eof')
            self.assertEqual(adapter.stop(req.ref).status,
                             G.StopStatus.UNCONFIRMED)
            with self.assertRaises(G.CollectionError):
                adapter.collect_output(req.ref)

    def test_finish_stop_then_eof_without_done_completes(self):
        # finish_reason is the terminal; [DONE] is optional post-terminal.
        adapter, req, _, _ = G.build(
            G.OpenAIChatAdapter,
            [[G.StreamStarted(200), G.chunk({'content': 'x'}, 'stop'),
              G.StreamEnded()]])
        self.assertEqual(adapter.execute(req).status,
                         G.OperationStatus.ACCEPTED)
        self.assertEqual(G.finish(adapter, req.ref), G.State.COMPLETED)
        self.assertEqual([i.text for i in adapter.collect_output(req.ref)],
                         ['x'])
        self.assertEqual(adapter.stop(req.ref).status,
                         G.StopStatus.CONFIRMED)


if __name__ == '__main__':
    unittest.main()
