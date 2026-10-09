"""Focused turn/start stage-gate tests over the real RPCTracker."""

import unittest
from unittest import mock

from co_v4.adapters.codex import NativeError
from co_v4.codex_rpc_sequence import INVALID, CodexRPCSequence

THREAD_ID = 't-1'


def drive_to_thread_ready(seq):
    seq.record_outgoing({'id': 1, 'method': 'initialize', 'params': {}})
    seq.consume_response({'id': 1, 'result': {'userAgent': 'ua'}})
    seq.record_outgoing({'method': 'initialized', 'jsonrpc': '2.0'})
    seq.record_outgoing({'id': 'thr', 'method': 'thread/start', 'params': {}})
    seq.consume_response({'id': 'thr', 'result': {'thread': {'id': THREAD_ID}}})


def turn_message(request_id=7):
    return {'id': request_id, 'method': 'turn/start',
            'params': {'threadId': THREAD_ID}}


def reply_frame(request_id, result):
    return {'id': request_id, 'result': result}


def good_turn_result():
    return {'turn': {'id': 'turn-1', 'status': 'inProgress', 'items': []}}


class TurnStartGateTest(unittest.TestCase):

    def test_ctor_defaults_no_clock_call(self):
        clock = mock.Mock(return_value=1.0)
        seq = CodexRPCSequence(clock=clock)
        clock.assert_not_called()
        self.assertEqual(seq.stage, 'new')
        self.assertEqual(seq.turn_submissions, 0)
        self.assertIsNone(seq.turn_write_attempt_at)
        self.assertFalse(seq.turn_rpc_confirmed)
        self.assertIsNone(seq.turn_id)
        self.assertIsNone(seq.error)
        with self.assertRaises(NativeError):
            CodexRPCSequence(clock=object())
        with self.assertRaises(NativeError):
            seq.record_outgoing('turn/start')
        self.assertEqual(seq.turn_submissions, 0)

    def test_full_sequence_probe_then_turn(self):
        clock = mock.Mock(return_value=42.5)
        seq = CodexRPCSequence(clock=clock)
        drive_to_thread_ready(seq)
        seq.record_outgoing({'id': 'probe', 'method': 'model/list', 'params': {}})
        method, _ = seq.consume_response(reply_frame('probe', {}))
        self.assertEqual(method, 'model/list')
        seq.record_outgoing(turn_message('req-9'))
        self.assertEqual((seq.turn_submissions, seq.stage), (1, 'turn_pending'))
        # The stamp observes the write attempt only, not a completed write.
        self.assertEqual(seq.turn_write_attempt_at, 42.5)
        result = good_turn_result()
        result['error'] = None
        result['turn']['items'] = [{'i': 1}]
        method, _ = seq.consume_response(reply_frame('req-9', result))
        self.assertEqual(method, 'turn/start')
        self.assertEqual(seq.turn_id, 'turn-1')
        self.assertTrue(seq.turn_rpc_confirmed)
        self.assertEqual(seq.stage, 'turn_replied')
        self.assertFalse(hasattr(seq, 'turn_items'))

    def test_turn_before_thread_ready_stamps_then_refuses(self):
        seq = CodexRPCSequence(clock=mock.Mock(return_value=1.0))
        seq.record_outgoing({'id': 1, 'method': 'initialize', 'params': {}})
        seq.consume_response({'id': 1, 'result': {'userAgent': 'ua'}})
        seq.record_outgoing({'method': 'initialized'})
        with self.assertRaises(NativeError):
            seq.record_outgoing(turn_message())
        self.assertEqual(seq.error, INVALID)
        self.assertEqual(seq.turn_submissions, 1)
        self.assertEqual(seq.turn_write_attempt_at, 1.0)
        self.assertEqual(seq.pending_rpc_count, 0)

    def test_turn_with_pending_probe_refuses(self):
        seq = CodexRPCSequence(clock=lambda: 2.0)
        drive_to_thread_ready(seq)
        seq.record_outgoing({'id': 4, 'method': 'model/list', 'params': {}})
        with self.assertRaises(NativeError):
            seq.record_outgoing(turn_message())
        self.assertEqual(seq.error, INVALID)
        self.assertEqual(seq.pending_rpc_count, 1)
        self.assertEqual(seq.turn_write_attempt_at, 2.0)

    def test_probe_during_turn_pending_refuses_state_retained(self):
        clock = mock.Mock(return_value=3.25)
        seq = CodexRPCSequence(clock=clock)
        drive_to_thread_ready(seq)
        seq.record_outgoing(turn_message())
        with self.assertRaises(NativeError):
            seq.record_outgoing({'id': 8, 'method': 'model/list', 'params': {}})
        self.assertEqual(seq.error, INVALID)
        self.assertEqual((seq.turn_submissions, seq.turn_write_attempt_at),
                         (1, 3.25))
        self.assertEqual(clock.call_count, 1)

    def test_bad_params_refuse(self):
        bad = [None, 'nope', {}, {'threadId': 'other'}, {'threadId': ''},
               {'threadId': 7}, {'threadId': 'x' * 1100}]
        for params in bad:
            with self.subTest(params=params):
                seq = CodexRPCSequence(clock=lambda: 5.0)
                drive_to_thread_ready(seq)
                msg = turn_message(9)
                if params is None:
                    del msg['params']
                else:
                    msg['params'] = params
                with self.assertRaises(NativeError):
                    seq.record_outgoing(msg)
                self.assertEqual(seq.error, INVALID)
                self.assertEqual(seq.pending_rpc_count, 0)

    def test_clock_rejection_sticky_without_resample(self):
        for bad in (float('nan'), float('inf'), -1.0, True, 'x', None):
            with self.subTest(bad=bad):
                clock = mock.Mock(return_value=bad)
                seq = CodexRPCSequence(clock=clock)
                drive_to_thread_ready(seq)
                with self.assertRaises(NativeError):
                    seq.record_outgoing(turn_message())
                self.assertEqual(seq.error, INVALID)
                self.assertIsNone(seq.turn_write_attempt_at)
                self.assertEqual(clock.call_count, 1)
                with self.assertRaises(NativeError):
                    seq.record_outgoing(turn_message())
                self.assertEqual(seq.turn_submissions, 2)
                self.assertEqual(clock.call_count, 1)
        seq = CodexRPCSequence(clock=mock.Mock(side_effect=ValueError))
        drive_to_thread_ready(seq)
        with self.assertRaises(NativeError):
            seq.record_outgoing(turn_message())
        self.assertEqual(seq.error, INVALID)

    def test_missing_clock_refuses(self):
        seq = CodexRPCSequence()
        drive_to_thread_ready(seq)
        with self.assertRaises(NativeError):
            seq.record_outgoing(turn_message())
        self.assertEqual(seq.error, INVALID)
        self.assertIsNone(seq.turn_write_attempt_at)
        self.assertEqual(seq.pending_rpc_count, 0)

    def test_clock_base_errors_propagate_same_object(self):
        for boom in (KeyboardInterrupt('halt'), SystemExit(3)):
            with self.subTest(boom=type(boom).__name__):
                seq = CodexRPCSequence(clock=mock.Mock(side_effect=boom))
                drive_to_thread_ready(seq)
                with self.assertRaises(type(boom)) as ctx:
                    seq.record_outgoing(turn_message())
                self.assertIs(ctx.exception, boom)
                self.assertEqual(seq.error, INVALID)
                self.assertEqual(seq.turn_submissions, 1)
                self.assertIsNone(seq.turn_write_attempt_at)
                self.assertEqual(seq.pending_rpc_count, 0)

    def test_duplicate_attempt_increments_without_resample(self):
        clock = mock.Mock(return_value=9.0)
        seq = CodexRPCSequence(clock=clock)
        drive_to_thread_ready(seq)
        seq.record_outgoing(turn_message())
        with self.assertRaises(NativeError):
            seq.record_outgoing(turn_message(8))
        self.assertEqual(seq.turn_submissions, 2)
        self.assertEqual(seq.turn_write_attempt_at, 9.0)
        self.assertEqual(clock.call_count, 1)
        self.assertEqual(seq.error, INVALID)

    def test_malformed_turn_results_refuse(self):
        results = [
            {}, {'turn': None},
            {'turn': {'status': 'inProgress', 'items': []}},
            {'turn': {'id': '', 'status': 'inProgress', 'items': []}},
            {'turn': {'id': 5, 'status': 'inProgress', 'items': []}},
            {'turn': {'id': 'x', 'status': 'done', 'items': []}},
            {'turn': {'id': 'x', 'status': 1, 'items': []}},
            {'turn': {'id': 'x', 'status': 'inProgress', 'items': 'x'}},
            {'turn': {'id': 'x', 'status': 'inProgress',
                      'items': [0] * 129}},
            {'turn': {'id': 'x', 'status': 'inProgress', 'items': []},
             'error': {'code': -32600}},
        ]
        for result in results:
            with self.subTest(result=repr(result)[:40]):
                seq = CodexRPCSequence(clock=lambda: 1.0)
                drive_to_thread_ready(seq)
                seq.record_outgoing(turn_message())
                with self.assertRaises(NativeError):
                    seq.consume_response(reply_frame(7, result))
                self.assertEqual(seq.error, INVALID)
                self.assertFalse(seq.turn_rpc_confirmed)
                self.assertIsNone(seq.turn_id)

    def test_future_and_duplicate_receipts_refuse(self):
        seq = CodexRPCSequence(clock=lambda: 1.0)
        drive_to_thread_ready(seq)
        with self.assertRaises(NativeError):
            seq.consume_response(reply_frame(99, {}))
        self.assertEqual(seq.error, INVALID)
        seq = CodexRPCSequence(clock=lambda: 1.0)
        drive_to_thread_ready(seq)
        seq.record_outgoing(turn_message())
        seq.consume_response(reply_frame(7, good_turn_result()))
        with self.assertRaises(NativeError):
            seq.consume_response(reply_frame(7, good_turn_result()))
        self.assertEqual(seq.turn_id, 'turn-1')
        self.assertEqual(seq.error, INVALID)
