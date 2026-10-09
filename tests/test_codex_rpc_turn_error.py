import unittest
from unittest import mock

from co_v4.adapters.codex import NativeError
from co_v4.codex_rpc_sequence import INVALID, CodexRPCSequence


class TestCodexRPCTurnError(unittest.TestCase):
    """Turn/start replies carrying error values: refusal vs acceptance."""

    def _sequence(self):
        clock = mock.Mock(return_value=7.5)
        seq = CodexRPCSequence(clock=clock)
        self.assertIsNone(seq.record_outgoing({'id': 0, 'method': 'initialize', 'params': {}}))
        seq.consume_response({'id': 0, 'result': {'userAgent': 'ua'}})
        self.assertIsNone(seq.record_outgoing({'method': 'initialized'}))
        self.assertIsNone(seq.record_outgoing({'id': 1, 'method': 'thread/start', 'params': {}}))
        seq.consume_response({'id': 1, 'result': {'thread': {'id': 't-1'}}})
        clock.assert_not_called()
        self.assertIsNone(seq.record_outgoing({'id': 2, 'method': 'turn/start', 'params': {'threadId': 't-1'}}))
        clock.assert_called_once_with()
        return seq, clock

    def _valid_turn_reply(self):
        return {'id': 2, 'result': {'turn': {'id': 'turn-x', 'status': 'inProgress', 'items': []}}}

    def _assert_refusal(self, seq, clock, frame):
        with self.assertRaises(NativeError) as ctx:
            seq.consume_response(frame)
        self.assertEqual(str(ctx.exception), INVALID)
        self.assertEqual(seq.error, INVALID)
        self.assertIsNone(seq.turn_id)
        self.assertFalse(seq.turn_rpc_confirmed)
        self.assertEqual(seq.stage, 'turn_pending')
        self.assertEqual(seq.pending_rpc_count, 0)
        self.assertEqual(seq.turn_submissions, 1)
        self.assertEqual(seq.turn_write_attempt_at, 7.5)
        clock.assert_called_once_with()
        with self.assertRaises(NativeError) as ctx:
            seq.record_outgoing({'id': 3, 'method': 'turn/start', 'params': {'threadId': 't-1'}})
        self.assertEqual(str(ctx.exception), INVALID)
        self.assertEqual(seq.turn_submissions, 2)
        self.assertEqual(seq.turn_write_attempt_at, 7.5)
        self.assertEqual(seq.pending_rpc_count, 0)
        clock.assert_called_once_with()
        with self.assertRaises(NativeError):
            seq.consume_response(self._valid_turn_reply())
        self.assertIsNone(seq.turn_id)
        self.assertFalse(seq.turn_rpc_confirmed)

    def _assert_acceptance(self, seq, frame):
        method, result = seq.consume_response(frame)
        self.assertEqual(method, 'turn/start')
        self.assertEqual(seq.turn_id, 'turn-x')
        self.assertTrue(seq.turn_rpc_confirmed)
        self.assertEqual(seq.stage, 'turn_replied')
        self.assertIsNone(seq.error)
        self.assertEqual(seq.pending_rpc_count, 0)

    def test_nested_turn_error_object_refused_and_sticky(self):
        seq, clock = self._sequence()
        turn = {'id': 'turn-x', 'status': 'inProgress', 'items': [], 'error': {'code': 'boom'}}
        self._assert_refusal(seq, clock, {'id': 2, 'result': {'turn': turn}})

    def test_falsey_nonnull_turn_error_refused(self):
        seq, clock = self._sequence()
        turn = {'id': 'turn-x', 'status': 'inProgress', 'items': [], 'error': 0}
        self._assert_refusal(seq, clock, {'id': 2, 'result': {'turn': turn}})

    def test_null_turn_error_accepted(self):
        seq, clock = self._sequence()
        turn = {'id': 'turn-x', 'status': 'inProgress', 'items': [], 'error': None}
        self._assert_acceptance(seq, {'id': 2, 'result': {'turn': turn}})

    def test_absent_turn_error_accepted(self):
        seq, clock = self._sequence()
        self._assert_acceptance(seq, self._valid_turn_reply())

    def test_root_result_error_refused(self):
        seq, clock = self._sequence()
        turn = {'id': 'turn-x', 'status': 'inProgress', 'items': []}
        self._assert_refusal(seq, clock, {'id': 2, 'result': {'turn': turn, 'error': 'boom'}})


if __name__ == '__main__':
    unittest.main()
