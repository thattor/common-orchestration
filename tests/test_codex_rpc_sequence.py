"""Independent stdlib unittest for co_v4.codex_rpc_sequence."""
import unittest
from co_v4.adapters.codex import NativeError
from co_v4.codex_rpc_sequence import INVALID, CodexRPCSequence
def _req(mid, method):
    return {'id': mid, 'method': method, 'params': {}}
def _res(mid, result):
    return {'id': mid, 'result': result}
def _replied():
    seq = CodexRPCSequence()
    seq.record_outgoing(_req(0, 'initialize'))
    seq.consume_response(_res(0, {'userAgent': 'codex/1'}))
    return seq
def _ready():
    seq = _replied()
    seq.record_outgoing({'method': 'initialized'})
    return seq
def _pending_thread():
    seq = _ready()
    seq.record_outgoing(_req(2, 'thread/start'))
    return seq
class TestCodexRPCSequence(unittest.TestCase):
    def test_good_order_and_fresh_result(self):
        seq = CodexRPCSequence()
        self.assertEqual((seq.stage, seq.error, seq.thread_id), ('new', None, None))
        seq = _ready()
        self.assertEqual((seq.stage, seq.pending_rpc_count), ('ready', 0))
        seq.record_outgoing(_req(2, 'thread/start'))
        result = {'thread': {'id': 'thr-1', 'title': 'x'}}
        method, out = seq.consume_response(_res(2, result))
        self.assertEqual((method, out), ('thread/start', result))
        self.assertIsNot(out, result)
        self.assertEqual((seq.thread_id, seq.stage), ('thr-1', 'thread_ready'))
    def test_probe_overlap_any_order(self):
        seq = _ready()
        seq.record_outgoing(_req(7, 'account/read'))
        self.assertEqual(seq.consume_response(_res(7, {}))[0], 'account/read')
        seq.record_outgoing(_req(2, 'thread/start'))
        seq.consume_response(_res(2, {'thread': {'id': 't'}}))
        seq.record_outgoing(_req(1, 'model/list'))
        seq.record_outgoing(_req('1', 'config/read'))
        self.assertEqual(seq.pending_rpc_count, 2)
        self.assertEqual(seq.consume_response(_res('1', {}))[0], 'config/read')
        self.assertEqual(seq.consume_response(_res(1, {}))[0], 'model/list')
        self.assertEqual(seq.stage, 'thread_ready')
    def test_wrong_stage_and_duplicate_sends(self):
        for message in ('x', _req(1, 'thread/start'), _req(1, 'model/list'), {'method': 'initialized'}):
            seq = CodexRPCSequence()
            with self.assertRaises(NativeError):
                seq.record_outgoing(message)
            self.assertEqual(seq.error, INVALID)
        seq = _ready()
        with self.assertRaises(NativeError):
            seq.record_outgoing(_req(9, 'initialize'))
        seq = _ready()
        seq.record_outgoing(_req(4, 'model/list'))
        with self.assertRaises(NativeError):
            seq.record_outgoing(_req(5, 'thread/start'))
        seq = _pending_thread()
        seq.consume_response(_res(2, {'thread': {'id': 't'}}))
        with self.assertRaises(NativeError):
            seq.record_outgoing(_req(6, 'thread/start'))
    def test_initialized_keys_and_version(self):
        seq = _replied()
        seq.record_outgoing({'method': 'initialized', 'jsonrpc': '2.0'})
        self.assertEqual(seq.stage, 'ready')
        for bad in ({'method': 'initialized', 'jsonrpc': '1.0'},
                    {'method': 'initialized', 'jsonrpc': 2},
                    {'method': 'initialized', 'params': {}},
                    {'method': 'initialized', 'id': 1}):
            seq = _replied()
            with self.assertRaises(NativeError):
                seq.record_outgoing(bad)
            self.assertEqual(seq.stage, 'initialize_replied')
    def test_initialize_reply_requires_str_user_agent(self):
        seq = CodexRPCSequence()
        seq.record_outgoing(_req(1, 'initialize'))
        with self.assertRaises(NativeError):
            seq.consume_response(_res(1, {'userAgent': 7}))
        self.assertEqual((seq.stage, seq.error), ('initialize_pending', INVALID))
    def test_future_duplicate_and_bad_frames_sticky(self):
        seq = _pending_thread()
        frame = _res(2, {'thread': {'id': 't'}})
        seq.consume_response(frame)
        with self.assertRaises(NativeError):
            seq.consume_response(frame)
        for frame in (_res(9, {}), {'id': 1, 'error': {'code': -1}},
                      {'method': 'thread/started'},
                      {'id': 3, 'method': 'x', 'params': {}}, 'nope'):
            seq = _ready()
            with self.assertRaises(NativeError):
                seq.consume_response(frame)
            self.assertEqual(seq.error, INVALID)
    def test_bad_thread_id_never_binds(self):
        for tid in (True, '', '\ud800', 'x' * 1025, 7):
            seq = _pending_thread()
            with self.assertRaises(NativeError):
                seq.consume_response(_res(2, {'thread': {'id': tid}}))
            self.assertEqual((seq.thread_id, seq.error), (None, INVALID))
        seq = _pending_thread()
        with self.assertRaises(NativeError):
            seq.consume_response(_res(2, {'thread': 'x'}))
        self.assertIsNone(seq.thread_id)
    def test_bool_id_and_turn_refusal(self):
        seq = CodexRPCSequence()
        with self.assertRaises(NativeError):
            seq.record_outgoing(_req(True, 'initialize'))
        seq = _ready()
        with self.assertRaises(NativeError):
            seq.record_outgoing(_req(5, 'turn/start'))
    def test_sticky_error_never_recovers(self):
        seq = _ready()
        with self.assertRaises(NativeError):
            seq.consume_response(_res(9, {}))
        for act in (lambda: seq.record_outgoing(_req(1, 'model/list')), lambda: seq.consume_response(_res(1, {}))):
            with self.assertRaises(NativeError):
                act()
        self.assertEqual((seq.stage, seq.error), ('ready', INVALID))
if __name__ == '__main__':
    unittest.main()
