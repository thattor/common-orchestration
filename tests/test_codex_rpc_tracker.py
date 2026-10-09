import unittest

from co_v4.adapters.codex import NativeError
from co_v4.codex_rpc_tracker import RPCTracker
from co_v4.codex_text_validation import INT64_MAX, INT64_MIN

INVALID = 'codex_rpc_tracker_invalid'

METHODS = [
    'initialize', 'thread/start', 'model/list', 'config/read',
    'account/read', 'account/rateLimits/read', 'command/exec', 'turn/start',
]


def req(rid, method='initialize', **extra):
    m = {'id': rid, 'method': method, 'params': {}}
    m.update(extra)
    return m


def resp(rid, result=None):
    return {'id': rid, 'result': {} if result is None else result}


class TestRPCTracker(unittest.TestCase):

    def setUp(self):
        self.t = RPCTracker()

    def assert_refused(self, t, fn, arg, pending):
        with self.assertRaises(NativeError) as ctx:
            fn(arg)
        self.assertEqual(str(ctx.exception), INVALID)
        self.assertEqual(t.error, INVALID)
        self.assertEqual(t.pending_rpc_count, pending)

    def test_initial_state(self):
        self.assertIsNone(self.t.error)
        self.assertEqual(self.t.pending_rpc_count, 0)

    def test_each_method_roundtrip(self):
        for i, m in enumerate(METHODS):
            self.t.record_request(req(i, m))
            self.assertEqual(self.t.pending_rpc_count, i + 1)
        for i, m in enumerate(METHODS):
            result = {'n': i}
            method, out = self.t.consume_response({'id': i, 'result': result})
            self.assertEqual(method, m)
            self.assertEqual(out, result)
        self.assertEqual(self.t.pending_rpc_count, 0)

    def test_result_copy_isolation(self):
        self.t.record_request(req(1, 'turn/start'))
        result = {'a': 1, 'nested': [1]}
        frame = {'id': 1, 'result': result}
        _, out = self.t.consume_response(frame)
        self.assertIsNot(out, result)
        out['b'] = 2
        frame['result']['c'] = 3
        self.assertNotIn('b', result)
        self.assertNotIn('c', out)

    def test_no_payload_or_id_retained(self):
        self.t.record_request({'id': 1, 'method': 'initialize',
                               'params': {'secret': 'x'}, 'jsonrpc': '2.0'})
        self.assertEqual(set(self.t._pending.values()), {'initialize'})
        self.assertNotIn('secret', repr(self.t.__dict__))
        _, out = self.t.consume_response(resp(1, {'secret': 'y'}))
        self.assertEqual(out, {'secret': 'y'})
        self.assertNotIn('secret', repr(self.t.__dict__))
        self.assertEqual(self.t._pending, {})

    def test_int_and_str_ids_distinct(self):
        self.t.record_request(req(7))
        self.t.record_request(req('7'))
        self.assertEqual(self.t.pending_rpc_count, 2)
        self.assertEqual(self.t.consume_response(resp(7))[0], 'initialize')
        self.assertEqual(self.t.consume_response(resp('7'))[0], 'initialize')

    def test_id_bounds_accepted(self):
        for rid in (INT64_MIN, INT64_MAX, 0, 'x' * 1024, '€' * 341):
            self.t.record_request(req(rid))
        self.assertEqual(self.t.pending_rpc_count, 5)

    def test_invalid_ids_refuse(self):
        for bad in (True, False, '', '\ud800', 1.5, None, [], {},
                    INT64_MIN - 1, INT64_MAX + 1, 'x' * 1025, '€' * 342):
            t = RPCTracker()
            self.assert_refused(t, t.record_request, req(bad), 0)

    def test_request_shape_refusals(self):
        cases = [
            None, [], 'x',
            {'id': 1, 'method': 'initialize'},
            {'id': 1, 'params': {}},
            {'method': 'initialize', 'params': {}},
            {'id': 1, 'method': 'initialize', 'params': {}, 'extra': 1},
            req(1, jsonrpc='2'), req(1, jsonrpc=2.0), req(1, jsonrpc=None),
            req(1, 'turn/stop'), req(1, 'Initialize'), req(1, ''), req(1, 7),
            req(1, None), {'id': 1, 'method': 'initialize', 'params': []},
            {'id': 1, 'method': 'initialize', 'params': None},
        ]
        for msg in cases:
            t = RPCTracker()
            self.assert_refused(t, t.record_request, msg, 0)

    def test_response_shape_refusals(self):
        cases = [
            None, [], 'x',
            {'method': 'warning', 'params': {}},
            {'method': 'turn/started', 'params': {}},
            {'id': 1, 'method': 'turn/start', 'params': {}},
            {'id': 1, 'error': {'code': -1}},
            {'id': 1, 'result': {}, 'error': {'code': -1}},
            {'id': 1, 'result': {}, 'jsonrpc': '2'},
            {'id': 1, 'result': {}, 'jsonrpc': 2},
            {'id': 1, 'result': []}, {'id': 1, 'result': 'x'},
            {'id': 1}, {'id': 1, 'result': {}, 'extra': 1},
            {'id': 99, 'result': {}},
        ]
        for frame in cases:
            t = RPCTracker()
            t.record_request(req(1))
            self.assert_refused(t, t.consume_response, frame, 1)

    def test_future_response_refuses(self):
        self.assert_refused(self.t, self.t.consume_response, resp(1), 0)

    def test_duplicate_and_extra_response_refuse(self):
        self.t.record_request(req(1))
        self.t.consume_response(resp(1, {'ok': True}))
        self.assert_refused(self.t, self.t.consume_response, resp(1), 0)

    def test_consumed_id_reuse_refuses(self):
        self.t.record_request(req(1))
        self.t.consume_response(resp(1))
        self.assert_refused(self.t, self.t.record_request, req(1), 0)

    def test_pending_limit_128(self):
        for i in range(128):
            self.t.record_request(req(i, 'model/list'))
        self.assertEqual(self.t.pending_rpc_count, 128)
        self.assert_refused(self.t, self.t.record_request, req(128), 128)

    def test_lifetime_limit_256_with_consumed(self):
        for i in range(128):
            self.t.record_request(req(i, 'model/list'))
        for i in range(128):
            self.t.consume_response(resp(i))
        self.assertEqual(self.t.pending_rpc_count, 0)
        for i in range(128, 256):
            self.t.record_request(req(i, 'model/list'))
        self.assertEqual(self.t.pending_rpc_count, 128)
        self.assert_refused(self.t, self.t.record_request, req(256), 128)

    def test_sticky_refusal_blocks_both_methods(self):
        self.t.record_request(req(1, 'config/read'))
        self.assert_refused(
            self.t, self.t.consume_response,
            {'method': 'warning', 'params': {}}, 1)
        for _ in range(2):
            self.assert_refused(self.t, self.t.record_request, req(2), 1)
            self.assert_refused(self.t, self.t.consume_response, resp(1), 1)
        self.assertEqual(set(self.t._pending.values()), {'config/read'})
        self.assertEqual(len(self.t._used), 1)

    def test_lifetime_limit_refuses_with_no_pending_requests(self):
        for rid in range(256):
            self.t.record_request(req(rid, 'config/read'))
            self.t.consume_response(resp(rid))
        self.assertEqual(self.t.pending_rpc_count, 0)
        self.assert_refused(self.t, self.t.record_request, req(256), 0)


if __name__ == '__main__':
    unittest.main()
