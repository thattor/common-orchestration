"""Public collect_output wrappers over audited private text_output (EDGES §6).

Drives the same synthetic adapter fixtures used by test_claude,
test_t3code and test_antigravity against the real adapter classes; no
live Native provider, host, transport or route qualification is
involved. Fixtures only — nothing here is a claim that these tests were
executed.
"""
import unittest

from co_v4 import contracts as c
from co_v4.adapters import antigravity, claude, t3code
from test_claude import Wire as ClaudeWire, frames as claude_frames, request as claude_request
from test_t3code import Transport as T3Transport
from test_antigravity import Transport as AGYTransport, frames as agy_frames, request as agy_request


def t3_projection(launch, status='running', text='OK'):
    value = {key: [] for key in t3code.PROJECTION_ARRAYS}
    value.update(updatedAt='2026-10-04T00:00:01.000Z', thread={
        'id': launch['threadId'], 'projectId': 'project', 'providerInstanceId': 'instance',
        'modelSelection': launch['modelSelection'], 'runtimeMode': 'approval-required',
        'interactionMode': 'default', 'worktreePath': None})
    value['runs'] = [{'id': 't3-run', 'threadId': launch['threadId'],
        'userMessageId': launch['initialMessage']['messageId'], 'providerInstanceId': 'instance',
        'modelSelection': launch['modelSelection'], 'status': status,
        'completedAt': None if status == 'running' else '2026-10-04T00:00:01.000Z'}]
    value['messages'] = [{'id': launch['initialMessage']['messageId'],
        'threadId': launch['threadId'], 'runId': 't3-run', 'role': 'user',
        'text': launch['initialMessage']['text'], 'streaming': False, 'attachments': []}]
    if status == 'completed':
        value['messages'].append({'id': 'assistant', 'threadId': launch['threadId'],
            'runId': 't3-run', 'role': 'assistant', 'text': text,
            'streaming': False, 'attachments': []})
    return value


class NativeCollectorTests(unittest.TestCase):
    def claude_run(self, text='OK', eof=True, code=0):
        req = claude_request()
        def factory(request, session, payload):
            self.wire = ClaudeWire(claude_frames(request, session))
            self.wire.messages[-1]['result'] = text
            self.wire.eof, self.wire.code = eof, code
            return self.wire
        adapter = claude.ClaudeAdapter(verify_host=lambda r: None,
            transport_factory=factory, clock=lambda: 0)
        self.addCleanup(adapter.close)
        adapter.execute(req)
        return adapter, req.ref

    def t3_run(self, status='completed', text='OK', stop=False):
        ref = c.AttemptRef('run', 'job', 'attempt')
        req = c.ExecuteRequest(ref, c.Job('run', 'job', 'Return OK', ('exact OK',), '{}'),
            c.ExecutionConditions('model-id', t3code.ADAPTER, '/workspace', 'fixture:host'))
        wire, launch = T3Transport(), {}
        adapter = t3code.T3CodeAdapter(
            profile=t3code.T3Profile(req, 'project', 'instance', 'fixture:intent'),
            verify_host=lambda *a: None,
            transport_factory=lambda r, p: (launch.update(p), wire)[1],
            poll_interval=0, clock=lambda: 0)
        self.addCleanup(adapter.close)
        adapter.execute(req)
        wire.reply({'threadId': launch['threadId'],
                    'projection': t3_projection(launch), 'resumed': False})
        adapter.status(ref)
        if stop:
            adapter.stop(ref)
        elif status:
            wire.reply(t3_projection(launch, status, text))
            adapter.events(ref)
        return adapter, ref

    def agy_run(self, values=None, **kw):
        req = agy_request()
        wire = AGYTransport(agy_frames() if values is None else values, **kw)
        adapter = antigravity.AntigravityTextAdapter(
            verify_host=lambda *a: None, transport_factory=lambda *a: wire,
            profile=antigravity.TextProfile(req, antigravity.payload_digest(req), ()),
            verify_completion=lambda *a: 'fixture:owned')
        self.addCleanup(adapter.close)
        adapter.execute(req)
        return adapter, req.ref

    def test_claude_success_collects_verbatim_deterministic(self):
        adapter, ref = self.claude_run('first line\n日本語 ✓')
        self.assertIsInstance(adapter, c.OutputCollector)
        self.assertEqual(adapter.status(ref).state, c.State.COMPLETED)
        items = adapter.collect_output(ref)
        self.assertEqual(items, (c.OutputItem(0, 'text/plain', 'first line\n日本語 ✓'),))
        self.assertEqual(adapter.collect_output(ref), items)
        # The assistant transcript canary never enters collected output.
        self.assertNotIn('PRIVATE-CANARY', repr(items))

    def test_claude_unfinished_failed_stopped_foreign_refuse_fixed(self):
        adapter, ref = self.claude_run(eof=False)
        adapter.status(ref)
        with self.assertRaises(ValueError) as ctx:
            adapter.collect_output(ref)
        self.assertNotIn('PRIVATE-CANARY', str(ctx.exception))
        adapter, ref = self.claude_run(code=1)
        adapter.status(ref)
        with self.assertRaises(ValueError):
            adapter.collect_output(ref)
        adapter, ref = self.claude_run()
        adapter.stop(ref)
        with self.assertRaises(ValueError):
            adapter.collect_output(ref)
        with self.assertRaises(c.CollectionError) as ctx:
            adapter.collect_output(c.AttemptRef('run', 'job', 'ghost'))
        self.assertEqual(str(ctx.exception),
                         'attempt unavailable in this adapter instance')
        self.assertNotIn('ghost', repr(ctx.exception))

    def test_claude_tool_activity_never_reaches_collected_output(self):
        adapter, ref = self.claude_run()
        self.wire.messages[1]['message']['content'].append({'type': 'tool_use'})
        self.assertEqual(adapter.status(ref).state, c.State.ERROR)
        with self.assertRaises(ValueError) as ctx:
            adapter.collect_output(ref)
        self.assertNotIn('PRIVATE-CANARY', str(ctx.exception))

    def test_t3_success_collects_verbatim_deterministic(self):
        adapter, ref = self.t3_run(text='two\nlines ✓')
        self.assertIsInstance(adapter, c.OutputCollector)
        self.assertEqual(adapter.status(ref).state, c.State.COMPLETED)
        items = adapter.collect_output(ref)
        self.assertEqual(items, (c.OutputItem(0, 'text/plain', 'two\nlines ✓'),))
        self.assertEqual(adapter.collect_output(ref), items)

    def test_t3_unfinished_failed_stopped_foreign_refuse_fixed(self):
        adapter, ref = self.t3_run(status=None)
        with self.assertRaises(ValueError):
            adapter.collect_output(ref)
        adapter, ref = self.t3_run(status='failed')
        with self.assertRaises(ValueError):
            adapter.collect_output(ref)
        adapter, ref = self.t3_run(stop=True)
        with self.assertRaises(ValueError):
            adapter.collect_output(ref)
        with self.assertRaises(c.CollectionError) as ctx:
            adapter.collect_output(c.AttemptRef('run', 'job', 'ghost'))
        self.assertEqual(str(ctx.exception),
                         'attempt unavailable in this adapter instance')
        self.assertNotIn('ghost', repr(ctx.exception))

    def test_agy_success_collects_verbatim_deterministic(self):
        frames = agy_frames()
        frames[2]['step_update']['text_delta'] = '日本語\n'
        frames[-1]['result']['response'] = '日本語\n'
        adapter, ref = self.agy_run(frames)
        self.assertIsInstance(adapter, c.OutputCollector)
        self.assertEqual(adapter.status(ref).state, c.State.COMPLETED)
        items = adapter.collect_output(ref)
        self.assertEqual(items, (c.OutputItem(0, 'text/plain', '日本語\n'),))
        self.assertEqual(adapter.collect_output(ref), items)
        adapter2, ref2 = self.agy_run()
        adapter2.status(ref2)
        self.assertEqual(adapter2.collect_output(ref2),
                         (c.OutputItem(0, 'text/plain', 'review'),))

    def test_agy_unfinished_failed_stopped_foreign_refuse_fixed(self):
        adapter, ref = self.agy_run(drained=False)
        adapter.status(ref)
        with self.assertRaises(ValueError):
            adapter.collect_output(ref)
        adapter, ref = self.agy_run(code=1)
        adapter.status(ref)
        with self.assertRaises(ValueError):
            adapter.collect_output(ref)
        adapter, ref = self.agy_run()
        adapter.stop(ref)
        with self.assertRaises(ValueError):
            adapter.collect_output(ref)
        with self.assertRaises(c.CollectionError) as ctx:
            adapter.collect_output(c.AttemptRef('run', 'job', 'ghost'))
        self.assertEqual(str(ctx.exception),
                         'attempt unavailable in this adapter instance')
        self.assertNotIn('ghost', repr(ctx.exception))


if __name__ == '__main__':
    unittest.main()
