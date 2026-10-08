"""Synthetic operator history fixtures; no Orca process or actual history."""
from copy import deepcopy
from dataclasses import replace
import json
import unittest

from co_v4.orca_history import (HistoryRefused, MAX_BYTES, OwnedTerminal,
    OwnedTerminalHistory, ReadPlan)


def response():
    return {'id': 'fixture-rpc', 'ok': True, '_meta': {'runtimeId': 'fixture-runtime'},
        'result': {'terminal': {'handle': 'fixture-handle', 'status': 'running',
            'tail': ['PRIVATE-TEXT'], 'draft': 'PRIVATE-DRAFT', 'source': 'stream',
            'truncated': False, 'limited': False, 'oldestCursor': '0',
            'nextCursor': '2', 'latestCursor': '2', 'returnedLineCount': 1}}}


class OrcaHistoryTests(unittest.TestCase):
    def setUp(self):
        self.binding = OwnedTerminal('fixture-handle', 'fixture-runtime', 'owner-evidence', 'lease-evidence')
        self.checks, self.calls = [], []
        self.data = response()
        self.live = True
        def owner(binding):
            self.checks.append(binding)
            if not self.live: raise RuntimeError('PRIVATE-STALE-REASON')
        def client(plan):
            self.calls.append(plan)
            return json.dumps(self.data).encode()
        self.helper = OwnedTerminalHistory(self.binding, verify_owner=owner, client=client)

    def read(self):
        return self.helper.read(self.helper.plan(cursor='0', limit=10))

    def test_exact_plan_bound_source_private_page(self):
        plan = self.helper.plan(cursor='0', limit=10)
        self.assertEqual(plan.arguments, ('terminal', 'read', '--terminal', 'fixture-handle',
            '--cursor', '0', '--limit', '10', '--json'))
        page = self.helper.read(plan)
        self.assertEqual(len(self.checks), 3)
        self.assertEqual(self.calls, [plan])
        self.assertEqual(page.tail, ('PRIVATE-TEXT',))
        self.assertEqual((page.next_cursor, page.latest_cursor), ('2', '2'))
        self.assertFalse(page.gap_before_page)
        self.assertNotIn('PRIVATE', repr(page))
        self.assertNotIn('fixture-handle', repr(plan))
        self.assertNotIn('owner-evidence', repr(self.binding))
        self.assertFalse(hasattr(page, 'draft'))
        for attr in ('execute', 'send', 'stop', 'resume', 'usage', 'result'):
            self.assertFalse(hasattr(self.helper, attr))

    def test_default_denies_before_client(self):
        helper = OwnedTerminalHistory(self.binding, client=lambda _: self.fail('client called'))
        with self.assertRaisesRegex(HistoryRefused, '^owner_unverified$'): helper.plan(cursor='0')

    def test_no_default_live_client(self):
        helper = OwnedTerminalHistory(self.binding, verify_owner=lambda _: None)
        plan = helper.plan(cursor='0')
        with self.assertRaisesRegex(HistoryRefused, '^client_unavailable$'): helper.read(plan)

    def test_boolean_owner_flag_is_not_authentication(self):
        for flag in (True, False):
            helper = OwnedTerminalHistory(self.binding, verify_owner=lambda _: flag)
            with self.assertRaisesRegex(HistoryRefused, '^owner_unverified$'): helper.plan(cursor='0')

    def test_no_plan_forgery_replay_or_cross_reader(self):
        plan = self.helper.plan(cursor='0')
        with self.assertRaisesRegex(HistoryRefused, '^plan_pending$'): self.helper.plan(cursor='1')
        for forged in (None, replace(plan), ReadPlan(self.binding, '1', 100)):
            with self.assertRaisesRegex(HistoryRefused, '^plan_unbound$'): self.helper.read(forged)
        self.helper.read(plan)
        with self.assertRaisesRegex(HistoryRefused, '^plan_unbound$'): self.helper.read(plan)
        self.assertEqual(len(self.calls), 1)

    def test_revoked_before_io_or_during_io_refuses(self):
        plan = self.helper.plan(cursor='0'); self.live = False
        with self.assertRaisesRegex(HistoryRefused, '^owner_unverified$'): self.helper.read(plan)
        self.assertEqual(self.calls, [])
        self.live = True
        def replaced(plan):
            self.live = False
            return json.dumps(response()).encode()
        self.helper._client = replaced
        plan = self.helper.plan(cursor='0')
        with self.assertRaisesRegex(HistoryRefused, '^owner_unverified$'): self.helper.read(plan)

    def test_truncation_gap_and_limited_retained(self):
        self.data['result']['terminal'].update(oldestCursor='5', nextCursor='7',
            latestCursor='20', truncated=True, limited=True)
        page = self.read()
        self.assertTrue(page.truncated)
        self.assertTrue(page.gap_before_page)
        self.assertTrue(page.limited)
        self.assertEqual(page.next_cursor, '7')
        self.assertEqual(len(self.calls), 1)  # never automatic pagination

    def test_exited_unknown_are_only_terminal_attributes(self):
        for status in ('exited', 'unknown'):
            self.data['result']['terminal']['status'] = status
            page = self.read()
            self.assertEqual(page.terminal_status, status)
            self.assertFalse(hasattr(page, 'completed'))
            self.assertFalse(hasattr(page, 'cessation'))

    def test_legacy_stream_is_explicit_and_never_screen(self):
        del self.data['result']['terminal']['source']
        self.assertEqual(self.read().source, 'legacy-stream')
        for source in ('screen', 'screen-unavailable', 'unknown'):
            self.data['result']['terminal']['source'] = source
            with self.assertRaisesRegex(HistoryRefused, '^response_invalid$'): self.read()

    def test_response_negative_matrix(self):
        mutations = {
            'cross handle': lambda r,t: t.update(handle='other'),
            'cross runtime': lambda r,t: r['_meta'].update(runtimeId='other'),
            'missing runtime': lambda r,t: r.pop('_meta'),
            'unknown envelope': lambda r,t: r.update(extra='PRIVATE'),
            'unknown terminal': lambda r,t: t.update(extra='PRIVATE'),
            'failure': lambda r,t: r.update(ok=False),
            'bool status': lambda r,t: t.update(status=True),
            'missing cursor': lambda r,t: t.pop('oldestCursor'),
            'null cursor': lambda r,t: t.update(nextCursor=None),
            'numeric cursor': lambda r,t: t.update(nextCursor=2),
            'reversed range': lambda r,t: t.update(oldestCursor='3'),
            'undeclared gap': lambda r,t: t.update(oldestCursor='1'),
            'no progress': lambda r,t: t.update(limited=True, nextCursor='0'),
            'no limited evidence': lambda r,t: t.pop('limited'),
            'wrong count': lambda r,t: t.update(returnedLineCount=2),
            'bool count': lambda r,t: t.update(returnedLineCount=True),
            'tail type': lambda r,t: t.update(tail='PRIVATE'),
            'tail entry': lambda r,t: t.update(tail=[{}]),
            'too many lines': lambda r,t: t.update(tail=['x']*11,returnedLineCount=11),
            'bool truncated': lambda r,t: t.update(truncated=1),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.data = response(); mutate(self.data, self.data['result']['terminal'])
                with self.assertRaisesRegex(HistoryRefused, '^response_invalid$'): self.read()

    def test_raw_data_and_client_errors_never_leak(self):
        for raw in (b'PRIVATE', b'\xff', b'{}', b'{"a":1,"a":2}',
                    b'NaN', b'x'*(MAX_BYTES+1), response()):
            self.helper._client = lambda _: raw
            with self.assertRaisesRegex(HistoryRefused, '^response_invalid$'): self.read()
        def failed(_): raise RuntimeError('PRIVATE-ERROR')
        self.helper._client = failed
        with self.assertRaisesRegex(HistoryRefused, '^read_unavailable$'): self.read()

    def test_input_validation(self):
        for cursor in (None, 0, True, '-1', '01', '1.0', '١', '9007199254740992'):
            with self.assertRaisesRegex(HistoryRefused, '^cursor_invalid$'): self.helper.plan(cursor=cursor)
        for limit in (False, 0, -1, 1001, 1.5):
            with self.assertRaisesRegex(HistoryRefused, '^limit_invalid$'): self.helper.plan(cursor='0', limit=limit)
        for handle in ('active', 'current', '--all', '', 'line\nbreak'):
            with self.assertRaisesRegex(HistoryRefused, '^binding_invalid$'):
                OwnedTerminal(handle, 'runtime', 'owner', 'lease')

    def test_surrogate_in_each_binding_label_is_sanitized(self):
        for index in range(4):
            with self.subTest(field=index):
                labels = ['handle', 'runtime', 'owner', 'lease']
                labels[index] = 'SECRET-CANARY\ud800'
                with self.assertRaises(HistoryRefused) as caught:
                    OwnedTerminal(*labels)
                error = caught.exception
                self.assertEqual(str(error), 'binding_invalid')
                self.assertNotIn('SECRET-CANARY', repr(error))
                self.assertFalse(hasattr(error, 'object'))
                self.assertIsNone(error.__context__)


if __name__ == '__main__':
    unittest.main()
