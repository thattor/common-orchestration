# tests/test_codex_spec_target.py — Codex route in closed task/2+ targets.
"""task/2 and task/3 selection targets accept route 'codex' with the
unchanged exact {route, model} shape. Unknown adapters still refuse, and
an effort member still refuses: effort is a measured entry bound, not a
target property.
"""
import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parent))

from co_v4.task import spec              # noqa: E402
from co_v4.task.common import TaskError  # noqa: E402


class CodexTargetTests(unittest.TestCase):
    def test_codex_route_model_pair_accepted(self):
        target = {'route': 'codex', 'model': 'gpt-6.1-sol'}
        self.assertEqual(spec._target(dict(target)), target)
        sel = spec._selection({'mode': 'fixed', 'targets': {
            'planner': dict(target), 'implement': dict(target)}})
        self.assertEqual(sel['mode'], 'fixed')
        self.assertEqual(sel['targets'],
                         {'planner': target, 'implement': target})

    def test_existing_routes_still_accepted(self):
        for route in ('claude', 'devin'):
            with self.subTest(route=route):
                self.assertEqual(
                    spec._target({'route': route, 'model': 'm'}),
                    {'route': route, 'model': 'm'})

    def test_unknown_adapter_route_refused(self):
        for route in ('gemini', 'openai', 'antigravity', 't3code',
                      'Codex', '', 1, None):
            with self.subTest(route=route):
                with self.assertRaises(TaskError) as cm:
                    spec._target({'route': route, 'model': 'm'})
                self.assertEqual(cm.exception.code, 'spec_invalid')
        with self.assertRaises(TaskError) as cm:
            spec._target({'route': 'gemini', 'model': 'm'})
        self.assertIn('codex', cm.exception.detail)

    def test_extra_effort_key_refused(self):
        # effort is a measured entry bound, not a target property.
        for target in ({'route': 'codex', 'model': 'm', 'effort': 'high'},
                       {'route': 'codex', 'model': 'm', 'effort': None},
                       {'route': 'codex', 'effort': 'high'},
                       {'route': 'codex', 'model': 'm', 'extra': 1}):
            with self.subTest(target=target):
                with self.assertRaises(TaskError) as cm:
                    spec._target(target)
                self.assertEqual(cm.exception.code, 'spec_invalid')
        with self.assertRaises(TaskError) as cm:
            spec._selection({'mode': 'suitability', 'effort': 'high',
                             'targets': {}})
        self.assertEqual(cm.exception.code, 'spec_invalid')


if __name__ == '__main__':
    unittest.main()
