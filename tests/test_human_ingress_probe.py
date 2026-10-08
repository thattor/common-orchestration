"""Offline probe tests. These source fixtures make no live authentication claim."""
from copy import deepcopy
import json
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4.human_gateway import IssueTarget
from probes.human_ingress_boundary import LIMIT, main, probe


class HumanIngressProbeTests(unittest.TestCase):
    def setUp(self):
        self.target = IssueTarget('fixture/co', 160)
        self.snapshot = {
            'issue': {'number': 160, 'url': self.target.api_url, 'state': 'open'},
            'comment': {'id': 42, 'issue_url': self.target.api_url,
                        'user': {'id': 101, 'type': 'User'},
                        'created_at': '2026-09-28T00:00:00Z',
                        'updated_at': '2026-09-28T00:00:00Z',
                        'body': 'PRIVATE-CANARY: ordinary comment, not an approval'},
        }

    def run_probe(self, snapshot=None):
        return probe(self.snapshot if snapshot is None else snapshot,
                     target=self.target, comment_id=42, actor_id=101,
                     observed_at='2026-10-01T00:00:00Z')

    def test_source_observation_is_not_live_acceptance_or_approval(self):
        report = self.run_probe()
        self.assertEqual(report['source_binding'], 'matched')
        self.assertEqual(report['ingress'], 'blocked_isolation_unverified')
        self.assertFalse(report['approval_created'])
        self.assertEqual(report['live_acceptance'], 'not_established')
        self.assertEqual(report['waiting_lifecycle'], 'not_exercised')
        self.assertNotIn('PRIVATE-CANARY', json.dumps(report))

    def test_wrong_source_and_edited_bot_future_comments_are_rejected(self):
        variants = [dict(id=43), dict(id=True), dict(issue_url='https://wrong.invalid'),
                    dict(user={'id': 102, 'type': 'User'}),
                    dict(user={'id': 101, 'type': 'Bot'}),
                    dict(updated_at='2026-09-28T00:00:01Z'),
                    dict(created_at='2027-01-01T00:00:00Z', updated_at='2027-01-01T00:00:00Z')]
        for change in variants:
            with self.subTest(change=change):
                snapshot = deepcopy(self.snapshot)
                snapshot['comment'].update(change)
                self.assertEqual(self.run_probe(snapshot)['source_binding'], 'rejected')

    def test_issue_binding_closed_issue_pr_and_missing_snapshot_are_rejected(self):
        for change in ({'number': 161}, {'state': 'closed'}, {'pull_request': {}},
                       {'url': 'https://wrong.invalid'}):
            snapshot = deepcopy(self.snapshot)
            snapshot['issue'].update(change)
            self.assertEqual(self.run_probe(snapshot)['source_binding'], 'rejected')
        self.assertEqual(self.run_probe({})['source_binding'], 'rejected')

    def test_cli_reports_only_status_and_bounds_snapshot_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.json'
            argv = ['probe', str(path), '--repository', 'fixture/co', '--issue', '160',
                    '--comment', '42', '--actor', '101',
                    '--observed-at', '2026-10-01T00:00:00Z']
            path.write_text(json.dumps(self.snapshot))
            with patch('sys.argv', argv), patch('sys.stdout', new_callable=io.StringIO) as out:
                self.assertEqual(main(), 0)
                self.assertNotIn('PRIVATE-CANARY', out.getvalue())
                self.assertEqual(json.loads(out.getvalue())['source_binding'], 'matched')
            for content in ('PRIVATE-CANARY', 'x' * (LIMIT + 1)):
                path.write_text(content)
                with patch('sys.argv', argv), patch('sys.stderr', new_callable=io.StringIO) as err:
                    with self.assertRaises(SystemExit) as result:
                        main()
                    self.assertEqual(result.exception.code, 2)
                    self.assertNotIn('PRIVATE-CANARY', err.getvalue())
                    self.assertNotIn(str(path), err.getvalue())

    def test_probe_detects_guard_bypass_without_provisioning_state(self):
        with patch('co_v4.human_gateway.HumanGateway._isolated', lambda self: None):
            with self.assertRaisesRegex(AssertionError, 'read-only boundary'):
                self.run_probe()

    def test_probe_rejects_silent_receive_success(self):
        with patch('co_v4.human_gateway.HumanGateway.receive', lambda *a, **kw: None):
            with self.assertRaisesRegex(AssertionError, 'fail closed'):
                self.run_probe()


if __name__ == '__main__':
    unittest.main()
