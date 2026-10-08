"""Fail-closed metadata parsing; these fixtures are not Native qualification."""
import os
import unittest
from pathlib import Path
from unittest.mock import patch
from probes.antigravity_preflight import parse_config, parse_quota, protection


CONFIG = ('useG1Credits\tfalse\ndisableSlashCommands\tfalse\n'
          'allowNonWorkspaceAccess\tfalse\ntoolPermission\trequest-review\n'
          'modelProvider\t\ncustomModelsConfig\t\ngcp\t\n')
QUOTA = ('Claude and GPT models\tWeekly Limit Remaining\t83%\t2026-10-10T17:58:32Z\n'
         'Claude and GPT models\tFive Hour Limit Remaining\t100%\t2026-10-05T01:00:00Z\n')


class PreflightTests(unittest.TestCase):
    def test_config_requires_current_explicit_off(self):
        self.assertTrue(parse_config(CONFIG)['credits_off'])
        for changed in (CONFIG.replace('useG1Credits\tfalse\n', ''),
                        CONFIG.replace('useG1Credits\tfalse', 'useG1Credits\ttrue'),
                        CONFIG.replace('disableSlashCommands\tfalse', 'disableSlashCommands\ttrue'),
                        CONFIG.replace('modelProvider\t\n', 'modelProvider\tcustom\n'),
                        CONFIG + 'useG1Credits\tfalse\n'):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                parse_config(changed)

    def test_quota_requires_both_nonzero_current_family_windows(self):
        self.assertEqual(parse_quota(QUOTA), {'weekly': 83.0, 'five_hour': 100.0})
        for changed in (QUOTA.replace('83%', '0%'), QUOTA.replace('83%', 'nan%'),
                        QUOTA.replace('83%', '101%'), QUOTA.splitlines()[0],
                        QUOTA + QUOTA, QUOTA.replace('Claude and GPT models', 'Gemini Models')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                parse_quota(changed)

    def test_protection_has_no_grant_and_refuses_home_remapping(self):
        with patch.dict(os.environ, {'HOME': '/Users/example'}):
            value = protection(Path('/Users/example'))
            self.assertIn('(deny file-write*', value)
            self.assertIn('/Users/example/.gemini/antigravity-cli/settings.json', value)
            with self.assertRaises(ValueError):
                protection(Path('/private/tmp/another-home'))


if __name__ == '__main__':
    unittest.main()
