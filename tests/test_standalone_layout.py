# tests/test_standalone_layout.py — standalone checkout layout invariants.
"""The opt-in Native fixture's CHECKOUT is the flattened repo root.

Importing the fixture binds constants only; no Native process, auth or
probe call is made.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FIXTURE = ROOT / 'tests' / 'fixtures' / 'codex_native_bootstrap.py'


class StandaloneLayout(unittest.TestCase):
    def test_checkout_is_standalone_root(self):
        spec = importlib.util.spec_from_file_location(
            'codex_native_bootstrap', FIXTURE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.CHECKOUT, ROOT)
        self.assertTrue((module.CHECKOUT / 'co_v4').is_dir())


if __name__ == '__main__':
    unittest.main()
