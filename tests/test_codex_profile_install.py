"""The V3 copied payload must import both new helpers inside the owned venv."""
import json
from pathlib import Path
import unittest
from tests import test_e2e_candidate_install as install_fixture


class ProfileInstallTests(unittest.TestCase):
    setUp = install_fixture.CandidateInstallE2E.setUp
    hashes = install_fixture.CandidateInstallE2E.hashes
    run_python = install_fixture.CandidateInstallE2E.run_python
    available = install_fixture.CandidateInstallE2E.available

    def test_owned_payload_contains_and_imports_profile_helpers_then_rolls_back(self):
        expected = {"co_v4/codex_permissions.py", "co_v4/codex_profile_transport.py"}
        self.assertTrue(expected <= set(self.manifest))
        code = ("import json,co_v4.codex_host,co_v4.codex_permissions,co_v4.codex_profile_transport;"
                "print(json.dumps([m.__file__ for m in (co_v4.codex_host,co_v4.codex_permissions,co_v4.codex_profile_transport)]))")
        paths = json.loads(self.run_python('-c', code).stdout)
        self.assertEqual(len(paths), 3)
        self.assertTrue(all(Path(p).is_relative_to(self.candidate) for p in paths))
        self.activation.unlink()
        self.assertEqual(self.available(), 'False')
        self.assertEqual(self.hashes(self.candidate), self.manifest)

if __name__ == '__main__': unittest.main()
