import copy
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.summary import render_run_summary
from test_state import Harness


class EmptyErrorRunSummaryRegressionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.h = Harness(directory.name)
        self.addCleanup(self.h.store.close)

    def render_empty_error(self, cessation):
        self.h.ctrl.finalize_run(
            "r", c.State.ERROR, "controller_error",
            self.h.rev(), cessation=cessation,
        )
        before = copy.deepcopy(self.h.ctrl.get_run("r"))
        self.assertEqual(before.state, c.State.ERROR)
        self.assertIs(before.cessation_confirmed, cessation)
        self.assertEqual(len(before.job_ids), 0)
        self.assertEqual(len(self.h.ctrl.attempts("r")), 0)

        summary = render_run_summary(self.h.ctrl, "r")

        self.assertEqual(self.h.ctrl.get_run("r"), before)
        lines = summary.splitlines()
        self.assertEqual(len(lines), 5)
        self.assertTrue(lines[4].startswith("Cautions: "))
        self.assertEqual(
            lines[1],
            "Work: 0 Jobs; 0 Attempts; "
            "0 Jobs with independent AC and Goal pass.",
        )
        return summary, lines[4]

    def test_empty_error_with_unconfirmed_cessation_warns(self):
        summary, cautions = self.render_empty_error(False)
        self.assertIn("cessation unconfirmed", cautions)
        self.assertEqual(summary.count("cessation unconfirmed"), 1)

    def test_empty_error_with_confirmed_cessation_has_no_warning(self):
        summary, cautions = self.render_empty_error(True)
        self.assertNotIn("cessation unconfirmed", summary)
        self.assertIn("Run did not complete", cautions)


if __name__ == "__main__":
    unittest.main()
