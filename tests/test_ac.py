"""Independent acceptance mechanics, with explicitly synthetic attestations."""
from dataclasses import replace
import unittest

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.state import RunSnapshot, body_digest


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.job = c.Job("r", "j", "Goal", ("file exists", "content checked"))
        self.run = RunSnapshot("r", "Human Goal", "fixture:origin",
                               derived_interpretation=(self.job,), job_ids=("j",))
        self.result = c.Result(c.AttemptRef("r", "j", "a"), c.State.COMPLETED,
                               artifact_refs=("worker:claims-success",))

    def verifier(self, request):
        return CheckEvidence(body_digest(request), Finding("pass", ("fixture:goal-test",)),
            tuple(Finding("pass", ("fixture:independent-test",))
                  for _ in (request.job.acceptance_criteria if request.job else ())))

    def test_completed_with_failing_ac_preserves_result(self):
        def verify(request):
            return replace(self.verifier(request), criteria=(Finding("pass", ("checked",)), Finding("fail")))
        outcome = Acceptance(verify).job(self.run, self.job, self.result)
        self.assertEqual(outcome.ac.verdict, "fail")
        self.assertEqual(outcome.result, self.result)
        self.assertFalse(outcome.completed)

    def test_criteria_pass_is_not_job_goal_pass(self):
        check = Acceptance(lambda r: replace(self.verifier(r), goal=Finding("incomplete")))
        self.assertEqual(check.job(self.run, self.job, self.result).ac.verdict, "incomplete")

    def test_unbound_or_missing_checks_rejected(self):
        for mutation in ({"request_digest": "another-attempt"}, {"criteria": ()}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                Acceptance(lambda r: replace(self.verifier(r), **mutation)).job(self.run, self.job, self.result)
        with self.assertRaises(ValueError):
            Finding("pass")
        with self.assertRaises(ValueError):
            Acceptance(self.verifier).job(self.run, self.job,
                replace(self.result, ref=c.AttemptRef("r", "other", "a")))

    def test_missing_required_job_or_stopped_run_cannot_pass(self):
        check = Acceptance(self.verifier)
        job = check.job(self.run, self.job, self.result)
        self.assertEqual(check.run(self.run, (job,)).finding.verdict, "pass")
        self.assertEqual(check.run(self.run, ()).finding.verdict, "incomplete")
        self.assertEqual(check.run(replace(self.run, stop_requested=True), (job,)).finding.verdict, "incomplete")
        extra = c.Job("r", "required", "another goal", ())
        self.assertEqual(check.run(replace(self.run, derived_interpretation=(self.job, extra)),
                                   (job,)).finding.verdict, "incomplete")

    def test_run_goal_separately_checked_with_original_intent(self):
        seen = []
        def verify(request):
            seen.append(request)
            result = self.verifier(request)
            return replace(result, goal=Finding("fail")) if request.kind == "run" else result
        check = Acceptance(verify)
        job = check.job(self.run, self.job, self.result)
        self.assertTrue(job.completed)
        self.assertEqual(check.run(self.run, (job,)).finding.verdict, "fail")
        self.assertEqual(seen[-1].run.original_intent, "Human Goal")

    def test_all_unperformed_verdicts_stay_distinct(self):
        for verdict in ("not_run", "incomplete", "blocked", "fail"):
            check = Acceptance(lambda r: replace(self.verifier(r), goal=Finding(verdict)))
            self.assertEqual(check.job(self.run, self.job, self.result).ac.verdict, verdict)


if __name__ == "__main__":
    unittest.main()
