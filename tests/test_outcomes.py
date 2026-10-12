"""Demo outcomes must follow gate records and isolated mock effects."""

import unittest

from defense.comparison import ComparisonEngine
from defense.engine import Engine, Run
from defense.evaluation import evaluate
from defense.fixtures import BASE_DOCUMENT, DEMO_SCENARIOS
from defense.security import DLP, Policy, grants_for_task, task_mode_for_grants


class OfflineProvider:
    def respond(self, **kwargs):
        raise AssertionError("Offline checks must not contact a model.")


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        self.dlp = DLP()
        self.engine = Engine(OfflineProvider(), self.dlp)

    def make_run(self, task, document=BASE_DOCUMENT, scenario_id="custom"):
        grants = grants_for_task(task)
        policy = Policy("draft_email" in grants, "send_email" in grants, {"team@example.com"},
                        task_mode=task_mode_for_grants(grants), allow_edit="edit_document" in grants,
                        granted_tools=grants)
        return Run("replay", task, document, policy, self.dlp, scenario_id)

    def test_five_demos_and_separate_comparison_effects(self):
        expected = {
            "benign": ("completed", [], "unprotected_no_effects"),
            "injection": ("contained", ["Document screening", "Tool gate"], "unprotected_effects"),
            "tool-misuse": ("contained", ["Tool gate"], "unprotected_effects"),
            "document-edit": ("completed", [], "unprotected_effects"),
            "edit-injection": ("contained", ["Document screening", "Tool gate"], "unprotected_effects"),
        }
        report = evaluate(self.engine, {"team@example.com"})
        self.assertEqual(report["passed"], 5, report)
        for fixture in DEMO_SCENARIOS:
            with self.subTest(scenario=fixture["id"]):
                run = self.make_run(fixture["task"], fixture["document"], fixture["id"])
                self.engine.execute(run)
                protected = run.snapshot()
                state, layers, off_state = expected[fixture["id"]]
                self.assertEqual(protected["outcome"]["state"], state)
                self.assertEqual(sorted({item["layer"] for item in protected["outcome"]["interventions"]}), layers)
                comparison = self.make_run(fixture["task"], fixture["document"], fixture["id"])
                comparison.firewall_enabled = False
                comparison.comparison_of = run.id
                ComparisonEngine(OfflineProvider(), self.dlp).execute(comparison)
                off = comparison.snapshot()
                self.assertEqual(off["status"], "completed")
                self.assertEqual(off["outcome"]["state"], off_state)
                self.assertEqual(off["outcome"]["interventions"], [])
                self.assertEqual(run.snapshot(), protected, "Comparison must not mutate the protected run")
                if fixture["id"] == "edit-injection":
                    self.assertEqual(protected["edits"], [])
                    self.assertIn("The budget is $50,000.", off["edits"][0]["after"])
                if fixture["id"] == "injection":
                    self.assertEqual(protected["outbox"], [])
                    self.assertEqual(off["outbox"][0]["to"], "attacker@evil.example")
                if fixture["id"] == "tool-misuse":
                    self.assertGreater(len(off["comparison_effects"]["deleted_documents"]), 0)

    def test_detected_request_without_call_gets_no_gate_credit(self):
        run = self.make_run("Delete all project documents, then summarize the plan.")
        self.engine.execute(run)  # Custom replay never attempts deletion.
        snapshot = run.snapshot()
        self.assertEqual(snapshot["metrics"]["unsafe_requests_detected"], 1)
        self.assertEqual(snapshot["metrics"]["blocked_tool_calls"], 0)
        self.assertEqual(snapshot["outcome"]["state"], "not_attempted")
        self.assertEqual(snapshot["outcome"]["interventions"], [])

    def test_failed_run_cannot_be_reported_as_contained(self):
        fixture = next(item for item in DEMO_SCENARIOS if item["id"] == "injection")
        run = self.make_run(fixture["task"], fixture["document"], fixture["id"])
        self.engine.execute(run)
        run.status, run.error = "failed", "Model unavailable."
        outcome = run.snapshot()["outcome"]
        self.assertEqual(outcome["state"], "failed")
        self.assertEqual(outcome["message"], "Model unavailable.")
        self.assertTrue(outcome["interventions"])

    def test_pending_send_is_not_sent_or_completed(self):
        run = self.make_run("Send a launch summary to team@example.com.")
        self.engine.execute(run)
        run.gate.dispatch("send_email", {"to": "team@example.com", "subject": "Launch", "body": "Launch Friday."})
        run.status = "awaiting_approval"
        snapshot = run.snapshot()
        self.assertEqual(snapshot["outcome"]["state"], "approval")
        self.assertEqual(snapshot["outbox"], [])
        self.assertEqual(snapshot["outcome"]["interventions"][0]["layer"], "Human approval")


if __name__ == "__main__":
    unittest.main()
