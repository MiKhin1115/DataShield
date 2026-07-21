import tempfile
from pathlib import Path
from unittest import TestCase

from dlp_agent.policy import PolicyEngine
from dlp_agent.policy_store import PolicyStore
from dlp_agent.sensitive_scanner import SensitiveFinding


class PolicyStoreTests(TestCase):
    def test_creates_updates_disables_and_deletes_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = PolicyStore(Path(directory) / "policies.json")
            policy = store.create(
                {
                    "name": "HR internal exception",
                    "description": "Allow HR internal documents",
                    "priority": 1,
                    "enabled": True,
                    "conditions": [
                        {"field": "department", "operator": "equals", "value": "HR"},
                        {"field": "file_classification", "operator": "equals", "value": "Internal"},
                    ],
                    "action": "Allow",
                    "notify_soc": False,
                }
            )
            updated = store.update(policy["policy_id"], {**policy, "action": "Alert"})
            disabled = store.set_enabled(policy["policy_id"], False)
            deleted = store.delete(policy["policy_id"])

        self.assertEqual(updated["action"], "Alert")
        self.assertFalse(disabled["enabled"])
        self.assertTrue(deleted)

    def test_higher_priority_policy_overrides_baseline_decision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = PolicyStore(Path(directory) / "policies.json")
            store.create(
                {
                    "name": "HR internal exception",
                    "priority": 1,
                    "enabled": True,
                    "conditions": [
                        {"field": "department", "operator": "equals", "value": "Human Resources"},
                        {"field": "file_classification", "operator": "equals", "value": "Internal"},
                    ],
                    "action": "Allow",
                    "notify_soc": False,
                }
            )
            engine = PolicyEngine(store.list)
            assessment = engine.assess(
                [SensitiveFinding("email", "test@example.test", 0, "low")],
                context={"department": "Human Resources"},
            )

        self.assertEqual(assessment.policy_decision, "Allow")
        self.assertEqual(assessment.matched_policy_names[0], "HR internal exception")
        self.assertFalse(assessment.notify_soc)

    def test_sensitive_count_condition_matches_selected_type(self) -> None:
        findings = [SensitiveFinding("bank_account", "masked", index, "high") for index in range(6)]
        policy = {
            "policy_id": "POL-COUNT",
            "name": "Bank account volume",
            "enabled": True,
            "priority": 1,
            "conditions": [
                {"field": "sensitive_data_count", "operator": "greater_than", "value": 5, "data_type": "bank_account"}
            ],
            "action": "Alert",
            "notify_soc": True,
            "risk_score_override": 95,
        }
        assessment = PolicyEngine(lambda: [policy]).assess(findings)

        self.assertEqual(assessment.policy_decision, "Alert")
        self.assertEqual(assessment.risk_score, 100)
        self.assertEqual(assessment.matched_policy_ids, ["POL-COUNT"])
