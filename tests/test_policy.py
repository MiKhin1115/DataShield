from unittest import TestCase

from dlp_agent.policy import PolicyEngine
from dlp_agent.sensitive_scanner import SensitiveFinding


def finding(kind: str, severity: str) -> SensitiveFinding:
    return SensitiveFinding(kind=kind, match="masked", position=0, severity=severity)


class PolicyEngineTests(TestCase):
    def setUp(self) -> None:
        self.engine = PolicyEngine()

    def test_public_file_is_allowed(self) -> None:
        assessment = self.engine.assess([])

        self.assertEqual(assessment.file_classification, "Public")
        self.assertEqual(assessment.risk_score, 0)
        self.assertEqual(assessment.policy_decision, "Allow")

    def test_low_or_medium_finding_is_internal_and_alerted(self) -> None:
        assessment = self.engine.assess([finding("email", "low")])

        self.assertEqual(assessment.file_classification, "Internal")
        self.assertEqual(assessment.risk_score, 6)
        self.assertEqual(assessment.policy_decision, "Alert")

    def test_high_finding_is_confidential_and_alerted(self) -> None:
        assessment = self.engine.assess([finding("bank_account", "high")])

        self.assertEqual(assessment.file_classification, "Confidential")
        self.assertEqual(assessment.risk_score, 28)
        self.assertEqual(assessment.policy_decision, "Alert")

    def test_critical_finding_is_restricted_and_blocked(self) -> None:
        assessment = self.engine.assess([finding("api_key", "critical")])

        self.assertEqual(assessment.file_classification, "Restricted")
        self.assertEqual(assessment.risk_score, 55)
        self.assertEqual(assessment.policy_decision, "Block")

    def test_multiple_findings_raise_risk_score_to_100(self) -> None:
        assessment = self.engine.assess(
            [
                finding("password", "critical"),
                finding("api_key", "critical"),
                finding("bank_account", "high"),
            ]
        )

        self.assertEqual(assessment.risk_score, 100)
        self.assertEqual(assessment.policy_decision, "Block")

    def test_scan_error_is_confidential_and_alerted(self) -> None:
        assessment = self.engine.assess([], "Permission denied")

        self.assertEqual(assessment.file_classification, "Confidential")
        self.assertEqual(assessment.risk_score, 40)
        self.assertEqual(assessment.policy_decision, "Alert")
