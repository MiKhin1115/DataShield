from unittest import TestCase

from dlp_agent.sensitive_scanner import SensitiveDataScanner


class SensitiveDataScannerTests(TestCase):
    def test_detects_core_sensitive_values(self) -> None:
        scanner = SensitiveDataScanner()
        findings = scanner.scan_text(
            "CONFIDENTIAL payroll file. "
            "Email alice@example.com. "
            "password=SuperSecret123 "
            "api_key=abcd1234abcd1234abcd1234 "
            "bank account: 1234-5678-9012"
        )

        kinds = {finding.kind for finding in findings}

        self.assertIn("confidential_keyword", kinds)
        self.assertIn("salary_or_payroll", kinds)
        self.assertIn("email", kinds)
        self.assertIn("password", kinds)
        self.assertIn("api_key", kinds)
        self.assertIn("bank_account", kinds)

    def test_masks_long_matches(self) -> None:
        scanner = SensitiveDataScanner()
        findings = scanner.scan_text("password=VeryLongPassword123")

        self.assertEqual(findings[0].match, "pass...d123")

