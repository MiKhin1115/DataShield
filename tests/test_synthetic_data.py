import tempfile
from pathlib import Path
from unittest import TestCase

from dlp_agent.policy import PolicyEngine
from dlp_agent.sensitive_scanner import SensitiveDataScanner
from dlp_agent.synthetic_data import generate_synthetic_dataset


class SyntheticDataTests(TestCase):
    def test_generates_fake_files_covering_policy_levels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = generate_synthetic_dataset(Path(directory))
            scanner = SensitiveDataScanner()
            engine = PolicyEngine()
            classifications = {
                engine.assess(scanner.scan_file(path).findings).file_classification
                for path in paths
            }

        self.assertEqual(len(paths), 6)
        self.assertIn("Public", classifications)
        self.assertIn("Internal", classifications)
        self.assertIn("Confidential", classifications)
        self.assertIn("Restricted", classifications)
