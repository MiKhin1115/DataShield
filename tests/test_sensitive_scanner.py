from pathlib import Path
from io import BytesIO
from tempfile import TemporaryDirectory
from unittest import TestCase
from zipfile import ZipFile

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

    def test_detects_sensitive_content_in_zip_with_innocent_member_name(self) -> None:
        with TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "public access.zip"
            with ZipFile(archive_path, "w") as archive:
                archive.writestr("normal.txt", "password=Secret123")

            result = SensitiveDataScanner().scan_file(archive_path)

        self.assertTrue(result.readable)
        self.assertIn("password", {finding.kind for finding in result.findings})

    def test_scans_later_members_after_large_innocent_content(self) -> None:
        with TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "normal.zip"
            with ZipFile(archive_path, "w") as archive:
                archive.writestr("large.txt", "A" * 2_100_000)
                archive.writestr("normal.txt", "password=Secret123")

            result = SensitiveDataScanner().scan_file(archive_path)

        self.assertIn("password", {finding.kind for finding in result.findings})

    def test_detects_utf16_content_without_sensitive_filenames(self) -> None:
        with TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "normal.zip"
            with ZipFile(archive_path, "w") as archive:
                archive.writestr("normal.txt", "password=Secret123".encode("utf-16-le"))

            result = SensitiveDataScanner().scan_file(archive_path)

        self.assertIn("password", {finding.kind for finding in result.findings})

    def test_reuses_docx_extractor_for_document_inside_zip(self) -> None:
        document = BytesIO()
        with ZipFile(document, "w") as docx:
            docx.writestr(
                "word/document.xml",
                "<document><p>password=Secret123</p></document>",
            )

        with TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "normal.zip"
            with ZipFile(archive_path, "w") as archive:
                archive.writestr("normal.docx", document.getvalue())

            result = SensitiveDataScanner().scan_file(archive_path)

        self.assertIn("password", {finding.kind for finding in result.findings})

    def test_detects_sensitive_content_in_zip_with_sensitive_member_name(self) -> None:
        with TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "documents.zip"
            with ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "confidential-payroll.txt",
                    "bank account: 1234-5678-9012",
                )

            result = SensitiveDataScanner().scan_file(archive_path)

        kinds = {finding.kind for finding in result.findings}
        self.assertIn("salary_or_payroll", kinds)
        self.assertIn("bank_account", kinds)

    def test_detects_sensitive_content_in_nested_zip(self) -> None:
        with TemporaryDirectory() as tmp:
            inner_path = Path(tmp) / "inner.zip"
            with ZipFile(inner_path, "w") as archive:
                archive.writestr("readme.txt", "api_key=abcd1234abcd1234abcd1234")

            outer_path = Path(tmp) / "outer.zip"
            with ZipFile(outer_path, "w") as archive:
                archive.write(inner_path, "attachments/backup.bin")

            result = SensitiveDataScanner().scan_file(outer_path)

        self.assertIn("api_key", {finding.kind for finding in result.findings})

    def test_zip_cannot_evade_scanning_with_a_document_extension(self) -> None:
        with TemporaryDirectory() as tmp:
            disguised_archive = Path(tmp) / "innocent.docx"
            with ZipFile(disguised_archive, "w") as archive:
                archive.writestr("notes.txt", "password=VerySecretPassword123")

            result = SensitiveDataScanner().scan_file(disguised_archive)

        self.assertTrue(result.readable)
        self.assertIn("password", {finding.kind for finding in result.findings})
