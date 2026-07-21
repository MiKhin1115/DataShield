from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree


TEXT_EXTENSIONS = {
    ".bat",
    ".cfg",
    ".conf",
    ".csv",
    ".env",
    ".ini",
    ".json",
    ".log",
    ".md",
    ".ps1",
    ".py",
    ".sql",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

MAX_SCAN_BYTES = 2_000_000


@dataclass(frozen=True)
class SensitiveFinding:
    kind: str
    match: str
    position: int
    severity: str


@dataclass(frozen=True)
class ScanResult:
    file_path: str
    readable: bool
    findings: list[SensitiveFinding]
    error: str | None = None


class SensitiveDataScanner:
    def __init__(self) -> None:
        self.patterns: list[tuple[str, str, re.Pattern[str]]] = [
            (
                "email",
                "low",
                re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
            ),
            (
                "phone_number",
                "medium",
                re.compile(r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?){2,4}\d{3,4}(?!\d)"),
            ),
            (
                "passport_number",
                "high",
                re.compile(r"\b(?:passport|pp|ppt)[\s:=-]*[A-Z]{1,2}\d{6,9}\b", re.IGNORECASE),
            ),
            (
                "myanmar_nrc",
                "high",
                re.compile(r"\b\d{1,2}/[A-Z]{3,10}\((?:N|NAING|E|P|T)\)\d{6}\b", re.IGNORECASE),
            ),
            (
                "bank_account",
                "high",
                re.compile(r"\b(?:account|acct|bank)[\s#:=-]*(?:\d[\s-]?){8,20}\b", re.IGNORECASE),
            ),
            (
                "password",
                "critical",
                re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{6,}", re.IGNORECASE),
            ),
            (
                "api_key",
                "critical",
                re.compile(r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}", re.IGNORECASE),
            ),
            (
                "private_key",
                "critical",
                re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),
            ),
            (
                "salary_or_payroll",
                "high",
                re.compile(r"\b(?:salary|payroll|compensation|bonus|wage|bank account number)\b", re.IGNORECASE),
            ),
            (
                "confidential_keyword",
                "medium",
                re.compile(r"\b(?:confidential|restricted|secret|internal use only|do not distribute)\b", re.IGNORECASE),
            ),
        ]

    def scan_file(self, path: Path) -> ScanResult:
        try:
            text = self._extract_text(path)
        except Exception as exc:
            return ScanResult(file_path=str(path), readable=False, findings=[], error=str(exc))

        findings = self.scan_text(text)
        return ScanResult(file_path=str(path), readable=True, findings=findings)

    def scan_text(self, text: str) -> list[SensitiveFinding]:
        findings: list[SensitiveFinding] = []
        for kind, severity, pattern in self.patterns:
            for match in pattern.finditer(text):
                findings.append(
                    SensitiveFinding(
                        kind=kind,
                        match=self._mask(match.group(0)),
                        position=match.start(),
                        severity=severity,
                    )
                )
        return sorted(findings, key=lambda finding: finding.position)

    def _extract_text(self, path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix == ".docx":
            return self._extract_docx_text(path)
        if suffix == ".xlsx":
            return self._extract_xlsx_text(path)
        if suffix in TEXT_EXTENSIONS or suffix == "":
            return self._read_text_bytes(path)
        return self._read_text_bytes(path)

    def _read_text_bytes(self, path: Path) -> str:
        data = path.read_bytes()[:MAX_SCAN_BYTES]
        return data.decode("utf-8", errors="ignore")

    def _extract_docx_text(self, path: Path) -> str:
        with zipfile.ZipFile(path) as archive:
            xml = archive.read("word/document.xml")
        root = ElementTree.fromstring(xml)
        return " ".join(node.text or "" for node in root.iter() if node.text)

    def _extract_xlsx_text(self, path: Path) -> str:
        parts: list[str] = []
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if name == "xl/sharedStrings.xml" or name.startswith("xl/worksheets/"):
                    try:
                        root = ElementTree.fromstring(archive.read(name))
                    except ElementTree.ParseError:
                        continue
                    parts.extend(node.text or "" for node in root.iter() if node.text)
        return " ".join(parts)

    @staticmethod
    def _mask(value: str) -> str:
        clean = value.strip()
        if len(clean) <= 8:
            return clean
        return f"{clean[:4]}...{clean[-4:]}"

