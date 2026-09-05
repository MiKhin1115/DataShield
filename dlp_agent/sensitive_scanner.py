from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
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
    ".tsv",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

MAX_SCAN_BYTES = 2_000_000
MAX_ARCHIVE_MEMBER_BYTES = 5_000_000
MAX_ARCHIVE_TOTAL_BYTES = 20_000_000
MAX_ARCHIVE_ENTRIES = 1_000
MAX_ARCHIVE_DEPTH = 3


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

    def scan_file(self, path: Path, display_name: str | None = None) -> ScanResult:
        extraction_errors: list[str] = []
        try:
            text = self._extract_text(path, extraction_errors)
        except Exception as exc:
            return ScanResult(file_path=str(path), readable=False, findings=[], error=str(exc))

        findings = self.scan_text(f"{display_name or path.name} {text}")
        error = "; ".join(dict.fromkeys(extraction_errors)) or None
        return ScanResult(
            file_path=str(path),
            readable=True,
            findings=findings,
            error=error,
        )

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

    def _extract_text(self, path: Path, errors: list[str]) -> str:
        suffix = path.suffix.lower()
        if zipfile.is_zipfile(path):
            if suffix == ".docx":
                try:
                    return self._extract_docx_text(path)
                except (KeyError, ElementTree.ParseError):
                    pass
            if suffix == ".xlsx":
                try:
                    return self._extract_xlsx_text(path)
                except (KeyError, ElementTree.ParseError):
                    pass
            return self._extract_zip_text(path, errors)
        if suffix == ".pdf":
            return self._extract_pdf_text(path, errors, path.name)
        return self._read_text_bytes(path)

    def _read_text_bytes(self, path: Path) -> str:
        return self._decode_text(path.read_bytes()[:MAX_SCAN_BYTES])

    def _extract_docx_text(self, source: Path | BinaryIO) -> str:
        with zipfile.ZipFile(source) as archive:
            xml = archive.read("word/document.xml")
        root = ElementTree.fromstring(xml)
        return " ".join(node.text or "" for node in root.iter() if node.text)

    def _extract_xlsx_text(self, source: Path | BinaryIO) -> str:
        parts: list[str] = []
        with zipfile.ZipFile(source) as archive:
            for name in archive.namelist():
                if name == "xl/sharedStrings.xml" or name.startswith("xl/worksheets/"):
                    try:
                        root = ElementTree.fromstring(archive.read(name))
                    except ElementTree.ParseError:
                        continue
                    parts.extend(node.text or "" for node in root.iter() if node.text)
        return " ".join(parts)

    def _extract_pdf_text(
        self,
        source: Path | BinaryIO,
        errors: list[str],
        label: str,
    ) -> str:
        try:
            from pypdf import PdfReader
        except ImportError:
            errors.append(f"PDF extraction unavailable for {label}")
            return ""
        try:
            reader = PdfReader(source)
            return " ".join(page.extract_text() or "" for page in reader.pages)
        except Exception:
            errors.append(f"Could not extract PDF content from {label}")
            return ""

    def _extract_zip_text(self, source: Path | BinaryIO, errors: list[str]) -> str:
        parts: list[str] = []
        remaining_bytes = [MAX_ARCHIVE_TOTAL_BYTES]
        remaining_entries = [MAX_ARCHIVE_ENTRIES]
        with zipfile.ZipFile(source) as archive:
            self._extract_zip_archive(
                archive,
                parts,
                errors,
                remaining_bytes,
                remaining_entries,
                depth=0,
            )
        return " ".join(parts)

    def _extract_zip_archive(
        self,
        archive: zipfile.ZipFile,
        parts: list[str],
        errors: list[str],
        remaining_bytes: list[int],
        remaining_entries: list[int],
        depth: int,
    ) -> None:
        for info in archive.infolist():
            if remaining_entries[0] <= 0:
                errors.append("Archive entry limit reached before inspection completed")
                return
            remaining_entries[0] -= 1
            parts.append(info.filename)
            if info.is_dir():
                continue
            if remaining_bytes[0] <= 0:
                errors.append("Archive content limit reached before inspection completed")
                continue

            read_limit = min(MAX_ARCHIVE_MEMBER_BYTES, remaining_bytes[0])
            try:
                with archive.open(info) as member:
                    data = member.read(read_limit + 1)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                errors.append(f"Could not inspect archive member {info.filename}")
                continue

            truncated = len(data) > read_limit
            if truncated:
                data = data[:read_limit]
                errors.append(f"Archive member limit reached for {info.filename}")
            remaining_bytes[0] -= len(data)
            parts.append(
                self._extract_archive_member(
                    info.filename,
                    data,
                    parts,
                    errors,
                    remaining_bytes,
                    remaining_entries,
                    depth,
                    truncated,
                )
            )

    def _extract_archive_member(
        self,
        name: str,
        data: bytes,
        parts: list[str],
        errors: list[str],
        remaining_bytes: list[int],
        remaining_entries: list[int],
        depth: int,
        truncated: bool,
    ) -> str:
        suffix = Path(name).suffix.lower()
        member_stream = io.BytesIO(data)
        if not truncated and zipfile.is_zipfile(member_stream):
            member_stream.seek(0)
            if suffix == ".docx":
                try:
                    return self._extract_docx_text(member_stream)
                except (KeyError, ElementTree.ParseError, zipfile.BadZipFile):
                    member_stream.seek(0)
            elif suffix == ".xlsx":
                try:
                    return self._extract_xlsx_text(member_stream)
                except (KeyError, ElementTree.ParseError, zipfile.BadZipFile):
                    member_stream.seek(0)
            if depth >= MAX_ARCHIVE_DEPTH:
                errors.append(f"Nested archive depth limit reached for {name}")
                return ""
            try:
                with zipfile.ZipFile(member_stream) as nested_archive:
                    self._extract_zip_archive(
                        nested_archive,
                        parts,
                        errors,
                        remaining_bytes,
                        remaining_entries,
                        depth + 1,
                    )
            except zipfile.BadZipFile:
                errors.append(f"Could not inspect nested archive {name}")
            return ""
        if suffix == ".pdf":
            member_stream.seek(0)
            return self._extract_pdf_text(member_stream, errors, name)
        return self._decode_text(data)

    @staticmethod
    def _decode_text(data: bytes) -> str:
        if data.startswith(b"\xef\xbb\xbf"):
            return data.decode("utf-8-sig", errors="ignore")
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16", errors="ignore")
        if data and data.count(b"\x00") > len(data) // 4:
            even_nulls = data[0::2].count(0)
            odd_nulls = data[1::2].count(0)
            preferred = "utf-16-le" if odd_nulls >= even_nulls else "utf-16-be"
            try:
                return data.decode(preferred)
            except UnicodeDecodeError:
                pass
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("cp1252", errors="ignore")

    @staticmethod
    def _mask(value: str) -> str:
        clean = value.strip()
        if len(clean) <= 8:
            return clean
        return f"{clean[:4]}...{clean[-4:]}"
