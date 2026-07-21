from __future__ import annotations

import ctypes
import getpass
import hashlib
import json
import os
import socket
import subprocess
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4


CRYPTPROTECT_UI_FORBIDDEN = 0x01
MAX_PROTECTED_COPY_BYTES = 25 * 1024 * 1024


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def system_context() -> tuple[str, list[str]]:
    computer_name = socket.gethostname()
    addresses: set[str] = set()
    try:
        for result in socket.getaddrinfo(computer_name, None):
            address = str(result[4][0])
            if address not in {"127.0.0.1", "::1"} and "%" not in address:
                addresses.add(address)
    except OSError:
        pass
    return computer_name, sorted(addresses)


class EvidenceVault:
    def __init__(
        self,
        directory: Path,
        retention_days: int = 90,
        preserve_files: bool = True,
        apply_access_controls: bool = True,
        protector: Callable[[bytes], bytes] | None = None,
        unprotector: Callable[[bytes], bytes] | None = None,
    ) -> None:
        self.directory = directory
        self.retention_days = max(1, retention_days)
        self.preserve_files = preserve_files
        self._protector = protector or self._dpapi_protect
        self._unprotector = unprotector or self._dpapi_unprotect
        self.directory.mkdir(parents=True, exist_ok=True)
        if apply_access_controls:
            self._restrict_directory()

    def collect(
        self,
        incident: dict[str, object],
        source_path: Path,
    ) -> dict[str, object]:
        self.cleanup_expired()
        evidence_id = f"EVD-{uuid4().hex[:12].upper()}"
        collected_at = utc_now()
        retained_until = collected_at + timedelta(days=self.retention_days)
        computer_name, ip_addresses = system_context()
        suffix = source_path.suffix.lower() or "no extension"

        metadata: dict[str, object] = {
            "evidence_id": evidence_id,
            "incident_id": incident.get("incident_id"),
            "collected_at": collected_at.isoformat(),
            "retained_until": retained_until.isoformat(),
            "file_name": incident.get("file_name"),
            "file_path": incident.get("file_path"),
            "file_size": incident.get("file_size"),
            "file_type": suffix,
            "file_hashes": incident.get("file_hashes", {}),
            "usb_serial_number": incident.get("usb_serial_number", ""),
            "usb_manufacturer": incident.get("usb_manufacturer", ""),
            "usb_device_name": incident.get("device_name", ""),
            "username": incident.get("user_name", ""),
            "computer_name": computer_name,
            "ip_addresses": ip_addresses,
            "event_time": incident.get("event_time"),
            "sensitive_findings": incident.get("sensitive_findings", []),
            "matched_policies": incident.get("matched_policy_names", []),
            "action_taken": incident.get("action_taken", ""),
            "encryption": "Windows DPAPI current-user",
            "protected_copy_preserved": False,
            "protected_copy_error": None,
        }

        if self.preserve_files:
            self._preserve_copy(metadata, source_path, evidence_id)

        canonical = json.dumps(metadata, sort_keys=True, ensure_ascii=False).encode("utf-8")
        metadata["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
        manifest_path = self.directory / f"{evidence_id}.json"
        manifest_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
        self._restrict_file(manifest_path)
        return metadata

    def load(self, evidence_id: str) -> dict[str, object] | None:
        if not evidence_id.startswith("EVD-") or not evidence_id.replace("-", "").isalnum():
            return None
        path = self.directory / f"{evidence_id}.json"
        if not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def verify(self, evidence: dict[str, object]) -> tuple[bool, str]:
        expected_manifest = str(evidence.get("manifest_sha256", ""))
        manifest = {key: value for key, value in evidence.items() if key != "manifest_sha256"}
        actual_manifest = hashlib.sha256(
            json.dumps(manifest, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        if expected_manifest != actual_manifest:
            return False, "Evidence manifest integrity check failed"
        if evidence.get("protected_copy_preserved"):
            copy_name = str(evidence.get("protected_copy_name", ""))
            copy_path = self.directory / copy_name
            if not copy_path.is_file():
                return False, "Protected evidence copy is missing"
            actual_copy_hash = hashlib.sha256(copy_path.read_bytes()).hexdigest()
            if actual_copy_hash != evidence.get("protected_copy_sha256"):
                return False, "Protected evidence copy integrity check failed"
        return True, "Evidence integrity verified"

    def decrypt_copy(self, evidence_id: str) -> tuple[bytes, dict[str, object]]:
        evidence = self.load(evidence_id)
        if evidence is None:
            raise FileNotFoundError("Evidence record not found")
        verified, message = self.verify(evidence)
        if not verified:
            raise ValueError(message)
        if not evidence.get("protected_copy_preserved"):
            raise FileNotFoundError("No protected file copy is available")
        encrypted = (self.directory / str(evidence["protected_copy_name"])).read_bytes()
        return self._unprotector(encrypted), evidence

    def cleanup_expired(self) -> list[str]:
        removed: list[str] = []
        now = utc_now()
        for manifest_path in self.directory.glob("EVD-*.json"):
            try:
                metadata = json.loads(manifest_path.read_text(encoding="utf-8"))
                expiry = datetime.fromisoformat(str(metadata.get("retained_until")))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
            if expiry > now:
                continue
            copy_name = str(metadata.get("protected_copy_name", ""))
            if copy_name:
                copy_path = self.directory / copy_name
                if copy_path.is_file():
                    copy_path.unlink()
            manifest_path.unlink()
            removed.append(str(metadata.get("evidence_id", manifest_path.stem)))
        return removed

    def _preserve_copy(
        self,
        metadata: dict[str, object],
        source_path: Path,
        evidence_id: str,
    ) -> None:
        try:
            size = source_path.stat().st_size
            if size > MAX_PROTECTED_COPY_BYTES:
                raise ValueError("File exceeds the 25 MB protected-copy limit")
            plaintext = source_path.read_bytes()
            encrypted = self._protector(plaintext)
            copy_name = f"{evidence_id}.dpapi"
            copy_path = self.directory / copy_name
            copy_path.write_bytes(encrypted)
            self._restrict_file(copy_path)
            metadata.update(
                protected_copy_preserved=True,
                protected_copy_name=copy_name,
                protected_copy_sha256=hashlib.sha256(encrypted).hexdigest(),
            )
        except Exception as exc:
            metadata["protected_copy_error"] = str(exc)

    def _restrict_directory(self) -> None:
        if os.name != "nt":
            os.chmod(self.directory, 0o700)
            return
        try:
            completed = subprocess.run(
                ["whoami"], check=False, capture_output=True, text=True, timeout=5
            )
            principal = completed.stdout.strip() or getpass.getuser()
            subprocess.run(
                [
                    "icacls",
                    str(self.directory),
                    "/inheritance:r",
                    "/grant:r",
                    f"{principal}:(OI)(CI)F",
                    "/grant:r",
                    "SYSTEM:(OI)(CI)F",
                ],
                check=False,
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            pass

    @staticmethod
    def _restrict_file(path: Path) -> None:
        if os.name != "nt":
            os.chmod(path, 0o600)

    @staticmethod
    def _dpapi_protect(data: bytes) -> bytes:
        if os.name != "nt":
            raise RuntimeError("Windows DPAPI is unavailable on this operating system")
        input_blob, input_buffer = EvidenceVault._blob(data)
        output_blob = DataBlob()
        crypt32 = ctypes.windll.crypt32
        if not crypt32.CryptProtectData(
            ctypes.byref(input_blob),
            "USB DLP evidence",
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        ):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(output_blob.pbData)
            del input_buffer

    @staticmethod
    def _dpapi_unprotect(data: bytes) -> bytes:
        if os.name != "nt":
            raise RuntimeError("Windows DPAPI is unavailable on this operating system")
        input_blob, input_buffer = EvidenceVault._blob(data)
        output_blob = DataBlob()
        crypt32 = ctypes.windll.crypt32
        if not crypt32.CryptUnprotectData(
            ctypes.byref(input_blob),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        ):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(output_blob.pbData)
            del input_buffer

    @staticmethod
    def _blob(data: bytes) -> tuple[DataBlob, ctypes.Array[ctypes.c_char]]:
        buffer = ctypes.create_string_buffer(data, len(data))
        blob = DataBlob(
            len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        )
        return blob, buffer
