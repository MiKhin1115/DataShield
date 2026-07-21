import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase

from dlp_agent.evidence_vault import EvidenceVault


def protect(data: bytes) -> bytes:
    return b"PROTECTED:" + data[::-1]


def unprotect(data: bytes) -> bytes:
    if not data.startswith(b"PROTECTED:"):
        raise ValueError("Invalid protected data")
    return data[len(b"PROTECTED:") :][::-1]


class EvidenceVaultTests(TestCase):
    def test_collects_verifies_and_decrypts_protected_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "payroll.txt"
            source.write_bytes(b"synthetic restricted payroll")
            vault = EvidenceVault(
                root / "vault",
                apply_access_controls=False,
                protector=protect,
                unprotector=unprotect,
            )
            evidence = vault.collect(
                {
                    "incident_id": "INC-TEST",
                    "file_name": source.name,
                    "file_path": str(source),
                    "file_size": source.stat().st_size,
                    "file_hashes": {"sha256": "original-hash"},
                    "risk_score": 95,
                    "action_taken": "Block",
                    "sensitive_findings": [{"kind": "salary_or_payroll"}],
                    "matched_policy_names": ["Block payroll"],
                },
                source,
            )
            verified, _ = vault.verify(evidence)
            plaintext, loaded = vault.decrypt_copy(str(evidence["evidence_id"]))

        self.assertTrue(verified)
        self.assertTrue(evidence["protected_copy_preserved"])
        self.assertEqual(plaintext, b"synthetic restricted payroll")
        self.assertEqual(loaded["incident_id"], "INC-TEST")

    def test_detects_tampering_and_removes_expired_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "secret.txt"
            source.write_bytes(b"secret")
            vault = EvidenceVault(
                root / "vault",
                apply_access_controls=False,
                protector=protect,
                unprotector=unprotect,
            )
            evidence = vault.collect(
                {"incident_id": "INC-OLD", "file_name": source.name}, source
            )
            copy_path = vault.directory / str(evidence["protected_copy_name"])
            copy_path.write_bytes(b"tampered")
            verified, _ = vault.verify(evidence)

            manifest_path = vault.directory / f"{evidence['evidence_id']}.json"
            stored = json.loads(manifest_path.read_text(encoding="utf-8"))
            stored["retained_until"] = (
                datetime.now(timezone.utc) - timedelta(days=1)
            ).isoformat()
            manifest_path.write_text(json.dumps(stored), encoding="utf-8")
            removed = vault.cleanup_expired()

        self.assertFalse(verified)
        self.assertEqual(removed, [evidence["evidence_id"]])
