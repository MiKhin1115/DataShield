import tempfile
from pathlib import Path
from unittest import TestCase

from dlp_agent.agent import UsbDlpAgent, utc_now_iso
from dlp_agent.alerting import AlertResult
from dlp_agent.evidence_vault import EvidenceVault
from dlp_agent.file_monitor import FileCopyEvent
from dlp_agent.incident_store import IncidentStore
from dlp_agent.policy import PolicyEngine
from dlp_agent.policy_store import PolicyStore
from dlp_agent.usb_detector import UsbDevice
from dlp_agent.usb_registry import UsbRegistry


class FakeUserStore:
    def find_by_username(self, username: str) -> None:
        return None


class FakeAlerter:
    def notify(self, incident: dict[str, object]) -> list[AlertResult]:
        return [AlertResult(sent=True, channel="console")]


def protect(data: bytes) -> bytes:
    return b"ENC" + data[::-1]


def unprotect(data: bytes) -> bytes:
    return data[3:][::-1]


class AgentEvidenceTests(TestCase):
    def test_high_risk_incident_collects_evidence_and_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "credentials.env"
            source.write_text(
                "password=SyntheticPassword123 api_key=abcdefghijklmnop12345678",
                encoding="utf-8",
            )
            expected_plaintext = source.read_bytes()
            store = IncidentStore(root / "incidents.jsonl")
            vault = EvidenceVault(
                root / "evidence",
                apply_access_controls=False,
                protector=protect,
                unprotector=unprotect,
            )
            policy_store = PolicyStore(root / "policies.json")
            agent = UsbDlpAgent(
                policy_engine=PolicyEngine(policy_store.list),
                policy_store=policy_store,
                incident_store=store,
                usb_registry=UsbRegistry(root / "usb.json"),
                user_store=FakeUserStore(),
                evidence_vault=vault,
                alerter=FakeAlerter(),
            )
            device = UsbDevice(
                "E:",
                str(root),
                "Test USB",
                "TEST",
                "FAT32",
                1024,
                "SERIAL-123",
                "Example Manufacturer",
                "Example Model",
            )
            agent.devices[device.device_id] = device
            agent.device_inserted_at[device.device_id] = utc_now_iso()
            stat = source.stat()
            record = agent.process_file_event(
                FileCopyEvent(root, source, stat.st_size, stat.st_mtime_ns, "created")
            )
            event_types = [event["event_type"] for event in record["timeline"]]
            evidence_id = record["evidence"]["evidence_id"]
            plaintext, _ = vault.decrypt_copy(evidence_id)

        self.assertEqual(record["usb_serial_number"], "SERIAL-123")
        self.assertEqual(record["file_type"], ".env")
        self.assertIn("evidence_collected", event_types)
        self.assertIn("soc_alert", event_types)
        self.assertEqual(plaintext, expected_plaintext)
