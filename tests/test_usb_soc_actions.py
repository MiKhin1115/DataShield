import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from dlp_agent.dashboard import DashboardHandler
from dlp_agent.incident_store import IncidentStore
from dlp_agent.usb_enforcement import UsbEnforcementResult


class FakeWindowsUsbEnforcer:
    result = UsbEnforcementResult(
        True,
        "Blocked - device safely ejected",
        "Windows ejected D:\\",
    )
    transfers: list[tuple[str, str]] = []

    def block_transfer(self, drive_path: str, file_path: str) -> UsbEnforcementResult:
        self.transfers.append((drive_path, file_path))
        return self.result


class UsbSocActionTests(TestCase):
    def _handler(self, store: IncidentStore, action: str) -> DashboardHandler:
        handler = object.__new__(DashboardHandler)
        handler.store = store
        handler._json_body = lambda: {"action": action}
        handler._serve_json = lambda *args, **kwargs: None
        handler._audit_change = lambda *args, **kwargs: None
        return handler

    @staticmethod
    def _append_pending_incident(store: IncidentStore, incident_id: str) -> None:
        store.append(
            {
                "incident_id": incident_id,
                "incident_type": "usb_file",
                "device_id": "USB-SERIAL-1",
                "drive": "D:\\",
                "file_path": "D:\\sensitive.csv",
                "policy_decision": "Alert",
                "enforcement_state": "pending_soc",
                "incident_status": "Open",
                "timeline": [],
            }
        )

    def test_allow_keeps_usb_available_and_closes_alert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.jsonl")
            self._append_pending_incident(store, "INC-USB-ALLOW")

            self._handler(store, "allow")._enforce_incident("INC-USB-ALLOW")
            updated = store.get("INC-USB-ALLOW")

        self.assertEqual(updated["manual_action"], "allow")
        self.assertEqual(updated["enforcement_state"], "allowed")
        self.assertEqual(updated["incident_status"], "Closed")
        self.assertEqual(updated["timeline"][-1]["event_type"], "soc_enforcement")

    def test_block_safely_ejects_usb_without_wiping_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.jsonl")
            self._append_pending_incident(store, "INC-USB-BLOCK")
            FakeWindowsUsbEnforcer.transfers = []

            with patch(
                "dlp_agent.usb_enforcement.WindowsUsbEnforcer",
                FakeWindowsUsbEnforcer,
            ):
                self._handler(store, "block")._enforce_incident("INC-USB-BLOCK")
            updated = store.get("INC-USB-BLOCK")

        self.assertEqual(
            FakeWindowsUsbEnforcer.transfers,
            [("D:\\", "D:\\sensitive.csv")],
        )
        self.assertEqual(updated["manual_action"], "block")
        self.assertEqual(updated["enforcement_state"], "blocked")
        self.assertEqual(updated["incident_status"], "Resolved")
        self.assertIn("safely ejected", updated["action_taken"])

    def test_legacy_usb_incident_uses_current_routed_ip(self) -> None:
        incident = {
            "incident_id": "INC-USB-LEGACY",
            "drive": "D:\\",
            "ip_addresses": ["172.23.160.1"],
            "policy_decision": "Block",
            "action_taken": "Block",
            "incident_status": "Open",
        }
        with patch(
            "dlp_agent.dashboard._source_ipv4_for_destination",
            return_value="192.168.100.146",
        ):
            public = DashboardHandler._public_incident(incident)

        self.assertEqual(public["source_ip"], "192.168.100.146")
        self.assertEqual(public["ip_addresses"], ["192.168.100.146"])
        self.assertEqual(public["policy_decision"], "Alert")
        self.assertEqual(public["enforcement_state"], "pending_soc")
