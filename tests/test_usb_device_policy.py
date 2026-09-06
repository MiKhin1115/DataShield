import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from dlp_agent.agent import UsbDlpAgent, utc_now_iso
from dlp_agent.file_monitor import FileCopyEvent
from dlp_agent.incident_store import IncidentStore
from dlp_agent.rbac import UserStore
from dlp_agent.usb_detector import UsbDevice
from dlp_agent.usb_enforcement import UsbEnforcementResult
from dlp_agent.usb_registry import UsbRegistry


class FakeEnforcer:
    def __init__(self, result: UsbEnforcementResult) -> None:
        self.result = result
        self.devices: list[UsbDevice] = []

    def block(self, device: UsbDevice) -> UsbEnforcementResult:
        self.devices.append(device)
        return self.result


class FakeAlerter:
    def __init__(self) -> None:
        self.incidents: list[dict[str, object]] = []

    def notify(self, incident: dict[str, object]) -> list[object]:
        self.incidents.append(incident)
        return []


class UsbDevicePolicyTests(TestCase):
    def _agent(
        self,
        directory: str,
        registry: UsbRegistry,
        enforcer: FakeEnforcer,
        alerter: FakeAlerter,
    ) -> UsbDlpAgent:
        return UsbDlpAgent(
            incident_store=IncidentStore(Path(directory) / "incidents.jsonl"),
            usb_registry=registry,
            user_store=UserStore(Path(directory) / "users.json"),
            usb_enforcer=enforcer,
            alerter=alerter,  # type: ignore[arg-type]
        )

    def test_unknown_device_alerts_without_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = UsbRegistry(Path(directory) / "usb.json")
            enforcer = FakeEnforcer(UsbEnforcementResult(True, "Blocked", "done"))
            alerter = FakeAlerter()
            agent = self._agent(directory, registry, enforcer, alerter)
            device = UsbDevice(
                device_id="E:",
                drive=directory,
                name="Test USB",
                volume_name="TEST",
                filesystem="FAT32",
                size=100,
                serial_number="SERIAL-UNKNOWN",
            )
            agent.monitor.add_root(Path(device.drive))
            agent.device_inserted_at[device.device_id] = utc_now_iso()

            incident = agent.process_device_insertion(device)

            self.assertIsNotNone(incident)
            self.assertEqual(incident["usb_authorization_status"], "unknown")
            self.assertEqual(incident["policy_decision"], "Alert")
            self.assertEqual(incident["device_id"], "SERIAL-UNKNOWN")
            self.assertEqual(enforcer.devices, [])
            self.assertIn(Path(directory).absolute(), agent.monitor.roots)
            self.assertEqual(len(alerter.incidents), 1)

    def test_unauthorized_device_is_ejected_and_action_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = UsbRegistry(Path(directory) / "usb.json")
            registry.upsert("SERIAL-DENIED", "Denied USB", "unauthorized")
            enforcer = FakeEnforcer(
                UsbEnforcementResult(
                    True,
                    "Blocked - device safely ejected",
                    "Windows ejected E:",
                )
            )
            alerter = FakeAlerter()
            agent = self._agent(directory, registry, enforcer, alerter)
            device = UsbDevice(
                device_id="E:",
                drive=directory,
                name="Denied USB",
                volume_name="DENIED",
                filesystem="FAT32",
                size=100,
                serial_number="SERIAL-DENIED",
            )
            agent.monitor.add_root(Path(device.drive))

            incident = agent.process_device_insertion(device)

            self.assertEqual(incident["policy_decision"], "Block")
            self.assertEqual(incident["action_taken"], "Blocked - device safely ejected")
            self.assertEqual(enforcer.devices, [device])
            self.assertNotIn(Path(directory).absolute(), agent.monitor.roots)
            event_types = [item["event_type"] for item in incident["timeline"]]
            self.assertIn("device_blocked", event_types)

    def test_failed_block_keeps_drive_monitored_and_reports_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = UsbRegistry(Path(directory) / "usb.json")
            registry.upsert("SERIAL-DENIED", "Denied USB", "blocked")
            enforcer = FakeEnforcer(
                UsbEnforcementResult(
                    False,
                    "Block failed - drive remains monitored",
                    "Windows refused the eject request",
                )
            )
            alerter = FakeAlerter()
            agent = self._agent(directory, registry, enforcer, alerter)
            device = UsbDevice(
                device_id="E:",
                drive=directory,
                name="Denied USB",
                volume_name="DENIED",
                filesystem="FAT32",
                size=100,
                serial_number="SERIAL-DENIED",
            )

            incident = agent.process_device_insertion(device)

            self.assertEqual(incident["action_taken"], "Block failed - drive remains monitored")
            self.assertIn(Path(directory).absolute(), agent.monitor.roots)
            event_types = [item["event_type"] for item in incident["timeline"]]
            self.assertIn("device_block_failed", event_types)

    def test_usb_file_events_wait_for_soc_decision(self) -> None:
        for device_status, minimum_risk in (
            ("unknown", 50),
            ("unauthorized", 90),
            ("authorized", 0),
        ):
            with self.subTest(device_status=device_status), tempfile.TemporaryDirectory() as directory:
                registry = UsbRegistry(Path(directory) / "usb.json")
                if device_status != "unknown":
                    registry.upsert("SERIAL-1", "Test USB", device_status)
                agent = self._agent(
                    directory,
                    registry,
                    FakeEnforcer(UsbEnforcementResult(True, "Blocked", "done")),
                    FakeAlerter(),
                )
                device = UsbDevice(
                    device_id="E:",
                    drive=directory,
                    name="Test USB",
                    volume_name="TEST",
                    filesystem="FAT32",
                    size=100,
                    serial_number="SERIAL-1",
                )
                agent.devices[device.device_id] = device
                path = Path(directory) / "public.txt"
                path.write_text("Public product announcement", encoding="utf-8")
                stat = path.stat()

                with patch(
                    "dlp_agent.agent.system_context",
                    return_value=("WORKSTATION", ["192.168.100.146", "172.23.160.1"]),
                ):
                    incident = agent.scan_file_event(
                        FileCopyEvent(
                            root=Path(directory),
                            path=path,
                            size=stat.st_size,
                            modified_ns=stat.st_mtime_ns,
                            change_type="created",
                        )
                    )

                self.assertEqual(incident.usb_authorization_status, device_status)
                self.assertEqual(incident.policy_decision, "Alert")
                self.assertEqual(incident.action_taken, "Awaiting SOC decision")
                self.assertEqual(incident.enforcement_state, "pending_soc")
                self.assertEqual(incident.source_ip, "192.168.100.146")
                self.assertGreaterEqual(incident.risk_score, minimum_risk)
