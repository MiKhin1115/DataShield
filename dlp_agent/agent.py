from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from uuid import uuid4

from .alerting import SocAlerter
from .evidence_vault import EvidenceVault, system_context
from .file_hashing import hash_file
from .file_monitor import FileCopyEvent, UsbFileMonitor
from .incident_store import IncidentStore
from .network_monitor import NetworkConnectionEvent, NetworkMonitor
from .policy import PolicyEngine
from .policy_store import PolicyStore
from .process_enforcer import suspend_process
from .rbac import UserStore
from .sensitive_scanner import SensitiveDataScanner
from .synthetic_data import generate_synthetic_dataset
from .usb_detector import UsbDevice, UsbDetector, WindowsUsbProvider
from .usb_enforcement import UsbEnforcer, WindowsUsbEnforcer
from .usb_registry import UsbRegistry


@dataclass(frozen=True)
class Incident:
    incident_id: str
    event_time: str
    user_name: str
    department: str
    computer_name: str
    ip_addresses: list[str]
    device_id: str
    device_name: str
    usb_serial_number: str
    usb_manufacturer: str
    usb_model: str
    usb_authorization_status: str
    drive: str
    file_name: str
    file_type: str
    file_path: str
    file_size: int
    change_type: str
    sensitive_findings: list[dict[str, object]]
    finding_count: int
    scan_readable: bool
    scan_error: str | None
    file_hashes: dict[str, str]
    hash_error: str | None
    duplicate_incident_count: int
    file_classification: str
    recommended_classification: str
    risk_score: int
    policy_decision: str
    action_taken: str
    policy_reasons: list[str]
    matched_policy_ids: list[str]
    matched_policy_names: list[str]
    notify_soc: bool
    incident_status: str
    assigned_to: str
    status_history: list[dict[str, object]]
    assignment_history: list[dict[str, object]]
    investigation_notes: list[dict[str, object]]
    timeline: list[dict[str, str]]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def classification_for(findings_count: int) -> str:
    if findings_count >= 8:
        return "Restricted"
    if findings_count >= 3:
        return "Confidential"
    if findings_count >= 1:
        return "Internal"
    return "Public"


class UsbDlpAgent:
    def __init__(
        self,
        detector: UsbDetector | None = None,
        scanner: SensitiveDataScanner | None = None,
        policy_engine: PolicyEngine | None = None,
        policy_store: PolicyStore | None = None,
        incident_store: IncidentStore | None = None,
        usb_registry: UsbRegistry | None = None,
        user_store: UserStore | None = None,
        evidence_vault: EvidenceVault | None = None,
        alerter: SocAlerter | None = None,
        usb_enforcer: UsbEnforcer | None = None,
        interval_seconds: float = 2.0,
    ) -> None:
        self.detector = detector or UsbDetector(WindowsUsbProvider())
        self.scanner = scanner or SensitiveDataScanner()
        self.policy_store = policy_store or PolicyStore(Path("data/policies.json"))
        self.policy_engine = policy_engine or PolicyEngine(self.policy_store.list)
        self.incident_store = incident_store or IncidentStore(Path("data/incidents.jsonl"))
        self.usb_registry = usb_registry or UsbRegistry(Path("data/usb_devices.json"))
        self.user_store = user_store or UserStore(Path("data/users.json"))
        self.evidence_vault = evidence_vault or EvidenceVault(Path("data/evidence"))
        self.alerter = alerter or SocAlerter()
        self.usb_enforcer = usb_enforcer or WindowsUsbEnforcer()
        self.interval_seconds = interval_seconds
        self.monitor = UsbFileMonitor()
        self.network_monitor = NetworkMonitor()
        self.devices: dict[str, UsbDevice] = {}
        self.device_inserted_at: dict[str, str] = {}

    def refresh_devices(self) -> tuple[list[UsbDevice], list[UsbDevice]]:
        events = self.detector.poll()
        inserted: list[UsbDevice] = []
        removed: list[UsbDevice] = []

        for event in events:
            if event.event_type == "inserted":
                self.devices[event.device.device_id] = event.device
                self.monitor.add_root(Path(event.device.drive))
                inserted.append(event.device)
                self.device_inserted_at[event.device.device_id] = utc_now_iso()
            elif event.event_type == "removed":
                self.devices.pop(event.device.device_id, None)
                self.monitor.remove_root(Path(event.device.drive))
                removed.append(event.device)
                self.device_inserted_at.pop(event.device.device_id, None)

        return inserted, removed

    def scan_file_event(self, event: FileCopyEvent) -> Incident:
        device = self._device_for_drive(event.root)
        device_id = self._authorization_id(device) if device else str(event.root)
        usb_status = self._authorization_status(device) if device else self.usb_registry.status(device_id)
        timeline: list[dict[str, str]] = []
        inserted_at = self.device_inserted_at.get(device.device_id if device else device_id)
        if inserted_at:
            timeline.append(
                self._timeline_event(
                    "usb_inserted", "USB device inserted", device.name if device else device_id, inserted_at
                )
            )
        timeline.append(
            self._timeline_event(
                "usb_authorization",
                f"USB device identified as {usb_status}",
                device_id,
            )
        )
        timeline.append(
            self._timeline_event(
                "copy_detected",
                "File copy operation detected",
                event.path.name,
            )
        )
        timeline.append(self._timeline_event("scan_started", "Sensitive data scan started"))
        result = self.scanner.scan_file(event.path)
        detected_types = sorted({finding.kind for finding in result.findings})
        timeline.append(
            self._timeline_event(
                "scan_completed",
                "Sensitive data scan completed",
                ", ".join(detected_types) if detected_types else "No sensitive data detected",
            )
        )
        hash_result = hash_file(event.path)
        findings = [asdict(finding) for finding in result.findings]
        user_name = getpass.getuser()
        managed_user = self.user_store.find_by_username(user_name)
        department = str(
            managed_user.get("department")
            if managed_user
            else os.environ.get("USB_DLP_DEPARTMENT", "Unknown")
        )
        assessment = self.policy_engine.assess(
            result.findings,
            result.error,
            {
                "file_size": event.size,
                "file_extension": event.path.suffix.lower(),
                "usb_authorized": usb_status == "authorized",
                "user_name": user_name,
                "department": department,
                "transfer_time": datetime.now().strftime("%H:%M"),
            },
        )
        if usb_status in {"unauthorized", "blocked"}:
            assessment = replace(
                assessment,
                risk_score=max(90, assessment.risk_score),
                policy_decision="Block",
                policy_reasons=[
                    *assessment.policy_reasons,
                    "USB device is explicitly unauthorized and all transfers are blocked",
                ],
                matched_policy_ids=[*assessment.matched_policy_ids, "USB-DEVICE-AUTHORIZATION"],
                matched_policy_names=[*assessment.matched_policy_names, "USB device authorization"],
                notify_soc=True,
            )
        elif usb_status == "unknown" and assessment.policy_decision == "Allow":
            assessment = replace(
                assessment,
                risk_score=max(50, assessment.risk_score),
                policy_decision="Alert",
                policy_reasons=[
                    *assessment.policy_reasons,
                    "USB device is not registered and requires authorization review",
                ],
                matched_policy_ids=[*assessment.matched_policy_ids, "USB-DEVICE-UNKNOWN"],
                matched_policy_names=[*assessment.matched_policy_names, "Unknown USB device review"],
                notify_soc=True,
            )
        sha256 = hash_result.hashes.get("sha256", "")
        computer_name, ip_addresses = system_context()
        timeline.extend(
            [
                self._timeline_event(
                    "classified",
                    f"File classified as {assessment.file_classification}",
                ),
                self._timeline_event(
                    "risk_scored",
                    f"Risk score calculated as {assessment.risk_score}/100",
                ),
                self._timeline_event(
                    "policy_decision",
                    f"Policy action selected: {assessment.policy_decision}",
                    ", ".join(assessment.matched_policy_names) or "Baseline policy",
                ),
            ]
        )

        return Incident(
            incident_id=f"INC-{uuid4().hex[:12].upper()}",
            event_time=utc_now_iso(),
            user_name=user_name,
            department=department,
            computer_name=computer_name,
            ip_addresses=ip_addresses,
            device_id=device_id,
            device_name=device.name if device else "Unknown USB storage",
            usb_serial_number=device.serial_number if device else "",
            usb_manufacturer=device.manufacturer if device else "",
            usb_model=device.model if device else "",
            usb_authorization_status=usb_status,
            drive=str(event.root),
            file_name=event.path.name,
            file_type=event.path.suffix.lower() or "no extension",
            file_path=str(event.path),
            file_size=event.size,
            change_type=event.change_type,
            sensitive_findings=findings,
            finding_count=len(findings),
            scan_readable=result.readable,
            scan_error=result.error,
            file_hashes=hash_result.hashes,
            hash_error=hash_result.error,
            duplicate_incident_count=self.incident_store.count_by_sha256(sha256),
            file_classification=assessment.file_classification,
            recommended_classification=assessment.file_classification,
            risk_score=assessment.risk_score,
            policy_decision=assessment.policy_decision,
            action_taken=assessment.policy_decision,
            policy_reasons=assessment.policy_reasons,
            matched_policy_ids=assessment.matched_policy_ids,
            matched_policy_names=assessment.matched_policy_names,
            notify_soc=assessment.notify_soc,
            incident_status="Open",
            assigned_to="",
            status_history=[],
            assignment_history=[],
            investigation_notes=[],
            timeline=timeline,
        )

    def process_device_insertion(self, device: UsbDevice) -> dict[str, object] | None:
        usb_status = self._authorization_status(device)
        event_time = self.device_inserted_at.get(device.device_id, utc_now_iso())
        device_id = self._authorization_id(device)
        user_name = getpass.getuser()
        managed_user = self.user_store.find_by_username(user_name)
        department = str(
            managed_user.get("department")
            if managed_user
            else os.environ.get("USB_DLP_DEPARTMENT", "Unknown")
        )
        computer_name, ip_addresses = system_context()
        timeline = [
            self._timeline_event("usb_inserted", "USB device inserted", device.name, event_time),
            self._timeline_event(
                "usb_authorization",
                f"USB device identified as {usb_status}",
                device_id,
            ),
        ]

        if usb_status in {"unauthorized", "blocked"}:
            self.monitor.remove_root(Path(device.drive))
            timeline.append(
                self._timeline_event(
                    "device_block_started",
                    "Automatic USB block started",
                    "Requesting Windows to safely eject the device",
                )
            )
            enforcement = self.usb_enforcer.block(device)
            action_taken = enforcement.action
            timeline.append(
                self._timeline_event(
                    "device_blocked" if enforcement.enforced else "device_block_failed",
                    "USB device blocked" if enforcement.enforced else "USB block failed",
                    enforcement.details,
                )
            )
            if not enforcement.enforced:
                self.monitor.add_root(Path(device.drive))
            risk_score = 100 if usb_status == "blocked" else 90
            classification = "Restricted"
            decision = "Block"
            policy_id = "USB-DEVICE-BLOCK"
            reason = f"USB device is explicitly {usb_status}"
        else:
            action_taken = "Informational - USB device inserted (Monitored)"
            risk_score = 10
            classification = "Informational"
            decision = "Allow"
            policy_id = "USB-INFO-001"
            reason = "USB device insertion detected - Informational event (not a serious threat)"
            timeline.append(
                self._timeline_event(
                    "unknown_device_alert",
                    "Unknown USB device requires review",
                    "The drive remains monitored until an administrator authorizes or denies it",
                )
            )

        incident: dict[str, object] = {
            "incident_id": f"INC-{uuid4().hex[:12].upper()}",
            "incident_type": "usb_device",
            "event_time": utc_now_iso(),
            "user_name": user_name,
            "department": department,
            "computer_name": computer_name,
            "ip_addresses": ip_addresses,
            "device_id": device_id,
            "device_name": device.name,
            "usb_serial_number": device.serial_number,
            "usb_manufacturer": device.manufacturer,
            "usb_model": device.model,
            "usb_pnp_device_id": device.pnp_device_id,
            "usb_authorization_status": usb_status,
            "drive": device.drive,
            "file_name": "USB device insertion",
            "file_type": "usb-device",
            "file_path": "",
            "file_size": 0,
            "change_type": "usb_inserted",
            "sensitive_findings": [],
            "finding_count": 0,
            "scan_readable": True,
            "scan_error": None,
            "file_hashes": {},
            "hash_error": None,
            "duplicate_incident_count": 0,
            "file_classification": classification,
            "recommended_classification": classification,
            "risk_score": risk_score,
            "policy_decision": decision,
            "action_taken": action_taken,
            "policy_reasons": [reason],
            "matched_policy_ids": [policy_id],
            "matched_policy_names": ["USB device authorization"],
            "notify_soc": True,
            "incident_status": "Open",
            "assigned_to": "",
            "status_history": [],
            "assignment_history": [],
            "investigation_notes": [],
            "timeline": timeline,
        }
        alert_results = self.alerter.notify(incident)
        if alert_results:
            channels = ", ".join(result.channel for result in alert_results if result.sent)
            self._append_timeline(
                incident,
                "soc_alert",
                "SOC alert generated",
                channels or "Alert delivery attempted",
            )
        self.incident_store.append(incident)
        return incident

    def process_file_event(self, event: FileCopyEvent) -> dict[str, object]:
        incident_record = asdict(self.scan_file_event(event))
        if int(incident_record.get("risk_score", 0)) >= 75 or incident_record.get("policy_decision") == "Block":
            try:
                evidence = self.evidence_vault.collect(incident_record, event.path)
                incident_record["evidence"] = evidence
                self._append_timeline(
                    incident_record,
                    "evidence_collected",
                    "Encrypted evidence package preserved",
                    str(evidence.get("evidence_id", "")),
                )
            except Exception as exc:
                incident_record["evidence"] = {"collection_error": str(exc)}
                self._append_timeline(
                    incident_record,
                    "evidence_failed",
                    "Evidence collection failed",
                    str(exc),
                )

        alert_results = self.alerter.notify(incident_record)
        if alert_results:
            channels = ", ".join(result.channel for result in alert_results if result.sent)
            self._append_timeline(
                incident_record,
                "soc_alert",
                "SOC alert generated",
                channels or "Alert delivery attempted",
            )
        self.incident_store.append(incident_record)
        return incident_record

    def process_network_event(self, event: NetworkConnectionEvent) -> dict[str, object]:
        user_name = getpass.getuser()
        managed_user = self.user_store.find_by_username(user_name)
        department = str(managed_user.get("department") if managed_user else os.environ.get("USB_DLP_DEPARTMENT", "Unknown"))
        computer_name, ip_addresses = system_context()
        
        try:
            is_internal = ipaddress.ip_address(event.remote_address).is_private
        except ValueError:
            is_internal = False
        ip_classification = "Internal" if is_internal else "External"

        file_name_display = event.extracted_file_name if event.extracted_file_name != event.process_name else event.process_name

        findings = []
        scan_error = None
        scan_readable = True
        if event.extracted_file_path and not event.extracted_file_path.startswith("PID:"):
            result = self.scanner.scan_file(Path(event.extracted_file_path))
            findings = result.findings
            scan_error = result.error
            scan_readable = result.readable

        detection_title = (
            "PowerShell transfer command detected"
            if event.status == "COMMAND_DETECTED"
            else "Outbound connection detected"
        )
        timeline = [
            self._timeline_event(
                "connection_detected",
                f"{detection_title}: {file_name_display}",
                f"{event.process_name} (PID: {event.pid}) targeted {event.remote_address}:{event.remote_port} ({ip_classification})",
            ),
        ]

        assessment = self.policy_engine.assess(
            findings,
            scan_error,
            {
                "file_extension": Path(event.extracted_file_path).suffix.lower(),
                "user_name": user_name,
                "department": department,
                "transfer_time": datetime.now().strftime("%H:%M"),
                "network_exfiltration": True,
            }
        )

        is_shell_process = event.process_name.casefold() in {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
        }
        if is_shell_process and (findings or scan_error):
            suspension = suspend_process(
                event.pid,
                event.process_name,
                event.process_create_time,
            )
            action_desc = suspension.message
            enforcement_state = suspension.state
            timeline.append(
                self._timeline_event(
                    "policy_decision",
                    "Sensitive command-line transfer awaiting SOC decision",
                    suspension.message,
                )
            )
            policy_decision = "Alert"
            risk_score = max(85, assessment.risk_score)
        else:
            action_desc = f"Connection detected to {event.remote_address} ({ip_classification})"
            enforcement_state = "observed"
            timeline.append(self._timeline_event("policy_decision", f"Policy action selected: {assessment.policy_decision}", "Network Exfiltration Prevention"))
            policy_decision = assessment.policy_decision
            risk_score = assessment.risk_score

        content_classification = (
            assessment.file_classification if findings or scan_error else ip_classification
        )
        incident: dict[str, object] = {
            "incident_id": f"INC-{uuid4().hex[:12].upper()}",
            "incident_type": "network_exfiltration",
            "event_time": utc_now_iso(),
            "user_name": user_name,
            "department": department,
            "computer_name": computer_name,
            "ip_addresses": ip_addresses,
            "device_id": "NETWORK",
            "device_name": "Network Connection",
            "usb_serial_number": "",
            "usb_manufacturer": "",
            "usb_model": "",
            "usb_authorization_status": "",
            "drive": "",
            "file_name": event.extracted_file_name,
            "file_type": Path(event.extracted_file_path).suffix.lower() or "Data Payload",
            "file_path": event.extracted_file_path,
            "remote_ip": event.remote_address,
            "remote_port": event.remote_port,
            "process_name": event.process_name,
            "process_pid": event.pid,
            "process_create_time": event.process_create_time,
            "process_status": event.status,
            "enforcement_state": enforcement_state,
            "file_size": 0,
            "change_type": "powershell_transfer" if is_shell_process else "network_connection",
            "sensitive_findings": [asdict(f) for f in findings],
            "finding_count": len(findings),
            "scan_readable": scan_readable,
            "scan_error": scan_error,
            "file_hashes": {},
            "hash_error": None,
            "duplicate_incident_count": 0,
            "file_classification": content_classification,
            "recommended_classification": content_classification,
            "risk_score": risk_score,
            "policy_decision": policy_decision,
            "action_taken": action_desc,
            "policy_reasons": assessment.policy_reasons + [f"Command-line process targeted an {ip_classification.lower()} network destination"],
            "matched_policy_ids": assessment.matched_policy_ids + ["NET-EXFIL-001"],
            "matched_policy_names": assessment.matched_policy_names + ["Network Exfiltration Prevention"],
            "notify_soc": bool(findings or scan_error) or policy_decision != "Allow",
            "incident_status": "Open",
            "assigned_to": "",
            "status_history": [],
            "assignment_history": [],
            "investigation_notes": [],
            "timeline": timeline,
        }
        
        alert_results = self.alerter.notify(incident)
        if alert_results:
            channels = ", ".join(result.channel for result in alert_results if result.sent)
            self._append_timeline(incident, "soc_alert", "SOC alert generated", channels or "Alert delivery attempted")
            
        self.incident_store.append(incident)
        return incident

    @staticmethod
    def _timeline_event(
        event_type: str,
        title: str,
        details: str = "",
        event_time: str | None = None,
    ) -> dict[str, str]:
        return {
            "event_time": event_time or utc_now_iso(),
            "event_type": event_type,
            "title": title,
            "details": details,
        }

    @classmethod
    def _append_timeline(
        cls,
        incident: dict[str, object],
        event_type: str,
        title: str,
        details: str = "",
    ) -> None:
        timeline = incident.setdefault("timeline", [])
        if isinstance(timeline, list):
            timeline.append(cls._timeline_event(event_type, title, details))

    def _device_for_drive(self, drive: Path) -> UsbDevice | None:
        normalized = str(drive).rstrip("\\/").lower()
        for device in self.devices.values():
            if device.drive.rstrip("\\/").lower() == normalized:
                return device
        return None

    @staticmethod
    def _authorization_id(device: UsbDevice) -> str:
        return device.serial_number or device.pnp_device_id or device.device_id

    def _authorization_status(self, device: UsbDevice) -> str:
        return self.usb_registry.status(
            self._authorization_id(device),
            device.serial_number,
            device.pnp_device_id,
            device.device_id,
        )

    def run_forever(self) -> None:
        print("USB DLP agent started. Press Ctrl+C to stop.", file=sys.stderr)
        while True:
            inserted, removed = self.refresh_devices()
            for device in inserted:
                device_incident = self.process_device_insertion(device)
                print(
                    json.dumps(
                        {
                            "event_time": utc_now_iso(),
                            "event": "usb_inserted",
                            "device": asdict(device),
                            "authorization_status": self._authorization_status(device),
                            "action_taken": (
                                device_incident.get("action_taken")
                                if device_incident
                                else "Allow - authorized device"
                            ),
                            "incident_id": device_incident.get("incident_id") if device_incident else None,
                        }
                    )
                )
            for device in removed:
                print(
                    json.dumps(
                        {
                            "event_time": utc_now_iso(),
                            "event": "usb_removed",
                            "device": asdict(device),
                        }
                    )
                )

            for file_event in self.monitor.poll():
                incident_record = self.process_file_event(file_event)
                print(json.dumps(incident_record, ensure_ascii=False))

            for net_event in self.network_monitor.poll():
                incident_record = self.process_network_event(net_event)
                print(json.dumps(incident_record, ensure_ascii=False))

            time.sleep(self.interval_seconds)


def scan_paths(paths: Iterable[str]) -> int:
    scanner = SensitiveDataScanner()
    policy_store = PolicyStore(Path("data/policies.json"))
    policy_engine = PolicyEngine(policy_store.list)
    exit_code = 0
    for raw_path in paths:
        path = Path(raw_path)
        result = scanner.scan_file(path)
        hash_result = hash_file(path)
        assessment = policy_engine.assess(
            result.findings,
            result.error,
            {
                "file_size": path.stat().st_size if path.exists() else 0,
                "file_extension": path.suffix.lower(),
                "usb_authorized": False,
                "user_name": getpass.getuser(),
                "department": os.environ.get("USB_DLP_DEPARTMENT", "Unknown"),
                "transfer_time": datetime.now().strftime("%H:%M"),
            },
        )
        output = {
            "file_path": str(path),
            "readable": result.readable,
            "error": result.error,
            "finding_count": len(result.findings),
            "file_classification": assessment.file_classification,
            "recommended_classification": assessment.file_classification,
            "risk_score": assessment.risk_score,
            "policy_decision": assessment.policy_decision,
            "policy_reasons": assessment.policy_reasons,
            "matched_policy_names": assessment.matched_policy_names,
            "file_hashes": hash_result.hashes,
            "hash_error": hash_result.error,
            "findings": [asdict(finding) for finding in result.findings],
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
        if result.error:
            exit_code = 1
    return exit_code


def print_incident_report(store: IncidentStore, limit: int, output_format: str) -> int:
    incidents = store.query(limit=limit)
    if output_format == "json":
        print(json.dumps(incidents, indent=2, ensure_ascii=False))
        return 0

    fields = [
        "incident_id",
        "event_time",
        "user_name",
        "device_name",
        "device_id",
        "file_name",
        "file_path",
        "file_classification",
        "finding_count",
        "risk_score",
        "policy_decision",
        "action_taken",
        "incident_status",
        "sha256",
    ]
    export_rows = []
    for incident in incidents:
        hashes = incident.get("file_hashes", {})
        export_rows.append(
            {
                **incident,
                "sha256": hashes.get("sha256", "") if isinstance(hashes, dict) else "",
            }
        )
    writer = csv.DictWriter(sys.stdout, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(export_rows)
    return 0


def seed_synthetic_incidents(paths: list[Path], store: IncidentStore) -> int:
    root = paths[0].parent.absolute() if paths else Path.cwd()
    agent = UsbDlpAgent(incident_store=store, alerter=SocAlerter())
    device = UsbDevice(
        device_id="SYNTHETIC-USB-001",
        drive=str(root),
        name="Synthetic Test USB",
        volume_name="DLP_TEST_DATA",
        filesystem="TEST",
        size=None,
    )
    agent.devices[device.device_id] = device
    agent.device_inserted_at[device.device_id] = utc_now_iso()
    agent.usb_registry.upsert(device.device_id, device.name, "authorized")

    for path in paths:
        stat = path.stat()
        event = FileCopyEvent(
            root=root,
            path=path.absolute(),
            size=stat.st_size,
            modified_ns=stat.st_mtime_ns,
            change_type="created",
        )
        agent.process_file_event(event)
    return len(paths)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="USB Data Loss Prevention agent")
    subparsers = parser.add_subparsers(dest="command")

    def add_monitor_arguments(command_parser: argparse.ArgumentParser) -> None:
        command_parser.add_argument(
            "--interval", type=float, default=0.5, help="poll interval in seconds"
        )
        command_parser.add_argument(
            "--log-file", default="data/incidents.jsonl", help="incident record file"
        )
        command_parser.add_argument(
            "--alert-webhook",
            default=os.environ.get("USB_DLP_ALERT_WEBHOOK"),
            help="optional SOC webhook URL",
        )
        command_parser.add_argument("--policies-file", default="data/policies.json")
        command_parser.add_argument("--usb-registry", default="data/usb_devices.json")
        command_parser.add_argument("--users-file", default="data/users.json")
        command_parser.add_argument("--evidence-directory", default="data/evidence")
        command_parser.add_argument("--evidence-retention-days", type=int, default=90)
        command_parser.add_argument(
            "--no-evidence-copy",
            action="store_true",
            help="store evidence metadata without preserving an encrypted file copy",
        )

    run_parser = subparsers.add_parser("run", help="monitor USB and command-line transfers")
    add_monitor_arguments(run_parser)
    monitor_parser = subparsers.add_parser("monitor", help="alias for the DLP monitoring agent")
    add_monitor_arguments(monitor_parser)

    scan_parser = subparsers.add_parser("scan", help="scan one or more files")
    scan_parser.add_argument("paths", nargs="+", help="files to scan")

    report_parser = subparsers.add_parser("report", help="print stored incident records")
    report_parser.add_argument("--log-file", default="data/incidents.jsonl")
    report_parser.add_argument("--limit", type=int, default=100)
    report_parser.add_argument("--format", choices=("json", "csv"), default="json")

    dataset_parser = subparsers.add_parser(
        "generate-test-data", help="create synthetic files for DLP testing"
    )
    dataset_parser.add_argument("--output", default="synthetic_test_data")
    dataset_parser.add_argument(
        "--seed-incidents",
        action="store_true",
        help="add synthetic incidents to the dashboard log",
    )
    dataset_parser.add_argument("--log-file", default="data/incidents.jsonl")

    dashboard_parser = subparsers.add_parser("dashboard", help="start the incident dashboard")
    dashboard_parser.add_argument("--host", default="127.0.0.1")
    dashboard_parser.add_argument("--port", type=int, default=8080)
    dashboard_parser.add_argument("--log-file", default="data/incidents.jsonl")

    parser.add_argument("--interval", type=float, default=None, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return scan_paths(args.paths)
    if args.command == "generate-test-data":
        created = generate_synthetic_dataset(Path(args.output))
        print(f"Created {len(created)} synthetic test files in {Path(args.output).absolute()}")
        if args.seed_incidents:
            count = seed_synthetic_incidents(created, IncidentStore(Path(args.log_file)))
            print(f"Added {count} synthetic incidents to {Path(args.log_file).absolute()}")
        return 0
    if args.command == "report":
        return print_incident_report(
            IncidentStore(Path(args.log_file)), args.limit, args.format
        )
    if args.command == "dashboard":
        from .dashboard import serve_dashboard

        return serve_dashboard(args.host, args.port, Path(args.log_file))

    interval = args.interval if args.interval is not None else 0.5
    log_file = Path(getattr(args, "log_file", "data/incidents.jsonl"))
    webhook = getattr(args, "alert_webhook", None)
    agent = UsbDlpAgent(
        interval_seconds=interval,
        incident_store=IncidentStore(log_file),
        policy_store=PolicyStore(Path(getattr(args, "policies_file", "data/policies.json"))),
        usb_registry=UsbRegistry(Path(getattr(args, "usb_registry", "data/usb_devices.json"))),
        user_store=UserStore(Path(getattr(args, "users_file", "data/users.json"))),
        evidence_vault=EvidenceVault(
            Path(getattr(args, "evidence_directory", "data/evidence")),
            retention_days=getattr(args, "evidence_retention_days", 90),
            preserve_files=not getattr(args, "no_evidence_copy", False),
        ),
        alerter=SocAlerter(webhook),
    )
    try:
        agent.run_forever()
    except KeyboardInterrupt:
        print("USB DLP agent stopped.", file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
