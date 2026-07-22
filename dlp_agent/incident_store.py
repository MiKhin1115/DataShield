from __future__ import annotations

import json
import threading
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Iterable


class IncidentStore:
    """Append-only JSONL storage for USB DLP incident records."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def append(self, incident: dict[str, object]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(incident, ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def update(self, incident_id: str, changes: dict[str, object]) -> dict[str, object] | None:
        allowed = {
            "incident_status",
            "assigned_to",
            "status_history",
            "assignment_history",
            "investigation_notes",
            "timeline",
            "manual_action",
        }
        clean_changes = {key: value for key, value in changes.items() if key in allowed}
        with self._lock:
            incidents = self.read_all_unlocked()
            for incident in incidents:
                if incident.get("incident_id") == incident_id:
                    incident.update(clean_changes)
                    self._write_all_unlocked(incidents)
                    return incident
        return None

    def delete(self, incident_id: str) -> bool:
        with self._lock:
            incidents = self.read_all_unlocked()
            filtered = [inc for inc in incidents if inc.get("incident_id") != incident_id]
            if len(filtered) < len(incidents):
                self._write_all_unlocked(filtered)
                return True
            return False

    def count_by_sha256(self, sha256: str) -> int:
        if not sha256:
            return 0
        return sum(
            1
            for incident in self.read_all()
            if isinstance(incident.get("file_hashes"), dict)
            and incident["file_hashes"].get("sha256") == sha256
        )

    def read_all(self) -> list[dict[str, object]]:
        with self._lock:
            return self.read_all_unlocked()

    def read_all_unlocked(self) -> list[dict[str, object]]:
        if not self.path.exists():
            return []

        incidents: list[dict[str, object]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    incidents.append(value)
        return incidents

    def get(self, incident_id: str) -> dict[str, object] | None:
        return next(
            (incident for incident in self.read_all() if incident.get("incident_id") == incident_id),
            None,
        )

    def _write_all_unlocked(self, incidents: list[dict[str, object]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            for incident in incidents:
                handle.write(json.dumps(incident, ensure_ascii=False) + "\n")
        temporary.replace(self.path)

    def query(
        self,
        *,
        classification: str = "",
        decision: str = "",
        search: str = "",
        min_risk: int = 0,
        max_risk: int = 100,
        risk_level: str = "",
        incident_id: str = "",
        user_name: str = "",
        computer_name: str = "",
        usb_name: str = "",
        usb_serial: str = "",
        file_name: str = "",
        file_type: str = "",
        status: str = "",
        assigned_to: str = "",
        assignment_state: str = "",
        date_from: str = "",
        date_to: str = "",
        limit: int = 250,
    ) -> list[dict[str, object]]:
        incidents = reversed(self.read_all())
        filtered: list[dict[str, object]] = []
        search_term = search.casefold().strip()
        date_from_value = self._parse_datetime(date_from) if date_from else None
        date_to_value = self._parse_datetime(date_to) if date_to else None

        for incident in incidents:
            if classification and incident.get("file_classification") != classification:
                continue
            if decision and incident.get("policy_decision") != decision:
                continue
            score = int(incident.get("risk_score", 0) or 0)
            if score < min_risk or score > max_risk:
                continue
            if risk_level and self.risk_level(score) != risk_level:
                continue
            if incident_id and incident_id.casefold() not in str(incident.get("incident_id", "")).casefold():
                continue
            if user_name and user_name.casefold() not in str(incident.get("user_name", "")).casefold():
                continue
            if computer_name and computer_name.casefold() not in str(incident.get("computer_name", "")).casefold():
                continue
            if usb_name and usb_name.casefold() not in str(incident.get("device_name", "")).casefold():
                continue
            if usb_serial and usb_serial.casefold() not in str(incident.get("usb_serial_number", "")).casefold():
                continue
            if file_name and file_name.casefold() not in str(incident.get("file_name", "")).casefold():
                continue
            if file_type and file_type.casefold() != str(incident.get("file_type", Path(str(incident.get("file_name", ""))).suffix)).casefold():
                continue
            incident_status = str(incident.get("incident_status", "Open"))
            if incident_status == "New":
                incident_status = "Open"
            if status and status != incident_status:
                continue
            assignee = str(incident.get("assigned_to", "")).strip()
            if assigned_to and assigned_to.casefold() not in assignee.casefold():
                continue
            if assignment_state == "unassigned" and assignee:
                continue
            if assignment_state == "assigned" and not assignee:
                continue
            event_time = self._parse_datetime(str(incident.get("event_time", "")))
            if date_from and (
                event_time is None or date_from_value is None or event_time < date_from_value
            ):
                continue
            if date_to and (
                event_time is None or date_to_value is None or event_time > date_to_value
            ):
                continue
            if search_term and search_term not in self._search_text(incident):
                continue
            filtered.append(incident)
            if len(filtered) >= limit:
                break
        return filtered

    @staticmethod
    def risk_level(score: int) -> str:
        if score >= 75:
            return "Critical"
        if score >= 50:
            return "High"
        if score >= 25:
            return "Medium"
        return "Low"

    @staticmethod
    def _parse_datetime(value: str) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.astimezone()
            return parsed
        except ValueError:
            return None

    def summary(self) -> dict[str, object]:
        incidents = self.read_all()
        classifications = Counter(
            str(item.get("file_classification", "Unknown")) for item in incidents
        )
        decisions = Counter(str(item.get("policy_decision", "Unknown")) for item in incidents)
        finding_types: Counter[str] = Counter()
        scores: list[int] = []

        for item in incidents:
            scores.append(int(item.get("risk_score", 0) or 0))
            for finding in self._findings(item):
                kind = str(finding.get("kind", "unknown"))
                finding_types[kind] += 1

        return {
            "total_incidents": len(incidents),
            "high_risk_incidents": sum(score >= 75 for score in scores),
            "average_risk_score": round(sum(scores) / len(scores)) if scores else 0,
            "classifications": dict(classifications),
            "decisions": dict(decisions),
            "sensitive_types": dict(finding_types.most_common(8)),
            "latest_event_time": incidents[-1].get("event_time") if incidents else None,
        }

    @staticmethod
    def _findings(incident: dict[str, object]) -> Iterable[dict[str, object]]:
        findings = incident.get("sensitive_findings", [])
        if not isinstance(findings, list):
            return []
        return [item for item in findings if isinstance(item, dict)]

    @staticmethod
    def _search_text(incident: dict[str, object]) -> str:
        searchable = (
            incident.get("incident_id", ""),
            incident.get("user_name", ""),
            incident.get("device_name", ""),
            incident.get("device_id", ""),
            incident.get("file_name", ""),
            incident.get("file_path", ""),
            incident.get("computer_name", ""),
            incident.get("usb_serial_number", ""),
            incident.get("file_type", ""),
            " ".join(
                str(value)
                for value in (
                    incident.get("file_hashes", {}).values()
                    if isinstance(incident.get("file_hashes"), dict)
                    else []
                )
            ),
        )
        return " ".join(str(value) for value in searchable).casefold()
