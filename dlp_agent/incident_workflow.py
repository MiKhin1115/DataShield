from __future__ import annotations

import base64
import binascii
import hashlib
import mimetypes
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .incident_store import IncidentStore
from .rbac import UserStore


INCIDENT_STATUSES = (
    "Open",
    "Investigating",
    "Resolved",
    "False Positive",
    "Escalated",
    "Pending User Confirmation",
    "Pending Manager Approval",
    "Closed",
)
MAX_CASE_ATTACHMENT_BYTES = 2 * 1024 * 1024
CONTENT_TYPE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*$")


def normalized_status(value: object) -> str:
    status = str(value or "Open").strip()
    return "Open" if status == "New" else status


class CaseAttachmentStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        incident_id: str,
        note_id: str,
        actor: str,
        value: dict[str, object],
    ) -> dict[str, object]:
        file_name = Path(str(value.get("file_name", ""))).name.strip()
        encoded = str(value.get("data_base64", ""))
        if not file_name or file_name in {".", ".."} or len(file_name) > 255 or not encoded:
            raise ValueError("Attachment file name and content are required")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Attachment content is invalid") from exc
        if not content:
            raise ValueError("Attachment cannot be empty")
        if len(content) > MAX_CASE_ATTACHMENT_BYTES:
            raise ValueError("Attachment exceeds the 2 MB limit")

        attachment_id = f"ATT-{uuid4().hex[:12].upper()}"
        incident_directory = self.directory / incident_id
        incident_directory.mkdir(parents=True, exist_ok=True)
        storage_name = f"{attachment_id}.bin"
        path = incident_directory / storage_name
        path.write_bytes(content)
        requested_type = str(value.get("content_type", "")).strip()
        content_type = requested_type if CONTENT_TYPE_PATTERN.fullmatch(requested_type) else (
            mimetypes.guess_type(file_name)[0] or "application/octet-stream"
        )
        return {
            "attachment_id": attachment_id,
            "note_id": note_id,
            "file_name": file_name,
            "content_type": content_type,
            "file_size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "uploaded_by": actor,
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
            "storage_name": storage_name,
        }

    def read(self, incident_id: str, attachment: dict[str, object]) -> bytes:
        storage_name = Path(str(attachment.get("storage_name", ""))).name
        if not storage_name:
            raise FileNotFoundError("Attachment record is incomplete")
        path = self.directory / incident_id / storage_name
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != attachment.get("sha256"):
            raise ValueError("Attachment integrity check failed")
        return content

    def remove(self, incident_id: str, attachment: dict[str, object]) -> None:
        storage_name = Path(str(attachment.get("storage_name", ""))).name
        if storage_name:
            (self.directory / incident_id / storage_name).unlink(missing_ok=True)


class IncidentWorkflowService:
    def __init__(
        self,
        store: IncidentStore,
        users: UserStore,
        attachments: CaseAttachmentStore,
    ) -> None:
        self.store = store
        self.users = users
        self.attachments = attachments
        self._lock = threading.Lock()

    def update(
        self,
        incident_id: str,
        actor: dict[str, object],
        value: dict[str, object],
    ) -> tuple[dict[str, object], list[tuple[str, str]]]:
        with self._lock:
            incident = self.store.get(incident_id)
            if incident is None:
                raise LookupError("Incident not found")

            current_status = normalized_status(incident.get("incident_status"))
            new_status = normalized_status(value.get("incident_status", current_status))
            if new_status not in INCIDENT_STATUSES:
                raise ValueError("Invalid incident status")

            current_assignee = str(incident.get("assigned_to", "")).strip()
            new_assignee = str(value.get("assigned_to", current_assignee)).strip()
            if new_assignee.casefold() == current_assignee.casefold():
                new_assignee = current_assignee
            elif new_assignee:
                new_assignee = self._validated_analyst(new_assignee)

            status_changed = new_status != current_status
            assignment_changed = new_assignee.casefold() != current_assignee.casefold()
            reason = str(value.get("change_reason", "")).strip()
            if (status_changed or assignment_changed) and not reason:
                raise ValueError("A reason is required for status or assignment changes")
            if len(reason) > 1000:
                raise ValueError("Change reason cannot exceed 1000 characters")

            note_text = str(value.get("note", "")).strip()
            attachment_value = value.get("attachment")
            if attachment_value is not None and not isinstance(attachment_value, dict):
                raise ValueError("Attachment is invalid")
            if attachment_value and not note_text:
                raise ValueError("A case note is required when adding an attachment")
            if len(note_text) > 5000:
                raise ValueError("Case note cannot exceed 5000 characters")
            if not status_changed and not assignment_changed and not note_text:
                raise ValueError("No investigation changes were provided")

            now = datetime.now(timezone.utc).isoformat()
            actor_name = str(actor.get("username", "unknown"))
            actor_role = str(actor.get("role", "Unknown"))
            status_history = self._list(incident, "status_history")
            assignment_history = self._list(incident, "assignment_history")
            notes = self._list(incident, "investigation_notes")
            timeline = self._list(incident, "timeline")
            audit_events: list[tuple[str, str]] = []
            saved_attachment: dict[str, object] | None = None

            if status_changed:
                status_history.append(
                    {
                        "changed_by": actor_name,
                        "changed_by_role": actor_role,
                        "event_time": now,
                        "previous_status": current_status,
                        "new_status": new_status,
                        "reason": reason,
                    }
                )
                timeline.append(
                    {
                        "event_time": now,
                        "event_type": "status_changed",
                        "title": f"Incident status changed to {new_status}",
                        "details": f"{current_status} to {new_status} by {actor_name}; Reason: {reason}",
                    }
                )
                audit_events.append(
                    ("incident_status_changed", f"{current_status} -> {new_status}; reason={reason}")
                )

            if assignment_changed:
                assignment_history.append(
                    {
                        "changed_by": actor_name,
                        "changed_by_role": actor_role,
                        "event_time": now,
                        "previous_assignee": current_assignee,
                        "new_assignee": new_assignee,
                        "reason": reason,
                    }
                )
                assignment_title = "Incident unassigned" if not new_assignee else (
                    "Incident reassigned" if current_assignee else "Incident assigned"
                )
                timeline.append(
                    {
                        "event_time": now,
                        "event_type": "assignment_changed",
                        "title": assignment_title,
                        "details": f"{current_assignee or 'Unassigned'} to {new_assignee or 'Unassigned'} by {actor_name}; Reason: {reason}",
                    }
                )
                audit_events.append(
                    (
                        "incident_assignment_changed",
                        f"{current_assignee or 'Unassigned'} -> {new_assignee or 'Unassigned'}; reason={reason}",
                    )
                )

            if note_text:
                note_id = f"NOTE-{uuid4().hex[:12].upper()}"
                attachments: list[dict[str, object]] = []
                if attachment_value:
                    saved_attachment = self.attachments.save(
                        incident_id, note_id, actor_name, attachment_value
                    )
                    attachments.append(saved_attachment)
                notes.append(
                    {
                        "note_id": note_id,
                        "incident_id": incident_id,
                        "author": actor_name,
                        "author_role": actor_role,
                        "event_time": now,
                        "text": note_text,
                        "attachments": attachments,
                    }
                )
                timeline.append(
                    {
                        "event_time": now,
                        "event_type": "case_note_added",
                        "title": "Case note added",
                        "details": f"Added by {actor_name}"
                        + (f" with attachment {saved_attachment['file_name']}" if saved_attachment else ""),
                    }
                )
                audit_events.append(
                    (
                        "incident_note_added",
                        f"note_id={note_id}"
                        + (f"; attachment_id={saved_attachment['attachment_id']}" if saved_attachment else ""),
                    )
                )

            changes = {
                "incident_status": new_status,
                "assigned_to": new_assignee,
                "status_history": status_history,
                "assignment_history": assignment_history,
                "investigation_notes": notes,
                "timeline": timeline,
            }
            updated = self.store.update(incident_id, changes)
            if updated is None:
                if saved_attachment:
                    self.attachments.remove(incident_id, saved_attachment)
                raise LookupError("Incident not found")
            return updated, audit_events

    def analysts(self) -> list[dict[str, object]]:
        return [
            user
            for user in self.users.list()
            if user.get("enabled", True) and user.get("role") == "SOC Analyst"
        ]

    def find_attachment(
        self, incident_id: str, attachment_id: str
    ) -> tuple[dict[str, object], bytes]:
        incident = self.store.get(incident_id)
        if incident is None:
            raise FileNotFoundError("Incident not found")
        for note in self._list(incident, "investigation_notes"):
            if not isinstance(note, dict):
                continue
            attachments = note.get("attachments", [])
            if not isinstance(attachments, list):
                continue
            for attachment in attachments:
                if isinstance(attachment, dict) and attachment.get("attachment_id") == attachment_id:
                    return attachment, self.attachments.read(incident_id, attachment)
        raise FileNotFoundError("Case attachment not found")

    def _validated_analyst(self, username: str) -> str:
        for analyst in self.analysts():
            candidate = str(analyst.get("username", ""))
            if candidate.casefold() == username.casefold():
                return candidate
        raise ValueError("Incidents can only be assigned to an enabled SOC analyst")

    @staticmethod
    def _list(incident: dict[str, object], key: str) -> list[object]:
        value = incident.get(key, [])
        return list(value) if isinstance(value, list) else []
