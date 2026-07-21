import base64
import tempfile
from pathlib import Path
from unittest import TestCase

from dlp_agent.incident_store import IncidentStore
from dlp_agent.incident_workflow import CaseAttachmentStore, IncidentWorkflowService
from dlp_agent.rbac import UserStore


def open_incident() -> dict[str, object]:
    return {
        "incident_id": "INC-WORKFLOW",
        "event_time": "2026-07-20T10:00:00+00:00",
        "incident_status": "Open",
        "assigned_to": "",
        "investigation_notes": [],
        "status_history": [],
        "assignment_history": [],
        "timeline": [],
        "risk_score": 98,
        "file_name": "payroll.xlsx",
    }


class IncidentWorkflowTests(TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.store = IncidentStore(root / "incidents.jsonl")
        self.store.append(open_incident())
        self.users = UserStore(root / "users.json")
        self.attachments = CaseAttachmentStore(root / "case_attachments")
        self.workflow = IncidentWorkflowService(self.store, self.users, self.attachments)
        self.actor = self.users.authenticate("soc", "Soc123!")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_records_status_assignment_note_attachment_and_timeline(self) -> None:
        attachment_content = b"Manager approval for the transfer"
        updated, audit_events = self.workflow.update(
            "INC-WORKFLOW",
            self.actor,
            {
                "incident_status": "Investigating",
                "assigned_to": "soc",
                "change_reason": "Critical payroll transfer requires review",
                "note": "Started investigation and attached manager approval.",
                "attachment": {
                    "file_name": "approval.txt",
                    "content_type": "text/plain",
                    "data_base64": base64.b64encode(attachment_content).decode("ascii"),
                },
            },
        )

        self.assertEqual(updated["incident_status"], "Investigating")
        self.assertEqual(updated["assigned_to"], "soc")
        self.assertEqual(updated["status_history"][0]["previous_status"], "Open")
        self.assertEqual(updated["status_history"][0]["changed_by"], "soc")
        self.assertEqual(updated["assignment_history"][0]["new_assignee"], "soc")
        note = updated["investigation_notes"][0]
        self.assertTrue(str(note["note_id"]).startswith("NOTE-"))
        attachment = note["attachments"][0]
        self.assertEqual(
            self.attachments.read("INC-WORKFLOW", attachment), attachment_content
        )
        self.assertEqual(
            [event["event_type"] for event in updated["timeline"]],
            ["status_changed", "assignment_changed", "case_note_added"],
        )
        self.assertEqual(
            [action for action, _ in audit_events],
            [
                "incident_status_changed",
                "incident_assignment_changed",
                "incident_note_added",
            ],
        )

    def test_notes_are_appended_and_cannot_be_silently_replaced(self) -> None:
        first, _ = self.workflow.update(
            "INC-WORKFLOW", self.actor, {"note": "First finding"}
        )
        second, _ = self.workflow.update(
            "INC-WORKFLOW", self.actor, {"note": "Second finding"}
        )

        self.assertEqual(
            [note["text"] for note in second["investigation_notes"]],
            ["First finding", "Second finding"],
        )
        self.assertNotEqual(
            first["investigation_notes"][0]["note_id"],
            second["investigation_notes"][1]["note_id"],
        )

    def test_requires_reason_and_rejects_non_analyst_assignment(self) -> None:
        with self.assertRaisesRegex(ValueError, "reason is required"):
            self.workflow.update(
                "INC-WORKFLOW", self.actor, {"incident_status": "Escalated"}
            )
        with self.assertRaisesRegex(ValueError, "enabled SOC analyst"):
            self.workflow.update(
                "INC-WORKFLOW",
                self.actor,
                {"assigned_to": "viewer", "change_reason": "Assign for review"},
            )

    def test_detects_attachment_tampering(self) -> None:
        updated, _ = self.workflow.update(
            "INC-WORKFLOW",
            self.actor,
            {
                "note": "Attachment integrity test",
                "attachment": {
                    "file_name": "test.txt",
                    "data_base64": base64.b64encode(b"original").decode("ascii"),
                },
            },
        )
        attachment = updated["investigation_notes"][0]["attachments"][0]
        path = (
            self.attachments.directory
            / "INC-WORKFLOW"
            / str(attachment["storage_name"])
        )
        path.write_bytes(b"tampered")

        with self.assertRaisesRegex(ValueError, "integrity check failed"):
            self.attachments.read("INC-WORKFLOW", attachment)
