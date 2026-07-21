import tempfile
from pathlib import Path
from unittest import TestCase

from dlp_agent.incident_store import IncidentStore


def incident(
    incident_id: str,
    classification: str,
    decision: str,
    risk_score: int,
) -> dict[str, object]:
    return {
        "incident_id": incident_id,
        "event_time": "2026-07-20T10:00:00+00:00",
        "user_name": "test-user",
        "device_name": "Test USB",
        "device_id": "E:",
        "file_name": f"{incident_id}.txt",
        "file_path": f"E:\\{incident_id}.txt",
        "file_classification": classification,
        "risk_score": risk_score,
        "policy_decision": decision,
        "sensitive_findings": [{"kind": "email"}],
    }


class IncidentStoreTests(TestCase):
    def test_appends_queries_and_summarizes_incidents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.jsonl")
            store.append(incident("INC-1", "Internal", "Alert", 15))
            store.append(incident("INC-2", "Restricted", "Block", 95))

            results = store.query(classification="Restricted", min_risk=75)
            summary = store.summary()

        self.assertEqual([item["incident_id"] for item in results], ["INC-2"])
        self.assertEqual(summary["total_incidents"], 2)
        self.assertEqual(summary["high_risk_incidents"], 1)
        self.assertEqual(summary["decisions"], {"Alert": 1, "Block": 1})
        self.assertEqual(summary["sensitive_types"], {"email": 2})

    def test_searches_user_device_and_file_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.jsonl")
            store.append(incident("INC-1", "Internal", "Alert", 15))

            results = store.query(search="test usb")

        self.assertEqual(len(results), 1)

    def test_updates_investigation_fields_and_correlates_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.jsonl")
            value = incident("INC-1", "Restricted", "Block", 95)
            value["file_hashes"] = {"sha256": "abc123"}
            store.append(value)

            updated = store.update(
                "INC-1",
                {"incident_status": "Investigating", "assigned_to": "soc", "investigation_notes": []},
            )
            duplicate_count = store.count_by_sha256("abc123")

        self.assertEqual(updated["incident_status"], "Investigating")
        self.assertEqual(duplicate_count, 1)

    def test_filters_by_identity_risk_status_type_and_date(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.jsonl")
            value = incident("INC-FILTER", "Restricted", "Block", 92)
            value.update(
                computer_name="DLP-PC-01",
                usb_serial_number="USB-SERIAL-99",
                file_type=".xlsx",
                incident_status="Investigating",
                event_time="2026-07-20T10:00:00+00:00",
            )
            store.append(value)

            results = store.query(
                incident_id="FILTER",
                computer_name="dlp-pc",
                usb_serial="serial-99",
                file_type=".xlsx",
                risk_level="Critical",
                status="Investigating",
                date_from="2026-07-19T00:00:00+00:00",
                date_to="2026-07-21T00:00:00+00:00",
            )
            excluded = store.query(risk_level="Low")

        self.assertEqual(len(results), 1)
        self.assertEqual(excluded, [])

    def test_risk_levels_cover_full_score_range(self) -> None:
        self.assertEqual(IncidentStore.risk_level(0), "Low")
        self.assertEqual(IncidentStore.risk_level(25), "Medium")
        self.assertEqual(IncidentStore.risk_level(50), "High")
        self.assertEqual(IncidentStore.risk_level(75), "Critical")

    def test_filters_by_assignee_and_treats_legacy_new_as_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.jsonl")
            assigned = incident("INC-ASSIGNED", "Restricted", "Block", 95)
            assigned.update(incident_status="New", assigned_to="soc")
            unassigned = incident("INC-UNASSIGNED", "Internal", "Alert", 20)
            unassigned.update(incident_status="Open", assigned_to="")
            store.append(assigned)
            store.append(unassigned)

            analyst_results = store.query(assigned_to="soc", status="Open")
            unassigned_results = store.query(assignment_state="unassigned")

        self.assertEqual([item["incident_id"] for item in analyst_results], ["INC-ASSIGNED"])
        self.assertEqual([item["incident_id"] for item in unassigned_results], ["INC-UNASSIGNED"])
