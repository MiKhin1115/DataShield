import tempfile
from pathlib import Path
from unittest import TestCase

from dlp_agent.dashboard import DashboardHandler
from dlp_agent.incident_store import IncidentStore


def history_incident(incident_id: str, status: str) -> dict[str, object]:
    return {
        "incident_id": incident_id,
        "incident_status": status,
        "event_time": "2026-09-06T08:00:00+00:00",
    }


class HistoryClearTests(TestCase):
    def _handler(
        self,
        store: IncidentStore,
        body: dict[str, object],
    ) -> tuple[DashboardHandler, list[dict[str, object]], list[tuple[object, ...]]]:
        responses: list[dict[str, object]] = []
        audits: list[tuple[object, ...]] = []
        handler = object.__new__(DashboardHandler)
        handler.store = store
        handler._json_body = lambda: body
        handler._serve_json = lambda value, *args: responses.append(value)
        handler._audit_change = lambda *args: audits.append(args)
        return handler, responses, audits

    def test_selected_delete_removes_only_chosen_history_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.jsonl")
            store.append(history_incident("INC-CLOSED", "Closed"))
            store.append(history_incident("INC-RESOLVED", "Resolved"))
            store.append(history_incident("INC-OPEN", "Open"))
            handler, responses, audits = self._handler(
                store,
                {"incident_ids": ["INC-CLOSED", "INC-OPEN"]},
            )

            handler._delete_history_incidents()

            remaining = [item["incident_id"] for item in store.read_all()]

        self.assertEqual(remaining, ["INC-RESOLVED", "INC-OPEN"])
        self.assertEqual(responses[0]["deleted_ids"], ["INC-CLOSED"])
        self.assertEqual(len(audits), 1)

    def test_clear_all_removes_history_but_preserves_open_incidents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(Path(directory) / "incidents.jsonl")
            for incident_id, status in (
                ("INC-CLOSED", "Closed"),
                ("INC-FALSE-POSITIVE", "False Positive"),
                ("INC-OPEN", "Open"),
            ):
                store.append(history_incident(incident_id, status))
            handler, responses, _ = self._handler(store, {"clear_all": True})

            handler._delete_history_incidents()

            remaining = [item["incident_id"] for item in store.read_all()]

        self.assertEqual(remaining, ["INC-OPEN"])
        self.assertEqual(responses[0]["deleted_count"], 2)

    def test_history_ui_has_clear_all_and_checkbox_selection(self) -> None:
        html = Path("dlp_agent/dashboard_assets/index.html").read_text(encoding="utf-8")
        script = Path("dlp_agent/dashboard_assets/app.js").read_text(encoding="utf-8")

        self.assertIn('id="history-clear-toggle"', html)
        self.assertIn('id="history-delete-selected"', html)
        self.assertIn('id="history-clear-all"', html)
        self.assertIn('id="history-delete-dialog"', html)
        self.assertIn('id="history-delete-confirm"', html)
        self.assertIn('class="history-select-checkbox"', script)
        self.assertIn('method: "DELETE"', script)
        self.assertIn('deleteError.status !== 404', script)
        self.assertIn("function requestHistoryDeletion", script)
        self.assertIn("async function confirmHistoryDeletion", script)
