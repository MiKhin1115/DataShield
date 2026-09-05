import re
from pathlib import Path
from unittest import TestCase


class DashboardColumnTests(TestCase):
    def test_incident_and_history_tables_use_transfer_columns(self) -> None:
        html = Path("dlp_agent/dashboard_assets/index.html").read_text(encoding="utf-8")
        expected = [
            "Time",
            "User &amp; Device",
            "File",
            "Classification",
            "Channel",
            "Destination",
            "Action",
        ]
        for body_id in ("incident-rows", "history-rows"):
            match = re.search(
                rf"<table><thead><tr>(.*?)</tr></thead><tbody id=\"{body_id}\"",
                html,
            )
            self.assertIsNotNone(match)
            headers = re.findall(r"<th>(.*?)</th>", match.group(1))
            self.assertEqual(headers, expected)

    def test_channel_and_destination_cover_requested_transfer_types(self) -> None:
        script = Path("dlp_agent/dashboard_assets/app.js").read_text(encoding="utf-8")
        for channel in ("PowerShell", "Web Upload", "Telegram", "Google Drive"):
            self.assertIn(f'return "{channel}"', script)
        self.assertIn("incident.remote_ip", script)
        self.assertIn("incident.email_recipient", script)
        self.assertIn("new URL(targetValue)", script)

        styles = Path("dlp_agent/dashboard_assets/styles.css").read_text(encoding="utf-8")
        self.assertIn('td:nth-child(5)::before { content: "Channel"; }', styles)
        self.assertIn('td:nth-child(6)::before { content: "Destination"; }', styles)
        self.assertIn('td:nth-child(7)::before { content: "Action"; }', styles)

    def test_incident_dialog_omits_investigation_and_evidence_tabs(self) -> None:
        script = Path("dlp_agent/dashboard_assets/app.js").read_text(encoding="utf-8")
        show_incident = script.split("function showIncident(incident)", 1)[1].split(
            "function railFact", 1
        )[0]

        self.assertNotIn('["investigation", "Investigation"]', show_incident)
        self.assertNotIn('["evidence", "Evidence"]', show_incident)
        self.assertNotIn('data-detail-panel="investigation"', show_incident)
        self.assertNotIn('data-detail-panel="evidence"', show_incident)
        self.assertIn('["overview", "Overview"]', show_incident)
        self.assertIn('["timeline", "Timeline"]', show_incident)

    def test_action_button_executes_final_decisions_and_expands_alerts(self) -> None:
        script = Path("dlp_agent/dashboard_assets/app.js").read_text(encoding="utf-8")
        handler = script.split("function handlePrimaryAction", 1)[1].split(
            "async function enforceAction", 1
        )[0]

        self.assertIn('normalized === "alert"', handler)
        self.assertIn("showActionOptions(btn, incidentId)", handler)
        self.assertIn('normalized === "allow" || normalized === "block"', handler)
        self.assertIn("enforceAction(incidentId, normalized)", handler)
