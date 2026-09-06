import io
import json
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
from zipfile import ZipFile

from dlp_agent.dashboard import DashboardHandler
from dlp_agent.incident_store import IncidentStore


class DashboardDeepScanTests(TestCase):
    def setUp(self) -> None:
        self.temp_directory = TemporaryDirectory()
        DashboardHandler.store = IncidentStore(
            Path(self.temp_directory.name) / "incidents.jsonl"
        )
        DashboardHandler._recent_browser_incidents.clear()
        DashboardHandler._browser_commands.clear()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp_directory.cleanup()

    def test_preflight_allows_original_filename_header(self) -> None:
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request(
            "OPTIONS",
            "/api/scan_file",
            headers={
                "Origin": "https://example.test",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "x-file-name",
            },
        )
        response = connection.getresponse()
        response.read()
        connection.close()

        allowed_headers = response.getheader("Access-Control-Allow-Headers", "").lower()
        self.assertEqual(response.status, 200)
        self.assertIn("x-file-name", allowed_headers)

    def test_legacy_browser_incident_displays_current_routed_source_ip(self) -> None:
        legacy = {
            "device_id": "BROWSER_EXT",
            "device_name": "192.168.100.143",
            "destination_url": "http://192.168.100.143:1234/upload",
            "ip_addresses": ["127.0.0.1"],
        }
        with patch(
            "dlp_agent.dashboard._source_ipv4_for_destination",
            return_value="192.168.100.146",
        ):
            public = DashboardHandler._public_incident(legacy)

        self.assertEqual(public["source_ip"], "192.168.100.146")
        self.assertEqual(public["ip_addresses"], ["192.168.100.146"])

    def test_endpoint_blocks_sensitive_zip_with_innocent_names(self) -> None:
        archive_bytes = io.BytesIO()
        with ZipFile(archive_bytes, "w") as archive:
            archive.writestr("normal.txt", "password=Secret123")

        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request(
            "POST",
            "/api/scan_file",
            body=archive_bytes.getvalue(),
            headers={
                "Content-Type": "application/zip",
                "X-File-Name": "public%20access.zip",
            },
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["blocked"])
        self.assertEqual(payload["classification"], "Restricted")
        self.assertIn("password", payload["details"])
        self.assertEqual(payload["findings"][0]["kind"], "password")
        self.assertNotIn("VerySecretPassword123", json.dumps(payload))

    def test_endpoint_allows_benign_zip(self) -> None:
        archive_bytes = io.BytesIO()
        with ZipFile(archive_bytes, "w") as archive:
            archive.writestr("notes.txt", "Team picnic starts at noon.")

        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request(
            "POST",
            "/api/scan_file",
            body=archive_bytes.getvalue(),
            headers={"X-File-Name": "documents.zip"},
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()

        self.assertEqual(response.status, 200)
        self.assertFalse(payload["blocked"])
        self.assertEqual(payload["finding_count"], 0)
        self.assertEqual(payload["classification"], "Public")
        self.assertEqual(payload["risk_score"], 0)

    def test_endpoint_allows_empty_text_file(self) -> None:
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request(
            "POST",
            "/api/scan_file",
            body=b"",
            headers={"X-File-Name": "a.txt"},
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()

        self.assertEqual(response.status, 200)
        self.assertFalse(payload["blocked"])
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["classification"], "Public")
        self.assertIsNone(payload["error"])

    def test_blocked_scan_findings_are_saved_as_dashboard_incident(self) -> None:
        incident_payload = {
            "url": "https://drive.google.com/drive/my-drive",
            "file_name": "public access.zip",
            "action": "Blocked by Google Drive security",
            "classification": "Restricted",
            "sensitive_findings": [
                {
                    "kind": "password",
                    "match": "pass...d123",
                    "position": 20,
                    "severity": "critical",
                }
            ],
        }
        body = json.dumps(incident_payload).encode("utf-8")
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request(
            "POST",
            "/api/browser_incident",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        response.read()
        connection.close()

        incidents = DashboardHandler.store.query(limit=10)
        self.assertEqual(response.status, 200)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["device_name"], "Google Drive")
        self.assertEqual(incidents[0]["file_name"], "public access.zip")
        self.assertEqual(incidents[0]["finding_count"], 1)
        self.assertEqual(incidents[0]["sensitive_findings"][0]["kind"], "password")
        self.assertEqual(incidents[0]["policy_decision"], "Alert")
        self.assertEqual(incidents[0]["enforcement_state"], "pending_soc")
        self.assertEqual(incidents[0]["action_taken"], "Blocked by Google Drive security")
        self.assertEqual(incidents[0]["channel"], "Google Drive")
        self.assertEqual(incidents[0]["destination"], "drive.google.com")
        self.assertEqual(
            [event["event_type"] for event in incidents[0]["timeline"]],
            [
                "upload_detected",
                "destination_identified",
                "scan_started",
                "scan_completed",
                "policy_decision",
                "upload_blocked",
                "soc_alert",
            ],
        )
        self.assertEqual(
            incidents[0]["timeline"][0]["description"],
            "Google Drive upload attempt detected",
        )
        for event in incidents[0]["timeline"]:
            self.assertTrue(event["event_time"])
            self.assertEqual(event["title"], event["description"])

    def test_web_upload_to_ip_has_detailed_timeline(self) -> None:
        incident_payload = {
            "url": "http://192.168.100.143:1234/upload",
            "file_name": "customer-list.csv",
            "action": "Blocked by Enterprise Browser Extension",
            "blocked": True,
            "classification": "Internal",
            "sensitive_findings": [
                {
                    "kind": "email",
                    "match": "alic...com",
                    "position": 10,
                    "severity": "low",
                }
            ],
        }
        body = json.dumps(incident_payload).encode("utf-8")
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        with patch(
            "dlp_agent.dashboard._source_ipv4_for_destination",
            return_value="192.168.100.146",
        ):
            connection.request(
                "POST",
                "/api/browser_incident",
                body=body,
                headers={"Content-Type": "application/json"},
            )
        response = connection.getresponse()
        response.read()
        connection.close()

        incident = DashboardHandler.store.query(limit=1)[0]
        self.assertEqual(response.status, 200)
        self.assertEqual(incident["channel"], "Web Upload")
        self.assertEqual(incident["destination"], "192.168.100.143:1234")
        self.assertEqual(incident["source_ip"], "192.168.100.146")
        self.assertEqual(incident["ip_addresses"], ["192.168.100.146"])
        self.assertEqual(incident["destination_scope"], "Internal")
        self.assertEqual(incident["file_classification"], "Confidential")
        self.assertEqual(len(incident["timeline"]), 7)
        for event in incident["timeline"]:
            self.assertTrue(event["event_time"])
            self.assertEqual(event["title"], event["description"])
        self.assertEqual(
            incident["timeline"][0]["description"],
            "Browser file upload attempt detected",
        )
        self.assertIn("192.168.100.143:1234", incident["timeline"][1]["details"])
        self.assertIn("email", incident["timeline"][3]["details"])
        self.assertEqual(
            incident["timeline"][5]["description"],
            "Browser upload blocked",
        )

    def test_benign_browser_uploads_to_internal_and_external_destinations_are_alerted(self) -> None:
        destinations = [
            ("http://192.168.200.3:6666/upload", "192.168.200.3:6666", "Internal"),
            ("https://uploads.example.test/receive", "uploads.example.test", "External"),
        ]
        for index, (url, _destination, _scope) in enumerate(destinations):
            incident_payload = {
                "url": url,
                "file_name": f"meeting-notes-{index}.txt",
                "action": "Allowed by Enterprise Browser Extension",
                "blocked": False,
                "classification": "Public",
                "risk_score": 0,
                "sensitive_findings": [],
            }
            body = json.dumps(incident_payload).encode("utf-8")
            connection = HTTPConnection("127.0.0.1", self.server.server_port)
            connection.request(
                "POST",
                "/api/browser_incident",
                body=body,
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            response.read()
            connection.close()
            self.assertEqual(response.status, 200)

        incidents = DashboardHandler.store.query(limit=10)
        self.assertEqual(len(incidents), 2)
        by_destination = {incident["destination"]: incident for incident in incidents}
        for _url, destination, scope in destinations:
            incident = by_destination[destination]
            self.assertEqual(incident["policy_decision"], "Alert")
            self.assertEqual(incident["enforcement_state"], "pending_soc")
            self.assertEqual(incident["action_taken"], "Allowed by Enterprise Browser Extension")
            self.assertEqual(incident["file_classification"], "Public")
            self.assertNotIn(incident["file_classification"], {"Internal", "External"})
            self.assertEqual(incident["destination_scope"], scope)
            self.assertEqual(incident["channel"], "Web Upload")
            self.assertEqual(incident["risk_score"], 0)
            self.assertEqual(
                [event["event_type"] for event in incident["timeline"]],
                [
                    "upload_detected",
                    "destination_identified",
                    "scan_started",
                    "scan_completed",
                    "policy_decision",
                    "upload_allowed",
                    "soc_alert",
                ],
            )

    def test_soc_block_queues_close_for_originating_browser_window(self) -> None:
        incident_payload = {
            "url": "http://192.168.200.3:1234/upload",
            "file_name": "sensitive.txt",
            "action": "Blocked by Enterprise Browser Extension",
            "blocked": True,
            "browser_client_id": "browser-client-test",
            "browser_tab_id": 42,
            "browser_window_id": 7,
            "sensitive_findings": [
                {
                    "kind": "password",
                    "match": "pass...t123",
                    "position": 0,
                    "severity": "critical",
                }
            ],
        }
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request(
            "POST",
            "/api/browser_incident",
            body=json.dumps(incident_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        created = json.loads(response.read())
        connection.close()

        handler = object.__new__(DashboardHandler)
        handler.store = DashboardHandler.store
        handler._json_body = lambda: {"action": "block"}
        handler._serve_json = lambda *args, **kwargs: None
        handler._audit_change = lambda *args, **kwargs: None
        handler._enforce_incident(created["incident_id"])

        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request(
            "GET",
            "/api/browser_commands?client_id=browser-client-test",
        )
        response = connection.getresponse()
        commands = json.loads(response.read())["commands"]
        connection.close()

        updated = DashboardHandler.store.get(created["incident_id"])
        self.assertEqual(response.status, 200)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0]["action"], "block")
        self.assertEqual(commands[0]["file_name"], "sensitive.txt")
        self.assertEqual(commands[0]["browser_tab_id"], 42)
        self.assertEqual(commands[0]["browser_window_id"], 7)
        self.assertEqual(updated["enforcement_state"], "close_requested")
        self.assertEqual(updated["manual_action"], "block")
