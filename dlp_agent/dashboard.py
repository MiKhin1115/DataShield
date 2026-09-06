from __future__ import annotations

import csv
import io
import json
import mimetypes
import os
import socket
import tempfile
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .ai_analysis import (
    AiAnalysisError,
    AiAnalysisService,
    AiAnalysisStore,
    OpenRouterClient,
    OpenRouterConfig,
    load_dotenv,
)
from .audit_log import AuditLog
from .evidence_vault import EvidenceVault
from .incident_store import IncidentStore
from .incident_workflow import CaseAttachmentStore, IncidentWorkflowService
from .policy import PolicyEngine
from .policy_store import PolicyStore
from .process_enforcer import ProcessActionResult, resume_process, terminate_process_tree
from .rbac import ROLES, SessionManager, UserStore, has_permission
from .sensitive_scanner import SensitiveDataScanner, SensitiveFinding
from .usb_registry import UsbRegistry

ASSET_DIRECTORY = Path(__file__).with_name("dashboard_assets")


def _source_ipv4_for_destination(destination_host: str) -> str:
    """Return the host IPv4 address selected by the OS route table."""
    candidates = [destination_host, "8.8.8.8"]
    for candidate in candidates:
        if not candidate:
            continue
        route_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # UDP connect selects an interface without sending application data.
            route_socket.connect((candidate, 443))
            address = str(route_socket.getsockname()[0])
            if address and not address.startswith("127.") and address != "0.0.0.0":
                return address
        except OSError:
            pass
        finally:
            route_socket.close()

    try:
        address = socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"
    return address or "127.0.0.1"


class DashboardHandler(BaseHTTPRequestHandler):
    store: IncidentStore
    policies: PolicyStore
    users: UserStore
    sessions: SessionManager
    audit: AuditLog
    usb_registry: UsbRegistry
    evidence_vault: EvidenceVault
    workflow: IncidentWorkflowService
    ai_analysis: AiAnalysisService

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path_parts = parsed.path.strip("/").split("/")
        if parsed.path == "/api/me":
            user = self._current_user()
            self._serve_json(
                {
                    "authenticated": user is not None,
                    "user": user,
                    "permissions": sorted(ROLES.get(str(user.get("role")), set())) if user else [],
                }
            )
            return
        if parsed.path == "/api/browser_commands":
            self._serve_browser_commands(parse_qs(parsed.query))
            return
        if parsed.path == "/api/incidents":
            if self._require("incidents.view"):
                self._serve_incidents(parse_qs(parsed.query))
            return
        if parsed.path == "/api/analysts":
            if self._require("incidents.view"):
                self._serve_json({"analysts": self.workflow.analysts()})
            return
        if parsed.path == "/api/ai/status":
            if self._require("ai_analysis.view"):
                self._serve_json(self.ai_analysis.status())
            return
        if (
            len(path_parts) == 4
            and path_parts[:2] == ["api", "incidents"]
            and path_parts[3] == "ai-analysis"
        ):
            if self._require("ai_analysis.view"):
                self._serve_ai_analyses(unquote(path_parts[2]))
            return
        if parsed.path == "/api/summary":
            if self._require("dashboard.view"):
                self._serve_json(self.store.summary())
            return
        if parsed.path == "/api/export.csv":
            if self._require("reports.export"):
                self._serve_csv()
            return
        if parsed.path == "/api/policies":
            if self._require("policies.view"):
                self._serve_json({"policies": self.policies.list()})
            return
        if parsed.path == "/api/users":
            if self._require("users.manage"):
                self._serve_json({"users": self.users.list(), "roles": list(ROLES)})
            return
        if parsed.path == "/api/audit":
            if self._require("audit.view"):
                self._serve_json({"entries": self.audit.list()})
            return
        if parsed.path == "/api/usb-devices":
            if self._require("usb.manage"):
                self._serve_json({"devices": self.usb_registry.list()})
            return
        if parsed.path.startswith("/api/evidence/") and parsed.path.endswith("/download"):
            if self._require("evidence.download"):
                evidence_id = unquote(parsed.path.split("/")[3])
                self._serve_evidence_download(evidence_id)
            return
        if (
            len(path_parts) == 5
            and path_parts[:2] == ["api", "incidents"]
            and path_parts[3] == "attachments"
        ):
            if self._require("case_attachments.download"):
                self._serve_case_attachment(
                    unquote(path_parts[2]), unquote(path_parts[4])
                )
            return
        self._serve_asset(parsed.path)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-File-Name")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path_parts = parsed.path.strip("/").split("/")
        if parsed.path == "/api/login":
            self._login()
            return
        if parsed.path == "/api/logout":
            self._logout()
            return
        if parsed.path == "/api/browser_incident":
            self._handle_browser_incident()
            return
        if parsed.path == "/api/scan_file":
            self._handle_scan_file()
            return
        if parsed.path == "/api/policies":
            if self._require_mutation("policies.manage"):
                self._create_policy()
            return
        if parsed.path == "/api/users":
            if self._require_mutation("users.manage"):
                self._create_user()
            return
        if parsed.path == "/api/usb-devices":
            if self._require_mutation("usb.manage"):
                self._upsert_usb()
            return
        if parsed.path == "/api/incidents/history/delete":
            if self._require_mutation("incidents.update"):
                self._delete_history_incidents()
            return
        if (
            len(path_parts) == 4
            and path_parts[:2] == ["api", "incidents"]
            and path_parts[3] == "ai-analysis"
        ):
            if self._require_mutation("ai_analysis.generate"):
                self._generate_ai_analysis(unquote(path_parts[2]))
            return
        if (
            len(path_parts) == 4
            and path_parts[:2] == ["api", "incidents"]
            and path_parts[3] == "enforce"
        ):
            if self._require_mutation("incidents.update"):
                self._enforce_incident(unquote(path_parts[2]))
            return
        if parsed.path.startswith("/api/incidents/"):
            if self._require_mutation("incidents.update"):
                self._update_incident(unquote(parsed.path.rsplit("/", 1)[-1]))
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def _delete_history_incidents(self) -> None:
        body = self._json_body()
        clear_all = body.get("clear_all") is True
        raw_ids = body.get("incident_ids", [])
        if not clear_all and not isinstance(raw_ids, list):
            self._serve_json({"error": "incident_ids must be a list"}, HTTPStatus.BAD_REQUEST)
            return

        incident_ids = [] if clear_all else list(dict.fromkeys(
            str(value) for value in raw_ids[:250] if str(value).startswith("INC-")
        ))
        if not clear_all and not incident_ids:
            self._serve_json({"error": "Select at least one history incident"}, HTTPStatus.BAD_REQUEST)
            return

        deleted_ids = self.store.delete_history(None if clear_all else incident_ids)
        if deleted_ids:
            scope = "all history" if clear_all else "selected history"
            self._audit_change(
                "history_incidents_deleted",
                "incidents",
                scope,
                f"count={len(deleted_ids)}; ids={','.join(deleted_ids)}",
            )
        self._serve_json({"status": "ok", "deleted_count": len(deleted_ids), "deleted_ids": deleted_ids})

    def do_PUT(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/policies/"):
            if self._require_mutation("policies.manage"):
                self._update_policy(unquote(parsed.path.rsplit("/", 1)[-1]))
            return
        if parsed.path.startswith("/api/users/"):
            if self._require_mutation("users.manage"):
                self._update_user(unquote(parsed.path.rsplit("/", 1)[-1]))
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if not self._valid_mutation_header():
            self._serve_json({"error": "Invalid request"}, HTTPStatus.FORBIDDEN)
            return
        if parsed.path.startswith("/api/policies/"):
            if self._require("policies.manage"):
                self._delete_policy(unquote(parsed.path.rsplit("/", 1)[-1]))
            return
        if parsed.path.startswith("/api/users/"):
            if self._require("users.manage"):
                self._delete_user(unquote(parsed.path.rsplit("/", 1)[-1]))
            return
        if parsed.path.startswith("/api/usb-devices/"):
            if self._require("usb.manage"):
                self._delete_usb(unquote(parsed.path.rsplit("/", 1)[-1]))
            return
        if parsed.path.startswith("/api/incidents/"):
            if self._require("incidents.update"):
                incident_id = unquote(parsed.path.rsplit("/", 1)[-1])
                if self.store.delete(incident_id):
                    self._audit_change("incident_deleted", "incident", incident_id)
                    self._serve_json({"status": "ok"})
                else:
                    self._serve_json({"error": "Incident not found"}, HTTPStatus.NOT_FOUND)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def _login(self) -> None:
        body = self._json_body()
        username = str(body.get("username", ""))
        user = self.users.authenticate(username, str(body.get("password", "")))
        if user is None:
            self.audit.record(username or "unknown", "login_failed", "session", "")
            self._serve_json({"error": "Invalid username or password"}, HTTPStatus.UNAUTHORIZED)
            return
        token = self.sessions.create(user)
        self.audit.record(str(user.get("username")), "login", "session", str(user.get("user_id")))
        self._serve_json(
            {"user": user, "permissions": sorted(ROLES.get(str(user.get("role")), set()))},
            headers={"Set-Cookie": f"dlp_session={token}; HttpOnly; SameSite=Strict; Path=/"},
        )

    def _logout(self) -> None:
        token = self._session_token()
        user = self._current_user()
        if token:
            self.sessions.delete(token)
        if user:
            self.audit.record(str(user.get("username")), "logout", "session", str(user.get("user_id")))
        self._serve_json(
            {"ok": True},
            headers={"Set-Cookie": "dlp_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"},
        )

    def _create_policy(self) -> None:
        try:
            policy = self.policies.create(self._json_body())
        except (ValueError, TypeError) as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self._audit_change("policy_created", "policy", str(policy["policy_id"]), str(policy["name"]))
        self._serve_json(policy, HTTPStatus.CREATED)

    def _update_policy(self, policy_id: str) -> None:
        try:
            policy = self.policies.update(policy_id, self._json_body())
        except (ValueError, TypeError) as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if policy is None:
            self._serve_json({"error": "Policy not found"}, HTTPStatus.NOT_FOUND)
            return
        self._audit_change("policy_updated", "policy", policy_id, str(policy["name"]))
        self._serve_json(policy)

    def _delete_policy(self, policy_id: str) -> None:
        if not self.policies.delete(policy_id):
            self._serve_json({"error": "Policy not found"}, HTTPStatus.NOT_FOUND)
            return
        self._audit_change("policy_deleted", "policy", policy_id)
        self._serve_json({"ok": True})

    def _create_user(self) -> None:
        try:
            user = self.users.create(self._json_body())
        except ValueError as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self._audit_change("user_created", "user", str(user["user_id"]), str(user["username"]))
        self._serve_json(user, HTTPStatus.CREATED)

    def _update_user(self, user_id: str) -> None:
        try:
            user = self.users.update(user_id, self._json_body())
        except ValueError as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if user is None:
            self._serve_json({"error": "User not found"}, HTTPStatus.NOT_FOUND)
            return
        self._audit_change("user_updated", "user", user_id, str(user["username"]))
        self._serve_json(user)

    def _delete_user(self, user_id: str) -> None:
        current = self._current_user() or {}
        try:
            deleted = self.users.delete(user_id, str(current.get("user_id", "")))
        except ValueError as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if not deleted:
            self._serve_json({"error": "User not found"}, HTTPStatus.NOT_FOUND)
            return
        self._audit_change("user_deleted", "user", user_id)
        self._serve_json({"ok": True})

    def _upsert_usb(self) -> None:
        body = self._json_body()
        try:
            device = self.usb_registry.upsert(
                str(body.get("device_id", "")),
                str(body.get("name", "")),
                str(body.get("status", "unauthorized")),
            )
        except ValueError as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self._audit_change("usb_updated", "usb_device", str(device["device_id"]), str(device["status"]))
        self._serve_json(device)

    def _delete_usb(self, device_id: str) -> None:
        if not self.usb_registry.delete(device_id):
            self._serve_json({"error": "USB device not found"}, HTTPStatus.NOT_FOUND)
            return
        self._audit_change("usb_deleted", "usb_device", device_id)
        self._serve_json({"ok": True})

    def _update_incident(self, incident_id: str) -> None:
        body = self._json_body()
        user = self._current_user() or {}
        try:
            updated, audit_events = self.workflow.update(incident_id, user, body)
        except LookupError as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            return
        except (ValueError, OSError) as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        for action, details in audit_events:
            self._audit_change(action, "incident", incident_id, details)
        self._serve_json(self._public_incident(updated))

    def _serve_ai_analyses(self, incident_id: str) -> None:
        try:
            analyses = self.ai_analysis.list_for_incident(incident_id)
        except LookupError as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            return
        self._serve_json({"analyses": analyses, "count": len(analyses)})

    def _generate_ai_analysis(self, incident_id: str) -> None:
        body = self._json_body()
        force = body.get("force") is True
        user = self._current_user() or {}
        actor = str(user.get("username", "unknown"))
        self._audit_change(
            "ai_analysis_requested",
            "incident",
            incident_id,
            f"model={self.ai_analysis.client.config.model}; force={force}",
        )
        try:
            analysis, cached = self.ai_analysis.generate(incident_id, actor, force)
        except LookupError as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            return
        except AiAnalysisError as exc:
            self._audit_change(
                "ai_analysis_failed", "incident", incident_id, f"code={exc.code}"
            )
            status = (
                HTTPStatus.SERVICE_UNAVAILABLE
                if exc.code in {"not_configured", "network_error", "timeout"}
                else HTTPStatus.BAD_GATEWAY
            )
            self._serve_json({"error": str(exc), "code": exc.code}, status)
            return
        action = "ai_analysis_cache_hit" if cached else "ai_analysis_completed"
        self._audit_change(
            action,
            "incident",
            incident_id,
            f"analysis_id={analysis.get('analysis_id')}; model={analysis.get('model_used')}",
        )
        self._serve_json({"analysis": analysis, "cached": cached})

    def _enforce_incident(self, incident_id: str) -> None:
        body = self._json_body()
        action = str(body.get("action", ""))
        if action not in {"allow", "block"}:
            self._serve_json({"error": "Action must be allow or block"}, HTTPStatus.BAD_REQUEST)
            return
        
        incident = self.store.get(incident_id)
        if not incident:
            self._serve_json({"error": "Incident not found"}, HTTPStatus.NOT_FOUND)
            return
        
        action_message = "Allowed by SOC"
        enforcement_state = str(incident.get("enforcement_state", "observed"))
        timeline = list(incident.get("timeline", []))
        if incident.get("incident_type") == "network_exfiltration" and incident.get("device_id") != "BROWSER_EXT":
            pid = incident.get("process_pid")
            process_name = str(incident.get("process_name", ""))
            create_time = incident.get("process_create_time")
            try:
                parsed_pid = int(pid)
                parsed_create_time = float(create_time) if create_time is not None else None
            except (TypeError, ValueError):
                result = ProcessActionResult(
                    False,
                    "identity_missing",
                    "Process identity metadata is missing; no process was changed",
                )
            else:
                if action == "block":
                    result = terminate_process_tree(
                        parsed_pid,
                        process_name,
                        parsed_create_time,
                    )
                elif enforcement_state == "suspended":
                    result = resume_process(
                        parsed_pid,
                        process_name,
                        parsed_create_time,
                    )
                else:
                    result = ProcessActionResult(
                        True,
                        "allowed",
                        f"{process_name} (PID {parsed_pid}) allowed by SOC",
                    )
            action_message = result.message
            enforcement_state = result.state
            enforcement_time = datetime.now(timezone.utc).isoformat()
            enforcement_title = f"SOC selected {action.title()}"
            timeline.append(
                {
                    "event_time": enforcement_time,
                    "time": enforcement_time,
                    "event_type": "soc_enforcement",
                    "title": enforcement_title,
                    "description": enforcement_title,
                    "details": result.message,
                }
            )
        elif incident.get("device_id") == "BROWSER_EXT":
            client_id = str(incident.get("browser_client_id", ""))
            command_queued = bool(client_id)
            if command_queued:
                self._queue_browser_command(
                    client_id,
                    {
                        "command_id": f"{incident_id}-{len(timeline) + 1}",
                        "incident_id": incident_id,
                        "action": action,
                        "file_name": incident.get("file_name"),
                        "browser_tab_id": incident.get("browser_tab_id"),
                        "browser_window_id": incident.get("browser_window_id"),
                    },
                )
            if action == "block":
                action_message = (
                    "Browser close requested by SOC"
                    if command_queued
                    else "Block recorded; browser link unavailable for this older incident"
                )
                enforcement_state = "close_requested" if command_queued else "blocked"
            else:
                action_message = "Browser upload allowed by SOC"
                enforcement_state = "allowed"
            enforcement_time = datetime.now(timezone.utc).isoformat()
            enforcement_title = f"SOC selected {action.title()}"
            timeline.append(
                {
                    "event_time": enforcement_time,
                    "time": enforcement_time,
                    "event_type": "soc_enforcement",
                    "title": enforcement_title,
                    "description": enforcement_title,
                    "details": action_message,
                }
            )
        elif incident.get("drive") and incident.get("incident_type") != "network_exfiltration":
            enforcement_time = datetime.now(timezone.utc).isoformat()
            enforcement_title = f"SOC selected {action.title()}"
            if action == "allow":
                action_message = "USB transfer allowed by SOC"
                action_details = "The removable drive remains available and monitored"
                enforcement_state = "allowed"
            else:
                from .usb_enforcement import WindowsUsbEnforcer

                result = WindowsUsbEnforcer().block_transfer(
                    str(incident.get("drive", "")),
                    str(incident.get("file_path", "")),
                )
                action_message = result.action
                action_details = result.details
                enforcement_state = "blocked" if result.enforced else "block_failed"
            timeline.append(
                {
                    "event_time": enforcement_time,
                    "time": enforcement_time,
                    "event_type": "soc_enforcement",
                    "title": enforcement_title,
                    "description": enforcement_title,
                    "details": action_details,
                }
            )

        changes = {
            "manual_action": action,
            "incident_status": (
                "Closed"
                if action == "allow"
                else "Open" if enforcement_state == "block_failed" else "Resolved"
            ),
            "action_taken": action_message,
            "enforcement_state": enforcement_state,
            "timeline": timeline,
        }
        updated = self.store.update(incident_id, changes)
        if updated is None:
            self._serve_json({"error": "Failed to update"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
            
        self._audit_change(f"incident_manual_{action}", "incident", incident_id)
        self._serve_json(self._public_incident(updated))

    _recent_browser_incidents: dict[str, float] = {}
    _browser_commands: dict[str, list[dict[str, object]]] = {}
    _browser_commands_lock = threading.Lock()

    def _queue_browser_command(
        self,
        client_id: str,
        command: dict[str, object],
    ) -> None:
        with DashboardHandler._browser_commands_lock:
            DashboardHandler._browser_commands.setdefault(client_id, []).append(command)

    def _serve_browser_commands(self, query: dict[str, list[str]]) -> None:
        client_id = str(query.get("client_id", [""])[0])[:128]
        if not client_id:
            self._serve_json(
                {"error": "client_id is required"},
                HTTPStatus.BAD_REQUEST,
            )
            return
        with DashboardHandler._browser_commands_lock:
            commands = DashboardHandler._browser_commands.pop(client_id, [])
        self._serve_json({"commands": commands})

    def _handle_browser_incident(self) -> None:
        body = self._json_body()
        file_name = str(body.get("file_name", "Unknown"))
        if file_name in {"Raw Payload Data", "Unknown", "Unknown File"}:
            self._serve_json({"status": "ignored"})
            return
        target_url = str(body.get("url", "Unknown"))
        import time
        now_ts = time.time()
        dedup_key = f"{file_name}::{target_url}"
        if dedup_key in DashboardHandler._recent_browser_incidents:
            if (now_ts - DashboardHandler._recent_browser_incidents[dedup_key]) < 5.0:
                print(f"[DLP DASHBOARD] Skipping duplicate incident for {file_name} within 5s", flush=True)
                self._serve_json({"status": "deduplicated"})
                return
        DashboardHandler._recent_browser_incidents[dedup_key] = now_ts

        action = str(body.get("action", "Blocked by Enterprise Browser Extension"))
        browser_client_id = str(body.get("browser_client_id", ""))[:128]

        def browser_identifier(name: str) -> int | None:
            try:
                value = int(body.get(name))
            except (TypeError, ValueError):
                return None
            return value if value >= 0 else None

        browser_tab_id = browser_identifier("browser_tab_id")
        browser_window_id = browser_identifier("browser_window_id")
        print(f"[DLP DASHBOARD] New Browser Incident Received: file={file_name}, target={target_url}", flush=True)
        
        from uuid import uuid4
        import getpass

        def utc_now_iso() -> str:
            return datetime.now(timezone.utc).isoformat()
        
        scanner = SensitiveDataScanner()
        findings: list[dict[str, object]] = []
        supplied_findings = body.get("sensitive_findings", [])
        if isinstance(supplied_findings, list):
            for item in supplied_findings:
                if not isinstance(item, dict):
                    continue
                kind = str(item.get("kind", "unknown"))[:80]
                severity = str(item.get("severity", "medium")).lower()
                if severity not in {"low", "medium", "high", "critical"}:
                    severity = "medium"
                try:
                    position = max(0, int(item.get("position", 0)))
                except (TypeError, ValueError):
                    position = 0
                findings.append(
                    {
                        "kind": kind,
                        "match": str(item.get("match", "detected"))[:120],
                        "position": position,
                        "severity": severity,
                    }
                )
        sample_text = str(body.get("sample_text", ""))
        if not findings and sample_text:
            try:
                findings = [asdict(f) for f in scanner.scan_text(sample_text)]
            except Exception:
                pass

        if not findings:
            try:
                findings = [asdict(f) for f in scanner.scan_text(file_name)]
            except Exception:
                pass

        parsed_target = urlparse(target_url)
        parsed_host = parsed_target.hostname or ""
        is_internal_url = (
            parsed_host in {"localhost", "127.0.0.1", "::1"}
            or parsed_host.startswith("192.168.")
            or parsed_host.startswith("10.")
            or (parsed_host.startswith("172.") and len(parsed_host.split(".")) == 4 and parsed_host.split(".")[1].isdigit() and 16 <= int(parsed_host.split(".")[1]) <= 31)
        )
        url_classification = "Internal" if is_internal_url else "External"

        lower_url = target_url.lower()
        if "drive.google" in lower_url or "google.com/drive" in lower_url:
            app_name = "Google Drive"
        elif "telegram" in lower_url:
            app_name = "Telegram Web"
        elif "gmail" in lower_url or "mail.google" in lower_url:
            app_name = "Gmail"
        elif "dropbox" in lower_url:
            app_name = "Dropbox"
        elif "onedrive" in lower_url or "sharepoint" in lower_url:
            app_name = "Microsoft OneDrive"
        elif "slack" in lower_url:
            app_name = "Slack"
        elif "whatsapp" in lower_url:
            app_name = "WhatsApp Web"
        elif parsed_host:
            app_name = parsed_host
        else:
            app_name = "Enterprise Browser Extension"

        known_browser_channels = {
            "Google Drive": "Google Drive",
            "Telegram Web": "Telegram",
            "Gmail": "Gmail",
            "Dropbox": "Dropbox",
            "Microsoft OneDrive": "Microsoft OneDrive",
            "Slack": "Slack",
            "WhatsApp Web": "WhatsApp",
        }
        channel = known_browser_channels.get(app_name, "Web Upload")
        try:
            target_port = parsed_target.port
        except ValueError:
            target_port = None
        if parsed_host:
            destination = f"{parsed_host}:{target_port}" if target_port else parsed_host
        else:
            destination = target_url
        source_ip = _source_ipv4_for_destination(parsed_host)

        scan_error = str(body.get("scan_error", ""))[:300] or None
        supplied_blocked = body.get("blocked")
        action_indicates_block = action.casefold().startswith("blocked")
        blocked = bool(findings or scan_error or action_indicates_block)
        if isinstance(supplied_blocked, bool):
            blocked = blocked or supplied_blocked

        assessment_findings = [
            SensitiveFinding(
                kind=str(item.get("kind", "unknown")),
                match=str(item.get("match", "detected")),
                position=int(item.get("position", 0)),
                severity=str(item.get("severity", "medium")),
            )
            for item in findings
        ]
        assessment = PolicyEngine().assess(assessment_findings, scan_error)
        # Internal/External describes the destination scope, not data sensitivity.
        # Browser file classifications intentionally use only data-based labels.
        if findings:
            content_classification = (
                "Confidential"
                if assessment.file_classification == "Internal"
                else assessment.file_classification
            )
        elif blocked:
            content_classification = "Restricted"
        else:
            content_classification = "Public"

        supplied_risk = body.get("risk_score")
        try:
            risk_score = int(supplied_risk) if supplied_risk is not None else assessment.risk_score
        except (TypeError, ValueError):
            risk_score = assessment.risk_score
        risk_score = max(0, min(100, risk_score))
        if blocked and not findings:
            risk_score = max(risk_score, 75)
        # Browser activity always enters the SOC review stage first. The scan
        # outcome remains in action_taken/timeline while the dashboard presents
        # the analyst with an explicit Allow or Block decision.
        policy_decision = "Alert"
        finding_types = sorted({str(item.get("kind", "unknown")) for item in findings})
        policy_reasons = [
            "Sensitive browser upload held for SOC review"
            if blocked
            else "Browser upload inspected and recorded for SOC review"
        ]
        if finding_types:
            policy_reasons.append(f"Sensitive data detected: {', '.join(finding_types)}")
        if scan_error:
            policy_reasons.append("Deep content inspection could not complete safely")

        incident_id = f"INC-{uuid4().hex[:12].upper()}"

        def timeline_event(event_type: str, description: str, details: str) -> dict[str, str]:
            event_time = utc_now_iso()
            return {
                "event_time": event_time,
                "time": event_time,
                "event_type": event_type,
                "title": description,
                "description": description,
                "details": details,
            }

        scan_details = (
            f"Detected {len(findings)} finding(s): {', '.join(finding_types)}. "
            f"Content classified as {content_classification}."
            if finding_types
            else (
                f"Inspection could not complete safely: {scan_error}"
                if scan_error
                else f"No scanner finding metadata was available. Content classified as {content_classification}."
            )
        )
        if blocked:
            enforcement_description = (
                "Google Drive rejected the upload"
                if action == "Blocked by Google Drive security"
                else "Browser upload blocked"
            )
            enforcement_details = f"{action}. Transfer of {file_name} to {destination} did not proceed."
            enforcement_event_type = "upload_blocked"
        else:
            enforcement_description = "Browser upload allowed"
            enforcement_details = f"{action}. Transfer of {file_name} to {destination} was permitted."
            enforcement_event_type = "upload_allowed"
        upload_description = (
            "Browser file upload attempt detected"
            if channel == "Web Upload"
            else f"{channel} upload attempt detected"
        )
        timeline = [
            timeline_event(
                "upload_detected",
                upload_description,
                f"User selected {file_name} for transfer through {channel}.",
            ),
            timeline_event(
                "destination_identified",
                "Upload destination identified",
                f"Target {destination} classified as {url_classification}.",
            ),
            timeline_event(
                "scan_started",
                "Sensitive data scan started",
                f"Deep content inspection started for {file_name}.",
            ),
            timeline_event(
                "scan_completed",
                "Sensitive data scan completed" if not scan_error else "Sensitive data scan failed safely",
                scan_details,
            ),
            timeline_event(
                "policy_decision",
                f"Policy action selected: {policy_decision}",
                f"HTTPS Payload Inspection assigned risk {risk_score}/100 and {content_classification} classification.",
            ),
            timeline_event(
                enforcement_event_type,
                enforcement_description,
                enforcement_details,
            ),
            timeline_event(
                "soc_alert",
                "SOC dashboard alert generated",
                f"Incident {incident_id} opened for analyst review.",
            ),
        ]

        incident = {
            "incident_id": incident_id,
            "incident_type": "network_exfiltration",
            "event_time": utc_now_iso(),
            "user_name": getpass.getuser(),
            "department": "Unknown",
            "computer_name": socket.gethostname(),
            "source_ip": source_ip,
            "ip_addresses": [source_ip],
            "device_id": "BROWSER_EXT",
            "device_name": app_name,
            "browser_client_id": browser_client_id,
            "browser_tab_id": browser_tab_id,
            "browser_window_id": browser_window_id,
            "usb_serial_number": "",
            "usb_manufacturer": "",
            "usb_model": "",
            "usb_authorization_status": "",
            "drive": "",
            "file_name": file_name,
            "file_type": "Data Payload",
            "file_path": f"Target: {target_url}",
            "channel": channel,
            "destination": destination,
            "destination_url": target_url,
            "file_size": 0,
            "change_type": "browser_upload",
            "finding_count": len(findings),
            "sensitive_findings": findings,
            "scan_readable": scan_error is None,
            "scan_error": scan_error,
            "file_classification": content_classification,
            "recommended_classification": content_classification,
            "destination_classification": url_classification,
            "destination_scope": url_classification,
            "risk_score": risk_score,
            "policy_decision": policy_decision,
            "action_taken": action,
            "policy_reasons": policy_reasons,
            "matched_policy_ids": ["EXT-HTTPS-001"],
            "matched_policy_names": ["HTTPS Payload Inspection"],
            "manual_action": "",
            "incident_status": "Open",
            "enforcement_state": "pending_soc",
            "timeline": timeline,
        }
        self.store.append(incident)
        self._serve_json({"status": "ok", "incident_id": incident_id})

    def _handle_scan_file(self) -> None:
        file_name = unquote(self.headers.get("X-File-Name", "unknown"))
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._serve_json(
                {"blocked": True, "error": "invalid content length"},
                HTTPStatus.BAD_REQUEST,
            )
            return
        if content_length < 0:
            self._serve_json(
                {"blocked": True, "error": "invalid content length"},
                HTTPStatus.BAD_REQUEST,
            )
            return
        if content_length > 10 * 1024 * 1024:
            self._serve_json(
                {"blocked": True, "error": "file is too large to inspect safely"},
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            return

        file_data = self.rfile.read(content_length)
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file_name).suffix) as tmp:
            tmp.write(file_data)
            tmp_path = tmp.name

        try:
            scanner = SensitiveDataScanner()
            scan_result = scanner.scan_file(Path(tmp_path), display_name=file_name)
            assessment = PolicyEngine().assess(scan_result.findings, scan_result.error)
            blocked = bool(scan_result.findings or scan_result.error)
            classification = (
                "Confidential"
                if assessment.file_classification == "Internal"
                else assessment.file_classification
            )
            details = ", ".join(
                sorted({finding.kind for finding in scan_result.findings})
            )
            self._serve_json(
                {
                    "blocked": blocked,
                    "details": details,
                    "finding_count": len(scan_result.findings),
                    "findings": [asdict(finding) for finding in scan_result.findings],
                    "classification": classification,
                    "risk_score": assessment.risk_score,
                    "error": scan_result.error,
                }
            )
        except Exception as exc:
            # The browser must not treat an inspection failure as a clean result.
            self._serve_json({"blocked": True, "error": str(exc)})
        finally:
            try:
                os.remove(tmp_path)
            except FileNotFoundError:
                pass

    def _serve_incidents(self, query: dict[str, list[str]]) -> None:
        try:
            min_risk = max(0, min(100, int(self._first(query, "min_risk", "0"))))
            max_risk = max(0, min(100, int(self._first(query, "max_risk", "100"))))
            limit = max(1, min(1000, int(self._first(query, "limit", "250"))))
        except ValueError:
            self._serve_json({"error": "Invalid numeric filter"}, HTTPStatus.BAD_REQUEST)
            return
        incidents = self.store.query(
            classification=self._first(query, "classification"),
            decision=self._first(query, "decision"),
            search=self._first(query, "search"),
            min_risk=min_risk,
            max_risk=max_risk,
            risk_level=self._first(query, "risk_level"),
            incident_id=self._first(query, "incident_id"),
            user_name=self._first(query, "user_name"),
            computer_name=self._first(query, "computer_name"),
            usb_name=self._first(query, "usb_name"),
            usb_serial=self._first(query, "usb_serial"),
            file_name=self._first(query, "file_name"),
            file_type=self._first(query, "file_type"),
            status=self._first(query, "status"),
            assigned_to=self._first(query, "assigned_to"),
            assignment_state=self._first(query, "assignment_state"),
            date_from=self._first(query, "date_from"),
            date_to=self._first(query, "date_to"),
            limit=limit,
        )
        self._serve_json(
            {"incidents": [self._public_incident(item) for item in incidents], "count": len(incidents)}
        )

    def _serve_csv(self) -> None:
        fields = [
            "incident_id", "event_time", "user_name", "department", "device_name",
            "device_id", "usb_authorization_status", "file_name", "file_path",
            "file_classification", "finding_count", "risk_score", "policy_decision",
            "action_taken", "incident_status", "assigned_to", "sha256",
        ]
        rows = []
        for incident in self.store.query(limit=1000):
            hashes = incident.get("file_hashes", {})
            rows.append({**incident, "sha256": hashes.get("sha256", "") if isinstance(hashes, dict) else ""})
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        body = output.getvalue().encode("utf-8-sig")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", "attachment; filename=usb-dlp-incidents.csv")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_evidence_download(self, evidence_id: str) -> None:
        try:
            plaintext, evidence = self.evidence_vault.decrypt_copy(evidence_id)
        except (FileNotFoundError, ValueError, OSError) as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            return
        file_name = Path(str(evidence.get("file_name", "evidence.bin"))).name
        self._audit_change("evidence_downloaded", "evidence", evidence_id, file_name)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{file_name}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(plaintext)))
        self.end_headers()
        self.wfile.write(plaintext)

    def _serve_case_attachment(self, incident_id: str, attachment_id: str) -> None:
        try:
            attachment, content = self.workflow.find_attachment(incident_id, attachment_id)
        except FileNotFoundError as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            return
        except (ValueError, OSError) as exc:
            self._serve_json({"error": str(exc)}, HTTPStatus.CONFLICT)
            return
        file_name = Path(str(attachment.get("file_name", "attachment.bin"))).name
        safe_name = file_name.replace('"', "").replace("\r", "").replace("\n", "")
        self._audit_change(
            "case_attachment_downloaded", "incident", incident_id, attachment_id
        )
        self.send_response(HTTPStatus.OK)
        self.send_header(
            "Content-Type", str(attachment.get("content_type", "application/octet-stream"))
        )
        self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _current_user(self) -> dict[str, object] | None:
        token = self._session_token()
        return self.sessions.get(token) if token else None

    def _session_token(self) -> str:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("dlp_session")
        return morsel.value if morsel else ""

    def _require(self, permission: str) -> bool:
        user = self._current_user()
        if user is None:
            self._serve_json({"error": "Authentication required"}, HTTPStatus.UNAUTHORIZED)
            return False
        if not has_permission(user, permission):
            self._serve_json({"error": "Permission denied"}, HTTPStatus.FORBIDDEN)
            return False
        return True

    def _require_mutation(self, permission: str) -> bool:
        if not self._valid_mutation_header():
            self._serve_json({"error": "Invalid request"}, HTTPStatus.FORBIDDEN)
            return False
        return self._require(permission)

    def _valid_mutation_header(self) -> bool:
        return self.headers.get("X-DLP-Request") == "dashboard"

    def _json_body(self) -> dict[str, object]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                length = 65536
            length = min(length, 3_200_000)
            data = self.rfile.read(length)
            value = json.loads(data.decode("utf-8", errors="ignore") or "{}")
        except (ValueError, json.JSONDecodeError, Exception):
            return {}
        return value if isinstance(value, dict) else {}

    def _audit_change(
        self, action: str, target_type: str, target_id: str, details: str = ""
    ) -> None:
        user = self._current_user() or {}
        self.audit.record(str(user.get("username", "unknown")), action, target_type, target_id, details)

    @staticmethod
    def _public_incident(incident: dict[str, object]) -> dict[str, object]:
        public = dict(incident)
        if incident.get("device_id") == "BROWSER_EXT":
            source_ip = str(incident.get("source_ip", ""))
            if not source_ip or source_ip.startswith("127.") or source_ip == "0.0.0.0":
                target_url = str(
                    incident.get("destination_url")
                    or incident.get("file_path", "")
                ).removeprefix("Target: ")
                destination_host = urlparse(target_url).hostname or ""
                source_ip = _source_ipv4_for_destination(destination_host)
                public["source_ip"] = source_ip
                public["ip_addresses"] = [source_ip]
        elif incident.get("drive") and not incident.get("source_ip"):
            # Legacy USB incidents stored every adapter address and the UI
            # commonly picked a virtual adapter. Show the current routed host
            # IPv4 for those records; new incidents persist source_ip directly.
            source_ip = _source_ipv4_for_destination("")
            public["source_ip"] = source_ip
            public["ip_addresses"] = [source_ip]
        if (
            incident.get("drive")
            and not incident.get("manual_action")
            and incident.get("incident_status", "Open") in {"New", "Open"}
            and (
                incident.get("incident_type") != "usb_device"
                or incident.get("policy_decision") != "Block"
            )
        ):
            # USB transfers created before the SOC-review workflow stored the
            # recommendation as the action. Present unresolved legacy records
            # through the same Alert -> Allow/Block workflow as new records.
            public["policy_decision"] = "Alert"
            public["action_taken"] = "Awaiting SOC decision"
            public["enforcement_state"] = "pending_soc"
        notes = incident.get("investigation_notes", [])
        if isinstance(notes, list):
            public_notes: list[object] = []
            for note in notes:
                if not isinstance(note, dict):
                    public_notes.append(note)
                    continue
                public_note = dict(note)
                attachments = note.get("attachments", [])
                if isinstance(attachments, list):
                    public_note["attachments"] = [
                        {key: value for key, value in attachment.items() if key != "storage_name"}
                        if isinstance(attachment, dict)
                        else attachment
                        for attachment in attachments
                    ]
                public_notes.append(public_note)
            public["investigation_notes"] = public_notes
        return public

    def _serve_asset(self, request_path: str) -> None:
        relative = "index.html" if request_path in {"", "/"} else request_path.lstrip("/")
        candidate = (ASSET_DIRECTORY / relative).resolve()
        asset_root = ASSET_DIRECTORY.resolve()
        if asset_root not in candidate.parents and candidate != asset_root:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if not candidate.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_json(
        self,
        value: object,
        status: HTTPStatus = HTTPStatus.OK,
        headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-File-Name")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        for name, header_value in (headers or {}).items():
            self.send_header(name, header_value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _first(query: dict[str, list[str]], name: str, default: str = "") -> str:
        values = query.get(name)
        return values[0] if values else default

    def log_message(self, format: str, *args: object) -> None:
        return


def serve_dashboard(host: str, port: int, log_file: Path) -> int:
    load_dotenv(Path(".env"))
    data_directory = log_file.parent
    handler = type("ConfiguredDashboardHandler", (DashboardHandler,), {})
    handler.store = IncidentStore(log_file)
    handler.policies = PolicyStore(data_directory / "policies.json")
    handler.users = UserStore(data_directory / "users.json")
    handler.sessions = SessionManager()
    handler.audit = AuditLog(data_directory / "audit.jsonl")
    handler.usb_registry = UsbRegistry(data_directory / "usb_devices.json")
    handler.evidence_vault = EvidenceVault(data_directory / "evidence")
    handler.workflow = IncidentWorkflowService(
        handler.store,
        handler.users,
        CaseAttachmentStore(data_directory / "case_attachments"),
    )
    handler.ai_analysis = AiAnalysisService(
        handler.store,
        AiAnalysisStore(data_directory / "ai_analyses.jsonl"),
        OpenRouterClient(OpenRouterConfig.from_environment()),
    )
    server = ThreadingHTTPServer((host, port), handler)
    print(f"USB DLP dashboard available at http://{host}:{port}")
    print(f"Reading platform data from {data_directory.absolute()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("USB DLP dashboard stopped.")
    finally:
        server.server_close()
    return 0
