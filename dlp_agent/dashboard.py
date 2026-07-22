from __future__ import annotations

import csv
import io
import json
import mimetypes
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
from .policy_store import PolicyStore
from .rbac import ROLES, SessionManager, UserStore, has_permission
from .usb_registry import UsbRegistry


ASSET_DIRECTORY = Path(__file__).with_name("dashboard_assets")


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
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
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
        
        incident = self.store.get(incident_id)
        if not incident:
            self._serve_json({"error": "Incident not found"}, HTTPStatus.NOT_FOUND)
            return
        
        if action == "block":
            if incident.get("incident_type") == "network_exfiltration":
                import psutil
                from .firewall_enforcer import block_ip_firewall
                
                remote_ip = incident.get("remote_ip")
                if remote_ip:
                    block_ip_firewall(str(remote_ip))
                    
                pid = incident.get("process_pid")
                if pid:
                    try:
                        psutil.Process(int(pid)).terminate()
                    except (ValueError, psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
                        pass
                
                if incident.get("device_id") == "BROWSER_EXT":
                    for proc in psutil.process_iter(['name']):
                        if proc.info['name'] in ['chrome.exe']:
                            try:
                                proc.kill()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
            else:
                drive = str(incident.get("drive", ""))
                if drive:
                    from .usb_enforcement import WindowsUsbEnforcer
                    enforcer = WindowsUsbEnforcer()
                    enforcer.wipe_and_block(drive)
        
        changes = {"manual_action": action, "incident_status": "Closed" if action == "allow" else "Resolved"}
        updated = self.store.update(incident_id, changes)
        if updated is None:
            self._serve_json({"error": "Failed to update"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
            
        self._audit_change(f"incident_manual_{action}", "incident", incident_id)
        self._serve_json(self._public_incident(updated))

    def _handle_browser_incident(self) -> None:
        body = self._json_body()
        file_name = str(body.get("file_name", "Unknown"))
        target_url = str(body.get("url", "Unknown"))
        action = str(body.get("action", "Blocked"))
        
        from uuid import uuid4
        from datetime import datetime, timezone
        import getpass
        import socket
        
        def utc_now_iso() -> str:
            return datetime.now(timezone.utc).isoformat()
        import socket
        
        incident = {
            "incident_id": f"INC-{uuid4().hex[:12].upper()}",
            "incident_type": "network_exfiltration",
            "event_time": utc_now_iso(),
            "user_name": getpass.getuser(),
            "department": "Unknown",
            "computer_name": socket.gethostname(),
            "ip_addresses": ["127.0.0.1"],
            "device_id": "BROWSER_EXT",
            "device_name": "Enterprise Browser Extension",
            "usb_serial_number": "",
            "usb_manufacturer": "",
            "usb_model": "",
            "usb_authorization_status": "",
            "drive": "",
            "file_name": file_name,
            "file_type": "Data Payload",
            "file_path": f"Target: {target_url}",
            "file_size": 0,
            "change_type": "browser_upload",
            "sensitive_findings": [],
            "file_classification": "Restricted",
            "recommended_classification": "Restricted",
            "risk_score": 95,
            "policy_decision": "Block",
            "action_taken": action,
            "policy_reasons": ["Browser Extension detected sensitive payload upload over HTTPS"],
            "matched_policy_ids": ["EXT-HTTPS-001"],
            "matched_policy_names": ["HTTPS Payload Inspection"],
            "manual_action": "",
            "incident_status": "Open",
            "timeline": [
                {
                    "time": utc_now_iso(),
                    "event_type": "HTTPS Inspection",
                    "description": f"Browser extension intercepted upload to {target_url}",
                    "details": f"Payload contained sensitive data. Upload blocked natively in browser."
                }
            ]
        }
        self.store.append(incident)
        self._serve_json({"status": "ok"})

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
            length = min(int(self.headers.get("Content-Length", "0")), 3_200_000)
            value = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
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
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
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
