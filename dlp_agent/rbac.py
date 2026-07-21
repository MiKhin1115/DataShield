from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


ROLES = {
    "Administrator": {
        "dashboard.view",
        "incidents.view",
        "incidents.update",
        "reports.export",
        "policies.view",
        "policies.manage",
        "users.manage",
        "usb.manage",
        "audit.view",
        "evidence.view",
        "evidence.download",
        "case_attachments.download",
        "ai_analysis.view",
        "ai_analysis.generate",
    },
    "SOC Analyst": {
        "dashboard.view",
        "incidents.view",
        "incidents.update",
        "reports.export",
        "policies.view",
        "evidence.view",
        "evidence.download",
        "case_attachments.download",
        "ai_analysis.view",
        "ai_analysis.generate",
    },
    "Auditor": {
        "dashboard.view",
        "incidents.view",
        "reports.export",
        "policies.view",
        "audit.view",
        "evidence.view",
        "ai_analysis.view",
    },
    "Read-Only User": {
        "dashboard.view",
        "incidents.view",
        "reports.export",
    },
}

DEFAULT_USERS = [
    ("admin", "Administrator", "Administration", "Admin123!"),
    ("soc", "SOC Analyst", "Security Operations", "Soc123!"),
    ("auditor", "Auditor", "Compliance", "Audit123!"),
    ("viewer", "Read-Only User", "General", "View123!"),
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UserStore:
    ITERATIONS = 210_000

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        if not self.path.exists():
            users = [
                self._new_user(username, role, department, password)
                for username, role, department, password in DEFAULT_USERS
            ]
            self._write(users)

    def authenticate(self, username: str, password: str) -> dict[str, object] | None:
        for user in self._read():
            if str(user.get("username", "")).casefold() != username.casefold():
                continue
            if not user.get("enabled", True):
                return None
            salt = bytes.fromhex(str(user.get("password_salt", "")))
            expected = bytes.fromhex(str(user.get("password_hash", "")))
            actual = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, self.ITERATIONS
            )
            return self.public(user) if hmac.compare_digest(actual, expected) else None
        return None

    def list(self) -> list[dict[str, object]]:
        return [self.public(user) for user in self._read()]

    def get(self, user_id: str) -> dict[str, object] | None:
        for user in self._read():
            if user.get("user_id") == user_id:
                return self.public(user)
        return None

    def find_by_username(self, username: str) -> dict[str, object] | None:
        for user in self._read():
            if str(user.get("username", "")).casefold() == username.casefold():
                return self.public(user)
        return None

    def create(self, value: dict[str, object]) -> dict[str, object]:
        username = str(value.get("username", "")).strip()
        password = str(value.get("password", ""))
        role = str(value.get("role", ""))
        department = str(value.get("department", "")).strip()
        if len(username) < 3:
            raise ValueError("Username must contain at least 3 characters")
        if len(password) < 8:
            raise ValueError("Password must contain at least 8 characters")
        if role not in ROLES:
            raise ValueError("Invalid role")
        with self._lock:
            users = self._read()
            if any(str(user.get("username", "")).casefold() == username.casefold() for user in users):
                raise ValueError("Username already exists")
            user = self._new_user(username, role, department, password)
            users.append(user)
            self._write(users)
        return self.public(user)

    def update(self, user_id: str, value: dict[str, object]) -> dict[str, object] | None:
        role = str(value.get("role", ""))
        if role not in ROLES:
            raise ValueError("Invalid role")
        with self._lock:
            users = self._read()
            for user in users:
                if user.get("user_id") != user_id:
                    continue
                user["role"] = role
                user["department"] = str(value.get("department", "")).strip()
                user["enabled"] = bool(value.get("enabled", True))
                password = str(value.get("password", ""))
                if password:
                    if len(password) < 8:
                        raise ValueError("Password must contain at least 8 characters")
                    salt, digest = self._password(password)
                    user["password_salt"] = salt
                    user["password_hash"] = digest
                user["updated_at"] = utc_now_iso()
                self._write(users)
                return self.public(user)
        return None

    def delete(self, user_id: str, current_user_id: str) -> bool:
        if user_id == current_user_id:
            raise ValueError("You cannot delete your own account")
        with self._lock:
            users = self._read()
            target = next((user for user in users if user.get("user_id") == user_id), None)
            if target is None:
                return False
            if target.get("role") == "Administrator":
                admin_count = sum(user.get("role") == "Administrator" for user in users)
                if admin_count <= 1:
                    raise ValueError("At least one administrator is required")
            self._write([user for user in users if user.get("user_id") != user_id])
            return True

    @staticmethod
    def public(user: dict[str, object]) -> dict[str, object]:
        return {
            key: value
            for key, value in user.items()
            if key not in {"password_hash", "password_salt"}
        }

    def _new_user(
        self, username: str, role: str, department: str, password: str
    ) -> dict[str, object]:
        salt, digest = self._password(password)
        now = utc_now_iso()
        return {
            "user_id": f"USR-{uuid4().hex[:10].upper()}",
            "username": username,
            "role": role,
            "department": department,
            "enabled": True,
            "password_salt": salt,
            "password_hash": digest,
            "created_at": now,
            "updated_at": now,
        }

    def _password(self, password: str) -> tuple[str, str]:
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, self.ITERATIONS
        )
        return salt.hex(), digest.hex()

    def _read(self) -> list[dict[str, object]]:
        if not self.path.exists():
            return []
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return value if isinstance(value, list) else []

    def _write(self, users: list[dict[str, object]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(users, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.path)


class SessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, object]] = {}
        self._lock = threading.Lock()

    def create(self, user: dict[str, object]) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[token] = user
        return token

    def get(self, token: str) -> dict[str, object] | None:
        with self._lock:
            return self._sessions.get(token)

    def delete(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)


def has_permission(user: dict[str, object] | None, permission: str) -> bool:
    if user is None:
        return False
    return permission in ROLES.get(str(user.get("role", "")), set())
