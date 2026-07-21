from __future__ import annotations

import json
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


VALID_ACTIONS = {"Allow", "Alert", "Block"}
VALID_FIELDS = {
    "file_classification",
    "sensitive_data_type",
    "sensitive_data_count",
    "file_size",
    "file_extension",
    "usb_authorized",
    "user_name",
    "department",
    "risk_score",
    "transfer_time",
}
VALID_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "greater_than",
    "greater_or_equal",
    "less_than",
    "less_or_equal",
}

DEFAULT_POLICIES = [
    {
        "policy_id": "POL-RESTRICTED-USB",
        "name": "Block restricted files",
        "description": "Block Restricted files and notify the SOC.",
        "enabled": True,
        "priority": 10,
        "conditions": [
            {"field": "file_classification", "operator": "equals", "value": "Restricted"}
        ],
        "action": "Block",
        "notify_soc": True,
        "risk_score_override": 90,
    },
    {
        "policy_id": "POL-BANK-ACCOUNT-VOLUME",
        "name": "High volume bank account alert",
        "description": "Raise a high-risk alert when more than five bank accounts are found.",
        "enabled": True,
        "priority": 20,
        "conditions": [
            {
                "field": "sensitive_data_count",
                "operator": "greater_than",
                "value": 5,
                "data_type": "bank_account",
            }
        ],
        "action": "Alert",
        "notify_soc": True,
        "risk_score_override": 85,
    },
    {
        "policy_id": "POL-LARGE-FILE",
        "name": "Large transfer review",
        "description": "Alert on files larger than 100 MB.",
        "enabled": False,
        "priority": 50,
        "conditions": [
            {"field": "file_size", "operator": "greater_than", "value": 104857600}
        ],
        "action": "Alert",
        "notify_soc": True,
        "risk_score_override": 60,
    },
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PolicyStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        if not self.path.exists():
            now = utc_now_iso()
            policies = [
                {**deepcopy(policy), "created_at": now, "updated_at": now}
                for policy in DEFAULT_POLICIES
            ]
            self._write(policies)

    def list(self) -> list[dict[str, object]]:
        with self._lock:
            return sorted(self._read(), key=lambda item: int(item.get("priority", 100)))

    def create(self, value: dict[str, object]) -> dict[str, object]:
        policy = self._validated(value)
        now = utc_now_iso()
        policy.update(
            policy_id=f"POL-{uuid4().hex[:10].upper()}",
            created_at=now,
            updated_at=now,
        )
        with self._lock:
            policies = self._read()
            policies.append(policy)
            self._write(policies)
        return policy

    def update(self, policy_id: str, value: dict[str, object]) -> dict[str, object] | None:
        update = self._validated(value)
        with self._lock:
            policies = self._read()
            for index, existing in enumerate(policies):
                if existing.get("policy_id") != policy_id:
                    continue
                policy = {
                    **update,
                    "policy_id": policy_id,
                    "created_at": existing.get("created_at", utc_now_iso()),
                    "updated_at": utc_now_iso(),
                }
                policies[index] = policy
                self._write(policies)
                return policy
        return None

    def delete(self, policy_id: str) -> bool:
        with self._lock:
            policies = self._read()
            remaining = [item for item in policies if item.get("policy_id") != policy_id]
            if len(remaining) == len(policies):
                return False
            self._write(remaining)
            return True

    def set_enabled(self, policy_id: str, enabled: bool) -> dict[str, object] | None:
        with self._lock:
            policies = self._read()
            for policy in policies:
                if policy.get("policy_id") == policy_id:
                    policy["enabled"] = enabled
                    policy["updated_at"] = utc_now_iso()
                    self._write(policies)
                    return policy
        return None

    @staticmethod
    def _validated(value: dict[str, object]) -> dict[str, object]:
        name = str(value.get("name", "")).strip()
        action = str(value.get("action", ""))
        conditions = value.get("conditions")
        if not name:
            raise ValueError("Policy name is required")
        if action not in VALID_ACTIONS:
            raise ValueError("Policy action must be Allow, Alert, or Block")
        if not isinstance(conditions, list) or not conditions:
            raise ValueError("At least one policy condition is required")

        clean_conditions: list[dict[str, object]] = []
        for raw in conditions:
            if not isinstance(raw, dict):
                raise ValueError("Invalid policy condition")
            field = str(raw.get("field", ""))
            operator = str(raw.get("operator", ""))
            if field not in VALID_FIELDS or operator not in VALID_OPERATORS:
                raise ValueError("Invalid condition field or operator")
            condition = {"field": field, "operator": operator, "value": raw.get("value")}
            if field == "sensitive_data_count":
                condition["data_type"] = str(raw.get("data_type", "")).strip()
            clean_conditions.append(condition)

        priority = int(value.get("priority", 100))
        risk_override_raw = value.get("risk_score_override")
        risk_override = None if risk_override_raw in {None, ""} else int(risk_override_raw)
        if priority < 1 or priority > 999:
            raise ValueError("Priority must be between 1 and 999")
        if risk_override is not None and not 0 <= risk_override <= 100:
            raise ValueError("Risk score override must be between 0 and 100")

        return {
            "name": name,
            "description": str(value.get("description", "")).strip(),
            "enabled": bool(value.get("enabled", True)),
            "priority": priority,
            "conditions": clean_conditions,
            "action": action,
            "notify_soc": bool(value.get("notify_soc", action != "Allow")),
            "risk_score_override": risk_override,
        }

    def _read(self) -> list[dict[str, object]]:
        if not self.path.exists():
            return []
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        return value if isinstance(value, list) else []

    def _write(self, policies: list[dict[str, object]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(policies, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.path)
