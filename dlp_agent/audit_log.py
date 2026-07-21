from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def record(
        self,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        details: str = "",
    ) -> dict[str, object]:
        entry = {
            "audit_id": f"AUD-{uuid4().hex[:12].upper()}",
            "event_time": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "details": details,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def list(self, limit: int = 250) -> list[dict[str, object]]:
        if not self.path.exists():
            return []
        entries: list[dict[str, object]] = []
        with self._lock, self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    entries.append(entry)
        return list(reversed(entries[-limit:]))
