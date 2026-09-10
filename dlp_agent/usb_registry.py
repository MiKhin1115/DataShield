from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class UsbRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()

    def list(self) -> list[dict[str, object]]:
        with self._lock:
            return self._read()

    def status(self, serial_number: str) -> str:
        serial = serial_number.strip().casefold()
        if not serial:
            return "unknown"
        for device in self.list():
            if str(device.get("device_id", "")).strip().casefold() == serial:
                return str(device.get("status", "unknown"))
        return "unknown"
    def upsert(self, device_id: str, name: str, status: str) -> dict[str, object]:
        if status not in {"authorized", "unauthorized", "blocked"}:
            raise ValueError("Invalid USB authorization status")
        device_id = device_id.strip()
        if ":" in device_id or "\\" in device_id or "/" in device_id:
            raise ValueError("Enter the hardware USB serial number, not a drive letter or device path")
        record = {
            "device_id": device_id.strip(),
            "name": name.strip() or device_id.strip(),
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if not record["device_id"]:
            raise ValueError("USB serial number is required")
        with self._lock:
            devices = self._read()
            for index, existing in enumerate(devices):
                if str(existing.get("device_id", "")).strip().casefold() == device_id.casefold():
                    devices[index] = record
                    self._write(devices)
                    return record
            devices.append(record)
            self._write(devices)
        return record

    def delete(self, device_id: str) -> bool:
        with self._lock:
            devices = self._read()
            remaining = [
                item
                for item in devices
                if str(item.get("device_id", "")).casefold() != device_id.strip().casefold()
            ]
            if len(remaining) == len(devices):
                return False
            self._write(remaining)
            return True

    def _read(self) -> list[dict[str, object]]:
        if not self.path.exists():
            return []
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return value if isinstance(value, list) else []

    def _write(self, devices: list[dict[str, object]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(devices, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.path)
