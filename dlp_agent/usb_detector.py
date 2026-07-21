from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class UsbDevice:
    device_id: str
    drive: str
    name: str
    volume_name: str
    filesystem: str
    size: int | None
    serial_number: str = ""
    manufacturer: str = ""
    model: str = ""
    pnp_device_id: str = ""


@dataclass(frozen=True)
class UsbDeviceEvent:
    event_type: str
    device: UsbDevice


class UsbProvider(Protocol):
    def list_devices(self) -> list[UsbDevice]:
        ...


class WindowsUsbProvider:
    """Reads removable USB storage drives through Windows CIM."""

    POWERSHELL_COMMAND = (
        "$items = @(); "
        "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=2\" | ForEach-Object { "
        "$logical = $_; $disk = $null; "
        "$partition = Get-CimAssociatedInstance -InputObject $logical "
        "-Association Win32_LogicalDiskToPartition | Select-Object -First 1; "
        "if ($partition) { $disk = Get-CimAssociatedInstance -InputObject $partition "
        "-Association Win32_DiskDriveToDiskPartition | Select-Object -First 1 }; "
        "$items += [PSCustomObject]@{ DeviceID=$logical.DeviceID; "
        "VolumeName=$logical.VolumeName; FileSystem=$logical.FileSystem; Size=$logical.Size; "
        "SerialNumber=if($disk){$disk.SerialNumber}else{''}; "
        "Manufacturer=if($disk){$disk.Manufacturer}else{''}; "
        "Model=if($disk){$disk.Model}else{''}; "
        "PnpDeviceID=if($disk){$disk.PNPDeviceID}else{''} } }; "
        "$items | ConvertTo-Json -Compress"
    )

    def list_devices(self) -> list[UsbDevice]:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", self.POWERSHELL_COMMAND],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "failed to query USB devices")

        output = completed.stdout.strip()
        if not output:
            return []

        raw_devices = json.loads(output)
        if isinstance(raw_devices, dict):
            raw_devices = [raw_devices]

        devices: list[UsbDevice] = []
        for raw in raw_devices:
            drive = str(raw.get("DeviceID") or "").strip()
            if not drive:
                continue
            volume_name = str(raw.get("VolumeName") or "").strip()
            filesystem = str(raw.get("FileSystem") or "").strip()
            name = volume_name or f"Removable Disk {drive}"
            devices.append(
                UsbDevice(
                    device_id=drive,
                    drive=f"{drive}\\",
                    name=name,
                    volume_name=volume_name,
                    filesystem=filesystem,
                    size=_to_int_or_none(raw.get("Size")),
                    serial_number=str(raw.get("SerialNumber") or "").strip(),
                    manufacturer=str(raw.get("Manufacturer") or "").strip(),
                    model=str(raw.get("Model") or "").strip(),
                    pnp_device_id=str(raw.get("PnpDeviceID") or "").strip(),
                )
            )
        return devices


class UsbDetector:
    def __init__(self, provider: UsbProvider) -> None:
        self.provider = provider
        self._known: dict[str, UsbDevice] = {}
        self._initialized = False

    def poll(self) -> list[UsbDeviceEvent]:
        current = {device.device_id: device for device in self.provider.list_devices()}

        if not self._initialized:
            self._known = current
            self._initialized = True
            return [UsbDeviceEvent("inserted", device) for device in current.values()]

        events: list[UsbDeviceEvent] = []
        for device_id, device in current.items():
            if device_id not in self._known:
                events.append(UsbDeviceEvent("inserted", device))

        for device_id, device in self._known.items():
            if device_id not in current:
                events.append(UsbDeviceEvent("removed", device))

        self._known = current
        return events


def _to_int_or_none(value: object) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
