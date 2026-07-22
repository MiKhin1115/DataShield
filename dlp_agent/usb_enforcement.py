from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Protocol

from .usb_detector import UsbDevice


@dataclass(frozen=True)
class UsbEnforcementResult:
    enforced: bool
    action: str
    details: str


class UsbEnforcer(Protocol):
    def block(self, device: UsbDevice) -> UsbEnforcementResult:
        ...
        
    def wipe_and_block(self, drive_path: str) -> UsbEnforcementResult:
        ...


class WindowsUsbEnforcer:
    """Block access to a removable drive by safely ejecting it."""

    POWERSHELL_COMMAND = (
        "& { param([string]$targetDrive) "
        "$drive = $targetDrive.TrimEnd('\\'); "
        "$shell = New-Object -ComObject Shell.Application; "
        "$item = $shell.Namespace(17).ParseName($drive); "
        "if ($null -eq $item) { Write-Error 'USB drive was not found'; exit 2 }; "
        "$item.InvokeVerb('Eject'); "
        "Start-Sleep -Milliseconds 1200; "
        "if (Test-Path ($drive + '\\')) { Write-Error 'Windows did not eject the USB drive'; exit 3 } "
        "}"
    )

    POWERSHELL_WIPE_COMMAND = (
        "& { param([string]$targetDrive) "
        "$drive = $targetDrive.TrimEnd('\\'); "
        "if ($drive -match '^[D-Z]:$') { "
        "  Remove-Item -Path \"$drive\\*\" -Recurse -Force -ErrorAction SilentlyContinue; "
        "} "
        "$shell = New-Object -ComObject Shell.Application; "
        "$item = $shell.Namespace(17).ParseName($drive); "
        "if ($null -eq $item) { Write-Error 'USB drive was not found'; exit 2 }; "
        "$item.InvokeVerb('Eject'); "
        "Start-Sleep -Milliseconds 1200; "
        "if (Test-Path ($drive + '\\')) { Write-Error 'Windows did not eject the USB drive'; exit 3 } "
        "}"
    )

    def block(self, device: UsbDevice) -> UsbEnforcementResult:
        try:
            completed = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    self.POWERSHELL_COMMAND,
                    device.device_id,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return UsbEnforcementResult(
                False,
                "Block failed",
                f"Windows USB enforcement could not run: {exc}",
            )

        if completed.returncode == 0:
            return UsbEnforcementResult(
                True,
                "Blocked - device safely ejected",
                f"Windows ejected {device.device_id}; remove the USB device before reconnecting it.",
            )

        error = (completed.stderr or completed.stdout).strip()
        return UsbEnforcementResult(
            False,
            "Block failed - drive remains monitored",
            error or f"Windows returned exit code {completed.returncode}",
        )

    def wipe_and_block(self, drive_path: str) -> UsbEnforcementResult:
        import re
        if not re.match(r"^[D-Z]:\\?$", drive_path, re.IGNORECASE):
            return UsbEnforcementResult(False, "Wipe failed", "Invalid drive letter.")
        
        try:
            completed = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    self.POWERSHELL_WIPE_COMMAND,
                    drive_path,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return UsbEnforcementResult(
                False,
                "Wipe and Block failed",
                f"Windows USB enforcement could not run: {exc}",
            )

        if completed.returncode == 0:
            return UsbEnforcementResult(
                True,
                "Wiped and Blocked - device safely ejected",
                f"Windows wiped and ejected {drive_path}; remove the USB device before reconnecting it.",
            )

        error = (completed.stderr or completed.stdout).strip()
        return UsbEnforcementResult(
            False,
            "Wipe and Block failed - drive remains monitored",
            error or f"Windows returned exit code {completed.returncode}",
        )
