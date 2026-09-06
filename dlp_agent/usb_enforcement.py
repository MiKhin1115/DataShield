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

    def block_drive(self, drive_path: str) -> UsbEnforcementResult:
        ...

    def block_transfer(self, drive_path: str, file_path: str) -> UsbEnforcementResult:
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
        "if ($drive -notmatch '^[D-Z]:$') { Write-Error 'Invalid removable-drive letter'; exit 4 }; "
        "$logicalDisk = Get-CimInstance Win32_LogicalDisk -Filter (\"DeviceID='\" + $drive + \"'\") -ErrorAction Stop; "
        "if ($null -eq $logicalDisk -or [int]$logicalDisk.DriveType -ne 2) { "
        "  Write-Error 'Target is not a removable drive'; exit 6 "
        "}; "
        "$root = [IO.Path]::GetFullPath($drive + '\\'); "
        "if ($root -ne ($drive + '\\')) { Write-Error 'Invalid removable-drive root'; exit 4 }; "
        "if (-not (Test-Path -LiteralPath $root -PathType Container)) { Write-Error 'USB drive was not found'; exit 2 }; "
        "$items = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop); "
        "foreach ($entry in $items) { Remove-Item -LiteralPath $entry.FullName -Recurse -Force -ErrorAction Stop }; "
        "$remaining = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop); "
        "if ($remaining.Count -ne 0) { Write-Error 'USB cleanup verification failed'; exit 7 }; "
        "$shell = New-Object -ComObject Shell.Application; "
        "$item = $shell.Namespace(17).ParseName($drive); "
        "if ($null -eq $item) { Write-Error 'USB drive was not found'; exit 2 }; "
        "$item.InvokeVerb('Eject'); "
        "Start-Sleep -Milliseconds 1200; "
        "if (Test-Path ($drive + '\\')) { Write-Error 'Windows did not eject the USB drive'; exit 3 } "
        "}"
    )

    POWERSHELL_BLOCK_TRANSFER_COMMAND = (
        "& { param([string]$targetDrive, [string]$targetFile) "
        "$drive = $targetDrive.TrimEnd('\\'); "
        "if ($drive -notmatch '^[D-Z]:$') { Write-Error 'Invalid removable-drive letter'; exit 4 }; "
        "if (-not [string]::IsNullOrWhiteSpace($targetFile)) { "
        "  $root = [IO.Path]::GetFullPath($drive + '\\'); "
        "  $file = [IO.Path]::GetFullPath($targetFile); "
        "  if (-not $file.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { "
        "    Write-Error 'Incident file is outside the removable drive'; exit 5 "
        "  }; "
        "  if (Test-Path -LiteralPath $file -PathType Leaf) { "
        "    Remove-Item -LiteralPath $file -Force -ErrorAction Stop "
        "  } "
        "}; "
        "$shell = New-Object -ComObject Shell.Application; "
        "$item = $shell.Namespace(17).ParseName($drive); "
        "if ($null -eq $item) { Write-Error 'USB drive was not found'; exit 2 }; "
        "$item.InvokeVerb('Eject'); "
        "Start-Sleep -Milliseconds 1200; "
        "if (Test-Path ($drive + '\\')) { Write-Error 'Windows did not eject the USB drive'; exit 3 } "
        "}"
    )

    def block(self, device: UsbDevice) -> UsbEnforcementResult:
        return self.block_drive(device.drive or device.device_id)

    def block_drive(self, drive_path: str) -> UsbEnforcementResult:
        import re

        if not re.match(r"^[D-Z]:\\?$", drive_path, re.IGNORECASE):
            return UsbEnforcementResult(False, "Block failed", "Invalid removable-drive letter.")

        try:
            completed = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    self.POWERSHELL_COMMAND,
                    drive_path,
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
                f"Windows ejected {drive_path}; remove the USB device before reconnecting it.",
            )

        error = (completed.stderr or completed.stdout).strip()
        return UsbEnforcementResult(
            False,
            "Block failed - drive remains monitored",
            error or f"Windows returned exit code {completed.returncode}",
        )

    def block_transfer(self, drive_path: str, file_path: str) -> UsbEnforcementResult:
        import re

        if not re.match(r"^[D-Z]:\\?$", drive_path, re.IGNORECASE):
            return UsbEnforcementResult(False, "Block failed", "Invalid removable-drive letter.")

        try:
            completed = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    self.POWERSHELL_BLOCK_TRANSFER_COMMAND,
                    drive_path,
                    file_path,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
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
                "Blocked - transfer revoked and device safely ejected",
                f"Windows removed the incident file when present and ejected {drive_path}.",
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
                timeout=60,
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
                f"Windows deleted all files from {drive_path}, verified the drive was empty, and safely ejected it.",
            )

        error = (completed.stderr or completed.stdout).strip()
        return UsbEnforcementResult(
            False,
            "Wipe and Block failed - drive remains monitored",
            error or f"Windows returned exit code {completed.returncode}",
        )
