from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

import psutil


TRANSFER_COMMANDS = (
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "curl.exe",
    "wget.exe",
)


@dataclass
class NetworkConnectionEvent:
    process_name: str
    pid: int
    local_address: str
    remote_address: str
    remote_port: int
    status: str
    extracted_file_name: str
    extracted_file_path: str
    process_create_time: float | None = None
    command_line: str = ""


class NetworkMonitor:
    def __init__(self) -> None:
        self.monitored_processes = {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "chrome.exe",
            "msedge.exe",
            "firefox.exe",
        }
        self._last_alerted: set[str] = set()
        self._last_command_alerted: set[str] = set()

    def extract_file_context(self, proc: psutil.Process) -> tuple[str, str]:
        extracted_name = proc.name()
        extracted_path = f"PID: {proc.pid}"

        try:
            command_line = " ".join(proc.cmdline())
            match = re.search(
                r"-infile\s+(?:(['\"])(.*?)\1|([^\s'\"]+))",
                command_line,
                re.IGNORECASE,
            )
            if match:
                file_path = match.group(2) or match.group(3)
                extracted_path = file_path
                if not os.path.isabs(extracted_path):
                    try:
                        extracted_path = os.path.join(proc.cwd(), extracted_path)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                extracted_name = os.path.basename(file_path.replace("\\", "/"))
                return extracted_name, extracted_path

            for open_file in proc.open_files():
                path = open_file.path
                if (
                    any(folder in path for folder in ("synthetic_test_data", "Desktop", "Documents"))
                    and "Cache" not in path
                    and "AppData" not in path
                ):
                    return os.path.basename(path), path
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass

        return extracted_name, extracted_path

    @staticmethod
    def _transfer_target(command_line: str) -> tuple[str, int] | None:
        lower_command = command_line.casefold()
        if not any(command in lower_command for command in TRANSFER_COMMANDS):
            return None
        match = re.search(r"https?://[^\s'\"]+", command_line, re.IGNORECASE)
        if not match:
            return None
        parsed = urlparse(match.group(0).rstrip(")],;"))
        if not parsed.hostname:
            return None
        return parsed.hostname, parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

    def _command_events(self) -> tuple[list[NetworkConnectionEvent], set[int]]:
        events: list[NetworkConnectionEvent] = []
        command_pids: set[int] = set()
        current_commands: set[str] = set()
        try:
            processes = psutil.process_iter(["pid", "name", "cmdline", "create_time"])
            for proc in processes:
                try:
                    process_name = str(proc.info.get("name") or proc.name())
                    if process_name.casefold() not in {"powershell.exe", "pwsh.exe", "cmd.exe"}:
                        continue
                    command_line = " ".join(proc.info.get("cmdline") or proc.cmdline())
                    target = self._transfer_target(command_line)
                    if not target:
                        continue
                    file_name, file_path = self.extract_file_context(proc)
                    if file_path.startswith("PID:"):
                        continue
                    create_time = float(proc.info.get("create_time") or proc.create_time())
                    command_id = f"{proc.pid}-{create_time}-{file_path}-{target[0]}-{target[1]}"
                    current_commands.add(command_id)
                    command_pids.add(proc.pid)
                    if command_id in self._last_command_alerted:
                        continue
                    self._last_command_alerted.add(command_id)
                    events.append(
                        NetworkConnectionEvent(
                            process_name=process_name,
                            pid=proc.pid,
                            local_address="",
                            remote_address=target[0],
                            remote_port=target[1],
                            status="COMMAND_DETECTED",
                            extracted_file_name=file_name,
                            extracted_file_path=file_path,
                            process_create_time=create_time,
                            command_line=command_line,
                        )
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, TypeError, OSError):
                    continue
        except psutil.Error:
            pass
        self._last_command_alerted.intersection_update(current_commands)
        return events, command_pids

    def poll(self) -> Iterable[NetworkConnectionEvent]:
        command_events, command_pids = self._command_events()
        events = list(command_events)
        current_connections: set[str] = set()

        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.raddr or conn.pid in command_pids:
                    continue
                remote_ip = conn.raddr.ip
                if (
                    remote_ip.startswith("127.")
                    or remote_ip in {"::1", "0.0.0.0"}
                    or remote_ip.startswith("fe80:")
                ):
                    continue

                try:
                    proc = psutil.Process(conn.pid)
                    process_name = proc.name()
                    create_time = proc.create_time()
                except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, TypeError):
                    continue
                if process_name.casefold() not in self.monitored_processes:
                    continue

                connection_id = f"{conn.pid}-{create_time}-{remote_ip}-{conn.raddr.port}"
                current_connections.add(connection_id)
                if connection_id in self._last_alerted:
                    continue
                self._last_alerted.add(connection_id)

                file_name, file_path = self.extract_file_context(proc)
                if process_name.casefold() in {"chrome.exe", "firefox.exe", "msedge.exe"}:
                    if file_name == process_name:
                        continue

                events.append(
                    NetworkConnectionEvent(
                        process_name=process_name,
                        pid=conn.pid,
                        local_address=conn.laddr.ip,
                        remote_address=remote_ip,
                        remote_port=conn.raddr.port,
                        status=conn.status,
                        extracted_file_name=file_name,
                        extracted_file_path=file_path,
                        process_create_time=create_time,
                        command_line=" ".join(proc.cmdline()),
                    )
                )
            self._last_alerted.intersection_update(current_connections)
        except psutil.Error:
            pass
        return events
