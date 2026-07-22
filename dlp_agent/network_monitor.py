import os
import psutil
from dataclasses import dataclass
from typing import Iterable, Set, Tuple

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

class NetworkMonitor:
    def __init__(self):
        self.monitored_processes = {"powershell.exe", "cmd.exe", "chrome.exe", "msedge.exe", "firefox.exe"}
        self._last_alerted = set()

    def extract_file_context(self, proc: psutil.Process) -> Tuple[str, str]:
        extracted_name = proc.name()
        extracted_path = f"PID: {proc.pid}"
        
        try:
            # 1. Check command line (good for PowerShell)
            cmdline = proc.cmdline()
            full_cmd = " ".join(cmdline)
            if "-infile" in full_cmd.lower() or "<" in full_cmd:
                import re
                match = re.search(r'-infile\s+(?:([\'"])(.*?)\1|([^\s\'"]+))', full_cmd, re.IGNORECASE)
                if match:
                    file_path = match.group(2) or match.group(3)
                    extracted_path = file_path
                    if not os.path.isabs(extracted_path):
                        try:
                            extracted_path = os.path.join(proc.cwd(), extracted_path)
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                    extracted_name = os.path.basename(file_path.replace('\\', '/'))
                    return extracted_name, extracted_path
            
            # 2. Check open files (good for browsers)
            for open_file in proc.open_files():
                path = open_file.path
                if "synthetic_test_data" in path or "Desktop" in path or "Documents" in path:
                    if "Cache" not in path and "AppData" not in path:
                        extracted_path = path
                        extracted_name = os.path.basename(path)
                        return extracted_name, extracted_path
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            pass
            
        return extracted_name, extracted_path

    def poll(self) -> Iterable[NetworkConnectionEvent]:
        current_connections = set()

        try:
            for conn in psutil.net_connections(kind='inet'):
                if not conn.raddr:
                    continue
                    
                remote_ip = conn.raddr.ip
                if remote_ip.startswith("127.") or remote_ip == "::1" or remote_ip == "0.0.0.0" or remote_ip.startswith("fe80:"):
                    continue
                    
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name().lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, TypeError):
                    continue

                if proc_name in self.monitored_processes:
                    conn_id = f"{conn.pid}-{remote_ip}-{conn.raddr.port}"
                    current_connections.add(conn_id)
                    
                    if conn_id not in self._last_alerted:
                        self._last_alerted.add(conn_id)
                        
                        file_name, file_path = self.extract_file_context(proc)
                        
                        # Filter out normal browser background traffic (telemetry/sync)
                        # Only alert on browsers if we actually detected a sensitive file being read
                        if proc_name in ("chrome.exe", "firefox.exe", "msedge.exe"):
                            if file_name == proc.name():
                                continue
                        
                        yield NetworkConnectionEvent(
                            process_name=proc.name(),
                            pid=conn.pid,
                            local_address=conn.laddr.ip,
                            remote_address=remote_ip,
                            remote_port=conn.raddr.port,
                            status=conn.status,
                            extracted_file_name=file_name,
                            extracted_file_path=file_path
                        )
                        
            self._last_alerted.intersection_update(current_connections)
        except psutil.Error:
            pass
