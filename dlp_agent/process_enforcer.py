from __future__ import annotations

from dataclasses import dataclass

import psutil


@dataclass(frozen=True)
class ProcessActionResult:
    success: bool
    state: str
    message: str


def _verified_process(
    pid: int,
    expected_name: str,
    expected_create_time: float | None,
) -> psutil.Process:
    if pid <= 0:
        raise ValueError("Invalid process ID")
    if expected_create_time is None:
        raise ValueError("Process identity metadata is missing")

    process = psutil.Process(pid)
    if expected_name and process.name().casefold() != expected_name.casefold():
        raise ValueError("Process name no longer matches the incident")
    if abs(process.create_time() - expected_create_time) > 0.01:
        raise ValueError("Process ID has been reused")
    return process


def suspend_process(
    pid: int,
    expected_name: str,
    expected_create_time: float | None,
) -> ProcessActionResult:
    try:
        process = _verified_process(pid, expected_name, expected_create_time)
        process.suspend()
        return ProcessActionResult(
            True,
            "suspended",
            f"{process.name()} (PID {pid}) suspended pending SOC decision",
        )
    except psutil.NoSuchProcess:
        return ProcessActionResult(False, "exited", f"Process PID {pid} already exited")
    except (psutil.AccessDenied, ValueError) as exc:
        return ProcessActionResult(False, "suspend_failed", str(exc))


def resume_process(
    pid: int,
    expected_name: str,
    expected_create_time: float | None,
) -> ProcessActionResult:
    try:
        process = _verified_process(pid, expected_name, expected_create_time)
        process.resume()
        return ProcessActionResult(
            True,
            "resumed",
            f"{process.name()} (PID {pid}) resumed by SOC",
        )
    except psutil.NoSuchProcess:
        return ProcessActionResult(False, "exited", f"Process PID {pid} already exited")
    except (psutil.AccessDenied, ValueError) as exc:
        return ProcessActionResult(False, "resume_failed", str(exc))


def terminate_process_tree(
    pid: int,
    expected_name: str,
    expected_create_time: float | None,
    timeout_seconds: float = 2.0,
) -> ProcessActionResult:
    try:
        process = _verified_process(pid, expected_name, expected_create_time)
        targets = process.children(recursive=True) + [process]
        target_name = process.name()
        for target in targets:
            try:
                target.terminate()
            except psutil.NoSuchProcess:
                continue

        _, alive = psutil.wait_procs(targets, timeout=timeout_seconds)
        for target in alive:
            try:
                target.kill()
            except psutil.NoSuchProcess:
                continue
        _, still_alive = psutil.wait_procs(alive, timeout=timeout_seconds)
        if still_alive:
            return ProcessActionResult(
                False,
                "terminate_failed",
                f"Could not terminate every process associated with PID {pid}",
            )
        return ProcessActionResult(
            True,
            "terminated",
            f"{target_name} (PID {pid}) terminated by SOC",
        )
    except psutil.NoSuchProcess:
        return ProcessActionResult(False, "exited", f"Process PID {pid} already exited")
    except (psutil.AccessDenied, ValueError) as exc:
        return ProcessActionResult(False, "terminate_failed", str(exc))

