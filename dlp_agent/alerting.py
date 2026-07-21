from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Callable
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class AlertResult:
    sent: bool
    channel: str
    error: str | None = None


class SocAlerter:
    """Send risky incident notifications to the console and an optional webhook."""

    def __init__(
        self,
        webhook_url: str | None = None,
        webhook_sender: Callable[[Request, float], object] | None = None,
    ) -> None:
        self.webhook_url = webhook_url
        self._webhook_sender = webhook_sender or self._send_request

    def notify(self, incident: dict[str, object]) -> list[AlertResult]:
        if not incident.get("notify_soc", incident.get("policy_decision") != "Allow"):
            return []

        message = self._message(incident)
        print(f"[SOC ALERT] {message}", file=sys.stderr)
        results = [AlertResult(sent=True, channel="console")]

        if self.webhook_url:
            payload = {
                "text": message,
                "incident": incident,
            }
            request = Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                self._webhook_sender(request, 5.0)
                results.append(AlertResult(sent=True, channel="webhook"))
            except Exception as exc:
                print(f"[SOC ALERT DELIVERY FAILED] {exc}", file=sys.stderr)
                results.append(AlertResult(sent=False, channel="webhook", error=str(exc)))
        return results

    @staticmethod
    def _send_request(request: Request, timeout: float) -> object:
        return urlopen(request, timeout=timeout)

    @staticmethod
    def _message(incident: dict[str, object]) -> str:
        if incident.get("incident_type") == "usb_device":
            return (
                f"{incident.get('policy_decision')} | Risk {incident.get('risk_score')}/100 | "
                f"USB {incident.get('usb_authorization_status')} | {incident.get('user_name')} "
                f"inserted {incident.get('device_name')} | Action: {incident.get('action_taken')} | "
                f"Incident {incident.get('incident_id')}"
            )
        return (
            f"{incident.get('policy_decision')} | Risk {incident.get('risk_score')}/100 | "
            f"{incident.get('file_classification')} | {incident.get('user_name')} copied "
            f"{incident.get('file_name')} to {incident.get('device_name')} | "
            f"Incident {incident.get('incident_id')}"
        )
