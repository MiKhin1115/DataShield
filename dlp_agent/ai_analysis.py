from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from .incident_store import IncidentStore


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_OPENROUTER_MODEL = "openai/gpt-oss-20b"
PROMPT_VERSION = "incident-analysis-v1"
DOTENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CLASSIFICATIONS = {"Public", "Internal", "Confidential", "Restricted"}
ACTIONS = {"Allow", "Alert", "Block"}
PRIORITIES = {"Immediate", "High", "Medium", "Low"}


class AiAnalysisError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def load_dotenv(path: Path = Path(".env")) -> set[str]:
    """Load simple KEY=VALUE entries without overriding process environment values."""
    if not path.is_file():
        return set()
    loaded: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return loaded
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not DOTENV_KEY.fullmatch(key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if key not in os.environ:
            os.environ[key] = value
            loaded.add(key)
    return loaded


@dataclass(frozen=True)
class OpenRouterConfig:
    api_key: str
    model: str = DEFAULT_OPENROUTER_MODEL
    timeout_seconds: float = 25.0

    @property
    def configured(self) -> bool:
        return bool(self.api_key.strip())

    @classmethod
    def from_environment(cls) -> "OpenRouterConfig":
        timeout_text = os.environ.get("OPENROUTER_TIMEOUT_SECONDS", "25")
        try:
            timeout = max(5.0, min(60.0, float(timeout_text)))
        except ValueError:
            timeout = 25.0
        return cls(
            api_key=os.environ.get("OPENROUTER_API_KEY", "").strip(),
            model=os.environ.get("OPENROUTER_MODEL", DEFAULT_OPENROUTER_MODEL).strip()
            or DEFAULT_OPENROUTER_MODEL,
            timeout_seconds=timeout,
        )


ANALYSIS_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string", "minLength": 1, "maxLength": 1200},
        "risk_explanation": {
            "type": "array",
            "minItems": 1,
            "maxItems": 6,
            "items": {"type": "string", "minLength": 1, "maxLength": 500},
        },
        "recommendations": {
            "type": "array",
            "minItems": 1,
            "maxItems": 6,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "priority": {"type": "string", "enum": sorted(PRIORITIES)},
                    "action": {"type": "string", "minLength": 1, "maxLength": 300},
                    "rationale": {"type": "string", "minLength": 1, "maxLength": 500},
                },
                "required": ["priority", "action", "rationale"],
            },
        },
        "investigation_questions": {
            "type": "array",
            "minItems": 1,
            "maxItems": 6,
            "items": {"type": "string", "minLength": 1, "maxLength": 400},
        },
    },
    "required": [
        "summary",
        "risk_explanation",
        "recommendations",
        "investigation_questions",
    ],
}


SYSTEM_PROMPT = """You are a security operations analyst assisting with a USB data-loss-prevention incident.
Use only the supplied category-level metadata. Do not assume identities, motives, file contents, approvals, or facts that are not present.
The official classification, risk score, severity, and policy action were calculated deterministically and must not be changed or recalculated.
Explain the existing risk, recommend investigation steps, and ask focused questions. Recommendations are advisory and must require human review.
Never request passwords, API keys, access tokens, full account numbers, raw evidence, or other secret values."""


class OpenRouterClient:
    def __init__(
        self,
        config: OpenRouterConfig,
        sender: Callable[[dict[str, object]], dict[str, object]] | None = None,
    ) -> None:
        self.config = config
        self._sender = sender or self._http_send

    def analyze(self, metadata: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
        if not self.config.configured:
            raise AiAnalysisError(
                "not_configured",
                "OpenRouter is not configured. Add OPENROUTER_API_KEY to .env and restart the dashboard.",
            )
        request_body = self.request_body(metadata)
        response = self._sender(request_body)
        content = self._response_content(response)
        result = validate_analysis_output(content)
        usage = response.get("usage", {})
        safe_usage = {
            key: int(value)
            for key, value in (usage.items() if isinstance(usage, dict) else [])
            if key in {"prompt_tokens", "completion_tokens", "total_tokens"}
            and isinstance(value, (int, float))
        }
        return result, {
            "model_used": str(response.get("model", self.config.model)),
            "usage": safe_usage,
            "generation_id": str(response.get("id", "")),
        }

    def request_body(self, metadata: dict[str, object]) -> dict[str, object]:
        return {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(metadata, sort_keys=True, ensure_ascii=True),
                },
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "usb_dlp_incident_analysis",
                    "strict": True,
                    "schema": ANALYSIS_SCHEMA,
                },
            },
            "provider": {
                "zdr": True,
                "data_collection": "deny",
                "require_parameters": True,
                "allow_fallbacks": True,
            },
            "reasoning": {"effort": "low", "exclude": True},
            "max_tokens": 2200,
            "stream": False,
        }

    def _http_send(self, body: dict[str, object]) -> dict[str, object]:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = Request(
            OPENROUTER_URL,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-OpenRouter-Title": "Intelligent USB DLP Platform",
            },
        )
        for attempt in range(2):
            try:
                with urlopen(request, timeout=self.config.timeout_seconds) as response:
                    data = response.read(2_000_001)
                if len(data) > 2_000_000:
                    raise AiAnalysisError("invalid_response", "OpenRouter response was too large")
                value = json.loads(data.decode("utf-8"))
                if not isinstance(value, dict):
                    raise AiAnalysisError("invalid_response", "OpenRouter returned an invalid response")
                return value
            except HTTPError as exc:
                if exc.code == 401:
                    raise AiAnalysisError("authentication_failed", "OpenRouter rejected the API key") from exc
                if exc.code == 429 and attempt == 0:
                    time.sleep(1)
                    continue
                if 500 <= exc.code < 600 and attempt == 0:
                    time.sleep(1)
                    continue
                code, message = self._http_error_details(exc)
                raise AiAnalysisError(code, message) from exc
            except (TimeoutError, socket.timeout) as exc:
                raise AiAnalysisError("timeout", "OpenRouter request timed out") from exc
            except URLError as exc:
                raise AiAnalysisError("network_error", "OpenRouter could not be reached") from exc
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AiAnalysisError("invalid_response", "OpenRouter returned invalid JSON") from exc
        raise AiAnalysisError("provider_error", "OpenRouter request failed")

    def _http_error_details(self, error: HTTPError) -> tuple[str, str]:
        provider_message = ""
        try:
            body = error.read(65_537)
            if len(body) <= 65_536:
                value = json.loads(body.decode("utf-8"))
                error_value = value.get("error", {}) if isinstance(value, dict) else {}
                if isinstance(error_value, dict):
                    provider_message = str(error_value.get("message", ""))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            pass

        if "zero data retention" in provider_message.casefold():
            return (
                "privacy_route_unavailable",
                f"No OpenRouter endpoint for {self.config.model} matches the required Zero Data Retention policy. Choose a ZDR-compatible model or review OpenRouter privacy settings.",
            )
        messages = {
            400: ("invalid_request", "OpenRouter rejected the analysis request parameters"),
            402: ("insufficient_credits", "The OpenRouter account has insufficient credits"),
            403: ("permission_denied", "The OpenRouter API key does not permit this request"),
            404: ("model_unavailable", f"The OpenRouter model {self.config.model} is unavailable"),
            408: ("timeout", "OpenRouter request timed out"),
            429: ("rate_limited", "OpenRouter rate limit reached"),
            502: ("provider_unavailable", "The selected OpenRouter model provider is unavailable"),
            503: ("route_unavailable", "No OpenRouter provider currently matches the required routing policy"),
        }
        return messages.get(error.code, ("provider_error", "OpenRouter request failed"))

    @staticmethod
    def _response_content(response: dict[str, object]) -> object:
        error = response.get("error")
        if isinstance(error, dict):
            code = int(error.get("code", 0) or 0)
            message = str(error.get("message", "")).casefold()
            if "zero data retention" in message:
                raise AiAnalysisError(
                    "privacy_route_unavailable",
                    "No OpenRouter endpoint matches the required Zero Data Retention policy.",
                )
            if code == 402:
                raise AiAnalysisError("insufficient_credits", "The OpenRouter account has insufficient credits")
            raise AiAnalysisError("provider_error", "OpenRouter could not complete the analysis")
        choices = response.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise AiAnalysisError("invalid_response", "OpenRouter response did not include an analysis")
        message = choices[0].get("message")
        if not isinstance(message, dict):
            raise AiAnalysisError("invalid_response", "OpenRouter response did not include an analysis")
        content = message.get("content")
        if isinstance(content, list):
            content = "".join(
                str(item.get("text", ""))
                for item in content
                if isinstance(item, dict) and item.get("type") == "text"
            )
        if not isinstance(content, str):
            if choices[0].get("finish_reason") == "length":
                raise AiAnalysisError(
                    "output_limit",
                    "The AI used its output allowance before producing the analysis. Try again.",
                )
            raise AiAnalysisError("invalid_response", "OpenRouter analysis was not JSON text")
        if not content.strip():
            raise AiAnalysisError(
                "empty_response",
                "OpenRouter returned an empty analysis. Try again.",
            )
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise AiAnalysisError("invalid_response", "OpenRouter analysis did not contain valid JSON") from exc


class AiAnalysisStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def append(self, analysis: dict[str, object]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(analysis, ensure_ascii=False) + "\n")

    def list_for_incident(self, incident_id: str, limit: int = 20) -> list[dict[str, object]]:
        if not self.path.is_file():
            return []
        values: list[dict[str, object]] = []
        with self._lock, self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict) and value.get("incident_id") == incident_id:
                    values.append(value)
        return list(reversed(values[-max(1, limit) :]))

    def cached(
        self, incident_id: str, fingerprint: str, model: str
    ) -> dict[str, object] | None:
        return next(
            (
                item
                for item in self.list_for_incident(incident_id)
                if item.get("input_fingerprint") == fingerprint
                and item.get("model_requested") == model
                and item.get("prompt_version") == PROMPT_VERSION
            ),
            None,
        )


class AiAnalysisService:
    def __init__(
        self,
        incident_store: IncidentStore,
        analysis_store: AiAnalysisStore,
        client: OpenRouterClient,
    ) -> None:
        self.incident_store = incident_store
        self.analysis_store = analysis_store
        self.client = client
        self._lock = threading.Lock()

    def status(self) -> dict[str, object]:
        return {
            "configured": self.client.config.configured,
            "model": self.client.config.model,
            "privacy": "Metadata only; Zero Data Retention required; provider data collection denied",
        }

    def list_for_incident(self, incident_id: str) -> list[dict[str, object]]:
        if self.incident_store.get(incident_id) is None:
            raise LookupError("Incident not found")
        return self.analysis_store.list_for_incident(incident_id)

    def generate(
        self, incident_id: str, actor: str, force: bool = False
    ) -> tuple[dict[str, object], bool]:
        with self._lock:
            incident = self.incident_store.get(incident_id)
            if incident is None:
                raise LookupError("Incident not found")
            metadata = build_ai_metadata(incident, self.incident_store.read_all())
            fingerprint = hashlib.sha256(
                json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if not force:
                cached = self.analysis_store.cached(
                    incident_id, fingerprint, self.client.config.model
                )
                if cached is not None:
                    return cached, True

            result, provider_metadata = self.client.analyze(metadata)
            analysis = {
                "analysis_id": f"AI-{uuid4().hex[:12].upper()}",
                "incident_id": incident_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generated_by": actor,
                "prompt_version": PROMPT_VERSION,
                "input_fingerprint": fingerprint,
                "input_metadata": metadata,
                "model_requested": self.client.config.model,
                **provider_metadata,
                "official_risk_score": int(incident.get("risk_score", 0) or 0),
                "official_risk_level": IncidentStore.risk_level(
                    int(incident.get("risk_score", 0) or 0)
                ),
                "official_classification": str(incident.get("file_classification", "Public")),
                "official_action": str(incident.get("policy_decision", "Allow")),
                **result,
            }
            self.analysis_store.append(analysis)
            timeline = incident.get("timeline", [])
            timeline = list(timeline) if isinstance(timeline, list) else []
            timeline.append(
                {
                    "event_time": str(analysis["generated_at"]),
                    "event_type": "ai_analysis_generated",
                    "title": "AI incident analysis generated",
                    "details": f"{analysis['analysis_id']} by {actor}; Model: {analysis['model_used']}",
                }
            )
            self.incident_store.update(incident_id, {"timeline": timeline})
            return analysis, False


def build_ai_metadata(
    incident: dict[str, object], incidents: list[dict[str, object]]
) -> dict[str, object]:
    findings = incident.get("sensitive_findings", [])
    safe_findings = [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []
    counts = Counter(str(item.get("kind", "unknown")) for item in safe_findings)
    severities = Counter(str(item.get("severity", "unknown")) for item in safe_findings)
    incident_id = incident.get("incident_id")
    same_user = [
        item
        for item in incidents
        if item.get("incident_id") != incident_id
        and item.get("user_name") == incident.get("user_name")
    ]
    same_device = [
        item
        for item in incidents
        if item.get("incident_id") != incident_id
        and item.get("device_id") == incident.get("device_id")
    ]
    score = max(0, min(100, int(incident.get("risk_score", 0) or 0)))
    classification = str(incident.get("file_classification", "Public"))
    if classification not in CLASSIFICATIONS:
        classification = "Public"
    action = str(incident.get("policy_decision", "Allow"))
    if action not in ACTIONS:
        action = "Allow"
    usb_status = str(incident.get("usb_authorization_status", "unknown")).lower()
    if usb_status not in {"authorized", "unauthorized", "personal", "blocked"}:
        usb_status = "unknown"

    risk_factors = [f"Official classification is {classification}"]
    if usb_status != "authorized":
        risk_factors.append(f"USB authorization status is {usb_status}")
    if safe_findings:
        risk_factors.append(f"{len(safe_findings)} sensitive-data findings were detected")
    if severities.get("critical", 0):
        risk_factors.append("Critical credential or secret categories were detected")
    duplicate_count = max(0, int(incident.get("duplicate_incident_count", 0) or 0))
    if duplicate_count:
        risk_factors.append("The same file content appeared in previous incidents")
    risk_factors.append(f"The deterministic policy action is {action}")

    return {
        "schema_version": "usb-dlp-ai-metadata-v1",
        "user_department": _bounded(incident.get("department", "Unknown"), 100),
        "usb_status": usb_status,
        "file_type": _safe_file_type(incident.get("file_type", "unknown")),
        "file_size_bucket": _file_size_bucket(int(incident.get("file_size", 0) or 0)),
        "classification": classification,
        "sensitive_type_counts": dict(sorted(counts.items())),
        "sensitive_finding_count": len(safe_findings),
        "severity_counts": dict(sorted(severities.items())),
        "duplicate_file_incident_count": duplicate_count,
        "user_previous_incident_count": len(same_user),
        "user_previous_block_count": sum(
            str(item.get("policy_decision")) == "Block" for item in same_user
        ),
        "usb_previous_incident_count": len(same_device),
        "official_risk_score": score,
        "official_risk_level": IncidentStore.risk_level(score),
        "official_action": action,
        "risk_factors": risk_factors,
    }


def validate_analysis_output(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AiAnalysisError("invalid_response", "AI analysis was not an object")
    if set(value) != {
        "summary",
        "risk_explanation",
        "recommendations",
        "investigation_questions",
    }:
        raise AiAnalysisError("invalid_response", "AI analysis fields did not match the required schema")
    summary = _required_text(value.get("summary"), "summary", 1200)
    explanations = _string_list(value.get("risk_explanation"), "risk explanation", 6, 500)
    questions = _string_list(value.get("investigation_questions"), "investigation questions", 6, 400)
    recommendations_value = value.get("recommendations")
    if not isinstance(recommendations_value, list) or not 1 <= len(recommendations_value) <= 6:
        raise AiAnalysisError("invalid_response", "AI recommendations were invalid")
    recommendations: list[dict[str, str]] = []
    for item in recommendations_value:
        if not isinstance(item, dict) or set(item) != {"priority", "action", "rationale"}:
            raise AiAnalysisError("invalid_response", "An AI recommendation was invalid")
        priority = str(item.get("priority", ""))
        if priority not in PRIORITIES:
            raise AiAnalysisError("invalid_response", "An AI recommendation priority was invalid")
        recommendations.append(
            {
                "priority": priority,
                "action": _required_text(item.get("action"), "recommendation action", 300),
                "rationale": _required_text(item.get("rationale"), "recommendation rationale", 500),
            }
        )
    return {
        "summary": summary,
        "risk_explanation": explanations,
        "recommendations": recommendations,
        "investigation_questions": questions,
    }


def _required_text(value: object, label: str, maximum: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum:
        raise AiAnalysisError("invalid_response", f"AI {label} was invalid")
    return text


def _string_list(value: object, label: str, maximum_items: int, maximum_length: int) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum_items:
        raise AiAnalysisError("invalid_response", f"AI {label} were invalid")
    return [_required_text(item, label, maximum_length) for item in value]


def _safe_file_type(value: object) -> str:
    text = str(value or "unknown").lower().strip()
    return text if re.fullmatch(r"\.?[a-z0-9]{1,12}", text) else "unknown"


def _file_size_bucket(size: int) -> str:
    if size < 100_000:
        return "under 100 KB"
    if size < 1_000_000:
        return "100 KB to 1 MB"
    if size < 10_000_000:
        return "1 MB to 10 MB"
    return "10 MB or larger"


def _bounded(value: object, maximum: int) -> str:
    text = str(value or "Unknown").strip()
    return text[:maximum] or "Unknown"
