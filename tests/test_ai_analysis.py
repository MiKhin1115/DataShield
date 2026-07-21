import json
import os
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from dlp_agent.ai_analysis import (
    AiAnalysisError,
    AiAnalysisService,
    AiAnalysisStore,
    OpenRouterClient,
    OpenRouterConfig,
    build_ai_metadata,
    load_dotenv,
    validate_analysis_output,
)
from dlp_agent.incident_store import IncidentStore


def restricted_incident() -> dict[str, object]:
    return {
        "incident_id": "DLP-AI-001",
        "event_time": "2026-07-20T10:00:00+00:00",
        "user_name": "private-user",
        "department": "Human Resources",
        "computer_name": "PRIVATE-PC",
        "device_name": "Private USB",
        "device_id": "E:",
        "usb_serial_number": "SECRET-SERIAL-123",
        "usb_authorization_status": "unauthorized",
        "file_name": "Payroll_Secret.xlsx",
        "file_path": "E:\\Payroll_Secret.xlsx",
        "file_type": ".xlsx",
        "file_size": 456_000,
        "file_hashes": {"sha256": "private-file-hash"},
        "file_classification": "Restricted",
        "risk_score": 98,
        "policy_decision": "Block",
        "duplicate_incident_count": 2,
        "sensitive_findings": [
            {"kind": "bank_account", "severity": "high", "match": "123456789012"},
            {"kind": "api_key", "severity": "critical", "match": "secret-api-value"},
        ],
        "timeline": [],
    }


def valid_analysis() -> dict[str, object]:
    return {
        "summary": "A restricted file transfer to an unauthorized USB device was blocked.",
        "risk_explanation": ["The official risk score is Critical."],
        "recommendations": [
            {
                "priority": "Immediate",
                "action": "Verify whether the transfer was approved.",
                "rationale": "The destination USB device was unauthorized.",
            }
        ],
        "investigation_questions": ["Was manager approval provided?"],
    }


def provider_response() -> dict[str, object]:
    return {
        "id": "gen-test-1",
        "model": "test/model",
        "usage": {"prompt_tokens": 100, "completion_tokens": 80, "total_tokens": 180},
        "choices": [{"message": {"content": json.dumps(valid_analysis())}}],
    }


class AiAnalysisTests(TestCase):
    def test_load_dotenv_loads_quotes_without_overriding_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                'OPENROUTER_API_KEY="from-file"\nOPENROUTER_MODEL=test/model\n',
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"OPENROUTER_API_KEY": "already-set"}, clear=False):
                os.environ.pop("OPENROUTER_MODEL", None)
                loaded = load_dotenv(path)
                self.assertEqual(os.environ["OPENROUTER_API_KEY"], "already-set")
                self.assertEqual(os.environ["OPENROUTER_MODEL"], "test/model")
                self.assertEqual(loaded, {"OPENROUTER_MODEL"})
                os.environ.pop("OPENROUTER_MODEL", None)

    def test_metadata_excludes_identifiers_paths_hashes_and_sensitive_values(self) -> None:
        incident = restricted_incident()
        metadata = build_ai_metadata(incident, [incident])
        serialized = json.dumps(metadata)

        self.assertEqual(metadata["official_risk_score"], 98)
        self.assertEqual(metadata["official_action"], "Block")
        self.assertEqual(metadata["sensitive_type_counts"], {"api_key": 1, "bank_account": 1})
        for private_value in (
            "private-user",
            "PRIVATE-PC",
            "Private USB",
            "SECRET-SERIAL-123",
            "Payroll_Secret.xlsx",
            "private-file-hash",
            "123456789012",
            "secret-api-value",
        ):
            self.assertNotIn(private_value, serialized)

    def test_openrouter_request_requires_structured_output_and_privacy_controls(self) -> None:
        captured: list[dict[str, object]] = []

        def sender(body: dict[str, object]) -> dict[str, object]:
            captured.append(body)
            return provider_response()

        client = OpenRouterClient(OpenRouterConfig("test-key", "test/model"), sender)
        metadata = build_ai_metadata(restricted_incident(), [restricted_incident()])
        result, provider = client.analyze(metadata)

        request = captured[0]
        self.assertTrue(request["response_format"]["json_schema"]["strict"])
        self.assertEqual(request["provider"]["zdr"], True)
        self.assertEqual(request["provider"]["data_collection"], "deny")
        self.assertEqual(request["provider"]["require_parameters"], True)
        self.assertEqual(request["reasoning"], {"effort": "low", "exclude": True})
        self.assertEqual(request["max_tokens"], 2200)
        self.assertNotIn("secret-api-value", request["messages"][1]["content"])
        self.assertEqual(result["summary"], valid_analysis()["summary"])
        self.assertEqual(provider["model_used"], "test/model")

    def test_service_caches_analysis_and_force_regenerates(self) -> None:
        calls = 0

        def sender(_: dict[str, object]) -> dict[str, object]:
            nonlocal calls
            calls += 1
            return provider_response()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incidents = IncidentStore(root / "incidents.jsonl")
            incidents.append(restricted_incident())
            service = AiAnalysisService(
                incidents,
                AiAnalysisStore(root / "ai_analyses.jsonl"),
                OpenRouterClient(OpenRouterConfig("test-key", "test/model"), sender),
            )

            first, first_cached = service.generate("DLP-AI-001", "soc")
            second, second_cached = service.generate("DLP-AI-001", "soc")
            third, third_cached = service.generate("DLP-AI-001", "admin", force=True)
            saved = service.list_for_incident("DLP-AI-001")
            timeline = incidents.get("DLP-AI-001")["timeline"]

        self.assertFalse(first_cached)
        self.assertTrue(second_cached)
        self.assertFalse(third_cached)
        self.assertEqual(first["analysis_id"], second["analysis_id"])
        self.assertNotEqual(first["analysis_id"], third["analysis_id"])
        self.assertEqual(calls, 2)
        self.assertEqual(len(saved), 2)
        self.assertEqual([item["event_type"] for item in timeline], ["ai_analysis_generated"] * 2)

    def test_rejects_unconfigured_client_and_invalid_output(self) -> None:
        with self.assertRaisesRegex(AiAnalysisError, "not configured"):
            OpenRouterClient(OpenRouterConfig("")).analyze({})
        invalid = valid_analysis()
        invalid["official_risk_score"] = 10
        with self.assertRaisesRegex(AiAnalysisError, "required schema"):
            validate_analysis_output(invalid)

    def test_accepts_text_block_content_and_reports_output_limit(self) -> None:
        block_response = provider_response()
        block_response["choices"][0]["message"]["content"] = [
            {"type": "text", "text": json.dumps(valid_analysis())}
        ]
        client = OpenRouterClient(
            OpenRouterConfig("test-key", "test/model"), lambda _: block_response
        )
        result, _ = client.analyze({"schema_version": "test"})
        self.assertEqual(result["summary"], valid_analysis()["summary"])

        limited_response = {
            "choices": [{"finish_reason": "length", "message": {"content": None}}]
        }
        limited = OpenRouterClient(
            OpenRouterConfig("test-key", "test/model"), lambda _: limited_response
        )
        with self.assertRaisesRegex(AiAnalysisError, "output allowance"):
            limited.analyze({"schema_version": "test"})
