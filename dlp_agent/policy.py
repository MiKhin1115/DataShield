from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from .sensitive_scanner import SensitiveFinding


SEVERITY_WEIGHTS = {
    "low": 6,
    "medium": 15,
    "high": 28,
    "critical": 55,
}


@dataclass(frozen=True)
class PolicyAssessment:
    file_classification: str
    risk_score: int
    policy_decision: str
    policy_reasons: list[str]
    matched_policy_ids: list[str] = field(default_factory=list)
    matched_policy_names: list[str] = field(default_factory=list)
    notify_soc: bool = False


class PolicyEngine:
    """Turn scanner findings into an explainable DLP decision."""

    def __init__(
        self,
        policy_loader: Callable[[], list[dict[str, object]]] | None = None,
    ) -> None:
        self.policy_loader = policy_loader

    def assess(
        self,
        findings: Iterable[SensitiveFinding],
        scan_error: str | None = None,
        context: dict[str, object] | None = None,
    ) -> PolicyAssessment:
        finding_list = list(findings)
        risk_score = self._risk_score(finding_list, scan_error)
        classification = self._classification(finding_list, risk_score, scan_error)
        decision = self._decision(classification)
        reasons = self._reasons(finding_list, scan_error)
        matched = self._matching_policies(
            finding_list,
            {
                **(context or {}),
                "file_classification": classification,
                "risk_score": risk_score,
            },
        )
        if matched:
            for policy in matched:
                override = policy.get("risk_score_override")
                if override not in {None, ""}:
                    risk_score = max(risk_score, int(override))
            winning_policy = matched[0]
            decision = str(winning_policy.get("action", decision))
            reasons.append(f"Matched policy: {winning_policy.get('name')}")
        notify_soc = (
            bool(matched[0].get("notify_soc", decision != "Allow"))
            if matched
            else decision != "Allow"
        )

        return PolicyAssessment(
            file_classification=classification,
            risk_score=risk_score,
            policy_decision=decision,
            policy_reasons=reasons,
            matched_policy_ids=[str(item.get("policy_id", "")) for item in matched],
            matched_policy_names=[str(item.get("name", "")) for item in matched],
            notify_soc=notify_soc,
        )

    def _matching_policies(
        self,
        findings: list[SensitiveFinding],
        context: dict[str, object],
    ) -> list[dict[str, object]]:
        if self.policy_loader is None:
            return []
        sensitive_counts: dict[str, int] = {}
        for finding in findings:
            sensitive_counts[finding.kind] = sensitive_counts.get(finding.kind, 0) + 1
        context = {
            **context,
            "sensitive_counts": sensitive_counts,
            "sensitive_data_type": list(sensitive_counts),
        }
        policies = [item for item in self.policy_loader() if item.get("enabled", True)]
        matches = [
            item
            for item in policies
            if all(self._condition_matches(condition, context) for condition in item.get("conditions", []))
        ]
        return sorted(matches, key=lambda item: int(item.get("priority", 100)))

    @staticmethod
    def _condition_matches(condition: object, context: dict[str, object]) -> bool:
        if not isinstance(condition, dict):
            return False
        field_name = str(condition.get("field", ""))
        operator = str(condition.get("operator", "equals"))
        expected = condition.get("value")
        if field_name == "sensitive_data_count":
            counts = context.get("sensitive_counts", {})
            data_type = str(condition.get("data_type", ""))
            actual = counts.get(data_type, 0) if isinstance(counts, dict) else 0
        else:
            actual = context.get(field_name)
        return PolicyEngine._compare(actual, expected, operator)

    @staticmethod
    def _compare(actual: object, expected: object, operator: str) -> bool:
        if operator == "contains":
            if isinstance(actual, list):
                return str(expected).casefold() in {str(item).casefold() for item in actual}
            return str(expected).casefold() in str(actual or "").casefold()
        if operator in {"equals", "not_equals"}:
            if isinstance(actual, bool):
                expected_value: object = str(expected).casefold() in {"true", "1", "yes", "authorized"}
            else:
                expected_value = expected
            equal = str(actual).casefold() == str(expected_value).casefold()
            return equal if operator == "equals" else not equal
        try:
            left = float(actual)  # type: ignore[arg-type]
            right = float(expected)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            left = str(actual or "")
            right = str(expected or "")
        if operator == "greater_than":
            return left > right
        if operator == "greater_or_equal":
            return left >= right
        if operator == "less_than":
            return left < right
        if operator == "less_or_equal":
            return left <= right
        return False

    @staticmethod
    def _risk_score(
        findings: list[SensitiveFinding], scan_error: str | None
    ) -> int:
        score = sum(SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings)

        unique_kinds = len({finding.kind for finding in findings})
        if unique_kinds > 1:
            score += min(12, (unique_kinds - 1) * 3)
        if len(findings) > 1:
            score += min(10, len(findings) - 1)
        if scan_error:
            score = max(score, 40)

        return min(100, score)

    @staticmethod
    def _classification(
        findings: list[SensitiveFinding],
        risk_score: int,
        scan_error: str | None,
    ) -> str:
        severities = {finding.severity for finding in findings}
        if "critical" in severities or risk_score >= 75:
            return "Restricted"
        if "high" in severities or risk_score >= 35 or scan_error:
            return "Confidential"
        if findings:
            return "Internal"
        return "Public"

    @staticmethod
    def _decision(classification: str) -> str:
        if classification == "Restricted":
            return "Block"
        if classification in {"Internal", "Confidential"}:
            return "Alert"
        return "Allow"

    @staticmethod
    def _reasons(
        findings: list[SensitiveFinding], scan_error: str | None
    ) -> list[str]:
        reasons: list[str] = []
        if findings:
            counts: dict[str, int] = {}
            for finding in findings:
                counts[finding.kind] = counts.get(finding.kind, 0) + 1
            details = ", ".join(
                f"{kind} ({count})" for kind, count in sorted(counts.items())
            )
            reasons.append(f"Sensitive data detected: {details}")
        else:
            reasons.append("No sensitive data detected")
        if any(finding.severity == "critical" for finding in findings):
            reasons.append("Critical secret or credential detected")
        if scan_error:
            reasons.append("File could not be scanned completely")
        return reasons
