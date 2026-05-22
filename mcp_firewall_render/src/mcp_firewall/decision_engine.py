from __future__ import annotations

from mcp_firewall.config import FirewallConfig
from mcp_firewall.models import AnalysisResult, PrivacyAssessment, RuleMatch, SupervisedAssessment


class DecisionEngine:
    def __init__(self, config: FirewallConfig) -> None:
        self._config = config

    def decide(
        self,
        risk_score: float,
        rule_matches: list[RuleMatch],
        features: dict[str, float | int | str | bool],
        supervised_assessment: SupervisedAssessment | None = None,
        privacy_assessment: PrivacyAssessment | None = None,
    ) -> AnalysisResult:
        block_reasons = [match for match in rule_matches if match.severity == "block"]
        warn_reasons = [match for match in rule_matches if match.severity == "warn"]

        if block_reasons:
            rationale = "; ".join(match.reason for match in block_reasons)
            return AnalysisResult(
                risk_score=risk_score,
                decision="block",
                rule_matches=rule_matches,
                features=features,
                rationale=rationale,
                supervised_assessment=supervised_assessment,
                privacy_assessment=privacy_assessment,
            )

        if supervised_assessment is not None:
            if supervised_assessment.predicted_label == "malicious":
                confidence = supervised_assessment.probabilities.get("malicious", 0.0)
                return AnalysisResult(
                    risk_score=risk_score,
                    decision="block",
                    rule_matches=rule_matches,
                    features=features,
                    rationale=(
                        f"{supervised_assessment.model_name} predicted malicious "
                        f"(p={confidence:.3f})."
                    ),
                    supervised_assessment=supervised_assessment,
                    privacy_assessment=privacy_assessment,
                )

            if warn_reasons:
                reasons = "; ".join(match.reason for match in warn_reasons)
                return AnalysisResult(
                    risk_score=risk_score,
                    decision="warn",
                    rule_matches=rule_matches,
                    features=features,
                    rationale=reasons,
                    supervised_assessment=supervised_assessment,
                    privacy_assessment=privacy_assessment,
                )

            if supervised_assessment.predicted_label == "anomalous":
                confidence = supervised_assessment.probabilities.get("anomalous", 0.0)
                return AnalysisResult(
                    risk_score=risk_score,
                    decision="warn",
                    rule_matches=rule_matches,
                    features=features,
                    rationale=(
                        f"{supervised_assessment.model_name} predicted anomalous "
                        f"(p={confidence:.3f})."
                    ),
                    supervised_assessment=supervised_assessment,
                    privacy_assessment=privacy_assessment,
                )

            return AnalysisResult(
                risk_score=risk_score,
                decision="allow",
                rule_matches=rule_matches,
                features=features,
                rationale=(
                    f"{supervised_assessment.model_name} predicted normal and "
                    "rule-based escalation was not required."
                ),
                supervised_assessment=supervised_assessment,
                privacy_assessment=privacy_assessment,
            )

        if risk_score >= self._config.block_risk_threshold:
            return AnalysisResult(
                risk_score=risk_score,
                decision="block",
                rule_matches=rule_matches,
                features=features,
                rationale="ML risk score exceeded block threshold.",
                supervised_assessment=supervised_assessment,
                privacy_assessment=privacy_assessment,
            )

        if warn_reasons or risk_score >= self._config.warn_risk_threshold:
            reasons = "; ".join(match.reason for match in warn_reasons) or "ML risk score exceeded warn threshold."
            return AnalysisResult(
                risk_score=risk_score,
                decision="warn",
                rule_matches=rule_matches,
                features=features,
                rationale=reasons,
                supervised_assessment=supervised_assessment,
                privacy_assessment=privacy_assessment,
            )

        return AnalysisResult(
            risk_score=risk_score,
            decision="allow",
            rule_matches=rule_matches,
            features=features,
            rationale="No blocking rules matched and risk score is within safe range.",
            supervised_assessment=supervised_assessment,
            privacy_assessment=privacy_assessment,
        )
