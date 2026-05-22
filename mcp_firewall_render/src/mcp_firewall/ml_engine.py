from __future__ import annotations

from mcp_firewall.models import SessionState


class HeuristicRiskModel:
    """Temporary stand-in for a trained ML model."""

    def score(self, features: dict[str, float | int | str | bool], state: SessionState) -> float:
        score = 0.05

        if bool(features["sensitive_path_flag"]):
            score += 0.45
        if bool(features["private_ip_flag"]):
            score += 0.35
        if bool(features["sensitive_keyword_flag"]):
            score += 0.20
        if bool(features.get("dangerous_command_flag", False)):
            score += 0.35
        if bool(features.get("excessive_scope_flag", False)):
            score += 0.15
        if bool(features.get("inline_secret_flag", False)):
            score += 0.15
        if bool(features.get("exfiltration_flag", False)):
            score += 0.30
        if bool(features["repeated_tool_flag"]):
            score += 0.05
        if int(features["failed_calls_last_session"]) >= 2:
            score += 0.10
        if int(features["payload_size"]) > 8_000:
            score += 0.10
        if int(features["response_time_ms"]) > 2_000:
            score += 0.10
        if state.sensitive_hits >= 1:
            score += 0.10
        if bool(features.get("full_context_sensitive_flag", False)):
            score += 0.30
        if bool(features.get("full_context_high_risk_flag", False)):
            score += 0.20
        if float(features.get("full_context_max_confidence", 0.0)) >= 0.85:
            score += 0.10

        return min(score, 1.0)
