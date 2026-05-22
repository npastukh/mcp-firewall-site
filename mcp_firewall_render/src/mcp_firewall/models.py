from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class MCPEvent:
    timestamp: datetime
    session_id: str
    client_id: str
    server_id: str
    transport_type: str
    jsonrpc_method: str
    tool_name: str | None = None
    resource_name: str | None = None
    prompt_name: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    payload_size: int = 0
    response_size: int = 0
    response_time_ms: int = 0
    is_error: bool = False
    error_code: int | None = None
    label: str | None = None
    scenario_type: str | None = None


@dataclass(slots=True)
class SessionState:
    session_id: str
    total_calls: int = 0
    failed_calls: int = 0
    tools_called: list[str] = field(default_factory=list)
    last_tool_name: str | None = None
    sensitive_hits: int = 0


@dataclass(slots=True)
class RuleMatch:
    name: str
    severity: str
    reason: str


@dataclass(slots=True)
class PrivacyEntitySpan:
    label: str
    text: str
    score: float
    start_token: int
    end_token: int


@dataclass(slots=True)
class PrivacyAssessment:
    context_text: str
    max_confidence: float
    detected_labels: tuple[str, ...]
    entity_count: int
    sensitive_entity_count: int
    spans: list[PrivacyEntitySpan] = field(default_factory=list)


@dataclass(slots=True)
class SupervisedAssessment:
    model_name: str
    predicted_label: str
    predicted_class_id: int
    probabilities: dict[str, float] = field(default_factory=dict)
    risk_score: float = 0.0


@dataclass(slots=True)
class AnalysisResult:
    risk_score: float
    decision: str
    rule_matches: list[RuleMatch]
    features: dict[str, float | int | str | bool]
    rationale: str
    supervised_assessment: SupervisedAssessment | None = None
    privacy_assessment: PrivacyAssessment | None = None
