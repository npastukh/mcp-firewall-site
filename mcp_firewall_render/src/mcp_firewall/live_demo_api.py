from __future__ import annotations

import os
import uuid
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from mcp_firewall.catboost_runtime import resolve_runtime_artifact_dir
from mcp_firewall.config import FirewallConfig
from mcp_firewall.firewall import FirewallService
from mcp_firewall.models import AnalysisResult, MCPEvent, PrivacyAssessment
from mcp_firewall.privacy_filter_runtime import HIGH_RISK_PRIVACY_LABELS, PrivacyFilterEvaluator
from mcp_firewall.prompt_interpreter import build_event_from_prompt


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1)
    client_id: str = "agent-1"
    transport_type: str = "stdio"
    session_id: str | None = None


def _cors_origins() -> list[str]:
    value = os.getenv("CORS_ORIGINS", "*").strip()
    if value == "*":
        return ["*"]
    return [item.strip() for item in value.split(",") if item.strip()]


def _allow_credentials(cors_origins: list[str]) -> bool:
    return cors_origins != ["*"]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_gliner_model_path(project_root: Path) -> Path | None:
    candidates = (
        project_root / "artifacts" / "gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1" / "best",
        project_root / "artifacts" / "gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1" / "final",
    )
    return next((path for path in candidates if path.exists()), None)


@lru_cache(maxsize=1)
def get_rules_catboost_service() -> FirewallService:
    project_root = _project_root()
    runtime_artifact_dir = resolve_runtime_artifact_dir(project_root)
    config = FirewallConfig(
        supervised_runtime_enabled=runtime_artifact_dir is not None,
        supervised_model_path=str(runtime_artifact_dir) if runtime_artifact_dir else None,
        full_context_evaluator_enabled=False,
        full_context_model_path=None,
    )
    return FirewallService(config)


def get_gliner_config() -> FirewallConfig:
    return FirewallConfig(
        supervised_runtime_enabled=False,
        full_context_evaluator_enabled=False,
        full_context_model_path=None,
    )


@lru_cache(maxsize=1)
def get_gliner_evaluator() -> PrivacyFilterEvaluator | None:
    project_root = _project_root()
    model_path = _resolve_gliner_model_path(project_root)
    if model_path is None:
        return None

    config = get_gliner_config()
    return PrivacyFilterEvaluator(
        model_path=str(model_path),
        max_length=config.full_context_max_length,
        extraction_threshold=config.full_context_extraction_threshold,
    )


def build_mcp_request(event: MCPEvent) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": "live-tools-call",
        "method": event.jsonrpc_method,
        "params": {
            "name": event.tool_name,
            "arguments": event.params,
        },
    }


def evaluate_gliner_stage(event: MCPEvent) -> dict[str, Any]:
    evaluator = get_gliner_evaluator()
    if evaluator is None:
        return {
            "status": "unavailable",
            "decision": None,
            "rationale": "GLiNER + LoRA checkpoint was not found.",
            "confidence": None,
            "labels": [],
            "spans": [],
        }

    config = get_gliner_config()
    try:
        assessment = evaluator.evaluate_event(event)
    except Exception as exc:
        return {
            "status": "unavailable",
            "decision": None,
            "rationale": str(exc),
            "confidence": None,
            "labels": [],
            "spans": [],
        }

    decision, rationale = _derive_gliner_decision(
        assessment,
        warn_threshold=config.full_context_warn_threshold,
        block_threshold=config.full_context_block_threshold,
    )
    return {
        "status": "analyzed",
        "decision": decision,
        "rationale": rationale,
        "confidence": assessment.max_confidence,
        "labels": list(assessment.detected_labels),
        "spans": [asdict(span) for span in assessment.spans],
        "assessment": asdict(assessment),
        "model_path": evaluator._model_path,  # noqa: SLF001 - returned for demo transparency.
    }


def skip_gliner_stage(reason: str) -> dict[str, Any]:
    return {
        "status": "skipped",
        "decision": None,
        "rationale": reason,
        "confidence": None,
        "labels": [],
        "spans": [],
    }


def should_run_gliner_stage(
    rules_result: AnalysisResult,
    config: FirewallConfig,
) -> tuple[bool, str]:
    if rules_result.decision == "block":
        return (
            False,
            "GLiNER + LoRA was skipped because Rules + CatBoost already produced a blocking decision.",
        )

    if rules_result.decision == "warn":
        return (
            True,
            "GLiNER + LoRA was triggered because Rules + CatBoost marked the request as suspicious.",
        )

    suspicious_feature_flags = (
        "external_url_flag",
        "private_ip_flag",
        "sensitive_keyword_flag",
        "dangerous_command_flag",
        "excessive_scope_flag",
        "inline_secret_flag",
        "exfiltration_flag",
    )
    triggered_flags = [
        flag
        for flag in suspicious_feature_flags
        if bool(rules_result.features.get(flag, False))
    ]
    if triggered_flags:
        return (
            True,
            "GLiNER + LoRA was triggered by stage-1 suspicious signals: " + ", ".join(triggered_flags),
        )

    if rules_result.risk_score >= config.warn_risk_threshold:
        return (
            True,
            "GLiNER + LoRA was triggered because the stage-1 risk score crossed the warning threshold.",
        )

    return (
        False,
        "GLiNER + LoRA was skipped because Rules + CatBoost classified the request as low-risk allow.",
    )


def _derive_gliner_decision(
    assessment: PrivacyAssessment,
    warn_threshold: float,
    block_threshold: float,
) -> tuple[str, str]:
    labels = tuple(sorted({span.label for span in assessment.spans}))
    high_risk_labels = tuple(sorted({span.label for span in assessment.spans if span.label in HIGH_RISK_PRIVACY_LABELS}))
    decision = "allow"
    rationale = "GLiNER + LoRA did not detect suspicious spans in the MCP request."

    if high_risk_labels and assessment.max_confidence >= block_threshold:
        decision = "block"
        rationale = "GLiNER + LoRA detected high-risk sensitive entities: " + ", ".join(high_risk_labels)
    elif assessment.entity_count and assessment.max_confidence >= warn_threshold:
        decision = "warn"
        rationale = "GLiNER + LoRA detected suspicious entities: " + ", ".join(labels)
    return decision, rationale


def combine_stage_decisions(rules_decision: str, gliner_result: dict[str, Any]) -> tuple[str, str]:
    gliner_decision = gliner_result.get("decision")
    if rules_decision == "block" or gliner_decision == "block":
        if rules_decision == "block":
            return "block", "Final decision follows Rules + CatBoost."
        return "block", "Final decision was escalated by GLiNER + LoRA."
    if rules_decision == "warn" or gliner_decision == "warn":
        if rules_decision == "warn":
            return "warn", "Final decision follows Rules + CatBoost."
        return "warn", "Final decision was escalated by GLiNER + LoRA."
    return "allow", "Both live stages remained in the safe zone."


_CORS_ORIGINS = _cors_origins()

app = FastAPI(title="MCP Firewall Live Demo API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=_allow_credentials(_CORS_ORIGINS),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, Any]:
    project_root = _project_root()
    return {
        "status": "ok",
        "service": "mcp-firewall-live-demo-api",
        "catboost_runtime_ready": resolve_runtime_artifact_dir(project_root) is not None,
        "gliner_checkpoint_ready": _resolve_gliner_model_path(project_root) is not None,
    }


@app.post("/api/analyze")
def analyze(payload: AnalyzeRequest) -> dict[str, Any]:
    session_id = payload.session_id or f"session-{uuid.uuid4().hex[:8]}"
    rules_service = get_rules_catboost_service()
    interpretation, event = build_event_from_prompt(
        prompt=payload.prompt,
        client_id=payload.client_id,
        transport_type=payload.transport_type,
        session_id=session_id,
        policy=rules_service._config,  # noqa: SLF001 - API reuses the configured allowlists and server map.
    )

    if event is None:
        return {
            "status": interpretation["status"],
            "session_id": session_id,
            "message": interpretation["message"],
            "interpretation": interpretation,
            "mcp_request": None,
            "rules_catboost": None,
            "gliner_lora": None,
            "final_decision": None,
            "final_rationale": "Analysis did not start because a valid MCP event could not be constructed.",
        }

    rules_result = rules_service.process_event(event)
    should_run_gliner, gliner_trigger_reason = should_run_gliner_stage(
        rules_result,
        rules_service._config,  # noqa: SLF001 - API reuses configured risk thresholds.
    )
    if should_run_gliner:
        gliner_result = evaluate_gliner_stage(event)
        gliner_result["trigger_reason"] = gliner_trigger_reason
    else:
        gliner_result = skip_gliner_stage(gliner_trigger_reason)
    final_decision, final_rationale = combine_stage_decisions(rules_result.decision, gliner_result)

    return {
        "status": "analyzed",
        "session_id": session_id,
        "message": "Live analysis completed.",
        "interpretation": interpretation,
        "event": {
            **asdict(event),
            "timestamp": event.timestamp.isoformat(),
        },
        "mcp_request": build_mcp_request(event),
        "rules_catboost": {
            "decision": rules_result.decision,
            "risk_score": rules_result.risk_score,
            "rationale": rules_result.rationale,
            "rule_matches": [asdict(match) for match in rules_result.rule_matches],
            "features": rules_result.features,
            "supervised_assessment": (
                asdict(rules_result.supervised_assessment)
                if rules_result.supervised_assessment is not None
                else None
            ),
        },
        "gliner_lora": gliner_result,
        "final_decision": final_decision,
        "final_rationale": final_rationale,
    }
