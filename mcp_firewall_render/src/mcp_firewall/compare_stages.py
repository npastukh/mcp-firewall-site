from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path

from mcp_firewall.config import FirewallConfig
from mcp_firewall.firewall import FirewallService
from mcp_firewall.llama_firewall_runtime import LlamaFirewallAssessment, LlamaFirewallEvaluator
from mcp_firewall.models import MCPEvent, PrivacyAssessment
from mcp_firewall.privacy_filter_runtime import HIGH_RISK_PRIVACY_LABELS, PrivacyFilterEvaluator
from mcp_firewall.stack_demo import build_lab_config, build_lab_events


@dataclass(slots=True)
class StageRunResult:
    stage_name: str
    decision: str
    rationale: str
    risk_score: float | None = None
    labels: tuple[str, ...] = field(default_factory=tuple)
    confidence: float | None = None


@dataclass(slots=True)
class StageComparisonRecord:
    event: MCPEvent
    results: tuple[StageRunResult, ...]


def resolve_default_gliner_model_path(project_root: Path) -> Path | None:
    candidates = (
        project_root / "artifacts" / "gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1" / "best",
        project_root / "artifacts" / "gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1" / "final",
    )
    return next((path for path in candidates if path.exists()), None)


def run_rules_ml_stage(event: MCPEvent, config: FirewallConfig | None = None) -> StageRunResult:
    firewall = FirewallService(config or FirewallConfig())
    result = firewall.process_event(event)
    return StageRunResult(
        stage_name="rules_ml",
        decision=result.decision,
        rationale=result.rationale,
        risk_score=round(result.risk_score, 4),
    )


def build_rules_ml_stage_config() -> FirewallConfig:
    config = build_lab_config()
    config.full_context_evaluator_enabled = False
    config.full_context_model_path = None
    return config


def run_gliner_lora_stage(
    event: MCPEvent,
    evaluator: PrivacyFilterEvaluator,
    warn_threshold: float = 0.55,
    block_threshold: float = 0.85,
) -> StageRunResult:
    assessment = evaluator.evaluate_event(event)
    return _build_gliner_result(
        assessment=assessment,
        warn_threshold=warn_threshold,
        block_threshold=block_threshold,
    )


def run_llama_firewall_stage(event: MCPEvent, evaluator: LlamaFirewallEvaluator) -> StageRunResult:
    assessment = evaluator.evaluate_event(event)
    return _build_llama_result(assessment)


def compare_stages(
    events: list[MCPEvent],
    gliner_model_path: str | None = None,
    rules_ml_config: FirewallConfig | None = None,
    gliner_warn_threshold: float = 0.55,
    gliner_block_threshold: float = 0.85,
) -> list[StageComparisonRecord]:
    project_root = Path(__file__).resolve().parents[2]
    default_gliner_path = resolve_default_gliner_model_path(project_root)
    resolved_gliner_path = gliner_model_path or (str(default_gliner_path) if default_gliner_path is not None else None)
    gliner_evaluator = (
        PrivacyFilterEvaluator(model_path=resolved_gliner_path, max_length=128, extraction_threshold=0.80)
        if resolved_gliner_path
        else None
    )
    llama_evaluator = LlamaFirewallEvaluator()
    stage1_config = rules_ml_config or build_rules_ml_stage_config()
    rules_ml_firewall = FirewallService(stage1_config)

    records: list[StageComparisonRecord] = []
    for event in events:
        stage_results = [
            StageRunResult(
                stage_name="rules_ml",
                decision=(rules_ml_result := rules_ml_firewall.process_event(event)).decision,
                rationale=rules_ml_result.rationale,
                risk_score=round(rules_ml_result.risk_score, 4),
            )
        ]

        if gliner_evaluator is None:
            stage_results.append(
                StageRunResult(
                    stage_name="gliner_lora",
                    decision="error",
                    rationale="GLiNER + LoRA checkpoint was not found.",
                )
            )
        else:
            try:
                stage_results.append(
                    run_gliner_lora_stage(
                        event,
                        evaluator=gliner_evaluator,
                        warn_threshold=gliner_warn_threshold,
                        block_threshold=gliner_block_threshold,
                    )
                )
            except RuntimeError as exc:
                stage_results.append(
                    StageRunResult(
                        stage_name="gliner_lora",
                        decision="error",
                        rationale=str(exc),
                    )
                )

        try:
            stage_results.append(run_llama_firewall_stage(event, evaluator=llama_evaluator))
        except RuntimeError as exc:
            stage_results.append(
                StageRunResult(
                    stage_name="llama_firewall",
                    decision="error",
                    rationale=str(exc),
                )
            )

        records.append(StageComparisonRecord(event=event, results=tuple(stage_results)))

    return records


def format_comparison(records: list[StageComparisonRecord]) -> str:
    lines: list[str] = []
    for index, record in enumerate(records, start=1):
        event = record.event
        lines.append(
            f"[{index}] {event.tool_name or event.jsonrpc_method} | "
            f"label={event.label or '-'} | scenario={event.scenario_type or '-'}"
        )
        for result in record.results:
            extra_parts: list[str] = []
            if result.risk_score is not None:
                extra_parts.append(f"risk={result.risk_score:.2f}")
            if result.confidence is not None:
                extra_parts.append(f"confidence={result.confidence:.2f}")
            if result.labels:
                extra_parts.append("labels=" + ",".join(result.labels))
            extras = f" | {'; '.join(extra_parts)}" if extra_parts else ""
            lines.append(
                f"  - {result.stage_name}: {result.decision}{extras} | {result.rationale}"
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def _build_gliner_result(
    assessment: PrivacyAssessment,
    warn_threshold: float,
    block_threshold: float,
) -> StageRunResult:
    labels = tuple(sorted({span.label for span in assessment.spans}))
    high_risk_labels = tuple(
        sorted({span.label for span in assessment.spans if span.label in HIGH_RISK_PRIVACY_LABELS})
    )
    decision = "allow"
    rationale = "GLiNER + LoRA did not detect suspicious spans in the MCP request."

    if high_risk_labels and assessment.max_confidence >= block_threshold:
        decision = "block"
        rationale = (
            "GLiNER + LoRA detected high-risk sensitive entities: "
            + ", ".join(high_risk_labels)
        )
    elif assessment.entity_count and assessment.max_confidence >= warn_threshold:
        decision = "warn"
        rationale = (
            "GLiNER + LoRA detected suspicious entities: "
            + ", ".join(labels)
        )

    return StageRunResult(
        stage_name="gliner_lora",
        decision=decision,
        rationale=rationale,
        labels=labels,
        confidence=round(assessment.max_confidence, 4),
    )


def _build_llama_result(assessment: LlamaFirewallAssessment) -> StageRunResult:
    scanner_list = ", ".join(assessment.scanners) or "default"
    rationale = (
        f"LlamaFirewall decision reason: {assessment.reason}; scanners: {scanner_list}."
    )
    return StageRunResult(
        stage_name="llama_firewall",
        decision=assessment.decision,
        rationale=rationale,
        confidence=assessment.score,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare three independent MCP protection stages on the same events."
    )
    parser.add_argument(
        "--gliner-model-path",
        type=str,
        default=None,
        help="Path to the GLiNER + LoRA checkpoint directory.",
    )
    parser.add_argument(
        "--warn-threshold",
        type=float,
        default=0.55,
        help="Warn threshold for GLiNER + LoRA max confidence.",
    )
    parser.add_argument(
        "--block-threshold",
        type=float,
        default=0.85,
        help="Block threshold for GLiNER + LoRA max confidence.",
    )
    args = parser.parse_args()

    records = compare_stages(
        events=build_lab_events(),
        gliner_model_path=args.gliner_model_path,
        gliner_warn_threshold=args.warn_threshold,
        gliner_block_threshold=args.block_threshold,
    )
    print(format_comparison(records))


if __name__ == "__main__":
    main()
