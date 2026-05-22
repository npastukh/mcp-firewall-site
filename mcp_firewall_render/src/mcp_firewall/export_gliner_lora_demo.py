from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_firewall.config import FirewallConfig
from mcp_firewall.firewall import FirewallService
from mcp_firewall.models import AnalysisResult, MCPEvent, PrivacyAssessment
from mcp_firewall.privacy_filter_runtime import PrivacyFilterEvaluator

DEFAULT_DEMO_REQUESTS = "data/gliner_lora_demo_requests.json"
DEFAULT_DEMO_OUTPUT = "data/gliner_lora_demo_output.json"


@dataclass(slots=True)
class DemoRequest:
    id: str
    title: str
    prompt: str
    notes: str = ""


def normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def normalize_path_candidate(candidate: str) -> str:
    path = str(candidate or "").strip().strip("\"'")
    path = re.sub(r"[),.;:]+$", "", path)
    if not path or re.match(r"^https?://", path, flags=re.IGNORECASE):
        return ""
    if path.startswith("/"):
        return path
    if path.startswith("./"):
        path = path[2:]
    if path.startswith("../"):
        path = re.sub(r"^(?:\.\./)+", "", path)
    if not path:
        return ""
    return f"/workspace/project/{path}"


def extract_path(text: str) -> str:
    normalized = normalize_whitespace(text)
    patterns = [
        r"[\"'](\/[^\"'\s,;]+|\.\.?\/[^\"'\s,;]+|\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)[\"']",
        r"(\/[^\s,;]+)",
        r"\b(?:файл|файла|путь|path|file)\s+((?:\.\.?\/)?\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)",
        r"\b((?:\.\.?\/)?\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, normalized, flags=re.IGNORECASE)
        if not match:
            continue
        candidate = match.group(1) if match.groups() else match.group(0)
        normalized_path = normalize_path_candidate(candidate)
        if normalized_path:
            return normalized_path
    return ""


def extract_url(text: str) -> str:
    explicit = re.search(r"https?://[^\s)]+", text, flags=re.IGNORECASE)
    if explicit:
        return explicit.group(0)
    bare = re.search(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s,;]*)?", text, flags=re.IGNORECASE)
    if bare:
        if bare.start() > 0 and text[bare.start() - 1] in {".", "/", "_"}:
            return ""
        candidate = bare.group(0)
        if re.match(r"^https?://", candidate, flags=re.IGNORECASE):
            return candidate
        return f"https://{candidate}"
    return ""


def cleanup_search_query(prompt: str) -> str:
    cleaned = normalize_whitespace(
        re.sub(
            r"\b(?:в|inside|within)\s+(\/[^\s,;]+|(?:\.\.?\/)?\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)\b",
            "",
            re.sub(r"^(найди|выполни поиск|поиск|search for|search)\s*", "", prompt, flags=re.IGNORECASE),
            flags=re.IGNORECASE,
        )
    )
    cleaned = re.sub(r"\b(?:файл|путь|path|file)\b", "", cleaned, flags=re.IGNORECASE)
    return normalize_whitespace(cleaned) or prompt


def has_read_intent(lowered_prompt: str, path: str) -> bool:
    if re.search(r"\b(read|cat|open file|show file)\b", lowered_prompt, flags=re.IGNORECASE):
        return True
    if re.search(r"(прочитай|прочти|открой файл|покажи файл|выведи файл|содержимое файла)", lowered_prompt, flags=re.IGNORECASE):
        return True
    return bool(path and re.search(r"(файл|file|read|прочитай|прочти|открой|покажи)", lowered_prompt, flags=re.IGNORECASE))


def has_fetch_intent(lowered_prompt: str) -> bool:
    return bool(
        re.search(
            r"(fetch|http|url|сайт|страниц|страницу|перейди|скачай|запроси|web[- ]?запрос|открой\s+(?!файл))",
            lowered_prompt,
            flags=re.IGNORECASE,
        )
    )


def has_search_intent(lowered_prompt: str) -> bool:
    return bool(
        re.search(
            r"(найди|ищи|поиск|search|find|grep|поищи|проверь.*(секрет|token|password|key))",
            lowered_prompt,
            flags=re.IGNORECASE,
        )
    )


def interpret_prompt(prompt: str, policy: dict[str, Any]) -> dict[str, Any]:
    normalized_prompt = normalize_whitespace(prompt)
    lowered_prompt = normalized_prompt.lower()
    path = extract_path(normalized_prompt)
    url = extract_url(normalized_prompt)

    if not normalized_prompt:
        return {
            "status": "unknown",
            "intent": "unknown",
            "confidence": 0.0,
            "message": "Пустой запрос не может быть интерпретирован как MCP-сценарий.",
        }

    if has_fetch_intent(lowered_prompt) or url:
        if not url:
            return {
                "status": "incomplete",
                "intent": "web_fetch",
                "confidence": 0.52,
                "missing": ["url"],
                "message": "Распознан web-сценарий, но в запросе не указан конкретный URL.",
            }
        return {
            "status": "supported",
            "intent": "web_fetch",
            "confidence": 0.95,
            "tool_name": "web.fetch",
            "server_id": policy["tool_server_map"].get("web.fetch", "http-server"),
            "arguments": {"url": url},
            "message": "Запрос интерпретирован как web-fetch вызов.",
        }

    if has_read_intent(lowered_prompt, path):
        if not path:
            return {
                "status": "incomplete",
                "intent": "read_file",
                "confidence": 0.74,
                "missing": ["path"],
                "message": "Распознан сценарий чтения файла, но не указан конкретный путь.",
            }
        return {
            "status": "supported",
            "intent": "read_file",
            "confidence": 0.92,
            "tool_name": "filesystem.read_file",
            "server_id": policy["tool_server_map"].get("filesystem.read_file", "filesystem-server"),
            "arguments": {"path": path},
            "message": "Запрос интерпретирован как чтение файла через filesystem.read_file.",
        }

    if has_search_intent(lowered_prompt):
        query = cleanup_search_query(normalized_prompt)
        if not query or len(query) < 3:
            return {
                "status": "incomplete",
                "intent": "search",
                "confidence": 0.61,
                "missing": ["query"],
                "message": "Распознан поисковый сценарий, но запрос недостаточно конкретен для построения search-вызова.",
            }
        return {
            "status": "supported",
            "intent": "search",
            "confidence": 0.83,
            "tool_name": "filesystem.search",
            "server_id": policy["tool_server_map"].get("filesystem.search", "filesystem-server"),
            "arguments": {"path": path or "/workspace/project", "query": query},
            "message": "Запрос интерпретирован как поиск по файловому дереву.",
        }

    return {
        "status": "unknown",
        "intent": "unknown",
        "confidence": 0.18,
        "message": "Запрос находится вне поддерживаемых демонстрационных сценариев. Demo интерпретирует чтение файла, web-fetch и поиск.",
    }


def estimate_payload_size(prompt: str, params: dict[str, Any]) -> int:
    return max(
        220,
        len(prompt) * 18 + sum(len(str(value)) * 6 for value in params.values()),
    )


def build_prompt_review_event(prompt: str, client_id: str, transport_type: str) -> MCPEvent:
    return MCPEvent(
        timestamp=datetime.now(UTC),
        session_id=f"prompt-{abs(hash(prompt)) % 100_000}",
        client_id=client_id,
        server_id="prompt-review",
        transport_type=transport_type,
        jsonrpc_method="tools/call",
        tool_name="prompt.review",
        params={"prompt": prompt},
        payload_size=max(120, len(prompt) * 10),
    )


def build_interpreted_event(
    prompt: str,
    client_id: str,
    transport_type: str,
    interpretation: dict[str, Any],
) -> MCPEvent:
    arguments = dict(interpretation.get("arguments", {}))
    return MCPEvent(
        timestamp=datetime.now(UTC),
        session_id=f"demo-{interpretation.get('intent', 'case')}-{abs(hash(prompt)) % 100_000}",
        client_id=client_id,
        server_id=str(interpretation.get("server_id", "filesystem-server")),
        transport_type=transport_type,
        jsonrpc_method="tools/call",
        tool_name=str(interpretation["tool_name"]),
        params=arguments,
        payload_size=estimate_payload_size(prompt, arguments),
    )


def build_mcp_request(event: MCPEvent) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": "gliner-lora-demo",
        "method": event.jsonrpc_method,
        "params": {
            "name": event.tool_name,
            "arguments": event.params,
        },
    }


def serialize_privacy_assessment(assessment: PrivacyAssessment | None) -> dict[str, Any] | None:
    if assessment is None:
        return None
    return {
        "context_text": assessment.context_text,
        "max_confidence": assessment.max_confidence,
        "detected_labels": list(assessment.detected_labels),
        "entity_count": assessment.entity_count,
        "sensitive_entity_count": assessment.sensitive_entity_count,
        "spans": [asdict(span) for span in assessment.spans],
    }


def serialize_prompt_analysis(prompt: str, evaluator: PrivacyFilterEvaluator) -> dict[str, Any]:
    evaluator._load()  # noqa: SLF001 - exporter intentionally reuses the already-initialized runtime model
    if getattr(evaluator, "_runtime_kind", "") != "gliner2":  # noqa: SLF001
        return serialize_privacy_assessment(evaluator.evaluate_event(build_prompt_review_event(prompt, "agent-1", "stdio"))) or {
            "context_text": prompt,
            "max_confidence": 0.0,
            "detected_labels": [],
            "entity_count": 0,
            "sensitive_entity_count": 0,
            "spans": [],
        }

    from mcp_firewall.privacy_filter_runtime import (
        HIGH_RISK_PRIVACY_LABELS,
        _build_gliner2_schema,
        _predict_request_safety,
    )

    payload = evaluator._model.extract(  # noqa: SLF001
        prompt,
        _build_gliner2_schema(),
        threshold=0.5,
        include_confidence=True,
        include_spans=True,
    )
    entities = payload.get("entities", {})
    spans: list[dict[str, Any]] = []
    for label, values in entities.items():
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            start_char = item.get("start")
            end_char = item.get("end")
            if start_char is None or end_char is None:
                continue
            spans.append(
                {
                    "label": label,
                    "text": item.get("text", prompt[int(start_char): int(end_char)]),
                    "score": round(float(item.get("score", item.get("confidence", 0.0))), 4),
                    "start_char": int(start_char),
                    "end_char": int(end_char),
                }
            )
    predicted_safety = _predict_request_safety(  # noqa: SLF001 - demo export intentionally mirrors runtime gating
        payload,
        fallback_label="suspicious" if spans else "safe",
    )
    if predicted_safety != "suspicious":
        spans = []
    spans.sort(key=lambda item: (int(item["start_char"]), int(item["end_char"]), str(item["label"])))
    detected_labels = sorted({str(span["label"]) for span in spans})
    max_confidence = max((float(span["score"]) for span in spans), default=0.0)
    sensitive_entity_count = sum(1 for span in spans if span["label"] in HIGH_RISK_PRIVACY_LABELS)
    return {
        "context_text": prompt,
        "max_confidence": round(max_confidence, 4),
        "detected_labels": detected_labels,
        "entity_count": len(spans),
        "sensitive_entity_count": sensitive_entity_count,
        "spans": spans,
    }


def serialize_analysis_result(result: AnalysisResult, config: FirewallConfig) -> dict[str, Any]:
    block_matches = [match for match in result.rule_matches if match.severity == "block"]
    warn_matches = [match for match in result.rule_matches if match.severity == "warn"]
    if block_matches:
        decision_source = {
            "source": "rule-based",
            "detail": block_matches[0].name,
        }
    elif result.risk_score >= config.block_risk_threshold:
        decision_source = {
            "source": "ml",
            "detail": "risk_score >= block threshold",
        }
    elif warn_matches:
        decision_source = {
            "source": "rule-based",
            "detail": warn_matches[0].name,
        }
    elif result.risk_score >= config.warn_risk_threshold:
        decision_source = {
            "source": "ml",
            "detail": "risk_score >= warn threshold",
        }
    else:
        decision_source = {
            "source": "safe",
            "detail": "no escalation",
        }

    return {
        "risk_score": round(result.risk_score, 4),
        "decision": result.decision,
        "rationale": result.rationale,
        "features": result.features,
        "rule_matches": [asdict(match) for match in result.rule_matches],
        "decision_source": decision_source,
        "privacy_assessment": serialize_privacy_assessment(result.privacy_assessment),
    }


def load_demo_requests(path: Path) -> list[DemoRequest]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [
        DemoRequest(
            id=str(item["id"]),
            title=str(item["title"]),
            prompt=str(item["prompt"]),
            notes=str(item.get("notes", "")),
        )
        for item in payload
    ]


def load_best_metric_row(path: Path, label: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not rows:
        return None
    best = max(rows, key=lambda row: float(row.get("micro_f1", 0.0)))
    return {
        "label": label,
        "threshold": best.get("threshold"),
        "precision": best.get("micro_precision"),
        "recall": best.get("micro_recall"),
        "f1": best.get("micro_f1"),
        "tp": best.get("tp"),
        "fp": best.get("fp"),
        "fn": best.get("fn"),
    }


def resolve_model_path(project_root: Path, explicit_model_path: str | None) -> Path:
    if explicit_model_path:
        path = Path(explicit_model_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Model path does not exist: {path}")
        return path

    candidate_paths = [
        project_root / "artifacts" / "gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1" / "best",
        project_root / "artifacts" / "gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1" / "final",
    ]
    resolved = next((path for path in candidate_paths if path.exists()), None)
    if resolved is None:
        raise FileNotFoundError(
            "No GLiNER demo model found. Expected artifacts/gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1/best "
            "or artifacts/gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1/final."
        )
    return resolved


def build_policy_snapshot(config: FirewallConfig) -> dict[str, Any]:
    return {
        "allowed_transports": list(config.allowed_transports),
        "allowed_clients": sorted(config.client_tool_allowlist.keys()),
        "client_tool_allowlist": {client: list(tools) for client, tools in sorted(config.client_tool_allowlist.items())},
        "tool_server_map": dict(sorted(config.tool_server_map.items())),
        "blocked_paths": list(config.blocked_paths),
        "blocked_hosts": list(config.blocked_hosts),
        "safe_file_roots": list(config.safe_file_roots),
        "max_payload_size": config.max_payload_size,
        "max_response_size": config.max_response_size,
        "warn_risk_threshold": config.warn_risk_threshold,
        "block_risk_threshold": config.block_risk_threshold,
        "high_frequency_threshold": config.high_frequency_threshold,
        "sensitive_keywords": list(config.sensitive_keywords),
    }


def build_demo_payload(
    project_root: Path,
    model_path: Path,
    requests: list[DemoRequest],
) -> dict[str, Any]:
    config = FirewallConfig(
        full_context_evaluator_enabled=True,
        full_context_model_path=str(model_path),
        full_context_max_length=128,
        full_context_extraction_threshold=0.80,
    )
    policy = build_policy_snapshot(config)
    evaluator = PrivacyFilterEvaluator(str(model_path), max_length=128, extraction_threshold=0.80)

    comparison = [
        row
        for row in (
            load_best_metric_row_from_markdown(
                project_root / "reports" / "gliner2_v5_base_test.md",
                "Baseline GLiNER2 large v1 · test",
            ),
            load_best_metric_row_from_markdown(
                project_root / "reports" / "gliner2_v5_safe1_best_eval.md",
                "LoRA v5 safe1 · validation",
            ),
            load_best_metric_row_from_markdown(
                project_root / "reports" / "gliner2_v5_lora_best_test.md",
                "LoRA v5 safe1 · test",
                is_active_export=True,
            ),
        )
        if row is not None
    ]

    cases: list[dict[str, Any]] = []
    for request in requests:
        interpretation = interpret_prompt(request.prompt, policy)
        case_payload: dict[str, Any] = {
            "id": request.id,
            "title": request.title,
            "prompt": request.prompt,
            "normalized_prompt": normalize_whitespace(request.prompt),
            "notes": request.notes,
            "prompt_analysis": serialize_prompt_analysis(request.prompt, evaluator),
            "interpretation": interpretation,
        }

        if interpretation.get("status") == "supported":
            event = build_interpreted_event(request.prompt, "agent-1", "stdio", interpretation)
            firewall = FirewallService(config=config, privacy_evaluator=evaluator)
            result = firewall.process_event(event)
            case_payload["mcp_request"] = build_mcp_request(event)
            case_payload["firewall"] = serialize_analysis_result(result, config)
        else:
            case_payload["mcp_request"] = None
            case_payload["firewall"] = None

        cases.append(case_payload)

    return {
        "meta": {
            "generated_at": datetime.now(UTC).isoformat(),
            "model_path": str(model_path),
            "mode": "static-precomputed-demo",
            "request_count": len(cases),
            "update_command": "python3 -m mcp_firewall.export_gliner_lora_demo",
            "requests_file": str(project_root / DEFAULT_DEMO_REQUESTS),
            "output_file": str((project_root / DEFAULT_DEMO_OUTPUT).resolve()),
        },
        "policy": policy,
        "categories": [
            {
                "name": "env_access_pattern",
                "description": "Доступ к переменным окружения через process.env, os.environ, getenv.",
            },
            {
                "name": "secret_name",
                "description": "Имена секретов и переменных вроде GITHUB_TOKEN или DB_PASSWORD.",
            },
            {
                "name": "secret_value",
                "description": "Сами token-like или secret-like значения.",
            },
            {
                "name": "sensitive_path",
                "description": "Пути к секретным конфигам, .env и чувствительным артефактам.",
            },
            {
                "name": "private_host",
                "description": "Внутренние host/IP/localhost-цели, в том числе внутри URL вызовов.",
            },
            {
                "name": "secret_store_ref",
                "description": "Ссылки на vault, secret manager, KMS и другие контейнеры секретов.",
            },
        ],
        "model_comparison": comparison,
        "cases": cases,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export GLiNER+LoRA demo payload into a local JSON artifact.")
    parser.add_argument("--model-path", default=None, help="Checkpoint or adapter directory to use for prompt analysis.")
    parser.add_argument("--requests-file", default=DEFAULT_DEMO_REQUESTS, help="JSON file with demo prompts.")
    parser.add_argument("--output", default=DEFAULT_DEMO_OUTPUT, help="Target JSON file for the exported demo payload.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parents[2]
    model_path = resolve_model_path(project_root, args.model_path)
    requests_file = (project_root / args.requests_file).resolve()
    output_path = (project_root / args.output).resolve()

    payload = build_demo_payload(project_root, model_path, load_demo_requests(requests_file))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"GLiNER+LoRA demo data written to {output_path}")
    print(f"Model path: {model_path}")
    print(f"Requests file: {requests_file}")


if __name__ == "__main__":
    main()
