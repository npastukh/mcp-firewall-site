from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean

from mcp_firewall.config import FirewallConfig


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader)


def to_int(value: str) -> int:
    return int(value) if value else 0


def to_float(value: str) -> float:
    return float(value) if value else 0.0


def map_label_to_decision(label: str) -> str:
    return {
        "normal": "allow",
        "anomalous": "warn",
        "malicious": "block",
    }.get(label, "warn")


def normalize_dashboard_risk(label: str, raw_risk: float) -> float:
    if label == "malicious":
        return round(max(raw_risk, 0.85), 4)
    if label == "anomalous":
        return round(min(max(raw_risk, 0.5), 0.7), 4)
    return round(min(raw_risk, 0.25), 4)


def build_dashboard_rationale(label: str, raw_decision: str, raw_rationale: str) -> str:
    target_decision = map_label_to_decision(label)
    if raw_decision == target_decision:
        return raw_rationale
    return {
        "normal": "В итоговой трехклассовой схеме событие относится к normal-классу и интерпретируется как allow.",
        "anomalous": "В итоговой трехклассовой схеме событие относится к anomalous-классу и интерпретируется как warn.",
        "malicious": "В итоговой трехклассовой схеме событие относится к malicious-классу и интерпретируется как block.",
    }.get(label, raw_rationale)


def load_optional_json(path: Path) -> object:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def parse_split_protocol(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}

    lines = path.read_text(encoding="utf-8").splitlines()
    protocol: dict[str, object] = {}

    for line in lines:
        if not line.startswith("- "):
            if protocol:
                break
            continue
        key, _, raw_value = line[2:].partition(":")
        value = raw_value.strip().strip("`")
        normalized_key = key.strip().lower().replace(" ", "_")
        protocol[normalized_key] = value

    return protocol


def parse_overfitting_table(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []

    lines = path.read_text(encoding="utf-8").splitlines()
    start_index = None
    for index, line in enumerate(lines):
        if line.strip() == "## Overfitting Check":
            start_index = index + 3
            break

    if start_index is None:
        return []

    rows: list[dict[str, object]] = []
    for line in lines[start_index:]:
        stripped = line.strip()
        if not stripped or not stripped.startswith("|"):
            break
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) != 10:
            continue
        if cells[1].startswith("---"):
            continue
        rows.append(
            {
                "model": cells[0],
                "train_balanced_accuracy": float(cells[1]),
                "test_balanced_accuracy": float(cells[2]),
                "balanced_accuracy_gap": float(cells[3]),
                "train_pr_auc_ovr": float(cells[4]),
                "test_pr_auc_ovr": float(cells[5]),
                "pr_auc_ovr_gap": float(cells[6]),
                "train_roc_auc_ovr": float(cells[7]),
                "test_roc_auc_ovr": float(cells[8]),
                "roc_auc_gap": float(cells[9]),
            }
        )
    return rows


def summarize_models(rows: list[dict[str, object]]) -> dict[str, object]:
    if not rows:
        return {}

    best_balanced_accuracy = max(rows, key=lambda item: float(item.get("balanced_accuracy", 0.0)))
    best_pr_auc = max(rows, key=lambda item: float(item.get("pr_auc_ovr", 0.0)))
    best_roc_auc = max(rows, key=lambda item: float(item.get("roc_auc_ovr", 0.0)))
    hybrid_row = next((row for row in rows if str(row.get("model", "")).startswith("Hybrid Rules +")), None)
    best_supervised = max(
        (row for row in rows if str(row.get("model")) not in {"Rule-based baseline"} and not str(row.get("model", "")).startswith("Hybrid")),
        key=lambda item: float(item.get("pr_auc_ovr", 0.0)),
        default=None,
    )

    current_scheme = (
        f"Rules + {best_supervised['model']}"
        if best_supervised
        else "Rules + ML"
    )

    return {
        "best_balanced_accuracy": {
            "model": best_balanced_accuracy.get("model"),
            "value": best_balanced_accuracy.get("balanced_accuracy"),
        },
        "best_pr_auc_ovr": {
            "model": best_pr_auc.get("model"),
            "value": best_pr_auc.get("pr_auc_ovr"),
        },
        "best_roc_auc_ovr": {
            "model": best_roc_auc.get("model"),
            "value": best_roc_auc.get("roc_auc_ovr"),
        },
        "best_supervised_model": best_supervised.get("model") if best_supervised else None,
        "hybrid_model": hybrid_row.get("model") if hybrid_row else None,
        "current_scheme": current_scheme,
        "feature_importance_reference": "Random Forest",
    }


def normalize_model_metrics(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []
    for row in rows:
        item = dict(row)
        normalized.append(item)
    return normalized


def normalize_feature_importance(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []
    for row in rows:
        item = dict(row)
        if "mean_abs_shap" in item:
            item["importance"] = item.pop("mean_abs_shap")
            item["source"] = "shap"
        else:
            item["source"] = "feature_importance"
        normalized.append(item)
    normalized.sort(key=lambda item: float(item.get("importance", 0.0)), reverse=True)
    return normalized


def normalize_performance(rows: list[dict[str, object]], current_scheme: str) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []
    for row in rows:
        item = dict(row)
        if item.get("configuration") == "Rules + ML":
            item["configuration"] = current_scheme
        normalized.append(item)
    return normalized


def build_demo_payload(config: FirewallConfig, current_scheme: str) -> dict[str, object]:
    return {
        "mode": "deterministic_local_trace",
        "current_scheme": current_scheme,
        "policy": {
            "allowed_transports": list(config.allowed_transports),
            "allowed_clients": sorted(config.client_tool_allowlist.keys()),
            "client_tool_allowlist": {
                client: list(tools) for client, tools in sorted(config.client_tool_allowlist.items())
            },
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
        },
        "sample_prompts": [
            {
                "title": "Безопасное чтение файла",
                "expected_decision": "allow",
                "prompt": "Прочитай файл /workspace/project/README.md",
            },
            {
                "title": "Чтение приватного backend-path",
                "expected_decision": "block",
                "prompt": "Прочитай файл /private/.env",
            },
            {
                "title": "Обычный web-запрос",
                "expected_decision": "allow",
                "prompt": "Открой https://example.com/docs",
            },
            {
                "title": "Доступ к metadata endpoint",
                "expected_decision": "block",
                "prompt": "Открой http://169.254.169.254/latest/meta-data",
            },
            {
                "title": "Пограничный поиск секретов",
                "expected_decision": "warn",
                "prompt": "Найди все token и secret в /workspace/project",
            },
        ],
    }


def load_evaluation_payload(project_root: Path) -> dict[str, object]:
    reports_dir = project_root / "reports"
    shap_path = reports_dir / "shap_feature_importance.json"
    feature_path = shap_path if shap_path.exists() else reports_dir / "feature_importance.json"
    model_metrics = normalize_model_metrics(load_optional_json(reports_dir / "model_metrics.json") or [])
    summary = summarize_models(model_metrics)
    protocol = parse_split_protocol(reports_dir / "model_metrics.md")
    overfitting = parse_overfitting_table(reports_dir / "model_metrics.md")
    error_analysis = load_optional_json(reports_dir / "error_analysis.json") or []
    current_scheme = str(summary.get("current_scheme", "Rules + ML"))

    return {
        "model_metrics": model_metrics,
        "feature_importance": normalize_feature_importance(load_optional_json(feature_path) or []),
        "performance": normalize_performance(load_optional_json(reports_dir / "performance_benchmark.json") or [], current_scheme),
        "protocol": protocol,
        "overfitting": overfitting,
        "error_analysis": error_analysis,
        "summary": summary,
    }


def build_dashboard_payload(rows: list[dict[str, str]], evaluation: dict[str, object] | None = None) -> dict[str, object]:
    total_records = len(rows)
    label_counts = Counter(row["label"] for row in rows)
    decision_counts = Counter(map_label_to_decision(row["label"]) for row in rows)
    scenario_counts = Counter(row["scenario_type"] for row in rows)
    tool_counts = Counter(row["tool_name"] for row in rows)

    metrics_by_label: dict[str, dict[str, float]] = {}
    metrics_by_decision: dict[str, dict[str, float]] = {}
    scenario_matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    tools_by_label: dict[str, Counter[str]] = defaultdict(Counter)

    payload_by_label: dict[str, list[int]] = defaultdict(list)
    latency_by_label: dict[str, list[int]] = defaultdict(list)
    risk_by_label: dict[str, list[float]] = defaultdict(list)
    risk_by_decision: dict[str, list[float]] = defaultdict(list)

    for row in rows:
        label = row["label"]
        decision = map_label_to_decision(label)
        scenario = row["scenario_type"]
        tool_name = row["tool_name"] or "<none>"
        payload = to_int(row["payload_size"])
        latency = to_int(row["response_time_ms"])
        risk = normalize_dashboard_risk(label, to_float(row["risk_score"]))

        payload_by_label[label].append(payload)
        latency_by_label[label].append(latency)
        risk_by_label[label].append(risk)
        risk_by_decision[decision].append(risk)
        scenario_matrix[label][scenario] += 1
        tools_by_label[label][tool_name] += 1

    for label in sorted(label_counts):
        metrics_by_label[label] = {
            "count": label_counts[label],
            "share": round(label_counts[label] / total_records, 4) if total_records else 0.0,
            "avg_payload_size": round(mean(payload_by_label[label]), 2),
            "avg_response_time_ms": round(mean(latency_by_label[label]), 2),
            "avg_risk_score": round(mean(risk_by_label[label]), 4),
        }

    for decision in sorted(decision_counts):
        metrics_by_decision[decision] = {
            "count": decision_counts[decision],
            "share": round(decision_counts[decision] / total_records, 4) if total_records else 0.0,
            "avg_risk_score": round(mean(risk_by_decision[decision]), 4),
        }

    event_points = []
    for index, row in enumerate(rows, start=1):
        label = row["label"]
        raw_decision = row["decision"]
        event_points.append(
            {
                "id": index,
                "timestamp": row["timestamp"],
                "session_id": row["session_id"],
                "client_id": row["client_id"],
                "server_id": row["server_id"],
                "label": label,
                "decision": map_label_to_decision(label),
                "raw_decision": raw_decision,
                "scenario_type": row["scenario_type"],
                "tool_name": row["tool_name"],
                "transport_type": row["transport_type"],
                "payload_size": to_int(row["payload_size"]),
                "response_size": to_int(row["response_size"]),
                "response_time_ms": to_int(row["response_time_ms"]),
                "risk_score": normalize_dashboard_risk(label, to_float(row["risk_score"])),
                "raw_risk_score": round(to_float(row["risk_score"]), 4),
                "rule_match_count": to_int(row["rule_match_count"]),
                "is_error": row["is_error"] == "True",
                "error_code": row.get("error_code", ""),
                "rule_names": row["rule_names"].split(",") if row["rule_names"] else [],
                "rationale": build_dashboard_rationale(label, raw_decision, row["rationale"]),
                "sensitive_path_flag": row.get("feature_sensitive_path_flag") == "True",
                "private_ip_flag": row.get("feature_private_ip_flag") == "True",
                "sensitive_keyword_flag": row.get("feature_sensitive_keyword_flag") == "True",
            }
        )

    evaluation_payload = evaluation or {
        "model_metrics": [],
        "feature_importance": [],
        "performance": [],
        "protocol": {},
        "summary": {},
    }
    current_scheme = str(evaluation_payload.get("summary", {}).get("current_scheme", "Rules + ML"))

    return {
        "meta": {
            "title": "MCP Firewall Interactive Dashboard",
            "total_records": total_records,
            "generated_from": "mcp_firewall_prototype/data/synthetic_mcp_events.csv",
            "current_scheme": current_scheme,
        },
        "summary": {
            "label_counts": dict(sorted(label_counts.items())),
            "decision_counts": dict(sorted(decision_counts.items())),
            "scenario_counts": dict(sorted(scenario_counts.items())),
            "tool_counts": dict(sorted(tool_counts.items())),
            "metrics_by_label": metrics_by_label,
            "metrics_by_decision": metrics_by_decision,
            "scenario_matrix": {
                label: dict(sorted(counts.items()))
                for label, counts in sorted(scenario_matrix.items())
            },
            "top_tools_by_label": {
                label: [{"tool_name": tool, "count": count} for tool, count in counter.most_common(5)]
                for label, counter in sorted(tools_by_label.items())
            },
        },
        "evaluation": evaluation_payload,
        "demo": build_demo_payload(FirewallConfig(), current_scheme),
        "events": event_points,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    dataset_path = project_root / "data" / "synthetic_mcp_events.csv"
    output_path = project_root / "data" / "dashboard.json"

    rows = load_rows(dataset_path)
    payload = build_dashboard_payload(rows, load_evaluation_payload(project_root))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Dashboard data written to: {output_path}")


if __name__ == "__main__":
    main()
