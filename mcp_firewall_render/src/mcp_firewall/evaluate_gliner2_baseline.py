from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from gliner2 import GLiNER2
from tqdm.auto import tqdm

from mcp_firewall.gliner2_dataset import (
    GLINER2_CLASSIFICATION_DESCRIPTIONS,
    GLINER2_CLASSIFICATION_LABELS,
    GLINER2_CLASSIFICATION_TASK,
    GLINER2_ENTITY_DESCRIPTIONS,
)


@dataclass(frozen=True)
class Span:
    category: str
    start: int
    end: int


@dataclass(frozen=True)
class ClassificationPrediction:
    label: str
    confidence: float
    source: str


def _load_model(model_name: str) -> object:
    model_path = Path(model_name)
    if model_path.exists() and (model_path / "adapter_config.json").exists():
        try:
            from peft import PeftConfig, PeftModel
        except ImportError as exc:
            raise RuntimeError(
                "This GLiNER2 checkpoint uses LoRA adapters. Install peft to evaluate adapter checkpoints."
            ) from exc

        peft_config = PeftConfig.from_pretrained(model_name)
        base_model = GLiNER2.from_pretrained(peft_config.base_model_name_or_path)
        return PeftModel.from_pretrained(base_model, model_name)

    return GLiNER2.from_pretrained(model_name)


def _load_rows(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def _request_safety(row: dict) -> str:
    info = row.get("info", {})
    value = str(info.get("request_safety", "")).strip()
    if value in GLINER2_CLASSIFICATION_LABELS:
        return value
    return "suspicious" if row.get("label") else "safe"


def _build_schema() -> dict[str, object]:
    return {
        "entities": GLINER2_ENTITY_DESCRIPTIONS,
        "classifications": [
            {
                "task": GLINER2_CLASSIFICATION_TASK,
                "labels": list(GLINER2_CLASSIFICATION_LABELS),
                "label_descriptions": GLINER2_CLASSIFICATION_DESCRIPTIONS,
            }
        ],
    }


def _as_spans(items: Iterable[dict]) -> set[Span]:
    return {
        Span(
            category=str(item["category"]),
            start=int(item["start"]),
            end=int(item["end"]),
        )
        for item in items
    }


def _normalize_predictions(payload: dict[str, object]) -> set[Span]:
    entities = payload.get("entities", [])
    normalized: set[Span] = set()
    if isinstance(entities, dict):
        entity_groups = [entities]
    elif isinstance(entities, list):
        entity_groups = [item for item in entities if isinstance(item, dict)]
    else:
        return normalized

    for entity_group in entity_groups:
        for category, values in entity_group.items():
            if not isinstance(values, list):
                continue
            for item in values:
                if not isinstance(item, dict):
                    continue
                start = item.get("start")
                end = item.get("end")
                if start is None or end is None:
                    continue
                normalized.add(Span(category=str(category), start=int(start), end=int(end)))
    return normalized


def _safe_div(num: float, den: float) -> float:
    return 0.0 if den == 0 else num / den


def _f1(precision: float, recall: float) -> float:
    return 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)


def _extract_label(value: object) -> str | None:
    if isinstance(value, str) and value in GLINER2_CLASSIFICATION_LABELS:
        return value
    if isinstance(value, list) and len(value) == 1:
        only = value[0]
        if isinstance(only, str) and only in GLINER2_CLASSIFICATION_LABELS:
            return only
    if isinstance(value, dict):
        for key in ("predicted_label", "label", "top_label", "value"):
            nested = _extract_label(value.get(key))
            if nested is not None:
                return nested
    return None


def _extract_confidence(candidate: dict[str, object], label: str) -> float:
    for key in ("confidence", "score", "probability"):
        value = candidate.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    label_scores = candidate.get("label_scores")
    if isinstance(label_scores, dict):
        score = label_scores.get(label)
        if isinstance(score, (int, float)):
            return float(score)
    return 0.0


def _iter_candidate_dicts(payload: object) -> Iterable[dict[str, object]]:
    stack = [payload]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            yield current
            for value in current.values():
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(current, list):
            for value in current:
                if isinstance(value, (dict, list)):
                    stack.append(value)


def _normalize_request_safety_prediction(
    payload: dict[str, object],
    *,
    fallback_label: str,
) -> ClassificationPrediction:
    classifications = payload.get("classifications")
    candidates: list[ClassificationPrediction] = []
    for candidate in _iter_candidate_dicts(classifications):
        task_name = str(candidate.get("task", "")).strip()
        if task_name and task_name != GLINER2_CLASSIFICATION_TASK:
            continue
        for key in ("predicted_label", "label", "top_label", "prediction", "value"):
            label = _extract_label(candidate.get(key))
            if label is not None:
                candidates.append(
                    ClassificationPrediction(
                        label=label,
                        confidence=_extract_confidence(candidate, label),
                        source="classification_head",
                    )
                )
                break
        task_value = candidate.get(GLINER2_CLASSIFICATION_TASK)
        label = _extract_label(task_value)
        if label is not None:
            candidates.append(
                ClassificationPrediction(
                    label=label,
                    confidence=_extract_confidence(candidate, label),
                    source="classification_head",
                )
            )
    if candidates:
        return max(candidates, key=lambda item: item.confidence)
    return ClassificationPrediction(label=fallback_label, confidence=0.0, source="span_fallback")


def _update_span_counts(
    gold: set[Span],
    predicted: set[Span],
    *,
    total_counts: Counter,
    per_label_counts: dict[str, Counter],
) -> None:
    hits = gold & predicted
    extra = predicted - gold
    missed = gold - predicted
    total_counts["tp"] += len(hits)
    total_counts["fp"] += len(extra)
    total_counts["fn"] += len(missed)
    for span in hits:
        per_label_counts[span.category]["tp"] += 1
    for span in extra:
        per_label_counts[span.category]["fp"] += 1
    for span in missed:
        per_label_counts[span.category]["fn"] += 1


def _summarize_per_label(per_label_counts: dict[str, Counter]) -> dict[str, dict[str, float | int]]:
    summary: dict[str, dict[str, float | int]] = {}
    for category in sorted(GLINER2_ENTITY_DESCRIPTIONS):
        counts = per_label_counts[category]
        precision = _safe_div(counts["tp"], counts["tp"] + counts["fp"])
        recall = _safe_div(counts["tp"], counts["tp"] + counts["fn"])
        summary[category] = {
            "support": counts["tp"] + counts["fn"],
            "precision": precision,
            "recall": recall,
            "f1": _f1(precision, recall),
            "tp": counts["tp"],
            "fp": counts["fp"],
            "fn": counts["fn"],
        }
    return summary


def _span_summary(total_counts: Counter, per_label_counts: dict[str, Counter]) -> dict[str, object]:
    precision = _safe_div(total_counts["tp"], total_counts["tp"] + total_counts["fp"])
    recall = _safe_div(total_counts["tp"], total_counts["tp"] + total_counts["fn"])
    return {
        "micro_precision": precision,
        "micro_recall": recall,
        "micro_f1": _f1(precision, recall),
        "tp": total_counts["tp"],
        "fp": total_counts["fp"],
        "fn": total_counts["fn"],
        "per_label": _summarize_per_label(per_label_counts),
    }


def evaluate(
    rows: list[dict],
    model: GLiNER2,
    threshold: float,
    max_len: int | None = None,
) -> dict[str, object]:
    schema = _build_schema()
    request_counts: Counter = Counter()
    raw_span_counts: Counter = Counter()
    gated_span_counts: Counter = Counter()
    raw_per_label_counts: dict[str, Counter] = defaultdict(Counter)
    gated_per_label_counts: dict[str, Counter] = defaultdict(Counter)
    source_counts: Counter = Counter()
    examples: list[dict[str, object]] = []

    progress = tqdm(rows, desc=f"Evaluating @ {threshold:.2f}", unit="row")
    for index, row in enumerate(progress):
        gold = _as_spans(row["label"])
        gold_safety = _request_safety(row)
        payload = model.extract(
            str(row["text"]),
            schema,
            threshold=threshold,
            include_spans=True,
            include_confidence=True,
            max_len=max_len,
        )
        raw_predicted = _normalize_predictions(payload)
        predicted_safety = _normalize_request_safety_prediction(
            payload,
            fallback_label="suspicious" if raw_predicted else "safe",
        )
        source_counts[predicted_safety.source] += 1
        gated_predicted = raw_predicted if predicted_safety.label == "suspicious" else set()

        if gold_safety == "suspicious" and predicted_safety.label == "suspicious":
            request_counts["tp"] += 1
        elif gold_safety == "safe" and predicted_safety.label == "suspicious":
            request_counts["fp"] += 1
        elif gold_safety == "suspicious" and predicted_safety.label == "safe":
            request_counts["fn"] += 1
        else:
            request_counts["tn"] += 1

        _update_span_counts(gold, raw_predicted, total_counts=raw_span_counts, per_label_counts=raw_per_label_counts)
        _update_span_counts(gold, gated_predicted, total_counts=gated_span_counts, per_label_counts=gated_per_label_counts)

        raw_hits = gold & raw_predicted
        raw_extra = raw_predicted - gold
        raw_missed = gold - raw_predicted
        gated_hits = gold & gated_predicted
        gated_extra = gated_predicted - gold
        gated_missed = gold - gated_predicted

        if len(examples) < 8 and (
            predicted_safety.label != gold_safety or gated_extra or gated_missed
        ):
            examples.append(
                {
                    "row_index": index,
                    "gold_safety": gold_safety,
                    "predicted_safety": predicted_safety.label,
                    "prediction_source": predicted_safety.source,
                    "prediction_confidence": round(predicted_safety.confidence, 4),
                    "text": row["text"],
                    "gold": [span.__dict__ for span in sorted(gold, key=lambda s: (s.start, s.end, s.category))],
                    "raw_predicted": [
                        span.__dict__ for span in sorted(raw_predicted, key=lambda s: (s.start, s.end, s.category))
                    ],
                    "gated_predicted": [
                        span.__dict__ for span in sorted(gated_predicted, key=lambda s: (s.start, s.end, s.category))
                    ],
                    "raw_tp": len(raw_hits),
                    "raw_fp": len(raw_extra),
                    "raw_fn": len(raw_missed),
                    "gated_tp": len(gated_hits),
                    "gated_fp": len(gated_extra),
                    "gated_fn": len(gated_missed),
                }
            )

        if (index + 1) % 50 == 0:
            request_precision = _safe_div(request_counts["tp"], request_counts["tp"] + request_counts["fp"])
            request_recall = _safe_div(request_counts["tp"], request_counts["tp"] + request_counts["fn"])
            gated_precision = _safe_div(gated_span_counts["tp"], gated_span_counts["tp"] + gated_span_counts["fp"])
            gated_recall = _safe_div(gated_span_counts["tp"], gated_span_counts["tp"] + gated_span_counts["fn"])
            progress.set_postfix(
                request_f1=f"{_f1(request_precision, request_recall):.4f}",
                gated_f1=f"{_f1(gated_precision, gated_recall):.4f}",
                raw_f1=f"{_f1(_safe_div(raw_span_counts['tp'], raw_span_counts['tp'] + raw_span_counts['fp']), _safe_div(raw_span_counts['tp'], raw_span_counts['tp'] + raw_span_counts['fn'])):.4f}",
            )

    progress.close()

    request_precision = _safe_div(request_counts["tp"], request_counts["tp"] + request_counts["fp"])
    request_recall = _safe_div(request_counts["tp"], request_counts["tp"] + request_counts["fn"])
    request_f1 = _f1(request_precision, request_recall)
    request_accuracy = _safe_div(
        request_counts["tp"] + request_counts["tn"],
        request_counts["tp"] + request_counts["tn"] + request_counts["fp"] + request_counts["fn"],
    )

    return {
        "threshold": threshold,
        "request_safety": {
            "precision": request_precision,
            "recall": request_recall,
            "f1": request_f1,
            "accuracy": request_accuracy,
            "tp": request_counts["tp"],
            "fp": request_counts["fp"],
            "fn": request_counts["fn"],
            "tn": request_counts["tn"],
            "prediction_sources": dict(source_counts),
        },
        "gated_spans": _span_summary(gated_span_counts, gated_per_label_counts),
        "raw_spans": _span_summary(raw_span_counts, raw_per_label_counts),
        "error_examples": examples,
    }


def render_markdown(model_name: str, dataset_path: Path, results: list[dict[str, object]]) -> str:
    lines = [
        "# GLiNER2 baseline evaluation",
        "",
        f"- Model: `{model_name}`",
        f"- Dataset: `{dataset_path}`",
        "- Primary metric: request-safety gated span F1.",
        "",
        "| threshold | request_f1 | request_acc | gated_f1 | gated_precision | gated_recall | raw_f1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for result in results:
        request_safety = result["request_safety"]
        gated = result["gated_spans"]
        raw = result["raw_spans"]
        lines.append(
            "| "
            f"{result['threshold']:.2f} | "
            f"{request_safety['f1']:.4f} | "
            f"{request_safety['accuracy']:.4f} | "
            f"{gated['micro_f1']:.4f} | "
            f"{gated['micro_precision']:.4f} | "
            f"{gated['micro_recall']:.4f} | "
            f"{raw['micro_f1']:.4f} |"
        )

    best = max(results, key=lambda item: (item["gated_spans"]["micro_f1"], item["request_safety"]["f1"]))
    request_safety = best["request_safety"]
    gated = best["gated_spans"]
    raw = best["raw_spans"]
    lines.extend(
        [
            "",
            f"Best threshold: `{best['threshold']:.2f}` with gated span F1 `{gated['micro_f1']:.4f}`.",
            "",
            "## Request Safety",
            "",
            f"- Precision: `{request_safety['precision']:.4f}`",
            f"- Recall: `{request_safety['recall']:.4f}`",
            f"- F1: `{request_safety['f1']:.4f}`",
            f"- Accuracy: `{request_safety['accuracy']:.4f}`",
            f"- TP: `{request_safety['tp']}`",
            f"- FP: `{request_safety['fp']}`",
            f"- FN: `{request_safety['fn']}`",
            f"- TN: `{request_safety['tn']}`",
            "",
            "## Span Metrics",
            "",
            f"- Gated micro precision: `{gated['micro_precision']:.4f}`",
            f"- Gated micro recall: `{gated['micro_recall']:.4f}`",
            f"- Gated micro F1: `{gated['micro_f1']:.4f}`",
            f"- Raw micro F1: `{raw['micro_f1']:.4f}`",
            "",
            "| label | support | gated_precision | gated_recall | gated_f1 | raw_f1 |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for category, stats in gated["per_label"].items():
        raw_stats = raw["per_label"][category]
        lines.append(
            "| "
            f"{category} | {stats['support']} | {stats['precision']:.4f} | "
            f"{stats['recall']:.4f} | {stats['f1']:.4f} | {raw_stats['f1']:.4f} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a GLiNER2 model on the suspicious MCP request span dataset.")
    parser.add_argument("--model-name", default="fastino/gliner2-large-v1")
    parser.add_argument(
        "--dataset-path",
        type=Path,
        default=Path("data/mcp_suspicious_requests_hf_v5_span_curated/test.json"),
    )
    parser.add_argument("--thresholds", type=float, nargs="+", default=[0.3, 0.4, 0.5])
    parser.add_argument("--max-len", type=int, default=None)
    parser.add_argument("--report-json", type=Path, default=Path("reports/gliner2_v5_base_test.json"))
    parser.add_argument("--report-md", type=Path, default=Path("reports/gliner2_v5_base_test.md"))
    args = parser.parse_args()

    rows = _load_rows(args.dataset_path)
    model = _load_model(args.model_name)

    results = []
    for threshold in args.thresholds:
        print(f"Starting threshold={threshold:.2f} on {len(rows)} rows")
        results.append(evaluate(rows, model, threshold=threshold, max_len=args.max_len))

    args.report_json.parent.mkdir(parents=True, exist_ok=True)
    args.report_md.parent.mkdir(parents=True, exist_ok=True)
    args.report_json.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    args.report_md.write_text(render_markdown(args.model_name, args.dataset_path, results), encoding="utf-8")

    best = max(results, key=lambda item: (item["gated_spans"]["micro_f1"], item["request_safety"]["f1"]))
    print(
        f"best_threshold={best['threshold']:.2f} "
        f"request_f1={best['request_safety']['f1']:.4f} "
        f"gated_f1={best['gated_spans']['micro_f1']:.4f} "
        f"raw_f1={best['raw_spans']['micro_f1']:.4f}"
    )
    print(f"Saved JSON report to {args.report_json}")
    print(f"Saved Markdown report to {args.report_md}")


if __name__ == "__main__":
    main()
