from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from mcp_firewall.build_mcp_v5_splits import (
    EVAL_MAX_ROWS_PER_SKELETON,
    TRAIN_MAX_ROWS_PER_SKELETON,
    _normalize_text,
    _skeletonize_text,
)
from mcp_firewall.mcp_gliner_v5_schema import V5_SPAN_LABELS, row_combo_key, validate_v5_span_row


def _load_rows(path: Path) -> list[dict]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"expected JSON array in {path}")
    for row in raw:
        validate_v5_span_row(row)
    return raw


def _request_safety(row: dict) -> str:
    return str(row.get("info", {}).get("request_safety", ""))


def _template_family(row: dict) -> str:
    return str(row.get("info", {}).get("template_family", "unknown"))


def _family_skeleton_key(row: dict) -> str:
    return f"{_template_family(row)}::{_skeletonize_text(str(row['text']))}"


def _semantic_skeleton_key(row: dict) -> str:
    semantic = str(row.get("info", {}).get("semantic_skeleton", "")).strip()
    if semantic:
        return semantic
    return _family_skeleton_key(row)


def _count_suspicious_empty(rows: list[dict]) -> int:
    return sum(1 for row in rows if _request_safety(row) == "suspicious" and not row.get("label"))


def _count_safe_labeled(rows: list[dict]) -> int:
    return sum(1 for row in rows if _request_safety(row) == "safe" and row.get("label"))


def _count_exact_duplicates(rows: list[dict]) -> int:
    seen: set[str] = set()
    duplicates = 0
    for row in rows:
        key = _normalize_text(str(row["text"]))
        if key in seen:
            duplicates += 1
        seen.add(key)
    return duplicates


def _semantic_duplicate_count(rows: list[dict]) -> int:
    counts = Counter(_semantic_skeleton_key(row) for row in rows)
    return sum(count - 1 for count in counts.values() if count > 1)


def _max_skeleton_frequency(rows: list[dict]) -> int:
    counts = Counter(_semantic_skeleton_key(row) for row in rows)
    return max(counts.values(), default=0)


def _top_repeated_skeletons(rows: list[dict], *, limit: int = 10) -> list[tuple[str, int]]:
    counts = Counter(_semantic_skeleton_key(row) for row in rows)
    return [(key, value) for key, value in counts.most_common(limit) if value > 1]


def _cross_split_overlap(left: list[dict], right: list[dict], *, key_fn) -> int:
    left_keys = {key_fn(row) for row in left}
    right_keys = {key_fn(row) for row in right}
    return len(left_keys & right_keys)


def _row_label_counts(rows: list[dict]) -> Counter:
    counts: Counter = Counter()
    for row in rows:
        for label_name in sorted({str(label["category"]) for label in row.get("label", [])}):
            counts[label_name] += 1
    return counts


def _span_label_counts(rows: list[dict]) -> Counter:
    counts: Counter = Counter()
    for row in rows:
        for label in row.get("label", []):
            counts[str(label["category"])] += 1
    return counts


def _combo_counts(rows: list[dict]) -> Counter:
    counts: Counter = Counter()
    for row in rows:
        combo = row_combo_key(row)
        if combo:
            counts[combo] += 1
    return counts


def _source_type_counts(rows: list[dict]) -> Counter:
    return Counter(str(row.get("info", {}).get("source_type", "")) for row in rows)


def _template_counts(rows: list[dict]) -> Counter:
    return Counter(str(row.get("info", {}).get("template_family", "")) for row in rows)


def _span_per_row(rows: list[dict]) -> Counter:
    return Counter(len(row.get("label", [])) for row in rows)


def _multi_sensitive_path_ratio(rows: list[dict]) -> float:
    if not rows:
        return 0.0
    multi = 0
    for row in rows:
        count = sum(1 for label in row.get("label", []) if str(label["category"]) == "sensitive_path")
        if count > 1:
            multi += 1
    return multi / len(rows)


def _label_divergence(validation_rows: list[dict], test_rows: list[dict]) -> dict[str, float]:
    validation_counts = _row_label_counts(validation_rows)
    test_counts = _row_label_counts(test_rows)
    divergence: dict[str, float] = {}
    for label_name in V5_SPAN_LABELS:
        validation_value = validation_counts.get(label_name, 0)
        test_value = test_counts.get(label_name, 0)
        if validation_value == 0:
            divergence[label_name] = 0.0
        else:
            divergence[label_name] = abs(test_value - validation_value) / validation_value
    return divergence


def _render_report(train_rows: list[dict], validation_rows: list[dict], test_rows: list[dict], failures: list[str]) -> str:
    lines = ["# MCP GLiNER V5 Span Audit", ""]
    if failures:
        lines.extend(["## Status", "", "- `FAILED`", ""])
    else:
        lines.extend(["## Status", "", "- `PASSED`", ""])

    for split_name, rows in (("train", train_rows), ("validation", validation_rows), ("test", test_rows)):
        safety_counts = Counter(_request_safety(row) for row in rows)
        row_label_counts = _row_label_counts(rows)
        span_label_counts = _span_label_counts(rows)
        combo_counts = _combo_counts(rows)
        template_counts = _template_counts(rows)
        semantic_duplicates = _semantic_duplicate_count(rows)
        max_skeleton_frequency = _max_skeleton_frequency(rows)
        unique_skeletons = len({_semantic_skeleton_key(row) for row in rows})
        lines.extend(
            [
                f"## {split_name.title()}",
                "",
                f"- Rows: `{len(rows)}`",
                f"- Suspicious empty: `{_count_suspicious_empty(rows)}`",
                f"- Safe labeled: `{_count_safe_labeled(rows)}`",
                f"- Exact duplicates: `{_count_exact_duplicates(rows)}`",
                f"- Unique semantic skeletons: `{unique_skeletons}`",
                f"- Semantic duplicates: `{semantic_duplicates}`",
                f"- Max rows per semantic skeleton: `{max_skeleton_frequency}`",
                f"- Multi sensitive_path ratio: `{_multi_sensitive_path_ratio(rows):.4f}`",
                "",
                "### Request Safety",
                "",
            ]
        )
        for key, value in safety_counts.most_common():
            lines.append(f"- `{key}`: `{value}`")
        lines.extend(["", "### Source Types", ""])
        for key, value in _source_type_counts(rows).most_common():
            lines.append(f"- `{key}`: `{value}`")
        lines.extend(["", "### Template Families", ""])
        for key, value in template_counts.most_common():
            lines.append(f"- `{key}`: `{value}`")
        lines.extend(["", "### Row Label Support", ""])
        for key in V5_SPAN_LABELS:
            lines.append(f"- `{key}`: `{row_label_counts.get(key, 0)}`")
        lines.extend(["", "### Span Label Support", ""])
        for key in V5_SPAN_LABELS:
            lines.append(f"- `{key}`: `{span_label_counts.get(key, 0)}`")
        lines.extend(["", "### Span Count Per Row", ""])
        for key, value in sorted(_span_per_row(rows).items()):
            lines.append(f"- `{key}`: `{value}`")
        lines.extend(["", "### Top Combos", ""])
        for combo, value in combo_counts.most_common(12):
            lines.append(f"- `{combo}`: `{value}`")
        repeated_skeletons = _top_repeated_skeletons(rows)
        lines.extend(["", "### Repeated Semantic Skeletons", ""])
        if repeated_skeletons:
            for skeleton, value in repeated_skeletons:
                lines.append(f"- `{skeleton}`: `{value}`")
        else:
            lines.append("- `none`")
        lines.append("")

    lines.extend(["## Cross-Split Overlap", ""])
    exact_checks = {
        "train_validation": _cross_split_overlap(train_rows, validation_rows, key_fn=lambda row: _normalize_text(str(row["text"]))),
        "train_test": _cross_split_overlap(train_rows, test_rows, key_fn=lambda row: _normalize_text(str(row["text"]))),
        "validation_test": _cross_split_overlap(validation_rows, test_rows, key_fn=lambda row: _normalize_text(str(row["text"]))),
    }
    skeleton_checks = {
        "train_validation": _cross_split_overlap(train_rows, validation_rows, key_fn=_semantic_skeleton_key),
        "train_test": _cross_split_overlap(train_rows, test_rows, key_fn=_semantic_skeleton_key),
        "validation_test": _cross_split_overlap(validation_rows, test_rows, key_fn=_semantic_skeleton_key),
    }
    for key, value in exact_checks.items():
        lines.append(f"- Exact `{key}`: `{value}`")
    for key, value in skeleton_checks.items():
        lines.append(f"- Skeleton `{key}`: `{value}`")

    lines.extend(["", "## Validation Vs Test Divergence", ""])
    for key, value in _label_divergence(validation_rows, test_rows).items():
        lines.append(f"- `{key}`: `{value:.4f}`")

    if failures:
        lines.extend(["", "## Failures", ""])
        for failure in failures:
            lines.append(f"- {failure}")
    lines.append("")
    return "\n".join(lines)


def _audit_failures(train_rows: list[dict], validation_rows: list[dict], test_rows: list[dict]) -> list[str]:
    failures: list[str] = []
    for split_name, rows in (("train", train_rows), ("validation", validation_rows), ("test", test_rows)):
        suspicious_empty = _count_suspicious_empty(rows)
        safe_labeled = _count_safe_labeled(rows)
        duplicates = _count_exact_duplicates(rows)
        semantic_duplicates = _semantic_duplicate_count(rows)
        max_skeleton_frequency = _max_skeleton_frequency(rows)
        multi_ratio = _multi_sensitive_path_ratio(rows)
        if suspicious_empty != 0:
            failures.append(f"{split_name}: suspicious_empty={suspicious_empty}")
        if safe_labeled != 0:
            failures.append(f"{split_name}: safe_labeled={safe_labeled}")
        if duplicates != 0:
            failures.append(f"{split_name}: exact_duplicates={duplicates}")
        if split_name == "train" and max_skeleton_frequency > TRAIN_MAX_ROWS_PER_SKELETON:
            failures.append(
                f"train: max_rows_per_semantic_skeleton={max_skeleton_frequency} > {TRAIN_MAX_ROWS_PER_SKELETON}"
            )
        if split_name in {"validation", "test"} and semantic_duplicates != 0:
            failures.append(f"{split_name}: semantic_duplicates={semantic_duplicates}")
        if split_name in {"validation", "test"} and max_skeleton_frequency > EVAL_MAX_ROWS_PER_SKELETON:
            failures.append(
                f"{split_name}: max_rows_per_semantic_skeleton={max_skeleton_frequency} > {EVAL_MAX_ROWS_PER_SKELETON}"
            )
        if split_name == "train" and multi_ratio > 0.10:
            failures.append(f"train: multi_sensitive_path_ratio={multi_ratio:.4f} > 0.10")
        if split_name in {"validation", "test"} and multi_ratio > 0.05:
            failures.append(f"{split_name}: multi_sensitive_path_ratio={multi_ratio:.4f} > 0.05")

    exact_overlap_checks = {
        "train_validation": _cross_split_overlap(train_rows, validation_rows, key_fn=lambda row: _normalize_text(str(row["text"]))),
        "train_test": _cross_split_overlap(train_rows, test_rows, key_fn=lambda row: _normalize_text(str(row["text"]))),
        "validation_test": _cross_split_overlap(validation_rows, test_rows, key_fn=lambda row: _normalize_text(str(row["text"]))),
    }
    for name, value in exact_overlap_checks.items():
        if value != 0:
            failures.append(f"exact_overlap[{name}]={value}")

    semantic_overlap_checks = {
        "train_validation": _cross_split_overlap(train_rows, validation_rows, key_fn=_semantic_skeleton_key),
        "train_test": _cross_split_overlap(train_rows, test_rows, key_fn=_semantic_skeleton_key),
        "validation_test": _cross_split_overlap(validation_rows, test_rows, key_fn=_semantic_skeleton_key),
    }
    for name, value in semantic_overlap_checks.items():
        if value != 0:
            failures.append(f"semantic_overlap[{name}]={value}")

    divergence = _label_divergence(validation_rows, test_rows)
    for label_name, value in divergence.items():
        if value > 0.10:
            failures.append(f"validation_test_divergence[{label_name}]={value:.4f}")
    return failures


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit the clean v5 GLiNER span dataset.")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("data/mcp_suspicious_requests_hf_v5_span_curated"),
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=Path("reports/mcp_gliner_v5_span_audit.md"),
    )
    parser.add_argument(
        "--json-path",
        type=Path,
        default=Path("reports/mcp_gliner_v5_span_audit.json"),
    )
    args = parser.parse_args()

    train_rows = _load_rows(args.dataset_dir / "train.json")
    validation_rows = _load_rows(args.dataset_dir / "validation.json")
    test_rows = _load_rows(args.dataset_dir / "test.json")

    failures = _audit_failures(train_rows, validation_rows, test_rows)
    report = _render_report(train_rows, validation_rows, test_rows, failures)
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.json_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.write_text(report, encoding="utf-8")
    args.json_path.write_text(json.dumps({"failures": failures}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"report: {args.report_path}")
    print(f"json: {args.json_path}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        raise SystemExit(1)
    print("audit: PASSED")


if __name__ == "__main__":
    main()
