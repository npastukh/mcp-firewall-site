from __future__ import annotations

import argparse
import json
import random
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path

from mcp_firewall.mcp_gliner_v5_schema import (
    V5_CLASSIFICATION_LABELS,
    V5_ENTITY_DESCRIPTIONS,
    V5_SPAN_LABELS,
    row_combo_key,
    validate_v5_span_row,
)


SAFE_TEMPLATE_QUOTAS = {
    "safe_docs": 160,
    "safe_config_review": 160,
    "safe_public_reference": 160,
    "safe_schema_discussion": 160,
    "safe_benign_mcp": 160,
}

SUSPICIOUS_TEMPLATE_QUOTAS = {
    "private_host_only": 110,
    "secret_store_ref_only": 80,
    "secret_name_sensitive_path": 100,
    "env_access_secret_value": 80,
    "env_access_secret_name": 80,
    "secret_store_ref_secret_value": 90,
    "sensitive_path_only": 90,
    "secret_value_only": 80,
    "private_host_secret_store_ref": 60,
    "private_host_secret_name": 40,
    "env_access_sensitive_path": 80,
    "secret_name_only": 60,
    "env_access_only": 50,
}

TRAIN_SIZE = 9000
VALIDATION_SIZE = 1800
TEST_SIZE = 1800
EVAL_MAX_ROWS_PER_SKELETON = 1
TRAIN_MAX_ROWS_PER_SKELETON = 6

NORMALIZE_WS_RE = re.compile(r"\s+")
URL_RE = re.compile(r"https?://[^\s\"']+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
NUMBER_RE = re.compile(r"\b\d{2,}\b")
STRING_RE = re.compile(r'"[^"\n]{3,}"')
SINGLE_STRING_RE = re.compile(r"'[^'\n]{3,}'")


def _load_rows(path: Path) -> list[dict]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"expected JSON array in {path}")
    for row in raw:
        validate_v5_span_row(row)
    return raw


def _write_rows(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _normalize_text(text: str) -> str:
    return " ".join(str(text).lower().split())


def _skeletonize_text(text: str) -> str:
    value = str(text).lower()
    value = URL_RE.sub("<url>", value)
    value = IP_RE.sub("<ip>", value)
    value = NUMBER_RE.sub("<num>", value)
    value = STRING_RE.sub('"<str>"', value)
    value = SINGLE_STRING_RE.sub("'<str>'", value)
    return NORMALIZE_WS_RE.sub(" ", value).strip()


def _template_family(row: dict) -> str:
    return str(row.get("info", {}).get("template_family", "unknown"))


def _request_safety(row: dict) -> str:
    return str(row.get("info", {}).get("request_safety", ""))


def _source_type(row: dict) -> str:
    return str(row.get("info", {}).get("source_type", ""))


def _semantic_skeleton(row: dict) -> str:
    info = row.get("info", {})
    semantic = str(info.get("semantic_skeleton", "")).strip()
    if semantic:
        return semantic
    return f"{_template_family(row)}::{_skeletonize_text(str(row['text']))}"


def _row_label_counts(rows: list[dict]) -> Counter:
    counts: Counter = Counter()
    for row in rows:
        for label_name in sorted({str(label["category"]) for label in row.get("label", [])}):
            counts[label_name] += 1
    return counts


def _row_combo_counts(rows: list[dict]) -> Counter:
    counts: Counter = Counter()
    for row in rows:
        combo = row_combo_key(row)
        if combo:
            counts[combo] += 1
    return counts


def _group_key(row: dict) -> str:
    return _semantic_skeleton(row)


def _group_rows(rows: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[_group_key(row)].append(row)
    return grouped


def _build_family_pools(rows: list[dict], *, seed: int) -> dict[str, list[list[dict]]]:
    rng = random.Random(seed)
    pools: dict[str, list[list[dict]]] = defaultdict(list)
    for group_rows in _group_rows(rows).values():
        family = _template_family(group_rows[0])
        group_rows = list(group_rows)
        rng.shuffle(group_rows)
        pools[family].append(group_rows)
    for groups in pools.values():
        rng.shuffle(groups)
    return pools


def _select_family_rows(
    family_groups: list[list[dict]],
    *,
    quota: int,
    max_per_group: int,
) -> tuple[list[dict], list[list[dict]]]:
    selected: list[dict] = []
    leftover_groups: list[list[dict]] = []
    remaining = quota
    for group_rows in family_groups:
        if remaining <= 0:
            leftover_groups.append(group_rows)
            continue
        take = min(remaining, max_per_group, len(group_rows))
        selected.extend(group_rows[:take])
        remaining -= take
        if take < len(group_rows):
            # Reserve the whole skeleton for this split by discarding the unused tail.
            continue
    if remaining > 0:
        raise ValueError(f"unable to satisfy family quota {quota}")
    return selected, leftover_groups


def _weighted_targets(available_counts: Counter, target_size: int) -> Counter:
    total = sum(available_counts.values())
    if total < target_size:
        raise ValueError(f"insufficient rows for target size {target_size}: {total}")
    raw_targets = {family: target_size * count / total for family, count in available_counts.items()}
    targets = Counter({family: int(value) for family, value in raw_targets.items()})
    remaining = target_size - sum(targets.values())
    if remaining <= 0:
        return targets
    remainders = sorted(
        ((raw_targets[family] - targets[family], family) for family in available_counts),
        reverse=True,
    )
    for _, family in remainders:
        if remaining <= 0:
            break
        if targets[family] >= available_counts[family]:
            continue
        targets[family] += 1
        remaining -= 1
    return targets


def _select_train_family_rows(
    family_groups: list[list[dict]],
    *,
    quota: int,
) -> list[dict]:
    selected: list[dict] = []
    capped_groups = [list(group_rows[:TRAIN_MAX_ROWS_PER_SKELETON]) for group_rows in family_groups if group_rows]
    while len(selected) < quota:
        made_progress = False
        for group_rows in capped_groups:
            if len(selected) >= quota:
                break
            if not group_rows:
                continue
            selected.append(group_rows.pop(0))
            made_progress = True
        if not made_progress:
            raise ValueError(f"unable to satisfy train family quota {quota}")
    return selected


def _select_train_rows(rows: list[dict], *, seed: int, target_size: int) -> list[dict]:
    rng = random.Random(seed)
    by_family_groups: dict[str, list[list[dict]]] = defaultdict(list)
    for group_rows in _group_rows(rows).values():
        shuffled = list(group_rows)
        rng.shuffle(shuffled)
        by_family_groups[_template_family(shuffled[0])].append(shuffled)
    for family_groups in by_family_groups.values():
        rng.shuffle(family_groups)
    available_counts = Counter(
        {
            family: sum(min(len(group_rows), TRAIN_MAX_ROWS_PER_SKELETON) for group_rows in family_groups)
            for family, family_groups in by_family_groups.items()
        }
    )
    targets = _weighted_targets(available_counts, target_size)
    selected: list[dict] = []
    for family, quota in targets.items():
        selected.extend(_select_train_family_rows(by_family_groups[family], quota=quota))
    rng.shuffle(selected)
    return selected


def _semantic_duplicate_count(rows: list[dict]) -> int:
    counts = Counter(_semantic_skeleton(row) for row in rows)
    return sum(count - 1 for count in counts.values() if count > 1)


def _max_skeleton_frequency(rows: list[dict]) -> int:
    counts = Counter(_semantic_skeleton(row) for row in rows)
    return max(counts.values(), default=0)


def _render_split_report(train_rows: list[dict], validation_rows: list[dict], test_rows: list[dict]) -> str:
    lines = ["# MCP GLiNER V5 Span Split Report", ""]
    for split_name, rows in (("train", train_rows), ("validation", validation_rows), ("test", test_rows)):
        safety_counts = Counter(_request_safety(row) for row in rows)
        template_counts = Counter(_template_family(row) for row in rows)
        source_type_counts = Counter(_source_type(row) for row in rows)
        row_label_counts = _row_label_counts(rows)
        combo_counts = _row_combo_counts(rows)
        semantic_duplicates = _semantic_duplicate_count(rows)
        max_skeleton_frequency = _max_skeleton_frequency(rows)
        unique_skeletons = len({_semantic_skeleton(row) for row in rows})
        lines.extend(
            [
                f"## {split_name.title()}",
                "",
                f"- Rows: `{len(rows)}`",
                f"- Unique semantic skeletons: `{unique_skeletons}`",
                f"- Semantic duplicates: `{semantic_duplicates}`",
                f"- Max rows per semantic skeleton: `{max_skeleton_frequency}`",
                "",
                "### Request Safety",
                "",
            ]
        )
        for key, value in safety_counts.most_common():
            lines.append(f"- `{key}`: `{value}`")
        lines.extend(["", "### Source Types", ""])
        for key, value in source_type_counts.most_common():
            lines.append(f"- `{key}`: `{value}`")
        lines.extend(["", "### Template Families", ""])
        for key, value in template_counts.most_common():
            lines.append(f"- `{key}`: `{value}`")
        lines.extend(["", "### Row Label Support", ""])
        for key in V5_SPAN_LABELS:
            lines.append(f"- `{key}`: `{row_label_counts.get(key, 0)}`")
        lines.extend(["", "### Top Combos", ""])
        for combo, value in combo_counts.most_common(12):
            lines.append(f"- `{combo}`: `{value}`")
        lines.append("")
    return "\n".join(lines)


def build_v5_span_splits(rows: list[dict], *, seed: int = 42) -> tuple[list[dict], list[dict], list[dict]]:
    family_pools = _build_family_pools(rows, seed=seed)

    validation_rows: list[dict] = []
    for family, quota in {**SAFE_TEMPLATE_QUOTAS, **SUSPICIOUS_TEMPLATE_QUOTAS}.items():
        chosen, leftover = _select_family_rows(
            family_pools.get(family, []),
            quota=quota,
            max_per_group=EVAL_MAX_ROWS_PER_SKELETON,
        )
        validation_rows.extend(chosen)
        family_pools[family] = leftover

    test_rows: list[dict] = []
    for family, quota in {**SAFE_TEMPLATE_QUOTAS, **SUSPICIOUS_TEMPLATE_QUOTAS}.items():
        chosen, leftover = _select_family_rows(
            family_pools.get(family, []),
            quota=quota,
            max_per_group=EVAL_MAX_ROWS_PER_SKELETON,
        )
        test_rows.extend(chosen)
        family_pools[family] = leftover

    remaining_rows = [row for groups in family_pools.values() for group_rows in groups for row in group_rows]
    train_rows = _select_train_rows(remaining_rows, seed=seed + 101, target_size=TRAIN_SIZE)

    if len(validation_rows) != VALIDATION_SIZE:
        raise ValueError(f"unexpected validation size: {len(validation_rows)} != {VALIDATION_SIZE}")
    if len(test_rows) != TEST_SIZE:
        raise ValueError(f"unexpected test size: {len(test_rows)} != {TEST_SIZE}")
    if len(train_rows) != TRAIN_SIZE:
        raise ValueError(f"unexpected train size: {len(train_rows)} != {TRAIN_SIZE}")
    return train_rows, validation_rows, test_rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build clean v5 GLiNER span splits from the source pool.")
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path("data/mcp_suspicious_requests_hf_v5_span_source"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/mcp_suspicious_requests_hf_v5_span_curated"),
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=Path("reports/mcp_gliner_v5_span_split_report.md"),
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rows = _load_rows(args.source_dir / "source_pool.json")
    train_rows, validation_rows, test_rows = build_v5_span_splits(rows, seed=args.seed)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write_rows(args.output_dir / "train.json", train_rows)
    _write_rows(args.output_dir / "validation.json", validation_rows)
    _write_rows(args.output_dir / "test.json", test_rows)

    source_schema = args.source_dir / "label_schema.json"
    if source_schema.exists():
        target_schema = args.output_dir / "label_schema.json"
        if source_schema.resolve() != target_schema.resolve():
            shutil.copy2(source_schema, target_schema)

    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.write_text(_render_split_report(train_rows, validation_rows, test_rows), encoding="utf-8")

    print(f"train_rows: {len(train_rows)}")
    print(f"validation_rows: {len(validation_rows)}")
    print(f"test_rows: {len(test_rows)}")
    print(f"output_dir: {args.output_dir}")
    print(f"report: {args.report_path}")


if __name__ == "__main__":
    main()
