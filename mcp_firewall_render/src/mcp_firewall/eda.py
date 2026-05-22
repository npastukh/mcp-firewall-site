from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader)


def summarize(rows: list[dict[str, str]]) -> str:
    total_records = len(rows)
    label_counts = Counter(row["label"] for row in rows)
    decision_counts = Counter(row["decision"] for row in rows)
    scenario_counts = Counter(row["scenario_type"] for row in rows)

    payload_by_label: dict[str, list[int]] = defaultdict(list)
    latency_by_label: dict[str, list[int]] = defaultdict(list)
    risk_by_decision: dict[str, list[float]] = defaultdict(list)
    tool_by_label: dict[str, Counter[str]] = defaultdict(Counter)

    for row in rows:
        label = row["label"]
        decision = row["decision"]
        tool_name = row["tool_name"] or "<none>"
        payload_by_label[label].append(int(row["payload_size"]))
        latency_by_label[label].append(int(row["response_time_ms"]))
        risk_by_decision[decision].append(float(row["risk_score"]))
        tool_by_label[label][tool_name] += 1

    lines: list[str] = []
    lines.append("# EDA Summary")
    lines.append("")
    lines.append(f"- Total records: {total_records}")
    lines.append("- Label distribution:")
    for label, count in sorted(label_counts.items()):
        share = count / total_records if total_records else 0
        lines.append(f"  - {label}: {count} ({share:.1%})")
    lines.append("- Firewall decisions:")
    for decision, count in sorted(decision_counts.items()):
        share = count / total_records if total_records else 0
        lines.append(f"  - {decision}: {count} ({share:.1%})")
    lines.append("- Scenario types:")
    for scenario, count in sorted(scenario_counts.items()):
        lines.append(f"  - {scenario}: {count}")
    lines.append("")
    lines.append("## Numeric summaries")
    lines.append("")
    lines.append("| Group | Avg payload size | Avg response time, ms |")
    lines.append("| --- | ---: | ---: |")
    for label in sorted(payload_by_label):
        lines.append(
            f"| {label} | {mean(payload_by_label[label]):.1f} | {mean(latency_by_label[label]):.1f} |"
        )
    lines.append("")
    lines.append("| Decision | Avg risk score |")
    lines.append("| --- | ---: |")
    for decision in sorted(risk_by_decision):
        lines.append(f"| {decision} | {mean(risk_by_decision[decision]):.3f} |")
    lines.append("")
    lines.append("## Most frequent tools by label")
    lines.append("")
    for label in sorted(tool_by_label):
        lines.append(f"### {label}")
        for tool_name, count in tool_by_label[label].most_common(3):
            lines.append(f"- {tool_name}: {count}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    dataset_path = project_root / "data" / "synthetic_mcp_events.csv"
    report_path = project_root / "reports" / "eda_summary.md"

    rows = load_rows(dataset_path)
    summary = summarize(rows)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(summary, encoding="utf-8")

    print(f"EDA summary written to {report_path}")


if __name__ == "__main__":
    main()
