from __future__ import annotations

import argparse
from pathlib import Path

from mcp_firewall.eda import summarize
from mcp_firewall.export_dashboard_data import build_dashboard_payload, load_evaluation_payload
from mcp_firewall.generate_dataset import build_dataset, write_csv, write_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build dataset, EDA report, and dashboard data.")
    parser.add_argument("--records", type=int, default=300, help="Number of synthetic events to generate.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parents[2]

    rows = build_dataset(records=args.records, seed=args.seed)

    csv_path = project_root / "data" / "synthetic_mcp_events.csv"
    jsonl_path = project_root / "data" / "synthetic_mcp_events.jsonl"
    report_path = project_root / "reports" / "eda_summary.md"
    dashboard_path = project_root / "data" / "dashboard.json"

    write_csv(rows, csv_path)
    write_jsonl(rows, jsonl_path)

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(summarize([{key: str(value) for key, value in row.items()} for row in rows]), encoding="utf-8")

    dashboard_payload = build_dashboard_payload(
        [{key: str(value) for key, value in row.items()} for row in rows],
        load_evaluation_payload(project_root),
    )
    serialized = __import__("json").dumps(dashboard_payload, ensure_ascii=False, indent=2)
    dashboard_path.parent.mkdir(parents=True, exist_ok=True)
    dashboard_path.write_text(serialized, encoding="utf-8")

    print(f"Dataset CSV: {csv_path}")
    print(f"Dataset JSONL: {jsonl_path}")
    print(f"EDA report: {report_path}")
    print(f"Dashboard JSON: {dashboard_path}")


if __name__ == "__main__":
    main()
