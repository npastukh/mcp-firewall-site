from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict
from pathlib import Path

from mcp_firewall.config import FirewallConfig
from mcp_firewall.firewall import FirewallService
from mcp_firewall.models import MCPEvent
from mcp_firewall.synthetic_data import SyntheticDatasetGenerator


def build_dataset(records: int, seed: int) -> list[dict[str, object]]:
    config = FirewallConfig()
    firewall = FirewallService(config=config)
    generator = SyntheticDatasetGenerator(seed=seed)

    rows: list[dict[str, object]] = []
    for event in generator.generate(records):
        result = firewall.process_event(event)
        rows.append(_build_row(event, result))
    return rows


def _build_row(event: MCPEvent, result: object) -> dict[str, object]:
    analysis = result
    row: dict[str, object] = {
        "timestamp": event.timestamp.isoformat(),
        "session_id": event.session_id,
        "client_id": event.client_id,
        "server_id": event.server_id,
        "transport_type": event.transport_type,
        "jsonrpc_method": event.jsonrpc_method,
        "tool_name": event.tool_name or "",
        "payload_size": event.payload_size,
        "response_size": event.response_size,
        "response_time_ms": event.response_time_ms,
        "is_error": event.is_error,
        "error_code": event.error_code if event.error_code is not None else "",
        "label": event.label or "",
        "scenario_type": event.scenario_type or "",
        "decision": analysis.decision,
        "risk_score": round(analysis.risk_score, 4),
        "rule_match_count": len(analysis.rule_matches),
        "rule_names": ",".join(match.name for match in analysis.rule_matches),
        "rationale": analysis.rationale,
    }
    for key, value in analysis.features.items():
        row[f"feature_{key}"] = value
    return row


def write_csv(rows: list[dict[str, object]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(rows: list[dict[str, object]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a synthetic MCP firewall dataset.")
    parser.add_argument("--records", type=int, default=300, help="Number of events to generate.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parents[2]
    rows = build_dataset(records=args.records, seed=args.seed)

    csv_path = project_root / "data" / "synthetic_mcp_events.csv"
    jsonl_path = project_root / "data" / "synthetic_mcp_events.jsonl"
    write_csv(rows, csv_path)
    write_jsonl(rows, jsonl_path)

    print(f"Generated {len(rows)} events")
    print(f"CSV dataset: {csv_path}")
    print(f"JSONL dataset: {jsonl_path}")


if __name__ == "__main__":
    main()
