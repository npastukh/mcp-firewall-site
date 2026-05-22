from __future__ import annotations

from datetime import datetime, timedelta, UTC
from pathlib import Path

from mcp_firewall.catboost_runtime import resolve_runtime_artifact_dir
from mcp_firewall.config import FirewallConfig
from mcp_firewall.firewall import FirewallService
from mcp_firewall.logger import JsonlLogger
from mcp_firewall.models import MCPEvent


def demo_events() -> list[MCPEvent]:
    base = datetime.now(UTC)
    return [
        MCPEvent(
            timestamp=base,
            session_id="session-1",
            client_id="agent-1",
            server_id="filesystem-server",
            transport_type="stdio",
            jsonrpc_method="tools/call",
            tool_name="filesystem.read_file",
            params={"path": "/workspace/project/readme.txt"},
            payload_size=180,
            response_size=1_200,
            response_time_ms=45,
            label="normal",
        ),
        MCPEvent(
            timestamp=base + timedelta(seconds=2),
            session_id="session-1",
            client_id="agent-1",
            server_id="filesystem-server",
            transport_type="stdio",
            jsonrpc_method="tools/call",
            tool_name="filesystem.read_file",
            params={"path": "/etc/passwd"},
            payload_size=160,
            response_size=0,
            response_time_ms=30,
            label="malicious",
        ),
        MCPEvent(
            timestamp=base + timedelta(seconds=5),
            session_id="session-2",
            client_id="agent-2",
            server_id="http-server",
            transport_type="streamable_http",
            jsonrpc_method="tools/call",
            tool_name="web.fetch",
            params={"url": "http://169.254.169.254/latest/meta-data/"},
            payload_size=240,
            response_size=0,
            response_time_ms=90,
            label="malicious",
        ),
        MCPEvent(
            timestamp=base + timedelta(seconds=7),
            session_id="session-3",
            client_id="agent-3",
            server_id="filesystem-server",
            transport_type="stdio",
            jsonrpc_method="tools/call",
            tool_name="filesystem.search",
            params={
                "query": "find token secrets password in deployment config",
                "path": "/workspace/project/config",
            },
            payload_size=9_500,
            response_size=500,
            response_time_ms=2_300,
            label="anomalous",
        ),
    ]


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    runtime_artifact_dir = resolve_runtime_artifact_dir(project_root)
    candidate_paths = (
        project_root / "artifacts" / "gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1" / "best",
        project_root / "artifacts" / "gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1" / "final",
    )
    model_path = next((path for path in candidate_paths if path.exists()), candidate_paths[0])
    config = FirewallConfig(
        supervised_runtime_enabled=runtime_artifact_dir is not None,
        supervised_model_path=str(runtime_artifact_dir) if runtime_artifact_dir else None,
        full_context_evaluator_enabled=model_path.exists(),
        full_context_model_path=str(model_path) if model_path.exists() else None,
        full_context_max_length=128,
        full_context_extraction_threshold=0.80,
    )
    logger = JsonlLogger(str(project_root / config.logs_dir / "demo_events.jsonl"))
    firewall = FirewallService(config=config, logger=logger)

    print("Running MCP firewall demo")
    print("-" * 72)
    for event in demo_events():
        result = firewall.process_event(event)
        print(
            f"{event.session_id} | {event.tool_name or event.jsonrpc_method} | "
            f"decision={result.decision} | risk={result.risk_score:.2f} | {result.rationale}"
        )
    print("-" * 72)
    print(f"Log written to {project_root / config.logs_dir / 'demo_events.jsonl'}")


if __name__ == "__main__":
    main()
