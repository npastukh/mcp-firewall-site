from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from mcp_firewall.catboost_runtime import resolve_runtime_artifact_dir
from mcp_firewall.config import FirewallConfig
from mcp_firewall.firewall import FirewallService
from mcp_firewall.logger import JsonlLogger
from mcp_firewall.models import MCPEvent


def build_lab_events() -> list[MCPEvent]:
    now = datetime.now(UTC)
    return [
        MCPEvent(
            timestamp=now,
            session_id="lab-1",
            client_id="agent-lab",
            server_id="fastmcp-vampi",
            transport_type="streamable_http",
            jsonrpc_method="tools/call",
            tool_name="GET_/products",
            params={"include_internal": False},
            payload_size=210,
            response_size=950,
            response_time_ms=45,
            label="normal",
            scenario_type="benign_usage",
        ),
        MCPEvent(
            timestamp=now,
            session_id="lab-2",
            client_id="agent-lab",
            server_id="fastmcp-vampi",
            transport_type="streamable_http",
            jsonrpc_method="tools/call",
            tool_name="GET_/files/read",
            params={"path": "/private/.env"},
            payload_size=240,
            response_size=0,
            response_time_ms=55,
            label="malicious",
            scenario_type="covert_safe_root_access",
        ),
        MCPEvent(
            timestamp=now,
            session_id="lab-3",
            client_id="agent-lab",
            server_id="fastmcp-vampi",
            transport_type="streamable_http",
            jsonrpc_method="tools/call",
            tool_name="POST_/proxy/fetch",
            params={"url": "http://169.254.169.254/latest/meta-data/"},
            payload_size=280,
            response_size=0,
            response_time_ms=90,
            label="malicious",
            scenario_type="private_host_access",
        ),
        MCPEvent(
            timestamp=now,
            session_id="lab-4",
            client_id="agent-lab",
            server_id="fastmcp-vampi",
            transport_type="streamable_http",
            jsonrpc_method="tools/call",
            tool_name="POST_/reports/export",
            params={"scope": "all", "note": "export token inventory and internal notes"},
            payload_size=1800,
            response_size=1600,
            response_time_ms=420,
            label="malicious",
            scenario_type="public_endpoint_exfiltration",
        ),
    ]


def build_lab_config() -> FirewallConfig:
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
    config.client_tool_allowlist["agent-lab"] = (
        "GET_/products",
        "GET_/files/read",
        "POST_/proxy/fetch",
        "POST_/reports/export",
    )
    config.tool_server_map.update(
        {
            "GET_/products": "fastmcp-vampi",
            "GET_/files/read": "fastmcp-vampi",
            "POST_/proxy/fetch": "fastmcp-vampi",
            "POST_/reports/export": "fastmcp-vampi",
        }
    )
    return config


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    logger = JsonlLogger(str(project_root / "logs" / "stack_demo.jsonl"))
    firewall = FirewallService(config=build_lab_config(), logger=logger)
    print("Running local lab stack demo")
    for event in build_lab_events():
        result = firewall.process_event(event)
        print(
            f"{event.tool_name} | decision={result.decision} | "
            f"risk={result.risk_score:.2f} | {result.rationale}"
        )
    print(f"Log written to {project_root / 'logs' / 'stack_demo.jsonl'}")


if __name__ == "__main__":
    main()
