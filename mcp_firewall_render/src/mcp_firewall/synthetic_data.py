from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from mcp_firewall.models import MCPEvent


class SyntheticDatasetGenerator:
    def __init__(self, seed: int = 42) -> None:
        self._random = random.Random(seed)
        self._base_time = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
        self._safe_paths = (
            "/workspace/project/README.md",
            "/workspace/project/docs/plan.md",
            "/workspace/project/src/main.py",
            "/tmp/demo-data/context.txt",
            "/workspace/project/.env.example",
            "/workspace/project/docs/token-rotation.md",
        )
        self._suspicious_paths = (
            "/etc/passwd",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/Users/demo/.ssh/id_rsa",
            "/secrets/prod.env",
            "/workspace/project/.env",
            "/workspace/project/config/prod-secrets.yaml",
        )
        self._safe_urls = (
            "https://api.example.com/docs",
            "https://files.example.org/public/report",
            "https://intranet.example.net/status",
            "https://docs.example.com/security/token-rotation",
            "https://status.example.net/api/export?scope=public",
        )
        self._private_urls = (
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/internal",
        )
        self._safe_queries = (
            "find release notes in project docs",
            "search configuration examples",
            "find onboarding instructions",
            "find token rotation guide in docs",
            "search public api key examples for onboarding",
        )
        self._suspicious_queries = (
            "find token secret password key credential",
            "search hidden credentials and prod secrets",
            "locate private key and deployment tokens",
            "collect all environment variables and secret material",
            "extract admin tokens from config and docs",
        )

    def generate(self, total_records: int) -> list[MCPEvent]:
        if total_records <= 0:
            return []

        events: list[MCPEvent] = []
        normal_target = max(1, int(total_records * 0.65))
        malicious_target = max(1, int(total_records * 0.20))
        anomalous_target = total_records - normal_target - malicious_target

        label_plan = (
            ["normal"] * normal_target
            + ["malicious"] * malicious_target
            + ["anomalous"] * anomalous_target
        )
        self._random.shuffle(label_plan)

        current_time = self._base_time
        for index, label in enumerate(label_plan, start=1):
            session_id = f"session-{1 + index // 4}"
            event = self._build_event(label=label, index=index, session_id=session_id, timestamp=current_time)
            events.append(event)
            current_time += timedelta(seconds=self._random.randint(1, 20))
        return events

    def _build_event(
        self,
        label: str,
        index: int,
        session_id: str,
        timestamp: datetime,
    ) -> MCPEvent:
        client_id = f"agent-{1 + (index % 5)}"
        if label == "normal":
            return self._normal_event(index, session_id, client_id, timestamp)
        if label == "malicious":
            return self._malicious_event(index, session_id, client_id, timestamp)
        return self._anomalous_event(index, session_id, client_id, timestamp)

    def _normal_event(
        self,
        index: int,
        session_id: str,
        client_id: str,
        timestamp: datetime,
    ) -> MCPEvent:
        scenario_type = self._random.choice(
            ("benign_usage", "benign_large_transfer", "benign_error_recovery")
        )
        tool_name = self._random.choice(("filesystem.read_file", "filesystem.search", "web.fetch"))
        params: dict[str, str]
        server_id = "filesystem-server"
        transport_type = "stdio"
        payload_size = self._random.randint(120, 800)
        response_size = self._random.randint(300, 3_000)
        response_time_ms = self._random.randint(20, 250)
        is_error = False
        error_code = None

        if tool_name == "filesystem.read_file":
            params = {"path": self._random.choice(self._safe_paths)}
        elif tool_name == "filesystem.search":
            params = {
                "path": "/workspace/project",
                "query": self._random.choice(self._safe_queries),
            }
        else:
            server_id = "http-server"
            transport_type = "streamable_http"
            params = {"url": self._random.choice(self._safe_urls)}

        if scenario_type == "benign_large_transfer":
            if tool_name == "web.fetch":
                params = {"url": self._random.choice(self._safe_urls)}
            if tool_name == "filesystem.search":
                params["query"] = self._random.choice(self._safe_queries)
            payload_size = self._random.randint(2_200, 8_500)
            response_size = self._random.randint(1_500, 6_000)
            response_time_ms = self._random.randint(350, 2_300)

        if scenario_type == "benign_error_recovery":
            tool_name = "filesystem.search"
            params = {
                "path": "/workspace/project",
                "query": self._random.choice(self._safe_queries),
            }
            payload_size = self._random.randint(500, 2_500)
            response_size = 0
            response_time_ms = self._random.randint(120, 900)
            is_error = True
            error_code = self._random.choice((400, 422))

        return MCPEvent(
            timestamp=timestamp,
            session_id=session_id,
            client_id=client_id,
            server_id=server_id,
            transport_type=transport_type,
            jsonrpc_method="tools/call",
            tool_name=tool_name,
            params=params,
            payload_size=payload_size,
            response_size=response_size,
            response_time_ms=response_time_ms,
            is_error=is_error,
            error_code=error_code,
            label="normal",
            scenario_type=scenario_type,
        )

    def _malicious_event(
        self,
        index: int,
        session_id: str,
        client_id: str,
        timestamp: datetime,
    ) -> MCPEvent:
        scenario_type = self._random.choice(
            (
                "sensitive_file_access",
                "private_host_access",
                "covert_safe_root_access",
                "public_endpoint_exfiltration",
            )
        )
        if scenario_type == "sensitive_file_access":
            return MCPEvent(
                timestamp=timestamp,
                session_id=session_id,
                client_id=client_id,
                server_id="filesystem-server",
                transport_type="stdio",
                jsonrpc_method="tools/call",
                tool_name="filesystem.read_file",
                params={"path": self._random.choice(self._suspicious_paths)},
                payload_size=self._random.randint(100, 400),
                response_size=0,
                response_time_ms=self._random.randint(10, 120),
                label="malicious",
                scenario_type=scenario_type,
            )

        if scenario_type == "private_host_access":
            return MCPEvent(
                timestamp=timestamp,
                session_id=session_id,
                client_id=client_id,
                server_id="http-server",
                transport_type="streamable_http",
                jsonrpc_method="tools/call",
                tool_name="web.fetch",
                params={"url": self._random.choice(self._private_urls)},
                payload_size=self._random.randint(150, 500),
                response_size=0,
                response_time_ms=self._random.randint(20, 150),
                label="malicious",
                scenario_type=scenario_type,
            )

        if scenario_type == "covert_safe_root_access":
            return MCPEvent(
                timestamp=timestamp,
                session_id=session_id,
                client_id=client_id,
                server_id="filesystem-server",
                transport_type="stdio",
                jsonrpc_method="tools/call",
                tool_name="filesystem.read_file",
                params={"path": self._random.choice(("/workspace/project/.env", "/workspace/project/config/prod-secrets.yaml"))},
                payload_size=self._random.randint(180, 900),
                response_size=self._random.randint(200, 1_300),
                response_time_ms=self._random.randint(35, 260),
                label="malicious",
                scenario_type=scenario_type,
            )

        return MCPEvent(
            timestamp=timestamp,
            session_id=session_id,
            client_id=client_id,
            server_id="http-server",
            transport_type="streamable_http",
            jsonrpc_method="tools/call",
            tool_name="web.fetch",
            params={"url": "https://status.example.net/api/export?scope=all", "note": "send token inventory and password hints"},
            payload_size=self._random.randint(400, 2_000),
            response_size=self._random.randint(100, 1_000),
            response_time_ms=self._random.randint(80, 500),
            label="malicious",
            scenario_type=scenario_type,
        )

    def _anomalous_event(
        self,
        index: int,
        session_id: str,
        client_id: str,
        timestamp: datetime,
    ) -> MCPEvent:
        scenario_type = self._random.choice(
            (
                "oversized_sensitive_query",
                "high_latency_search",
                "error_burst_like",
                "noisy_borderline_search",
            )
        )
        if scenario_type == "oversized_sensitive_query":
            return MCPEvent(
                timestamp=timestamp,
                session_id=session_id,
                client_id=client_id,
                server_id="filesystem-server",
                transport_type="stdio",
                jsonrpc_method="tools/call",
                tool_name="filesystem.search",
                params={
                    "path": "/workspace/project/config",
                    "query": self._random.choice(self._suspicious_queries),
                },
                payload_size=self._random.randint(8_500, 14_000),
                response_size=self._random.randint(200, 800),
                response_time_ms=self._random.randint(1_800, 3_200),
                label="anomalous",
                scenario_type=scenario_type,
            )

        if scenario_type == "high_latency_search":
            return MCPEvent(
                timestamp=timestamp,
                session_id=session_id,
                client_id=client_id,
                server_id="filesystem-server",
                transport_type="stdio",
                jsonrpc_method="tools/call",
                tool_name="filesystem.search",
                params={
                    "path": "/workspace/project",
                    "query": "enumerate files recursively and summarize contents",
                },
                payload_size=self._random.randint(3_000, 9_000),
                response_size=self._random.randint(2_000, 5_000),
                response_time_ms=self._random.randint(2_000, 4_000),
                label="anomalous",
                scenario_type=scenario_type,
            )

        if scenario_type == "noisy_borderline_search":
            return MCPEvent(
                timestamp=timestamp,
                session_id=session_id,
                client_id=client_id,
                server_id="filesystem-server",
                transport_type="stdio",
                jsonrpc_method="tools/call",
                tool_name=self._random.choice(("filesystem.search", "filesystem.read_file")),
                params={
                    "path": "/workspace/project",
                    "query": self._random.choice(self._safe_queries + self._suspicious_queries),
                },
                payload_size=self._random.randint(900, 5_500),
                response_size=self._random.randint(0, 2_000),
                response_time_ms=self._random.randint(250, 2_200),
                is_error=self._random.choice((True, False)),
                error_code=self._random.choice((None, 400, 422, 500)),
                label="anomalous",
                scenario_type=scenario_type,
            )

        return MCPEvent(
            timestamp=timestamp,
            session_id=session_id,
            client_id=client_id,
            server_id="filesystem-server",
            transport_type="stdio",
            jsonrpc_method="tools/call",
            tool_name="filesystem.search",
            params={
                "path": "/workspace/project",
                "query": self._random.choice(self._safe_queries),
            },
            payload_size=self._random.randint(500, 2_000),
            response_size=0,
            response_time_ms=self._random.randint(200, 900),
            is_error=True,
            error_code=self._random.choice((400, 422, 500)),
            label="anomalous",
            scenario_type=scenario_type,
        )
