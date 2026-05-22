from __future__ import annotations

from mcp_firewall.config import FirewallConfig
from mcp_firewall.models import MCPEvent, RuleMatch


class AccessControlEngine:
    """Checks coarse-grained policy before the event reaches backend execution."""

    def __init__(self, config: FirewallConfig) -> None:
        self._config = config

    def evaluate(self, event: MCPEvent) -> list[RuleMatch]:
        matches: list[RuleMatch] = []

        if event.transport_type not in self._config.allowed_transports:
            matches.append(
                RuleMatch(
                    name="disallowed_transport",
                    severity="block",
                    reason=f"Transport '{event.transport_type}' is not allowed by policy.",
                )
            )

        allowed_tools = self._config.client_tool_allowlist.get(event.client_id)
        if allowed_tools is None:
            matches.append(
                RuleMatch(
                    name="unknown_client",
                    severity="block",
                    reason=f"Client '{event.client_id}' is not registered in the firewall policy.",
                )
            )
        elif event.tool_name and event.tool_name not in allowed_tools:
            matches.append(
                RuleMatch(
                    name="tool_not_allowed_for_client",
                    severity="block",
                    reason=f"Tool '{event.tool_name}' is not allowed for client '{event.client_id}'.",
                )
            )

        if event.tool_name:
            expected_server = self._config.tool_server_map.get(event.tool_name)
            if expected_server and event.server_id != expected_server:
                matches.append(
                    RuleMatch(
                        name="tool_server_mismatch",
                        severity="block",
                        reason=(
                            f"Tool '{event.tool_name}' is expected to target '{expected_server}', "
                            f"but the event points to '{event.server_id}'."
                        ),
                    )
                )

        return matches
