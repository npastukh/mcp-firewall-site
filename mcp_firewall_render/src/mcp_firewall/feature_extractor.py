from __future__ import annotations

import re

from mcp_firewall.config import FirewallConfig
from mcp_firewall.models import MCPEvent, SessionState
from mcp_firewall.utils import (
    extract_candidate_urls,
    extract_host,
    flatten_values,
    flatten_key_values,
    host_matches_blocklist,
    looks_sensitive_path,
)


class FeatureExtractor:
    def __init__(self, config: FirewallConfig) -> None:
        self._config = config

    def extract(self, event: MCPEvent, state: SessionState) -> dict[str, float | int | str | bool]:
        values = flatten_values(event.params)
        keyed_values = flatten_key_values(event.params)
        joined = " ".join(values).lower()
        path_values = [value for value in values if "/" in value]
        url_values: list[str] = []
        for value in values:
            url_values.extend(extract_candidate_urls(value))

        private_url_flag = any(
            host_matches_blocklist(
                extract_host(url),
                self._config.blocked_hosts,
                self._config.blocked_host_suffixes,
            )
            for url in url_values
        )
        sensitive_path_flag = any(self._looks_sensitive_path(path) for path in path_values)
        sensitive_keyword_flag = any(keyword in joined for keyword in self._config.sensitive_keywords)
        dangerous_command_flag = any(self._looks_dangerous_command(key, value) for key, value in keyed_values)
        excessive_scope_flag = any(self._looks_excessive_scope(key, value) for key, value in keyed_values)
        inline_secret_flag = any(self._looks_inline_secret(key, value) for key, value in keyed_values)
        exfiltration_flag = self._looks_exfiltration(joined, keyed_values, url_values)
        repeated_tool_flag = bool(event.tool_name and event.tool_name == state.last_tool_name)

        return {
            "transport_type": event.transport_type,
            "jsonrpc_method": event.jsonrpc_method,
            "tool_name": event.tool_name or "",
            "arg_count": len(event.params),
            "payload_size": event.payload_size,
            "response_size": event.response_size,
            "response_time_ms": event.response_time_ms,
            "is_error": event.is_error,
            "tools_called_last_session": len(state.tools_called),
            "failed_calls_last_session": state.failed_calls,
            "sensitive_path_flag": sensitive_path_flag,
            "external_url_flag": bool(url_values),
            "private_ip_flag": private_url_flag,
            "sensitive_keyword_flag": sensitive_keyword_flag,
            "dangerous_command_flag": dangerous_command_flag,
            "excessive_scope_flag": excessive_scope_flag,
            "inline_secret_flag": inline_secret_flag,
            "exfiltration_flag": exfiltration_flag,
            "repeated_tool_flag": repeated_tool_flag,
        }

    def _looks_sensitive_path(self, path: str) -> bool:
        return looks_sensitive_path(
            path,
            self._config.blocked_paths,
            self._config.sensitive_path_patterns,
        )

    def _looks_dangerous_command(self, key: str, value: str) -> bool:
        leaf_key = key.rsplit(".", 1)[-1].lower()
        if leaf_key not in self._config.dangerous_param_keys:
            return False
        return any(re.search(pattern, value) for pattern in self._config.dangerous_command_patterns)

    def _looks_excessive_scope(self, key: str, value: str) -> bool:
        leaf_key = key.rsplit(".", 1)[-1].lower()
        if leaf_key not in self._config.scope_param_keys:
            return False
        return any(re.search(pattern, value) for pattern in self._config.excessive_scope_patterns)

    def _looks_inline_secret(self, key: str, value: str) -> bool:
        if not value.strip():
            return False
        normalized_key = key.lower().replace("[", ".").replace("]", "")
        return any(re.search(pattern, normalized_key) for pattern in self._config.inline_secret_key_patterns)

    def _looks_exfiltration(
        self,
        joined: str,
        keyed_values: list[tuple[str, str]],
        url_values: list[str],
    ) -> bool:
        has_callback = any(
            key.rsplit(".", 1)[-1].lower() in self._config.callback_param_keys
            for key, _ in keyed_values
        )
        has_broad_scope = any(self._looks_excessive_scope(key, value) for key, value in keyed_values)
        has_sensitive_terms = any(keyword in joined for keyword in self._config.exfiltration_keywords)
        has_export_url = any("/export" in url.lower() or "scope=all" in url.lower() for url in url_values)
        has_action_intent = any(keyword in joined for keyword in self._config.exfiltration_action_keywords)
        return has_sensitive_terms and (has_callback or has_broad_scope or (has_export_url and has_action_intent))
