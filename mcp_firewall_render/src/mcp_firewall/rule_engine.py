from __future__ import annotations

import re

from mcp_firewall.config import FirewallConfig
from mcp_firewall.models import MCPEvent, PrivacyAssessment, RuleMatch, SessionState
from mcp_firewall.privacy_filter_runtime import HIGH_RISK_PRIVACY_LABELS
from mcp_firewall.utils import (
    extract_candidate_urls,
    extract_host,
    extract_query_keys,
    flatten_values,
    flatten_key_values,
    has_path_traversal,
    host_is_external,
    host_matches_blocklist,
    looks_sensitive_path,
    normalize_host,
    normalize_path,
    path_is_within_roots,
    split_url,
)


class RuleEngine:
    def __init__(self, config: FirewallConfig) -> None:
        self._config = config

    def evaluate(
        self,
        event: MCPEvent,
        state: SessionState,
        privacy_assessment: PrivacyAssessment | None = None,
    ) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        values = flatten_values(event.params)
        keyed_values = flatten_key_values(event.params)
        joined = " ".join(values).lower()

        if event.tool_name and event.tool_name in self._config.blocked_tools:
            matches.append(
                RuleMatch(
                    name="blocked_tool",
                    severity="block",
                    reason=f"Tool '{event.tool_name}' is prohibited by policy.",
                )
            )

        if event.payload_size > self._config.max_payload_size:
            matches.append(
                RuleMatch(
                    name="oversized_payload",
                    severity="warn",
                    reason="Payload size exceeds the configured threshold.",
                )
            )

        if event.response_size > self._config.max_response_size:
            matches.append(
                RuleMatch(
                    name="oversized_response",
                    severity="warn",
                    reason="Response size exceeds the configured threshold.",
                )
            )

        if state.total_calls >= self._config.high_frequency_threshold:
            matches.append(
                RuleMatch(
                    name="high_frequency_calls",
                    severity="warn",
                    reason="Session frequency is above the expected threshold.",
                )
            )

        for value in values:
            if looks_sensitive_path(
                value,
                self._config.blocked_paths,
                self._config.sensitive_path_patterns,
            ):
                matches.append(
                    RuleMatch(
                        name="sensitive_path_access",
                        severity="block",
                        reason=f"Attempted access to sensitive path fragment: {value}",
                    )
                )
                break

        for key, value in keyed_values:
            leaf_key = key.rsplit(".", 1)[-1].lower()
            if leaf_key in self._config.dangerous_param_keys and any(
                re.search(pattern, value) for pattern in self._config.dangerous_command_patterns
            ):
                matches.append(
                    RuleMatch(
                        name="dangerous_command_pattern",
                        severity="block",
                        reason=f"Payload contains a dangerous command pattern in '{key}'.",
                    )
                )
                break

        for key, value in keyed_values:
            leaf_key = key.rsplit(".", 1)[-1].lower()
            if leaf_key in self._config.scope_param_keys and any(
                re.search(pattern, value) for pattern in self._config.excessive_scope_patterns
            ):
                matches.append(
                    RuleMatch(
                        name="excessive_scope_request",
                        severity="block",
                        reason=f"Requested scope is broader than policy allows: {value}",
                    )
                )
                break

        for key, value in keyed_values:
            normalized_key = key.lower().replace("[", ".").replace("]", "")
            if value.strip() and any(
                re.search(pattern, normalized_key) for pattern in self._config.inline_secret_key_patterns
            ):
                matches.append(
                    RuleMatch(
                        name="inline_secret_material",
                        severity="warn",
                        reason=f"Sensitive credential-like material is passed inline via '{key}'.",
                    )
                )
                break

        for value in values:
            for candidate_url in extract_candidate_urls(value):
                parsed = split_url(candidate_url)
                if parsed is None:
                    matches.append(
                        RuleMatch(
                            name="malformed_url",
                            severity="warn",
                            reason=f"URL could not be parsed safely: {candidate_url}",
                        )
                    )
                    continue

                if not parsed.scheme and candidate_url.startswith("//"):
                    matches.append(
                        RuleMatch(
                            name="scheme_relative_url",
                            severity="warn",
                            reason=f"Scheme-relative URL requires explicit validation: {candidate_url}",
                        )
                    )

                if parsed.scheme and parsed.scheme.lower() not in self._config.allowed_url_schemes:
                    matches.append(
                        RuleMatch(
                            name="disallowed_url_scheme",
                            severity="block",
                            reason=f"URL scheme '{parsed.scheme.lower()}' is not allowed by policy.",
                        )
                    )
                    continue

                if parsed.username or parsed.password:
                    matches.append(
                        RuleMatch(
                            name="credentialed_url",
                            severity="block",
                            reason="URL embeds user credentials and is blocked by policy.",
                        )
                    )
                    continue

                host = normalize_host(parsed.hostname)
                if not host:
                    continue

                if host_matches_blocklist(
                    host,
                    self._config.blocked_hosts,
                    self._config.blocked_host_suffixes,
                ):
                    matches.append(
                        RuleMatch(
                            name="private_address_access",
                            severity="block",
                            reason=f"Attempted access to blocked or private host: {host}",
                        )
                    )
                    continue

                if "." not in host:
                    matches.append(
                        RuleMatch(
                            name="non_fqdn_host",
                            severity="warn",
                            reason=f"Host '{host}' is not a fully qualified domain name.",
                        )
                    )

                query_keys = set(extract_query_keys(candidate_url))
                if query_keys.intersection(self._config.sensitive_query_keys):
                    matches.append(
                        RuleMatch(
                            name="sensitive_url_parameter",
                            severity="warn",
                            reason="URL query contains a sensitive credential-like parameter.",
                        )
                    )

        for key, value in keyed_values:
            leaf_key = key.rsplit(".", 1)[-1].lower()
            if leaf_key not in self._config.callback_param_keys:
                continue
            callback_host = extract_host(value)
            if callback_host and host_is_external(callback_host):
                matches.append(
                    RuleMatch(
                        name="external_callback_target",
                        severity="warn",
                        reason=f"Callback or webhook target points to an external host: {callback_host}",
                    )
                )
                break

        has_broad_scope = any(
            key.rsplit(".", 1)[-1].lower() in self._config.scope_param_keys
            and any(re.search(pattern, value) for pattern in self._config.excessive_scope_patterns)
            for key, value in keyed_values
        )
        has_callback = any(
            key.rsplit(".", 1)[-1].lower() in self._config.callback_param_keys
            and extract_host(value)
            and host_is_external(extract_host(value))
            for key, value in keyed_values
        )
        has_export_url = any("/export" in value.lower() or "scope=all" in value.lower() for value in values)
        has_sensitive_exfil_terms = any(keyword in joined for keyword in self._config.exfiltration_keywords)
        has_action_intent = any(keyword in joined for keyword in self._config.exfiltration_action_keywords)
        if has_sensitive_exfil_terms and (has_broad_scope or has_callback or (has_export_url and has_action_intent)):
            matches.append(
                RuleMatch(
                    name="sensitive_exfiltration_attempt",
                    severity="block",
                    reason="Payload combines sensitive terms with broad export or external delivery indicators.",
                )
            )

        if event.tool_name and "read" in event.tool_name.lower():
            path = str(event.params.get("path", ""))
            if path and has_path_traversal(path):
                matches.append(
                    RuleMatch(
                        name="path_traversal_attempt",
                        severity="block",
                        reason="Read operation contains path traversal segments.",
                    )
                )
            if path and not path_is_within_roots(path, self._config.safe_file_roots):
                matches.append(
                    RuleMatch(
                        name="path_outside_safe_roots",
                        severity="block",
                        reason="Read operation targets a path outside allowed roots.",
                    )
                )

        path = str(event.params.get("path", ""))
        if normalize_path(path).startswith("/private") and event.tool_name and "read" in event.tool_name.lower():
            matches.append(
                RuleMatch(
                    name="private_backend_path_access",
                    severity="block",
                    reason="Attempted access to a private backend path exposed through MCP.",
                )
            )

        if event.tool_name and "export" in event.tool_name.lower():
            scope = str(event.params.get("scope", "")).lower()
            if scope == "all":
                matches.append(
                    RuleMatch(
                        name="sensitive_export_scope",
                        severity="warn",
                        reason="Export request targets full scope and may expose sensitive records.",
                    )
                )

        if privacy_assessment and privacy_assessment.entity_count:
            high_risk_labels = sorted(
                {span.label for span in privacy_assessment.spans if span.label in HIGH_RISK_PRIVACY_LABELS}
            )
            if (
                privacy_assessment.max_confidence >= self._config.full_context_block_threshold
                and high_risk_labels
            ):
                matches.append(
                    RuleMatch(
                        name="full_context_sensitive_request",
                        severity="block",
                        reason=(
                            "Full-context privacy evaluator detected high-risk sensitive entities: "
                            + ", ".join(high_risk_labels)
                        ),
                    )
                )
            elif privacy_assessment.max_confidence >= self._config.full_context_warn_threshold:
                matches.append(
                    RuleMatch(
                        name="full_context_sensitive_request",
                        severity="warn",
                        reason=(
                            "Full-context privacy evaluator detected sensitive entities: "
                            + ", ".join(privacy_assessment.detected_labels)
                        ),
                    )
                )

        return matches

