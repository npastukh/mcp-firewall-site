from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class FirewallConfig:
    allowed_transports: tuple[str, ...] = ("stdio", "streamable_http")
    blocked_paths: tuple[str, ...] = (
        "/etc/passwd",
        "/.ssh",
        "/secrets",
        "/var/run/secrets",
        "/proc/self/environ",
        "/private/.env",
    )
    blocked_hosts: tuple[str, ...] = (
        "169.254.169.254",
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "::1",
    )
    blocked_host_suffixes: tuple[str, ...] = (
        ".internal",
        ".local",
        ".localhost",
        ".home.arpa",
        ".lan",
    )
    blocked_tools: tuple[str, ...] = ()
    allowed_url_schemes: tuple[str, ...] = ("http", "https")
    sensitive_query_keys: tuple[str, ...] = (
        "access_token",
        "api_key",
        "apikey",
        "auth_token",
        "authorization",
        "jwt",
        "password",
        "secret",
        "signature",
        "sig",
        "token",
    )
    dangerous_param_keys: tuple[str, ...] = (
        "args",
        "bash",
        "cmd",
        "command",
        "script",
        "shell",
        "startup_command",
    )
    dangerous_command_patterns: tuple[str, ...] = (
        r"(?i)\bsudo\b",
        r"(?i)\brm\s+-rf\b",
        r"(?i)\bcurl\b[^\n|]*\|\s*(?:ba)?sh\b",
        r"(?i)\bwget\b[^\n|]*\|\s*(?:ba)?sh\b",
        r"(?i)\bchmod\s+\+x\b",
        r"(?i)\bpowershell(?:\.exe)?\b.*(?:-enc|-encodedcommand)\b",
        r"(?i)\bnc\b|\bnetcat\b",
    )
    scope_param_keys: tuple[str, ...] = ("permission", "permissions", "scope", "scopes")
    excessive_scope_patterns: tuple[str, ...] = (
        r"(?i)^\*$",
        r"(?i)\ball\b",
        r"(?i)\badmin\b",
        r"(?i)\bfull[-_ ]?access\b",
        r"(?i)\broot\b",
        r"(?i)\*:",
        r"(?i):\*",
    )
    inline_secret_key_patterns: tuple[str, ...] = (
        r"(?i)(^|\.)(authorization|proxy_authorization)$",
        r"(?i)(^|\.)(x[-_]?api[-_]?key|api[-_]?key|apikey)$",
        r"(?i)(^|\.)(access[-_]?token|auth[-_]?token|refresh[-_]?token|token)$",
        r"(?i)(^|\.)(password|secret|jwt|private[-_]?key|client[-_]?secret)$",
    )
    callback_param_keys: tuple[str, ...] = (
        "callback_url",
        "destination_url",
        "redirect_url",
        "return_url",
        "webhook",
        "webhook_url",
    )
    sensitive_path_patterns: tuple[str, ...] = (
        r"(^|/)\.env(?:\.[^/]+)?$",
        r"(^|/)\.git(?:/|$)",
        r"(^|/)\.aws/(?:credentials|config)$",
        r"(^|/)\.kube/config$",
        r"(^|/)(?:id_rsa|id_dsa|authorized_keys|known_hosts)$",
    )
    exfiltration_keywords: tuple[str, ...] = (
        "dump",
        "exfil",
        "export",
        "leak",
        "password",
        "secret",
        "send",
        "token",
        "upload",
    )
    exfiltration_action_keywords: tuple[str, ...] = (
        "dump",
        "exfil",
        "leak",
        "send",
        "upload",
    )
    max_payload_size: int = 16_000
    max_response_size: int = 8_000
    warn_risk_threshold: float = 0.40
    block_risk_threshold: float = 0.75
    high_frequency_threshold: int = 8
    sensitive_keywords: tuple[str, ...] = (
        "token",
        "secret",
        "password",
        "key",
        "credential",
    )
    safe_file_roots: tuple[str, ...] = ("/workspace", "/tmp/demo-data")
    client_tool_allowlist: dict[str, tuple[str, ...]] = field(
        default_factory=lambda: {
            "agent-1": ("filesystem.read_file", "filesystem.search", "web.fetch"),
            "agent-2": ("filesystem.read_file", "filesystem.search", "web.fetch"),
            "agent-3": ("filesystem.read_file", "filesystem.search", "web.fetch"),
            "agent-4": ("filesystem.read_file", "filesystem.search", "web.fetch"),
            "agent-5": ("filesystem.read_file", "filesystem.search", "web.fetch"),
        }
    )
    tool_server_map: dict[str, str] = field(
        default_factory=lambda: {
            "filesystem.read_file": "filesystem-server",
            "filesystem.search": "filesystem-server",
            "web.fetch": "http-server",
        }
    )
    logs_dir: str = "logs"
    supervised_runtime_enabled: bool = False
    supervised_model_path: str | None = None
    supervised_model_name: str = "CatBoost"
    full_context_evaluator_enabled: bool = False
    full_context_model_path: str | None = None
    full_context_max_length: int = 128
    full_context_extraction_threshold: float = 0.5
    full_context_warn_threshold: float = 0.55
    full_context_block_threshold: float = 0.85
    metadata: dict[str, str] = field(default_factory=dict)
