from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import urlparse

from mcp_firewall.config import FirewallConfig
from mcp_firewall.models import MCPEvent


def normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def normalize_path_candidate(candidate: str) -> str:
    if not candidate:
        return ""

    path = str(candidate).strip()
    path = re.sub(r'^["\']|["\']$', "", path)
    path = re.sub(r"[),.;:]+$", "", path)
    if not path or re.match(r"^https?://", path, re.IGNORECASE):
        return ""

    if path.startswith("/"):
        return path
    if path.startswith("./"):
        path = path[2:]
    if path.startswith("../"):
        path = re.sub(r"^(\.\./)+", "", path)
    if not path:
        return ""

    return f"/workspace/project/{path}"


def extract_path(text: str) -> str:
    normalized = normalize_whitespace(text)
    patterns = [
        r'["\'](\/[^"\'\s,;]+|\.\.?\/[^"\'\s,;]+|\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)["\']',
        r"(\/[^\s,;]+)",
        r"\b(?:файл|файла|путь|path|file)\s+((?:\.\.?\/)?\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)",
        r"\b((?:\.\.?\/)?\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if not match:
            continue
        candidate = match.group(1) if match.groups() else match.group(0)
        normalized_path = normalize_path_candidate(candidate)
        if normalized_path:
            return normalized_path

    return ""


def extract_url(text: str, allow_bare: bool = False) -> str:
    explicit = re.search(r"https?://[^\s)]+", text, re.IGNORECASE)
    if explicit:
        return explicit.group(0)

    if allow_bare:
        bare = re.search(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s,;]*)?", text, re.IGNORECASE)
        if bare:
            candidate = bare.group(0)
            if re.match(r"^https?://", candidate, re.IGNORECASE):
                return candidate
            return f"https://{candidate}"

    return ""


def cleanup_search_query(prompt: str) -> str:
    cleaned = re.sub(r"^(найди|выполни поиск|поиск|search for|search)\s*", "", prompt, flags=re.IGNORECASE)
    cleaned = re.sub(
        r"\b(?:в|inside|within)\s+(\/[^\s,;]+|(?:\.\.?\/)?\.?[A-Za-z0-9_-]+(?:[./][A-Za-z0-9._-]+)+)\b",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r"\b(?:файл|путь|path|file)\b", "", cleaned, flags=re.IGNORECASE)
    return normalize_whitespace(cleaned) or prompt


def has_read_intent(lower: str, path: str) -> bool:
    if re.search(r"\b(read|cat|open file|show file)\b", lower, re.IGNORECASE):
        return True
    if re.search(r"(прочитай|прочти|открой файл|покажи файл|выведи файл|содержимое файла)", lower, re.IGNORECASE):
        return True
    return bool(path and re.search(r"(файл|file|read|прочитай|прочти|открой|покажи)", lower, re.IGNORECASE))


def has_fetch_intent(lower: str) -> bool:
    return bool(
        re.search(
            r"(fetch|http|url|сайт|страниц|страницу|перейди|скачай|запроси|web[- ]?запрос|открой\s+(?!файл))",
            lower,
            re.IGNORECASE,
        )
    )


def has_search_intent(lower: str) -> bool:
    return bool(re.search(r"(найди|ищи|поиск|search|find|grep|поищи|проверь.*(секрет|token|password|key))", lower, re.IGNORECASE))


def estimate_payload_size(prompt: str, params: dict) -> int:
    payload = len(prompt) * 18 + sum(len(str(value)) * 6 for value in params.values())
    return max(220, payload)


def _synthesize_response_features(tool_name: str, params: dict[str, object]) -> tuple[int, int]:
    if tool_name == "filesystem.read_file":
        path = str(params.get("path", ""))
        if path.startswith("/etc") or path.startswith("/private") or "/.ssh" in path:
            return 0, 0
        return (2400, 90) if "README" in path or "readme" in path.lower() else (3600, 420)

    if tool_name == "filesystem.search":
        query = str(params.get("query", "")).lower()
        broad = any(token in query for token in ("all", "все", "полный", "full"))
        sensitive = any(token in query for token in ("token", "secret", "password", "credential", "key"))
        return (8600, 2480) if broad or sensitive else (3100, 430)

    url = str(params.get("url", "https://example.com"))
    hostname = (urlparse(url).hostname or "").lower()
    if hostname in {"169.254.169.254", "127.0.0.1", "localhost"}:
        return 0, 0
    return (3200, 460) if "docs" in url else (2100, 230)


def interpret_prompt(prompt: str, policy: FirewallConfig) -> dict[str, object]:
    normalized_prompt = normalize_whitespace(prompt)
    lower = normalized_prompt.lower()
    path = extract_path(normalized_prompt)
    fetch_intent = has_fetch_intent(lower)
    url = extract_url(normalized_prompt, allow_bare=fetch_intent)

    if not normalized_prompt:
        return {
            "status": "unknown",
            "intent": "unknown",
            "confidence": 0.0,
            "message": "Пустой запрос не может быть интерпретирован как MCP-сценарий.",
        }

    if fetch_intent or url:
        if not url:
            return {
                "status": "incomplete",
                "intent": "web_fetch",
                "confidence": 0.52,
                "missing": ["url"],
                "message": "Распознан web-сценарий, но в запросе не указан конкретный URL.",
            }

        return {
            "status": "supported",
            "intent": "web_fetch",
            "confidence": 0.95,
            "tool_name": "web.fetch",
            "server_id": policy.tool_server_map.get("web.fetch", "http-server"),
            "arguments": {"url": url},
            "message": "Запрос интерпретирован как web-fetch вызов.",
        }

    if has_read_intent(lower, path):
        if not path:
            return {
                "status": "incomplete",
                "intent": "read_file",
                "confidence": 0.74,
                "missing": ["path"],
                "message": "Распознан сценарий чтения файла, но не указан конкретный путь.",
            }

        return {
            "status": "supported",
            "intent": "read_file",
            "confidence": 0.92,
            "tool_name": "filesystem.read_file",
            "server_id": policy.tool_server_map.get("filesystem.read_file", "filesystem-server"),
            "arguments": {"path": path},
            "message": "Запрос интерпретирован как чтение файла через filesystem.read_file.",
        }

    if has_search_intent(lower):
        query = cleanup_search_query(normalized_prompt)
        if not query or len(query) < 3:
            return {
                "status": "incomplete",
                "intent": "search",
                "confidence": 0.61,
                "missing": ["query"],
                "message": "Распознан поисковый сценарий, но запрос недостаточно конкретен для search-вызова.",
            }

        return {
            "status": "supported",
            "intent": "search",
            "confidence": 0.83,
            "tool_name": "filesystem.search",
            "server_id": policy.tool_server_map.get("filesystem.search", "filesystem-server"),
            "arguments": {
                "path": path or "/workspace/project",
                "query": query,
            },
            "message": "Запрос интерпретирован как поиск по файловому дереву.",
        }

    return {
        "status": "unknown",
        "intent": "unknown",
        "confidence": 0.18,
        "message": "Запрос находится вне поддерживаемых демонстрационных сценариев. Сейчас поддерживаются чтение файла, web-fetch и поиск.",
    }


def build_event_from_prompt(
    prompt: str,
    client_id: str,
    transport_type: str,
    session_id: str,
    policy: FirewallConfig,
) -> tuple[dict[str, object], MCPEvent | None]:
    interpretation = interpret_prompt(prompt, policy)
    if interpretation["status"] != "supported":
        return interpretation, None

    params = dict(interpretation["arguments"])
    response_size, response_time_ms = _synthesize_response_features(str(interpretation["tool_name"]), params)
    event = MCPEvent(
        timestamp=datetime.now(UTC),
        session_id=session_id,
        client_id=client_id,
        server_id=str(interpretation["server_id"]),
        transport_type=transport_type,
        jsonrpc_method="tools/call",
        tool_name=str(interpretation["tool_name"]),
        params=params,
        payload_size=estimate_payload_size(prompt, params),
        response_size=response_size,
        response_time_ms=response_time_ms,
        is_error=False,
    )
    return interpretation, event
