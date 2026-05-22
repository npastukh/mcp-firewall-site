from __future__ import annotations

import posixpath
import re
from ipaddress import ip_address
from urllib.parse import parse_qsl, unquote, unwrap, urlsplit

URL_PATTERN = re.compile(
    r"(?i)(?:(?:[a-z][a-z0-9+.-]*://)|//)[^\s<>'\"]+|(?:data:[^\s<>'\"]+)"
)
PATH_TRAVERSAL_PATTERN = re.compile(r"(?i)(?:^|[\\/])\.\.(?:[\\/]|$)")


def flatten_values(payload: object) -> list[str]:
    if isinstance(payload, dict):
        values: list[str] = []
        for value in payload.values():
            values.extend(flatten_values(value))
        return values
    if isinstance(payload, list):
        values = []
        for item in payload:
            values.extend(flatten_values(item))
        return values
    if payload is None:
        return []
    return [str(payload)]


def flatten_key_values(payload: object, prefix: str = "") -> list[tuple[str, str]]:
    if isinstance(payload, dict):
        values: list[tuple[str, str]] = []
        for key, value in payload.items():
            nested_prefix = f"{prefix}.{key}" if prefix else str(key)
            values.extend(flatten_key_values(value, nested_prefix))
        return values
    if isinstance(payload, list):
        values = []
        for index, item in enumerate(payload):
            nested_prefix = f"{prefix}[{index}]" if prefix else f"[{index}]"
            values.extend(flatten_key_values(item, nested_prefix))
        return values
    if payload is None:
        return []
    return [(prefix, str(payload))]


def normalize_host(host: str | None) -> str:
    if not host:
        return ""
    return host.strip().rstrip(".").lower()


def is_private_host(host: str | None) -> bool:
    normalized = normalize_host(host)
    if not normalized:
        return False
    if normalized in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return not ip_address(normalized).is_global
    except ValueError:
        return False


def host_matches_blocklist(
    host: str | None,
    blocked_hosts: tuple[str, ...],
    blocked_host_suffixes: tuple[str, ...],
) -> bool:
    normalized = normalize_host(host)
    if not normalized:
        return False
    if normalized in {normalize_host(value) for value in blocked_hosts}:
        return True
    if is_private_host(normalized):
        return True
    return any(
        normalized == suffix.removeprefix(".") or normalized.endswith(suffix)
        for suffix in blocked_host_suffixes
    )


def extract_host(value: str) -> str | None:
    parsed = split_url(value)
    if parsed is None:
        return None
    return normalize_host(parsed.hostname)


def split_url(value: str):
    cleaned = unwrap(str(value).strip())
    if not cleaned:
        return None
    try:
        return urlsplit(cleaned)
    except ValueError:
        return None


def extract_candidate_urls(value: str) -> list[str]:
    matches = [match.group(0).rstrip(".,);") for match in URL_PATTERN.finditer(unwrap(str(value).strip()))]
    unique: list[str] = []
    for match in matches:
        if match not in unique:
            unique.append(match)
    return unique


def extract_query_keys(value: str) -> tuple[str, ...]:
    parsed = split_url(value)
    if parsed is None or not parsed.query:
        return ()
    return tuple(key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True))


def host_is_external(host: str | None) -> bool:
    normalized = normalize_host(host)
    if not normalized:
        return False
    return not is_private_host(normalized)


def normalize_path(path: str) -> str:
    decoded = unquote(str(path).strip()).replace("\\", "/")
    normalized = posixpath.normpath(decoded or ".")
    if decoded.startswith("/") and not normalized.startswith("/"):
        return f"/{normalized}"
    return normalized


def has_path_traversal(path: str) -> bool:
    decoded = unquote(str(path)).replace("\\", "/")
    return bool(PATH_TRAVERSAL_PATTERN.search(decoded))


def path_is_within_roots(path: str, roots: tuple[str, ...]) -> bool:
    normalized_path = normalize_path(path)
    for root in roots:
        normalized_root = normalize_path(root)
        if normalized_path == normalized_root or normalized_path.startswith(f"{normalized_root}/"):
            return True
    return False


def looks_sensitive_path(
    path: str,
    blocked_paths: tuple[str, ...],
    sensitive_patterns: tuple[str, ...],
) -> bool:
    normalized = normalize_path(path).lower()
    if any(fragment in normalized for fragment in blocked_paths):
        return True
    return any(re.search(pattern, normalized) for pattern in sensitive_patterns)
