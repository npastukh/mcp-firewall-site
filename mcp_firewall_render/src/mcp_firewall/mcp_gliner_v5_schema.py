from __future__ import annotations

from typing import Iterable


V5_SPAN_LABELS = (
    "env_access_pattern",
    "secret_name",
    "secret_value",
    "sensitive_path",
    "private_host",
    "secret_store_ref",
)

V5_ENTITY_DESCRIPTIONS: dict[str, str] = {
    "env_access_pattern": "Code pattern used to read environment variables, such as process.env.KEY, os.getenv('KEY'), getenv('KEY'), or env['KEY'].",
    "secret_name": "Name of a secret, credential variable, password field, token field, API key identifier, authorization header name, or session field.",
    "secret_value": "Concrete value of a secret, password, bearer token, API key, webhook token, session token, or other credential.",
    "sensitive_path": "Sensitive file path or dotenv-style location pointing to secrets, credentials, private keys, restricted configs, kube tokens, ssh keys, or other protected files.",
    "private_host": "Standalone internal host, localhost name, private IP, CIDR, metadata endpoint host, or intranet DNS target, including hostnames embedded inside MCP URLs.",
    "secret_store_ref": "Reference to a secret store, vault object, KMS entry, secret manager path, Kubernetes secret name, or similar credential container.",
}

V5_CLASSIFICATION_TASK = "request_safety"
V5_CLASSIFICATION_LABELS = ("safe", "suspicious")

V5_CLASSIFICATION_LABEL_DESCRIPTIONS: dict[str, str] = {
    "safe": "Benign MCP-related request, code snippet, config fragment, or documentation text with no suspicious extraction or exfiltration intent.",
    "suspicious": "Request or artifact that attempts to locate, expose, read, extract, infer, exfiltrate, or misuse secrets, internal resources, or credential-bearing configuration.",
}


def row_label_set(row: dict) -> set[str]:
    return {str(label["category"]) for label in row.get("label", [])}


def row_combo_key(row: dict) -> tuple[str, ...]:
    return tuple(sorted(row_label_set(row)))


def _require_info_field(info: dict, field_name: str) -> None:
    value = info.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing required info field: {field_name}")


def _validate_spans(text: str, labels: Iterable[dict]) -> None:
    seen: set[tuple[str, int, int]] = set()
    for label in labels:
        category = str(label["category"])
        if category not in V5_SPAN_LABELS:
            raise ValueError(f"unknown v5 label: {category}")
        start = int(label["start"])
        end = int(label["end"])
        if start < 0 or end <= start or end > len(text):
            raise ValueError(f"invalid span bounds for label {category}: ({start}, {end})")
        key = (category, start, end)
        if key in seen:
            raise ValueError(f"duplicate span triplet: {key}")
        seen.add(key)


def validate_v5_span_row(row: dict) -> None:
    text = row.get("text")
    if not isinstance(text, str) or not text:
        raise ValueError("row text must be a non-empty string")
    labels = row.get("label")
    if not isinstance(labels, list):
        raise ValueError("row label must be a list")
    info = row.get("info")
    if not isinstance(info, dict):
        raise ValueError("row info must be a dict")

    for field_name in (
        "request_safety",
        "source_dataset",
        "source_language",
        "scenario_type",
        "source_type",
        "origin",
    ):
        _require_info_field(info, field_name)

    request_safety = str(info["request_safety"])
    if request_safety not in V5_CLASSIFICATION_LABELS:
        raise ValueError(f"unsupported request_safety label: {request_safety}")

    _validate_spans(text, labels)

    if request_safety == "safe" and labels:
        raise ValueError("safe v5 span rows must not contain labels")
    if request_safety == "suspicious" and not labels:
        raise ValueError("suspicious v5 span rows must contain at least one label")


def validate_v5_classification_row(row: dict) -> None:
    text = row.get("text")
    if not isinstance(text, str) or not text:
        raise ValueError("row text must be a non-empty string")
    labels = row.get("label")
    if labels != []:
        raise ValueError("classification-only rows must keep label=[]")
    info = row.get("info")
    if not isinstance(info, dict):
        raise ValueError("row info must be a dict")

    for field_name in (
        "request_safety",
        "source_dataset",
        "source_language",
        "scenario_type",
        "source_type",
        "origin",
    ):
        _require_info_field(info, field_name)

    request_safety = str(info["request_safety"])
    if request_safety not in V5_CLASSIFICATION_LABELS:
        raise ValueError(f"unsupported request_safety label: {request_safety}")
