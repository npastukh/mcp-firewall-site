from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

GLINER2_SPAN_LABELS = (
    "env_access_pattern",
    "secret_name",
    "secret_value",
    "sensitive_path",
    "private_host",
    "secret_store_ref",
)

GLINER2_ENTITY_DESCRIPTIONS: dict[str, str] = {
    "env_access_pattern": "Code pattern used to read environment variables, such as process.env.KEY, os.getenv('KEY'), getenv('KEY'), or env['KEY'].",
    "secret_name": "Name of a secret, credential variable, password field, token field, API key identifier, authorization header name, or session field.",
    "secret_value": "Concrete value of a secret, password, bearer token, API key, webhook token, session token, or other credential.",
    "sensitive_path": "Sensitive file path or dotenv-style location pointing to secrets, credentials, private keys, restricted configs, kube tokens, ssh keys, or other protected files.",
    "private_host": "Standalone internal host, localhost name, private IP, CIDR, metadata endpoint host, or intranet DNS target, including hostnames embedded inside MCP URLs.",
    "secret_store_ref": "Reference to a secret store, vault object, KMS entry, secret manager path, Kubernetes secret name, or similar credential container.",
}
GLINER2_CLASSIFICATION_TASK = "request_safety"
GLINER2_CLASSIFICATION_LABELS = ("safe", "suspicious")
GLINER2_CLASSIFICATION_DESCRIPTIONS: dict[str, str] = {
    "safe": "Benign technical request with no suspicious secret-seeking or private-data extraction intent.",
    "suspicious": "Suspicious MCP request that attempts to locate, expose, read, extract, or infer secrets, private user data, private hosts, internal URLs, sensitive paths, or environment-based credentials.",
}


def _extract_entities(example: dict[str, object]) -> dict[str, list[str]]:
    text = str(example["text"])
    entities: dict[str, list[str]] = {}
    for label in sorted(example.get("label", []), key=lambda item: (int(item["start"]), int(item["end"]))):
        category = str(label["category"])
        value = text[int(label["start"]) : int(label["end"])]
        entities.setdefault(category, []).append(value)
    return entities


def _build_classifications(example: dict[str, object]) -> list[dict[str, object]]:
    info = dict(example.get("info", {}))
    if str(info.get("request_safety", "")) in GLINER2_CLASSIFICATION_LABELS:
        true_label = str(info["request_safety"])
    else:
        true_label = "suspicious" if example.get("label") else "safe"
    return [
        {
            "task": GLINER2_CLASSIFICATION_TASK,
            "labels": list(GLINER2_CLASSIFICATION_LABELS),
            "true_label": [true_label],
            "label_descriptions": GLINER2_CLASSIFICATION_DESCRIPTIONS,
        }
    ]


def build_gliner2_record(
    example: dict[str, object],
    *,
    entity_descriptions: dict[str, str] | None = None,
) -> dict[str, object]:
    descriptions = entity_descriptions or GLINER2_ENTITY_DESCRIPTIONS
    unknown = sorted(set(_extract_entities(example)) - set(descriptions))
    if unknown:
        raise ValueError(f"missing GLiNER2 descriptions for labels: {', '.join(unknown)}")

    return {
        "input": str(example["text"]),
        "output": {
            "entities": _extract_entities(example),
            "entity_descriptions": {label: descriptions[label] for label in sorted(descriptions)},
            "classifications": _build_classifications(example),
        },
    }


def convert_hf_style_dataset(
    examples: Sequence[dict[str, object]],
    *,
    entity_descriptions: dict[str, str] | None = None,
) -> list[dict[str, object]]:
    return [
        build_gliner2_record(example, entity_descriptions=entity_descriptions)
        for example in examples
    ]


def _load_hf_style_examples(path: Path) -> list[dict[str, object]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"dataset file must contain a JSON array: {path}")
    return raw


def write_jsonl(records: Sequence[dict[str, object]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def export_gliner2_splits(
    source_dir: Path,
    output_dir: Path,
    *,
    entity_descriptions: dict[str, str] | None = None,
) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for split_name in ("train", "validation", "test"):
        records = convert_hf_style_dataset(
            _load_hf_style_examples(source_dir / f"{split_name}.json"),
            entity_descriptions=entity_descriptions,
        )
        output_path = output_dir / f"{split_name}.jsonl"
        write_jsonl(records, output_path)
        paths[split_name] = output_path
    return paths


def ensure_hf_style_source(source_dir: Path) -> None:
    required = [source_dir / f"{split_name}.json" for split_name in ("train", "validation", "test")]
    if all(path.exists() for path in required):
        return
    missing = ", ".join(str(path) for path in required if not path.exists())
    raise FileNotFoundError(
        "HF-style GLiNER source splits are missing. Rebuild or point to the v5 span-curated dataset first: "
        + missing
    )


def write_label_schema(path: Path) -> None:
    payload = {
        "labels": list(GLINER2_SPAN_LABELS),
        "entity_descriptions": GLINER2_ENTITY_DESCRIPTIONS,
        "classification_task": GLINER2_CLASSIFICATION_TASK,
        "classification_labels": list(GLINER2_CLASSIFICATION_LABELS),
        "classification_label_descriptions": GLINER2_CLASSIFICATION_DESCRIPTIONS,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert HF-style suspicious MCP spans into GLiNER2 JSONL format.")
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path("data/mcp_suspicious_requests_hf_v5_span_curated"),
        help="Directory with HF-style train/validation/test JSON files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/mcp_suspicious_requests_gliner2_v5_span_curated"),
        help="Directory where GLiNER2 JSONL splits will be written.",
    )
    parser.add_argument(
        "--label-schema-path",
        type=Path,
        default=Path("data/mcp_suspicious_requests_gliner2_v5_span_curated/label_schema.json"),
        help="Where to save the GLiNER2 label descriptions.",
    )
    args = parser.parse_args()

    ensure_hf_style_source(args.source_dir)
    paths = export_gliner2_splits(args.source_dir, args.output_dir)
    write_label_schema(args.label_schema_path)

    for split_name in ("train", "validation", "test"):
        print(f"{split_name}: {paths[split_name]}")
    print(f"label_schema: {args.label_schema_path}")


if __name__ == "__main__":
    main()
