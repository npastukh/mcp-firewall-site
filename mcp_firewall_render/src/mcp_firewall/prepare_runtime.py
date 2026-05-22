from __future__ import annotations

import json
from pathlib import Path

from huggingface_hub import snapshot_download


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _adapter_dir(project_root: Path) -> Path:
    return project_root / "artifacts" / "gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1" / "best"


def _normalize_hf_repo_id(base_model_name_or_path: str) -> str:
    candidate = base_model_name_or_path.strip().strip("/").replace("\\", "/")
    if not candidate:
        raise ValueError("base_model_name_or_path is empty")
    if "/" in candidate and not candidate.startswith("artifacts/models/"):
        return candidate

    model_name = Path(candidate).name
    parts = model_name.split("_", 1)
    if len(parts) == 2:
        namespace, repo_name = parts
        return f"{namespace}/{repo_name.replace('_', '-')}"
    return candidate


def _target_model_dir(project_root: Path, base_model_name_or_path: str) -> Path:
    base_name = Path(base_model_name_or_path).name
    return project_root / "artifacts" / "models" / base_name


def main() -> None:
    project_root = _project_root()
    adapter_dir = _adapter_dir(project_root)
    adapter_config_path = adapter_dir / "adapter_config.json"
    adapter_config = json.loads(adapter_config_path.read_text(encoding="utf-8"))
    base_model_name_or_path = str(adapter_config["base_model_name_or_path"])

    target_dir = _target_model_dir(project_root, base_model_name_or_path)
    if (target_dir / "config.json").exists() and (target_dir / "model.safetensors").exists():
        print(f"Base GLiNER model already prepared at {target_dir}")
        return

    target_dir.mkdir(parents=True, exist_ok=True)
    repo_id = _normalize_hf_repo_id(base_model_name_or_path)
    print(f"Downloading base GLiNER model {repo_id} into {target_dir}")
    snapshot_download(
        repo_id=repo_id,
        local_dir=str(target_dir),
        local_dir_use_symlinks=False,
    )
    print("Base GLiNER model prepared successfully.")


if __name__ == "__main__":
    main()
