from __future__ import annotations

import json
from pathlib import Path

from mcp_firewall.lab_api import app


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    output_path = project_root / "data" / "lab_api_openapi.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    spec = app.openapi()
    spec["servers"] = [{"url": "http://127.0.0.1:8000", "description": "Local thesis lab API"}]
    output_path.write_text(json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"OpenAPI spec written to {output_path}")


if __name__ == "__main__":
    main()
