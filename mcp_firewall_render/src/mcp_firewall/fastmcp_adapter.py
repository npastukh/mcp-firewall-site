from __future__ import annotations

import json
from pathlib import Path


def main() -> None:
    try:
        from fastmcp import FastMCP  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on external package
        print("FastMCP is not installed in the current environment.")
        print("Install it in the local .venv and rerun this command.")
        print(f"Import error: {exc}")
        return

    project_root = Path(__file__).resolve().parents[2]
    spec_path = project_root / "data" / "lab_api_openapi.json"
    if not spec_path.exists():
        raise SystemExit(f"OpenAPI spec not found: {spec_path}")

    server = FastMCP.from_openapi(
        openapi_spec=json.loads(spec_path.read_text(encoding="utf-8")),
        name="lab-api-mcp",
    )
    print("FastMCP server successfully created from OpenAPI spec.")
    print("Server object:", server)


if __name__ == "__main__":
    main()
