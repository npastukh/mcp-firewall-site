## What to upload

This folder is the clean backend bundle for Render.

Use this directory as the backend source when keeping everything in the current repository:

- `runtime_work/mcp_firewall_render_ready`

It already includes:

- `pyproject.toml`
- `src/`
- `artifacts/runtime/`
- `artifacts/gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1/`

It does not include the heavy local base model directory:

- `artifacts/models/fastino_gliner2_large_v1/`

During the Render build, the backend downloads the base GLiNER model automatically and prepares the runtime directory.

## Render settings

- Root Directory:
  `runtime_work/mcp_firewall_render_ready`
- Build Command:
  `HF_HUB_DISABLE_XET=1 pip install -e '.[boosting,privacy-filter,gliner2]' && HF_HUB_DISABLE_XET=1 python -m mcp_firewall.prepare_runtime`
- Start Command:
  `uvicorn mcp_firewall.live_demo_api:app --host 0.0.0.0 --port $PORT`
