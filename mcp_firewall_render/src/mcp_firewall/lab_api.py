from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from fastapi import Body, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field


@dataclass(slots=True)
class Product:
    product_id: int
    name: str
    category: str
    price: float
    public: bool = True


class FetchRequest(BaseModel):
    url: str = Field(..., description="URL to fetch through the backend proxy.")


class UserPatchRequest(BaseModel):
    email: str | None = None
    profile_note: str | None = None
    role: str | None = None
    is_admin: bool | None = None


class ReportRequest(BaseModel):
    scope: str = Field(default="public", description="public or all")
    note: str | None = None


PRODUCTS = {
    1: Product(product_id=1, name="Notebook", category="office", price=3.5),
    2: Product(product_id=2, name="Laptop", category="electronics", price=1199.0),
    3: Product(product_id=3, name="Internal Token Guide", category="docs", price=0.0, public=False),
}

USERS: dict[int, dict[str, Any]] = {
    1: {"user_id": 1, "email": "analyst@example.com", "role": "user", "profile_note": "public profile"},
    2: {"user_id": 2, "email": "ops@example.com", "role": "support", "profile_note": "limited internal access"},
}

FILES = {
    "/public/readme.txt": "Welcome to the public documentation.",
    "/public/token-rotation.md": "How to rotate API tokens safely.",
    "/private/.env": "DB_PASSWORD=prod-secret\nJWT_SECRET=ultra-secret\n",
    "/private/config/admin.yaml": "admin_mode: true\ntelemetry_token: hidden-token\n",
}


def create_lab_api() -> FastAPI:
    app = FastAPI(
        title="VAmPI-style Training API",
        version="0.1.0",
        description=(
            "A small intentionally vulnerable backend used as a reproducible laboratory "
            "for the MCP firewall thesis."
        ),
    )

    @app.get("/health", tags=["public"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/products/{product_id}", tags=["public"])
    def get_product(product_id: int) -> dict[str, Any]:
        product = PRODUCTS.get(product_id)
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        return asdict(product)

    @app.get("/products", tags=["public"])
    def list_products(include_internal: bool = Query(default=False)) -> list[dict[str, Any]]:
        return [
            asdict(product)
            for product in PRODUCTS.values()
            if include_internal or product.public
        ]

    @app.get("/files/read", tags=["filesystem"])
    def read_file(path: str = Query(..., description="Path to read from the backend file store")) -> dict[str, str]:
        content = FILES.get(path)
        if content is None:
            raise HTTPException(status_code=404, detail="File not found")
        return {"path": path, "content": content}

    @app.get("/internal/config", tags=["internal"])
    def internal_config() -> dict[str, str]:
        return {
            "db_host": "internal-db",
            "db_user": "service_account",
            "db_password": "prod-password",
            "jwt_secret": "hidden-jwt-secret",
        }

    @app.get("/admin/debug", tags=["admin"])
    def admin_debug() -> dict[str, Any]:
        return {
            "service": "training-api",
            "debug_mode": True,
            "telemetry_token": "debug-telemetry-token",
            "connected_backends": ["postgres", "s3", "internal-api"],
        }

    @app.post("/users/{user_id}", tags=["users"])
    def patch_user(user_id: int, payload: UserPatchRequest = Body(...)) -> dict[str, Any]:
        user = USERS.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Intentionally vulnerable mass-assignment style update for the lab.
        for key, value in payload.model_dump(exclude_none=True).items():
            user[key] = value
        return user

    @app.post("/reports/export", tags=["reports"])
    def export_report(payload: ReportRequest = Body(...)) -> dict[str, Any]:
        if payload.scope == "all":
            return {
                "scope": payload.scope,
                "rows": 2500,
                "contains_sensitive_fields": True,
                "preview": ["email", "token_hint", "internal_note"],
                "note": payload.note,
            }
        return {
            "scope": "public",
            "rows": 120,
            "contains_sensitive_fields": False,
            "preview": ["title", "created_at", "city"],
            "note": payload.note,
        }

    @app.post("/proxy/fetch", tags=["network"])
    def proxy_fetch(request: FetchRequest) -> dict[str, Any]:
        parsed = urlparse(request.url)
        return {
            "url": request.url,
            "hostname": parsed.hostname,
            "scheme": parsed.scheme,
            "fetched": True,
        }

    return app


app = create_lab_api()
