from __future__ import annotations

import time
from collections import defaultdict

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import Response

app = FastAPI(title="SentinelAPI Local Vulnerable Sandbox")
_request_times: dict[str, list[float]] = defaultdict(list)


def user_payload(user_id: str) -> dict[str, object]:
    return {
        "id": user_id,
        "user_id": user_id,
        "name": f"Sandbox User {user_id}",
        "email": f"{user_id}@example.test",
        "password": "demo-password-do-not-use",
        "passwordHash": "demo-hash-do-not-use",
        "token": "sandbox-token-do-not-use",
        "apiKey": "sandbox-key-do-not-use",
        "ssn": "000-00-0000",
        "internalRole": "sandbox-user",
        "internalNotes": "Controlled demo record",
        "orders": [{"id": f"{user_id}-001", "total": 125.5}],
    }


@app.get("/openapi.json", include_in_schema=False)
def openapi_document() -> dict[str, object]:
    return app.openapi()


@app.get("/openapi.yaml", include_in_schema=False)
def openapi_yaml() -> Response:
    import yaml

    return Response(yaml.safe_dump(app.openapi()), media_type="application/yaml")


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok"}


@app.get("/users/{user_id}/profile")
def profile(
    user_id: str,
    authorization: str | None = Header(default=None)
) -> dict[str, object]:
    if authorization not in {"Bearer user-a-token", "Bearer user-b-token"}:
        raise HTTPException(401, "Authentication required")

    return user_payload(user_id)

@app.get("/users/{user_id}/opaque")
def opaque_user_response(
    user_id: str, authorization: str | None = Header(default=None)
) -> dict[str, object]:
    if authorization not in {"Bearer user-a-token", "Bearer user-b-token"}:
        raise HTTPException(401, "Authentication required")
    # Deliberately lacks an owner identifier: a scanner must not infer BOLA from 200 alone.
    return {"result": {"id": user_id}}


@app.get("/admin/metrics")
def admin_metrics() -> dict[str, object]:
    # Intentionally unprotected in this isolated demo sandbox.
    return {
        "active_users": 2,
        "internal_api_key": "sandbox-key-do-not-use",
        "internalRole": "admin",
        "service": "sentinel-demo",
    }


@app.get("/rate-limit")
def rate_limit() -> dict[str, object]:
    now = time.time()
    key = "local-demo"
    _request_times[key] = [sent_at for sent_at in _request_times[key] if now - sent_at < 10]
    _request_times[key].append(now)
    # This controlled endpoint intentionally has no throttling or rate-limit headers.
    return {"accepted": True, "request_number": len(_request_times[key])}

