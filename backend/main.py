from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from . import auth

DEFAULT_TARGET = "http://127.0.0.1:8001"
ALLOWED_ORIGINS = {
    origin.strip().rstrip("/")
    for origin in os.getenv("SENTINELAPI_ALLOWED_ORIGINS", DEFAULT_TARGET).split(",")
    if origin.strip()
}
MAX_SPEC_BYTES = 2_000_000
MAX_RESPONSE_BYTES = 1_000_000
MAX_ENDPOINTS = 250
MAX_TESTED_ENDPOINTS = 50

app = FastAPI(title="SentinelAPI", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    allow_credentials=True,
)
app.include_router(auth.router)
_lock = threading.RLock()
_scans: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target: str = Field(default=DEFAULT_TARGET, max_length=300)
    spec_url: str | None = Field(default=None, max_length=500)
    identity: str = "user-a"
    test_classes: list[str] = Field(
        default_factory=lambda: ["bola", "exposure", "authentication", "rate-limit"]
    )


def check_origin(url: str, *, allow_path: bool = False) -> str:
    """Accept an explicitly configured loopback origin without resolving DNS."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(400, "Enter a valid sandbox URL.") from exc

    if (
        parsed.scheme != "http"
        or not host
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (not allow_path and parsed.path not in ("", "/"))
        or (allow_path and parsed.path and not parsed.path.startswith("/"))
    ):
        raise HTTPException(403, "Only a plain HTTP sandbox origin is allowed.")

    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise HTTPException(403, "Only explicitly configured loopback IP targets are allowed.")

    origin = f"http://{parsed.netloc}".rstrip("/")
    if origin not in ALLOWED_ORIGINS:
        raise HTTPException(403, "Target outside authorized scan boundary.")
    return origin


def safe_request(
    client: httpx.Client, method: str, url: str, headers: dict[str, str] | None = None,
    *, max_bytes: int = MAX_RESPONSE_BYTES,
) -> httpx.Response:
    parsed = urlparse(url)
    check_origin(f"{parsed.scheme}://{parsed.netloc}")
    with client.stream(method, url, headers=headers or {}, follow_redirects=False) as response:
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > max_bytes:
                raise ValueError("Sandbox response exceeds the configured size limit.")
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            content=bytes(body),
            request=response.request,
        )


def unpack_spec(response: httpx.Response) -> dict[str, Any]:
    try:
        result = response.json()
    except ValueError:
        try:
            import yaml

            result = yaml.safe_load(response.text)
        except Exception as exc:
            raise ValueError("Invalid OpenAPI document. Provide valid JSON or YAML.") from exc
    if not isinstance(result, dict):
        raise ValueError("OpenAPI document must be a JSON/YAML object.")
    return result


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _update_scan(scan_id: str, **values: Any) -> None:
    with _lock:
        scan = _scans.get(scan_id)
        if scan is not None:
            scan.update(values, updated_at=_timestamp())


def _is_protected_candidate(path: str, security_required: bool) -> bool:
    if re.search(r"/(?:health|ready|live|status)/?$", path, re.I):
        return False
    return security_required or bool(
        re.search(r"/(?:admin|private|accounts?)(?:/|$)|/users?/\{[^}]+\}|/profiles?/\{[^}]+\}", path, re.I)
    )


def _nonempty(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def _sensitive_field(name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    exact = {
        "password", "passwordhash", "token", "accesstoken", "refreshtoken",
        "apikey", "secret", "clientsecret", "ssn", "socialsecuritynumber",
        "internalrole", "internalnotes", "privatekey", "credential", "credentials",
    }
    return normalized in exact or normalized.endswith(
        ("password", "passwordhash", "token", "apikey", "secret", "ssn", "privatekey")
    )


def _sensitive_paths(value: Any, prefix: str = "", depth: int = 0) -> list[str]:
    if depth > 8:
        return []
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in list(value.items())[:100]:
            path = f"{prefix}.{key}" if prefix else str(key)
            if _sensitive_field(str(key)) and _nonempty(child):
                found.append(path)
            found.extend(_sensitive_paths(child, path, depth + 1))
    elif isinstance(value, list):
        for index, child in enumerate(value[:50]):
            found.extend(_sensitive_paths(child, f"{prefix}[{index}]", depth + 1))
    return found


def _matches_subject(payload: Any, expected: str, *, root: bool = True) -> tuple[bool, str | None]:
    """Require the response to identify the requested owner, not an unrelated nested id."""
    owner_keys = {"user_id", "owner_id", "account_id", "subject_id", "owner", "sub"}
    if not isinstance(payload, dict):
        return False, None
    root_id = payload.get("id") if root else None
    if root_id is not None and str(root_id) == expected:
        return True, str(root_id)
    for key, value in payload.items():
        if key.lower() in owner_keys and value is not None and str(value) == expected:
            return True, str(value)
        if isinstance(value, dict):
            matched, subject = _matches_subject(value, expected, root=False)
            if matched:
                return True, subject
        elif isinstance(value, list):
            for item in value[:50]:
                matched, subject = _matches_subject(item, expected, root=False)
                if matched:
                    return True, subject
    return False, None


def _redact(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return "<TRUNCATED>"
    if isinstance(value, dict):
        return {
            key: "<REDACTED>" if _sensitive_field(str(key)) else _redact(child, depth + 1)
            for key, child in list(value.items())[:100]
        }
    if isinstance(value, list):
        return [_redact(child, depth + 1) for child in value[:50]]
    return value


def _finding(
    kind: str, severity: str, confidence: str, endpoint: dict[str, Any],
    response: httpx.Response, description: str, remediation: str,
    *, affected_fields: list[str] | None = None, extra_evidence: dict[str, Any] | None = None,
    heuristic: bool = False,
) -> dict[str, Any]:
    try:
        excerpt = json.dumps(_redact(response.json()), ensure_ascii=False)[:700]
    except (ValueError, UnicodeDecodeError):
        excerpt = re.sub(
            r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+", r"\1<REDACTED>", response.text[:700]
        )
    evidence: dict[str, Any] = {"status": response.status_code, "excerpt": excerpt}
    if affected_fields:
        evidence["affected_fields"] = affected_fields
    if extra_evidence:
        evidence.update(extra_evidence)
    finding: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "type": kind,
        "severity": severity,
        "confidence": confidence,
        "method": endpoint["method"],
        "endpoint": endpoint["path"],
        "description": description,
        "evidence": evidence,
        "poc": f"{endpoint['method']} {endpoint['path']}\nAuthorization: Bearer <REDACTED>",
        "remediation": remediation,
    }
    if heuristic:
        finding["heuristic"] = True
    return finding


def _run_scan(scan_id: str, request: dict[str, Any]) -> None:
    try:
        target = check_origin(request["target"])
        spec_url = request.get("spec_url") or f"{target}/openapi.json"
        parsed_spec = urlparse(spec_url)
        if (
            parsed_spec.scheme != "http"
            or parsed_spec.netloc != urlparse(target).netloc
            or parsed_spec.username
            or parsed_spec.password
            or parsed_spec.query
            or parsed_spec.fragment
            or not parsed_spec.path.startswith("/")
        ):
            raise ValueError("OpenAPI specification must use the configured sandbox origin without credentials or query parameters.")

        _update_scan(scan_id, status="running", stage="Loading OpenAPI specification")
        with httpx.Client(timeout=4.0, trust_env=False) as client:
            spec_response = safe_request(
                client, "GET", spec_url,
                {"Accept": "application/json, application/yaml, text/yaml"},
                max_bytes=MAX_SPEC_BYTES,
            )
            if spec_response.status_code != 200:
                raise ValueError(f"OpenAPI request returned HTTP {spec_response.status_code}.")
            spec = unpack_spec(spec_response)
            version = spec.get("openapi")
            swagger = spec.get("swagger")
            if not (
                (isinstance(version, str) and version.startswith("3."))
                or swagger == "2.0"
            ):
                raise ValueError("Unsupported or invalid OpenAPI/Swagger version.")

            if swagger == "2.0":
                swagger_host = spec.get("host")
                if swagger_host and str(swagger_host).lower() != urlparse(target).netloc.lower():
                    raise ValueError("Swagger host is outside the configured sandbox target.")
                base_path = spec.get("basePath") or "/"
                parsed_base = urlparse(base_path) if isinstance(base_path, str) else None
                if (
                    parsed_base is None
                    or not parsed_base.path.startswith("/")
                    or parsed_base.scheme
                    or parsed_base.netloc
                    or parsed_base.query
                    or parsed_base.fragment
                    or "\\" in base_path
                    or any(part in {".", ".."} for part in parsed_base.path.split("/"))
                ):
                    raise ValueError("Invalid Swagger basePath.")
                api_url = target + parsed_base.path.rstrip("/")
            else:
                servers = spec.get("servers") or [{"url": target}]
                api_url = urljoin(f"{target}/", str(servers[0].get("url", target))).rstrip("/")
            try:
                api_origin = check_origin(api_url, allow_path=True)
            except HTTPException as exc:
                raise ValueError("OpenAPI server is outside the configured sandbox target.") from exc
            if api_origin != target:
                raise ValueError("OpenAPI server is outside the configured sandbox target.")
            api_prefix = urlparse(api_url).path.rstrip("/")

            endpoints: list[dict[str, Any]] = []
            for path, path_item in (spec.get("paths") or {}).items():
                if not isinstance(path_item, dict):
                    continue
                for method, operation in path_item.items():
                    method = method.upper()
                    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"} or not isinstance(operation, dict):
                        continue
                    security = operation.get("security", spec.get("security"))
                    full_path = f"{api_prefix}{path}" if api_prefix else path
                    if not full_path.startswith("/"):
                        full_path = "/" + full_path
                    endpoints.append({
                        "method": method,
                        "path": full_path,
                        "url": target + re.sub(r"\{([^}]+)\}", "1", full_path),
                        "security_required": bool(security),
                    })
            endpoints = endpoints[:MAX_ENDPOINTS]
            _update_scan(
                scan_id, stage="Discovering endpoints", endpoints=endpoints,
                endpoint_count=len(endpoints),
            )

            identity = request.get("identity", "user-a")
            own_user_id, other_user_id = (("101", "102") if identity == "user-a" else ("102", "101"))
            token = "user-a-token" if identity == "user-a" else "user-b-token"
            auth_headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
            anon_headers = {"Accept": "application/json"}
            selected = set(request["test_classes"])
            findings: list[dict[str, Any]] = []
            rate_probe_complete = False
            rate_candidate = None
            if "rate-limit" in selected:
                get_endpoints = [ep for ep in endpoints[:MAX_TESTED_ENDPOINTS] if ep["method"] == "GET"]
                rate_candidate = next(
                    (ep for ep in get_endpoints if re.search(r"rate.?limit", ep["path"], re.I)),
                    next((ep for ep in get_endpoints if not re.search(r"/health/?$|/openapi\.json$", ep["path"], re.I)), None),
                )

            for index, endpoint in enumerate(endpoints[:MAX_TESTED_ENDPOINTS]):
                _update_scan(
                    scan_id,
                    stage=f"Analyzing endpoints ({index + 1}/{min(len(endpoints), MAX_TESTED_ENDPOINTS)})",
                )
                if endpoint["method"] not in {"GET", "HEAD"}:
                    continue
                try:
                    response = safe_request(client, endpoint["method"], endpoint["url"], auth_headers)
                except (httpx.HTTPError, ValueError):
                    continue
                try:
                    payload = response.json()
                except (ValueError, UnicodeDecodeError):
                    payload = None

                if "authentication" in selected and _is_protected_candidate(
                    endpoint["path"], endpoint["security_required"]
                ):
                    try:
                        anonymous = safe_request(client, endpoint["method"], endpoint["url"], anon_headers)
                    except (httpx.HTTPError, ValueError):
                        anonymous = None
                    if anonymous is not None and 200 <= anonymous.status_code < 300 and anonymous.content:
                        findings.append(_finding(
                            "Authentication misconfiguration", "MEDIUM", "medium", endpoint,
                            anonymous,
                            f"Unauthenticated {endpoint['method']} request to this protected candidate returned HTTP {anonymous.status_code} and a non-empty response.",
                            "Require and enforce authentication before returning this protected resource.",
                            extra_evidence={"authentication": "none", "response_status": anonymous.status_code},
                        ))

                if "exposure" in selected and 200 <= response.status_code < 300 and payload is not None:
                    fields = sorted(set(_sensitive_paths(payload)))
                    if fields:
                        findings.append(_finding(
                            "Excessive data exposure", "HIGH", "medium", endpoint, response,
                            "Sensitive fields were returned to the caller: " + ", ".join(fields) + ". These values can expose credentials or internal personal data and should not be serialized in this response.",
                            "Return only fields required by the caller and never serialize credentials or internal-only fields.",
                            affected_fields=fields,
                        ))

                match = re.search(r"/users?/\{([^}]+)\}", endpoint["path"], re.I)
                if "bola" in selected and match and endpoint["path"].count("{") == 1:
                    parameter = match.group(1)
                    own_path = endpoint["path"].replace("{" + parameter + "}", own_user_id, 1)
                    other_path = endpoint["path"].replace("{" + parameter + "}", other_user_id, 1)
                    own_url = target + own_path
                    other_url = target + other_path
                    try:
                        own_response = safe_request(client, endpoint["method"], own_url, auth_headers)
                        other_response = safe_request(client, endpoint["method"], other_url, auth_headers)
                        own_payload = own_response.json() if own_response.content else None
                        other_payload = other_response.json() if other_response.content else None
                        own_matches, _ = _matches_subject(own_payload, own_user_id)
                        other_matches, observed_subject = _matches_subject(other_payload, other_user_id)
                        if (
                            200 <= own_response.status_code < 300
                            and 200 <= other_response.status_code < 300
                            and own_matches
                            and other_matches
                            and own_payload != other_payload
                        ):
                            cross_endpoint = {**endpoint, "path": other_path}
                            source_name = "User A" if identity == "user-a" else "User B"
                            findings.append(_finding(
                                "BOLA / IDOR", "HIGH", "high", cross_endpoint, other_response,
                                f"The {source_name} identity's authenticated request for {own_path} returned HTTP {own_response.status_code}. The same credentials requested {other_path}; the API returned the resource identified as user {observed_subject} with HTTP {other_response.status_code}, which crosses the user-level authorization boundary.",
                                "Enforce object-level authorization for every resource using the authenticated principal.",
                                extra_evidence={
                                    "authenticated_identity": identity,
                                    "expected_resource": own_path,
                                    "cross_resource_requested": other_path,
                                    "own_resource_status": own_response.status_code,
                                    "cross_resource_status": other_response.status_code,
                                    "returned_subject": observed_subject,
                                    "affected_parameter": parameter,
                                },
                            ))
                    except (httpx.HTTPError, ValueError):
                        pass

                if "rate-limit" in selected and not rate_probe_complete and endpoint is rate_candidate:
                    rate_probe_complete = True
                    statuses: list[int] = []
                    rate_headers: dict[str, str] = {}
                    rate_responses: list[httpx.Response] = []
                    for _ in range(4):
                        try:
                            probe_response = safe_request(client, "GET", endpoint["url"], auth_headers)
                        except (httpx.HTTPError, ValueError):
                            break
                        rate_responses.append(probe_response)
                        statuses.append(probe_response.status_code)
                        rate_headers.update({
                            key: value for key, value in probe_response.headers.items()
                            if key.lower() == "retry-after"
                            or key.lower().startswith("x-ratelimit-")
                            or key.lower().startswith("ratelimit-")
                        })
                    has_signal = any(status == 429 for status in statuses) or bool(rate_headers)
                    if len(statuses) == 4 and all(200 <= status < 300 for status in statuses) and not has_signal:
                        findings.append(_finding(
                            "Rate-limit weakness", "LOW", "low", endpoint, rate_responses[-1],
                            "Rate-limit weakness detected based on four controlled repeated requests and absence of throttling signals; this is a heuristic, not proof that no limit exists.",
                            "Apply per-identity rate limits and return HTTP 429 with clear retry guidance when limits are exceeded.",
                            extra_evidence={"heuristic": True, "status_sequence": statuses, "rate_limit_headers": rate_headers},
                            heuristic=True,
                        ))

            _update_scan(
                scan_id, status="completed", stage="Completed", findings=findings,
                finding_count=len(findings), completed_at=_timestamp(),
            )
    except Exception as exc:
        _update_scan(scan_id, status="failed", stage="Failed", error=str(exc))


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "allowed_targets": sorted(ALLOWED_ORIGINS)}


@app.get("/api/scans")
def list_scans(user: dict[str, Any] = Depends(auth.require_user)) -> dict[str, list[dict[str, Any]]]:
    with _lock:
        scans = (scan for scan in _scans.values() if scan.get("owner_id") == user["id"])
        return {"scans": [
            {key: value for key, value in scan.items() if key != "owner_id"}
            for scan in sorted(scans, key=lambda item: item["created_at"], reverse=True)
        ]}


@app.post("/api/scans", status_code=202)
def create_scan(body: ScanRequest, background_tasks: BackgroundTasks, user: dict[str, Any] = Depends(auth.require_user)) -> dict[str, Any]:
    target = check_origin(body.target)
    if body.identity not in {"user-a", "user-b"}:
        raise HTTPException(400, "Select a supported sandbox test identity.")
    supported = {"bola", "exposure", "authentication", "rate-limit"}
    if not body.test_classes or any(test not in supported for test in body.test_classes):
        raise HTTPException(400, "Select one or more supported test classes.")

    scan_id = str(uuid.uuid4())
    now = _timestamp()
    scan = {
        "id": scan_id,
        "target": target,
        "owner_id": user["id"],
        "status": "queued",
        "stage": "Queued",
        "endpoints": [],
        "endpoint_count": 0,
        "findings": [],
        "finding_count": 0,
        "created_at": now,
        "updated_at": now,
    }
    with _lock:
        _scans[scan_id] = scan
    background_tasks.add_task(_run_scan, scan_id, {**body.model_dump(), "target": target})
    return {key: value for key, value in scan.items() if key != "owner_id"}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, user: dict[str, Any] = Depends(auth.require_user)) -> dict[str, Any]:
    with _lock:
        scan = _scans.get(scan_id)
        if scan is None or scan.get("owner_id") != user["id"]:
            raise HTTPException(404, "Scan not found.")
        return {key: value for key, value in scan.items() if key != "owner_id"}
