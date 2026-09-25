import socket
import threading
import time
import tempfile
import uuid
from pathlib import Path
import unittest
from unittest.mock import patch

import httpx
import uvicorn
from fastapi.testclient import TestClient

from backend import auth, main as scanner
from vulnerable_api.main import app as sandbox


class ScanFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        cls.port = probe.getsockname()[1]
        probe.close()
        cls.target = f"http://127.0.0.1:{cls.port}"
        scanner.ALLOWED_ORIGINS = {cls.target}
        cls._auth_db_path = auth.AUTH_DB_PATH
        cls._auth_db_dir = tempfile.TemporaryDirectory()
        auth.AUTH_DB_PATH = Path(cls._auth_db_dir.name) / "scan-tests.sqlite3"
        cls.server = uvicorn.Server(
            uvicorn.Config(sandbox, host="127.0.0.1", port=cls.port, log_level="error")
        )
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        for _ in range(60):
            try:
                if httpx.get(cls.target + "/openapi.json", timeout=0.2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Sandbox did not start")

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=3)
        auth.AUTH_DB_PATH = cls._auth_db_path
        cls._auth_db_dir.cleanup()

    def authenticate(self, client):
        email = "scan-" + uuid.uuid4().hex + "@example.test"
        payload = {"name": "Scan Test", "email": email, "password": "scan test password long", "confirm_password": "scan test password long"}
        created = client.post("/api/auth/signup", json=payload)
        self.assertEqual(created.status_code, 201, created.text)
        signed_in = client.post("/api/auth/signin", json={"email": email, "password": payload["password"]})
        self.assertEqual(signed_in.status_code, 200, signed_in.text)

    def create_and_get_scan(self, client, **overrides):
        self.authenticate(client)
        payload = {
            "target": self.target,
            "spec_url": self.target + "/openapi.json",
            "identity": "user-a",
            "test_classes": ["bola", "exposure", "authentication", "rate-limit"],
        }
        payload.update(overrides)
        created = client.post("/api/scans", json=payload)
        self.assertEqual(created.status_code, 202, created.text)
        return client.get("/api/scans/" + created.json()["id"]).json()

    def test_scan_page_does_not_restore_saved_history_on_load(self):
        with open("assets/js/scan-page.js", encoding="utf-8") as source_file:
            source = source_file.read()
        with open("scan-your-api.html", encoding="utf-8") as html_file:
            html = html_file.read()
        self.assertNotIn("listScans", source)
        self.assertIn('id="scan-status">IDLE', html)
        self.assertIn('id="scan-endpoint-count">0</span>', html)
        self.assertIn('id="scan-endpoints" aria-live="polite">No scan data yet.', html)
        self.assertIn('id="scan-findings" aria-live="polite">Findings will appear when scan evidence is available.', html)
    def test_real_sandbox_scan_evidence_and_redaction(self):
        with TestClient(scanner.app) as client:
            self.assertEqual(client.get("/api/health").json()["status"], "ok")
            self.assertEqual(httpx.get(self.target + "/health", timeout=2).status_code, 200)
            scan = self.create_and_get_scan(client)
            self.assertEqual(scan["status"], "completed", scan)
            history = client.get("/api/scans").json()["scans"]
            recorded = next(item for item in history if item["id"] == scan["id"])
            self.assertEqual(recorded["finding_count"], scan["finding_count"])
            self.assertEqual(scan["endpoint_count"], 5)
            findings = scan["findings"]
            kinds = {finding["type"] for finding in findings}
            self.assertEqual(kinds, {
                "BOLA / IDOR", "Excessive data exposure",
                "Authentication misconfiguration", "Rate-limit weakness",
            })
            for finding in findings:
                for field in ("type", "severity", "confidence", "endpoint", "method", "evidence", "poc", "remediation"):
                    self.assertTrue(finding.get(field), (finding["type"], field))
                self.assertIn(finding["severity"], {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
                self.assertIn("<REDACTED>", finding["poc"])
                excerpt = finding["evidence"]["excerpt"]
                for secret in ("demo-password-do-not-use", "demo-hash-do-not-use", "sandbox-token-do-not-use", "sandbox-key-do-not-use", "000-00-0000"):
                    self.assertNotIn(secret, excerpt)

            bola = next(f for f in findings if f["type"] == "BOLA / IDOR")
            self.assertEqual(bola["method"], "GET")
            self.assertEqual(bola["endpoint"], "/users/102/profile")
            self.assertEqual(bola["evidence"]["authenticated_identity"], "user-a")
            self.assertEqual(bola["evidence"]["expected_resource"], "/users/101/profile")
            self.assertEqual(bola["evidence"]["cross_resource_requested"], "/users/102/profile")
            self.assertEqual(bola["evidence"]["returned_subject"], "102")
            self.assertIn("crosses the user-level authorization boundary", bola["description"])
            self.assertFalse(any(f["type"] == "BOLA / IDOR" and "opaque" in f["endpoint"] for f in findings))

            exposure = next(f for f in findings if f["type"] == "Excessive data exposure")
            self.assertTrue({"password", "passwordHash", "token", "apiKey", "ssn", "internalRole", "internalNotes"}.issubset(set(exposure["evidence"]["affected_fields"])))

            auth_findings = [f for f in findings if f["type"] == "Authentication misconfiguration"]
            self.assertTrue(auth_findings)
            self.assertTrue(all(f["endpoint"] != "/health" for f in auth_findings))
            self.assertTrue(all(f["evidence"]["authentication"] == "none" for f in auth_findings))

            rate = next(f for f in findings if f["type"] == "Rate-limit weakness")
            self.assertTrue(rate["heuristic"])
            self.assertEqual(rate["evidence"]["status_sequence"], [200, 200, 200, 200])
            self.assertEqual(rate["evidence"]["rate_limit_headers"], {})

    def test_server_side_boundary_rejects_invalid_origins_without_dns_allowance(self):
        invalid = [
            "https://example.com",
            "http://192.168.1.10:8001",
            "file:///etc/passwd",
            "ftp://127.0.0.1:8001",
            "http://user:password@127.0.0.1:8001",
            "http://127.0.0.1:8001/?next=http://example.com",
            "http://127.0.0.1.evil.test:8001",
            "http://localhost:8001",
            "http://127.0.0.1:8002",
        ]
        with TestClient(scanner.app) as client:
            self.authenticate(client)
            for target in invalid:
                with self.subTest(target=target):
                    result = client.post("/api/scans", json={"target": target})
                    self.assertIn(result.status_code, {400, 403})

    def test_unconfigured_loopback_target_is_rejected(self):
        with TestClient(scanner.app) as client:
            self.authenticate(client)
            result = client.post("/api/scans", json={"target": "http://127.0.0.1:8001"})
            self.assertEqual(result.status_code, 403)

    def test_rate_limit_headers_suppress_heuristic(self):
        real_request = scanner.safe_request

        def add_rate_header(client, method, url, headers=None, **kwargs):
            response = real_request(client, method, url, headers, **kwargs)
            if url.endswith("/rate-limit"):
                response.headers["X-RateLimit-Limit"] = "10"
                response.headers["X-RateLimit-Remaining"] = "6"
            return response

        with patch.object(scanner, "safe_request", side_effect=add_rate_header):
            with TestClient(scanner.app) as client:
                scan = self.create_and_get_scan(client, test_classes=["rate-limit"])
        self.assertEqual(scan["status"], "completed")
        self.assertFalse(any(f["type"] == "Rate-limit weakness" for f in scan["findings"]))

    def test_yaml_openapi_is_supported(self):
        with TestClient(scanner.app) as client:
            scan = self.create_and_get_scan(client, spec_url=self.target + "/openapi.yaml", test_classes=["exposure"])
        self.assertEqual(scan["status"], "completed", scan)
        self.assertEqual(scan["endpoint_count"], 5)

    def test_invalid_openapi_fails_without_mock_results(self):
        with TestClient(scanner.app) as client:
            scan = self.create_and_get_scan(client, spec_url=self.target + "/not-openapi")
        self.assertEqual(scan["status"], "failed")
        self.assertFalse(scan["findings"])


    def test_cors_allows_frontend_and_rejects_null_and_external_origins(self):
        with TestClient(scanner.app) as client:
            for origin in ("http://127.0.0.1:5500", "http://localhost:5500"):
                response = client.options("/api/scans", headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                })
                self.assertEqual(response.headers.get("access-control-allow-origin"), origin)
            for origin in ("null", "https://attacker.example"):
                response = client.options("/api/scans", headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                })
                self.assertNotIn("access-control-allow-origin", response.headers)

    def test_sandbox_unavailable_is_recorded_without_stack_trace(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        unavailable = f"http://127.0.0.1:{port}"
        scanner.ALLOWED_ORIGINS.add(unavailable)
        try:
            with TestClient(scanner.app) as client:
                scan = self.create_and_get_scan(
                    client, target=unavailable, spec_url=unavailable + "/openapi.json",
                    test_classes=["exposure"],
                )
            self.assertEqual(scan["status"], "failed")
            self.assertFalse(scan["findings"])
            self.assertNotIn("Traceback", scan.get("error", ""))
        finally:
            scanner.ALLOWED_ORIGINS.discard(unavailable)

    def test_swagger2_json_and_yaml_base_path_are_applied(self):
        host = self.target.removeprefix("http://")
        spec = {
            "swagger": "2.0", "host": host, "basePath": "/v1",
            "schemes": ["http"], "paths": {"/health": {"get": {}}},
        }
        yaml_spec = (
            "swagger: '2.0'\n"
            f"host: {host}\n"
            "basePath: /v1\n"
            "schemes:\n  - http\n"
            "paths:\n  /health:\n    get: {}\n"
        )
        for use_yaml in (False, True):
            with self.subTest(format="yaml" if use_yaml else "json"):
                spec_url = self.target + ("/swagger2.yaml" if use_yaml else "/swagger2.json")
                requested = []
                def fake_request(client, method, url, headers=None, **kwargs):
                    if url == spec_url:
                        return httpx.Response(200, text=yaml_spec) if use_yaml else httpx.Response(200, json=spec)
                    requested.append(url)
                    return httpx.Response(200, json={"status": "ok"})
                with patch.object(scanner, "safe_request", side_effect=fake_request):
                    with TestClient(scanner.app) as client:
                        scan = self.create_and_get_scan(
                            client, spec_url=spec_url, test_classes=["exposure"],
                        )
                self.assertEqual(scan["status"], "completed", scan)
                self.assertEqual(scan["endpoint_count"], 1)
                self.assertEqual(scan["endpoints"][0]["path"], "/v1/health")
                self.assertEqual(requested, [self.target + "/v1/health"])

    def test_empty_paths_complete_with_zero_endpoints_and_findings(self):
        spec_url = self.target + "/empty-openapi.json"
        spec = {"openapi": "3.1.0", "info": {"title": "Empty", "version": "1"}, "paths": {}}
        def fake_request(client, method, url, headers=None, **kwargs):
            return httpx.Response(200, json=spec)
        with patch.object(scanner, "safe_request", side_effect=fake_request):
            with TestClient(scanner.app) as client:
                scan = self.create_and_get_scan(client, spec_url=spec_url)
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(scan["endpoint_count"], 0)
        self.assertEqual(scan["finding_count"], 0)

    def test_unsupported_spec_version_fails_without_findings(self):
        spec_url = self.target + "/unsupported.json"
        def fake_request(client, method, url, headers=None, **kwargs):
            return httpx.Response(200, json={"openapi": "2.0", "paths": {}})
        with patch.object(scanner, "safe_request", side_effect=fake_request):
            with TestClient(scanner.app) as client:
                scan = self.create_and_get_scan(client, spec_url=spec_url)
        self.assertEqual(scan["status"], "failed")
        self.assertIn("Unsupported", scan["error"])
        self.assertFalse(scan["findings"])

    def test_malformed_json_and_yaml_fail_with_safe_message(self):
        malformed = {
            "json": ("/malformed.json", "{\"openapi\": "),
            "yaml": ("/malformed.yaml", "openapi: [unclosed"),
        }
        for kind, (path, body) in malformed.items():
            with self.subTest(format=kind):
                spec_url = self.target + path
                def fake_request(client, method, url, headers=None, **kwargs):
                    return httpx.Response(200, text=body)
                with patch.object(scanner, "safe_request", side_effect=fake_request):
                    with TestClient(scanner.app) as client:
                        scan = self.create_and_get_scan(client, spec_url=spec_url)
                self.assertEqual(scan["status"], "failed")
                self.assertIn("Invalid OpenAPI document", scan["error"])
                self.assertNotIn("Traceback", scan["error"])
                self.assertFalse(scan["findings"])

    def test_spec_timeout_fails_cleanly(self):
        def timeout(*args, **kwargs):
            raise httpx.ReadTimeout("Sandbox specification request timed out.")
        with patch.object(scanner, "safe_request", side_effect=timeout):
            with TestClient(scanner.app) as client:
                scan = self.create_and_get_scan(client, test_classes=["exposure"])
        self.assertEqual(scan["status"], "failed")
        self.assertEqual(scan["error"], "Sandbox request timed out.")
        self.assertNotIn("Traceback", scan["error"])

    def test_unexpected_scan_errors_do_not_expose_internal_details(self):
        with patch.object(scanner, "safe_request", side_effect=RuntimeError("/tmp/private.sqlite3 secret")):
            with TestClient(scanner.app) as client:
                scan = self.create_and_get_scan(client, test_classes=["exposure"])
        self.assertEqual(scan["status"], "failed")
        self.assertEqual(
            scan["error"],
            "An unexpected error occurred while scanning the authorized sandbox.",
        )
        self.assertNotIn("private.sqlite3", scan["error"])
        self.assertNotIn("secret", scan["error"])

    def test_openapi_server_cannot_override_authorized_target(self):
        spec_url = self.target + "/external-server.json"
        spec = {
            "openapi": "3.1.0", "info": {"title": "Boundary", "version": "1"},
            "servers": [{"url": "https://example.com"}],
            "paths": {"/health": {"get": {}}},
        }
        def fake_request(client, method, url, headers=None, **kwargs):
            return httpx.Response(200, json=spec)
        with patch.object(scanner, "safe_request", side_effect=fake_request):
            with TestClient(scanner.app) as client:
                scan = self.create_and_get_scan(client, spec_url=spec_url)
        self.assertEqual(scan["status"], "failed")
        self.assertIn("sandbox target", scan["error"])
        self.assertFalse(scan["findings"])

if __name__ == "__main__":
    unittest.main()
