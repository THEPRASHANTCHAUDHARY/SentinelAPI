import socket
import threading
import time
import unittest
from unittest.mock import patch

import httpx
import uvicorn
from fastapi.testclient import TestClient

from backend import main as scanner
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

    def create_and_get_scan(self, client, **overrides):
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

    def test_real_sandbox_scan_evidence_and_redaction(self):
        with TestClient(scanner.app) as client:
            self.assertEqual(client.get("/api/health").json()["status"], "ok")
            scan = self.create_and_get_scan(client)
            self.assertEqual(scan["status"], "completed", scan)
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
            "http://127.0.0.1:8002",
        ]
        with TestClient(scanner.app) as client:
            for target in invalid:
                with self.subTest(target=target):
                    result = client.post("/api/scans", json={"target": target})
                    self.assertIn(result.status_code, {400, 403})

    def test_unconfigured_loopback_target_is_rejected(self):
        with TestClient(scanner.app) as client:
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


if __name__ == "__main__":
    unittest.main()
