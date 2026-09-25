import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend import auth, main as scanner


class AuthFlow(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(auth, "AUTH_DB_PATH", Path(self.temp_dir.name) / "auth.sqlite3")
        self.db_patch.start()
        self.client = TestClient(scanner.app)

    def tearDown(self):
        self.client.close()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def signup(self, **overrides):
        payload = {
            "name": "Demo User",
            "email": "demo@example.test",
            "password": "correct horse battery staple",
            "confirm_password": "correct horse battery staple",
        }
        payload.update(overrides)
        return self.client.post("/api/auth/signup", json=payload)

    def signin(self, email="demo@example.test", password="correct horse battery staple"):
        return self.client.post("/api/auth/signin", json={"email": email, "password": password})

    def test_successful_signup_and_password_hash_is_never_returned(self):
        response = self.signup()
        self.assertEqual(response.status_code, 201, response.text)
        body = response.json()
        self.assertEqual(body["user"], {"name": "Demo User", "email": "demo@example.test"})
        self.assertNotIn("password", response.text)
        self.assertNotIn("password_hash", response.text)
        with auth._database() as connection:
            row = connection.execute("SELECT password_hash FROM users").fetchone()
        self.assertNotEqual(row["password_hash"], "correct horse battery staple")
        self.assertTrue(row["password_hash"].startswith("pbkdf2_sha256$"))

    def test_duplicate_signup_is_rejected_case_insensitively(self):
        self.assertEqual(self.signup().status_code, 201)
        duplicate = self.signup(email="DEMO@example.test")
        self.assertEqual(duplicate.status_code, 409)
        self.assertIn("already exists", duplicate.json()["detail"])

    def test_invalid_email_is_rejected(self):
        response = self.signup(email="not-an-email")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Enter a valid email address.")

    def test_weak_password_is_rejected(self):
        response = self.signup(password="short", confirm_password="short")
        self.assertEqual(response.status_code, 400)
        self.assertIn("at least 12", response.json()["detail"])

    def test_password_mismatch_is_rejected(self):
        response = self.signup(confirm_password="a different password")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Passwords do not match.")

    def test_empty_name_is_rejected(self):
        response = self.signup(name="   ")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Name is required.")

    def test_overlong_password_errors_do_not_echo_secret(self):
        secret = "Z" * 257
        signup = self.signup(password=secret, confirm_password=secret)
        signin = self.client.post(
            "/api/auth/signin", json={"email": "demo@example.test", "password": secret}
        )
        self.assertEqual(signup.status_code, 400)
        self.assertEqual(signin.status_code, 400)
        self.assertNotIn(secret, signup.text)
        self.assertNotIn(secret, signin.text)
    def test_successful_signin_and_current_user_session(self):
        self.assertEqual(self.signup().status_code, 201)
        response = self.signin()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["authenticated"], True)
        self.assertEqual(response.json()["user"]["email"], "demo@example.test")
        self.assertNotIn("password", response.text)
        self.assertNotIn("password_hash", response.text)
        cookie = response.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=lax", cookie)
        self.assertIn("path=/", cookie)
        current = self.client.get("/api/auth/me")
        self.assertEqual(current.json(), {
            "authenticated": True,
            "user": {"name": "Demo User", "email": "demo@example.test"},
        })
        self.assertNotIn("id", current.json()["user"])

    def test_invalid_signin_does_not_enumerate_accounts(self):
        self.signup()
        known = self.signin(password="wrong password")
        unknown = self.signin(email="missing@example.test")
        self.assertEqual(known.status_code, 401)
        self.assertEqual(unknown.status_code, 401)
        self.assertEqual(known.json()["detail"], "Invalid email or password.")
        self.assertEqual(unknown.json()["detail"], known.json()["detail"])

    def test_current_user_is_anonymous_without_a_session(self):
        response = self.client.get("/api/auth/me")
        self.assertEqual(response.json(), {"authenticated": False, "user": None})

    def test_session_is_required_for_scanner_and_survives_client_refresh(self):
        self.assertEqual(self.client.get("/api/scans").status_code, 401)
        self.assertEqual(self.signup().status_code, 201)
        self.assertEqual(self.signin().status_code, 200)
        self.assertEqual(self.client.get("/api/scans").status_code, 200)
        # A new request in the same cookie jar models a normal page refresh.
        self.assertEqual(self.client.get("/api/auth/me").json()["authenticated"], True)

    def test_scan_history_and_results_are_scoped_to_the_session_owner(self):
        self.signup()
        signed_in = self.signin()
        scan_id = "another-users-scan"
        scanner._scans[scan_id] = {"id": scan_id, "owner_id": -1, "created_at": "2026-01-01T00:00:00+00:00"}
        try:
            self.assertEqual(self.client.get("/api/scans").json()["scans"], [])
            self.assertEqual(self.client.get("/api/scans/" + scan_id).status_code, 404)
        finally:
            scanner._scans.pop(scan_id, None)

    def test_logout_invalidates_session_and_clears_cookie(self):
        self.signup()
        self.signin()
        response = self.client.post("/api/auth/logout")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"authenticated": False})
        self.assertIn("max-age=0", response.headers["set-cookie"].lower())
        self.assertEqual(self.client.get("/api/auth/me").json(), {"authenticated": False, "user": None})
        self.assertEqual(self.client.get("/api/scans").status_code, 401)

    def test_secure_cookie_attributes_when_secure_cookie_setting_is_enabled(self):
        self.assertEqual(self.signup().status_code, 201)
        with patch.object(auth, "COOKIE_SECURE", True):
            response = self.signin()
        self.assertEqual(response.status_code, 200)
        cookie = response.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("secure", cookie)
        self.assertIn("samesite=lax", cookie)
        self.assertIn("path=/", cookie)
        self.assertIn("max-age=28800", cookie)

    def test_frontend_pages_and_assets_are_served_without_exposing_source_files(self):
        paths = (
            "/", "/index.html", "/main.html", "/scanner.html", "/signin.html",
            "/signup.html", "/capabilities.html", "/how-it-works.html",
            "/scan-your-api.html", "/see-security-workflow.html",
            "/assets/styles/responsive.css", "/assets/js/config.js", "/assets/js/auth.js",
        )
        with TestClient(scanner.app) as client:
            for path in paths:
                with self.subTest(path=path):
                    self.assertEqual(client.get(path).status_code, 200)
            self.assertEqual(client.get("/backend/main.py").status_code, 404)
            self.assertEqual(client.get("/README.md").status_code, 404)

    def test_unhandled_api_errors_return_safe_json(self):
        test_app = FastAPI()
        test_app.add_exception_handler(Exception, scanner.unexpected_error_handler)

        @test_app.get("/fail")
        def fail():
            raise RuntimeError("/secret/config.env private-token")

        with TestClient(test_app, raise_server_exceptions=False) as client:
            response = client.get("/fail")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"detail": "An unexpected server error occurred."})
        self.assertNotIn("secret", response.text.lower())
        self.assertNotIn("private-token", response.text)

    def test_auth_storage_errors_return_safe_json(self):
        with patch.object(auth, "_connect", side_effect=sqlite3.OperationalError("/secret/db path is read-only")):
            response = self.signup()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "Authentication storage is temporarily unavailable."})
        self.assertNotIn("secret", response.text.lower())
        self.assertNotIn("sqlite", response.text.lower())

    def test_expired_session_is_rejected_server_side(self):
        self.signup()
        self.signin()
        with auth._database() as connection:
            connection.execute("UPDATE sessions SET expires_at = 0")
        self.assertEqual(self.client.get("/api/auth/me").json(), {"authenticated": False, "user": None})
        self.assertEqual(self.client.get("/api/scans").status_code, 401)

    def test_malformed_signup_is_rejected_without_internal_details(self):
        response = self.client.post("/api/auth/signup", content="{")
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("Traceback", response.text)
        self.assertNotIn("sqlite", response.text.lower())


if __name__ == "__main__":
    unittest.main()