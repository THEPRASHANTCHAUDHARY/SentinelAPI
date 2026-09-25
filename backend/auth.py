from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field, SecretStr

router = APIRouter(prefix="/api/auth", tags=["authentication"])
AUTH_DB_PATH = Path(os.getenv(
    "SENTINELAPI_AUTH_DB",
    str(Path(__file__).with_name("sentinelapi_auth.sqlite3")),
))
SESSION_COOKIE = "sentinelapi_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
PASSWORD_ITERATIONS = 310_000
COOKIE_SECURE = os.getenv("SENTINELAPI_AUTH_COOKIE_SECURE", "").lower() == "true"
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")



class SignUpRequest(BaseModel):
    name: str = Field(max_length=100)
    email: str = Field(max_length=254)
    password: SecretStr
    confirm_password: SecretStr


class SignInRequest(BaseModel):
    email: str = Field(max_length=254)
    password: SecretStr


def _connect() -> sqlite3.Connection:
    path = Path(AUTH_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at REAL NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at REAL NOT NULL
        )"""
    )
    connection.execute("CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at)")
    connection.commit()
    return connection


@contextmanager
def _database() -> Any:
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _safe_user(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": int(row["id"]), "name": row["name"], "email": row["email"]}


def _public_user(row: sqlite3.Row) -> dict[str, str]:
    return {"name": row["name"], "email": row["email"]}


def _password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return "pbkdf2_sha256$" + str(PASSWORD_ITERATIONS) + "$" + salt.hex() + "$" + digest.hex()


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def _dummy_password_hash() -> str:
    salt = bytes.fromhex("99" * 16)
    digest = hashlib.pbkdf2_hmac("sha256", b"invalid-account-placeholder", salt, PASSWORD_ITERATIONS)
    return "pbkdf2_sha256$" + str(PASSWORD_ITERATIONS) + "$" + salt.hex() + "$" + digest.hex()

_DUMMY_PASSWORD_HASH = _dummy_password_hash()

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _email_value(email: str) -> str:
    value = email.strip().lower()
    if len(value) > 254 or not _EMAIL.fullmatch(value):
        raise HTTPException(400, "Enter a valid email address.")
    return value


def _issue_session(user_id: int, response: Response) -> None:
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _database() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        connection.execute(
            "INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (_token_hash(token), user_id, now + SESSION_TTL_SECONDS),
        )
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def get_current_user(request: Request) -> dict[str, Any] | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token or len(token) > 200:
        return None
    with _database() as connection:
        row = connection.execute(
            """SELECT users.id, users.name, users.email, sessions.expires_at
               FROM sessions JOIN users ON users.id = sessions.user_id
               WHERE sessions.token_hash = ?""",
            (_token_hash(token),),
        ).fetchone()
        if row is None:
            return None
        if float(row["expires_at"]) <= time.time():
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))
            return None
        return _safe_user(row)


def require_user(request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    if user is None:
        raise HTTPException(401, "Sign in to continue.")
    return user


@router.post("/signup", status_code=201)
def signup(body: SignUpRequest) -> dict[str, Any]:
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Name is required.")
    email = _email_value(body.email)
    password = body.password.get_secret_value()
    confirm_password = body.confirm_password.get_secret_value()
    if len(password) > 256 or len(confirm_password) > 256:
        raise HTTPException(400, "Passwords must be 256 characters or fewer.")
    if len(password) < 12:
        raise HTTPException(400, "Use a password with at least 12 characters.")
    if password != confirm_password:
        raise HTTPException(400, "Passwords do not match.")
    try:
        with _database() as connection:
            cursor = connection.execute(
                "INSERT INTO users(name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, _password_hash(password), time.time()),
            )
            row = connection.execute(
                "SELECT id, name, email FROM users WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "An account with this email already exists.") from exc
    return {"message": "Account created. Sign in to continue.", "user": _public_user(row)}

@router.post("/signin")
def signin(body: SignInRequest, response: Response) -> dict[str, Any]:
    email = _email_value(body.email)
    password = body.password.get_secret_value()
    if len(password) > 256:
        raise HTTPException(400, "Password must be 256 characters or fewer.")
    with _database() as connection:
        row = connection.execute(
            "SELECT id, name, email, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()
    encoded = row["password_hash"] if row is not None else _DUMMY_PASSWORD_HASH
    password_valid = _verify_password(password, encoded)
    if row is None or not password_valid:
        raise HTTPException(401, "Invalid email or password.")
    _issue_session(int(row["id"]), response)
    return {"authenticated": True, "user": _public_user(row)}

@router.post("/logout")
def logout(request: Request, response: Response) -> dict[str, bool]:
    token = request.cookies.get(SESSION_COOKIE)
    if token and len(token) <= 200:
        with _database() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))
    response.delete_cookie(
        SESSION_COOKIE, path="/", httponly=True, secure=COOKIE_SECURE, samesite="lax"
    )
    return {"authenticated": False}


@router.get("/me")
def current_user(request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    if user is None:
        return {"authenticated": False, "user": None}
    return {"authenticated": True, "user": {"name": user["name"], "email": user["email"]}}