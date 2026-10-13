"""Local accounts, roles, cookie sessions and one-time email tokens.

Roles: "admin" manages users, integrations, AI providers and announcements;
"analyst" works incidents and uses the console. Replace with OIDC later.
"""
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request

from .db import db, iso, now

COOKIE = "cerberus_session"
SESSION_HOURS = 12
MAX_FAILURES = 5
LOCK_SECONDS = 60
ROLES = ("admin", "analyst")
TOKEN_HOURS = {"verify": 72, "reset": 1}

_failures: dict[str, tuple[int, float]] = {}


def hash_password(password: str, salt: str) -> str:
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_user(conn, username: str, password: str = "", *, email: str = "", role: str = "analyst",
                verified: bool = False) -> int:
    """An empty password creates an invited account that cannot sign in until one is set."""
    salt = secrets.token_hex(16)
    cur = conn.execute(
        "INSERT INTO users (username, pw_hash, salt, role, email, email_verified, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (username, hash_password(password, salt) if password else "", salt, role, email.lower(),
         int(verified), now()),
    )
    return cur.lastrowid


def set_password(conn, user_id: int, password: str) -> None:
    """Change the password and sign the user out everywhere."""
    salt = secrets.token_hex(16)
    conn.execute("UPDATE users SET pw_hash = ?, salt = ? WHERE id = ?", (hash_password(password, salt), salt, user_id))
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM user_tokens WHERE user_id = ? AND kind = 'reset'", (user_id,))


def throttle(key: str, limit: int = MAX_FAILURES, seconds: int = LOCK_SECONDS) -> None:
    """Count one attempt against `key`; raise 429 once the limit is passed inside the window."""
    count, until = _failures.get(key, (0, 0.0))
    if time.time() > until:
        count = 0
    if count >= limit:
        raise HTTPException(429, "Too many attempts. Please wait a minute and try again.")
    _failures[key] = (count + 1, time.time() + seconds)


def check_password(row, password: str) -> bool:
    # Hash even when the user is unknown so timing doesn't reveal usernames.
    salt = row["salt"] if row else "00" * 16
    candidate = hash_password(password, salt)
    return bool(row and row["pw_hash"] and hmac.compare_digest(candidate, row["pw_hash"]))


def verify_login(conn, username: str, password: str, client: str):
    key = f"login:{client}:{username.lower()}"
    count, until = _failures.get(key, (0, 0.0))
    if count >= MAX_FAILURES and time.time() < until:
        raise HTTPException(429, "Too many failed sign-in attempts. Try again in a minute.")
    row = conn.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE OR (email != '' AND email = ?)",
                       (username, username.lower())).fetchone()
    if check_password(row, password):
        _failures.pop(key, None)
        return row
    _failures[key] = (count + 1 if time.time() < until else 1, time.time() + LOCK_SECONDS)
    return None


def create_session(conn, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = iso(datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS))
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
        (_token_hash(token), user_id, expires),
    )
    conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now(), user_id))
    return token


def delete_session(conn, token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def lookup_user(conn, token: str | None):
    if not token:
        return None
    return conn.execute(
        "SELECT u.id, u.username, u.role, u.email, u.email_verified FROM sessions s "
        "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0",
        (_token_hash(token), now()),
    ).fetchone()


def issue_token(conn, user_id: int, kind: str) -> str:
    """One live token per user and kind; only its hash is stored."""
    token = secrets.token_urlsafe(32)
    expires = iso(datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS[kind]))
    conn.execute("DELETE FROM user_tokens WHERE (user_id = ? AND kind = ?) OR expires_at < ?", (user_id, kind, now()))
    conn.execute("INSERT INTO user_tokens (token_hash, user_id, kind, expires_at) VALUES (?, ?, ?, ?)",
                 (_token_hash(token), user_id, kind, expires))
    return token


def token_user(conn, token: str, kind: str):
    """The user a still-valid token belongs to, or None."""
    return conn.execute(
        "SELECT u.* FROM user_tokens t JOIN users u ON u.id = t.user_id "
        "WHERE t.token_hash = ? AND t.kind = ? AND t.expires_at > ? AND u.disabled = 0",
        (_token_hash(token), kind, now()),
    ).fetchone()


def consume_token(conn, token: str) -> None:
    conn.execute("DELETE FROM user_tokens WHERE token_hash = ?", (_token_hash(token),))


def current_user(request: Request) -> dict:
    """FastAPI dependency: the signed-in user, or 401."""
    with db() as conn:
        row = lookup_user(conn, request.cookies.get(COOKIE))
    if not row:
        raise HTTPException(401, "Sign in required")
    return dict(row)


def require_admin(user: dict = Depends(current_user)) -> dict:
    """FastAPI dependency: the signed-in user if they are an admin, else 403."""
    if user["role"] != "admin":
        raise HTTPException(403, "Only an admin can do this")
    return user
