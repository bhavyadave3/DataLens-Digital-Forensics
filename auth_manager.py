
"""DataLens authentication, investigator accounts, and case ownership.

Uses only the Python standard library and the existing DataLens SQLite database.
Authentication is performed with short-lived HMAC-signed bearer tokens. Passwords
are stored as PBKDF2-HMAC-SHA256 hashes with random per-user salts.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import evidence_manager as em

TOKEN_TTL_SECONDS = 8 * 60 * 60
PBKDF2_ITERATIONS = 600_000
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,40}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _connect() -> sqlite3.Connection:
    path = Path(em.DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")

    return conn


def _secret() -> bytes:
    value = os.environ.get("DATALENS_SECRET_KEY", "")

    if len(value) < 32:
        raise RuntimeError(
            "DATALENS_SECRET_KEY is missing or too short. "
            "Set a random secret of at least 32 characters in Render Environment."
        )

    return value.encode("utf-8")


def _hash_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")

    if len(password) > 256:
        raise ValueError("Password is too long.")

    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )

    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        _b64encode(salt),
        _b64encode(digest),
    )


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, expected_text = encoded.split("$", 3)

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations_text)

        if iterations < 100_000 or iterations > 2_000_000:
            return False

        salt = _b64decode(salt_text)
        expected = _b64decode(expected_text)

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            str(password).encode("utf-8"),
            salt,
            iterations,
        )

        return hmac.compare_digest(actual, expected)

    except (ValueError, TypeError):
        return False


def public_user(row: Any) -> dict:
    if row is None:
        return {}

    item = dict(row)
    item.pop("password_hash", None)
    item.pop("token_version", None)
    item["is_active"] = bool(item.get("is_active", 0))

    return item


def initialize_auth_schema() -> None:
    """Create auth tables and add ownership to existing cases without dropping data."""
    _secret()

    with _connect() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'investigator')),
                is_active INTEGER NOT NULL DEFAULT 1,
                token_version INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            )"""
        )

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_role ON users(role, is_active)"
        )

        conn.execute(
            """CREATE TABLE IF NOT EXISTS login_attempts (
                username_key TEXT NOT NULL,
                remote_ip TEXT NOT NULL,
                failures INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(username_key, remote_ip)
            )"""
        )

        user_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }

        if "token_version" not in user_columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0"
            )

        case_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(cases)").fetchall()
        }

        if not case_columns:
            raise RuntimeError(
                "The DataLens cases table is missing. Database initialization failed."
            )

        if "owner_id" not in case_columns:
            conn.execute("ALTER TABLE cases ADD COLUMN owner_id TEXT")

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cases_owner ON cases(owner_id, created_at)"
        )

        admin_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin'"
        ).fetchone()[0]

        if admin_count == 0:
            username = os.environ.get("DATALENS_ADMIN_USERNAME", "").strip()
            password = os.environ.get("DATALENS_ADMIN_PASSWORD", "")
            display_name = os.environ.get(
                "DATALENS_ADMIN_DISPLAY_NAME",
                "DataLens Administrator",
            ).strip()

            if not username or not password:
                raise RuntimeError(
                    "No DataLens administrator exists. Set "
                    "DATALENS_ADMIN_USERNAME and DATALENS_ADMIN_PASSWORD "
                    "in Render Environment, then redeploy."
                )

            if not USERNAME_RE.fullmatch(username):
                raise RuntimeError(
                    "DATALENS_ADMIN_USERNAME must be 3–40 characters "
                    "using letters, numbers, dot, underscore, or hyphen."
                )

            password_hash = _hash_password(password)
            admin_id = "USR-" + uuid.uuid4().hex[:16].upper()

            conn.execute(
                """INSERT INTO users
                   (user_id, username, display_name, password_hash,
                    role, is_active, created_at)
                   VALUES (?, ?, ?, ?, 'admin', 1, ?)""",
                (
                    admin_id,
                    username,
                    display_name or username,
                    password_hash,
                    _now(),
                ),
            )

            admin_user_id = admin_id

        else:
            admin = conn.execute(
                """SELECT user_id
                   FROM users
                   WHERE role = 'admin' AND is_active = 1
                   ORDER BY created_at LIMIT 1"""
            ).fetchone()

            if admin is None:
                raise RuntimeError(
                    "All DataLens administrator accounts are disabled. "
                    "Enable an administrator before continuing."
                )

            admin_user_id = admin["user_id"]

        # Assign existing pre-multi-user cases to the administrator.
        # This preserves legacy records and prevents new investigators
        # from seeing cases that existed before authentication was added.
        conn.execute(
            "UPDATE cases SET owner_id = ? WHERE owner_id IS NULL OR owner_id = ''",
            (admin_user_id,),
        )

        conn.commit()


def _get_user_by_username(username: str):
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username.strip(),),
        ).fetchone()


def get_user(user_id: str):
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    return public_user(row)


def create_user(
    username: str,
    display_name: str,
    password: str,
    role: str = "investigator",
) -> dict:
    username = str(username or "").strip()
    display_name = str(display_name or username).strip()
    role = str(role or "investigator").strip().lower()

    if not USERNAME_RE.fullmatch(username):
        raise ValueError(
            "Username must be 3–40 characters using letters, numbers, dot, underscore, or hyphen."
        )

    if not display_name or len(display_name) > 100:
        raise ValueError("Display name must contain 1–100 characters.")

    if role not in {"admin", "investigator"}:
        raise ValueError("Role must be admin or investigator.")

    encoded = _hash_password(password)
    user_id = "USR-" + uuid.uuid4().hex[:16].upper()

    with _connect() as conn:
        try:
            conn.execute(
                """INSERT INTO users
                   (user_id, username, display_name, password_hash,
                    role, is_active, created_at)
                   VALUES (?, ?, ?, ?, ?, 1, ?)""",
                (
                    user_id,
                    username,
                    display_name,
                    encoded,
                    role,
                    _now(),
                ),
            )

        except sqlite3.IntegrityError as exc:
            raise ValueError("That username is already in use.") from exc

        row = conn.execute(
            "SELECT * FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    return public_user(row)


def list_users() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """SELECT user_id, username, display_name, role,
                      is_active, created_at, last_login_at
               FROM users ORDER BY created_at ASC"""
        ).fetchall()

    return [public_user(row) for row in rows]


def set_user_active(user_id: str, active: bool) -> dict:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()

        if row is None:
            raise ValueError("User not found.")

        if row["role"] == "admin" and not active:
            admins = conn.execute(
                """SELECT COUNT(*)
                   FROM users
                   WHERE role = 'admin' AND is_active = 1"""
            ).fetchone()[0]

            if admins <= 1:
                raise ValueError(
                    "You cannot disable the last active administrator."
                )

        # Increment token_version so existing sessions are invalidated.
        conn.execute(
            """UPDATE users
               SET is_active = ?, token_version = token_version + 1
               WHERE user_id = ?""",
            (1 if active else 0, user_id),
        )

        updated = conn.execute(
            "SELECT * FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    return public_user(updated)


def admin_reset_password(user_id: str, new_password: str) -> None:
    new_hash = _hash_password(new_password)

    with _connect() as conn:
        cursor = conn.execute(
            """UPDATE users
               SET password_hash = ?, token_version = token_version + 1
               WHERE user_id = ?""",
            (new_hash, user_id),
        )

        if cursor.rowcount != 1:
            raise ValueError("User not found.")


def assign_case_owner(case_id: str, user_id: str) -> None:
    with _connect() as conn:
        user = conn.execute(
            "SELECT user_id FROM users WHERE user_id = ? AND is_active = 1",
            (user_id,),
        ).fetchone()

        if user is None:
            raise ValueError(
                "The selected investigator account does not exist or is disabled."
            )

        cursor = conn.execute(
            "UPDATE cases SET owner_id = ? WHERE case_id = ?",
            (user_id, case_id),
        )

        if cursor.rowcount != 1:
            raise ValueError("Case not found.")


def case_is_accessible(user: dict, case_id: str) -> bool:
    if not user:
        return False

    if user.get("role") == "admin":
        with _connect() as conn:
            return conn.execute(
                "SELECT 1 FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone() is not None

    with _connect() as conn:
        return conn.execute(
            """SELECT 1 FROM cases
               WHERE case_id = ? AND owner_id = ?""",
            (case_id, user.get("user_id")),
        ).fetchone() is not None


def visible_cases(user: dict) -> list[dict]:
    with _connect() as conn:
        if user.get("role") == "admin":
            rows = conn.execute(
                "SELECT * FROM cases ORDER BY created_at DESC"
            ).fetchall()

        else:
            rows = conn.execute(
                """SELECT * FROM cases
                   WHERE owner_id = ?
                   ORDER BY created_at DESC""",
                (user.get("user_id"),),
            ).fetchall()

    output = []

    for row in rows:
        item = dict(row)
        item.setdefault("status", "Open")
        item.setdefault("description", "")
        output.append(item)

    return output


def _issue_token(user: dict) -> str:
    now = int(time.time())

    payload = {
        "sub": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "ver": int(user.get("token_version", 0)),
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
        "jti": secrets.token_urlsafe(12),
    }

    body = _b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )

    signature = hmac.new(
        _secret(),
        body.encode("ascii"),
        hashlib.sha256,
    ).digest()

    return body + "." + _b64encode(signature)


def login(
    username: str,
    password: str,
    remote_ip: str = "unknown",
) -> dict:
    username = str(username or "").strip()
    username_key = username.casefold()[:80] or "(empty)"
    remote_ip = str(remote_ip or "unknown")[:64]
    now_epoch = int(time.time())

    with _connect() as conn:
        attempt = conn.execute(
            """SELECT failures, locked_until
               FROM login_attempts
               WHERE username_key = ? AND remote_ip = ?""",
            (username_key, remote_ip),
        ).fetchone()

        if attempt and int(attempt["locked_until"] or 0) > now_epoch:
            wait = int(attempt["locked_until"]) - now_epoch

            raise PermissionError(
                "Too many failed sign-in attempts. "
                f"Try again in about {max(1, (wait + 59) // 60)} minute(s)."
            )

    row = _get_user_by_username(username)

    password_ok = bool(
        row is not None
        and _verify_password(str(password or ""), row["password_hash"])
        and bool(row["is_active"])
    )

    if not password_ok:
        with _connect() as conn:
            current = conn.execute(
                """SELECT failures FROM login_attempts
                   WHERE username_key = ? AND remote_ip = ?""",
                (username_key, remote_ip),
            ).fetchone()

            failures = int(current["failures"] if current else 0) + 1
            locked_until = now_epoch + 900 if failures >= 5 else 0

            conn.execute(
                """INSERT INTO login_attempts
                   (username_key, remote_ip, failures, locked_until)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(username_key, remote_ip) DO UPDATE SET
                     failures = excluded.failures,
                     locked_until = excluded.locked_until""",
                (username_key, remote_ip, failures, locked_until),
            )

        if row is not None and not bool(row["is_active"]):
            raise PermissionError(
                "This account is disabled. Contact the administrator."
            )

        raise PermissionError("Invalid username or password.")

    with _connect() as conn:
        conn.execute(
            """DELETE FROM login_attempts
               WHERE username_key = ? AND remote_ip = ?""",
            (username_key, remote_ip),
        )

        conn.execute(
            "UPDATE users SET last_login_at = ? WHERE user_id = ?",
            (_now(), row["user_id"]),
        )

    user = public_user(row)
    token_user = {
        **user,
        "token_version": int(row["token_version"]),
    }

    return {
        "token": _issue_token(token_user),
        "user": user,
        "expires_in": TOKEN_TTL_SECONDS,
    }


def authenticate_token(token: str) -> dict | None:
    if not token or len(token) > 8192:
        return None

    try:
        body, signature_text = token.split(".", 1)

        expected = hmac.new(
            _secret(),
            body.encode("ascii"),
            hashlib.sha256,
        ).digest()

        supplied = _b64decode(signature_text)

        if not hmac.compare_digest(expected, supplied):
            return None

        payload = json.loads(
            _b64decode(body).decode("utf-8")
        )

        if int(payload.get("exp", 0)) < int(time.time()):
            return None

        user_id = str(payload.get("sub", ""))

        if not user_id:
            return None

        with _connect() as conn:
            row = conn.execute(
                """SELECT * FROM users
                   WHERE user_id = ? AND is_active = 1""",
                (user_id,),
            ).fetchone()

        if (
            row is None
            or int(payload.get("ver", -1)) != int(row["token_version"])
        ):
            return None

        # Role and username come from the database, not token claims.
        return public_user(row)

    except (
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        return None


def authenticate_header(header: str | None) -> dict | None:
    if not header:
        return None

    scheme, separator, token = header.partition(" ")

    if not separator or scheme.lower() != "bearer":
        return None

    return authenticate_token(token.strip())


def change_password(
    user_id: str,
    current_password: str,
    new_password: str,
) -> None:
    with _connect() as conn:
        row = conn.execute(
            """SELECT password_hash FROM users
               WHERE user_id = ? AND is_active = 1""",
            (user_id,),
        ).fetchone()

        if row is None or not _verify_password(
            current_password,
            row["password_hash"],
        ):
            raise PermissionError("Current password is incorrect.")

        new_hash = _hash_password(new_password)

        conn.execute(
            """UPDATE users
               SET password_hash = ?, token_version = token_version + 1
               WHERE user_id = ?""",
            (new_hash, user_id),
        )
