
from __future__ import annotations

"""DataLens multi-user API server.

The forensic engine remains in evidence_manager.py, forensics.py and recovery.py.
Authentication and authorization are enforced here before any case-scoped action.
On Render, mount a persistent disk at the existing DATA_DIR path described in the
setup instructions. Never expose this service without configuring its secrets.
"""

import base64
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import traceback
import zipfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, urlparse

import evidence_manager as em
import forensics
import recovery
import auth_manager as auth

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(getattr(em, "DATA_DIR", BASE_DIR / "datalens_data")).resolve()
RECOVERY_UPLOAD_DIR = DATA_DIR / "recovery_source_uploads"
BACKUP_DIR = DATA_DIR / "backups"

HOST = os.environ.get(
    "DATALENS_HOST",
    "0.0.0.0" if os.environ.get("RENDER") else "127.0.0.1",
)

PORT = int(
    os.environ.get("PORT")
    or os.environ.get("DATALENS_PORT")
    or "8000"
)

MAX_REQUEST_BYTES = 512 * 1024 * 1024
MAX_RESTORE_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_RESTORE_FILES = 100_000

FRONTEND_FILES = {
    "/": ([(BASE_DIR / "index.html")], "text/html; charset=utf-8"),
    "/index.html": ([(BASE_DIR / "index.html")], "text/html; charset=utf-8"),
    "/static.css": (
        [BASE_DIR / "static" / "static.css", BASE_DIR / "static.css"],
        "text/css; charset=utf-8",
    ),
    "/static/static.css": (
        [BASE_DIR / "static" / "static.css", BASE_DIR / "static.css"],
        "text/css; charset=utf-8",
    ),
    "/javascript.js": (
        [BASE_DIR / "javascript.js", BASE_DIR / "static" / "javascript.js"],
        "text/javascript; charset=utf-8",
    ),
    "/static/javascript.js": (
        [BASE_DIR / "static" / "javascript.js", BASE_DIR / "javascript.js"],
        "text/javascript; charset=utf-8",
    ),
}

# Initialize the existing forensic database first, then add auth and owner columns.
em.initialize_database()
DATA_DIR.mkdir(parents=True, exist_ok=True)
RECOVERY_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
auth.initialize_auth_schema()


def _json_default(value):
    if isinstance(value, Path):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")

    return str(value)


def _actor(user: dict) -> str:
    """Never trust an investigator name supplied by the browser."""
    return str(
        user.get("display_name")
        or user.get("username")
        or "Investigator"
    )


def _verification_passed(outcome) -> bool:
    if isinstance(outcome, bool):
        return outcome

    if isinstance(outcome, dict):
        for key in (
            "verified",
            "valid",
            "integrity_ok",
            "ok",
            "passed",
            "success",
        ):
            if key in outcome:
                value = outcome[key]

                if isinstance(value, bool):
                    return value

                if isinstance(value, str):
                    return value.strip().lower() in {
                        "true",
                        "yes",
                        "valid",
                        "passed",
                        "ok",
                        "success",
                    }

                if isinstance(value, (int, float)):
                    return value == 1

        status = str(outcome.get("status", "")).strip().lower()

        if status in {
            "valid",
            "verified",
            "passed",
            "ok",
            "success",
            "intact",
        }:
            return True

        if status in {
            "invalid",
            "failed",
            "error",
            "tampered",
            "mismatch",
        }:
            return False

    if isinstance(outcome, str):
        return outcome.strip().lower() in {
            "true",
            "yes",
            "valid",
            "verified",
            "passed",
            "ok",
            "success",
            "intact",
        }

    return False


def _decode_upload(item: dict):
    filename = Path(str(item.get("name") or "upload.bin")).name
    encoded = item.get("data_base64")

    if not isinstance(encoded, str):
        raise ValueError(
            f"Missing base64 file content for {filename}."
        )

    try:
        content = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(
            f"Invalid base64 content for {filename}."
        ) from exc

    upload = io.BytesIO(content)
    upload.name = filename

    return upload


def _case_visible(user: dict, case_id: str) -> bool:
    return bool(case_id) and auth.case_is_accessible(user, case_id)


def _evidence_visible(user: dict, evidence_id: str):
    evidence = em.get_evidence_item(evidence_id)

    if not evidence:
        return None

    if not _case_visible(user, evidence.get("case_id", "")):
        return None

    return evidence


def _visible_evidence_and_analysis(user: dict):
    cases = auth.visible_cases(user)
    evidence = []
    analysis_count = 0

    for case in cases:
        case_id = case.get("case_id", "")
        evidence.extend(em.get_evidence(case_id))
        analysis_count += len(em.get_analysis_results(case_id))

    return cases, evidence, analysis_count


def _dashboard_payload(user: dict):
    cases, evidence, analyses_count = _visible_evidence_and_analysis(user)

    usage = sum(
        int(item.get("size_bytes") or 0)
        for item in evidence
    )

    return {
        "app_name": "DataLens",
        "cases_count": len(cases),
        "evidence_count": len(evidence),
        "saved_analyses_count": analyses_count,
        "vault_usage_bytes": usage,
        "vault_usage_display": em.format_bytes(usage),
        "vault_limit_bytes": em.MAX_VAULT_BYTES,
        "recent_cases": cases[:8],
        "recent_evidence": sorted(
            evidence,
            key=lambda row: str(row.get("acquired_at", "")),
            reverse=True,
        )[:8],
        "generated_at": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "current_user": {
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
    }


class DataLensHandler(BaseHTTPRequestHandler):
    server_version = "DataLens/2.0"

    def log_message(self, fmt, *args):
        # Do not log request bodies, passwords, authorization headers,
        # or evidence content.
        sys.stdout.write(
            "[%s] %s\n"
            % (self.log_date_time_string(), fmt % args)
        )

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers=None,
    ):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Referrer-Policy",
            "strict-origin-when-cross-origin",
        )
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )

        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)

        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload):
        body = json.dumps(
            payload,
            ensure_ascii=False,
            default=_json_default,
        ).encode("utf-8")

        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
        )

    def _read_json(self):
        try:
            length = int(
                self.headers.get("Content-Length", "0")
            )
        except ValueError as exc:
            raise ValueError(
                "Invalid Content-Length header."
            ) from exc

        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError(
                "Request is too large. Maximum accepted request "
                f"size is {MAX_REQUEST_BYTES} bytes."
            )

        raw = self.rfile.read(length) if length else b"{}"

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "Request body must be valid JSON encoded as UTF-8."
            ) from exc

        if not isinstance(payload, dict):
            raise ValueError(
                "Request body must be a JSON object."
            )

        return payload

    def _query(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        return path, {
            key: values[-1]
            for key, values in parse_qs(parsed.query).items()
            if values
        }

    def _authenticated_user(self):
        return auth.authenticate_header(
            self.headers.get("Authorization")
        )

    def _require_user(self):
        user = self._authenticated_user()

        if user is None:
            self._send_json(401, {
                "error": "Authentication required. Sign in to DataLens.",
                "code": "AUTH_REQUIRED",
            })
            return None

        return user

    def _require_admin(self, user: dict) -> bool:
        if user.get("role") != "admin":
            self._send_json(
                403,
                {"error": "Administrator access is required."},
            )
            return False

        return True

    def _require_case(self, user: dict, case_id: str):
        if not case_id:
            self._send_json(
                400,
                {"error": "case_id is required."},
            )
            return None

        if not _case_visible(user, case_id):
            # Same response for missing and unauthorized cases
            # to avoid exposing whether another user's case exists.
            self._send_json(
                404,
                {"error": "Case not found or you do not have access to it."},
            )
            return None

        return em.get_case(case_id)

    def do_GET(self):
        path, query = self._query()

        # Public static assets are needed before login.
        if path in FRONTEND_FILES:
            candidates, content_type = FRONTEND_FILES[path]

            file_path = next(
                (
                    candidate
                    for candidate in candidates
                    if candidate.is_file()
                ),
                None,
            )

            if file_path is None:
                expected = " or ".join(
                    str(candidate.relative_to(BASE_DIR))
                    for candidate in candidates
                )

                self._send_json(404, {
                    "error": f"Frontend file not found. Checked: {expected}"
                })
                return

            self._send_bytes(
                200,
                file_path.read_bytes(),
                content_type,
            )
            return

        if path == "/favicon.ico":
            self._send_bytes(204, b"", "image/x-icon")
            return

        if path == "/api/health":
            self._send_json(200, {
                "ok": True,
                "app": "DataLens",
                "build": "multi-user-persistent-storage-v1",
                "time": datetime.now().astimezone().isoformat(
                    timespec="seconds"
                ),
                "authentication_required": True,
            })
            return

        user = self._require_user()

        if user is None:
            return

        try:
            if path == "/api/auth/me":
                self._send_json(200, {"user": user})

            elif path == "/api/admin/users":
                if not self._require_admin(user):
                    return

                self._send_json(
                    200,
                    {"users": auth.list_users()},
                )

            elif path == "/api/dashboard":
                self._send_json(
                    200,
                    _dashboard_payload(user),
                )

            elif path == "/api/cases":
                self._send_json(
                    200,
                    {"cases": auth.visible_cases(user)},
                )

            elif path == "/api/evidence":
                case_id = query.get("case_id", "")

                if self._require_case(user, case_id) is None:
                    return

                self._send_json(
                    200,
                    {"evidence": em.get_evidence(case_id)},
                )

            elif path == "/api/devices":
                devices = forensics.detect_attached_devices()
                checked_at = datetime.now().astimezone().isoformat(
                    timespec="seconds"
                )

                self._send_json(200, {
                    "devices": devices,
                    "checked_at": checked_at,
                })

            elif path == "/api/analysis":
                case_id = query.get("case_id", "")

                if self._require_case(user, case_id) is None:
                    return

                self._send_json(
                    200,
                    {"results": em.get_analysis_results(case_id)},
                )

            elif path == "/api/custody":
                case_id = query.get("case_id", "")
                case = self._require_case(user, case_id)

                if case is None:
                    return

                records = em.get_custody(case_id)

                self._send_json(200, {
                    "case": case,
                    "evidence": em.get_evidence(case_id),
                    "records": records,
                    "events": records,
                    "integrity": em.verify_custody_log(case_id),
                })

            elif path == "/api/system-checks":
                self._send_json(
                    200,
                    {"checks": forensics.run_system_checks()},
                )

            elif path == "/api/backup/download":
                if not self._require_admin(user):
                    return

                self._download_backup(query)

            elif path == "/api/download":
                self._download_report(query, user)

            else:
                self._send_json(
                    404,
                    {"error": "Endpoint not found."},
                )

        except Exception as exc:
            self._server_error(exc)

    def do_POST(self):
        path, _ = self._query()

        try:
            payload = self._read_json()

            # Login is the only unauthenticated data API action.
            if path == "/api/auth/login":
                try:
                    remote_ip = (
                        self.client_address[0]
                        if self.client_address
                        else "unknown"
                    )

                    result = auth.login(
                        str(payload.get("username", "")),
                        str(payload.get("password", "")),
                        remote_ip=remote_ip,
                    )

                except PermissionError as exc:
                    self._send_json(
                        401,
                        {"error": str(exc)},
                    )
                    return

                self._send_json(200, result)
                return

            user = self._require_user()

            if user is None:
                return

            actor = _actor(user)

            if path == "/api/auth/logout":
                # Bearer tokens are stateless. The browser removes
                # its current session token when the user signs out.
                self._send_json(200, {
                    "ok": True,
                    "message": "Signed out. Remove the bearer token in the browser.",
                })

            elif path == "/api/auth/change-password":
                auth.change_password(
                    user["user_id"],
                    str(payload.get("current_password", "")),
                    str(payload.get("new_password", "")),
                )

                self._send_json(200, {
                    "ok": True,
                    "message": "Password updated. Sign in again on other devices.",
                })

            elif path == "/api/admin/users":
                if not self._require_admin(user):
                    return

                created = auth.create_user(
                    username=payload.get("username", ""),
                    display_name=payload.get("display_name", ""),
                    password=payload.get("password", ""),
                    role="investigator",
                )

                self._send_json(201, {"user": created})

            elif path == "/api/admin/users/active":
                if not self._require_admin(user):
                    return

                updated = auth.set_user_active(
                    str(payload.get("user_id", "")),
                    bool(payload.get("is_active")),
                )

                self._send_json(200, {"user": updated})

            elif path == "/api/admin/users/password":
                if not self._require_admin(user):
                    return

                auth.admin_reset_password(
                    str(payload.get("user_id", "")),
                    str(payload.get("new_password", "")),
                )

                self._send_json(200, {
                    "ok": True,
                    "message": "Password reset. The investigator must sign in again.",
                })

            elif path == "/api/admin/cases/assign":
                if not self._require_admin(user):
                    return

                case_id = str(payload.get("case_id", "")).strip()
                owner_id = str(payload.get("owner_id", "")).strip()

                if not case_id or not em.get_case(case_id):
                    self._send_json(
                        404,
                        {"error": "Case not found."},
                    )
                    return

                auth.assign_case_owner(case_id, owner_id)

                em.add_custody_event(
                    case_id=case_id,
                    evidence_id=None,
                    actor=actor,
                    action="CASE_OWNER_CHANGED",
                    details={"new_owner_id": owner_id},
                )

                self._send_json(200, {
                    "ok": True,
                    "case_id": case_id,
                    "owner_id": owner_id,
                })

            elif path == "/api/cases":
                case_name = str(payload.get("case_name", "")).strip()

                if not case_name:
                    self._send_json(
                        400,
                        {"error": "Case name is required."},
                    )
                    return

                created = em.create_case(
                    case_name,
                    actor,
                    str(payload.get("description", "")),
                )

                auth.assign_case_owner(
                    created["case_id"],
                    user["user_id"],
                )

                created = em.get_case(created["case_id"])

                self._send_json(201, {"case": created})

            elif path == "/api/acquire/upload":
                case_id = str(payload.get("case_id", "")).strip()

                if self._require_case(user, case_id) is None:
                    return

                uploads = payload.get("files", [])

                if not isinstance(uploads, list) or not uploads:
                    self._send_json(
                        400,
                        {"error": "At least one file is required."},
                    )
                    return

                results = []

                for item in uploads:
                    try:
                        if not isinstance(item, dict):
                            raise ValueError(
                                "Each upload must include a filename and base64 content."
                            )

                        upload = _decode_upload(item)

                        record = forensics.acquire_uploaded_file(
                            upload,
                            case_id,
                            actor,
                        )

                        results.append({
                            "file_name": upload.name,
                            "ok": True,
                            "record": record,
                        })

                    except Exception as exc:
                        results.append({
                            "file_name": (
                                str(item.get("name", "unknown"))
                                if isinstance(item, dict)
                                else "unknown"
                            ),
                            "ok": False,
                            "error": str(exc),
                        })

                self._send_json(200, {
                    "results": results,
                    "successful": sum(
                        1 for item in results if item["ok"]
                    ),
                    "failed": sum(
                        1 for item in results if not item["ok"]
                    ),
                })

            elif path == "/api/acquire/device":
                case_id = str(payload.get("case_id", "")).strip()

                if self._require_case(user, case_id) is None:
                    return

                source = str(
                    payload.get(
                        "mountpoint",
                        payload.get("source_path", ""),
                    )
                ).strip()

                if not source:
                    self._send_json(
                        400,
                        {"error": "A mounted source path is required."},
                    )
                    return

                if payload.get("authorized") is not True:
                    self._send_json(
                        403,
                        {"error": "Confirm that you are authorized to acquire files from this source."},
                    )
                    return

                if os.environ.get("RENDER"):
                    self._send_json(400, {
                        "error": (
                            "A hosted Render service cannot access an "
                            "investigator's local USB or drive. Upload "
                            "authorized evidence files through the evidence upload form."
                        )
                    })
                    return

                detected = forensics.detect_attached_devices()

                permitted_sources = {
                    str(
                        item.get("mountpoint")
                        or item.get("mount_point")
                        or item.get("path")
                        or item.get("drive_letter")
                        or ""
                    )
                    for item in detected
                }

                if source not in permitted_sources:
                    self._send_json(
                        403,
                        {"error": "The selected source is not in the server's detected removable-device list."},
                    )
                    return

                result = forensics.acquire_directory(
                    source,
                    case_id,
                    actor,
                )

                self._send_json(200, result)

            elif path == "/api/verify":
                case_id = str(payload.get("case_id", "")).strip()
                evidence_id = str(payload.get("evidence_id", "")).strip()

                if payload.get("verify_custody") is True:
                    if self._require_case(user, case_id) is None:
                        return

                    outcome = em.verify_custody_log(case_id)
                    verified = _verification_passed(outcome)

                    self._send_json(200, {
                        "verified": verified,
                        "valid": verified,
                        "integrity_ok": verified,
                        "outcome": outcome,
                        "message": (
                            "Custody verification passed."
                            if verified
                            else "Custody verification did not pass. Review the returned integrity result."
                        ),
                    })
                    return

                if not evidence_id:
                    self._send_json(
                        400,
                        {"error": "evidence_id is required."},
                    )
                    return

                evidence = _evidence_visible(user, evidence_id)

                if evidence is None:
                    self._send_json(
                        404,
                        {"error": "Evidence not found or you do not have access to it."},
                    )
                    return

                outcome = em.verify_evidence(evidence_id, actor)
                verified = _verification_passed(outcome)

                self._send_json(200, {
                    "verified": verified,
                    "valid": verified,
                    "integrity_ok": verified,
                    "outcome": outcome,
                    "message": (
                        "Evidence verification passed."
                        if verified
                        else "Evidence verification did not pass. Review the returned result."
                    ),
                })

            elif path == "/api/analyze":
                case_id = str(payload.get("case_id", "")).strip()

                if self._require_case(user, case_id) is None:
                    return

                result = forensics.analyze_case_ai(case_id, actor)

                self._send_json(200, {
                    "analysis": result,
                    "message": "Analysis completed. Refreshing saved results now.",
                })

            elif path == "/api/recovery/scan":
                case_id = str(payload.get("case_id", "")).strip()

                if self._require_case(user, case_id) is None:
                    return

                supplied_source = str(
                    payload.get("source_path", "")
                ).strip()

                encoded = payload.get("data_base64")
                source_path = None
                created_temp_source = False

                if supplied_source:
                    source_path = Path(
                        supplied_source
                    ).expanduser().resolve()

                    recovery_root = RECOVERY_UPLOAD_DIR.resolve()

                    try:
                        source_path.relative_to(recovery_root)
                    except ValueError:
                        self._send_json(
                            403,
                            {"error": "Recovery source paths must be inside the DataLens recovery upload folder. Upload an image file instead of supplying a server path."},
                        )
                        return

                    if not source_path.is_file():
                        self._send_json(
                            400,
                            {"error": "The recovery source path must point to an existing uploaded image or file."},
                        )
                        return

                else:
                    filename = Path(
                        str(payload.get("name") or "source.img")
                    ).name

                    if not isinstance(encoded, str):
                        self._send_json(
                            400,
                            {"error": "Provide a recovery source path or upload image content."},
                        )
                        return

                    try:
                        content = base64.b64decode(
                            encoded,
                            validate=True,
                        )
                    except (ValueError, base64.binascii.Error):
                        self._send_json(
                            400,
                            {"error": "Invalid base64 image content."},
                        )
                        return

                    if not content:
                        self._send_json(
                            400,
                            {"error": "The uploaded image is empty."},
                        )
                        return

                    RECOVERY_UPLOAD_DIR.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    safe_suffix = Path(filename).suffix[:12]

                    with tempfile.NamedTemporaryFile(
                        prefix="source_",
                        suffix=safe_suffix,
                        dir=RECOVERY_UPLOAD_DIR,
                        delete=False,
                    ) as handle:
                        handle.write(content)
                        source_path = Path(handle.name)

                    created_temp_source = True

                try:
                    candidates = recovery.carve_image(
                        source_path,
                        selected_types=payload.get("file_types") or [
                            "JPEG",
                            "PNG",
                            "PDF",
                            "ZIP",
                        ],
                        max_files=int(payload.get("max_candidates", 100)),
                        max_candidate_bytes=(
                            int(payload.get("max_candidate_mb", 25))
                            * 1024
                            * 1024
                        ),
                    )

                except Exception:
                    if created_temp_source and source_path:
                        source_path.unlink(missing_ok=True)
                    raise

                self._send_json(200, {
                    "candidates": candidates,
                    "source_path": str(source_path),
                    "case_id": case_id,
                    "message": (
                        f"Recovery scan completed. {len(candidates)} candidate(s) found."
                    ),
                })

            elif path == "/api/recovery/register":
                case_id = str(payload.get("case_id", "")).strip()

                if self._require_case(user, case_id) is None:
                    return

                candidates = payload.get("candidates")

                source_image = str(
                    payload.get("source_image")
                    or payload.get("source_path")
                    or ""
                ).strip()

                if source_image:
                    source_path = Path(
                        source_image
                    ).expanduser().resolve()

                    try:
                        source_path.relative_to(
                            RECOVERY_UPLOAD_DIR.resolve()
                        )
                    except ValueError:
                        self._send_json(
                            403,
                            {"error": "Recovery source must be inside the DataLens recovery upload folder."},
                        )
                        return

                if not isinstance(candidates, list) or not candidates:
                    self._send_json(
                        400,
                        {"error": "No recovery candidates were supplied."},
                    )
                    return

                registered = recovery.register_recovered_files(
                    case_id,
                    candidates,
                    actor,
                    source_image=source_image or None,
                )

                registered_count = sum(
                    1 for item in registered if item.get("evidence_id")
                )

                self._send_json(200, {
                    "results": registered,
                    "successful": registered_count,
                    "registered": registered_count,
                    "message": (
                        f"Recovery registration completed: {registered_count} item(s)."
                    ),
                })

            elif path == "/api/backup":
                if not self._require_admin(user):
                    return

                archive_path = self._create_backup_archive()

                self._send_json(201, {
                    "ok": True,
                    "filename": archive_path.name,
                    "download_url": (
                        "/api/backup/download?name=" + archive_path.name
                    ),
                    "message": (
                        "Administrator backup created. Store it securely; "
                        "it contains the user database and potentially sensitive evidence."
                    ),
                })

            elif path == "/api/admin/restore":
                if not self._require_admin(user):
                    return

                if payload.get("confirm") != "RESTORE_DATALENS_BACKUP":
                    self._send_json(
                        400,
                        {"error": "Set confirm to RESTORE_DATALENS_BACKUP to confirm this operation."},
                    )
                    return

                restored = self._restore_backup_payload(
                    str(payload.get("data_base64", ""))
                )

                self._send_json(200, {
                    "ok": True,
                    "restored_files": restored,
                    "message": (
                        "Backup restored. Sign in again because the user database may have been replaced."
                    ),
                })

            elif path == "/api/reports/case":
                case_id = str(payload.get("case_id", "")).strip()

                if self._require_case(user, case_id) is None:
                    return

                report_path = Path(
                    em.generate_pdf_report(case_id, actor)
                ).resolve()

                self._send_json(200, {
                    "filename": report_path.name,
                    "download_url": (
                        "/api/download?kind=case&case_id="
                        + case_id
                        + "&name="
                        + report_path.name
                    ),
                })

            elif path == "/api/reports/evidence":
                evidence_id = str(
                    payload.get("evidence_id", "")
                ).strip()

                evidence = _evidence_visible(user, evidence_id)

                if evidence is None:
                    self._send_json(
                        404,
                        {"error": "Evidence not found or you do not have access to it."},
                    )
                    return

                report_path = Path(
                    em.generate_evidence_custody_pdf(
                        evidence_id,
                        actor,
                    )
                ).resolve()

                self._send_json(200, {
                    "filename": report_path.name,
                    "download_url": (
                        "/api/download?kind=evidence&evidence_id="
                        + evidence_id
                        + "&name="
                        + report_path.name
                    ),
                })

            else:
                self._send_json(
                    404,
                    {"error": "Endpoint not found."},
                )

        except PermissionError as exc:
            self._send_json(403, {"error": str(exc)})

        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})

        except Exception as exc:
            self._server_error(exc)

    def _create_backup_archive(self) -> Path:
        """Create a consistent database snapshot and include evidence and reports."""
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)

        db_path = Path(em.DB_PATH).resolve()

        if not db_path.is_file():
            raise FileNotFoundError(
                f"DataLens database not found: {db_path}"
            )

        stamp = datetime.now().astimezone().strftime(
            "%Y%m%d_%H%M%S_%f"
        )

        archive_path = BACKUP_DIR / f"datalens_backup_{stamp}.zip"
        snapshot_path = BACKUP_DIR / f".datalens_snapshot_{stamp}.sqlite3"

        try:
            with sqlite3.connect(str(db_path), timeout=30) as source_db:
                with sqlite3.connect(str(snapshot_path), timeout=30) as snapshot_db:
                    source_db.backup(snapshot_db)

            with zipfile.ZipFile(
                archive_path,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                archive.write(
                    snapshot_path,
                    arcname="datalens_data/datalens.db",
                )

                for path in DATA_DIR.rglob("*"):
                    if not path.is_file():
                        continue

                    resolved = path.resolve()

                    if resolved == db_path or path.name in {
                        db_path.name + "-wal",
                        db_path.name + "-shm",
                    }:
                        continue

                    if BACKUP_DIR == resolved or BACKUP_DIR in resolved.parents:
                        continue

                    try:
                        relative = path.relative_to(DATA_DIR)
                    except ValueError:
                        continue

                    archive.write(
                        path,
                        arcname=(
                            Path("datalens_data") / relative
                        ).as_posix(),
                    )

            if not archive_path.is_file() or archive_path.stat().st_size == 0:
                raise OSError(
                    "The backup archive was not created correctly."
                )

            return archive_path

        except Exception:
            archive_path.unlink(missing_ok=True)
            raise

        finally:
            snapshot_path.unlink(missing_ok=True)

    def _restore_backup_payload(self, encoded: str) -> int:
        """Restore a DataLens backup ZIP. Call only during a maintenance window."""
        if not encoded:
            raise ValueError("A base64 backup archive is required.")

        try:
            archive_bytes = base64.b64decode(
                encoded,
                validate=True,
            )
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError(
                "The backup archive is not valid base64."
            ) from exc

        if len(archive_bytes) > MAX_REQUEST_BYTES * 3 // 4:
            raise ValueError("Backup upload is too large.")

        stage_root = Path(
            tempfile.mkdtemp(
                prefix="datalens_restore_",
                dir=DATA_DIR.parent,
            )
        )

        stage_data = stage_root / "datalens_data"
        restored_count = 0
        total_size = 0

        try:
            with zipfile.ZipFile(
                io.BytesIO(archive_bytes),
                "r",
            ) as archive:
                infos = archive.infolist()

                if len(infos) > MAX_RESTORE_FILES:
                    raise ValueError(
                        "Backup contains too many files."
                    )

                for info in infos:
                    if info.is_dir():
                        continue

                    parts = PurePosixPath(info.filename).parts

                    if (
                        not parts
                        or parts[0] != "datalens_data"
                        or any(part in {"", ".", ".."} for part in parts)
                        or PurePosixPath(info.filename).is_absolute()
                    ):
                        raise ValueError(
                            "Backup contains an unsafe file path."
                        )

                    # Reject symbolic links and other special file types.
                    mode = (info.external_attr >> 16) & 0o170000

                    if mode not in (0, 0o100000):
                        raise ValueError(
                            "Backup contains a non-regular file."
                        )

                    total_size += int(info.file_size)

                    if total_size > MAX_RESTORE_UNCOMPRESSED_BYTES:
                        raise ValueError(
                            "Backup expands beyond the 2 GiB restore limit."
                        )

                    target = stage_root.joinpath(*parts)
                    target.parent.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    with archive.open(info, "r") as source:
                        with target.open("wb") as output:
                            shutil.copyfileobj(
                                source,
                                output,
                                length=1024 * 1024,
                            )

                    restored_count += 1

            staged_db = stage_data / "datalens.db"

            if not staged_db.is_file():
                raise ValueError(
                    "Backup archive does not contain datalens_data/datalens.db."
                )

            with sqlite3.connect(str(staged_db), timeout=30) as check_db:
                check = check_db.execute(
                    "PRAGMA quick_check"
                ).fetchone()

                if not check or check[0] != "ok":
                    raise ValueError(
                        "The backup database failed SQLite integrity validation."
                    )

                has_cases = check_db.execute(
                    """SELECT 1 FROM sqlite_master
                       WHERE type='table' AND name='cases'"""
                ).fetchone()

                if not has_cases:
                    raise ValueError(
                        "The backup database does not contain the DataLens cases table."
                    )

            # Keep an emergency pre-restore archive before replacing existing data.
            if Path(em.DB_PATH).is_file():
                self._create_backup_archive()

            for directory_name in (
                "evidence_vault",
                "reports",
                "recovery_source_uploads",
            ):
                current = DATA_DIR / directory_name
                staged = stage_data / directory_name

                if current.exists():
                    shutil.rmtree(current)

                if staged.exists():
                    shutil.copytree(staged, current)

            db_path = Path(em.DB_PATH)

            Path(str(db_path) + "-wal").unlink(missing_ok=True)
            Path(str(db_path) + "-shm").unlink(missing_ok=True)

            os.replace(staged_db, db_path)

            # Recreate indexes/auth migrations and attach legacy records to the admin.
            em.initialize_database()
            auth.initialize_auth_schema()

            return restored_count

        finally:
            shutil.rmtree(stage_root, ignore_errors=True)

    def _download_backup(self, query):
        name = query.get("name", "")

        if (
            not name
            or Path(name).name != name
            or not name.startswith("datalens_backup_")
            or not name.endswith(".zip")
        ):
            self._send_json(
                400,
                {"error": "Invalid backup download request."},
            )
            return

        backup_dir = BACKUP_DIR.resolve()
        backup_path = (backup_dir / name).resolve()

        try:
            backup_path.relative_to(backup_dir)
        except ValueError:
            self._send_json(
                403,
                {"error": "The requested path is not permitted."},
            )
            return

        if not backup_path.is_file():
            self._send_json(
                404,
                {"error": "Backup file not found."},
            )
            return

        self._send_bytes(
            200,
            backup_path.read_bytes(),
            "application/zip",
            {
                "Content-Disposition": (
                    f'attachment; filename="{backup_path.name}"'
                )
            },
        )

    def _download_report(self, query, user):
        kind = query.get("kind", "")
        name = query.get("name", "")

        if (
            kind not in {"case", "evidence"}
            or not name
            or Path(name).name != name
        ):
            self._send_json(
                400,
                {"error": "Invalid report download request."},
            )
            return

        if kind == "case":
            case_id = query.get("case_id", "")

            if not case_id or not _case_visible(user, case_id):
                self._send_json(
                    404,
                    {"error": "Case report not found or access denied."},
                )
                return

            expected_name = f"DataLens_Case_Custody_{case_id}.pdf"

        else:
            evidence_id = query.get("evidence_id", "")
            evidence = _evidence_visible(user, evidence_id)

            if evidence is None:
                self._send_json(
                    404,
                    {"error": "Evidence report not found or access denied."},
                )
                return

            expected_name = f"DataLens_Evidence_Custody_{evidence_id}.pdf"

        if name != expected_name:
            self._send_json(
                403,
                {"error": "The requested report does not match the authorized record."},
            )
            return

        report_dir = Path(em.REPORT_DIR).resolve()
        report_path = (report_dir / name).resolve()

        try:
            report_path.relative_to(report_dir)
        except ValueError:
            self._send_json(
                403,
                {"error": "The requested path is not permitted."},
            )
            return

        if not report_path.is_file() or report_path.suffix.lower() != ".pdf":
            self._send_json(
                404,
                {"error": "Report not found."},
            )
            return

        self._send_bytes(
            200,
            report_path.read_bytes(),
            "application/pdf",
            {
                "Content-Disposition": (
                    f'attachment; filename="{report_path.name}"'
                )
            },
        )

    def _server_error(self, exc: Exception):
        traceback.print_exc()
        self._send_json(
            500,
            {"error": str(exc) or exc.__class__.__name__},
        )

    def do_OPTIONS(self):
        self._send_bytes(
            204,
            b"",
            "text/plain; charset=utf-8",
            {"Allow": "GET, POST, OPTIONS"},
        )


def main():
    server = ThreadingHTTPServer(
        (HOST, PORT),
        DataLensHandler,
    )

    print("=" * 64)
    print("DataLens multi-user API server")
    print(f"Listening on {HOST}:{PORT}")
    print(f"Persistent data directory: {DATA_DIR}")
    print("Authentication: enabled")
    print("Stop with Ctrl+C.")
    print("=" * 64)

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nStopping DataLens server…")

    finally:
        server.server_close()


if __name__ == "__main__":
    main()
