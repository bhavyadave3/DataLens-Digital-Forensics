
from __future__ import annotations

"""DataLens local API server for the separate HTML/CSS/JavaScript interface.

This file is a thin web/API layer around the existing DataLens modules. The
forensic business logic remains in evidence_manager.py, forensics.py, and
recovery.py. The server binds to 127.0.0.1 by default and is intended for local
use only, not direct exposure to the public internet.

Frontend files expected:
    index.html
    static/static.css
    javascript.js (in the project root; /static/javascript.js is also supported)
"""

import base64
import io
import json
import mimetypes
import os
import sqlite3
import sys
import traceback
import zipfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import evidence_manager as em
import forensics
import recovery

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(getattr(em, "DATA_DIR", BASE_DIR / "datalens_data"))
RECOVERY_UPLOAD_DIR = DATA_DIR / "recovery_source_uploads"
BACKUP_DIR = BASE_DIR / "backups"
HOST = os.environ.get("DATALENS_HOST", "127.0.0.1")
PORT = int(os.environ.get("DATALENS_PORT", "8000"))
MAX_REQUEST_BYTES = 512 * 1024 * 1024  # Upper bound for JSON/base64 upload requests.
# Frontend routes accept either common folder layout:
#   index.html, javascript.js, static/static.css
# or:
#   index.html, static/static.css, static/javascript.js
# Legacy root-level static.css and javascript.js are also supported.
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

em.initialize_database()
DATA_DIR.mkdir(parents=True, exist_ok=True)
RECOVERY_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _json_default(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    return str(value)


def _as_dict(value):
    if isinstance(value, dict):
        return value
    if hasattr(value, "_asdict"):
        return value._asdict()
    try:
        return dict(value)
    except (TypeError, ValueError):
        return {"value": value}


def _actor(payload: dict) -> str:
    actor = str(payload.get("actor") or payload.get("investigator") or "Investigator").strip()
    return actor or "Investigator"


def _case_exists(case_id: str) -> bool:
    return em.get_case(case_id) is not None


def _verification_passed(outcome) -> bool:
    """Normalize common verification return shapes without treating unknown as success."""
    if isinstance(outcome, bool):
        return outcome
    if isinstance(outcome, dict):
        for key in ("verified", "valid", "integrity_ok", "ok", "passed", "success"):
            if key in outcome:
                value = outcome[key]
                if isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    return value.strip().lower() in {"true", "yes", "valid", "passed", "ok", "success"}
                if isinstance(value, (int, float)):
                    return value == 1
        status = str(outcome.get("status", "")).strip().lower()
        if status in {"valid", "verified", "passed", "ok", "success", "intact"}:
            return True
        if status in {"invalid", "failed", "error", "tampered", "mismatch"}:
            return False
    if isinstance(outcome, str):
        return outcome.strip().lower() in {"true", "yes", "valid", "verified", "passed", "ok", "success", "intact"}
    return False


def _decode_upload(item: dict):
    """Build the small file-like object expected by the existing acquisition API."""
    filename = Path(str(item.get("name") or "upload.bin")).name
    encoded = item.get("data_base64")
    if not isinstance(encoded, str):
        raise ValueError(f"Missing base64 file content for {filename}.")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"Invalid base64 content for {filename}.") from exc
    upload = io.BytesIO(content)
    upload.name = filename
    return upload


def _dashboard_payload():
    cases = em.get_cases()
    evidence = em.get_evidence()
    analyses_count = 0
    for case in cases:
        try:
            analyses_count += len(em.get_analysis_results(case.get("case_id", "")))
        except Exception:
            continue
    usage = em.vault_usage()
    return {
        "app_name": "DataLens",
        "cases_count": len(cases),
        "evidence_count": len(evidence),
        "saved_analyses_count": analyses_count,
        "vault_usage_bytes": usage,
        "vault_usage_display": em.format_bytes(usage),
        "vault_limit_bytes": 50 * 1024**3,
        "recent_cases": cases[:8],
        "recent_evidence": evidence[:8],
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


class DataLensHandler(BaseHTTPRequestHandler):
    server_version = "DataLensLocal/1.0"

    def log_message(self, fmt, *args):
        # Keep normal request logging concise; errors are still printed by the server.
        sys.stdout.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _send_bytes(self, status: int, body: bytes, content_type: str, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        # Frontend and API are served from the same local origin; no permissive CORS is needed.
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload):
        body = json.dumps(payload, ensure_ascii=False, default=_json_default).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header.") from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError(f"Request is too large. Maximum accepted request size is {MAX_REQUEST_BYTES} bytes.")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must be valid JSON encoded as UTF-8.") from exc
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        return payload

    def _query(self):
        parsed = urlparse(self.path)
        # Treat /api/backup and /api/backup/ as the same route.
        path = parsed.path.rstrip("/") or "/"
        return path, {key: values[-1] for key, values in parse_qs(parsed.query).items() if values}

    def do_GET(self):
        path, query = self._query()
        if path in FRONTEND_FILES:
            candidates, content_type = FRONTEND_FILES[path]
            file_path = next((candidate for candidate in candidates if candidate.is_file()), None)
            if file_path is None:
                expected = " or ".join(str(candidate.relative_to(BASE_DIR)) for candidate in candidates)
                self._send_json(404, {"error": f"Frontend file not found. Checked: {expected}"})
                return
            self._send_bytes(200, file_path.read_bytes(), content_type)
            return

        if path == "/favicon.ico":
            self._send_bytes(204, b"", "image/x-icon")
            return

        try:
            if path == "/api/health":
                self._send_json(200, {"ok": True, "app": "DataLens", "build": "backup-recovery-fix-20261017", "time": datetime.now().astimezone().isoformat()})
            elif path == "/api/dashboard":
                self._send_json(200, _dashboard_payload())
            elif path == "/api/cases":
                self._send_json(200, {"cases": em.get_cases()})
            elif path == "/api/evidence":
                case_id = query.get("case_id")
                self._send_json(200, {"evidence": em.get_evidence(case_id)})
            elif path == "/api/devices":
                devices = forensics.detect_attached_devices()
                checked_at = datetime.now().astimezone().isoformat(timespec="seconds")
                self._send_json(200, {"devices": devices, "checked_at": checked_at})
            elif path == "/api/analysis":
                case_id = query.get("case_id")
                if not case_id:
                    self._send_json(400, {"error": "case_id is required."})
                    return
                if not _case_exists(case_id):
                    self._send_json(404, {"error": "Case not found."})
                    return
                self._send_json(200, {"results": em.get_analysis_results(case_id)})
            elif path == "/api/custody":
                case_id = query.get("case_id")
                if not case_id:
                    self._send_json(400, {"error": "case_id is required."})
                    return
                if not _case_exists(case_id):
                    self._send_json(404, {"error": "Case not found."})
                    return
                custody_records = em.get_custody(case_id)
                custody_integrity = em.verify_custody_log(case_id)
                self._send_json(200, {
                    "case": em.get_case(case_id),
                    "evidence": em.get_evidence(case_id),
                    "records": custody_records,
                    "events": custody_records,
                    "integrity": custody_integrity,
                })
            elif path == "/api/system-checks":
                self._send_json(200, {"checks": forensics.run_system_checks()})
            elif path == "/api/backup/download":
                self._download_backup(query)
            elif path == "/api/download":
                self._download_report(query)
            else:
                self._send_json(404, {"error": "Endpoint not found."})
        except Exception as exc:
            self._server_error(exc)

    def do_POST(self):
        path, _ = self._query()
        try:
            payload = self._read_json()
            if path == "/api/cases":
                case_name = str(payload.get("case_name", "")).strip()
                if not case_name:
                    self._send_json(400, {"error": "Case name is required."})
                    return
                created = em.create_case(case_name, _actor(payload), str(payload.get("description", "")))
                self._send_json(201, {"case": created})
            elif path == "/api/acquire/upload":
                case_id = str(payload.get("case_id", "")).strip()
                if not case_id or not _case_exists(case_id):
                    self._send_json(400, {"error": "Select a valid case before acquiring files."})
                    return
                uploads = payload.get("files", [])
                if not isinstance(uploads, list) or not uploads:
                    self._send_json(400, {"error": "At least one file is required."})
                    return
                results = []
                for item in uploads:
                    try:
                        if not isinstance(item, dict):
                            raise ValueError("Each upload must include a filename and base64 content.")
                        upload = _decode_upload(item)
                        record = forensics.acquire_uploaded_file(upload, case_id, _actor(payload))
                        results.append({"file_name": upload.name, "ok": True, "record": record})
                    except Exception as exc:
                        results.append({"file_name": str(item.get("name", "unknown")) if isinstance(item, dict) else "unknown", "ok": False, "error": str(exc)})
                self._send_json(200, {"results": results, "successful": sum(1 for item in results if item["ok"]), "failed": sum(1 for item in results if not item["ok"])})
            elif path == "/api/acquire/device":
                case_id = str(payload.get("case_id", "")).strip()
                source = str(payload.get("mountpoint", payload.get("source_path", ""))).strip()
                if not case_id or not _case_exists(case_id):
                    self._send_json(400, {"error": "Select a valid case before acquiring files."})
                    return
                if not source:
                    self._send_json(400, {"error": "A mounted source path is required."})
                    return
                if payload.get("authorized") is not True:
                    self._send_json(403, {"error": "Confirm that you are authorized to acquire files from this source."})
                    return
                result = forensics.acquire_directory(source, case_id, _actor(payload))
                self._send_json(200, result)
            elif path == "/api/verify":
                case_id = str(payload.get("case_id", "")).strip()
                evidence_id = str(payload.get("evidence_id", "")).strip()

                if payload.get("verify_custody") is True:
                    if not case_id or not _case_exists(case_id):
                        self._send_json(400, {"error": "Select a valid case before verifying its chain of custody."})
                        return
                    outcome = em.verify_custody_log(case_id)
                    verified = _verification_passed(outcome)
                    self._send_json(200, {
                        "verified": verified,
                        "valid": verified,
                        "integrity_ok": verified,
                        "outcome": outcome,
                        "message": "Custody verification passed." if verified else "Custody verification did not pass. Review the returned integrity result.",
                    })
                    return

                if not evidence_id:
                    self._send_json(400, {"error": "evidence_id is required."})
                    return
                outcome = em.verify_evidence(evidence_id, _actor(payload))
                verified = _verification_passed(outcome)
                self._send_json(200, {
                    "verified": verified,
                    "valid": verified,
                    "integrity_ok": verified,
                    "outcome": outcome,
                    "message": "Evidence verification passed." if verified else "Evidence verification did not pass. Review the returned result.",
                })
            elif path == "/api/analyze":
                case_id = str(payload.get("case_id", "")).strip()
                if not case_id or not _case_exists(case_id):
                    self._send_json(400, {"error": "Select a valid case before analysis."})
                    return
                result = forensics.analyze_case_ai(case_id, _actor(payload))
                self._send_json(200, {
                    "analysis": result,
                    "message": "Analysis request completed. Refreshing saved results now.",
                })
            elif path == "/api/recovery/scan":
                case_id = str(payload.get("case_id", "")).strip()
                if not case_id or not _case_exists(case_id):
                    self._send_json(400, {"error": "Select a valid case before scanning for recoverable files."})
                    return

                supplied_source = str(payload.get("source_path", "")).strip()
                encoded = payload.get("data_base64")
                source_path = None
                created_temp_source = False

                if supplied_source:
                    source_path = Path(supplied_source).expanduser().resolve()
                    if not source_path.is_file():
                        self._send_json(400, {"error": "The recovery source path must point to an existing image or file."})
                        return
                else:
                    filename = Path(str(payload.get("name") or "source.img")).name
                    if not isinstance(encoded, str):
                        self._send_json(400, {"error": "Provide a recovery source path or upload image content."})
                        return
                    try:
                        content = base64.b64decode(encoded, validate=True)
                    except (ValueError, base64.binascii.Error):
                        self._send_json(400, {"error": "Invalid base64 image content."})
                        return
                    if not content:
                        self._send_json(400, {"error": "The uploaded image is empty."})
                        return
                    RECOVERY_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                    safe_suffix = Path(filename).suffix[:12]
                    import tempfile
                    with tempfile.NamedTemporaryFile(prefix="source_", suffix=safe_suffix, dir=RECOVERY_UPLOAD_DIR, delete=False) as handle:
                        handle.write(content)
                        source_path = Path(handle.name)
                    created_temp_source = True

                try:
                    candidates = recovery.carve_image(
                        source_path,
                        selected_types=payload.get("file_types") or ["JPEG", "PNG", "PDF", "ZIP"],
                        max_files=int(payload.get("max_candidates", 100)),
                        max_candidate_bytes=int(payload.get("max_candidate_mb", 25)) * 1024 * 1024,
                    )
                except Exception:
                    if created_temp_source and source_path:
                        source_path.unlink(missing_ok=True)
                    raise

                self._send_json(200, {
                    "candidates": candidates,
                    "source_path": str(source_path),
                    "case_id": case_id,
                    "message": f"Recovery scan completed. {len(candidates)} candidate(s) found.",
                })
            elif path == "/api/recovery/register":
                case_id = str(payload.get("case_id", "")).strip()
                candidates = payload.get("candidates")
                source_image = str(payload.get("source_image") or payload.get("source_path") or "").strip()
                if not case_id or not _case_exists(case_id):
                    self._send_json(400, {"error": "Select a valid case before registering recovery candidates."})
                    return
                if not isinstance(candidates, list) or not candidates:
                    self._send_json(400, {"error": "No recovery candidates were supplied."})
                    return
                registered = recovery.register_recovered_files(case_id, candidates, _actor(payload), source_image=source_image or None)
                registered_count = sum(1 for item in registered if item.get("evidence_id"))
                self._send_json(200, {
                    "results": registered,
                    "successful": registered_count,
                    "registered": registered_count,
                    "message": f"Recovery registration completed: {registered_count} item(s).",
                })
            elif path == "/api/backup":
                archive_path = self._create_backup_archive()
                self._send_json(201, {
                    "ok": True,
                    "filename": archive_path.name,
                    "download_url": "/api/backup/download?name=" + archive_path.name,
                    "message": "Backup created successfully. Store it securely; it may contain sensitive evidence.",
                })
            elif path == "/api/reports/case":
                case_id = str(payload.get("case_id", "")).strip()
                if not case_id or not _case_exists(case_id):
                    self._send_json(400, {"error": "Select a valid case before generating a report."})
                    return
                report_path = Path(em.generate_pdf_report(case_id, _actor(payload))).resolve()
                self._send_json(200, {"filename": report_path.name, "download_url": "/api/download?kind=case&name=" + report_path.name})
            elif path == "/api/reports/evidence":
                evidence_id = str(payload.get("evidence_id", "")).strip()
                if not evidence_id:
                    self._send_json(400, {"error": "evidence_id is required."})
                    return
                report_path = Path(em.generate_evidence_custody_pdf(evidence_id, _actor(payload))).resolve()
                self._send_json(200, {"filename": report_path.name, "download_url": "/api/download?kind=evidence&name=" + report_path.name})
            else:
                self._send_json(404, {"error": "Endpoint not found."})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:
            self._server_error(exc)

    def _create_backup_archive(self) -> Path:
        """Create a timestamped ZIP containing a consistent SQLite snapshot and DataLens data files."""
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        db_path = Path(getattr(em, "DB_PATH", DATA_DIR / "datalens.db")).resolve()
        if not db_path.is_file():
            raise FileNotFoundError(f"DataLens database not found: {db_path}")

        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
        archive_path = BACKUP_DIR / f"datalens_backup_{stamp}.zip"
        snapshot_path = BACKUP_DIR / f".datalens_snapshot_{stamp}.sqlite3"
        try:
            # SQLite's backup API captures a consistent snapshot while the app is running.
            with sqlite3.connect(str(db_path), timeout=30) as source_db:
                with sqlite3.connect(str(snapshot_path), timeout=30) as snapshot_db:
                    source_db.backup(snapshot_db)

            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.write(snapshot_path, arcname="datalens_data/datalens.db")
                for path in DATA_DIR.rglob("*"):
                    if not path.is_file():
                        continue
                    resolved = path.resolve()
                    if resolved == db_path or path.name in {db_path.name + "-wal", db_path.name + "-shm"}:
                        continue
                    # Do not include prior backups or transient snapshot files in a backup.
                    if BACKUP_DIR == resolved or BACKUP_DIR in resolved.parents:
                        continue
                    try:
                        relative = path.relative_to(DATA_DIR)
                    except ValueError:
                        continue
                    archive.write(path, arcname=(Path("datalens_data") / relative).as_posix())
            if not archive_path.is_file() or archive_path.stat().st_size == 0:
                raise OSError("The backup archive was not created correctly.")
            return archive_path
        except Exception:
            archive_path.unlink(missing_ok=True)
            raise
        finally:
            snapshot_path.unlink(missing_ok=True)

    def _download_backup(self, query):
        name = query.get("name", "")
        if not name or Path(name).name != name or not name.startswith("datalens_backup_") or not name.endswith(".zip"):
            self._send_json(400, {"error": "Invalid backup download request."})
            return
        backup_dir = BACKUP_DIR.resolve()
        backup_path = (backup_dir / name).resolve()
        try:
            backup_path.relative_to(backup_dir)
        except ValueError:
            self._send_json(403, {"error": "The requested path is not permitted."})
            return
        if not backup_path.is_file():
            self._send_json(404, {"error": "Backup file not found."})
            return
        self._send_bytes(200, backup_path.read_bytes(), "application/zip", {
            "Content-Disposition": f'attachment; filename="{backup_path.name}"'
        })

    def _download_report(self, query):
        kind = query.get("kind", "")
        name = Path(query.get("name", "")).name
        if kind not in {"case", "evidence"} or not name or name != query.get("name"):
            self._send_json(400, {"error": "Invalid report download request."})
            return
        report_dir = Path(getattr(em, "REPORT_DIR", DATA_DIR / "reports")).resolve()
        report_path = (report_dir / name).resolve()
        try:
            report_path.relative_to(report_dir)
        except ValueError:
            self._send_json(403, {"error": "The requested path is not permitted."})
            return
        if not report_path.is_file() or report_path.suffix.lower() != ".pdf":
            self._send_json(404, {"error": "Report not found."})
            return
        self._send_bytes(200, report_path.read_bytes(), "application/pdf", {"Content-Disposition": f'attachment; filename="{report_path.name}"'})

    def _server_error(self, exc: Exception):
        traceback.print_exc()
        self._send_json(500, {"error": str(exc) or exc.__class__.__name__})

    def do_OPTIONS(self):
        self._send_bytes(204, b"", "text/plain; charset=utf-8", {
            "Allow": "GET, POST, OPTIONS",
        })


def main():
    server = ThreadingHTTPServer((HOST, PORT), DataLensHandler)
    print("=" * 62)
    print("DataLens local frontend/API server")
    print(f"Open http://{HOST}:{PORT} in your browser")
    print("This server is local-only by default. Do not expose it directly to the internet.")
    print("Stop the server with Ctrl+C.")
    print("=" * 62)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping DataLens server…")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
