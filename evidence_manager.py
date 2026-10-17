"""

DataLens evidence management, SQLite persistence, integrity verification,

case-level chain of custody, and PDF reporting.



This module is intentionally self-contained so it fits the DataLens

five-file prototype. The custody hash chain is tamper-evident, but it is

not a substitute for signed, externally anchored, immutable audit storage.

"""



from __future__ import annotations



import hashlib

import json

import shutil

import sqlite3

import uuid

from datetime import datetime, timezone

from pathlib import Path



# ---------------------------------------------------------------------

# STORAGE LOCATIONS AND CAPACITY

# ---------------------------------------------------------------------



BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "datalens_data"

VAULT_DIR = DATA_DIR / "evidence_vault"

REPORT_DIR = DATA_DIR / "reports"

DB_PATH = DATA_DIR / "datalens.db"



MAX_VAULT_BYTES = 50 * 1024**3  # 50 GiB





def now_utc() -> str:

    """UTC timestamp in ISO 8601 format."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds")





def _new_id(prefix: str) -> str:

    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"





def _connect() -> sqlite3.Connection:

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH, timeout=30)

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")

    connection.execute("PRAGMA busy_timeout = 30000")

    return connection





def _json_dump(value) -> str:

    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)





def _json_load(value, default=None):

    if value is None:

        return default

    try:

        return json.loads(value)

    except (TypeError, json.JSONDecodeError):

        return default





def initialize_database() -> None:

    """Create DataLens directories and tables if they do not exist."""

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    VAULT_DIR.mkdir(parents=True, exist_ok=True)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)



    schema = """

    CREATE TABLE IF NOT EXISTS cases (

        case_id TEXT PRIMARY KEY,

        case_name TEXT NOT NULL,

        analyst TEXT NOT NULL,

        created_at TEXT NOT NULL,

        status TEXT NOT NULL DEFAULT 'Open',

        description TEXT DEFAULT ''

    );



    CREATE TABLE IF NOT EXISTS evidence (

        evidence_id TEXT PRIMARY KEY,

        case_id TEXT NOT NULL,

        file_name TEXT NOT NULL,

        relative_name TEXT NOT NULL,

        stored_path TEXT NOT NULL,

        size_bytes INTEGER NOT NULL,

        sha256 TEXT NOT NULL,

        acquired_at TEXT NOT NULL,

        acquired_by TEXT NOT NULL,

        status TEXT NOT NULL,

        source_path TEXT DEFAULT '',

        FOREIGN KEY(case_id) REFERENCES cases(case_id)

    );



    CREATE TABLE IF NOT EXISTS custody (

        event_id TEXT PRIMARY KEY,

        case_id TEXT NOT NULL,

        evidence_id TEXT,

        timestamp TEXT NOT NULL,

        actor TEXT NOT NULL,

        action TEXT NOT NULL,

        details_json TEXT NOT NULL DEFAULT '{}',

        previous_hash TEXT NOT NULL DEFAULT '',

        event_hash TEXT NOT NULL,

        FOREIGN KEY(case_id) REFERENCES cases(case_id),

        FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id)

    );



    CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);

    CREATE INDEX IF NOT EXISTS idx_custody_case ON custody(case_id);

    CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody(evidence_id);



    CREATE TABLE IF NOT EXISTS analyses (

        analysis_id TEXT PRIMARY KEY,

        case_id TEXT NOT NULL,

        evidence_id TEXT NOT NULL,

        analyzed_at TEXT NOT NULL,

        actor TEXT NOT NULL,

        findings_json TEXT NOT NULL,

        FOREIGN KEY(case_id) REFERENCES cases(case_id),

        FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id)

    );



    CREATE INDEX IF NOT EXISTS idx_analyses_case ON analyses(case_id);

    CREATE INDEX IF NOT EXISTS idx_analyses_evidence ON analyses(evidence_id);

    """

    with _connect() as conn:

        conn.executescript(schema)





def format_bytes(size_bytes: int | float | None) -> str:

    size = float(size_bytes or 0)

    for unit in ("B", "KB", "MB", "GB", "TB"):

        if size < 1024 or unit == "TB":

            return f"{size:.2f} {unit}"

        size /= 1024

    return f"{size:.2f} TB"





def sha256_file(file_path: str | Path) -> str:

    """Calculate a SHA-256 digest with bounded memory."""

    digest = hashlib.sha256()

    with open(file_path, "rb") as handle:

        for chunk in iter(lambda: handle.read(1024 * 1024), b""):

            digest.update(chunk)

    return digest.hexdigest()





def vault_usage() -> int:

    """Return the total size of regular files currently in the vault."""

    VAULT_DIR.mkdir(parents=True, exist_ok=True)

    total = 0

    for path in VAULT_DIR.rglob("*"):

        try:

            if path.is_file() and not path.is_symlink():

                total += path.stat().st_size

        except OSError:

            continue

    return total





def ensure_capacity(additional_bytes: int) -> None:

    """Raise an error if an acquisition would exceed the 50 GiB vault cap."""

    additional_bytes = max(0, int(additional_bytes))

    used = vault_usage()

    if used + additional_bytes > MAX_VAULT_BYTES:

        raise OSError(

            "DataLens evidence vault capacity would exceed the 50 GB limit. "

            f"Current usage: {format_bytes(used)}; requested: "

            f"{format_bytes(additional_bytes)}."

        )





def _row_to_dict(row):

    return dict(row) if row is not None else None





def get_cases():

    """Return all cases newest first, normalizing optional legacy fields."""

    with _connect() as conn:

        columns = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}

        order_column = "created_at" if "created_at" in columns else "rowid"

        rows = conn.execute(f"SELECT * FROM cases ORDER BY {order_column} DESC").fetchall()

    result = []

    for row in rows:

        item = dict(row)

        item.setdefault("status", "Open")

        item.setdefault("description", "")

        result.append(item)

    return result





def get_case(case_id: str):

    with _connect() as conn:

        row = conn.execute(

            "SELECT * FROM cases WHERE case_id = ?", (case_id,)

        ).fetchone()

    item = _row_to_dict(row)

    if item is not None:

        item.setdefault("status", "Open")

        item.setdefault("description", "")

    return item





def create_case(case_name: str, analyst: str, description: str = ""):

    case_name = str(case_name).strip()

    analyst = str(analyst).strip()

    if not case_name:

        raise ValueError("Enter a case name.")

    if not analyst:

        raise ValueError("Enter an investigator or participant name.")



    case_id = _new_id("CASE")

    created_at = now_utc()

    # Existing DataLens databases may have an older cases schema without

    # optional columns such as status or description. Insert only columns that

    # actually exist; do not rebuild or discard the user's database.

    values = {

        "case_id": case_id,

        "case_name": case_name,

        "analyst": analyst,

        "created_at": created_at,

        "status": "Open",

        "description": str(description).strip(),

    }

    with _connect() as conn:

        columns = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}

        insert_values = [(key, value) for key, value in values.items() if key in columns]

        required_missing = [

            name for name in ("case_id", "case_name", "analyst", "created_at")

            if name not in columns

        ]

        if required_missing:

            raise RuntimeError(

                "Your existing cases table is missing required column(s): "

                + ", ".join(required_missing)

                + ". Please share the output of PRAGMA table_info(cases); your data has not been reset."

            )

        column_sql = ", ".join(f'"{key}"' for key, _ in insert_values)

        placeholders = ", ".join("?" for _ in insert_values)

        conn.execute(

            f"INSERT INTO cases ({column_sql}) VALUES ({placeholders})",

            [value for _, value in insert_values],

        )

    add_custody_event(

        case_id=case_id,

        evidence_id=None,

        actor=analyst,

        action="CASE_CREATED",

        details={"case_name": case_name, "description": str(description).strip()},

    )

    return get_case(case_id)





def _normalize_evidence(row):

    """Normalize modern and legacy evidence rows to the fields used by the UI."""

    if row is None:

        return None

    item = dict(row)

    # Legacy database names are retained as aliases; don't rewrite existing rows.

    item.setdefault("file_name", Path(str(item.get("original_path") or "evidence.bin")).name)

    item.setdefault("source_path", item.get("original_path", ""))

    item.setdefault("relative_name", item.get("file_name", ""))

    item.setdefault("acquired_by", item.get("actor", item.get("analyst", "Unknown")))

    item.setdefault("status", "Acquired")

    item.setdefault("findings_json", "{}")

    return item





def get_evidence(case_id: str | None = None):

    """Return evidence normalized across the current and legacy schemas."""

    with _connect() as conn:

        columns = {row[1] for row in conn.execute("PRAGMA table_info(evidence)").fetchall()}

        order = "acquired_at" if "acquired_at" in columns else "rowid"

        if case_id:

            rows = conn.execute(

                f'SELECT * FROM evidence WHERE case_id = ? ORDER BY "{order}" ASC, evidence_id ASC',

                (case_id,),

            ).fetchall()

        else:

            rows = conn.execute(

                f'SELECT * FROM evidence ORDER BY "{order}" DESC, evidence_id ASC'

            ).fetchall()

    return [_normalize_evidence(row) for row in rows]





def get_evidence_item(evidence_id: str):

    with _connect() as conn:

        row = conn.execute(

            "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)

        ).fetchone()

    return _normalize_evidence(row)





def _custody_columns(conn) -> set[str]:

    """Return the actual custody columns, including legacy database schemas."""

    return {

        row["name"]

        for row in conn.execute("PRAGMA table_info(custody)").fetchall()

    }





def _custody_hash_payload(

    event_id: str,

    case_id: str,

    evidence_id: str | None,

    timestamp: str,

    actor: str,

    action: str,

    details_json: str,

    previous_hash: str,

    *,

    legacy_keys: bool = False,

) -> str:

    """Serialize an event payload in the selected schema's hash format."""

    if legacy_keys:

        payload = {

            "event_id": event_id,

            "case_id": case_id,

            "evidence_id": evidence_id,

            "event_time": timestamp,

            "actor": actor,

            "action": action,

            "details": details_json,

            "previous_hash": previous_hash,

        }

    else:

        payload = {

            "event_id": event_id,

            "case_id": case_id,

            "evidence_id": evidence_id,

            "timestamp": timestamp,

            "actor": actor,

            "action": action,

            "details_json": details_json,

            "previous_hash": previous_hash,

        }

    return _json_dump(payload)





def add_custody_event(

    case_id: str,

    evidence_id: str | None,

    actor: str,

    action: str,

    details: dict | None = None,

):

    """Append a custody event using the existing database's column names."""

    if not get_case(case_id):

        raise ValueError(f"Case not found: {case_id}")



    timestamp = now_utc()

    details_json = _json_dump(details or {})

    actor = str(actor or "Unknown").strip() or "Unknown"

    action = str(action or "UNSPECIFIED").strip() or "UNSPECIFIED"



    with _connect() as conn:

        columns_info = conn.execute("PRAGMA table_info(custody)").fetchall()

        columns = {row["name"] for row in columns_info}

        event_column = next((row for row in columns_info if row["name"] == "event_id"), None)

        # Older DataLens databases use INTEGER PRIMARY KEY for event_id.

        # In that schema SQLite must assign the ID; inserting an EVT-* string

        # causes the exact "datatype mismatch" reported by the user.

        auto_integer_event_id = bool(

            event_column

            and str(event_column["type"]).upper() == "INTEGER"

            and int(event_column["pk"] or 0) == 1

        )

        time_column = "timestamp" if "timestamp" in columns else "event_time"

        details_column = "details_json" if "details_json" in columns else "details"



        previous = conn.execute(

            "SELECT event_hash FROM custody WHERE case_id = ? ORDER BY rowid DESC LIMIT 1",

            (case_id,),

        ).fetchone()

        previous_hash = previous["event_hash"] if previous else ""



        # Insert first with a temporary hash when SQLite must allocate event_id,

        # then compute the final hash using the real integer ID and update it.

        event_id = None if auto_integer_event_id else _new_id("EVT")

        values = {

            "case_id": case_id,

            "evidence_id": evidence_id,

            time_column: timestamp,

            "actor": actor,

            "action": action,

            details_column: details_json,

            "previous_hash": previous_hash,

            "event_hash": "PENDING_HASH" if auto_integer_event_id else "",

        }

        if not auto_integer_event_id:

            values["event_id"] = event_id

        insert_columns = [name for name in values if name in columns]

        placeholders = ", ".join("?" for _ in insert_columns)

        sql_columns = ", ".join(f'"{name}"' for name in insert_columns)

        cursor = conn.execute(

            f"INSERT INTO custody ({sql_columns}) VALUES ({placeholders})",

            [values[name] for name in insert_columns],

        )

        if auto_integer_event_id:

            event_id = cursor.lastrowid



        payload = _custody_hash_payload(

            event_id, case_id, evidence_id, timestamp, actor, action,

            details_json, previous_hash,

            legacy_keys=(time_column == "event_time" or details_column == "details"),

        )

        event_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        conn.execute("UPDATE custody SET event_hash = ? WHERE event_id = ?", (event_hash, event_id))



    return {

        "event_id": event_id,

        "case_id": case_id,

        "evidence_id": evidence_id,

        "timestamp": timestamp,

        "event_time": timestamp,

        "actor": actor,

        "action": action,

        "details": details or {},

        "previous_hash": previous_hash,

        "event_hash": event_hash,

    }





def get_custody(case_id: str, evidence_id: str | None = None):

    """Read custody events and normalize legacy fields for the rest of DataLens."""

    with _connect() as conn:

        columns = _custody_columns(conn)

        time_column = "timestamp" if "timestamp" in columns else "event_time"

        details_column = "details_json" if "details_json" in columns else "details"



        query = (

            f"SELECT *, {time_column} AS normalized_timestamp, "

            f"{details_column} AS normalized_details FROM custody WHERE case_id = ?"

        )

        params = [case_id]

        if evidence_id:

            query += " AND evidence_id = ?"

            params.append(evidence_id)

        query += f" ORDER BY {time_column} ASC, rowid ASC"

        rows = conn.execute(query, params).fetchall()



    events = []

    for row in rows:

        item = dict(row)

        raw_details = item.pop("normalized_details", "{}")

        item["timestamp"] = item.get("normalized_timestamp") or item.get("timestamp") or item.get("event_time")

        item.pop("normalized_timestamp", None)

        item["details"] = _json_load(raw_details, {})

        events.append(item)

    return events



def get_case_custody(case_id: str):

    """Alias retained for UI compatibility."""

    return get_custody(case_id)





def verify_custody_log(case_id: str):

    """Verify custody links and hashes, supporting current and legacy payloads."""

    events = get_custody(case_id)

    previous_hash = ""

    errors = []



    for event in events:

        event_id = event.get("event_id", "")

        event_previous = event.get("previous_hash", "") or ""

        if event_previous != previous_hash:

            errors.append(f"Event {event_id}: previous hash mismatch.")



        timestamp = event.get("timestamp", event.get("event_time", ""))

        details_json = _json_dump(event.get("details") or {})

        common = (

            event_id,

            event.get("case_id", case_id),

            event.get("evidence_id"),

            timestamp,

            event.get("actor", ""),

            event.get("action", ""),

            details_json,

            event_previous,

        )

        candidates = {

            hashlib.sha256(_custody_hash_payload(*common).encode("utf-8")).hexdigest(),

            hashlib.sha256(_custody_hash_payload(*common, legacy_keys=True).encode("utf-8")).hexdigest(),

        }

        # Also support older versions that serialized the parsed details object

        # instead of its JSON string in the hash payload.

        for time_key, details_key in (("timestamp", "details_json"), ("event_time", "details")):

            alternate_payload = _json_dump({

                "event_id": event_id,

                "case_id": event.get("case_id", case_id),

                "evidence_id": event.get("evidence_id"),

                time_key: timestamp,

                "actor": event.get("actor", ""),

                "action": event.get("action", ""),

                details_key: event.get("details") or {},

                "previous_hash": event_previous,

            })

            candidates.add(hashlib.sha256(alternate_payload.encode("utf-8")).hexdigest())



        if event.get("event_hash") not in candidates:

            errors.append(f"Event {event_id}: event hash mismatch or legacy hash format not recognized.")

        previous_hash = event.get("event_hash", "") or ""



    return {"valid": not errors, "events_checked": len(events), "errors": errors}



def register_evidence(

    case_id: str,

    source_file: str | Path,

    actor: str,

    relative_name: str | None = None,

    allow_duplicate: bool = False,

):

    """

    Copy one file into the vault, hash source and copy, and register the

    evidence under the supplied case. Original media is not modified by this

    function, but the operating system may still update source metadata.

    """

    case = get_case(case_id)

    if not case:

        raise ValueError(f"Case not found: {case_id}")



    # Check the original path before resolving it; resolve() follows symlinks,
    # so checking is_symlink() only after resolve() would miss a symlink input.
    source_input = Path(source_file).expanduser()
    if source_input.is_symlink():
        raise ValueError("Evidence source must not be a symbolic link.")
    source = source_input.resolve(strict=True)
    if not source.is_file():
        raise ValueError("Evidence source must be a regular file.")

    source_size = source.stat().st_size
    source_hash = sha256_file(source)

    # Prevent accidental repeat acquisitions of identical bytes in the same case.
    # Existing evidence records are never deleted or overwritten. If the analyst
    # intentionally needs a second acquisition event, pass allow_duplicate=True.
    if not allow_duplicate:
        with _connect() as conn:
            evidence_columns = {row[1] for row in conn.execute("PRAGMA table_info(evidence)").fetchall()}
            if {"case_id", "sha256", "evidence_id"}.issubset(evidence_columns):
                name_expr = "file_name" if "file_name" in evidence_columns else "original_path"
                time_order = '"acquired_at" ASC, ' if "acquired_at" in evidence_columns else ""
                matches = conn.execute(
                    f'SELECT evidence_id, {name_expr} AS file_name '
                    f'FROM evidence WHERE case_id = ? AND lower(sha256) = lower(?) '
                    f'ORDER BY {time_order}evidence_id ASC',
                    (case_id, source_hash),
                ).fetchall()
            else:
                matches = []
        if matches:
            match_text = "; ".join(
                f"{row['evidence_id']} ({row['file_name']})" for row in matches
            )
            raise ValueError(
                "Duplicate evidence content detected: this file has the same SHA-256 "
                f"as evidence already registered in this case: {match_text}. "
                "No new evidence record was created. To intentionally record a separate "
                "acquisition event, call register_evidence(..., allow_duplicate=True)."
            )

    ensure_capacity(source_size)



    original_name = Path(relative_name or source.name).name

    if not original_name:

        raise ValueError("Evidence filename is invalid.")



    evidence_id = _new_id("EVD")

    case_folder = VAULT_DIR / case_id

    case_folder.mkdir(parents=True, exist_ok=True)



    # Keep the file's original suffix while using a unique vault filename.

    safe_name = f"{evidence_id}_{original_name}"

    destination = case_folder / safe_name



    record_inserted = False

    try:

        shutil.copyfile(source, destination)

        copied_hash = sha256_file(destination)

        if copied_hash != source_hash:

            destination.unlink(missing_ok=True)

            raise OSError("SHA-256 verification failed after evidence copy.")



        acquired_at = now_utc()

        status = "Acquired and hash-verified"

        relative_value = str(relative_name or source.name).replace("\\\\", "/")

        # Insert only columns supported by this database. Older DataLens DBs

        # use original_path and findings_json and lack relative_name/acquired_by/source_path.

        values = {

            "evidence_id": evidence_id,

            "case_id": case_id,

            "original_path": str(source),

            "source_path": str(source),

            "file_name": original_name,

            "relative_name": relative_value,

            "stored_path": str(destination),

            "size_bytes": destination.stat().st_size,

            "sha256": copied_hash,

            "acquired_at": acquired_at,

            "acquired_by": str(actor or "Unknown"),

            "status": status,

            "findings_json": "{}",

        }

        with _connect() as conn:

            info = conn.execute("PRAGMA table_info(evidence)").fetchall()

            columns = {row[1] for row in info}

            insert_columns = [name for name in values if name in columns]

            required_missing = [

                row[1] for row in info

                if row[3] and row[1] not in insert_columns and row[4] is None and not row[5]

            ]

            if required_missing:

                raise RuntimeError(

                    "Evidence table has unsupported required column(s): " + ", ".join(required_missing)

                )

            quoted_columns = ", ".join(f'"{name}"' for name in insert_columns)

            placeholders = ", ".join("?" for _ in insert_columns)

            conn.execute(

                f"INSERT INTO evidence ({quoted_columns}) VALUES ({placeholders})",

                [values[name] for name in insert_columns],

            )

        # Mark the committed record so exception cleanup can keep the vault
        # file and database row consistent if custody-event creation fails.
        record_inserted = True

        add_custody_event(

            case_id=case_id,

            evidence_id=evidence_id,

            actor=actor,

            action="EVIDENCE_ACQUIRED",

            details={

                "file_name": original_name,

                "relative_name": str(relative_name or source.name).replace("\\\\", "/"),

                "size_bytes": destination.stat().st_size,

                "sha256": copied_hash,

                "source_path": str(source),

                "acquisition_status": status,

            },

        )

        return get_evidence_item(evidence_id)

    except Exception as original_error:

        # If the evidence row was committed but custody-event creation failed,
        # remove the row first. Only delete the copied file if the row removal
        # succeeds; otherwise preserve the file so the database cannot point
        # to evidence that this cleanup has deleted.
        may_delete_file = not record_inserted

        if record_inserted:

            try:

                with _connect() as conn:

                    cursor = conn.execute(

                        "DELETE FROM evidence WHERE evidence_id = ?",

                        (evidence_id,),

                    )

                    may_delete_file = cursor.rowcount == 1

            except Exception:

                may_delete_file = False


        if may_delete_file and destination.exists():

            try:

                destination.unlink()

            except OSError:

                # Preserve the original exception; a leftover unregistered
                # file is safer than hiding the acquisition failure.
                pass

        elif record_inserted:

            raise RuntimeError(

                "Evidence acquisition encountered an error after the database "
                "record was committed. Cleanup could not safely remove the "
                "record, so the copied evidence file was preserved at: "
                f"{destination}. Original error: {original_error}"

            ) from original_error

        raise





def verify_evidence(evidence_id: str, actor: str = "Investigator"):

    """Recalculate the stored file hash and record an integrity check."""

    evidence = get_evidence_item(evidence_id)

    if not evidence:

        return {"status": "MISSING", "evidence_id": evidence_id, "message": "Record not found."}



    path = Path(evidence["stored_path"])

    if not path.is_file():

        status = "MISSING"

        actual_hash = None

    else:

        actual_hash = sha256_file(path)

        status = "VERIFIED" if actual_hash == evidence["sha256"] else "MISMATCH"



    add_custody_event(

        case_id=evidence["case_id"],

        evidence_id=evidence_id,

        actor=actor,

        action="EVIDENCE_INTEGRITY_CHECK",

        details={

            "status": status,

            "expected_sha256": evidence.get("sha256"),

            "actual_sha256": actual_hash,

        },

    )

    return {

        "status": status,

        "evidence_id": evidence_id,

        "expected_sha256": evidence.get("sha256"),

        "actual_sha256": actual_hash,

    }





def save_analysis_result(evidence_id: str, findings: dict, actor: str = "Investigator"):

    """Persist one analysis result and add a custody event for its evidence."""

    evidence = get_evidence_item(evidence_id)

    if not evidence:

        raise ValueError(f"Evidence not found: {evidence_id}")



    analysis_id = _new_id("ANL")

    analyzed_at = now_utc()

    with _connect() as conn:

        conn.execute(

            """INSERT INTO analyses

               (analysis_id, case_id, evidence_id, analyzed_at, actor, findings_json)

               VALUES (?, ?, ?, ?, ?, ?)""",

            (

                analysis_id, evidence["case_id"], evidence_id, analyzed_at,

                str(actor or "Unknown"), _json_dump(findings),

            ),

        )

    add_custody_event(

        case_id=evidence["case_id"],

        evidence_id=evidence_id,

        actor=actor,

        action="EVIDENCE_ANALYZED",

        details={

            "analysis_id": analysis_id,

            "analysis_method": findings.get("analysis_method", "AI and forensic triage"),

            "severity": findings.get("severity"),

            "risk_score": findings.get("risk_score"),

            "ai_models": findings.get("ai_models", {}),

        },

    )

    return {

        "analysis_id": analysis_id,

        "case_id": evidence["case_id"],

        "evidence_id": evidence_id,

        "analyzed_at": analyzed_at,

        "actor": actor,

        "findings": findings,

    }





def get_analysis_results(case_id: str, evidence_id: str | None = None):

    """Return saved analysis records for a case."""

    with _connect() as conn:

        if evidence_id:

            rows = conn.execute(

                """SELECT * FROM analyses WHERE case_id = ? AND evidence_id = ?

                   ORDER BY analyzed_at DESC""",

                (case_id, evidence_id),

            ).fetchall()

        else:

            rows = conn.execute(

                """SELECT * FROM analyses WHERE case_id = ?

                   ORDER BY analyzed_at DESC""",

                (case_id,),

            ).fetchall()

    output = []

    for row in rows:

        item = dict(row)

        item["findings"] = _json_load(item.pop("findings_json"), {})

        output.append(item)

    return output





def generate_evidence_custody_pdf(evidence_id: str, actor: str = "Investigator") -> Path:
    """Generate a readable, landscape PDF for one evidence item and its recorded events."""
    try:
        from xml.sax.saxutils import escape
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, LongTable, KeepTogether
        )
    except ImportError as exc:
        raise RuntimeError(
            "PDF reports require ReportLab. Install it with: python -m pip install reportlab"
        ) from exc

    item = get_evidence_item(evidence_id)
    if not item:
        raise ValueError(f"Evidence item not found: {evidence_id}")

    case = get_case(item["case_id"]) or {}
    events = get_custody(item["case_id"], evidence_id=evidence_id)
    chain_check = verify_custody_log(item["case_id"])
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / f"DataLens_Evidence_Custody_{evidence_id}.pdf"

    page_size = landscape(A4)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="DLSubtitle", parent=styles["Normal"], fontSize=10,
        leading=14, textColor=colors.HexColor("#53657D"), alignment=TA_CENTER,
        spaceAfter=5 * mm
    ))
    styles.add(ParagraphStyle(
        name="DLSection", parent=styles["Heading2"], fontSize=12,
        leading=15, textColor=colors.HexColor("#17365D"), spaceBefore=4 * mm,
        spaceAfter=2 * mm
    ))
    styles.add(ParagraphStyle(
        name="DLCell", parent=styles["BodyText"], fontSize=8, leading=10,
        wordWrap="CJK", splitLongWords=1
    ))
    styles.add(ParagraphStyle(
        name="DLSmall", parent=styles["BodyText"], fontSize=7, leading=9,
        wordWrap="CJK", splitLongWords=1
    ))
    styles.add(ParagraphStyle(
        name="DLHash", parent=styles["BodyText"], fontName="Courier",
        fontSize=6.5, leading=8, wordWrap="CJK", splitLongWords=1
    ))
    styles.add(ParagraphStyle(
        name="DLHeader", parent=styles["BodyText"], fontSize=8, leading=10,
        textColor=colors.white, fontName="Helvetica-Bold"
    ))

    generated_at = now_utc()
    doc = SimpleDocTemplate(
        str(report_path), pagesize=page_size,
        rightMargin=14 * mm, leftMargin=14 * mm,
        topMargin=19 * mm, bottomMargin=17 * mm,
        title=f"DataLens Evidence Chain of Custody - {evidence_id}",
        author="DataLens"
    )

    def para(value, style="DLCell"):
        return Paragraph(escape(str(value if value is not None else "")), styles[style])

    story = [
        Paragraph("DataLens | Evidence Chain of Custody", styles["Title"]),
        Paragraph("Individual evidence handling and integrity record", styles["DLSubtitle"]),
    ]

    metadata = [
        ["Case ID", str(item.get("case_id", "")),
         "Case name", str(case.get("case_name", ""))],
        ["Evidence ID", str(item.get("evidence_id", "")),
         "File name", str(item.get("file_name", ""))],
        ["Original path", str(item.get("original_path", item.get("source_path", ""))),
         "Stored path", str(item.get("stored_path", item.get("relative_name", "")))],
        ["Size", f'{item.get("size_bytes", "")} bytes',
         "Acquired at (UTC)", str(item.get("acquired_at", ""))],
        ["SHA-256", str(item.get("sha256", "")), "Status", str(item.get("status", "Acquired"))],
        ["Report generated by", str(actor), "Generated at (UTC)", generated_at],
    ]
    metadata_rows = []
    for row in metadata:
        metadata_rows.append([
            para(row[0]), para(row[1], "DLHash" if row[0] == "SHA-256" else "DLCell"),
            para(row[2]), para(row[3], "DLHash" if row[2] == "Stored path" else "DLCell")
        ])
    meta_table = Table(metadata_rows, colWidths=[32*mm, 94*mm, 35*mm, 94*mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EEF8")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#E8EEF8")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#A8B4C4")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([meta_table, Spacer(1, 4 * mm)])

    integrity_text = (
        f"Case custody-chain check: {'VALID' if chain_check['valid'] else 'FAILED'} "
        f"({chain_check['events_checked']} events checked)."
    )
    if not chain_check["valid"]:
        integrity_text += " Issues: " + "; ".join(chain_check["errors"])
    story.extend([
        Paragraph("Integrity verification", styles["DLSection"]),
        Paragraph(escape(integrity_text), styles["DLCell"]),
        Spacer(1, 2 * mm),
        Paragraph("Chronological Custody Events", styles["DLSection"]),
    ])

    headers = ["Timestamp (UTC)", "Actor", "Action", "Recorded details", "Previous hash", "Event hash"]
    rows = [[para(label, "DLHeader") for label in headers]]
    for ev in events:
        details = ev.get("details", {})
        if not isinstance(details, str):
            details = json.dumps(details, ensure_ascii=False, sort_keys=True, indent=2, default=str)
        rows.append([
            para(ev.get("timestamp", ev.get("event_time", "")), "DLSmall"),
            para(ev.get("actor", ""), "DLCell"),
            para(ev.get("action", ""), "DLCell"),
            para(details, "DLSmall"),
            para(ev.get("previous_hash", ""), "DLHash"),
            para(ev.get("event_hash", ""), "DLHash"),
        ])
    if len(rows) == 1:
        rows.append([para("No custody events have been recorded for this evidence item.")]
                     + ["", "", "", "", ""])

    event_table = LongTable(
        rows, colWidths=[32*mm, 25*mm, 36*mm, 79*mm, 44*mm, 44*mm],
        repeatRows=1, hAlign="LEFT"
    )
    event_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#23395D")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#A8B4C4")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#F4F7FB")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([
        event_table, Spacer(1, 5 * mm),
        Paragraph(
            "Important: this report reflects custody records currently stored in DataLens. "
            "A PDF export is not itself a digital signature or independent proof that records "
            "were never altered. Preserve the original evidence and validate findings independently.",
            styles["Italic"]
        ),
    ])

    def draw_page(canvas, document):
        canvas.saveState()
        width, height = page_size
        canvas.setStrokeColor(colors.HexColor("#D6DEE8"))
        canvas.line(14 * mm, height - 12 * mm, width - 14 * mm, height - 12 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#53657D"))
        canvas.drawString(14 * mm, height - 9 * mm, "DATALENS | DIGITAL FORENSICS")
        canvas.drawRightString(width - 14 * mm, 9 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    return report_path


def generate_pdf_report(case_id: str, actor: str = "Investigator") -> Path:

    """

    Generate a case-level chain-of-custody PDF including every evidence item

    and every custody event for the selected case.

    """

    try:

        from reportlab.lib import colors

        from reportlab.lib.enums import TA_CENTER

        from reportlab.lib.pagesizes import A4, landscape

        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

        from reportlab.lib.units import mm

        from reportlab.platypus import (

            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

        )

    except ImportError as exc:

        raise RuntimeError(

            "PDF reports require ReportLab. Install it with: python -m pip install reportlab"

        ) from exc



    case = get_case(case_id)

    if not case:

        raise ValueError(f"Case not found: {case_id}")



    evidence_items = get_evidence(case_id)

    custody_events = get_custody(case_id)

    integrity = verify_custody_log(case_id)



    report_path = REPORT_DIR / f"DataLens_Case_Custody_{case_id}.pdf"

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(

        name="SmallCell", parent=styles["BodyText"], fontSize=7, leading=9

    ))

    styles.add(ParagraphStyle(

        name="TinyCell", parent=styles["BodyText"], fontSize=6, leading=7

    ))

    styles.add(ParagraphStyle(

        name="CenteredSmall", parent=styles["BodyText"], alignment=TA_CENTER,

        fontSize=8, leading=10

    ))



    doc = SimpleDocTemplate(

        str(report_path),

        pagesize=landscape(A4),

        rightMargin=12 * mm,

        leftMargin=12 * mm,

        topMargin=14 * mm,

        bottomMargin=14 * mm,

        title=f"DataLens Case Chain of Custody - {case_id}",

        author="DataLens",

    )

    story = [

        Paragraph("DataLens — Case Chain of Custody", styles["Title"]),

        Paragraph("Case-level evidence inventory and chronological handling record", styles["Heading2"]),

        Spacer(1, 4 * mm),

    ]



    case_rows = [

        ["Case ID", case["case_id"], "Case name", case["case_name"]],

        ["Investigator", case["analyst"], "Created", case["created_at"]],

        ["Case status", case["status"], "Evidence count", str(len(evidence_items))],

        ["Custody events", str(len(custody_events)), "Hash-chain check", "VALID" if integrity["valid"] else "FAILED"],

    ]

    case_table = Table(case_rows, colWidths=[28*mm, 75*mm, 28*mm, 100*mm])

    case_table.setStyle(TableStyle([

        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EEF8")),

        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#E8EEF8")),

        ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),

        ("VALIGN", (0, 0), (-1, -1), "TOP"),

        ("FONTSIZE", (0, 0), (-1, -1), 8),

        ("LEFTPADDING", (0, 0), (-1, -1), 5),

        ("RIGHTPADDING", (0, 0), (-1, -1), 5),

        ("TOPPADDING", (0, 0), (-1, -1), 5),

        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),

    ]))

    story.extend([case_table, Spacer(1, 5 * mm), Paragraph("Evidence Inventory", styles["Heading2"])])



    evidence_data = [[

        "Evidence ID", "File name", "Size", "SHA-256", "Acquired at", "Acquired by", "Status"

    ]]

    for item in evidence_items:

        evidence_data.append([

            Paragraph(str(item["evidence_id"]), styles["TinyCell"]),

            Paragraph(str(item["file_name"]), styles["SmallCell"]),

            format_bytes(item["size_bytes"]),

            Paragraph(str(item["sha256"]), styles["TinyCell"]),

            Paragraph(str(item["acquired_at"]), styles["TinyCell"]),

            Paragraph(str(item["acquired_by"]), styles["SmallCell"]),

            Paragraph(str(item["status"]), styles["SmallCell"]),

        ])

    if len(evidence_data) == 1:

        evidence_data.append(["No evidence registered", "", "", "", "", "", ""])

    evidence_table = Table(

        evidence_data,

        repeatRows=1,

        colWidths=[30*mm, 42*mm, 20*mm, 58*mm, 35*mm, 30*mm, 35*mm],

    )

    evidence_table.setStyle(TableStyle([

        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#23395D")),

        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),

        ("VALIGN", (0, 0), (-1, -1), "TOP"),

        ("FONTSIZE", (0, 0), (-1, -1), 7),

        ("LEFTPADDING", (0, 0), (-1, -1), 4),

        ("RIGHTPADDING", (0, 0), (-1, -1), 4),

        ("TOPPADDING", (0, 0), (-1, -1), 4),

        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),

    ]))

    story.extend([evidence_table, Spacer(1, 5 * mm), Paragraph("Chronological Chain of Custody", styles["Heading2"])])



    custody_data = [[

        "Timestamp (UTC)", "Event ID", "Evidence ID", "Actor", "Action", "Details", "Previous hash", "Event hash"

    ]]

    for event in custody_events:

        details_text = json.dumps(event.get("details", {}), ensure_ascii=False, default=str)

        custody_data.append([

            Paragraph(str(event["timestamp"]), styles["TinyCell"]),

            Paragraph(str(event["event_id"]), styles["TinyCell"]),

            Paragraph(str(event.get("evidence_id") or "CASE"), styles["TinyCell"]),

            Paragraph(str(event["actor"]), styles["TinyCell"]),

            Paragraph(str(event["action"]), styles["TinyCell"]),

            Paragraph(details_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), styles["TinyCell"]),

            Paragraph(str(event.get("previous_hash", "")), styles["TinyCell"]),

            Paragraph(str(event.get("event_hash", "")), styles["TinyCell"]),

        ])

    if len(custody_data) == 1:

        custody_data.append(["No custody events", "", "", "", "", "", "", ""])

    custody_table = Table(

        custody_data,

        repeatRows=1,

        colWidths=[28*mm, 25*mm, 24*mm, 20*mm, 29*mm, 67*mm, 40*mm, 40*mm],

    )

    custody_table.setStyle(TableStyle([

        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#23395D")),

        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),

        ("VALIGN", (0, 0), (-1, -1), "TOP"),

        ("FONTSIZE", (0, 0), (-1, -1), 6),

        ("LEFTPADDING", (0, 0), (-1, -1), 3),

        ("RIGHTPADDING", (0, 0), (-1, -1), 3),

        ("TOPPADDING", (0, 0), (-1, -1), 3),

        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),

    ]))

    story.extend([

        custody_table,

        Spacer(1, 5 * mm),

        Paragraph(

            "Integrity note: the event-chain check is "

            + ("VALID." if integrity["valid"] else "FAILED: " + "; ".join(integrity["errors"]))

            + " This application-level hash chain is tamper-evident, but it is not independently immutable "

              "and should not be represented as a digitally signed or externally anchored log.",

            styles["BodyText"],

        ),

        Spacer(1, 3 * mm),

        Paragraph(

            f"Generated by {actor} at {now_utc()}. This report contains the case's currently registered "

            "evidence and custody events at generation time.",

            styles["Italic"],

        ),

    ])

    doc.build(story)



    # Record report generation after building the report, so the report itself

    # does not falsely claim to include its own generation event.

    add_custody_event(

        case_id=case_id,

        evidence_id=None,

        actor=actor,

        action="CASE_CUSTODY_REPORT_GENERATED",

        details={

            "report_file": report_path.name,

            "evidence_count": len(evidence_items),

            "custody_events_in_report": len(custody_events),

            "hash_chain_valid_at_generation": integrity["valid"],

        },

    )

    return report_path





# Initialize storage/schema when this module is imported.

initialize_database()
