"""
DataLens prototype file-carving recovery module.

This module performs basic signature-based carving from a raw image/file.
It is not a complete filesystem recovery tool and cannot reliably reconstruct
fragmented files, filesystem metadata, original names, or all deleted content.
Use only on media/images you are authorized to examine.
"""

from __future__ import annotations

import mmap
from pathlib import Path

from evidence_manager import (
    DATA_DIR,
    VAULT_DIR,
    add_custody_event,
    register_evidence,
)

RECOVERY_DIR = DATA_DIR / "recovery_staging"
DEFAULT_MAX_CANDIDATE_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_FILES = 500

# Signatures are byte patterns that indicate a possible file start.
# They do not guarantee that the carved result is valid or complete.
FILE_SIGNATURES = {
    "JPEG": (b"\xff\xd8\xff", ".jpg"),
    "PNG": (b"\x89PNG\r\n\x1a\n", ".png"),
    "PDF": (b"%PDF-", ".pdf"),
    "ZIP": (b"PK\x03\x04", ".zip"),
}

# Some types have a recognizable ending marker. ZIP's ending marker is
# variable, so this prototype uses the next signature or size cap for ZIP.
END_MARKERS = {
    "JPEG": b"\xff\xd9",
    "PNG": b"IEND\xaeB`\x82",
    "PDF": b"%%EOF",
}


def _is_within(path: str | Path, directory: str | Path) -> bool:
    try:
        Path(path).resolve().relative_to(Path(directory).resolve())
        return True
    except (ValueError, OSError, RuntimeError):
        return False


def validate_image(image_path: str | Path) -> Path:
    """Validate that a raw image/file is suitable for prototype carving."""
    supplied_path = Path(image_path).expanduser()
    if supplied_path.is_symlink():
        raise ValueError("Symbolic links cannot be used as recovery sources.")
    path = supplied_path.resolve(strict=True)

    if not path.is_file():
        raise ValueError("Recovery source must be a regular file.")
    if path.stat().st_size <= 0:
        raise ValueError("Recovery source is empty.")
    if _is_within(path, VAULT_DIR):
        raise ValueError("Do not use a vault evidence copy as a raw recovery source.")
    if _is_within(path, RECOVERY_DIR):
        raise ValueError("A previous recovery output cannot be used as a source.")
    return path


def _find_all(data, signature: bytes, start: int = 0):
    """Yield every occurrence of signature in a memory-mapped file."""
    position = start
    while True:
        position = data.find(signature, position)
        if position < 0:
            return
        yield position
        position += 1


def _candidate_end(data, file_type: str, start: int, next_start: int, max_bytes: int):
    """Determine a bounded candidate end using a footer where available."""
    hard_end = min(next_start, start + max_bytes, len(data))
    marker = END_MARKERS.get(file_type)

    if marker:
        marker_pos = data.find(marker, start, hard_end)
        if marker_pos >= 0:
            return min(marker_pos + len(marker), hard_end)

    return hard_end


def carve_image(
    image_path: str | Path,
    selected_types: list[str] | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_candidate_bytes: int = DEFAULT_MAX_CANDIDATE_BYTES,
):
    """
    Carve candidate files from a raw image/file.

    Returns a list of metadata dictionaries. Carved output is placed in
    datalens_data/recovery_staging and is not automatically registered as
    evidence until register_recovered_files() is called.
    """
    source = validate_image(image_path)
    max_files = max(1, min(int(max_files), 5000))
    max_candidate_bytes = max(1024, min(
        int(max_candidate_bytes), DEFAULT_MAX_CANDIDATE_BYTES
    ))

    chosen = set(selected_types or FILE_SIGNATURES.keys())
    chosen = {name.upper() for name in chosen}
    signatures = {
        file_type: details
        for file_type, details in FILE_SIGNATURES.items()
        if file_type in chosen
    }
    if not signatures:
        raise ValueError("Select at least one supported file type.")

    RECOVERY_DIR.mkdir(parents=True, exist_ok=True)
    candidates = []

    # Open first, then map the actual open file. This avoids relying on a size
    # observed before opening the source and handles an unexpectedly empty file.
    with open(source, "rb") as handle:
        handle.seek(0, 2)
        source_size = handle.tell()
        handle.seek(0)
        if source_size <= 0:
            raise ValueError("Recovery source became empty before scanning.")
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            found = []
            for file_type, (signature, _extension) in signatures.items():
                for offset in _find_all(mapped, signature):
                    found.append((offset, file_type))
            found.sort(key=lambda item: (item[0], item[1]))

            # If multiple signatures overlap, preserve each candidate, but
            # avoid duplicate entries at the exact same offset.
            unique_found = []
            seen = set()
            for item in found:
                if item[0] not in seen:
                    unique_found.append(item)
                    seen.add(item[0])

            for index, (offset, file_type) in enumerate(unique_found):
                if len(candidates) >= max_files:
                    break

                next_offset = (
                    unique_found[index + 1][0]
                    if index + 1 < len(unique_found)
                    else source_size
                )
                end = _candidate_end(
                    mapped, file_type, offset, next_offset, max_candidate_bytes
                )
                if end <= offset:
                    continue

                # Avoid creating extremely tiny false-positive candidates.
                if end - offset < len(FILE_SIGNATURES[file_type][0]) + 8:
                    continue

                extension = FILE_SIGNATURES[file_type][1]
                candidate_id = f"REC-{offset:012X}"
                output_path = RECOVERY_DIR / f"{candidate_id}{extension}"

                # Do not silently overwrite prior recovery output.
                if output_path.exists():
                    output_path = RECOVERY_DIR / f"{candidate_id}_{len(candidates)}{extension}"

                with open(output_path, "wb") as output:
                    output.write(mapped[offset:end])

                candidates.append({
                    "candidate_id": candidate_id,
                    "file_name": output_path.name,
                    "file_type": file_type,
                    "offset": int(offset),
                    "end_offset": int(end),
                    "size_bytes": int(end - offset),
                    "source_image": str(source),
                    "output_path": str(output_path),
                    "status": "Candidate carved; validation required",
                    "registered_evidence_id": None,
                })

    return candidates


def register_recovered_files(
    case_id: str,
    recovery_results: list[dict],
    actor: str = "Investigator",
    source_image: str | Path | None = None,
):
    """
    Register carved candidates as ordinary evidence items in the selected case.
    Each successful registration is hashed by evidence_manager and receives
    an explicit recovery provenance event.
    """
    registered = []
    source_value = str(source_image) if source_image else ""

    for candidate in recovery_results:
        raw_output_path = candidate.get("output_path")
        if not raw_output_path:
            registered.append({
                "candidate_id": candidate.get("candidate_id", ""),
                "evidence_id": None,
                "status": "FAILED: carved candidate path is missing",
            })
            continue
        output_path = Path(raw_output_path).expanduser()
        if output_path.is_symlink() or not _is_within(output_path, RECOVERY_DIR):
            registered.append({
                "candidate_id": candidate.get("candidate_id", ""),
                "evidence_id": None,
                "status": "FAILED: candidate must be a regular file inside recovery staging",
            })
            continue
        if not output_path.is_file():
            registered.append({
                "candidate_id": candidate.get("candidate_id", ""),
                "evidence_id": None,
                "status": "FAILED: carved candidate is missing",
            })
            continue
        try:
            if output_path.stat().st_size <= 0:
                raise ValueError("candidate file is empty")
        except OSError as exc:
            registered.append({
                "candidate_id": candidate.get("candidate_id", ""),
                "evidence_id": None,
                "status": f"FAILED: cannot inspect candidate file ({exc})",
            })
            continue

        evidence = None
        try:
            evidence = register_evidence(
                case_id=case_id,
                source_file=output_path,
                actor=actor,
                relative_name=(
                    f"recovered/{candidate.get('candidate_id', output_path.name)}"
                    f"{output_path.suffix}"
                ),
            )
        except Exception as exc:
            registered.append({
                "candidate_id": candidate.get("candidate_id", ""),
                "evidence_id": None,
                "status": f"FAILED during evidence registration: {exc}",
            })
            continue

        # Once register_evidence succeeds, do not report the whole operation as
        # failed just because the additional provenance event could not be saved.
        # The evidence record already exists and should not be blindly retried.
        candidate["registered_evidence_id"] = evidence["evidence_id"]
        candidate["status"] = "Registered as evidence; manual validation required"
        try:
            add_custody_event(
                case_id=case_id,
                evidence_id=evidence["evidence_id"],
                actor=actor,
                action="RECOVERED_FILE_REGISTERED",
                details={
                    "candidate_id": candidate.get("candidate_id"),
                    "file_type": candidate.get("file_type"),
                    "source_image": source_value or candidate.get("source_image", ""),
                    "offset": candidate.get("offset"),
                    "end_offset": candidate.get("end_offset"),
                    "carved_size_bytes": candidate.get("size_bytes"),
                    "recovery_method": "Signature-based file carving prototype",
                    "limitations": (
                        "Candidate content may be incomplete, false-positive, "
                        "or fragmented; validate manually."
                    ),
                },
            )
            status = candidate["status"]
        except Exception as exc:
            status = (
                "Evidence registered, but recovery provenance event failed; "
                f"review custody log before retrying ({exc})"
            )
            candidate["status"] = status

        registered.append({
            "candidate_id": candidate.get("candidate_id", ""),
            "evidence_id": evidence["evidence_id"],
            "file": evidence.get("file_name", output_path.name),
            "sha256": evidence.get("sha256", ""),
            "status": status,
        })

    return registered


def recovery_summary(recovery_results: list[dict]) -> dict:
    """Summarize carving results for display in the UI."""
    total = len(recovery_results)
    by_type = {}
    total_bytes = 0
    registered = 0

    for item in recovery_results:
        file_type = item.get("file_type", "Unknown")
        by_type[file_type] = by_type.get(file_type, 0) + 1
        total_bytes += int(item.get("size_bytes") or 0)
        if item.get("registered_evidence_id"):
            registered += 1

    return {
        "candidate_count": total,
        "registered_count": registered,
        "total_candidate_bytes": total_bytes,
        "by_type": by_type,
        "staging_directory": str(RECOVERY_DIR),
        "note": (
            "Signature-based carving is a prototype technique. It cannot "
            "reliably restore filesystem metadata, fragmented files, or prove "
            "that a candidate was deleted."
        ),
    }


def clear_unregistered_recovery_candidates(confirm: bool = False):
    """Safely clean staging only after explicit confirmation.

    This prototype does not maintain a reliable persistent registry mapping all
    staging files to evidence records. Therefore, it refuses to delete anything
    by default rather than risk removing a candidate that an investigator needs.
    When confirm=True, it deletes regular, non-symlink files in RECOVERY_DIR.
    Review the directory and preserve any required case material before calling.
    """
    if not confirm:
        raise ValueError(
            "Cleanup is destructive. Review recovery_staging and call with confirm=True only if safe."
        )
    RECOVERY_DIR.mkdir(parents=True, exist_ok=True)
    removed = []
    for path in RECOVERY_DIR.iterdir():
        if path.is_symlink() or not path.is_file():
            continue
        try:
            path.unlink()
            removed.append(path.name)
        except OSError:
            continue
    return removed
