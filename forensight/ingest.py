"""
Forensight - Evidence ingestion & integrity module.

Loads a suspicious email (.eml) as forensic evidence:
  1. Reads the raw bytes exactly once.
  2. Computes cryptographic hashes (MD5, SHA-1, SHA-256).
  3. Records the acquisition in a chain-of-custody log.
  4. Parses the email for later analysis.
  5. Can re-verify that the evidence file was not modified.
"""

import getpass
import hashlib
import json
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

CUSTODY_LOG = Path("output") / "custody_log.jsonl"


@dataclass
class EmailEvidence:
    """One email file treated as a piece of forensic evidence."""
    path: Path
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    acquired_at: str
    message: EmailMessage = field(repr=False)


def _utc_now() -> str:
    """Current time in UTC, ISO 8601 format (standard for forensic timestamps)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def compute_hashes(data: bytes) -> dict:
    """Return MD5, SHA-1 and SHA-256 of raw bytes."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def log_custody(action: str, evidence_path: Path, sha256: str, note: str = "") -> None:
    """Append one chain-of-custody record (who, what, when, where) as a JSON line."""
    CUSTODY_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": _utc_now(),
        "action": action,
        "evidence": str(evidence_path),
        "sha256": sha256,
        "analyst": getpass.getuser(),
        "host": socket.gethostname(),
        "note": note,
    }
    with CUSTODY_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def load_email(path: str | Path) -> EmailEvidence:
    """Acquire an .eml file as evidence: hash it, log it, parse it."""
    path = Path(path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    raw = path.read_bytes()                      # read once, never modify
    hashes = compute_hashes(raw)
    message = BytesParser(policy=policy.default).parsebytes(raw)

    evidence = EmailEvidence(
        path=path,
        size_bytes=len(raw),
        acquired_at=_utc_now(),
        message=message,
        **hashes,
    )
    log_custody("acquired", path, evidence.sha256)
    return evidence


def verify_integrity(evidence: EmailEvidence) -> bool:
    """Re-hash the file on disk and confirm it still matches the original SHA-256."""
    current = hashlib.sha256(evidence.path.read_bytes()).hexdigest()
    intact = current == evidence.sha256
    log_custody("verified" if intact else "INTEGRITY_FAILURE",
                evidence.path, current,
                note="" if intact else f"expected {evidence.sha256}")
    return intact


def raw_header_values(message: EmailMessage, name: str) -> list:
    """All raw (unparsed) values of a header. Never fails on malformed headers."""
    return [str(v) for k, v in message.raw_items() if k.lower() == name.lower()]


def safe_header(message: EmailMessage, name: str) -> str:
    """Read a header without crashing on malformed values (common in phishing)."""
    try:
        value = message.get(name)
        return str(value) if value is not None else "-"
    except Exception:
        raw = raw_header_values(message, name)
        return " ".join(raw[0].split()) if raw else "-"


def count_attachments(message: EmailMessage) -> int:
    """Count parts that are attachments (counted only, never opened)."""
    try:
        return sum(1 for _ in message.iter_attachments())
    except Exception:
        try:
            return sum(1 for part in message.walk()
                       if part.get_content_disposition() == "attachment")
        except Exception:
            return 0


def summarize(evidence: EmailEvidence) -> str:
    """Human-readable evidence summary."""
    m = evidence.message
    lines = [
        "=" * 60,
        "FORENSIGHT - Evidence Summary",
        "=" * 60,
        f"File        : {evidence.path.name}",
        f"Size        : {evidence.size_bytes} bytes",
        f"Acquired    : {evidence.acquired_at}",
        f"MD5         : {evidence.md5}",
        f"SHA-1       : {evidence.sha1}",
        f"SHA-256     : {evidence.sha256}",
        "-" * 60,
        f"From        : {safe_header(m, 'From')}",
        f"To          : {safe_header(m, 'To')}",
        f"Subject     : {safe_header(m, 'Subject')}",
        f"Date        : {safe_header(m, 'Date')}",
        f"Message-ID  : {safe_header(m, 'Message-ID')}",
        f"Return-Path : {safe_header(m, 'Return-Path')}",
        f"Reply-To    : {safe_header(m, 'Reply-To')}",
        f"Attachments : {count_attachments(m)}",
        "=" * 60,
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m forensight.ingest <path/to/email.eml>")
        sys.exit(1)

    ev = load_email(sys.argv[1])
    print(summarize(ev))
    status = "INTACT" if verify_integrity(ev) else "MODIFIED!"
    print(f"Integrity check: {status}")
    print(f"Custody log    : {CUSTODY_LOG}")
