"""Forensight dashboard: a local web interface that runs every analysis module on one email.

Run from the project root:
    streamlit run dashboard.py

The email is only parsed and analysed statically. It is never opened in a mail client,
its links are never visited and its attachments are never executed.
"""

import dataclasses
import enum
import hashlib
import inspect
import json
import re
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path

import pandas as pd
import streamlit as st

from forensight import attachments, auth, headers, ingest, lookalike, urls

PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "output"
UPLOAD_DIR = OUTPUT_DIR / "uploads"
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}


# ---------------------------------------------------------------------------
# Helpers that turn module results into plain data
# ---------------------------------------------------------------------------

def to_plain(obj):
    """Convert dataclasses, paths, enums and email objects into JSON-friendly data."""
    if isinstance(obj, Message):
        return "<email message object>"
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_plain(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, dict):
        return {str(key): to_plain(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_plain(item) for item in obj]
    if isinstance(obj, enum.Enum):
        return to_plain(obj.value)
    if isinstance(obj, bytes):
        return f"<{len(obj)} bytes>"
    if isinstance(obj, datetime):
        return obj.isoformat()
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)


def normalize_severity(value):
    """Map any severity representation (string, enum, 'Severity.HIGH') to a lowercase word."""
    text = str(value).lower().split(".")[-1].strip()
    return text if text in SEVERITY_ORDER else "info"


def collect_findings(data, section, context=""):
    """Walk plain data and return every finding (a dict with 'severity' and 'title')."""
    found = []
    if isinstance(data, dict):
        if "severity" in data and "title" in data:
            found.append({
                "Section": section,
                "Severity": normalize_severity(data["severity"]),
                "Title": str(data["title"]),
                "Detail": str(data.get("detail", "")),
                "Context": context,
            })
            return found
        label = data.get("url") or data.get("filename") or data.get("domain") or context
        for key, value in data.items():
            child_context = label or (key if key != "findings" else context)
            found.extend(collect_findings(value, section, str(child_context)))
    elif isinstance(data, list):
        for item in data:
            found.extend(collect_findings(item, section, context))
    return found


def scalar_table(rows):
    """Build a table from a list of dicts, keeping only simple (non-nested) columns."""
    cleaned = []
    for row in rows:
        if isinstance(row, dict):
            cleaned.append({k: v for k, v in row.items()
                            if isinstance(v, (str, int, float, bool)) or v is None})
    cleaned = [row for row in cleaned if row]
    return pd.DataFrame(cleaned).astype(str) if cleaned else None


def run_analyzer(func, evidence, **options):
    """Call an analysis function with the evidence object, or with the parsed message if needed.

    Only options that the function actually accepts are passed (for example live=False).
    """
    accepted = inspect.signature(func).parameters
    kwargs = {name: value for name, value in options.items() if name in accepted}
    try:
        return func(evidence, **kwargs)
    except (AttributeError, TypeError, KeyError):
        message = getattr(evidence, "message", None)
        if message is None:
            raise
        return func(message, **kwargs)


def header_value(message, name):
    """Read a header safely: malformed headers fall back to their raw text."""
    try:
        return str(ingest.safe_header(message, name) or "")
    except Exception:
        try:
            return str(message.get(name, "") or "")
        except Exception:
            return "<unreadable header>"


def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Analysis pipeline
# ---------------------------------------------------------------------------

ANALYZERS = [
    ("Headers", headers.analyze_headers),
    ("Authentication", auth.analyze_auth),
    ("Domains", lookalike.analyze_lookalikes),
    ("Links & QR", urls.analyze_urls),
    ("Attachments", attachments.analyze_attachments),
]


def analyze_email(path, live):
    """Run every module on one email and return evidence, plain results, findings and errors."""
    evidence = ingest.load_email(path)
    results, errors = {}, {}
    for section, func in ANALYZERS:
        try:
            results[section] = to_plain(run_analyzer(func, evidence, live=live))
        except Exception:
            results[section] = None
            errors[section] = traceback.format_exc()
    findings = []
    for section, data in results.items():
        if data is not None:
            findings.extend(collect_findings(data, section))
    findings.sort(key=lambda f: SEVERITY_ORDER[f["Severity"]])
    return evidence, results, findings, errors


def build_route_map(path):
    """Run the route map module as a separate process and return (terminal text, html or None)."""
    completed = subprocess.run(
        [sys.executable, "-m", "forensight.routemap", str(path)],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=120,
    )
    text = (completed.stdout + completed.stderr).strip()
    html_file = OUTPUT_DIR / f"route_{Path(path).stem}.html"
    match = re.search(r"saved to:\s*(\S+\.html)", completed.stdout)
    if match:
        candidate = Path(match.group(1))
        html_file = candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
    html = html_file.read_text(encoding="utf-8") if completed.returncode == 0 and html_file.exists() else None
    return text, html


# ---------------------------------------------------------------------------
# Page layout
# ---------------------------------------------------------------------------

st.set_page_config(page_title="Forensight", page_icon="🔎", layout="wide")
st.title("🔎 Forensight")
st.caption("Automated phishing email forensics: static analysis only. "
           "Emails are never opened in a mail client, links are never visited, attachments are never executed.")

with st.sidebar:
    st.header("Evidence")
    source = st.radio("Email source", ["Upload .eml file", "Path on this machine"])
    email_path = None
    if source == "Upload .eml file":
        uploaded = st.file_uploader("Choose an .eml file", type=["eml"])
        if uploaded is not None:
            data = uploaded.getvalue()
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", uploaded.name)
            email_path = UPLOAD_DIR / f"{sha256_of(data)[:12]}_{safe_name}"
            if not email_path.exists():
                email_path.write_bytes(data)
    else:
        typed = st.text_input("Full path to an .eml file",
                              placeholder=str(Path.home() / "samples/phishing_pot/email/sample-1000.eml"))
        if typed:
            candidate = Path(typed.strip()).expanduser()
            if candidate.is_file():
                email_path = candidate
            else:
                st.error("File not found.")

    st.header("Options")
    live = st.toggle("Live DNS checks (SPF/DKIM/DMARC)", value=False,
                     help="Off = offline mode: only the results recorded in the headers are used, "
                          "and nothing is sent over the network.")
    show_map = st.toggle("Build route map", value=True)

if email_path is None:
    st.info("Upload an email or enter a path in the sidebar to start the analysis.")
    st.stop()

cache_key = (str(email_path), live)
if st.session_state.get("cache_key") != cache_key:
    with st.spinner("Analysing email..."):
        st.session_state["analysis"] = analyze_email(email_path, live)
        st.session_state["route"] = None
        st.session_state["cache_key"] = cache_key

evidence, results, findings, errors = st.session_state["analysis"]
evidence_plain = to_plain(evidence)

tabs = st.tabs(["Overview", "Headers", "Authentication", "Domains",
                "Links & QR", "Attachments", "Route Map", "Export"])

# --- Overview -------------------------------------------------------------
with tabs[0]:
    counts = {level: sum(1 for f in findings if f["Severity"] == level) for level in SEVERITY_ORDER}
    columns = st.columns(4)
    for column, level in zip(columns, SEVERITY_ORDER):
        column.metric(f"{SEVERITY_ICON[level]} {level.capitalize()}", counts[level])

    st.subheader("Evidence integrity")
    integrity = {k: v for k, v in evidence_plain.items()
                 if isinstance(v, (str, int, float)) and v != "<email message object>"}
    st.table(pd.DataFrame(integrity.items(), columns=["Field", "Value"]).astype(str))

    message = getattr(evidence, "message", None)
    if message is not None:
        st.subheader("Email summary")
        summary = {name: header_value(message, name)
                   for name in ["From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID"]}
        st.table(pd.DataFrame(summary.items(), columns=["Header", "Value"]))

    if findings:
        st.subheader("Findings by module")
        per_section = pd.DataFrame(findings).groupby("Section").size().rename("Findings")
        st.bar_chart(per_section)
        st.subheader("All findings")
        st.dataframe(pd.DataFrame(findings), width="stretch", hide_index=True)
    else:
        st.success("No findings were raised for this email.")

    for section, error in errors.items():
        st.error(f"{section} module failed for this email.")
        with st.expander(f"Error details: {section}"):
            st.code(error)


# --- One tab per analysis module -------------------------------------------
def render_section(section):
    data = results.get(section)
    if section in errors:
        st.error(f"The {section} module failed for this email.")
        st.code(errors[section])
        return
    section_findings = [f for f in findings if f["Section"] == section]
    if section_findings:
        st.dataframe(pd.DataFrame(section_findings).drop(columns="Section"),
                     width="stretch", hide_index=True)
    else:
        st.success("No findings in this module.")

    if isinstance(data, list):
        table = scalar_table(data)
        if table is not None:
            st.subheader("Items")
            st.dataframe(table, width="stretch", hide_index=True)
        elif not data:
            st.caption("Nothing to analyse in this email.")
    elif isinstance(data, dict):
        simple = {k: v for k, v in data.items() if isinstance(v, (str, int, float, bool)) or v is None}
        if simple:
            st.table(pd.DataFrame(simple.items(), columns=["Field", "Value"]).astype(str))
        for key, value in data.items():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                table = scalar_table(value)
                if table is not None and key != "findings":
                    st.subheader(key.replace("_", " ").capitalize())
                    st.dataframe(table, width="stretch", hide_index=True)
            elif isinstance(value, dict) and value and key != "findings":
                inner = {k: v for k, v in value.items() if not isinstance(v, (list, dict))}
                if inner:
                    st.subheader(key.replace("_", " ").capitalize())
                    st.table(pd.DataFrame(inner.items(), columns=["Field", "Value"]).astype(str))

    with st.expander("Raw module output (JSON)"):
        st.json(data if data is not None else {})


for index, section in enumerate(["Headers", "Authentication", "Domains", "Links & QR", "Attachments"], start=1):
    with tabs[index]:
        if section == "Authentication":
            st.caption("Mode: " + ("live DNS verification" if live else "offline (recorded results only)"))
        render_section(section)

# --- Route map ------------------------------------------------------------
with tabs[6]:
    if not show_map:
        st.info("Route map is turned off in the sidebar.")
    else:
        if st.session_state.get("route") is None:
            with st.spinner("Geolocating hops (offline GeoIP)..."):
                try:
                    st.session_state["route"] = build_route_map(email_path)
                except Exception:
                    st.session_state["route"] = (traceback.format_exc(), None)
        text, html = st.session_state["route"]
        st.code(text or "(no output)")
        if html:
            # The map HTML is generated locally by our own routemap module (not taken from the email).
            st.iframe(html, height=550)
        else:
            st.warning("No map was produced for this email.")

# --- Export ---------------------------------------------------------------
with tabs[7]:
    report = {
        "tool": "Forensight",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "evidence": evidence_plain,
        "live_dns": live,
        "summary": {level: sum(1 for f in findings if f["Severity"] == level) for level in SEVERITY_ORDER},
        "findings": findings,
        "modules": results,
        "errors": {section: error.strip().splitlines()[-1] for section, error in errors.items()},
    }
    report_json = json.dumps(report, indent=2, ensure_ascii=False)
    st.download_button("Download JSON report", report_json,
                       file_name=f"forensight_{Path(email_path).stem}.json", mime="application/json")
    st.json(report, expanded=False)
