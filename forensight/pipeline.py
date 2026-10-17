"""Shared analysis pipeline: runs every Forensight module on one email and collects all findings.

Used by the scoring, clustering and rule-generation modules (and later by the dashboard and API),
so that every part of the tool analyses an email in exactly the same way.
"""

import dataclasses
import enum
import inspect
import traceback
from datetime import datetime
from email.message import Message

from forensight import attachments, auth, headers, ingest, lookalike, urls

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

ANALYZERS = [
    ("Headers", headers.analyze_headers),
    ("Authentication", auth.analyze_auth),
    ("Domains", lookalike.analyze_lookalikes),
    ("Links & QR", urls.analyze_urls),
    ("Attachments", attachments.analyze_attachments),
]


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
                "section": section,
                "severity": normalize_severity(data["severity"]),
                "title": str(data["title"]),
                "detail": str(data.get("detail", "")),
                "context": context,
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


def run_analyzer(func, evidence, **options):
    """Call an analysis function with the evidence object, or with the parsed message if needed."""
    accepted = inspect.signature(func).parameters
    kwargs = {name: value for name, value in options.items() if name in accepted}
    try:
        return func(evidence, **kwargs)
    except (AttributeError, TypeError, KeyError):
        message = getattr(evidence, "message", None)
        if message is None:
            raise
        return func(message, **kwargs)


def analyze_email(path, live=False, evidence=None, ai=False):
    """Run every module on one email.

    With ai=True the social-engineering module (local language model) is also run.
    Returns a dict with the evidence object, the plain results of each module,
    the list of findings (sorted by severity) and any module errors.
    """
    if evidence is None:
        evidence = ingest.load_email(path)
    analyzers = list(ANALYZERS)
    if ai:
        from forensight import social
        analyzers.append(("AI analysis", social.analyze_social))
    results, errors = {}, {}
    for section, func in analyzers:
        try:
            results[section] = to_plain(run_analyzer(func, evidence, live=live))
        except Exception:
            results[section] = None
            errors[section] = traceback.format_exc()
    findings = []
    for section, data in results.items():
        if data is not None:
            findings.extend(collect_findings(data, section))
    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return {"evidence": evidence, "results": results, "findings": findings, "errors": errors}
