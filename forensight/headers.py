"""
Forensight - Header forensics module.

Analyzes email headers like a forensic investigator:
  1. Reconstructs the delivery path from the Received headers (hop by hop).
  2. Finds the originating IP (first public IP in the chain).
  3. Detects timeline anomalies (time travel, large delays, future dates).
  4. Checks sender identity consistency (From / Return-Path / Reply-To / Message-ID).
  5. Detects display-name spoofing (e.g. "PayPal" sent from a Gmail address).
"""

import ipaddress
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from forensight.ingest import EmailEvidence, load_email, raw_header_values, safe_header

FREE_MAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "aol.com", "icloud.com", "mail.ru", "yandex.com", "gmx.com",
    "proton.me", "protonmail.com", "zoho.com",
}

IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
IPV6_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]{3,})\]")
FROM_RE = re.compile(r"\bfrom\s+([^\s;()]+)", re.IGNORECASE)
BY_RE = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)

LARGE_DELAY_SECONDS = 3600  # 1 hour between two hops is suspicious


@dataclass
class Hop:
    """One server-to-server step in the email's delivery path."""
    index: int
    from_host: str
    by_host: str
    ips: list
    timestamp: datetime | None
    delay_seconds: float | None = None
    raw: str = field(default="", repr=False)


@dataclass
class Finding:
    """One forensic observation, with severity and the evidence behind it."""
    severity: str          # info / low / medium / high
    title: str
    detail: str


@dataclass
class HeaderReport:
    hops: list
    originating_ip: str | None
    findings: list


# ---------- helpers ----------

def _domain(address: str) -> str:
    """Return the lower-case domain part of an email address ('' if none)."""
    _, addr = parseaddr(address or "")
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _parse_date(value: str) -> datetime | None:
    try:
        dt = parsedate_to_datetime(value.strip())
        return dt if dt.tzinfo else None   # ignore dates without timezone
    except Exception:
        return None


def _base_domain(domain: str) -> str:
    """Rough registrable domain: last two labels (mail.evil.com -> evil.com)."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


# ---------- 1. delivery path ----------

def parse_received(evidence: EmailEvidence) -> list:
    """Parse Received headers into hops, oldest (sender side) first."""
    raw_headers = raw_header_values(evidence.message, "Received")
    hops = []
    # Each server ADDS a Received header on top, so the list is newest-first.
    for i, raw in enumerate(reversed(raw_headers), start=1):
        text = " ".join(str(raw).split())          # unfold multi-line headers
        stamp = text.rsplit(";", 1)[1] if ";" in text else ""
        route = text.rsplit(";", 1)[0]               # ignore the date part
        ips = [ip for ip in IPV4_RE.findall(route) if _valid_ipv4(ip)]
        ips += IPV6_RE.findall(route)
        m_from, m_by = FROM_RE.search(text), BY_RE.search(text)
        hops.append(Hop(
            index=i,
            from_host=m_from.group(1) if m_from else "-",
            by_host=m_by.group(1) if m_by else "-",
            ips=list(dict.fromkeys(ips)),            # remove duplicates, keep order
            timestamp=_parse_date(stamp) if stamp else None,
            raw=text,
        ))
    # delay between consecutive hops
    for prev, cur in zip(hops, hops[1:]):
        if prev.timestamp and cur.timestamp:
            cur.delay_seconds = (cur.timestamp - prev.timestamp).total_seconds()
    return hops


def _valid_ipv4(ip: str) -> bool:
    """Real IPv4: 4 numbers 0-255, no leading zeros (filters out dates/versions)."""
    parts = ip.split(".")
    return all(p.isdigit() and int(p) <= 255 and (p == "0" or not p.startswith("0"))
               for p in parts)


def originating_ip(hops: list, evidence: EmailEvidence) -> str | None:
    """First public IP in the path = best estimate of the sender's machine/server."""
    x_orig = safe_header(evidence.message, "X-Originating-IP").strip("[] ")
    if x_orig != "-" and _is_public(x_orig):
        return x_orig
    for hop in hops:
        for ip in hop.ips:
            if _is_public(ip):
                return ip
    return None


# ---------- 2. anomalies ----------

def timeline_findings(hops: list, evidence: EmailEvidence) -> list:
    findings = []
    if not hops:
        findings.append(Finding("medium", "No Received headers",
                                "Delivery path cannot be reconstructed; headers may be stripped or forged."))
        return findings

    for hop in hops:
        if hop.timestamp is None:
            findings.append(Finding("low", f"Hop {hop.index}: no valid timestamp",
                                    f"{hop.from_host} -> {hop.by_host}"))
        if hop.delay_seconds is not None:
            if hop.delay_seconds < -60:
                findings.append(Finding("high", f"Hop {hop.index}: time travel",
                                        f"Arrived {abs(hop.delay_seconds):.0f}s BEFORE the previous hop "
                                        "(forged header or wrong server clock)."))
            elif hop.delay_seconds > LARGE_DELAY_SECONDS:
                findings.append(Finding("low", f"Hop {hop.index}: large delay",
                                        f"{hop.delay_seconds/3600:.1f} hours between hops."))

    sent = _parse_date(safe_header(evidence.message, "Date"))
    first = hops[0].timestamp
    if sent and first and (first - sent).total_seconds() < -300:
        findings.append(Finding("medium", "Date header is after first hop",
                                f"Date: {sent.isoformat()} but first server saw it at {first.isoformat()}."))
    return findings


# ---------- 3. identity ----------

def _safe_addresses(value: str) -> list:
    try:
        return getaddresses([value])
    except Exception:
        return []


def identity_findings(evidence: EmailEvidence) -> list:
    m = evidence.message
    findings = []
    from_raw = safe_header(m, "From")
    display, from_addr = parseaddr(from_raw)
    from_dom = _domain(from_raw)

    for header in ("Return-Path", "Reply-To", "Sender"):
        value = safe_header(m, header)
        if value == "-":
            continue
        dom = _domain(value)
        if dom and from_dom and _base_domain(dom) != _base_domain(from_dom):
            sev = "high" if header == "Reply-To" else "medium"
            findings.append(Finding(sev, f"{header} domain differs from From",
                                    f"From: {from_dom}  vs  {header}: {dom}"))

    msgid = safe_header(m, "Message-ID")
    mid_dom = msgid.rsplit("@", 1)[-1].strip("> ").lower() if "@" in msgid else ""
    if mid_dom and from_dom and _base_domain(mid_dom) != _base_domain(from_dom):
        findings.append(Finding("low", "Message-ID domain differs from From",
                                f"From: {from_dom}  vs  Message-ID: {mid_dom}"))

    # Display-name spoofing
    if display:
        embedded = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", display)
        for e in embedded:
            if e.lower() != from_addr.lower():
                findings.append(Finding("high", "Email address hidden in display name",
                                        f"Display name shows '{e}' but real sender is '{from_addr}'."))
        if from_dom in FREE_MAIL and not embedded:
            findings.append(Finding("medium", "Organization-style name from free-mail address",
                                    f"Display name '{display}' but sent from free provider {from_dom}."))

    if safe_header(m, "To") == "-" or not _safe_addresses(safe_header(m, "To")):
        findings.append(Finding("low", "Missing To header", "Often seen in bulk / BCC phishing."))

    return findings


# ---------- main entry ----------

def analyze_headers(evidence: EmailEvidence) -> HeaderReport:
    hops = parse_received(evidence)
    return HeaderReport(
        hops=hops,
        originating_ip=originating_ip(hops, evidence),
        findings=timeline_findings(hops, evidence) + identity_findings(evidence),
    )


def format_report(report: HeaderReport) -> str:
    out = ["=" * 60, "FORENSIGHT - Header Forensics", "=" * 60, "Delivery path (oldest -> newest):"]
    for h in report.hops:
        when = h.timestamp.isoformat() if h.timestamp else "?"
        delay = f"  (+{h.delay_seconds:.0f}s)" if h.delay_seconds is not None else ""
        ips = ", ".join(h.ips) or "-"
        out.append(f"  [{h.index}] {h.from_host} -> {h.by_host}")
        out.append(f"       IPs: {ips} | time: {when}{delay}")
    out.append("-" * 60)
    out.append(f"Originating IP: {report.originating_ip or 'not found'}")
    out.append("-" * 60)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    if not report.findings:
        out.append("No header anomalies found.")
    for f in sorted(report.findings, key=lambda x: order[x.severity]):
        out.append(f"[{f.severity.upper():6}] {f.title}")
        out.append(f"          {f.detail}")
    out.append("=" * 60)
    return "\n".join(out)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m forensight.headers <path/to/email.eml>")
        sys.exit(1)
    ev = load_email(sys.argv[1])
    print(format_report(analyze_headers(ev)))
