"""
Forensight - Email authentication verification module.

Examines SPF, DKIM and DMARC from three angles:
  1. Recorded results: what the recipient's own mail server concluded at
     delivery time (Authentication-Results and Received-SPF headers).
  2. Independent re-verification: Forensight repeats the SPF, DKIM and DMARC
     checks itself using live DNS, instead of trusting what is written.
  3. Alignment: whether the authenticated domains match the From domain the
     victim actually sees, and whether a brand is impersonated even though
     authentication passed.
"""

import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from email.utils import parseaddr
from pathlib import Path

import dkim
import dns.resolver
import spf

from forensight.headers import Finding, _base_domain, _domain, parse_received, _is_public
from forensight.ingest import EmailEvidence, load_email, raw_header_values, safe_header

DNS_TIMEOUT = 5  # seconds per DNS lookup


@dataclass
class AuthReport:
    recorded: dict                 # results written by the recipient's server
    spf_ip: str | None             # IP that connected to the recipient's server
    spf_helo: str | None
    mail_from: str                 # envelope sender domain (Return-Path)
    from_domain: str               # domain shown to the victim
    dkim_domains: list             # d= domains of all DKIM signatures
    verified: dict = field(default_factory=dict)   # Forensight's own results
    dmarc_policy: str | None = None
    findings: list = field(default_factory=list)


# ---------- DNS ----------

def txt_lookup(name: str) -> list:
    """Return the TXT records of a DNS name (empty list if none or on error)."""
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=DNS_TIMEOUT)
        return [b"".join(r.strings).decode(errors="replace") for r in answers]
    except Exception:
        return []


def _dkim_dns(name: bytes, timeout: int = DNS_TIMEOUT) -> bytes | None:
    """DNS function in the format expected by the dkim library."""
    records = txt_lookup(name.decode().rstrip("."))
    return records[0].encode() if records else None


# ---------- 1. recorded results ----------

def _unfold(value: str) -> str:
    return " ".join(str(value).split())


def recorded_results(evidence: EmailEvidence) -> dict:
    """Parse the TOP Authentication-Results header (written by the recipient's server)."""
    headers = raw_header_values(evidence.message, "Authentication-Results")
    if not headers:
        return {}
    text = _unfold(headers[0]).lower()
    result = {}
    for method in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{method}=(\w+)", text)
        result[method] = match.group(1) if match else "missing"
    for key, pattern in (("smtp.mailfrom", r"smtp\.mailfrom=([^\s;]+)"),
                         ("header.d", r"header\.d=([^\s;]+)"),
                         ("header.from", r"header\.from=([^\s;]+)")):
        match = re.search(pattern, text)
        result[key] = match.group(1) if match else "-"
    return result


def connecting_server(evidence: EmailEvidence) -> tuple:
    """IP and HELO name of the server that handed the email to the recipient."""
    spf_headers = raw_header_values(evidence.message, "Received-SPF")
    if spf_headers:
        text = _unfold(spf_headers[0])
        ip = re.search(r"client-ip=([0-9a-fA-F.:]+)", text)
        helo = re.search(r"helo=([^\s;]+)", text)
        if ip:
            return ip.group(1), helo.group(1) if helo else None
    # Fallback: the last public IP in the delivery path (closest to the recipient)
    for hop in reversed(parse_received(evidence)):
        for ip in hop.ips:
            if _is_public(ip):
                return ip, hop.from_host
    return None, None


def dkim_signature_domains(evidence: EmailEvidence) -> list:
    """The d= (signing domain) of every DKIM-Signature header."""
    domains = []
    for sig in raw_header_values(evidence.message, "DKIM-Signature"):
        match = re.search(r"\bd=([^;\s]+)", _unfold(sig))
        if match:
            domains.append(match.group(1).lower())
    return domains


# ---------- 2. independent re-verification (live DNS) ----------

def verify_spf(ip: str, mail_from: str, helo: str | None) -> str:
    try:
        result, _ = spf.check2(i=ip, s=f"postmaster@{mail_from}", h=helo or mail_from,
                               querytime=DNS_TIMEOUT * 2)
        return result
    except Exception as error:
        return f"error ({type(error).__name__})"


def verify_dkim(evidence: EmailEvidence) -> str:
    raw = evidence.path.read_bytes()        # read-only, evidence is not modified
    try:
        return "pass" if dkim.verify(raw, dnsfunc=_dkim_dns) else "fail"
    except Exception as error:
        return f"error ({type(error).__name__})"


def dmarc_policy(domain: str) -> str | None:
    """The p= policy of a domain's DMARC record, or None if it has no record."""
    for record in txt_lookup(f"_dmarc.{domain}"):
        if record.lower().startswith("v=dmarc1"):
            match = re.search(r"\bp=(\w+)", record, re.IGNORECASE)
            return match.group(1).lower() if match else "none"
    return None


# ---------- 3. findings ----------

def auth_findings(report: AuthReport, evidence: EmailEvidence) -> list:
    findings = []
    rec = report.recorded

    if not rec:
        findings.append(Finding("low", "No Authentication-Results header",
                                "The recipient's server did not record SPF/DKIM/DMARC results."))
    else:
        if rec["dmarc"] == "fail":
            findings.append(Finding("high", "DMARC failed at delivery",
                                    f"The sender is not authorized to use the From domain "
                                    f"'{report.from_domain}' (recorded by the recipient's server)."))
        if rec["spf"] in ("fail", "softfail"):
            findings.append(Finding("medium", f"SPF {rec['spf']} at delivery",
                                    f"Server {report.spf_ip} is not an authorized sender for "
                                    f"'{rec['smtp.mailfrom']}'."))
        if rec["dkim"] == "fail":
            findings.append(Finding("medium", "DKIM failed at delivery",
                                    "The signature did not match: the email may have been altered "
                                    "or the signature forged."))

    if not report.dkim_domains:
        findings.append(Finding("low", "Email is not DKIM-signed",
                                "No DKIM signature; the content cannot be cryptographically verified."))
    elif report.from_domain and all(_base_domain(d) != _base_domain(report.from_domain)
                                    for d in report.dkim_domains):
        findings.append(Finding("medium", "DKIM signature not aligned with From",
                                f"Signed by {', '.join(report.dkim_domains)} but From is "
                                f"'{report.from_domain}'."))

    # Brand impersonation despite authentication
    display, _ = parseaddr(safe_header(evidence.message, "From"))
    claimed = {e.rsplit("@", 1)[-1].lower()
               for e in re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", display)}
    for dom in claimed:
        if report.from_domain and _base_domain(dom) != _base_domain(report.from_domain):
            findings.append(Finding("high", "Impersonated domain is not the authenticated domain",
                                    f"Email presents itself as '{dom}' but the sending domain is "
                                    f"'{report.from_domain}'. Any SPF/DKIM/DMARC pass applies only "
                                    f"to '{report.from_domain}'."))

    if report.verified:
        if report.dmarc_policy is None:
            findings.append(Finding("low", "From domain has no DMARC record",
                                    f"'{report.from_domain}' does not protect itself against spoofing."))
        elif report.dmarc_policy == "none":
            findings.append(Finding("info", "DMARC policy is 'none'",
                                    f"'{report.from_domain}' only monitors spoofing and does not block it."))
        for method in ("spf", "dkim"):
            then, now = rec.get(method), report.verified.get(method)
            if not now:
                continue
            if then == "pass" and now != "pass":
                findings.append(Finding("info", f"{method.upper()} result changed since delivery",
                                        f"Recorded '{then}' at delivery, re-verified as '{now}' today. "
                                        "DNS records or keys may have changed since the email was sent."))
            elif then != "pass" and now in ("fail", "softfail"):
                findings.append(Finding("medium", f"{method.upper()} re-verification failed",
                                        f"Forensight's own {method.upper()} check returned '{now}'."))
    return findings


# ---------- main entry ----------

def analyze_auth(evidence: EmailEvidence, live: bool = True) -> AuthReport:
    ip, helo = connecting_server(evidence)
    rec = recorded_results(evidence)
    mail_from = _domain(safe_header(evidence.message, "Return-Path")) or rec.get("smtp.mailfrom", "-")
    report = AuthReport(
        recorded=rec,
        spf_ip=ip,
        spf_helo=helo,
        mail_from=mail_from,
        from_domain=_domain(safe_header(evidence.message, "From")),
        dkim_domains=dkim_signature_domains(evidence),
    )
    if live:
        report.verified["spf"] = verify_spf(ip, mail_from, helo) if ip and mail_from != "-" else "not checked"
        report.verified["dkim"] = verify_dkim(evidence) if report.dkim_domains else "none"
        report.dmarc_policy = dmarc_policy(report.from_domain) if report.from_domain else None
    report.findings = auth_findings(report, evidence)
    return report


def format_report(report: AuthReport) -> str:
    rec, ver = report.recorded, report.verified
    out = ["=" * 60, "FORENSIGHT - Authentication Verification", "=" * 60,
           f"From domain (shown to victim) : {report.from_domain or '-'}",
           f"Envelope sender (Return-Path): {report.mail_from}",
           f"DKIM signing domain(s)       : {', '.join(report.dkim_domains) or 'none'}",
           f"Connecting server            : {report.spf_ip or '-'} ({report.spf_helo or '-'})",
           "-" * 60,
           f"{'Check':<8}{'Recorded at delivery':<24}{'Re-verified now' if ver else ''}"]
    for method in ("spf", "dkim", "dmarc"):
        now = ver.get(method, "") if method != "dmarc" else (
            f"policy: {report.dmarc_policy}" if report.dmarc_policy else ("no record" if ver else ""))
        out.append(f"{method.upper():<8}{rec.get(method, '-'):<24}{now}")
    if not ver:
        out.append("(offline mode: live DNS re-verification skipped)")
    out.append("-" * 60)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    if not report.findings:
        out.append("No authentication issues found.")
    for f in sorted(report.findings, key=lambda x: order[x.severity]):
        out.append(f"[{f.severity.upper():6}] {f.title}")
        out.append(f"          {f.detail}")
    out.append("=" * 60)
    return "\n".join(out)


def dataset_statistics(folder: str) -> None:
    """Summarize the recorded SPF/DKIM/DMARC results across a folder of emails."""
    files = sorted(Path(folder).expanduser().glob("*.eml"))
    counts = {m: Counter() for m in ("spf", "dkim", "dmarc")}
    with_results, failed = 0, 0
    for path in files:
        try:
            rec = recorded_results(load_email(path))
        except Exception:
            failed += 1
            continue
        if rec:
            with_results += 1
            for method in counts:
                counts[method][rec[method]] += 1
    print("=" * 60)
    print("FORENSIGHT - Authentication Statistics (recorded at delivery)")
    print("=" * 60)
    print(f"Emails analyzed: {len(files)} | failed: {failed} | "
          f"with Authentication-Results: {with_results}")
    for method, counter in counts.items():
        print("-" * 60)
        print(method.upper())
        for result, n in counter.most_common():
            print(f"  {result:<15}{n:>6}  ({n / with_results * 100:5.1f}%)")
    print("=" * 60)


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "--stats":
        dataset_statistics(args[1])
    elif len(args) in (1, 2) and (len(args) == 1 or args[1] == "--offline"):
        ev = load_email(args[0])
        print(format_report(analyze_auth(ev, live=len(args) == 1)))
    else:
        print("Usage: python -m forensight.auth <email.eml> [--offline]")
        print("       python -m forensight.auth --stats <folder>")
        sys.exit(1)
