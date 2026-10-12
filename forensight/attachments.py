"""
Forensight - Attachment forensics module.

Analyzes every attachment WITHOUT opening or executing it. All work is done in
memory on the raw bytes; nothing is written to disk.
  1. Hashes (MD5, SHA-1, SHA-256) for threat-intelligence lookups.
  2. True file type from "magic bytes", compared with the file extension.
  3. Dangerous and double extensions, and the right-to-left override trick.
  4. Office documents: VBA macros and suspicious macro keywords (oletools).
  5. PDF documents: JavaScript, automatic actions, launch actions, embedded
     files, and links (the links are analyzed by the URL module).
  6. HTML and SVG attachments: local phishing pages and HTML smuggling.
  7. Archives: listing of contents and password protection, without extracting.
  8. Calendar invites and Apple configuration profiles.
"""

import hashlib
import io
import re
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from oletools.olevba import VBA_Parser

from forensight.headers import Finding
from forensight.ingest import EmailEvidence, load_email
from forensight.urls import Link, analyze_link

# File signatures ("magic bytes"): the first bytes identify the real file type.
SIGNATURES = [
    (b"%PDF", "pdf"),
    (b"MZ", "exe"),
    (b"\x7fELF", "elf"),
    (b"PK\x03\x04", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),     # old Office (.doc, .xls), .msg
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"MSCF", "cab"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF8", "gif"),
    (b"RIFF", "riff"),                                 # webp, wav, avi
    (b"{\\rtf", "rtf"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),          # Windows shortcut
    (b"BEGIN:VCALENDAR", "ics"),
]
# Extensions that are expected for each detected type.
EXPECTED_EXT = {
    "pdf": {"pdf"}, "exe": {"exe", "dll", "scr", "com", "cpl", "sys"}, "elf": {""},
    "zip": {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "jar", "apk", "odt", "ods"},
    "ole": {"doc", "xls", "ppt", "msg", "msi", "dot", "xlt"}, "rar": {"rar"}, "7z": {"7z"},
    "gzip": {"gz", "tgz"}, "cab": {"cab"}, "png": {"png"}, "jpg": {"jpg", "jpeg", "jfif"},
    "gif": {"gif"}, "riff": {"webp", "wav", "avi"}, "rtf": {"rtf", "doc"}, "lnk": {"lnk"},
    "ics": {"ics"}, "html": {"html", "htm", "shtml", "xhtml"}, "svg": {"svg"},
    "xml": {"xml", "svg", "plist"}, "mobileconfig": {"mobileconfig"},
    "pkcs7": {"p7s", "p7m", "p7b", "p7c"}, "iso": {"iso", "img"},
}
EXECUTABLE_EXT = {"exe", "scr", "com", "bat", "cmd", "pif", "cpl", "dll", "msi", "ps1", "vbs",
                  "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "jar", "reg", "chm", "apk"}
DISK_IMAGE_EXT = {"iso", "img", "vhd", "vhdx"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam"}
RTLO = "\u202e"   # right-to-left override: reverses the text that follows it on screen

PDF_RISKS = {
    b"/JavaScript": ("high", "PDF contains JavaScript"),
    b"/JS": ("high", "PDF contains JavaScript"),
    b"/Launch": ("high", "PDF can launch programs (/Launch)"),
    b"/EmbeddedFile": ("high", "PDF contains an embedded file"),
    b"/OpenAction": ("medium", "PDF performs an action when opened (/OpenAction)"),
    b"/AA": ("medium", "PDF has automatic actions (/AA)"),
    b"/AcroForm": ("low", "PDF contains a fillable form (/AcroForm)"),
}
HTML_RISKS = [
    (r"<form", "high", "contains an HTML form (possible credential harvesting page)"),
    (r"type\s*=\s*[\"']?password", "high", "contains a password field"),
    (r"atob\s*\(|msSaveOrOpenBlob|new\s+Blob\s*\(", "high",
     "decodes or builds a file in the browser (HTML smuggling)"),
    (r"window\.location|location\.href\s*=|location\.replace", "medium", "redirects the browser"),
    (r"<script", "medium", "contains JavaScript"),
    (r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh", "medium", "redirects with a meta refresh"),
]


@dataclass
class Attachment:
    filename: str
    declared_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    true_type: str
    findings: list = field(default_factory=list)


# ---------- helpers ----------

PKCS7_SIGNED_OID = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"   # 1.2.840.113549.1.7.2


def detect_type(data: bytes) -> str:
    """Identify the real file type from its first bytes (not from its name)."""
    if not data:
        return "empty"
    if PKCS7_SIGNED_OID in data[:32]:
        # Digitally signed container; signed Apple profiles keep their settings readable inside
        return "mobileconfig" if b"PayloadType" in data else "pkcs7"
    for magic, name in SIGNATURES:
        if data.startswith(magic):
            return name
    head = data[:2048].lstrip().lower()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        return "svg"
    if head.startswith((b"<!doctype html", b"<html")) or b"<html" in head[:512]:
        return "html"
    if head.startswith(b"<?xml") or head.startswith(b"<plist"):
        return "mobileconfig" if b"PayloadType" in data else "xml"
    if data[0x8001:0x8006] == b"CD001":
        return "iso"                                   # CD/DVD disk image
    if data[:4] == b"\x00\x00\x01\x00":
        return "ico"
    return "unknown"


def _extensions(filename: str) -> list:
    name = filename.lower().strip().strip('"')
    return [e for e in name.split(".")[1:] if e]


# ---------- checks ----------

def check_name(att: Attachment) -> list:
    findings = []
    name = att.filename
    exts = _extensions(name)
    ext = exts[-1] if exts else ""
    if RTLO in name:
        shown = name.replace(RTLO, "")
        findings.append(Finding("high", "Right-to-left override in file name",
                                f"The name '{shown}' is displayed reversed to hide its real extension"))
    if ext in EXECUTABLE_EXT:
        findings.append(Finding("high", "Executable or script attachment",
                                f"'{name}' can run code on the victim's computer"))
    elif ext in DISK_IMAGE_EXT:
        findings.append(Finding("high", "Disk image attachment",
                                f"'{name}': disk images are used to bypass security warnings"))
    elif ext in MACRO_EXT:
        findings.append(Finding("medium", "Macro-enabled Office extension", f"'{name}'"))
    if ext == "mobileconfig" or att.true_type == "mobileconfig":
        hidden = "" if ext == "mobileconfig" else " (disguised: the file name does not show it)"
        findings.append(Finding("high", "Apple configuration profile",
                                f"'{name}' can install settings, certificates or VPNs on an iPhone "
                                f"or Mac{hidden}"))
    if len(exts) >= 2 and exts[-1] in EXECUTABLE_EXT and len(exts[-2]) <= 4:
        findings.append(Finding("high", "Double extension",
                                f"'{name}' pretends to be a .{exts[-2]} file but is a .{exts[-1]}"))
    if att.true_type == "empty":
        findings.append(Finding("info", "Attachment is empty",
                                "The attachment has no content (it may have been removed or sanitized)"))
    expected = EXPECTED_EXT.get(att.true_type)
    if expected is not None and ext and ext not in expected and len(ext) <= 5 \
            and att.true_type != "xml":
        sev = "high" if att.true_type in ("exe", "elf", "lnk", "ole", "zip", "rar", "7z", "html",
                                          "mobileconfig", "iso") else "medium"
        findings.append(Finding(sev, "File type does not match extension",
                                f"'{name}' is named .{ext} but its content is {att.true_type.upper()}"))
    return findings


def check_office(data: bytes, name: str) -> list:
    findings = []
    try:
        parser = VBA_Parser(name or "attachment", data=data)
        if parser.detect_vba_macros():
            keywords = sorted({kw for kind, kw, _ in parser.analyze_macros()
                               if kind in ("AutoExec", "Suspicious")})[:8]
            findings.append(Finding("high", "Office document contains VBA macros",
                                    "Suspicious keywords: " + (", ".join(keywords) or "none detected")))
        parser.close()
    except Exception:
        pass
    return findings


def check_pdf(data: bytes) -> tuple:
    """Return (findings, links found in the PDF)."""
    findings, seen = [], set()
    for marker, (severity, title) in PDF_RISKS.items():
        if re.search(re.escape(marker) + rb"[\s/<(\[]", data) and title not in seen:
            seen.add(title)
            findings.append(Finding(severity, title, "Found in the raw PDF structure"))
    uris = {u.decode("latin-1") for u in re.findall(rb"/URI\s*\((https?://[^)\s]+)\)", data)}
    return findings, sorted(uris)


def check_html(data: bytes, kind: str) -> list:
    text = data[:2_000_000].decode("utf-8", errors="replace").lower()
    findings = []
    for pattern, severity, description in HTML_RISKS:
        if re.search(pattern, text):
            findings.append(Finding(severity, f"{kind.upper()} attachment {description.split(' (')[0]}",
                                    f"The attachment {description}"))
    return findings


def check_archive(data: bytes) -> list:
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if any(i.flag_bits & 0x1 for i in infos):
                findings.append(Finding("medium", "Password-protected archive",
                                        "Encrypted archives cannot be scanned by email security tools"))
            risky = [i.filename for i in infos
                     if (_extensions(i.filename) or [""])[-1] in EXECUTABLE_EXT | DISK_IMAGE_EXT]
            if risky:
                findings.append(Finding("high", "Archive contains executable files",
                                        ", ".join(risky[:5])))
    except Exception:
        pass
    return findings


def check_calendar(data: bytes) -> tuple:
    text = data.decode("utf-8", errors="replace")
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>\\]+", text)))
    findings = []
    if urls:
        findings.append(Finding("medium", "Calendar invite contains links",
                                "Calendar invites can add phishing links directly to the victim's calendar"))
    return findings, urls


# ---------- main entry ----------

def iter_attachments(evidence: EmailEvidence):
    for part in evidence.message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename and part.get_content_disposition() != "attachment":
            continue
        data = part.get_payload(decode=True) or b""
        yield filename or "(no name)", part.get_content_type(), data


def analyze_attachments(evidence: EmailEvidence) -> list:
    results = []
    for filename, declared, data in iter_attachments(evidence):
        att = Attachment(
            filename=filename, declared_type=declared, size=len(data),
            md5=hashlib.md5(data).hexdigest(), sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(), true_type=detect_type(data),
        )
        att.findings = check_name(att)
        links = []
        if att.true_type in ("ole", "zip"):
            att.findings += check_office(data, filename)
        if att.true_type == "zip":
            att.findings += check_archive(data)
        if att.true_type == "pdf":
            pdf_findings, links = check_pdf(data)
            att.findings += pdf_findings
        if att.true_type in ("html", "svg"):
            att.findings += check_html(data, att.true_type)
        if att.true_type == "ics":
            cal_findings, links = check_calendar(data)
            att.findings += cal_findings
        for url in links[:50]:
            for f in analyze_link(Link(url, f"Link in {att.true_type.upper()} attachment")):
                att.findings.append(f)
        results.append(att)
    return results


def format_report(attachments: list) -> str:
    out = ["=" * 60, "FORENSIGHT - Attachment Forensics", "=" * 60,
           f"Attachments: {len(attachments)} (analyzed in memory, never opened or executed)"]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for i, att in enumerate(attachments, start=1):
        out += ["-" * 60,
                f"[{i}] {att.filename}",
                f"    Declared type : {att.declared_type}",
                f"    Real type     : {att.true_type.upper()}   Size: {att.size} bytes",
                f"    SHA-256       : {att.sha256}",
                f"    MD5           : {att.md5}"]
        if not att.findings:
            out.append("    No suspicious indicators found.")
        for f in sorted(att.findings, key=lambda x: order[x.severity]):
            out.append(f"    [{f.severity.upper():6}] {f.title}")
            out.append(f"              {f.detail[:110]}")
    out.append("=" * 60)
    return "\n".join(out)


def dataset_statistics(folder: str) -> None:
    files = sorted(Path(folder).expanduser().glob("*.eml"))
    types, titles = Counter(), Counter()
    total = emails_with = flagged = failed = 0
    for path in files:
        try:
            atts = analyze_attachments(load_email(path))
        except Exception:
            failed += 1
            continue
        total += len(atts)
        emails_with += bool(atts)
        types.update(a.true_type for a in atts)
        hits = {f.title for a in atts for f in a.findings}
        flagged += bool({f.severity for a in atts for f in a.findings} & {"high", "medium"})
        titles.update(hits)
    print("=" * 60)
    print("FORENSIGHT - Attachment Statistics")
    print("=" * 60)
    print(f"Emails analyzed: {len(files)} | failed: {failed}")
    print(f"Emails with attachments: {emails_with} | total attachments: {total}")
    print(f"Emails with medium/high attachment findings: {flagged}")
    print("-" * 60)
    print("Real file types (from magic bytes):")
    for name, n in types.most_common(12):
        print(f"  {name.upper():<40}{n:>6}")
    print("-" * 60)
    print("Emails per finding type:")
    for name, n in titles.most_common(15):
        print(f"  {name[:40]:<40}{n:>6}")
    print("=" * 60)


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "--stats":
        dataset_statistics(args[1])
    elif len(args) == 1:
        print(format_report(analyze_attachments(load_email(args[0]))))
    else:
        print("Usage: python -m forensight.attachments <email.eml>")
        print("       python -m forensight.attachments --stats <folder>")
        sys.exit(1)
