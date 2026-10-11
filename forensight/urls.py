"""
Forensight - URL and QR-code forensics module.

Extracts every link from an email WITHOUT visiting it, including links hidden
inside QR-code images ("quishing"), and analyzes each one statically:
  - deceptive links (the visible text shows one domain, the real link another)
  - links that use an IP address instead of a domain name
  - the "@" trick (http://paypal.com@evil.com goes to evil.com)
  - URL shorteners that hide the real destination
  - free hosting platforms commonly abused for phishing pages
  - lookalike domains (reusing the engine of the lookalike module)
  - HTML forms embedded in the email (credential harvesting)
  - javascript: and data: links
"""

import ipaddress
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import cv2
import numpy as np

from forensight.headers import Finding
from forensight.ingest import EmailEvidence, load_email
from forensight.lookalike import check_domain, split_domain

URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]{}]+", re.IGNORECASE)
DOMAIN_IN_TEXT_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly",
    "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "buff.ly", "bl.ink", "short.io",
    "page.link", "geni.us", "cutt.us",
}
FREE_HOSTING = {
    "firebaseapp.com", "web.app", "github.io", "wixsite.com", "weebly.com", "blogspot.com",
    "glitch.me", "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app",
    "herokuapp.com", "000webhostapp.com", "ngrok.io", "ngrok-free.app", "sites.google.com",
    "forms.gle", "docs.google.com", "storage.googleapis.com", "ipfs.io", "dweb.link",
    "sharepoint.com", "1drv.ms", "dropboxusercontent.com", "translate.goog", "run.app",
}
CREDENTIAL_WORDS = ("login", "signin", "sign-in", "verify", "account", "password",
                    "secure", "update", "wallet", "confirm", "unlock", "billing")


@dataclass
class Link:
    url: str
    source: str            # "HTML link", "Plain text", "QR code", "HTML form", ...
    text: str = ""         # visible text of an HTML link


# ---------- 1. extraction ----------

class _HTMLLinkParser(HTMLParser):
    """Collects <a href> links with their visible text, and <form action> targets."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms = [], []
        self._href, self._text = None, []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self._href, self._text = attrs["href"].strip(), []
        elif tag == "form":
            self.forms.append(attrs.get("action") or "(no action)")

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split())))
            self._href = None


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def decode_qr_codes(image_bytes: bytes) -> list:
    """Return the text of every QR code found in an image (empty list if none)."""
    if not image_bytes:
        return []
    try:
        image = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            return []                      # not a readable image
        ok, texts, _, _ = cv2.QRCodeDetector().detectAndDecodeMulti(image)
        return [t for t in texts if t] if ok else []
    except Exception:
        return []                          # corrupted or unsupported image


def extract_links(evidence: EmailEvidence) -> tuple:
    """Return (links, number of images scanned for QR codes). Links are never visited."""
    links, images = [], 0
    seen = set()

    def add(url, source, text=""):
        key = (url, source, text)
        if url and key not in seen:
            seen.add(key)
            links.append(Link(url, source, text))

    for part in evidence.message.walk():
        ctype = part.get_content_type()
        if part.is_multipart():
            continue
        if ctype == "text/html":
            parser = _HTMLLinkParser()
            try:
                parser.feed(_part_text(part))
            except Exception:
                pass
            for href, text in parser.links:
                add(href, "HTML link", text)
            for action in parser.forms:
                add(action, "HTML form")
        elif ctype == "text/plain":
            for url in URL_RE.findall(_part_text(part)):
                add(url.rstrip(".,;:!?"), "Plain text")
        elif ctype.startswith("image/"):
            images += 1
            data = part.get_payload(decode=True) or b""
            for text in decode_qr_codes(data):
                add(text.strip(), "QR code")
    return links, images


# ---------- 2. analysis ----------

def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_link(link: Link) -> list:
    """Static checks on one link. Returns a list of Findings."""
    findings = []
    url, lower = link.url, link.url.lower()
    where = f"[{link.source}] {url[:120]}"

    if lower.startswith(("javascript:", "data:")):
        return [Finding("high", "Script or data link", where)]
    if link.source == "HTML form":
        findings.append(Finding("high", "HTML form embedded in email",
                                f"Forms can collect credentials directly from the email. Action: {url[:120]}"))
    if not lower.startswith(("http://", "https://")):
        return findings

    host = _host(url)
    if not host:
        return findings
    registered = split_domain(host)[2]

    if link.source == "QR code":
        findings.append(Finding("medium", "URL hidden in a QR code (quishing)",
                                f"Email filters usually cannot read links inside images: {url[:120]}"))

    # Deceptive link: visible text names one domain, the link goes to another
    if link.text:
        shown = DOMAIN_IN_TEXT_RE.search(link.text.lower())
        if shown and "." in shown.group(1):
            shown_registered = split_domain(shown.group(1))[2]
            if shown_registered and "." in shown_registered and shown_registered != registered:
                findings.append(Finding("high", "Deceptive link text",
                                        f"Text shows '{shown.group(1)}' but the link goes to '{host}'"))

    authority = urlsplit(url).netloc
    if "@" in authority:
        findings.append(Finding("high", "'@' trick in URL",
                                f"Everything before '@' is ignored by the browser; the real host is '{host}'"))
    if _is_ip(host):
        findings.append(Finding("medium", "Link uses an IP address", where))
    if registered in SHORTENERS:
        findings.append(Finding("medium", "URL shortener hides the destination", where))
    if registered in FREE_HOSTING or any(host.endswith("." + d) or host == d for d in FREE_HOSTING):
        findings.append(Finding("medium", "Link to a free hosting platform",
                                f"Platforms like this are often abused to host phishing pages: {host}"))
    for technique, brand, severity, detail in check_domain(host):
        findings.append(Finding(severity, f"Lookalike link domain: {technique} ({brand})", detail))
    path = urlsplit(lower).path + "?" + urlsplit(lower).query
    words = [w for w in CREDENTIAL_WORDS if w in path]
    if words and findings:
        findings.append(Finding("low", "Credential-related words in link",
                                f"{', '.join(words)} in {url[:100]}"))
    return findings


def analyze_urls(evidence: EmailEvidence) -> tuple:
    """Return (links, images scanned, findings)."""
    links, images = extract_links(evidence)
    findings, seen = [], set()
    for link in links:
        for f in analyze_link(link):
            if (f.title, f.detail) not in seen:          # same link repeated in the email
                seen.add((f.title, f.detail))
                findings.append(f)
    return links, images, findings


# ---------- output ----------

def format_report(links: list, images: int, findings: list) -> str:
    hosts = Counter(_host(l.url) for l in links if _host(l.url))
    out = ["=" * 60, "FORENSIGHT - URL & QR Forensics", "=" * 60,
           f"Links found: {len(links)} | unique hosts: {len(hosts)} | images scanned for QR: {images}",
           "Links (never visited):"]
    for link in links[:15]:
        text = f"  text: '{link.text[:40]}'" if link.text else ""
        out.append(f"  [{link.source}] {link.url[:90]}{text}")
    if len(links) > 15:
        out.append(f"  ... and {len(links) - 15} more")
    out.append("-" * 60)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    if not findings:
        out.append("No suspicious links found.")
    for f in sorted(findings, key=lambda x: order[x.severity]):
        out.append(f"[{f.severity.upper():6}] {f.title}")
        out.append(f"          {f.detail}")
    out.append("=" * 60)
    return "\n".join(out)


def dataset_statistics(folder: str) -> None:
    """Count links, QR codes and link findings across a folder of emails."""
    files = sorted(Path(folder).expanduser().glob("*.eml"))
    titles, sources, hosts = Counter(), Counter(), Counter()
    total_links = emails_with_links = emails_flagged = images = failed = 0
    start = time.time()
    for path in files:
        try:
            links, imgs, findings = analyze_urls(load_email(path))
        except Exception:
            failed += 1
            continue
        images += imgs
        total_links += len(links)
        emails_with_links += bool(links)
        emails_flagged += bool([f for f in findings if f.severity in ("high", "medium")])
        sources.update(l.source for l in links)
        hosts.update({split_domain(_host(l.url))[2] for l in links if _host(l.url)})
        titles.update({f.title.split(":")[0] for f in findings})
    print("=" * 60)
    print("FORENSIGHT - URL & QR Statistics")
    print("=" * 60)
    print(f"Emails analyzed: {len(files)} | failed: {failed} | time: {time.time() - start:.1f} s")
    print(f"Emails with links: {emails_with_links} | total links: {total_links}")
    print(f"Images scanned for QR codes: {images}")
    print(f"Emails with medium/high link findings: {emails_flagged}")
    print("-" * 60)
    print("Links by source:")
    for name, n in sources.most_common():
        print(f"  {name:<36}{n:>7}")
    print("-" * 60)
    print("Emails per finding type:")
    for name, n in titles.most_common():
        print(f"  {name:<36}{n:>7}")
    print("-" * 60)
    print("Top 10 linked domains (by number of emails):")
    for name, n in hosts.most_common(10):
        print(f"  {name:<36}{n:>7}")
    print("=" * 60)


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "--stats":
        dataset_statistics(args[1])
    elif len(args) == 1:
        print(format_report(*analyze_urls(load_email(args[0]))))
    else:
        print("Usage: python -m forensight.urls <email.eml>")
        print("       python -m forensight.urls --stats <folder>")
        sys.exit(1)
