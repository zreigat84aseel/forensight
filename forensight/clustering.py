"""Campaign clustering: groups phishing emails that share the same infrastructure or content.

Each email is reduced to a set of indicators (sender, Reply-To, originating IP, link domains,
attachment hashes, subject). Emails that share an indicator are linked, and every group of
linked emails is reported as one campaign, together with the indicators that connect it.

Usage:
    python -m forensight.clustering <folder> [--top N]
"""

import json
import re
import sys
import time
from collections import defaultdict
from datetime import timezone
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

import tldextract

from forensight import attachments, headers, ingest
from forensight.pipeline import run_analyzer, to_plain

OUTPUT_FILE = Path("output") / "campaigns.json"

# Strong indicators are specific to one actor (an attachment hash, a Reply-To mailbox).
# Weak indicators can be shared by unrelated senders (a mail provider's IP, a popular
# link domain), so they are ignored when they appear in too many emails.
STRONG = {"reply_to", "sender_address", "attachment"}
WEAK = {"sender_domain", "origin_ip", "link_domain", "subject"}
MAX_WEAK_EMAILS = 50
MIN_SUBJECT_LENGTH = 12
MIN_WEAK_SHARED = 2         # weak indicators two emails must share to be linked

# Public services used by many unrelated senders: never a campaign fingerprint.
GENERIC_LINK_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly",
    "ibb.co", "imgur.com", "google.com", "googleusercontent.com", "gstatic.com",
    "microsoft.com", "office.com", "apple.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "youtube.com", "w3.org", "schema.org",
}

FREE_MAIL = set(getattr(headers, "FREE_MAIL", ())) | {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
    "aol.com", "icloud.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com",
}

URL_PATTERN = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
_extract = tldextract.TLDExtract(suffix_list_urls=())


def registered_domain(host):
    parts = _extract(host)
    return f"{parts.domain}.{parts.suffix}".lower() if parts.domain and parts.suffix else ""


def _header(message, name):
    try:
        return str(message.get(name, "") or "")
    except Exception:
        return ""


RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
RESERVED_TLDS = {"example", "test", "invalid", "localhost"}


def is_reserved(domain):
    """Domains reserved for documentation and testing (RFC 2606), used as placeholders."""
    domain = domain.lower().rstrip(".")
    if domain.rsplit(".", 1)[-1] in RESERVED_TLDS:
        return True
    return any(domain == d or domain.endswith("." + d) for d in RESERVED_DOMAINS)


def _first_address(value):
    for _, address in getaddresses([value]):
        if "@" in address and not is_reserved(address.split("@")[-1]):
            return address.strip().lower()
    return ""


def _body_text(message):
    texts = []
    for part in message.walk():
        if part.get_content_maintype() == "text":
            try:
                texts.append(part.get_content())
            except Exception:
                payload = part.get_payload(decode=True) or b""
                texts.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(texts)


def normalize_subject(subject):
    """Lowercase, drop reply prefixes and numbers/random tokens so campaign variants match."""
    text = subject.lower()
    text = re.sub(r"^\s*((re|fw|fwd)\s*:\s*)+", "", text)
    text = re.sub(r"\S*\d\S*", " ", text)          # words with digits (codes, IDs, dates)
    text = re.sub(r"[^\w\s]", " ", text)
    return " ".join(text.split())


def extract_indicators(evidence):
    """Return the set of (type, value) indicators of one email and its date (or None)."""
    message = evidence.message
    indicators = set()

    sender = _first_address(_header(message, "From"))
    if sender:
        domain = sender.split("@")[-1]
        if domain in FREE_MAIL:
            indicators.add(("sender_address", sender))
        else:
            indicators.add(("sender_domain", registered_domain(domain) or domain))

    reply_to = _first_address(_header(message, "Reply-To"))
    if reply_to and reply_to != sender:
        indicators.add(("reply_to", reply_to))

    subject = normalize_subject(_header(message, "Subject"))
    if len(subject) >= MIN_SUBJECT_LENGTH:
        indicators.add(("subject", subject))

    try:
        header_result = to_plain(run_analyzer(headers.analyze_headers, evidence))
        origin = header_result.get("originating_ip") if isinstance(header_result, dict) else None
        if origin:
            indicators.add(("origin_ip", str(origin)))
    except Exception:
        pass

    for url in URL_PATTERN.findall(_body_text(message)):
        host = re.sub(r"^[^@/]*@", "", url.split("//", 1)[1]).split("/")[0].split(":")[0]
        domain = registered_domain(host)
        if domain and not is_reserved(domain) and domain not in GENERIC_LINK_DOMAINS:
            indicators.add(("link_domain", domain))

    try:
        for item in to_plain(run_analyzer(attachments.analyze_attachments, evidence)) or []:
            if isinstance(item, dict) and item.get("sha256") and str(item.get("size")) not in ("0", "None"):
                indicators.add(("attachment", item["sha256"]))
    except Exception:
        pass

    try:
        date = parsedate_to_datetime(_header(message, "Date"))
    except Exception:
        date = None
    if date is not None and date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)   # no time zone in header: assume UTC
    return indicators, date


def cluster(email_indicators, max_weak=MAX_WEAK_EMAILS, max_strong=None,
            min_weak_shared=MIN_WEAK_SHARED):
    """Group emails that share indicators.

    Two emails are linked if they share one strong indicator, or at least
    `min_weak_shared` different weak indicators. Requiring several weak indicators
    stops one generic value (a link shortener, a popular subject) from chaining
    unrelated campaigns together.

    email_indicators: {email name: set of (type, value)}
    Returns (list of campaigns as sets of email names, set of ignored indicators).
    """
    owners = defaultdict(set)
    for name, indicators in email_indicators.items():
        for indicator in indicators:
            owners[indicator].add(name)

    parent = {name: name for name in email_indicators}

    def find(name):
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    def union(a, b):
        parent[find(a)] = find(b)

    ignored = set()
    weak_pairs = defaultdict(int)
    for indicator, names in owners.items():
        if len(names) < 2:
            continue
        kind = indicator[0]
        if kind in WEAK:
            if len(names) > max_weak:
                ignored.add(indicator)
                continue
            members = sorted(names)
            for i, first in enumerate(members):
                for second in members[i + 1:]:
                    weak_pairs[(first, second)] += 1
        else:
            if max_strong is not None and len(names) > max_strong:
                ignored.add(indicator)
                continue
            first, *rest = sorted(names)
            for other in rest:
                union(other, first)

    for (first, second), shared in weak_pairs.items():
        if shared >= min_weak_shared:
            union(first, second)

    groups = defaultdict(set)
    for name in email_indicators:
        groups[find(name)].add(name)
    campaigns = [members for members in groups.values() if len(members) > 1]
    campaigns.sort(key=lambda members: (-len(members), sorted(members)[0]))
    return campaigns, ignored


def shared_indicators(members, email_indicators, ignored):
    """Indicators used by at least two emails of a campaign, most common first."""
    counts = defaultdict(int)
    for name in members:
        for indicator in email_indicators[name]:
            if indicator not in ignored:
                counts[indicator] += 1
    shared = [(indicator, count) for indicator, count in counts.items() if count > 1]
    shared.sort(key=lambda item: (-item[1], item[0]))
    return shared


def build_campaigns(folder):
    files = sorted(Path(folder).glob("*.eml"))
    email_indicators, dates, failed = {}, {}, 0
    for number, path in enumerate(files, start=1):
        try:
            evidence = ingest.load_email(path)
            email_indicators[path.name], dates[path.name] = extract_indicators(evidence)
        except Exception:
            failed += 1
        if number % 1000 == 0:
            print(f"  ... {number}/{len(files)} emails processed", flush=True)

    groups, ignored = cluster(email_indicators)
    campaigns = []
    for number, members in enumerate(groups, start=1):
        member_dates = sorted(d for d in (dates.get(m) for m in members) if d is not None)
        shared = shared_indicators(members, email_indicators, ignored)
        campaigns.append({
            "id": f"C{number:03d}",
            "size": len(members),
            "first_seen": member_dates[0].isoformat() if member_dates else None,
            "last_seen": member_dates[-1].isoformat() if member_dates else None,
            "indicators": [{"type": t, "value": v, "emails": c} for (t, v), c in shared],
            "emails": sorted(members),
        })
    summary = {
        "emails_total": len(files),
        "emails_processed": len(email_indicators),
        "emails_failed": failed,
        "campaigns": len(campaigns),
        "emails_in_campaigns": sum(c["size"] for c in campaigns),
        "ignored_weak_indicators": len(ignored),
    }
    return summary, campaigns


def format_report(summary, campaigns, top=10, elapsed=None):
    line = "=" * 72
    out = [line, "FORENSIGHT - Campaign Clustering", line,
           f"Emails processed:      {summary['emails_processed']}/{summary['emails_total']}"
           f"  (failed: {summary['emails_failed']})",
           f"Campaigns found:       {summary['campaigns']}",
           f"Emails in campaigns:   {summary['emails_in_campaigns']}",
           f"Ignored weak indicators (shared by more than {MAX_WEAK_EMAILS} emails): "
           f"{summary['ignored_weak_indicators']}"]
    for campaign in campaigns[:top]:
        first = (campaign["first_seen"] or "?")[:10]
        last = (campaign["last_seen"] or "?")[:10]
        out += ["", f"{campaign['id']}  {campaign['size']} emails  ({first} -> {last})"]
        for indicator in campaign["indicators"][:4]:
            value = indicator["value"] if len(indicator["value"]) <= 48 else indicator["value"][:45] + "..."
            out.append(f"    {indicator['type']:<15} {value:<48} {indicator['emails']} emails")
        examples = ", ".join(campaign["emails"][:3])
        more = f" (+{campaign['size'] - 3} more)" if campaign["size"] > 3 else ""
        out.append(f"    e.g. {examples}{more}")
    out.append("")
    if elapsed is not None:
        out.append(f"Time: {elapsed:.1f} s")
    out.append(f"Full results saved to: {OUTPUT_FILE}")
    out.append(line)
    return "\n".join(out)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 4) or (len(sys.argv) == 4 and sys.argv[2] != "--top"):
        print("Usage: python -m forensight.clustering <folder> [--top N]")
        sys.exit(1)
    top = int(sys.argv[3]) if len(sys.argv) == 4 else 10
    start = time.time()
    summary, campaigns = build_campaigns(sys.argv[1])
    OUTPUT_FILE.parent.mkdir(exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps({"summary": summary, "campaigns": campaigns}, indent=2),
                           encoding="utf-8")
    print(format_report(summary, campaigns, top, time.time() - start))
