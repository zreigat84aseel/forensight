"""
Forensight - Lookalike domain detection module.

Collects every domain that appears in an email's headers and checks whether
any of them imitates the domain of a well-known brand, using six techniques:
  1. Homograph (IDN) attack   - foreign letters that look Latin (pаypal with Cyrillic 'а')
  2. Character substitution   - digits or letter pairs that look alike (paypa1, rnicrosoft)
  3. Typosquatting            - one or two characters added, removed or changed (pexinterest)
  4. Combosquatting           - the brand name joined with other words (paypal-secure-login)
  5. Brand in subdomain       - the real brand domain used as a prefix (paypal.com.evil.ru)
  6. Different TLD            - the exact brand name on another extension (paypal.net)
"""

import re
import sys
from collections import Counter
from dataclasses import dataclass
from email.utils import parseaddr
from pathlib import Path

import tldextract

from forensight.headers import Finding, parse_received
from forensight.ingest import EmailEvidence, load_email, raw_header_values, safe_header

# Offline public-suffix parser: correctly splits "mail.and.co.uk" into
# subdomain "mail", name "and" and suffix "co.uk" without internet access.
_extract = tldextract.TLDExtract(suffix_list_urls=())

# Official domains of brands commonly impersonated in phishing.
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com", "office365.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "amazon": ["amazon.com", "amazon.com.br", "amazon.co.uk"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "pinterest": ["pinterest.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "ebay": ["ebay.com"],
    "spotify": ["spotify.com"],
    "metamask": ["metamask.io"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "mercadolivre": ["mercadolivre.com.br"],
    "mercadolibre": ["mercadolibre.com"],
    "nubank": ["nubank.com.br"],
    "itau": ["itau.com.br"],
    "bradesco": ["bradesco.com.br"],
    "santander": ["santander.com.br", "santander.com"],
    "caixa": ["caixa.gov.br"],
    "correios": ["correios.com.br"],
}

# Legitimate infrastructure that would otherwise trigger false alarms
# (tuned after testing on the dataset). In a SOC this list is maintained by analysts.
KNOWN_LEGITIMATE = {
    "onmicrosoft.com",   # Microsoft 365 tenant domains (official Microsoft infrastructure)
    "correio.biz",       # Brazilian email hosting provider ("correio" means "mail")
}

# Characters and pairs that attackers use because they look like other letters.
SUBSTITUTIONS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"),
                 ("3", "e"), ("4", "a"), ("5", "s"), ("7", "t"), ("8", "b"), ("9", "g")]

# Non-Latin letters that look identical to Latin letters (Cyrillic and Greek).
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ⅼ": "l", "ҏ": "p",
    "α": "a", "ο": "o", "ν": "v", "τ": "t", "ρ": "p", "κ": "k", "ι": "i",
}


@dataclass
class DomainRecord:
    domain: str       # full domain as found (e.g. mail.paypa1.com)
    role: str         # where it was found (From, Reply-To, Received, ...)


# ---------- 1. collect domains ----------

def _clean(domain: str) -> str:
    return domain.strip().strip("<>[]().,;'\"").rstrip(".").lower()


def _looks_like_domain(value: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9\u00a1-\uffff-]+(\.[a-z0-9\u00a1-\uffff-]+)+", value)) \
        and not re.fullmatch(r"[\d.]+", value)


def collect_domains(evidence: EmailEvidence) -> list:
    """Every domain found in the email headers, with the place it was found."""
    m = evidence.message
    found = []

    def add(value: str, role: str) -> None:
        dom = _clean(value)
        if _looks_like_domain(dom) and all(r.domain != dom or r.role != role for r in found):
            found.append(DomainRecord(dom, role))

    for header in ("From", "Return-Path", "Reply-To", "Sender"):
        _, addr = parseaddr(safe_header(m, header))
        if "@" in addr:
            add(addr.rsplit("@", 1)[1], header)

    display, _ = parseaddr(safe_header(m, "From"))
    for email in re.findall(r"[\w.+-]+@([\w.-]+\.\w+)", display):
        add(email, "Display name")

    msgid = safe_header(m, "Message-ID")
    if "@" in msgid:
        add(msgid.rsplit("@", 1)[1], "Message-ID")

    for sig in raw_header_values(m, "DKIM-Signature"):
        match = re.search(r"\bd=([^;\s]+)", " ".join(sig.split()))
        if match:
            add(match.group(1), "DKIM signer")

    for hop in parse_received(evidence):
        add(hop.from_host, f"Received hop {hop.index}")
    return found


# ---------- 2. detection techniques ----------

def split_domain(domain: str) -> tuple:
    """Return (subdomain, name, registered domain) using the public suffix list."""
    parts = _extract(domain)
    registered = f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain
    return parts.subdomain, parts.domain, registered


def edit_distance(a: str, b: str) -> int:
    """Number of single-character edits (insert, delete, replace, swap) between a and b."""
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[len(b)]


def decode_idn(name: str) -> str:
    """Convert punycode (xn--...) into the Unicode letters the victim actually sees."""
    try:
        return name.encode().decode("idna") if "xn--" in name else name
    except Exception:
        return name


def _normalize(name: str) -> str:
    for fake, real in SUBSTITUTIONS:
        name = name.replace(fake, real)
    return name.replace("-", "")


def check_domain(domain: str) -> list:
    """Compare one domain against every brand. Returns (technique, brand, severity, detail)."""
    subdomain, name, registered = split_domain(domain)
    if not name:
        return []
    official = {d for domains in BRANDS.values() for d in domains}
    if registered in official or registered in KNOWN_LEGITIMATE:
        return []                                   # the real brand domain or known infrastructure
    country_tld = len(registered.rsplit(".", 1)[-1]) == 2

    results = []
    unicode_name = decode_idn(name)
    latin_name = "".join(CONFUSABLES.get(ch, ch) for ch in unicode_name)
    tokens = [t for t in re.split(r"[-.\d]+", name) if t]

    for brand, domains in BRANDS.items():
        if name in BRANDS and name != brand:
            continue                                # a brand name is not a typo of another brand
        if not unicode_name.isascii() and latin_name == brand:
            results.append(("Homograph (IDN) attack", brand, "high",
                            f"'{domain}' is displayed as '{unicode_name}', which looks identical to '{brand}'"))
        elif name == brand and country_tld:
            continue                                # e.g. amazon.de: usually an official regional site
        elif name == brand:
            results.append(("Brand on a different TLD", brand, "medium",
                            f"'{registered}' uses the brand name but is not an official domain "
                            f"({', '.join(domains)})"))
        elif _normalize(name) == brand:
            results.append(("Character substitution", brand, "high",
                            f"'{name}' imitates '{brand}' by replacing look-alike characters"))
        elif len(brand) >= 5 and 0 < edit_distance(name, brand) <= (1 if len(brand) < 8 else 2):
            dist = edit_distance(name, brand)
            results.append(("Typosquatting", brand, "high" if dist == 1 else "medium",
                            f"'{name}' differs from '{brand}' by {dist} character(s)"))
        elif len(brand) >= 4 and brand in tokens and len(tokens) > 1:
            results.append(("Combosquatting", brand, "medium",
                            f"'{registered}' combines the brand name '{brand}' with other words"))
        elif subdomain and any(d in f"{subdomain}." or brand == s
                               for d in domains for s in subdomain.split(".")):
            results.append(("Brand in subdomain", brand, "high",
                            f"'{domain}' places '{brand}' in the subdomain, but the real "
                            f"registered domain is '{registered}'"))
    return results


# ---------- main entry ----------

def analyze_lookalikes(evidence: EmailEvidence) -> tuple:
    """Return (domains collected, findings). One finding per domain and technique."""
    records = collect_domains(evidence)
    grouped = {}
    for rec in records:
        registered = split_domain(rec.domain)[2]
        for technique, brand, severity, detail in check_domain(rec.domain):
            key = (registered, technique, brand)
            if key not in grouped:
                grouped[key] = [severity, detail, []]
            if rec.role not in grouped[key][2]:
                grouped[key][2].append(rec.role)
    findings = [Finding(sev, f"{technique}: imitates {brand}", f"{detail} [found in: {', '.join(roles)}]")
                for (_, technique, brand), (sev, detail, roles) in grouped.items()]
    return records, findings


def format_report(records: list, findings: list) -> str:
    out = ["=" * 60, "FORENSIGHT - Lookalike Domain Detection", "=" * 60,
           f"Domains analyzed ({len(records)}):"]
    for rec in records:
        out.append(f"  {rec.role:<18} {rec.domain}")
    out.append("-" * 60)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    if not findings:
        out.append("No lookalike domains found.")
    for f in sorted(findings, key=lambda x: order[x.severity]):
        out.append(f"[{f.severity.upper():6}] {f.title}")
        out.append(f"          {f.detail}")
    out.append("=" * 60)
    return "\n".join(out)


def dataset_statistics(folder: str) -> None:
    """Count lookalike techniques and impersonated brands across a folder of emails."""
    files = sorted(Path(folder).expanduser().glob("*.eml"))
    techniques, brands = Counter(), Counter()
    emails_with_hits, failed = 0, 0
    for path in files:
        try:
            _, findings = analyze_lookalikes(load_email(path))
        except Exception:
            failed += 1
            continue
        if findings:
            emails_with_hits += 1
        for f in {x.title for x in findings}:
            technique, brand = f.split(": imitates ")
            techniques[technique] += 1
            brands[brand] += 1
    print("=" * 60)
    print("FORENSIGHT - Lookalike Domain Statistics")
    print("=" * 60)
    print(f"Emails analyzed: {len(files)} | failed: {failed} | "
          f"emails with lookalike domains: {emails_with_hits}")
    print("-" * 60)
    print("By technique:")
    for name, n in techniques.most_common():
        print(f"  {name:<28}{n:>6}")
    print("-" * 60)
    print("Top 10 impersonated brands:")
    for name, n in brands.most_common(10):
        print(f"  {name:<28}{n:>6}")
    print("=" * 60)


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "--stats":
        dataset_statistics(args[1])
    elif len(args) == 2 and args[0] == "--domain":
        hits = check_domain(args[1].lower())
        print(f"{args[1]}: " + ("; ".join(f"{t} ({b}, {s})" for t, b, s, _ in hits) or "no match"))
    elif len(args) == 1:
        print(format_report(*analyze_lookalikes(load_email(args[0]))))
    else:
        print("Usage: python -m forensight.lookalike <email.eml>")
        print("       python -m forensight.lookalike --domain <domain>")
        print("       python -m forensight.lookalike --stats <folder>")
        sys.exit(1)
