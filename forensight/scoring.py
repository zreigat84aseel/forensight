"""Explainable risk scoring with MITRE ATT&CK mapping.

Every finding produced by the analysis modules adds points according to its severity.
The final score (0-100) is the sum of these points, so an analyst can always see exactly
why an email received its score. Each finding is also mapped to the MITRE ATT&CK
techniques it is evidence of.

Usage:
    python -m forensight.scoring <email.eml>
    python -m forensight.scoring --stats <folder>
"""

import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from forensight.pipeline import analyze_email

SEVERITY_POINTS = {"high": 30, "medium": 12, "low": 4, "info": 0}
MULTI_MODULE_BONUS = 10      # findings from 3 or more different modules
MULTI_MODULE_MIN = 3
MAX_SCORE = 100

# (minimum score, verdict) from the highest threshold down
VERDICTS = [(60, "Malicious"), (30, "Suspicious"), (10, "Low risk"), (0, "Clean")]

TECHNIQUES = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1036.002": "Masquerading: Right-to-Left Override",
    "T1036.007": "Masquerading: Double File Extension",
    "T1036.008": "Masquerading: Masquerade File Type",
    "T1027.006": "Obfuscated Files or Information: HTML Smuggling",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1553.005": "Subvert Trust Controls: Mark-of-the-Web Bypass",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1585.002": "Establish Accounts: Email Accounts",
    "T1656": "Impersonation",
    "T1672": "Email Spoofing",
}

# Keyword rules: a regular expression searched in the finding title (case-insensitive)
# and the techniques that the finding is evidence of. \b keeps short words such as
# "iso" from matching inside longer words such as "revision".
RULES = [
    (r"right-to-left|rtlo", ["T1036.002"]),
    (r"double extension", ["T1036.007"]),
    (r"does not match (the )?extension|type mismatch", ["T1036.008"]),
    (r"\bmacros?\b|\bvba\b", ["T1059.005", "T1204.002"]),
    (r"javascript", ["T1059.007"]),
    (r"builds a file in the browser|smuggl", ["T1027.006"]),
    (r"password field|credential|\bforms?\b", ["T1598.003"]),
    (r"\biso\b|disk image|mark-of-the-web", ["T1553.005"]),
    (r"executable|script attachment|configuration profile|mobileconfig", ["T1204.002"]),
    (r"homograph|typosquat|combosquat|lookalike|brand|substitution|different tld", ["T1583.001", "T1656"]),
    (r"free-mail|free mail|free provider|display name|organization-style", ["T1585.002", "T1656"]),
    (r"reply-to|return-path|spoof", ["T1656"]),
    (r"\bspf\b|\bdkim\b|\bdmarc\b|alignment", ["T1672"]),
]

# Every finding in these modules is at least evidence of the delivery technique.
SECTION_DEFAULTS = {
    "Attachments": ["T1566.001"],
    "Links & QR": ["T1566.002"],
}


@dataclass
class Contribution:
    section: str
    title: str
    severity: str
    count: int
    points: int
    techniques: list


@dataclass
class ScoreReport:
    path: str
    score: int
    verdict: str
    contributions: list = field(default_factory=list)
    bonus: int = 0
    techniques: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


def map_techniques(section, title):
    """Return the ATT&CK technique IDs that a finding is evidence of."""
    found = list(SECTION_DEFAULTS.get(section, []))
    text = title.lower()
    for pattern, techniques in RULES:
        if re.search(pattern, text):
            for technique in techniques:
                if technique not in found:
                    found.append(technique)
    return found


def verdict_for(score):
    for minimum, verdict in VERDICTS:
        if score >= minimum:
            return verdict
    return "Clean"


def score_findings(findings, path=""):
    """Turn a list of findings (dicts with section, severity, title) into an explainable score.

    The same finding repeated many times (for example twenty shortened links) is counted
    once, so one noisy indicator cannot push an email to the maximum score on its own.
    """
    grouped = Counter((f["section"], f["severity"], f["title"]) for f in findings)
    contributions = []
    for (section, severity, title), count in grouped.items():
        contributions.append(Contribution(
            section=section, title=title, severity=severity, count=count,
            points=SEVERITY_POINTS.get(severity, 0),
            techniques=map_techniques(section, title),
        ))
    contributions.sort(key=lambda c: -c.points)

    modules = {c.section for c in contributions if c.points > 0}
    bonus = MULTI_MODULE_BONUS if len(modules) >= MULTI_MODULE_MIN else 0
    score = min(MAX_SCORE, sum(c.points for c in contributions) + bonus)

    techniques = {}
    for c in contributions:
        for technique in c.techniques:
            techniques.setdefault(technique, []).append(c.title)

    return ScoreReport(path=str(path), score=score, verdict=verdict_for(score),
                       contributions=contributions, bonus=bonus, techniques=techniques)


def score_email(path, live=False):
    analysis = analyze_email(path, live=live)
    report = score_findings(analysis["findings"], path)
    report.errors = sorted(analysis["errors"])
    return report


def format_report(report):
    line = "=" * 72
    out = [line, "FORENSIGHT - Risk Score", line,
           f"Email:   {Path(report.path).name}",
           f"Score:   {report.score}/100",
           f"Verdict: {report.verdict}", "",
           "Score breakdown:"]
    if not report.contributions:
        out.append("  (no findings)")
    for c in report.contributions:
        times = f" (x{c.count})" if c.count > 1 else ""
        out.append(f"  +{c.points:<3} [{c.severity:<6}] {c.section}: {c.title}{times}")
    if report.bonus:
        out.append(f"  +{report.bonus:<3} findings from {MULTI_MODULE_MIN} or more modules")
    out += ["", "MITRE ATT&CK techniques:"]
    if not report.techniques:
        out.append("  (none)")
    for technique, titles in sorted(report.techniques.items()):
        out.append(f"  {technique:<10} {TECHNIQUES[technique]}")
        for title in dict.fromkeys(titles):
            out.append(f"             <- {title}")
    if report.errors:
        out += ["", "Modules that failed: " + ", ".join(report.errors)]
    out.append(line)
    return "\n".join(out)


def dataset_stats(folder):
    files = sorted(Path(folder).glob("*.eml"))
    verdicts, techniques, scores, failed = Counter(), Counter(), [], 0
    start = time.time()
    for number, path in enumerate(files, start=1):
        try:
            report = score_email(path)
        except Exception:
            failed += 1
            continue
        verdicts[report.verdict] += 1
        scores.append(report.score)
        techniques.update(report.techniques.keys())
        if number % 500 == 0:
            print(f"  ... {number}/{len(files)} emails scored", flush=True)
    elapsed = time.time() - start
    total = len(scores)
    line = "=" * 72
    print(line)
    print("FORENSIGHT - Risk Score Statistics")
    print(line)
    print(f"Emails scored: {total}/{len(files)}  (failed: {failed})")
    if total:
        print(f"Average score: {sum(scores) / total:.1f}")
        print("\nVerdicts:")
        for _, verdict in VERDICTS:
            count = verdicts[verdict]
            print(f"  {verdict:<11} {count:>6}  ({count / total:6.1%})")
        print("\nTop ATT&CK techniques (emails):")
        for technique, count in techniques.most_common(10):
            print(f"  {technique:<10} {count:>6}  {TECHNIQUES[technique]}")
    print(f"\nTime: {elapsed:.1f} s")
    print(line)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--stats":
        dataset_stats(sys.argv[2])
    elif len(sys.argv) == 2:
        print(format_report(score_email(sys.argv[1])))
    else:
        print("Usage: python -m forensight.scoring <email.eml> | --stats <folder>")
        sys.exit(1)
