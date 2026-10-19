"""HTML forensic report: one self-contained, printable file per investigated email.

The report records the evidence hashes (chain of custody), the email summary, the risk score
and its explanation, the MITRE ATT&CK techniques, the AI analysis, the matching campaigns and
every finding. It is meant to be archived with the case or sent to people who do not use the tool.

Security: every value taken from the email is HTML-escaped, links from the email are shown as
plain text (never as clickable links), and a Content-Security-Policy blocks all scripts and
external resources, so opening the report can never run code or contact the attacker.

Usage:
    python -m forensight.report <email.eml> [--ai]
"""

import html
import sys
from datetime import datetime, timezone
from pathlib import Path

from forensight import clustering, ingest, matching, pipeline, scoring, social

REPORTS_DIR = Path("output") / "reports"
AI_SECTION = "AI analysis"
SUMMARY_HEADERS = ["From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID"]
SEVERITY_COLOR = {"high": "#c62828", "medium": "#ef6c00", "low": "#f9a825", "info": "#1565c0"}
VERDICT_COLOR = {"Malicious": "#c62828", "Suspicious": "#ef6c00", "Low risk": "#f9a825", "Clean": "#2e7d32"}

CSS = """
body { font-family: Arial, Helvetica, sans-serif; color: #222; max-width: 1000px; margin: 24px auto; padding: 0 16px; }
h1 { color: #1f3a5f; margin-bottom: 0; }
h2 { color: #1f3a5f; border-bottom: 2px solid #1f3a5f; padding-bottom: 4px; margin-top: 28px; }
.sub { color: #666; margin-top: 4px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 13px; }
th { background: #1f3a5f; color: #fff; text-align: left; padding: 6px; }
td { border: 1px solid #ddd; padding: 5px 6px; vertical-align: top; word-break: break-word; }
.mono { font-family: Consolas, monospace; font-size: 12px; }
.badge { color: #fff; border-radius: 4px; padding: 1px 6px; font-weight: bold; font-size: 12px; }
.verdict { font-size: 26px; font-weight: bold; }
.bar { background: #eee; height: 12px; border-radius: 6px; width: 320px; }
.bar div { height: 12px; border-radius: 6px; }
.note { color: #666; font-size: 12px; }
@media print { h2 { page-break-after: avoid; } table { page-break-inside: auto; } }
"""


def esc(value):
    """Escape any value for HTML, so that text from the email can never become markup."""
    return html.escape("" if value is None else str(value), quote=True)


def header_value(message, name):
    try:
        return str(ingest.safe_header(message, name) or "")
    except Exception:
        try:
            return str(message.get(name, "") or "")
        except Exception:
            return "<unreadable header>"


def badge(severity):
    color = SEVERITY_COLOR.get(severity, "#555")
    return f'<span class="badge" style="background:{color}">{esc(severity)}</span>'


def table(headers, rows, mono=()):
    """Build an HTML table; every cell is escaped unless it is already-safe HTML (a tuple ('html', ...))."""
    out = ["<table><tr>" + "".join(f"<th>{esc(h)}</th>" for h in headers) + "</tr>"]
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            content = cell[1] if isinstance(cell, tuple) and cell[0] == "html" else esc(cell)
            css = ' class="mono"' if index in mono else ""
            cells.append(f"<td{css}>{content}</td>")
        out.append("<tr>" + "".join(cells) + "</tr>")
    out.append("</table>")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Collecting the data
# ---------------------------------------------------------------------------

def collect(path, ai=False, campaigns_file=matching.CAMPAIGNS_FILE):
    """Analyse one email and return everything the report needs (the same data as the dashboard)."""
    analysis = pipeline.analyze_email(path)
    evidence = analysis["evidence"]
    social_result = pipeline.to_plain(social.analyze_social(evidence, use_ai=ai))
    findings = analysis["findings"] + pipeline.collect_findings(social_result, AI_SECTION)
    findings.sort(key=lambda f: pipeline.SEVERITY_ORDER[f["severity"]])
    try:
        indicators, _ = clustering.extract_indicators(evidence)
    except Exception:
        indicators = set()
    _, campaigns = matching.load_campaigns(campaigns_file)
    message = getattr(evidence, "message", None)
    return {
        "evidence": pipeline.to_plain(evidence),
        "headers": {name: header_value(message, name) for name in SUMMARY_HEADERS} if message else {},
        "findings": findings,
        "score": scoring.score_findings(findings, path),
        "social": social_result,
        "matches": matching.match_campaigns(indicators, campaigns, Path(path).name),
        "errors": {section: error.strip().splitlines()[-1] for section, error in analysis["errors"].items()},
    }


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def render_html(data):
    """Return the full HTML report for the data produced by collect() (or by the dashboard)."""
    score, evidence = data["score"], data["evidence"]
    name = Path(str(evidence.get("path", "email"))).name
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    color = VERDICT_COLOR.get(score.verdict, "#555")
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        # No scripts, no external resources: the report cannot run code or contact any server.
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        f"<title>Forensight report: {esc(name)}</title><style>{CSS}</style></head><body>",
        "<h1>Forensight: Phishing Email Forensic Report</h1>",
        f'<p class="sub">Email: <b>{esc(name)}</b> &middot; Generated: {esc(generated)} &middot; '
        "Static analysis only: the email was not opened, its links were not visited and its "
        "attachments were not executed.</p>",
        "<h2>1. Verdict</h2>",
        f'<p class="verdict" style="color:{color}">{esc(score.verdict)}: {score.score}/100</p>',
        f'<div class="bar"><div style="width:{score.score}%;background:{color}"></div></div>',
        "<h2>2. Evidence (chain of custody)</h2>",
        table(["Field", "Value"], [(k, v) for k, v in evidence.items()
                                   if isinstance(v, (str, int, float)) and v != "<email message object>"],
              mono=(1,)),
        "<h2>3. Email summary</h2>",
        table(["Header", "Value"], [(k, v or "-") for k, v in data["headers"].items()]),
        '<p class="note">Values are shown exactly as received. Addresses and links from the email are '
        "deliberately not clickable.</p>",
    ]

    parts.append("<h2>4. Score explanation</h2>")
    rows = [(f"+{c.points}", ("html", badge(c.severity)), c.section, c.title, c.count, ", ".join(c.techniques))
            for c in score.contributions]
    if score.bonus:
        rows.append((f"+{score.bonus}", "", "", f"Findings from {scoring.MULTI_MODULE_MIN} or more modules", 1, ""))
    parts.append(table(["Points", "Severity", "Module", "Finding", "Times", "ATT&CK"], rows)
                 if rows else "<p>No findings: score 0.</p>")
    parts.append('<p class="note">Points: high 30, medium 12, low 4, info 0; a repeated finding counts once; '
                 f"+{scoring.MULTI_MODULE_BONUS} when {scoring.MULTI_MODULE_MIN} or more modules raise findings. "
                 "Verdicts: Clean 0-9, Low risk 10-29, Suspicious 30-59, Malicious 60-100.</p>")

    parts.append("<h2>5. MITRE ATT&amp;CK techniques</h2>")
    rows = []
    for technique, titles in sorted(score.techniques.items()):
        url = "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"
        rows.append((("html", f'<a href="{esc(url)}">{esc(technique)}</a>'), scoring.TECHNIQUES[technique],
                     "; ".join(dict.fromkeys(titles))))
    parts.append(table(["Technique", "Name", "Evidence"], rows) if rows else "<p>No technique mapped.</p>")

    parts.append("<h2>6. AI analysis (local model)</h2>")
    ai = data.get("social") or {}
    if ai.get("injection"):
        parts.append("<p><b>Prompt-injection attempt:</b> instructions aimed at an AI assistant were found.</p>")
        parts.append(table(["Phrase"], [(p,) for p in ai["injection"]]))
    if ai.get("hidden_text"):
        parts.append(table(["Hidden text (never sent to the model)"], [(ai["hidden_text"],)]))
    if ai.get("ai_status") == "ok":
        parts.append(f'<p class="note">Model {esc(ai.get("model"))}, {esc(ai.get("seconds"))} s. '
                     "Each tactic is confirmed by a quote that exists in the email.</p>")
        parts.append(table(["Tactic", "Evidence quoted from the email"],
                           [(t["tactic"], t["evidence"]) for t in ai.get("tactics", [])])
                     if ai.get("tactics") else "<p>No social-engineering tactic was confirmed.</p>")
        parts.append(f"<p><b>Summary by the model:</b> {esc(ai.get('summary') or '-')}</p>")
    else:
        parts.append(f'<p class="note">Language-model analysis: {esc(ai.get("ai_status", "not run"))}.</p>')

    parts.append("<h2>7. Campaigns</h2>")
    rows = [(m["id"], m["size"], "yes" if m["member"] else "no",
             ", ".join(f"{t}: {v}" for t, v in m["strong"]) or "-",
             ", ".join(f"{t}: {v}" for t, v in m["weak"]) or "-") for m in data.get("matches", [])]
    parts.append(table(["Campaign", "Emails", "Known member", "Shared strong", "Shared weak"], rows)
                 if rows else "<p>The email does not match any known campaign.</p>")

    parts.append("<h2>8. All findings</h2>")
    rows = [(("html", badge(f["severity"])), f["section"], f["title"], f["detail"], f["context"])
            for f in data["findings"]]
    parts.append(table(["Severity", "Module", "Finding", "Detail", "Context"], rows)
                 if rows else "<p>No findings.</p>")
    if data.get("errors"):
        parts.append("<h2>9. Modules that failed</h2>")
        parts.append(table(["Module", "Error"], list(data["errors"].items())))

    parts.append('<p class="note">Generated by Forensight (github.com/zreigat84aseel/forensight).</p>')
    parts.append("</body></html>")
    return "\n".join(parts)


def write_report(path, ai=False):
    data = collect(path, ai=ai)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    output = REPORTS_DIR / f"{Path(path).stem}_report.html"
    output.write_text(render_html(data), encoding="utf-8")
    return output, data


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) not in (1, 2) or (len(args) == 2 and args[1] != "--ai"):
        print("Usage: python -m forensight.report <email.eml> [--ai]")
        sys.exit(1)
    output, data = write_report(args[0], ai=len(args) == 2)
    print(f"Score: {data['score'].score}/100 ({data['score'].verdict})")
    print(f"Report saved to: {output}")
