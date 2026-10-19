"""Forensight dashboard: a local web interface for the whole investigation of one email.

Run from the project root:
    streamlit run dashboard.py --server.address 127.0.0.1

Tabs: overview, risk score with MITRE ATT&CK, one tab per analysis module, AI analysis
(local model), campaigns with detection rules, route map and export.

The email is only parsed and analysed statically. It is never opened in a mail client,
its links are never visited and its attachments are never executed.
"""

import hashlib
import json
import re
import subprocess
import sys
import traceback
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from forensight import clustering, ingest, matching, pipeline, rules, scoring, social

PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "output"
UPLOAD_DIR = OUTPUT_DIR / "uploads"
CAMPAIGNS_FILE = OUTPUT_DIR / "campaigns.json"
MAX_UPLOAD_MB = 25
SEVERITY_ORDER = pipeline.SEVERITY_ORDER
SEVERITY_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}
VERDICT_ICON = {"Malicious": "🔴", "Suspicious": "🟠", "Low risk": "🟡", "Clean": "🟢"}
MODULE_TABS = ["Headers", "Authentication", "Domains", "Links & QR", "Attachments"]
AI_SECTION = "AI analysis"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def scalar_table(rows):
    """Build a table from a list of dicts, keeping only simple (non-nested) columns."""
    cleaned = []
    for row in rows:
        if isinstance(row, dict):
            cleaned.append({k: v for k, v in row.items()
                            if isinstance(v, (str, int, float, bool)) or v is None})
    cleaned = [row for row in cleaned if row]
    return pd.DataFrame(cleaned).astype(str) if cleaned else None


def findings_table(findings):
    """Findings as a table with readable column names."""
    rows = [{"Severity": f"{SEVERITY_ICON[f['severity']]} {f['severity']}", "Module": f["section"],
             "Finding": f["title"], "Detail": f["detail"], "Context": f["context"]} for f in findings]
    return pd.DataFrame(rows)


def show_table(frame):
    """Show a table as plain text. st.table renders Markdown in its cells, so values taken from the
    email (headers, display names, URLs) could become clickable links; st.dataframe never does."""
    st.dataframe(frame.astype(str).replace({"": "-", "None": "-"}), width="stretch", hide_index=True)


def header_value(message, name):
    """Read a header safely: malformed headers fall back to their raw text."""
    try:
        return str(ingest.safe_header(message, name) or "")
    except Exception:
        try:
            return str(message.get(name, "") or "")
        except Exception:
            return "<unreadable header>"


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


@st.cache_data(show_spinner=False)
def cached_campaigns(path, modified):
    """Load campaigns.json once; the file's modification time makes the cache refresh after a new run."""
    return matching.load_campaigns(path)


# ---------------------------------------------------------------------------
# Analysis (cached in the session so that changing tabs does not re-run it)
# ---------------------------------------------------------------------------

def run_analysis(path, live):
    """Run every module, the prompt-injection checks (no model) and the campaign indicators."""
    analysis = pipeline.analyze_email(path, live=live)
    evidence = analysis["evidence"]
    checks = social.analyze_social(evidence, use_ai=False)
    analysis["injection"] = pipeline.to_plain(checks)
    analysis["findings"] += pipeline.collect_findings(analysis["injection"], AI_SECTION)
    try:
        indicators, _ = clustering.extract_indicators(evidence)
    except Exception:
        indicators = set()
    analysis["indicators"] = indicators
    return analysis


def current_findings():
    """Findings of all modules, plus the language-model findings if the AI analysis was run."""
    findings = list(analysis["findings"])
    ai = st.session_state.get("ai")
    if ai and ai["ai_status"] == "ok":
        known = {(f["section"], f["title"]) for f in findings}
        for finding in pipeline.collect_findings(ai, AI_SECTION):
            if (finding["section"], finding["title"]) not in known:
                findings.append(finding)
    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return findings


# ---------------------------------------------------------------------------
# Page layout and evidence selection
# ---------------------------------------------------------------------------

st.set_page_config(page_title="Forensight", page_icon="🔎", layout="wide")
st.title("🔎 Forensight")
st.caption("Automated phishing email forensics: static analysis only. "
           "Emails are never opened in a mail client, links are never visited, attachments are never executed.")

with st.sidebar:
    st.header("Evidence")
    source = st.radio("Email source", ["Upload .eml file", "Path on this machine"])
    email_path, email_name = None, None
    if source == "Upload .eml file":
        uploaded = st.file_uploader("Choose an .eml file", type=["eml"])
        if uploaded is not None:
            data = uploaded.getvalue()
            if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
                st.error(f"File is larger than {MAX_UPLOAD_MB} MB.")
            else:
                UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", uploaded.name)
                email_path = UPLOAD_DIR / f"{hashlib.sha256(data).hexdigest()[:12]}_{safe_name}"
                email_name = uploaded.name
                if not email_path.exists():
                    email_path.write_bytes(data)
    else:
        typed = st.text_input("Full path to an .eml file",
                              placeholder=str(Path.home() / "samples/phishing_pot/email/sample-1000.eml"))
        if typed:
            candidate = Path(typed).expanduser()
            if candidate.is_file():
                email_path, email_name = candidate, candidate.name
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
        st.session_state["analysis"] = run_analysis(email_path, live)
        st.session_state["route"] = None
        st.session_state["ai"] = None
        st.session_state["cache_key"] = cache_key

analysis = st.session_state["analysis"]
evidence, results, errors = analysis["evidence"], analysis["results"], analysis["errors"]
evidence_plain = pipeline.to_plain(evidence)
findings = current_findings()
report = scoring.score_findings(findings, email_path)

modified = CAMPAIGNS_FILE.stat().st_mtime if CAMPAIGNS_FILE.is_file() else 0
campaign_summary, campaigns = cached_campaigns(str(CAMPAIGNS_FILE), modified)
matches = matching.match_campaigns(analysis["indicators"], campaigns, email_name)

TAB_NAMES = ["Overview", "Risk Score"] + MODULE_TABS + ["AI Analysis", "Campaigns", "Route Map", "Export"]
TAB = dict(zip(TAB_NAMES, st.tabs(TAB_NAMES)))

# --- Overview -------------------------------------------------------------
with TAB["Overview"]:
    left, right = st.columns([1, 2])
    left.metric("Risk score", f"{report.score}/100")
    left.progress(report.score / 100)
    right.metric("Verdict", f"{VERDICT_ICON[report.verdict]} {report.verdict}")
    if matches:
        best = matches[0]
        relation = "is a known member of" if best["member"] else "matches"
        right.warning(f"This email {relation} campaign {best['id']} ({best['size']} emails). "
                      "See the Campaigns tab.")
    if not (st.session_state.get("ai") or {}).get("ai_status") == "ok":
        st.caption("The score does not include the language-model analysis yet. "
                   "Run it in the AI Analysis tab to add it.")

    columns = st.columns(4)
    for column, level in zip(columns, SEVERITY_ORDER):
        column.metric(f"{SEVERITY_ICON[level]} {level.capitalize()}",
                      sum(1 for f in findings if f["severity"] == level))

    st.subheader("Evidence integrity")
    integrity = {k: v for k, v in evidence_plain.items()
                 if isinstance(v, (str, int, float)) and v != "<email message object>"}
    show_table(pd.DataFrame(integrity.items(), columns=["Field", "Value"]).astype(str))

    message = getattr(evidence, "message", None)
    if message is not None:
        st.subheader("Email summary")
        summary = {name: header_value(message, name)
                   for name in ["From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID"]}
        show_table(pd.DataFrame(summary.items(), columns=["Header", "Value"]))

    if findings:
        st.subheader("Findings by module")
        st.bar_chart(pd.DataFrame(findings).groupby("section").size().rename("Findings"))
        st.subheader("All findings")
        st.dataframe(findings_table(findings), width="stretch", hide_index=True)
    else:
        st.success("No findings were raised for this email.")

    for section, error in errors.items():
        st.error(f"{section} module failed for this email.")
        with st.expander(f"Error details: {section}"):
            st.code(error)

# --- Risk score -----------------------------------------------------------
with TAB["Risk Score"]:
    st.subheader(f"{VERDICT_ICON[report.verdict]} {report.score}/100: {report.verdict}")
    st.caption("Points per finding: high 30, medium 12, low 4, info 0. A repeated finding is counted once. "
               f"+{scoring.MULTI_MODULE_BONUS} when {scoring.MULTI_MODULE_MIN} or more modules raise findings. "
               "Verdicts: Clean 0-9, Low risk 10-29, Suspicious 30-59, Malicious 60-100.")
    rows = [{"Points": f"+{c.points}", "Severity": f"{SEVERITY_ICON[c.severity]} {c.severity}",
             "Module": c.section, "Finding": c.title, "Times": c.count,
             "ATT&CK": ", ".join(c.techniques)} for c in report.contributions]
    if report.bonus:
        rows.append({"Points": f"+{report.bonus}", "Severity": "", "Module": "",
                     "Finding": f"Findings from {scoring.MULTI_MODULE_MIN} or more modules",
                     "Times": 1, "ATT&CK": ""})
    if rows:
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    else:
        st.success("No findings: score 0.")

    st.subheader("MITRE ATT&CK techniques")
    if report.techniques:
        attack = [{"Technique": technique, "Name": scoring.TECHNIQUES[technique],
                   "Evidence": "; ".join(dict.fromkeys(titles)),
                   "Link": "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"}
                  for technique, titles in sorted(report.techniques.items())]
        st.dataframe(pd.DataFrame(attack), width="stretch", hide_index=True,
                     column_config={"Link": st.column_config.LinkColumn("Link", display_text="open")})
    else:
        st.caption("No technique mapped.")


# --- One tab per analysis module -------------------------------------------
def render_section(section):
    data = results.get(section)
    if section in errors:
        st.error(f"The {section} module failed for this email.")
        st.code(errors[section])
        return
    section_findings = [f for f in findings if f["section"] == section]
    if section_findings:
        st.dataframe(findings_table(section_findings).drop(columns="Module"), width="stretch", hide_index=True)
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
            show_table(pd.DataFrame(simple.items(), columns=["Field", "Value"]).astype(str))
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
                    show_table(pd.DataFrame(inner.items(), columns=["Field", "Value"]).astype(str))

    with st.expander("Raw module output (JSON)"):
        st.json(data if data is not None else {})


for section in MODULE_TABS:
    with TAB[section]:
        if section == "Authentication":
            st.caption("Mode: " + ("live DNS verification" if live else "offline (recorded results only)"))
        render_section(section)

# --- AI analysis ----------------------------------------------------------
with TAB["AI Analysis"]:
    st.caption(f"Local model {social.MODEL} through Ollama at {social.OLLAMA_URL}: the email never leaves "
               "this machine. Email text is treated as untrusted input (prompt-injection defenses).")

    checks = analysis["injection"]
    st.subheader("Prompt-injection checks (no model needed)")
    if checks["injection"]:
        st.error("Instructions aimed at an AI assistant were found in this email:")
        show_table(pd.DataFrame({"Phrase": checks["injection"]}))
    else:
        st.success("No prompt-injection phrases found.")
    if checks["hidden_text"]:
        with st.expander("Hidden text (never sent to the model)"):
            st.text(checks["hidden_text"])

    st.subheader("Social-engineering analysis")
    if st.button("Run AI analysis", type="primary"):
        with st.spinner("The local model is reading the email (about 15 seconds on CPU)..."):
            st.session_state["ai"] = pipeline.to_plain(social.analyze_social(evidence, use_ai=True))
        st.rerun()

    ai = st.session_state.get("ai")
    if ai is None:
        st.info("Not run yet. The model runs on the CPU, so it is started only when you ask for it.")
    elif ai["ai_status"] != "ok":
        st.warning(f"AI status: {ai['ai_status']}. Is Ollama running? (ollama list)")
    else:
        st.caption(f"AI status: ok ({ai['seconds']} s)")
        if ai["tactics"]:
            st.markdown("**Tactics confirmed by evidence quoted from the email**")
            show_table(pd.DataFrame([{"Tactic": t["tactic"], "Evidence": t["evidence"]} for t in ai["tactics"]]))
        else:
            st.success("No social-engineering tactic was confirmed.")
        if ai["rejected"]:
            with st.expander(f"{len(ai['rejected'])} model claims rejected (quote not found in the email)"):
                st.dataframe(pd.DataFrame(ai["rejected"]).astype(str), width="stretch", hide_index=True)
        st.markdown("**Summary written by the model**")
        st.text(ai["summary"] or "(none)")       # shown as plain text: model output is not trusted markup

# --- Campaigns and detection rules ------------------------------------------
with TAB["Campaigns"]:
    if not campaigns:
        st.info("No campaign data yet. Run the clustering once from the project folder:\n\n"
                "python -m forensight.clustering ~/samples/phishing_pot/email")
    else:
        top = st.columns(3)
        top[0].metric("Campaigns", campaign_summary.get("campaigns", len(campaigns)))
        top[1].metric("Emails in campaigns", campaign_summary.get("emails_in_campaigns", "?"))
        top[2].metric("Emails analysed", campaign_summary.get("emails_processed", "?"))

        st.subheader("This email")
        if matches:
            rows = [{"Campaign": m["id"], "Size": m["size"], "Known member": "yes" if m["member"] else "no",
                     "Shared strong": ", ".join(f"{t}: {v}" for t, v in m["strong"]) or "-",
                     "Shared weak": ", ".join(f"{t}: {v}" for t, v in m["weak"]) or "-"} for m in matches]
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        else:
            st.success("This email does not match any known campaign "
                       "(rule: one shared strong indicator or two shared weak indicators).")

        st.subheader("Browse campaigns")
        overview = [{"Campaign": c["id"], "Emails": c["size"],
                     "First seen": (c.get("first_seen") or "")[:10], "Last seen": (c.get("last_seen") or "")[:10],
                     "Main indicator": f"{c['indicators'][0]['type']}: {c['indicators'][0]['value'][:60]}"
                     if c["indicators"] else "-"} for c in campaigns]
        st.dataframe(pd.DataFrame(overview), width="stretch", hide_index=True, height=250)

        ids = [c["id"] for c in campaigns]
        default = ids.index(matches[0]["id"]) if matches else 0
        chosen_id = st.selectbox("Campaign", ids, index=default)
        chosen = next(c for c in campaigns if c["id"] == chosen_id)
        show_table(pd.DataFrame([{"Type": i["type"], "Value": i["value"], "Emails": i["emails"]}
                               for i in chosen["indicators"]]).astype(str))
        with st.expander(f"{chosen['size']} emails in {chosen_id}"):
            st.text("\n".join(chosen["emails"]))

        st.subheader(f"Detection rules for {chosen_id}")
        st.caption("Same logic as the clustering: one strong indicator, or two different weak indicators.")
        yara_text = rules.yara_rules(chosen)
        sigma_text = rules.sigma_rule(chosen)
        stix_text = json.dumps(rules.stix_bundle(chosen), indent=2)
        rule_tabs = st.tabs(["YARA", "Sigma", "STIX 2.1"])
        with rule_tabs[0]:
            if yara_text:
                st.code(yara_text, language="text")
                st.download_button("Download .yar", yara_text, file_name=f"{chosen_id}.yar")
            else:
                st.caption("No text indicator to build a YARA rule.")
        with rule_tabs[1]:
            st.caption(f"Validation: {rules.check_sigma(sigma_text)}")
            st.code(sigma_text, language="yaml")
            st.download_button("Download Sigma rule", sigma_text, file_name=f"{chosen_id}_sigma.yml")
        with rule_tabs[2]:
            st.caption(f"Validation: {rules.check_stix(json.loads(stix_text))}")
            st.code(stix_text, language="json")
            st.download_button("Download STIX bundle", stix_text, file_name=f"{chosen_id}_stix.json")

# --- Route map ------------------------------------------------------------
with TAB["Route Map"]:
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
with TAB["Export"]:
    export = {
        "tool": "Forensight",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "evidence": evidence_plain,
        "live_dns": live,
        "score": {"score": report.score, "verdict": report.verdict, "bonus": report.bonus,
                  "contributions": [asdict(c) for c in report.contributions],
                  "attack_techniques": {t: scoring.TECHNIQUES[t] for t in sorted(report.techniques)}},
        "summary": {level: sum(1 for f in findings if f["severity"] == level) for level in SEVERITY_ORDER},
        "findings": findings,
        "ai_analysis": st.session_state.get("ai") or analysis["injection"],
        "campaigns": [{**m, "strong": [list(p) for p in m["strong"]], "weak": [list(p) for p in m["weak"]]}
                      for m in matches],
        "modules": results,
        "errors": {section: error.strip().splitlines()[-1] for section, error in errors.items()},
    }
    export_json = json.dumps(export, indent=2, ensure_ascii=False, default=str)
    st.download_button("Download JSON report", export_json,
                       file_name=f"forensight_{Path(email_path).stem}.json", mime="application/json")
    st.json(export, expanded=False)
