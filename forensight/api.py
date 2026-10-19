"""REST API: lets other tools (SOAR, ticketing, mail gateways) send emails to Forensight.

Endpoints:
    GET  /health                          service status
    POST /analyze        (file, ai)       full analysis as JSON: score, ATT&CK, findings, AI, campaigns
    POST /report         (file, ai)       the HTML forensic report (Section 21)
    GET  /campaigns                       list of known campaigns
    GET  /campaigns/{id}                  one campaign with its indicators and emails
    GET  /campaigns/{id}/rules/{kind}     YARA, Sigma or STIX rule for a campaign

Interactive documentation: http://127.0.0.1:8000/docs

Run from the project root (local machine only):
    uvicorn forensight.api:app --host 127.0.0.1 --port 8000

Security: the API listens on 127.0.0.1, accepts only .eml files up to 25 MB, stores each upload
under its SHA-256 hash, and can require an API key: set FORENSIGHT_API_KEY before starting it and
send the key in the X-API-Key header.
"""

import hashlib
import json
import os
import re
import secrets
from dataclasses import asdict
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Query, Security, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.security import APIKeyHeader

from forensight import matching, report, rules, scoring

VERSION = "1.0"
UPLOAD_DIR = Path("output") / "uploads"
CAMPAIGNS_FILE = matching.CAMPAIGNS_FILE
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
RULE_KINDS = {"yara": "text/plain", "sigma": "application/yaml", "stix": "application/json"}

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def check_api_key(key: str = Security(api_key_header)):
    """If FORENSIGHT_API_KEY is set, every request must send the same key (constant-time comparison)."""
    expected = os.environ.get("FORENSIGHT_API_KEY")
    if expected and not (key and secrets.compare_digest(key, expected)):
        raise HTTPException(status_code=401, detail="Missing or invalid API key")


app = FastAPI(title="Forensight API", version=VERSION,
              description="Automated phishing email forensics. Static analysis only: emails are never "
                          "opened in a mail client, links are never visited, attachments are never executed.",
              dependencies=[Depends(check_api_key)])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def save_upload(file: UploadFile) -> Path:
    """Check and store an uploaded email in a folder named after its SHA-256 hash.

    The original file name is kept, so an email from the dataset is recognised as a known campaign member.
    """
    name = file.filename or ""
    if not name.lower().endswith(".eml"):
        raise HTTPException(status_code=415, detail="Only .eml files are accepted")
    data = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File is larger than 25 MB")
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    folder = UPLOAD_DIR / hashlib.sha256(data).hexdigest()[:16]
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name)
    if not path.exists():
        path.write_bytes(data)
    return path


def to_json(data):
    """The analysis data from report.collect() as plain JSON."""
    score = data["score"]
    return {
        "evidence": data["evidence"],
        "score": score.score,
        "verdict": score.verdict,
        "score_breakdown": [asdict(c) for c in score.contributions],
        "multi_module_bonus": score.bonus,
        "attack_techniques": [{"id": t, "name": scoring.TECHNIQUES[t], "evidence": list(dict.fromkeys(titles))}
                              for t, titles in sorted(score.techniques.items())],
        "headers": data["headers"],
        "findings": data["findings"],
        "ai_analysis": data["social"],
        "campaigns": [{**m, "strong": [list(p) for p in m["strong"]], "weak": [list(p) for p in m["weak"]]}
                      for m in data["matches"]],
        "errors": data["errors"],
    }


def find_campaign(campaign_id):
    _, campaigns = matching.load_campaigns(CAMPAIGNS_FILE)
    for campaign in campaigns:
        if campaign["id"].upper() == campaign_id.upper():
            return campaign
    raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    _, campaigns = matching.load_campaigns(CAMPAIGNS_FILE)
    return {"status": "ok", "version": VERSION, "campaigns_loaded": len(campaigns)}


@app.post("/analyze")
def analyze(file: UploadFile = File(...), ai: bool = Query(False, description="Run the local language model")):
    """Analyse one .eml file and return the score, ATT&CK techniques, findings, AI analysis and campaigns."""
    path = save_upload(file)
    return to_json(report.collect(path, ai=ai, campaigns_file=CAMPAIGNS_FILE))


@app.post("/report", response_class=HTMLResponse)
def html_report(file: UploadFile = File(...), ai: bool = Query(False, description="Run the local language model")):
    """Analyse one .eml file and return the HTML forensic report."""
    path = save_upload(file)
    return HTMLResponse(report.render_html(report.collect(path, ai=ai, campaigns_file=CAMPAIGNS_FILE)))


@app.get("/campaigns")
def list_campaigns(limit: int = Query(50, ge=1, le=1000)):
    summary, campaigns = matching.load_campaigns(CAMPAIGNS_FILE)
    return {
        "summary": summary,
        "campaigns": [{"id": c["id"], "size": c["size"], "first_seen": c.get("first_seen"),
                       "last_seen": c.get("last_seen"), "indicators": c["indicators"][:3]}
                      for c in campaigns[:limit]],
    }


@app.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str):
    return find_campaign(campaign_id)


@app.get("/campaigns/{campaign_id}/rules/{kind}")
def get_rule(campaign_id: str, kind: str):
    """Detection rule for a campaign: kind is yara, sigma or stix."""
    if kind not in RULE_KINDS:
        raise HTTPException(status_code=400, detail="kind must be yara, sigma or stix")
    campaign = find_campaign(campaign_id)
    if kind == "yara":
        text = rules.yara_rules(campaign)
        if not text:
            raise HTTPException(status_code=404, detail="No text indicator to build a YARA rule")
    elif kind == "sigma":
        text = rules.sigma_rule(campaign)
    else:
        text = json.dumps(rules.stix_bundle(campaign), indent=2)
    return PlainTextResponse(text, media_type=RULE_KINDS[kind])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
