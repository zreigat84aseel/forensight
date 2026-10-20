<p align="center">
  <img src="docs/images/banner.png" alt="Forensight: Automated Phishing Email Forensics & Campaign Analysis" width="100%">
</p>

<p align="center">
  <a href="https://github.com/zreigat84aseel/forensight/actions/workflows/ci.yml"><img src="https://github.com/zreigat84aseel/forensight/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.14-0a0a0e?logo=python&logoColor=white" alt="Python 3.14">
  <img src="https://img.shields.io/badge/tests-114%20passed-1b7a3b" alt="114 tests">
  <img src="https://img.shields.io/badge/docker-ready-0a0a0e?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-e0261d" alt="MITRE ATT&CK">
  <img src="https://img.shields.io/badge/license-MIT-555" alt="MIT License">
</p>

<p align="center">
  <b>Treat every suspicious email as digital evidence, and get a full, explainable investigation in one pass.</b><br>
  Static analysis only: no link is ever visited and no attachment is ever executed.
</p>

---

## Why Forensight?

When a user reports a suspicious email, a SOC analyst still does most of the work by hand: reading raw headers, tracing mail servers, checking SPF/DKIM/DMARC, inspecting links and attachments, and searching several separate tools. It is slow, inconsistent between analysts, and evidence handling is often informal.

**Forensight** automates the whole investigation. It traces where an email came from, verifies who really sent it, unmasks lookalike domains, deceptive links, hidden QR codes and disguised attachments, reads the social engineering with a **local** AI model hardened against prompt injection, scores the risk in **MITRE ATT&CK** terms, links emails into **campaigns**, and turns each campaign into ready-to-deploy **YARA, Sigma and STIX 2.1** rules.

> Built in one month during the **CyberFox Society Cybersecurity R&D Internship** (Digital Forensics & Incident Response track).

## Highlights

| | |
|---|---|
| **8,614 / 8,614** | real phishing emails processed with zero failures and verified evidence integrity |
| **38,316** | links extracted and analyzed without visiting a single one |
| **1,135 → 22** | lookalike-domain alerts after tuning; all 22 confirmed as genuine impersonation |
| **859 campaigns** | uncovered from 4,698 emails; largest false group reduced from 6,236 to 174 |
| **57 / 58** | campaign emails caught by an auto-generated YARA rule, with **0** false matches in the rest of the dataset |
| **6 / 6** | hidden prompt-injection attacks detected before reaching the model |
| **0.01 s** | average analysis time per email (without the language model) |

## Features

| Layer | Capability |
|---|---|
| 🧾 **Evidence** | MD5 / SHA-1 / SHA-256 hashing, chain-of-custody log (JSONL), integrity re-verification after every analysis |
| 📨 **Header forensics** | Delivery-path reconstruction, originating IP, timeline anomalies ("time travel", impossible dates), Reply-To / Return-Path / Message-ID mismatches, display-name spoofing |
| 🔐 **Authentication** | Recorded SPF/DKIM/DMARC results **plus** independent re-verification and alignment checks (catches emails that *pass* authentication while impersonating a brand) |
| 🎭 **Lookalike domains** | Homographs (IDN / Punycode), character substitution, typosquatting, combosquatting, brand-in-subdomain, brand-on-other-TLD, using the Public Suffix List |
| 🔗 **Links & QR codes** | Deceptive link text, the `@` trick, IP links, shorteners, free hosting, embedded forms, and links **decoded from QR-code images** (quishing) |
| 📎 **Attachments** | Real file type from magic bytes, RTLO and double extensions, Office macros (oletools), PDF actions and links, HTML smuggling and credential pages, ZIP inspection, signed Apple configuration profiles, all in memory |
| 🗺️ **Route map** | Interactive world map of the delivery path with **offline** GeoIP/ASN lookups (no investigation data leaves the machine) |
| 📊 **Risk score** | Explainable 0–100 score where every point is traced to a finding, mapped to 16 MITRE ATT&CK techniques |
| 🕸️ **Campaign clustering** | Union-find graph clustering on strong/weak indicators, with protection against the chaining effect; new emails are matched to known campaigns |
| 🤖 **Local AI analysis** | Social-engineering tactics (urgency, threat, reward, authority, credential requests) via **Ollama + Qwen2.5** on your own machine, with five prompt-injection defenses and quote-verified evidence |
| 🛡️ **Detection rules** | YARA (incl. Base64 and UTF-16 variants), Sigma and STIX 2.1 per campaign, validated with yara, pySigma and the official stix2 library |
| 🖥️ **Delivery** | Streamlit dashboard, self-contained HTML forensic report, FastAPI REST API, Docker image, GitHub Actions CI |

## Screenshots

<table>
<tr>
<td width="50%"><img src="docs/images/dashboard-overview.png" alt="Dashboard overview"><br><sub><b>Dashboard</b>: score, verdict and a campaign alert for a known campaign member</sub></td>
<td width="50%"><img src="docs/images/dashboard-risk-score.png" alt="Risk score"><br><sub><b>Explainable score</b>: every point traced to a finding and an ATT&CK technique</sub></td>
</tr>
<tr>
<td><img src="docs/images/dashboard-ai-injection.png" alt="Prompt injection"><br><sub><b>Prompt injection</b>: hidden instructions detected and never sent to the model</sub></td>
<td><img src="docs/images/route-map.png" alt="Route map"><br><sub><b>Route map</b>: Gmail → Microsoft delivery path with offline GeoIP</sub></td>
</tr>
<tr>
<td><img src="docs/images/qr-code-phishing.png" alt="QR code phishing"><br><sub><b>Quishing</b>: a lookalike Microsoft link decoded from a QR-code image</sub></td>
<td><img src="docs/images/homograph-detection.png" alt="Homograph"><br><sub><b>Homograph attack</b>: a Cyrillic "ҏ" imitating PayPal</sub></td>
</tr>
<tr>
<td><img src="docs/images/apple-profiles-attachment.png" alt="Apple profiles"><br><sub><b>Attachments</b>: signed Apple configuration profiles disguised as calendar invites</sub></td>
<td><img src="docs/images/campaign-clustering.png" alt="Campaign clustering"><br><sub><b>Campaigns</b>: 859 campaigns found across 8,614 emails</sub></td>
</tr>
<tr>
<td><img src="docs/images/yara-rule.png" alt="YARA rule"><br><sub><b>Generated YARA rule</b>: one strong or two weak indicators, with Base64 variants</sub></td>
<td><img src="docs/images/html-report.png" alt="HTML report"><br><sub><b>HTML forensic report</b>: escaped, non-clickable, and locked down with a CSP</sub></td>
</tr>
</table>

## How it works

```mermaid
flowchart LR
    A[".eml file"] --> B["Evidence<br/>hash + custody log"]
    B --> C["Headers"]
    B --> D["Authentication"]
    B --> E["Lookalike domains"]
    B --> F["Links & QR codes"]
    B --> G["Attachments"]
    B --> H["Local AI<br/>+ injection checks"]
    C & D & E & F & G & H --> I["Explainable risk score<br/>MITRE ATT&CK"]
    I --> J["Campaign matching"]
    J --> K["YARA · Sigma · STIX"]
    I --> L["Dashboard · HTML report · REST API"]
```

All modules run through one shared pipeline (`forensight/pipeline.py`), so the CLI, dashboard, report and API always return exactly the same result.

## Quick start

### Option 1: Docker (recommended)

```bash
git clone https://github.com/zreigat84aseel/forensight.git
cd forensight
docker-compose up -d --build
```

- Dashboard: <http://127.0.0.1:8501>
- API docs: <http://127.0.0.1:8000/docs>

The containers run as a non-root user with all capabilities dropped, and the email samples and GeoIP databases are mounted **read-only**.

### Option 2: Local installation

```bash
sudo apt install -y python3-venv libmagic1 libzbar0 libgl1 libglib2.0-0 yara
git clone https://github.com/zreigat84aseel/forensight.git
cd forensight
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

**Optional: offline GeoIP for the route map** (free DB-IP Lite databases, CC BY 4.0):

```bash
mkdir -p ~/geoip && cd ~/geoip
M=$(date +%Y-%m)
wget -O city.mmdb.gz "https://download.db-ip.com/free/dbip-city-lite-$M.mmdb.gz"
wget -O asn.mmdb.gz  "https://download.db-ip.com/free/dbip-asn-lite-$M.mmdb.gz"
gunzip -c city.mmdb.gz > dbip-city-lite.mmdb && gunzip -c asn.mmdb.gz > dbip-asn-lite.mmdb
```

**Optional: local AI analysis** with [Ollama](https://ollama.com):

```bash
ollama pull qwen2.5:3b
```

## Usage

### Dashboard

```bash
streamlit run dashboard.py
```

### Command line

| Task | Command |
|---|---|
| Acquire evidence (hashes + custody log) | `python -m forensight.ingest email.eml` |
| Header forensics | `python -m forensight.headers email.eml` |
| SPF / DKIM / DMARC | `python -m forensight.auth email.eml` |
| Lookalike domains | `python -m forensight.lookalike email.eml` |
| Links and QR codes | `python -m forensight.urls email.eml` |
| Attachments | `python -m forensight.attachments email.eml` |
| Route map | `python -m forensight.routemap email.eml` |
| Social-engineering analysis | `python -m forensight.social email.eml` |
| Risk score (add `--ai` for the model) | `python -m forensight.scoring email.eml` |
| Statistics for a whole folder | `python -m forensight.scoring --stats <folder>` |
| Campaign clustering | `python -m forensight.clustering <folder>` |
| YARA / Sigma / STIX for a campaign | `python -m forensight.rules C008 --validate <folder>` |
| HTML forensic report | `python -m forensight.report email.eml [--ai]` |
| Evaluation | `python -m forensight.evaluate --phish <folder> --ham <folder>` |

The `auth`, `lookalike`, `urls`, `attachments` and `scoring` modules also accept `--stats <folder>` to analyze a whole dataset.

### REST API

```bash
uvicorn forensight.api:app --host 127.0.0.1 --port 8000
```

| Method | Endpoint | Returns |
|---|---|---|
| `GET` | `/health` | Service status |
| `POST` | `/analyze` | Full analysis as JSON (score, ATT&CK, findings, AI, campaigns) |
| `POST` | `/report` | HTML forensic report |
| `GET` | `/campaigns` | Known campaigns |
| `GET` | `/campaigns/{id}` | One campaign with its indicators |
| `GET` | `/campaigns/{id}/rules/{yara\|sigma\|stix}` | Detection rule for a campaign |

```bash
curl -F "file=@email.eml" http://127.0.0.1:8000/analyze
```

Set `FORENSIGHT_API_KEY` to require an `X-API-Key` header (compared in constant time). Only `.eml` files up to 25 MB are accepted.

## Security by design

- **Static analysis only.** Links are never visited, attachments are never opened or executed; everything is analyzed in memory.
- **Evidence integrity.** Every email is hashed on acquisition and re-verified after analysis; every action is written to a chain-of-custody log.
- **Offline by default.** GeoIP lookups are local, live DNS checks are opt-in, and the language model runs on your machine, so no investigation data reaches a third party (OPSEC).
- **Prompt-injection defenses.** Hidden text is detected and never sent to the model, the email is wrapped in random markers, output is schema-constrained, and every AI claim must quote the email.
- **Safe outputs.** The dashboard and report never render attacker content as links or HTML; the report blocks all scripts and external resources with a Content-Security-Policy.
- **Least privilege.** Services listen on `127.0.0.1`; containers run non-root with `cap_drop: ALL` and read-only evidence mounts; CI has read-only repository access.
- **No samples in Git.** `.gitignore` and `.dockerignore` exclude every `.eml` and `.msg` file.

## Evaluation

Evaluated on **8,615 phishing emails** ([phishing_pot](https://github.com/rf-peixoto/phishing_pot)) and **2,750 legitimate emails** ([SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/)), plus a 12-email prompt-injection test set.

<p align="center"><img src="docs/images/evaluation.png" alt="Evaluation results" width="100%"></p>

| Threshold | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| 10 (Low risk) | 70.4% | 74.8% | 72.5% | 98.6% |
| 30 (Suspicious) | 65.3% | 39.0% | 48.8% | 65.0% |
| 60 (Malicious) | 41.9% | 8.6% | 14.3% | 37.5% |

**Honest reading of the numbers.** The legitimate corpus dates from 2002, before DKIM (2007) and DMARC (2012) existed, so every legitimate email triggers the authentication findings, and mailing lists legitimately rewrite Return-Path and Sender. An ablation without these checks cut the false-positive rate at threshold 30 from 65.0% to 26.5%, but also cut recall at threshold 10 from 74.8% to 35.5%. The checks carry real signal on modern phishing; a fair false-positive rate needs a modern legitimate dataset. The score is designed as an **explainable triage aid**, not a calibrated classifier, and its thresholds were deliberately not tuned on the test data.

## Project structure

```
forensight/
├── forensight/
│   ├── ingest.py        # evidence acquisition, hashing, chain of custody
│   ├── headers.py       # delivery path, origin IP, identity checks
│   ├── auth.py          # SPF / DKIM / DMARC
│   ├── lookalike.py     # lookalike domain detection
│   ├── urls.py          # links and QR codes
│   ├── attachments.py   # static attachment analysis
│   ├── routemap.py      # offline GeoIP route map
│   ├── social.py        # local AI analysis + prompt-injection defenses
│   ├── pipeline.py      # shared analysis pipeline
│   ├── scoring.py       # explainable risk score + ATT&CK mapping
│   ├── clustering.py    # campaign clustering
│   ├── matching.py      # match new emails to known campaigns
│   ├── rules.py         # YARA, Sigma, STIX 2.1 generation
│   ├── report.py        # HTML forensic report
│   ├── api.py           # FastAPI REST API
│   └── evaluate.py      # evaluation and ablation
├── tests/               # 114 automated tests
├── dashboard.py         # Streamlit dashboard
├── Dockerfile
├── docker-compose.yml
└── .github/workflows/ci.yml
```

## Testing

```bash
python -m pytest tests/ -q
```

114 tests cover every module. Tests never visit a URL or execute an attachment; the language model and GeoIP databases are mocked so the suite runs anywhere. GitHub Actions runs the full suite and a Docker build on every push and pull request.

## Roadmap

- Evaluation against a modern legitimate email dataset
- Lower weights for mailing-list header mismatches
- Similarity-based campaign linking (e.g. `socialja.com` ↔ `socialou.com`)
- Comparison with existing phishing-analysis tools

## Acknowledgements

- **CyberFox Society**, for the Cybersecurity R&D Internship and its guidance
- **[phishing_pot](https://github.com/rf-peixoto/phishing_pot)** by R. Peixoto and the **SpamAssassin public corpus**, for the datasets
- **[DB-IP](https://db-ip.com)**, for the free IP geolocation databases (CC BY 4.0)
- **[MITRE ATT&CK](https://attack.mitre.org)**, **MITRE ATLAS** and the **OWASP Top 10 for LLM Applications**
- The open-source projects Forensight builds on: dnspython, pyspf, dkimpy, tldextract, OpenCV, oletools, maxminddb, folium, Ollama, Qwen2.5, YARA, pySigma, stix2, Streamlit and FastAPI

## Disclaimer

Forensight is a research and educational project. Use it only on emails you are authorized to analyze, inside an isolated environment. Malicious samples are never included in this repository.

## License

Released under the [MIT License](LICENSE).

<p align="center"><sub>Made by <b>Aseel Zreigat</b> · CyberFox Society R&D Internship · 2026</sub></p>
