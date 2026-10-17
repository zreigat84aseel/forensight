"""Detection rule generation: turns a phishing campaign into YARA, Sigma and STIX 2.1.

The campaign indicators found by the clustering module (Section 17) are converted into:
- a YARA rule that finds the campaign's emails (.eml files) and its attachments,
- a Sigma rule for email gateway or SIEM logs,
- a STIX 2.1 bundle to share the campaign as threat intelligence.

The linking logic is the same as in the clustering: one strong indicator, or two
different weak indicators, are required for a match.

Usage:
    python -m forensight.rules <campaign id> [--validate <email folder>]
"""

import json
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

CAMPAIGNS_FILE = Path("output") / "campaigns.json"
RULES_DIR = Path("output") / "rules"
MAX_PER_KIND = 4
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "forensight.local")

STRONG_TEXT = ("reply_to", "sender_address")          # strong indicators visible in the email text
WEAK_TEXT = ("sender_domain", "link_domain", "origin_ip")
SIGMA_FIELDS = {
    "reply_to": "reply_to",
    "sender_address": "sender",
    "attachment": "attachment_sha256",
    "sender_domain": "sender_domain",
    "link_domain": "url_domain",
    "origin_ip": "src_ip",
}
STIX_PATTERNS = {
    "reply_to": "[email-addr:value = '{}']",
    "sender_address": "[email-addr:value = '{}']",
    "attachment": "[file:hashes.'SHA-256' = '{}']",
    "sender_domain": "[domain-name:value = '{}']",
    "link_domain": "[domain-name:value = '{}']",
    "origin_ip": "[ipv4-addr:value = '{}']",
}


def load_campaign(campaign_id, path=CAMPAIGNS_FILE):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for campaign in data["campaigns"]:
        if campaign["id"].upper() == campaign_id.upper():
            return campaign
    raise KeyError(f"Campaign {campaign_id} not found in {path}")


def select_indicators(campaign):
    """Return (strong text, attachment hashes, weak text) indicators, most common first.

    Subjects are not used, because the clustering stores them in a normalized form
    that does not appear literally in the emails.
    """
    pick = lambda kinds: [(i["type"], i["value"]) for i in campaign["indicators"]
                          if i["type"] in kinds][:MAX_PER_KIND]
    return pick(STRONG_TEXT), pick(("attachment",)), pick(WEAK_TEXT)


def _pairs(names):
    return [(a, b) for i, a in enumerate(names) for b in names[i + 1:]]


def _date(value):
    if not value:
        return None
    return datetime.fromisoformat(value).astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# YARA
# ---------------------------------------------------------------------------

def _yara_string(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def yara_rules(campaign):
    """Return the YARA source for the campaign, or an empty string if nothing can be matched."""
    cid, size = campaign["id"], campaign["size"]
    strong, attachments, weak = select_indicators(campaign)
    period = f"{(campaign.get('first_seen') or '?')[:10]} to {(campaign.get('last_seen') or '?')[:10]}"
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    meta = [
        "    meta:",
        f'        description = "Phishing campaign {cid} ({size} emails, {period})"',
        '        author = "Forensight"',
        f'        date = "{today}"',
    ]
    out = []

    if strong or len(weak) >= 1:
        lines = [f"rule Forensight_Campaign_{cid}_Email", "{"] + meta + ["    strings:"]
        expressions, weak_names = [], []
        for number, (kind, value) in enumerate(strong, start=1):
            lines.append(f'        $s{number} = "{_yara_string(value)}" ascii wide nocase  // {kind}')
            lines.append(f'        $s{number}_b64 = "{_yara_string(value)}" base64')
            expressions.append(f"($s{number} or $s{number}_b64)")
        for number, (kind, value) in enumerate(weak, start=1):
            lines.append(f'        $w{number} = "{_yara_string(value)}" ascii wide nocase  // {kind}')
            lines.append(f'        $w{number}_b64 = "{_yara_string(value)}" base64')
            weak_names.append(f"($w{number} or $w{number}_b64)")
        pairs = [f"({a} and {b})" for a, b in _pairs(weak_names)]
        if not expressions and not pairs:
            pairs = weak_names            # only one weak indicator: low confidence
        lines += ["    condition:", "        filesize < 20MB and (",
                  "            " + "\n            or ".join(expressions + pairs), "        )", "}"]
        out.append("\n".join(lines))

    if attachments:
        lines = [f"rule Forensight_Campaign_{cid}_Attachment", "{"] + meta + ["    condition:"]
        checks = [f'hash.sha256(0, filesize) == "{value.lower()}"' for _, value in attachments]
        lines.append("        " + "\n        or ".join(checks))
        lines.append("}")
        out.append("\n".join(lines))

    if not out:
        return ""
    header = 'import "hash"\n\n' if attachments else ""
    return header + "\n\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Sigma
# ---------------------------------------------------------------------------

def sigma_rule(campaign):
    cid = campaign["id"]
    strong, attachments, weak = select_indicators(campaign)
    detection, strong_names, weak_names = {}, [], []
    for number, (kind, value) in enumerate(strong + attachments, start=1):
        name = f"strong_{number}"
        detection[name] = {SIGMA_FIELDS[kind]: value}
        strong_names.append(name)
    for number, (kind, value) in enumerate(weak, start=1):
        name = f"weak_{number}"
        field = SIGMA_FIELDS[kind] + ("|endswith" if kind in ("link_domain", "sender_domain") else "")
        detection[name] = {field: value}
        weak_names.append(name)
    pairs = [f"({a} and {b})" for a, b in _pairs(weak_names)]
    if not strong_names and not pairs:
        pairs = weak_names
    detection["condition"] = " or ".join(strong_names + pairs)

    tags = ["attack.initial-access", "attack.t1566"]
    if attachments:
        tags.append("attack.t1566.001")
    if any(kind == "link_domain" for kind, _ in weak):
        tags.append("attack.t1566.002")
    rule = {
        "title": f"Forensight Phishing Campaign {cid}",
        "id": str(uuid.uuid5(NAMESPACE, f"sigma:{cid}:{json.dumps(campaign['indicators'])}")),
        "status": "experimental",
        "description": (f"Detects emails of phishing campaign {cid} ({campaign['size']} emails) "
                        "using the indicators shared by its emails."),
        "author": "Forensight",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "tags": tags,
        "logsource": {"category": "email"},
        "detection": detection,
        "fields": ["sender", "reply_to", "subject", "url_domain", "attachment_sha256"],
        "falsepositives": ["Legitimate emails that use the same domains or mail infrastructure"],
        "level": "high" if strong_names else "medium",
    }
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------

def _stix_time(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _stix_value(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_bundle(campaign):
    cid = campaign["id"]
    now = _stix_time(datetime.now(timezone.utc))
    strong, attachments, weak = select_indicators(campaign)
    identity_id = f"identity--{uuid.uuid5(NAMESPACE, 'identity:forensight')}"
    campaign_id = f"campaign--{uuid.uuid5(NAMESPACE, 'campaign:' + json.dumps(campaign['emails']))}"
    attack_id = f"attack-pattern--{uuid.uuid5(NAMESPACE, 'attack:T1566')}"
    common = {"spec_version": "2.1", "created": now, "modified": now}

    campaign_object = {
        "type": "campaign", "id": campaign_id, **common, "created_by_ref": identity_id,
        "name": f"Forensight phishing campaign {cid}",
        "description": f"Phishing campaign of {campaign['size']} emails grouped by shared indicators.",
    }
    first, last = _date(campaign.get("first_seen")), _date(campaign.get("last_seen"))
    if first:
        campaign_object["first_seen"] = _stix_time(first)
    if last:
        campaign_object["last_seen"] = _stix_time(last)

    objects = [
        {"type": "identity", "id": identity_id, **common, "name": "Forensight", "identity_class": "system"},
        campaign_object,
        {"type": "attack-pattern", "id": attack_id, **common, "name": "Phishing",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1566",
                                  "url": "https://attack.mitre.org/techniques/T1566/"}]},
        {"type": "relationship", "id": f"relationship--{uuid.uuid4()}", **common,
         "relationship_type": "uses", "source_ref": campaign_id, "target_ref": attack_id},
    ]
    for kind, value in strong + attachments + weak:
        indicator_id = f"indicator--{uuid.uuid5(NAMESPACE, f'{kind}:{value}')}"
        objects.append({
            "type": "indicator", "id": indicator_id, **common, "created_by_ref": identity_id,
            "name": f"{kind}: {value}", "indicator_types": ["malicious-activity"],
            "pattern": STIX_PATTERNS[kind].format(_stix_value(value)), "pattern_type": "stix",
            "valid_from": now,
        })
        objects.append({
            "type": "relationship", "id": f"relationship--{uuid.uuid4()}", **common,
            "relationship_type": "indicates", "source_ref": indicator_id, "target_ref": campaign_id,
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def run_yara(rule_text, files):
    """Return the set of file names matched by the email rule (None if YARA is not available)."""
    files = [Path(f) for f in files]
    try:
        import yara
        rules = yara.compile(source=rule_text)
        return {f.name for f in files
                if any(m.rule.endswith("_Email") for m in rules.match(str(f)))}
    except ImportError:
        pass
    if not shutil.which("yara"):
        return None
    rule_file = RULES_DIR / "_validate.yar"
    rule_file.parent.mkdir(parents=True, exist_ok=True)
    rule_file.write_text(rule_text, encoding="utf-8")
    folders = {f.parent for f in files}
    matched = set()
    for folder in folders:
        result = subprocess.run(["yara", "-r", str(rule_file), str(folder)],
                                capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            rule, _, path = line.partition(" ")
            if rule.endswith("_Email"):
                matched.add(Path(path).name)
    rule_file.unlink()
    return matched & {f.name for f in files}


def check_sigma(text):
    """Parse the Sigma rule with pySigma if it is installed, otherwise check its structure."""
    try:
        from sigma.rule import SigmaRule
        SigmaRule.from_yaml(text)
        return "valid (pySigma)"
    except ImportError:
        rule = yaml.safe_load(text)
        missing = {"title", "id", "logsource", "detection"} - set(rule)
        return "valid (structure)" if not missing and "condition" in rule["detection"] else "invalid"


def check_stix(bundle):
    try:
        import stix2
        stix2.parse(bundle, allow_custom=False)
        return "valid (stix2)"
    except ImportError:
        ok = all("--" in obj["id"] and obj.get("spec_version") == "2.1" for obj in bundle["objects"])
        return "valid (structure)" if ok else "invalid"


def generate(campaign_id, validate_folder=None):
    campaign = load_campaign(campaign_id)
    cid = campaign["id"]
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    yara_text, sigma_text, bundle = yara_rules(campaign), sigma_rule(campaign), stix_bundle(campaign)
    paths = {"yara": RULES_DIR / f"{cid}.yar", "sigma": RULES_DIR / f"{cid}_sigma.yml",
             "stix": RULES_DIR / f"{cid}_stix.json"}
    if yara_text:
        paths["yara"].write_text(yara_text, encoding="utf-8")
    paths["sigma"].write_text(sigma_text, encoding="utf-8")
    paths["stix"].write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    strong, attachments, weak = select_indicators(campaign)
    line = "=" * 72
    out = [line, f"FORENSIGHT - Detection Rules for Campaign {cid}", line,
           f"Campaign size: {campaign['size']} emails",
           f"Indicators used: {len(strong)} strong, {len(attachments)} attachment hashes, {len(weak)} weak", ""]
    for kind, value in strong + attachments + weak:
        out.append(f"  {kind:<15} {value[:60]}")
    out.append("")
    out.append(f"YARA:  {paths['yara'] if yara_text else '(no text indicators)'}")
    out.append(f"Sigma: {paths['sigma']}  -> {check_sigma(sigma_text)}")
    out.append(f"STIX:  {paths['stix']}  -> {check_stix(bundle)} "
               f"({len(bundle['objects'])} objects)")

    if validate_folder and yara_text:
        files = sorted(Path(validate_folder).expanduser().glob("*.eml"))
        matched = run_yara(yara_text, files)
        if matched is None:
            out.append("\nYARA validation skipped: install YARA (sudo apt install yara)")
        else:
            members = set(campaign["emails"])
            hit, other = len(matched & members), len(matched - members)
            out += ["", "YARA validation on the dataset:",
                    f"  campaign emails matched:   {hit}/{len(members)} ({hit / len(members):.1%})",
                    f"  other emails matched:      {other}/{len(files) - len(members)}"]
    out.append(line)
    return "\n".join(out)


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 1:
        print(generate(args[0]))
    elif len(args) == 3 and args[1] == "--validate":
        print(generate(args[0], args[2]))
    else:
        print("Usage: python -m forensight.rules <campaign id> [--validate <email folder>]")
        sys.exit(1)
