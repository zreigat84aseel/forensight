"""Unit tests for YARA, Sigma and STIX rule generation."""

import base64
import json

import pytest
import yaml

from forensight import rules

CAMPAIGN = {
    "id": "C900", "size": 3,
    "first_seen": "2026-01-24T10:00:00+00:00", "last_seen": "2026-03-24T18:30:00+02:00",
    "indicators": [
        {"type": "reply_to", "value": "collect@evil-mail.xyz", "emails": 3},
        {"type": "attachment", "value": "AB" * 32, "emails": 2},
        {"type": "link_domain", "value": "fake-bank.top", "emails": 3},
        {"type": "origin_ip", "value": "203.0.113.7", "emails": 2},
        {"type": "subject", "value": "your account is suspended", "emails": 3},
    ],
    "emails": ["a.eml", "b.eml", "c.eml"],
}
WEAK_ONLY = {**CAMPAIGN, "id": "C901", "indicators": [
    {"type": "link_domain", "value": "fake-bank.top", "emails": 3},
    {"type": "sender_domain", "value": "bank-alerts.top", "emails": 3},
]}


def yara_available():
    try:
        import yara  # noqa: F401
        return True
    except ImportError:
        return rules.shutil.which("yara") is not None


def test_subjects_are_not_used_in_rules():
    strong, attachments, weak = rules.select_indicators(CAMPAIGN)
    used = {kind for kind, _ in strong + attachments + weak}
    assert "subject" not in used
    assert used == {"reply_to", "attachment", "link_domain", "origin_ip"}


def test_yara_rule_contains_indicators_and_logic():
    text = rules.yara_rules(CAMPAIGN)
    assert 'import "hash"' in text
    assert "rule Forensight_Campaign_C900_Email" in text
    assert '$s1 = "collect@evil-mail.xyz" ascii wide nocase' in text
    assert '$s1_b64 = "collect@evil-mail.xyz" base64' in text
    assert "(($w1 or $w1_b64) and ($w2 or $w2_b64))" in text
    assert 'hash.sha256(0, filesize) == "' + "ab" * 32 + '"' in text


def test_yara_escapes_quotes():
    campaign = {**WEAK_ONLY, "indicators": [{"type": "link_domain", "value": 'ev"il.top', "emails": 2}]}
    assert 'ev\\"il.top' in rules.yara_rules(campaign)


@pytest.mark.skipif(not yara_available(), reason="YARA is not installed")
def test_yara_rule_matches_like_the_clustering(tmp_path):
    files = {
        "strong.eml": b"Reply-To: collect@evil-mail.xyz\n\nHello",
        "two_weak.eml": b"Received: from x ([203.0.113.7])\n\nVisit https://fake-bank.top/login",
        "one_weak.eml": b"Visit https://fake-bank.top/login",
        "base64.eml": b"Content-Transfer-Encoding: base64\n\n"
                      + base64.b64encode(b"Please answer to collect@evil-mail.xyz today"),
        "clean.eml": b"Hello, see you tomorrow",
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    matched = rules.run_yara(rules.yara_rules(CAMPAIGN), sorted(tmp_path.glob("*.eml")))
    assert matched == {"strong.eml", "two_weak.eml", "base64.eml"}


def test_sigma_rule_structure():
    rule = yaml.safe_load(rules.sigma_rule(CAMPAIGN))
    detection = rule["detection"]
    assert detection["strong_1"] == {"reply_to": "collect@evil-mail.xyz"}
    assert detection["weak_1"] == {"url_domain|endswith": "fake-bank.top"}
    assert detection["condition"] == "strong_1 or strong_2 or (weak_1 and weak_2)"
    assert rule["level"] == "high"
    assert {"attack.t1566", "attack.t1566.001", "attack.t1566.002"} <= set(rule["tags"])


def test_sigma_rule_is_valid():
    assert rules.check_sigma(rules.sigma_rule(CAMPAIGN)).startswith("valid")
    assert rules.check_sigma(rules.sigma_rule(WEAK_ONLY)).startswith("valid")


def test_stix_bundle_links_indicators_to_campaign():
    bundle = rules.stix_bundle(CAMPAIGN)
    types = [obj["type"] for obj in bundle["objects"]]
    assert types.count("indicator") == 4
    campaign = next(o for o in bundle["objects"] if o["type"] == "campaign")
    assert campaign["last_seen"] == "2026-03-24T16:30:00.000Z"      # converted to UTC
    patterns = {o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"}
    assert "[email-addr:value = 'collect@evil-mail.xyz']" in patterns
    assert "[file:hashes.'SHA-256' = '" + "AB" * 32 + "']" in patterns
    indicates = [o for o in bundle["objects"] if o.get("relationship_type") == "indicates"]
    assert len(indicates) == 4 and all(r["target_ref"] == campaign["id"] for r in indicates)
    assert rules.check_stix(bundle).startswith("valid")


def test_generate_writes_three_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "output").mkdir()
    (tmp_path / "output" / "campaigns.json").write_text(json.dumps({"campaigns": [CAMPAIGN]}))
    report = rules.generate("c900")
    for name in ("C900.yar", "C900_sigma.yml", "C900_stix.json"):
        assert (tmp_path / "output" / "rules" / name).exists()
    assert "Campaign size: 3 emails" in report
