"""Unit tests for the risk scoring and MITRE ATT&CK mapping module."""

import pytest

from forensight.scoring import map_techniques, score_findings, verdict_for


def finding(section, severity, title):
    return {"section": section, "severity": severity, "title": title}


def test_no_findings_is_clean():
    report = score_findings([])
    assert report.score == 0
    assert report.verdict == "Clean"


def test_points_follow_severity():
    report = score_findings([
        finding("Headers", "medium", "Organization-style name from free-mail address"),
        finding("Attachments", "low", "PDF contains a fillable form (/AcroForm)"),
    ])
    assert report.score == 12 + 4
    assert report.verdict == "Low risk"


def test_repeated_finding_counted_once():
    same = finding("Links & QR", "medium", "URL shortener hides the destination")
    report = score_findings([same] * 20)
    assert report.score == 12
    assert report.contributions[0].count == 20


def test_multi_module_bonus_and_cap():
    report = score_findings([
        finding("Headers", "high", "Reply-To differs from From"),
        finding("Domains", "high", "Typosquatting of paypal"),
        finding("Links & QR", "high", "Link text shows a different domain"),
        finding("Attachments", "high", "Double extension"),
    ])
    assert report.bonus == 10
    assert report.score == 100          # 4 x 30 + 10 = 130, capped at 100
    assert report.verdict == "Malicious"


@pytest.mark.parametrize("score, verdict", [
    (0, "Clean"), (9, "Clean"), (10, "Low risk"), (29, "Low risk"),
    (30, "Suspicious"), (59, "Suspicious"), (60, "Malicious"), (100, "Malicious"),
])
def test_verdict_thresholds(score, verdict):
    assert verdict_for(score) == verdict


@pytest.mark.parametrize("section, title, expected", [
    ("Attachments", "Right-to-left override in file name", {"T1566.001", "T1036.002"}),
    ("Attachments", "Double extension", {"T1566.001", "T1036.007"}),
    ("Attachments", "HTML attachment decodes or builds a file in the browser", {"T1566.001", "T1027.006"}),
    ("Links & QR", "URL shortener hides the destination", {"T1566.002"}),
    ("Domains", "Typosquatting of paypal", {"T1583.001", "T1656"}),
    ("Headers", "Organization-style name from free-mail address", {"T1585.002", "T1656"}),
])
def test_attack_mapping(section, title, expected):
    assert set(map_techniques(section, title)) == expected


def test_short_keyword_does_not_match_inside_words():
    # "iso" must not match inside "revision"
    assert "T1553.005" not in map_techniques("Headers", "Message revision mismatch")
    assert "T1553.005" in map_techniques("Attachments", "ISO disk image attachment")
