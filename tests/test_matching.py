"""Unit tests for matching a new email against known campaigns."""

import json

from forensight import matching

CAMPAIGNS = [
    {"id": "C001", "size": 10, "emails": ["a.eml", "b.eml"], "indicators": [
        {"type": "reply_to", "value": "collect@evil-mail.xyz", "emails": 10},
        {"type": "link_domain", "value": "fake-bank.top", "emails": 8},
    ]},
    {"id": "C002", "size": 40, "emails": ["c.eml"], "indicators": [
        {"type": "link_domain", "value": "promo-site.top", "emails": 30},
        {"type": "origin_ip", "value": "203.0.113.7", "emails": 25},
        {"type": "sender_domain", "value": "news-mail.top", "emails": 20},
    ]},
]


def test_one_strong_indicator_is_enough():
    found = matching.match_campaigns({("reply_to", "collect@evil-mail.xyz")}, CAMPAIGNS)
    assert [m["id"] for m in found] == ["C001"]
    assert found[0]["strong"] == [("reply_to", "collect@evil-mail.xyz")]


def test_two_weak_indicators_are_needed():
    one_weak = {("link_domain", "promo-site.top")}
    two_weak = one_weak | {("origin_ip", "203.0.113.7")}
    assert matching.match_campaigns(one_weak, CAMPAIGNS) == []
    assert [m["id"] for m in matching.match_campaigns(two_weak, CAMPAIGNS)] == ["C002"]


def test_known_member_is_listed_first():
    indicators = {("link_domain", "promo-site.top"), ("origin_ip", "203.0.113.7")}
    found = matching.match_campaigns(indicators, CAMPAIGNS, email_name="b.eml")
    assert [m["id"] for m in found] == ["C001", "C002"]
    assert found[0]["member"] and not found[1]["member"]


def test_load_campaigns_missing_and_present(tmp_path):
    assert matching.load_campaigns(tmp_path / "missing.json") == (None, [])
    path = tmp_path / "campaigns.json"
    path.write_text(json.dumps({"summary": {"campaigns": 2}, "campaigns": CAMPAIGNS}))
    summary, campaigns = matching.load_campaigns(path)
    assert summary == {"campaigns": 2} and len(campaigns) == 2
