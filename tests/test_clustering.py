"""Unit tests for the campaign clustering module."""

import hashlib
from email.message import EmailMessage

import pytest

from forensight.clustering import cluster, extract_indicators, normalize_subject
from forensight.ingest import load_email


def test_shared_strong_indicator_links_emails():
    campaigns, _ = cluster({
        "a.eml": {("reply_to", "boss@evil.test")},
        "b.eml": {("reply_to", "boss@evil.test")},
        "c.eml": {("reply_to", "other@evil.test")},
    })
    assert campaigns == [{"a.eml", "b.eml"}]


def test_campaigns_are_linked_transitively():
    campaigns, _ = cluster({
        "a.eml": {("reply_to", "x@evil.test")},
        "b.eml": {("reply_to", "x@evil.test"), ("attachment", "hash1")},
        "c.eml": {("attachment", "hash1")},
    })
    assert campaigns == [{"a.eml", "b.eml", "c.eml"}]


def test_common_weak_indicator_is_ignored():
    emails = {f"{i}.eml": {("link_domain", "google.com")} for i in range(5)}
    campaigns, ignored = cluster(emails, max_weak=3)
    assert campaigns == []
    assert ("link_domain", "google.com") in ignored


def test_two_shared_weak_indicators_link_emails():
    emails = {f"{i}.eml": {("link_domain", "evil-login.top"), ("subject", "verify your account now")}
              for i in range(3)}
    campaigns, ignored = cluster(emails, max_weak=3)
    assert campaigns == [set(emails)]
    assert ignored == set()


def test_one_shared_weak_indicator_is_not_enough():
    # a single generic value must not chain unrelated emails together
    campaigns, _ = cluster({
        "a.eml": {("link_domain", "cdn-host.net"), ("subject", "invoice overdue")},
        "b.eml": {("link_domain", "cdn-host.net"), ("subject", "package delivery failed")},
    })
    assert campaigns == []


def test_strong_indicator_is_never_capped():
    emails = {f"{i}.eml": {("attachment", "samehash")} for i in range(10)}
    campaigns, _ = cluster(emails, max_weak=3)
    assert campaigns == [set(emails)]


@pytest.mark.parametrize("subject, expected", [
    ("RE: Fwd: Your account 88231 is suspended!", "your account is suspended"),
    ("Invoice #A7731 from PayPal", "invoice from paypal"),
])
def test_normalize_subject(subject, expected):
    assert normalize_subject(subject) == expected


def test_extract_indicators_from_email(tmp_path):
    msg = EmailMessage()
    msg["From"] = "Bank Support <support.bank77@gmail.com>"
    msg["Reply-To"] = "collect@evil-mailbox.xyz"
    msg["Subject"] = "Your account has been suspended 4471"
    msg["Date"] = "Wed, 26 Jul 2023 17:59:01 +0000"
    msg.set_content("Verify now: https://login.secure-bank.example.co.uk/verify?id=1")
    data = b"%PDF-1.7 fake invoice"
    msg.add_attachment(data, maintype="application", subtype="pdf", filename="invoice.pdf")
    msg.add_attachment(b"", maintype="application", subtype="octet-stream", filename="empty.bin")
    path = tmp_path / "test.eml"
    path.write_bytes(bytes(msg))

    indicators, date = extract_indicators(load_email(path))
    assert ("sender_address", "support.bank77@gmail.com") in indicators
    assert ("reply_to", "collect@evil-mailbox.xyz") in indicators
    assert ("subject", "your account has been suspended") in indicators
    assert ("link_domain", "example.co.uk") in indicators
    assert ("attachment", hashlib.sha256(data).hexdigest()) in indicators
    assert ("attachment", hashlib.sha256(b"").hexdigest()) not in indicators
    assert date.year == 2023


def test_date_without_time_zone_is_treated_as_utc(tmp_path):
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg["Date"] = "Wed, 26 Jul 2023 17:59:01 -0000"
    msg.set_content("hello")
    path = tmp_path / "naive.eml"
    path.write_bytes(bytes(msg))
    _, date = extract_indicators(load_email(path))
    assert date.tzinfo is not None


def test_placeholder_addresses_are_not_indicators(tmp_path):
    msg = EmailMessage()
    msg["From"] = "Support <no-reply@example.com>"
    msg["Reply-To"] = "no-reply@example.com"
    msg.set_content("Open https://www.example.org/login and https://real-phish.xyz/a")
    path = tmp_path / "placeholder.eml"
    path.write_bytes(bytes(msg))
    indicators, _ = extract_indicators(load_email(path))
    values = {value for _, value in indicators}
    assert not any("example" in value for value in values)
    assert ("link_domain", "real-phish.xyz") in indicators


def test_strong_indicator_cap_when_requested():
    emails = {f"{i}.eml": {("attachment", "logo")} for i in range(10)}
    campaigns, ignored = cluster(emails, max_strong=5)
    assert campaigns == []
    assert ("attachment", "logo") in ignored
