"""Unit tests for the lookalike domain detection module."""

import pytest

from forensight.lookalike import check_domain, edit_distance


def techniques(domain):
    return {(technique, brand) for technique, brand, _, _ in check_domain(domain)}


@pytest.mark.parametrize("domain, technique, brand", [
    ("xn--pypal-4ve.com", "Homograph (IDN) attack", "paypal"),      # Cyrillic 'а'
    ("paypa1.com", "Character substitution", "paypal"),             # 1 instead of l
    ("rnicrosoft.com", "Character substitution", "microsoft"),      # rn instead of m
    ("netfllx.com", "Typosquatting", "netflix"),                    # one character changed
    ("pexinterest.com", "Typosquatting", "pinterest"),              # two characters added
    ("paypal-secure-login.com", "Combosquatting", "paypal"),        # brand + other words
    ("itau-seguro.com.br", "Combosquatting", "itau"),
    ("paypal.com.evil.ru", "Brand in subdomain", "paypal"),         # brand as prefix
    ("dhl.de.securdeutsh.com", "Brand in subdomain", "dhl"),
    ("paypal.net", "Brand on a different TLD", "paypal"),
])
def test_detects_lookalikes(domain, technique, brand):
    assert (technique, brand) in techniques(domain)


@pytest.mark.parametrize("domain", [
    "paypal.com",               # official domain
    "mail.paypal.com",          # subdomain of an official domain
    "groups.google.com",        # 'ups' inside a word must not match
    "amazon.de",                # official regional domain
    "tenant.onmicrosoft.com",   # known legitimate infrastructure
    "mercadolivre.com.br",      # brand names are not typos of each other
    "example.com",
])
def test_no_false_positives(domain):
    assert check_domain(domain) == []


def test_edit_distance():
    assert edit_distance("paypal", "paypal") == 0
    assert edit_distance("paypal", "paypa") == 1      # deletion
    assert edit_distance("paypal", "payapl") == 1     # swap counts as one edit
    assert edit_distance("pinterest", "pexinterest") == 2


def test_detects_raw_unicode_homograph():
    # 'ҏ' is a Cyrillic letter that looks like the Latin 'p'
    assert ("Homograph (IDN) attack", "paypal") in techniques("ҏaypal.com")
