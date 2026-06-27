"""Tests for IOC type detection and defang normalization."""
import pytest

from app.services.ioc_detect import detect, parse_bulk_input, refang


@pytest.mark.parametrize("ioc,expected", [
    ("44d88612fea8a8f36de82e1278abb02f", "md5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
    ("8.8.8.8", "ip"),
    ("192.168.1.1/24", "cidr"),
    ("example.com", "domain"),
    ("sub.domain.co.uk", "domain"),
    ("https://evil.example.com/path?q=1", "url"),
    ("http://bad.test", "url"),
    ("not a valid ioc!!", "unknown"),
    ("", "unknown"),
    ("   ", "unknown"),
])
def test_detect_clean(ioc, expected):
    assert detect(ioc) == expected


@pytest.mark.parametrize("ioc,expected", [
    ("8[.]8[.]8[.]8", "ip"),
    ("evil(.)com", "domain"),
    ("hxxps://malware.example/x", "url"),
    ("hxxp[://]bad[.]test", "url"),
    ("bad[dot]domain[dot]com", "domain"),
])
def test_detect_defanged(ioc, expected):
    assert detect(ioc) == expected


@pytest.mark.parametrize("ioc,expected", [
    ("attacker@evil.com", "email"),
    ("user[at]bad[.]com", "email"),
    ("CVE-2021-44228", "cve"),
    ("cve-2014-0160", "cve"),
    ("AS15169", "asn"),
    ("ASN13335", "asn"),
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "crypto"),     # BTC legacy
    ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "crypto"),  # BTC bech32
    ("0x32Be343B94f860124dC4fEe278FDCBD38C102D88", "crypto"),  # ETH
    ("192.168.0.0/24", "cidr"),
    ("8.8.8.8", "ip"),
])
def test_detect_extended_types(ioc, expected):
    assert detect(ioc) == expected


@pytest.mark.parametrize("ioc,expected", [
    ("8[.]8[.]8[.]8", "8.8.8.8"),
    ("evil(.)com", "evil.com"),
    ("hxxps://bad/x", "https://bad/x"),
    ("hxxp[://]bad[.]test", "http://bad.test"),
])
def test_refang(ioc, expected):
    assert refang(ioc) == expected


def test_refang_does_not_corrupt_substrings():
    # 'hxxp' should only be replaced at the scheme start, not mid-string
    assert refang("myhxxpsite.com") == "myhxxpsite.com"


def test_parse_bulk_input_splits_newline_and_comma():
    text = "8.8.8.8,example.com\nevil.com, 1.2.3.4\n\n"
    assert parse_bulk_input(text) == ["8.8.8.8", "example.com", "evil.com", "1.2.3.4"]


def test_parse_bulk_input_empty():
    assert parse_bulk_input("   \n  ,  ") == []
