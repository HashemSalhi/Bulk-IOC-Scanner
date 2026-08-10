"""Tests for the risk scoring engine."""
from bulk_ioc_scanner.models.schemas import ProviderResult
from bulk_ioc_scanner.services.risk import compute_risk


def vt_result(mal, sus, harm, undet):
    return ProviderResult(
        provider="virustotal", ioc="x", ioc_type="md5", success=True,
        malicious=mal, suspicious=sus, harmless=harm, undetected=undet, raw={},
    )


def test_empty_is_low():
    score, band = compute_risk([])
    assert band == "Low"
    assert score == 0.0


def test_clean_is_low():
    score, band = compute_risk([vt_result(0, 0, 60, 10)])
    assert band == "Low"


def test_mostly_malicious_is_high():
    score, band = compute_risk([vt_result(60, 2, 5, 3)])
    assert band == "High"
    assert score > 70


def test_moderate_is_medium():
    score, band = compute_risk([vt_result(25, 5, 30, 10)])
    assert band == "Medium"
    assert 30 < score <= 70


def test_more_than_four_vt_malicious_is_at_least_medium():
    # 5/70 malicious is a low ratio (~7) that would score Low, but 5 vendors
    # agreeing should bump it to Medium.
    score, band = compute_risk([vt_result(5, 0, 60, 5)])
    assert band == "Medium"
    assert 30 < score <= 70


def test_exactly_four_vt_malicious_stays_low():
    # Threshold is "more than 4", so 4 flags with a low ratio remains Low.
    score, band = compute_risk([vt_result(4, 0, 60, 6)])
    assert band == "Low"


def test_many_vt_malicious_still_high():
    # A high ratio must still win over the Medium floor.
    score, band = compute_risk([vt_result(60, 0, 5, 5)])
    assert band == "High"
    assert score > 70


def test_abuseipdb_confidence_drives_score():
    pr = ProviderResult(
        provider="abuseipdb", ioc="1.2.3.4", ioc_type="ip", success=True,
        raw={"abuse_confidence_score": 82},
    )
    score, band = compute_risk([pr])
    assert score == 82.0
    assert band == "High"


def test_failed_results_ignored():
    failed = ProviderResult(
        provider="virustotal", ioc="x", ioc_type="md5", success=False,
        error="boom", raw={"error": "boom"},
    )
    score, band = compute_risk([failed])
    assert band == "Low"
    assert score == 0.0


def test_worst_case_wins_across_providers():
    clean_vt = vt_result(0, 0, 90, 0)
    abuse = ProviderResult(
        provider="abuseipdb", ioc="1.2.3.4", ioc_type="ip", success=True,
        raw={"abuse_confidence_score": 95},
    )
    score, band = compute_risk([clean_vt, abuse])
    assert score == 95.0
    assert band == "High"
