"""Compute a normalised 0-100 risk score from provider results."""
from app.models.schemas import ProviderResult


def compute_risk(provider_results: list[ProviderResult]) -> tuple[float, str]:
    """
    Returns (score: float 0-100, band: "Low" | "Medium" | "High").
    Aggregates across all successful provider results.
    """
    if not provider_results:
        return 0.0, "Low"

    scores: list[float] = []

    for pr in provider_results:
        if not pr.success:
            continue

        # VirusTotal-style: malicious/total ratio
        if pr.malicious is not None:
            total = (pr.malicious or 0) + (pr.suspicious or 0) + (pr.harmless or 0) + (pr.undetected or 0)
            if total > 0:
                ratio = pr.malicious / total
                # Suspicious counts half
                sus_ratio = (pr.suspicious or 0) / total * 0.5
                vt_score = min((ratio + sus_ratio) * 100, 100)
                scores.append(vt_score)

        # AbuseIPDB-style: confidence score stored in raw
        if "abuse_confidence_score" in (pr.raw or {}):
            abuse_score = float(pr.raw["abuse_confidence_score"])
            scores.append(abuse_score)

    if not scores:
        return 0.0, "Low"

    # Weight: highest score drives the final value (worst-case wins)
    raw_score = max(scores)

    # GreyNoise reducer: if it vouches the IP as benign/RIOT and nothing reported
    # actual malicious detections, dial the score down (likely benign noise).
    benign_signal = any(
        (pr.raw or {}).get("greynoise_benign") for pr in provider_results if pr.success
    )
    malicious_present = any(
        (pr.malicious or 0) > 0 for pr in provider_results if pr.success
    )
    if benign_signal and not malicious_present:
        raw_score *= 0.5

    raw_score = round(raw_score, 1)

    if raw_score <= 30:
        band = "Low"
    elif raw_score <= 70:
        band = "Medium"
    else:
        band = "High"

    return raw_score, band
