import logging

logger = logging.getLogger(__name__)

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"

WEIGHT_YARA_HIGH = 0.80
WEIGHT_YARA_MEDIUM = 0.40
WEIGHT_YARA_LOW = 0.05

WEIGHT_ANDRO_HIGH = 0.40
WEIGHT_ANDRO_MEDIUM = 0.05
WEIGHT_ANDRO_LOW = 0.01

MAX_ANDRO_MEDIUM_IMPACT = 0.25

# Verdict thresholds on the blended 0.0-1.0 threat score. Pulled out of the
# branching logic so they live in one tunable place instead of as magic
# numbers scattered through build_verdict.
MALICIOUS_THRESHOLD = 0.75
SUSPICIOUS_THRESHOLD = 0.40


def _calculate_score(yara_report: dict, heuristic_report: dict) -> float:
    score = 0.0

    if yara_report.get("status") == "completed":
        matches = yara_report.get("matches", [])
        for match in matches:
            confidence = match.get("confidence", "low")
            if confidence == "high":
                score += WEIGHT_YARA_HIGH
            elif confidence == "medium":
                score += WEIGHT_YARA_MEDIUM
            else:
                score += WEIGHT_YARA_LOW

    if heuristic_report.get("status") == "completed":
        high_count = heuristic_report.get("high_severity_count", 0)
        medium_count = heuristic_report.get("medium_severity_count", 0)
        low_count = heuristic_report.get("low_severity_count", 0)

        score += (high_count * WEIGHT_ANDRO_HIGH)

        medium_impact = min(medium_count * WEIGHT_ANDRO_MEDIUM, MAX_ANDRO_MEDIUM_IMPACT)
        score += medium_impact

        score += (low_count * WEIGHT_ANDRO_LOW)

    return max(0.0, min(score, 1.0))


def _find_high_confidence_yara(yara_report: dict) -> list:
    """Return YARA matches explicitly marked high-confidence.

    These are the known-malicious signatures we trust enough to convict on
    outright, without waiting for the blended heuristic score. Confidence comes
    from rule_confidence.json (via the scanner), so which rules count as 'high'
    is configuration, not hardcoded here."""
    if yara_report.get("status") != "completed":
        return []
    return [m for m in yara_report.get("matches", []) if m.get("confidence") == "high"]


def _decide(yara_report: dict, heuristic_report: dict):
    """Run the decision cascade.

    Returns (verdict, threat_score, reason, decision_path).

    Stage 1 is a high-confidence YARA short-circuit: a known-bad signature
    convicts immediately and heuristic scoring is skipped. Anything that
    survives Stage 1 falls through to the weighted blended score in Stage 2,
    which keeps the exact thresholds and behaviour the worker had before."""
    yara_available = yara_report.get("status") == "completed"

    # --- Stage 1: high-confidence YARA short-circuit -----------------------
    high_conf = _find_high_confidence_yara(yara_report)
    if high_conf:
        rules = sorted({m.get("rule", "unknown_rule") for m in high_conf})
        preview = ", ".join(rules[:3])
        if len(rules) > 3:
            preview += f", +{len(rules) - 3} more"
        reason = (
            f"High-confidence YARA signature matched ({preview}). "
            f"Known-malicious pattern — convicted on signature alone; "
            f"heuristic scoring skipped."
        )
        # Score is pinned to 1.0: a high-confidence signature hit is a
        # definitive known-bad, not a point on the fuzzy heuristic scale.
        return VERDICT_MALICIOUS, 1.0, reason, "yara_high_confidence_short_circuit"

    # --- Stage 2: blended heuristic score ----------------------------------
    threat_score = _calculate_score(yara_report, heuristic_report)

    if threat_score >= MALICIOUS_THRESHOLD:
        reason = (
            f"Threat score ({threat_score:.2f}/1.0) exceeded the malicious "
            f"threshold. Strong indicators of compromise found."
        )
        return VERDICT_MALICIOUS, threat_score, reason, "blended_score"

    if threat_score >= SUSPICIOUS_THRESHOLD:
        reason = (
            f"Threat score ({threat_score:.2f}/1.0) reached the suspicious "
            f"threshold. Anomalous structural patterns or low-confidence "
            f"signatures detected. Needs manual review."
        )
        return VERDICT_SUSPICIOUS, threat_score, reason, "blended_score"

    # Below the danger threshold: clean -- UNLESS YARA never ran, in which case
    # we can't honestly call it clean (incomplete scan, not a confirmed pass).
    if not yara_available:
        reason = (
            "YARA scanning was unavailable for this job. Treat with caution "
            "-- this is an incomplete scan, not a confirmed clean result."
        )
        return VERDICT_SUSPICIOUS, threat_score, reason, "yara_unavailable"

    reason = (
        f"Threat score ({threat_score:.2f}/1.0) is below the danger threshold. "
        f"No significant threats detected."
    )
    return VERDICT_CLEAN, threat_score, reason, "blended_score"


def build_verdict(yara_report: dict, heuristic_report: dict) -> dict:
    verdict, threat_score, reason, decision_path = _decide(yara_report, heuristic_report)

    return {
        "verdict": verdict,
        "threat_score": round(threat_score, 2),
        "reason": reason,
        # Which branch of the cascade produced the verdict. Handy for the
        # gateway/UI and for demoing that the short-circuit actually fires.
        "decision_path": decision_path,
        "yara_summary": {
            "is_clean": yara_report.get("is_clean"),
            "threats_found": yara_report.get("threats_found"),
            "needs_review": yara_report.get("needs_review"),
            "low_confidence_matches_found": yara_report.get("low_confidence_matches_found"),
        },
        "androguard_summary": {
            "has_significant_findings": heuristic_report.get("has_significant_findings"),
            "high_severity_count": heuristic_report.get("high_severity_count"),
            "medium_severity_count": heuristic_report.get("medium_severity_count"),
            "low_severity_count": heuristic_report.get("low_severity_count"),
        },
        "yara_report": yara_report,
        "androguard_report": heuristic_report,
    }