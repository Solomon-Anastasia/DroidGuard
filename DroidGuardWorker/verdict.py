import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"

MALICIOUS_THRESHOLD = 0.75
SUSPICIOUS_THRESHOLD = 0.40
SUSPICIOUS_CEILING = 0.74

# Evidence channels
# Corroboration = the same behaviour being pointed at by different channels
CH_SIGNATURE = "yara_signature"  # Rule match
CH_DEX_API = "dex_api"  # Code calls the API
CH_STRING = "string"  # Hardcoded URL/IP evidence
CH_STRUCTURE = "manifest_structure"  # Exported component surface
CH_PERMISSION = "permission"  # Requested permission (weak alone)
CH_CERT = "certificate"
CH_BEHAVIOR = "behavior_marker"  # A discriminator of malicious intent

CHANNEL_WEIGHTS = {
    CH_SIGNATURE: 0.45,
    CH_DEX_API: 0.25,
    CH_STRING: 0.25,
    CH_STRUCTURE: 0.20,
    CH_PERMISSION: 0.15,
    CH_CERT: 0.15,
    CH_BEHAVIOR: 0.30,
}
SIGNATURE_LOW_WEIGHT = 0.10
CONTEXT_CAP = 0.30

# When >=2 distinct channels agree on a behaviour
CORROBORATION_MULTIPLIER = 1.5
TRIPLE_CHANNEL_BONUS = 1.1

# How much non-primary behaviours contribute on top of the strongest one
SECONDARY_WEIGHT = 0.15

# Packing/obfuscation is never malicious alone, it only sharpens a verdict that
# already has a real malicious behaviour behind it
EVASION_AMPLIFIER = 1.15

# Behaviours
B_SMS = "sms_abuse"
B_OVERLAY = "overlay_attack"
B_DYNAMIC = "dynamic_payload"
B_EXFIL = "data_exfiltration"
B_SIGNATURE = "known_signature"
B_FINGERPRINT = "device_fingerprinting"
B_PERSIST = "persistence"
B_INTEGRITY = "integrity_anomaly"
B_EVASION = "evasion"

# Behaviours that indicate malice and may get a malicious verdict
STRONG_BEHAVIORS = {B_SMS, B_OVERLAY, B_DYNAMIC, B_EXFIL, B_SIGNATURE}
CONTEXT_BEHAVIORS = {B_FINGERPRINT, B_PERSIST, B_INTEGRITY}


def _is_context(behavior: str, interception_present: bool) -> bool:
    if behavior in CONTEXT_BEHAVIORS:
        return True
    if behavior == B_SMS and not interception_present:
        return True
    return False


# High convidence part
def _indicator(behavior, channel, weight, source):
    return {"behavior": behavior, "channel": channel, "weight": weight, "source": source}


def _find_high_confidence_yara(yara_report: dict) -> list:
    if yara_report.get("status") != "completed":
        return []
    return [m for m in yara_report.get("matches", []) if m.get("confidence") == "high"]


def _permission_behavior(short_perm: str):
    mapping = {
        "SEND_SMS": B_SMS,
        "RECEIVE_SMS": B_SMS,
        "READ_SMS": B_SMS,
        "RECEIVE_BOOT_COMPLETED": B_PERSIST,
        "READ_CONTACTS": B_EXFIL,
        "READ_CALL_LOG": B_EXFIL,
        "READ_PHONE_STATE": B_FINGERPRINT,
        "SYSTEM_ALERT_WINDOW": B_OVERLAY,
        "BIND_ACCESSIBILITY_SERVICE": B_OVERLAY,
    }
    return mapping.get(short_perm)


def _signature_behavior(rule_name: str, tags: str) -> str:
    hay = f"{rule_name} {tags}".lower()

    if "sms" in hay or "smish" in hay:
        return B_SMS
    if "overlay" in hay or "bank" in hay or "inject" in hay:
        return B_OVERLAY
    if "drop" in hay or "loader" in hay or "packer" in hay:
        return B_DYNAMIC
    if "spy" in hay or "steal" in hay or "exfil" in hay or "stealer" in hay:
        return B_EXFIL

    return B_SIGNATURE


def _combo_behaviors(name: str) -> set:
    n = name.lower()
    behaviors = set()

    if "sms" in n:
        behaviors.add(B_SMS)
    if "persistence" in n or "boot" in n:
        behaviors.add(B_PERSIST)
    if "overlay" in n or "accessibility" in n:
        behaviors.add(B_OVERLAY)
    if "exfiltration" in n or "contacts" in n or "call log" in n:
        behaviors.add(B_EXFIL)

    return behaviors or {B_INTEGRITY}


def _api_behavior(name: str):
    mapping = {
        "Dynamic code loading": B_DYNAMIC,
        "Runtime command execution": B_DYNAMIC,
        "Programmatic SMS sending": B_SMS,
        "Device identifier access": B_FINGERPRINT,
        "Installed-app enumeration": B_FINGERPRINT,
        "Reflection": B_EVASION,
        "Base64 decoding": B_EVASION,
    }

    return mapping.get(name)


# Data normalization
def _indicators_from_finding(finding: dict) -> list:
    ftype = finding.get("type")
    name = finding.get("name", "")
    out = []

    if ftype == "dangerous_permission_combo":
        for behavior in _combo_behaviors(name):
            out.append(_indicator(behavior, CH_PERMISSION, CHANNEL_WEIGHTS[CH_PERMISSION], name))

    elif ftype == "exported_component_without_permission":
        actions = finding.get("sensitive_actions") or []
        behaviors = set()

        for action in actions:
            if "SMS_RECEIVED" in action:
                behaviors.add(B_SMS)
            elif "BOOT_COMPLETED" in action:
                behaviors.add(B_PERSIST)
            elif "PHONE_STATE" in action:
                behaviors.add(B_FINGERPRINT)

        for behavior in (behaviors or {B_INTEGRITY}):
            out.append(_indicator(behavior, CH_STRUCTURE, CHANNEL_WEIGHTS[CH_STRUCTURE], name))

    elif ftype == "certificate_anomaly":
        weight = 0.25 if "No signing certificate" in name else CHANNEL_WEIGHTS[CH_CERT]
        out.append(_indicator(B_INTEGRITY, CH_CERT, weight, name))

    elif ftype == "suspicious_api_call":
        behavior = _api_behavior(name)

        if behavior == B_EVASION:
            out.append(_indicator(B_EVASION, CH_DEX_API, 0.0, name))
        elif behavior:
            out.append(_indicator(behavior, CH_DEX_API, CHANNEL_WEIGHTS[CH_DEX_API], name))

    elif ftype == "suspicious_string":
        behavior = B_DYNAMIC if "payload" in name.lower() else B_EXFIL
        out.append(_indicator(behavior, CH_STRING, CHANNEL_WEIGHTS[CH_STRING], name))

    elif ftype == "sms_interception":
        out.append(_indicator(B_SMS, CH_BEHAVIOR, CHANNEL_WEIGHTS[CH_BEHAVIOR], name))

    elif ftype == "obfuscation":
        out.append(_indicator(B_EVASION, CH_STRUCTURE, 0.0, name))  # amplifier marker

    return out


def _interception_present(heuristic_report: dict) -> bool:
    return any(f.get("type") == "sms_interception" for f in heuristic_report.get("findings", []))


# Rest of the confidence (without high indicators)
def _collect_indicators(yara_report: dict, heuristic_report: dict) -> list:
    indicators = []

    if yara_report.get("status") == "completed":
        for match in yara_report.get("matches", []):
            confidence = match.get("confidence", "low")

            if confidence == "high":
                continue

            rule = match.get("rule") or ""
            tags = " ".join(match.get("tags") or [])
            behavior = _signature_behavior(rule, tags)
            weight = CHANNEL_WEIGHTS[CH_SIGNATURE] if confidence == "medium" else SIGNATURE_LOW_WEIGHT

            indicators.append(_indicator(behavior, CH_SIGNATURE, weight, rule))

    for finding in heuristic_report.get("findings", []):
        indicators.extend(_indicators_from_finding(finding))

    for perm in heuristic_report.get("permissions", []):
        behavior = _permission_behavior(perm)

        if behavior:
            indicators.append(_indicator(behavior, CH_PERMISSION, CHANNEL_WEIGHTS[CH_PERMISSION], perm))

    return indicators


# Require multiple channels to confirm a strong threat
# Common behaviors are score-capped so they only act as context, not primary evidence
# For unconfirmed weak signals, take the maximum score
def _score_indicators(indicators: list, interception_present: bool = False):
    # Create key if not exists
    behavior_channels = defaultdict(dict)
    evasion_present = False

    for ind in indicators:
        behavior = ind["behavior"]

        if behavior == B_EVASION:
            evasion_present = True
            continue

        channel, weight = ind["channel"], ind["weight"]

        if weight > behavior_channels[behavior].get(channel, 0.0):
            behavior_channels[behavior][channel] = weight

    behavior_scores = {}
    channel_counts = {}

    for behavior, channels in behavior_channels.items():
        raw = sum(channels.values())
        n = len(channels)

        if n >= 2:
            raw *= CORROBORATION_MULTIPLIER
        if n >= 3:
            raw *= TRIPLE_CHANNEL_BONUS

        # Cap behaviours that lack evidence
        cap = CONTEXT_CAP if _is_context(behavior, interception_present) else 1.0
        behavior_scores[behavior] = min(raw, cap)
        channel_counts[behavior] = n

    breakdown = {
        "behaviors": {
            b: {
                "score": round(behavior_scores[b], 2),
                "channels": sorted(behavior_channels[b].keys()),
                "corroborated": channel_counts[b] >= 2,
                "context": _is_context(b, interception_present),
            }
            for b in behavior_scores
        },
        "evasion_present": evasion_present,
        "interception_present": interception_present,
    }

    if not behavior_scores:
        breakdown["overall"] = 0.0
        return 0.0, breakdown

    # A strong signal requires a strong behaviour
    corroborated_strong = [
        s for b, s in behavior_scores.items()
        if channel_counts[b] >= 2
           and b in STRONG_BEHAVIORS
           and not _is_context(b, interception_present)
    ]

    if corroborated_strong:
        # Diminishing returns aggregation rule
        primary = max(corroborated_strong)
        overall = primary + SECONDARY_WEIGHT * (sum(behavior_scores.values()) - primary)

        if evasion_present:
            overall *= EVASION_AMPLIFIER
        breakdown["decision"] = "corroborated_strong_behavior"
    else:
        # No strong behaviour confirmed
        overall = max(behavior_scores.values())
        notable = [s for s in behavior_scores.values() if s >= CONTEXT_CAP]

        if len(notable) >= 3:
            overall += 0.08

        overall = min(overall, SUSPICIOUS_CEILING)
        breakdown["decision"] = "uncorroborated_capped"

    overall = max(0.0, min(overall, 1.0))
    breakdown["overall"] = round(overall, 2)

    return overall, breakdown


def _decide(yara_report: dict, heuristic_report: dict):
    yara_available = yara_report.get("status") == "completed"

    # High-confidence YARA short-circuit
    high_conf = _find_high_confidence_yara(yara_report)

    if high_conf:
        rules = sorted({m.get("rule", "unknown_rule") for m in high_conf})
        preview = ", ".join(rules[:3])

        if len(rules) > 3:
            preview += f", +{len(rules) - 3} more"

        reason = (
            f"High-confidence YARA signature matched ({preview}). "
            f"Known-malicious pattern: convicted on signature alone."
            f"Corroboration scoring skipped."
        )

        return VERDICT_MALICIOUS, 1.0, reason, "yara_high_confidence_short_circuit", None

    # Corroboration-based fusion
    is_interception_present = _interception_present(heuristic_report)
    threat_score, breakdown = _score_indicators(
        _collect_indicators(yara_report, heuristic_report),
        is_interception_present,
    )

    if threat_score >= MALICIOUS_THRESHOLD:
        reason = (
            f"Threat score ({threat_score:.2f}/1.0) reached the malicious "
            f"threshold via corroborated indicators across independent "
            f"channels."
        )
        return VERDICT_MALICIOUS, threat_score, reason, "corroboration_score", breakdown

    if threat_score >= SUSPICIOUS_THRESHOLD:
        reason = (
            f"Threat score ({threat_score:.2f}/1.0) reached the suspicious threshold. "
            f"Signals present but not corroborated strongly enough to convict. "
            f"Needs manual review."
        )
        return VERDICT_SUSPICIOUS, threat_score, reason, "corroboration_score", breakdown

    if not yara_available:
        reason = (
            "YARA scanning was unavailable for this job. Treat with caution, "
            "this is an incomplete scan, not a confirmed clean result."
        )
        return VERDICT_SUSPICIOUS, threat_score, reason, "yara_unavailable", breakdown

    reason = (
        f"Threat score ({threat_score:.2f}/1.0) is below the danger threshold. "
        f"No corroborated threats detected."
    )
    return VERDICT_CLEAN, threat_score, reason, "corroboration_score", breakdown


def build_verdict(yara_report: dict, heuristic_report: dict) -> dict:
    verdict, threat_score, reason, decision_path, breakdown = _decide(yara_report, heuristic_report)

    return {
        "verdict": verdict,
        "threat_score": round(threat_score, 2),
        "reason": reason,
        "decision_path": decision_path,
        "signal_breakdown": breakdown,
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
