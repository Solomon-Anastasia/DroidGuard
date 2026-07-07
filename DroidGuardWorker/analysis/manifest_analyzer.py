import logging

from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis

logger = logging.getLogger(__name__)

MANIFEST_NS = "{http://schemas.android.com/apk/res/android}"

DANGEROUS_PERMISSION_COMBOS = [
    {
        "name": "SMS interception + boot persistence",
        "permissions": {"RECEIVE_SMS", "READ_SMS", "RECEIVE_BOOT_COMPLETED"},
        "severity": "high",
    },
    {
        "name": "SMS sending + boot persistence (classic banker/toll-fraud pattern)",
        "permissions": {"SEND_SMS", "RECEIVE_BOOT_COMPLETED"},
        "severity": "high",
    },
    {
        "name": "Overlay + accessibility service (classic overlay-attack pattern)",
        "permissions": {"SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"},
        "severity": "high",
    },
    {
        "name": "Call log + contacts + internet (data exfiltration pattern)",
        "permissions": {"READ_CALL_LOG", "READ_CONTACTS", "INTERNET"},
        "severity": "medium",
    },
]

SENSITIVE_EXPORTED_ACTIONS = {
    "android.provider.Telephony.SMS_RECEIVED",
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.PHONE_STATE",
}

DEBUG_CERT_MARKERS = ("android debug", "androiddebugkey", "debug")

SUSPICIOUS_VALIDITY_DAYS = 36500

# --- DEX API-call detection --------------------------------------------------
# Each category is a behaviour we care about, plus the concrete framework APIs
# that evidence it. An entry fires if ANY of its APIs is actually *called* in
# the app's bytecode (see _api_is_referenced -- we check cross-references, so a
# symbol merely present in the dex but never invoked does not count).
#
# API tuples are (class_descriptor_regex, method_name_regex) in Dalvik 'L...;'
# form. method ".*" means "any method on this class is enough". Severities feed
# straight into the existing high/medium/low weighting in verdict.py.
#
# Kept deliberately small and high-signal: every entry here should be something
# a reviewer would actually raise an eyebrow at, not just any API a normal app
# might touch. Noisy-but-common APIs (loadLibrary, generic crypto, HTTP) are
# intentionally left out to keep the false-positive rate down.
SUSPICIOUS_API_CATEGORIES = [
    {
        "name": "Dynamic code loading",
        "detail": "Loads and executes additional code at runtime (dropper/packer behaviour)",
        "severity": "high",
        "apis": [
            (r"Ldalvik/system/DexClassLoader;", r".*"),
            (r"Ldalvik/system/InMemoryDexClassLoader;", r".*"),
            (r"Ldalvik/system/BaseDexClassLoader;", r".*"),
        ],
    },
    {
        "name": "Runtime command execution",
        "detail": "Spawns OS-level processes or shell commands",
        "severity": "medium",
        "apis": [
            (r"Ljava/lang/Runtime;", r"exec"),
            (r"Ljava/lang/ProcessBuilder;", r"start"),
        ],
    },
    {
        "name": "Programmatic SMS sending",
        "detail": "Sends SMS from code (toll fraud / SMS-based C2)",
        "severity": "medium",
        "apis": [
            (r"Landroid/telephony/SmsManager;", r"send.*Message"),
        ],
    },
    {
        "name": "Device identifier access",
        "detail": "Reads hardware/SIM identifiers (device fingerprinting / exfiltration)",
        "severity": "medium",
        "apis": [
            (r"Landroid/telephony/TelephonyManager;", r"getDeviceId"),
            (r"Landroid/telephony/TelephonyManager;", r"getSubscriberId"),
            (r"Landroid/telephony/TelephonyManager;", r"getSimSerialNumber"),
            (r"Landroid/telephony/TelephonyManager;", r"getLine1Number"),
        ],
    },
    {
        "name": "Installed-app enumeration",
        "detail": "Lists other installed apps (target or security-tool discovery)",
        "severity": "medium",
        "apis": [
            (r"Landroid/content/pm/PackageManager;", r"getInstalledPackages"),
            (r"Landroid/content/pm/PackageManager;", r"getInstalledApplications"),
        ],
    },
    {
        "name": "Reflection",
        "detail": "Invokes methods reflectively (evasion technique; also common in libraries)",
        "severity": "low",
        "apis": [
            (r"Ljava/lang/reflect/Method;", r"invoke"),
        ],
    },
    {
        "name": "Base64 decoding",
        "detail": "Decodes Base64 payloads (frequently paired with obfuscated strings)",
        "severity": "low",
        "apis": [
            (r"Landroid/util/Base64;", r"decode"),
        ],
    },
]


def _short_perm(permission: str) -> str:
    return permission.split(".")[-1]


def _check_permission_combos(permissions: list) -> list:
    short_perms = {_short_perm(p) for p in permissions}
    findings = []

    for combo in DANGEROUS_PERMISSION_COMBOS:
        if combo["permissions"].issubset(short_perms):
            findings.append({
                "type": "dangerous_permission_combo",
                "name": combo["name"],
                "permissions": sorted(combo["permissions"]),
                "severity": combo["severity"],
            })

    return findings


def _is_exported(element, has_intent_filter: bool) -> bool:
    exported_attr = element.get(MANIFEST_NS + "exported")
    if exported_attr is not None:
        return exported_attr.lower() == "true"
    return has_intent_filter


def _check_exported_components(apk) -> list:
    findings = []

    try:
        root = apk.get_android_manifest_xml()
    except Exception as e:
        logger.warning(f"Failed to read AndroidManifest.xml for exported-component check: {e}")
        return findings

    for tag in ("activity", "service", "receiver", "provider"):
        for element in root.iter(tag):
            name = element.get(MANIFEST_NS + "name")
            if not name:
                continue

            intent_filters = list(element.iter("intent-filter"))
            has_intent_filter = len(intent_filters) > 0

            if not _is_exported(element, has_intent_filter):
                continue

            permission_attr = element.get(MANIFEST_NS + "permission")
            if permission_attr is not None:
                continue

            sensitive_actions = [
                action.get(MANIFEST_NS + "name")
                for intent_filter in intent_filters
                for action in intent_filter.iter("action")
                if action.get(MANIFEST_NS + "name") in SENSITIVE_EXPORTED_ACTIONS
            ]

            if tag in ("receiver", "service", "provider"):
                severity = "high" if sensitive_actions else "medium"
            else:  # activity — much more commonly and legitimately exported
                if not sensitive_actions:
                    continue
                severity = "medium"

            findings.append({
                "type": "exported_component_without_permission",
                "component_type": tag,
                "name": name,
                "sensitive_actions": sensitive_actions,
                "severity": severity,
            })

    return findings


def _check_certificates(apk) -> list:
    findings = []

    try:
        certs = apk.get_certificates()
    except Exception as e:
        logger.warning(f"Failed to read certificates: {e}")
        return findings

    if not certs:
        findings.append({
            "type": "certificate_anomaly",
            "name": "No signing certificate found",
            "severity": "high",
        })
        return findings

    for cert in certs:
        try:
            subject = cert.subject.native
            issuer = cert.issuer.native
            common_name = subject.get("common_name", "") if isinstance(subject, dict) else ""

            if subject == issuer:
                findings.append({
                    "type": "certificate_anomaly",
                    "name": "Self-signed certificate",
                    "detail": f"CN={common_name}",
                    "severity": "low",
                })

            if common_name and any(marker in common_name.lower() for marker in DEBUG_CERT_MARKERS):
                findings.append({
                    "type": "certificate_anomaly",
                    "name": "Debug certificate used for signing",
                    "detail": f"CN={common_name}",
                    # A production APK signed with a debug key is a real red flag.
                    "severity": "high",
                })

            validity = cert.native.get("tbs_certificate", {}).get("validity", {})
            not_before = validity.get("not_before")
            not_after = validity.get("not_after")
            if not_before and not_after:
                validity_days = (not_after - not_before).days
                if validity_days > SUSPICIOUS_VALIDITY_DAYS:
                    findings.append({
                        "type": "certificate_anomaly",
                        "name": "Unusually long certificate validity period",
                        "detail": f"{validity_days} days",
                        "severity": "low",
                    })

        except Exception as e:
            logger.warning(f"Error inspecting a certificate: {e}")

    return findings


def _build_dex_analysis(apk):
    """Build an androguard Analysis over every classesN.dex in the APK.

    NOTE: this is the expensive step -- it parses all dex bytecode and builds
    cross-references. It's kept self-contained here so this task doesn't touch
    extractor.py or consumer.py. If later stages also need the Analysis object,
    build it once in extractor.py and pass `dx` through instead of rebuilding
    it per-analysis."""
    dx = Analysis()
    for dex_bytes in apk.get_all_dex():
        dx.add(DalvikVMFormat(dex_bytes))
    dx.create_xref()
    return dx


def _api_is_referenced(dx, class_regex: str, method_regex: str) -> bool:
    """True if a method matching (class_regex, method_regex) is actually called
    somewhere in the app. We require at least one inbound cross-reference so a
    symbol that only sits in the dex string/method table -- but is never
    invoked -- doesn't produce a false finding."""
    for method_analysis in dx.find_methods(classname=class_regex, methodname=method_regex):
        for _ in method_analysis.get_xref_from():
            return True
    return False


def _check_dex_api_calls(dx) -> list:
    """Flag suspicious framework-API usage in the decompiled bytecode. This is
    what lets a manifest permission be corroborated against the code that
    actually exercises it (full corroboration scoring comes in a later step;
    for now each behaviour is reported on its own)."""
    findings = []

    for category in SUSPICIOUS_API_CATEGORIES:
        fired = False
        for class_regex, method_regex in category["apis"]:
            try:
                if _api_is_referenced(dx, class_regex, method_regex):
                    fired = True
                    break
            except Exception as e:
                logger.warning(
                    f"API check failed for {class_regex} -> {method_regex}: {e}"
                )

        if fired:
            findings.append({
                "type": "suspicious_api_call",
                "name": category["name"],
                "detail": category["detail"],
                "severity": category["severity"],
            })

    return findings


def analyze(apk) -> dict:
    findings = []

    try:
        findings.extend(_check_permission_combos(apk.get_permissions()))
    except Exception as e:
        logger.warning(f"Failed to check permission combos: {e}")

    findings.extend(_check_exported_components(apk))
    findings.extend(_check_certificates(apk))

    # DEX-level API-call analysis. Wrapped defensively: if bytecode parsing
    # fails (corrupt/packed dex, androguard hiccup), the manifest-based checks
    # above still produce a valid report rather than failing the whole job.
    try:
        dx = _build_dex_analysis(apk)
        findings.extend(_check_dex_api_calls(dx))
    except Exception as e:
        logger.warning(f"Failed to run DEX API-call analysis: {e}")

    high = [f for f in findings if f["severity"] == "high"]
    medium = [f for f in findings if f["severity"] == "medium"]
    low = [f for f in findings if f["severity"] == "low"]

    return {
        "status": "completed",
        "findings": findings,
        "high_severity_count": len(high),
        "medium_severity_count": len(medium),
        "low_severity_count": len(low),
        "has_significant_findings": len(high) > 0 or len(medium) > 0,
    }