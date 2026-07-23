import re
import math
import logging
import collections

from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.core.bytecodes.apk import APK

from xml.etree.ElementTree import Element

logger = logging.getLogger(__name__)

MANIFEST_NS = "{http://schemas.android.com/apk/res/android}"

DANGEROUS_PERMISSION_COMBOS = [
    # Bypasses 2fa for banking apps
    {
        "name": "SMS interception + boot persistence",
        "permissions": {"RECEIVE_SMS", "READ_SMS", "RECEIVE_BOOT_COMPLETED"},
        "severity": "high",
    },
    # Troll fraud
    {
        "name": "SMS sending + boot persistence (classic banker/toll-fraud pattern)",
        "permissions": {"SEND_SMS", "RECEIVE_BOOT_COMPLETED"},
        "severity": "high",
    },
    # Bank trojan
    {
        "name": "Overlay + accessibility service (classic overlay-attack pattern)",
        "permissions": {"SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"},
        "severity": "high",
    },
    # Spyware
    {
        "name": "Call log + contacts + internet (data exfiltration pattern)",
        "permissions": {"READ_CALL_LOG", "READ_CONTACTS", "INTERNET"},
        "severity": "medium",
    },
]

SENSITIVE_EXPORTED_ACTIONS = {
    "android.provider.Telephony.SMS_RECEIVED",  # OTP interception
    "android.intent.action.BOOT_COMPLETED",  # Start app silently after boot
    "android.intent.action.PHONE_STATE",  # Spyware for calls
}

# Real apps have a key, debug = absence of the key (repackaging)
DEBUG_CERT_MARKERS = ("android debug", "androiddebugkey", "debug")
SUSPICIOUS_VALIDITY_DAYS = 36_500  # 100 years

# API-call detection in the string pool of each .dex file
SUSPICIOUS_API_CATEGORIES = [
    # Dropper behaviour
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
    # Trojan behaviour
    {
        "name": "Runtime command execution",
        "detail": "Spawns OS-level processes or shell commands",
        "severity": "medium",
        "apis": [
            (r"Ljava/lang/Runtime;", r"exec"),
            (r"Ljava/lang/ProcessBuilder;", r"start"),
        ],
    },
    # Troll fraud behaviour
    {
        "name": "Programmatic SMS sending",
        "detail": "Sends SMS from code (toll fraud / SMS-based C2)",
        "severity": "medium",
        "apis": [
            (r"Landroid/telephony/SmsManager;", r"send.*Message"),
        ],
    },
    # Fingerprinting behaviour
    {
        "name": "Device identifier access",
        "detail": "Reads hardware/SIM identifiers (device fingerprinting)",
        "severity": "medium",
        "apis": [
            (r"Landroid/telephony/TelephonyManager;", r"getDeviceId"),
            (r"Landroid/telephony/TelephonyManager;", r"getSubscriberId"),
            (r"Landroid/telephony/TelephonyManager;", r"getSimSerialNumber"),
            (r"Landroid/telephony/TelephonyManager;", r"getLine1Number"),
        ],
    },
    # Overlay behavior + if malware find antivirus -> sleep
    {
        "name": "Installed-app enumeration",
        "detail": "Lists other installed apps (target or security-tool discovery)",
        "severity": "medium",
        "apis": [
            (r"Landroid/content/pm/PackageManager;", r"getInstalledPackages"),
            (r"Landroid/content/pm/PackageManager;", r"getInstalledApplications"),
        ],
    },
    # Last 2 is evasion behaviour
    {
        "name": "Reflection",
        "detail": "Invokes methods reflectively (evasion technique. Also common in libraries)",
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

# URL analysis
URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.IGNORECASE)
IP_URL_RE = re.compile(r"^https?://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)", re.IGNORECASE)
# Quote, html tag, url parameter, eof: dropper detection
PAYLOAD_URL_RE = re.compile(r"\.(?:apk|dex|jar)(?:[?#\"'<>]|$)", re.IGNORECASE)
MAX_URL_LEN = 200
MAX_URL_SAMPLES = 5

# Packer/obfuscation detection
# Presence of these strongly implies the DEX is packed
KNOWN_PACKER_SIGNATURES = {
    r"Ljiagu/": "360 Jiagu",
    r"Lcom/qihoo/util/": "360",
    r"Lcom/stub/StubApp": "Bangcle / SecShell",
    r"Lcom/secneo/apkwrapper/": "SecNeo",
    r"Lcom/baidu/protect/": "Baidu Protect",
    r"Lcom/tencent/StubShell/": "Tencent Legu",
    r"Lcom/ali/mobisecenhance/": "Alibaba",
    r"Lcom/dexprotector/": "DexProtector",
}

# Shannon entropy (bits/byte) above which a DEX looks encrypted/compressed
# Packed payloads approach 8.0
ENTROPY_THRESHOLD = 7.3

# Action that separates an SMS trojan that is hiding the message
SMS_RECEIVED_ACTION = "android.provider.Telephony.SMS_RECEIVED"

# Legit SMS receivers leave it at the default 0
SMS_RECEIVER_PRIORITY_THRESHOLD = 100


# Get only permission name
def _short_perm(permission: str) -> str:
    return permission.split(".")[-1]


def _check_permission_combos(permissions: list) -> list:
    short_perms = {
        _short_perm(p)
        for p in permissions
    }
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


def _is_exported(element: Element, has_intent_filter: bool) -> bool:
    exported_attr = element.get(MANIFEST_NS + "exported")

    if exported_attr is not None:
        return exported_attr.lower() == "true"

    return has_intent_filter


def _check_exported_components(apk: APK) -> list:
    findings = []

    try:
        root = apk.get_android_manifest_xml()
    except Exception as e:
        logger.warning(f"Failed to read AndroidManifest.xml for exported-component check: {e}")
        return findings

    if root is None:
        logger.warning("Manifest XML is None. Skipping exported components check")
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
            else:
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


def _check_certificates(apk: APK) -> list:
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
                    # A production APK signed with a debug key is a real red flag
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


def _build_dex_analysis(apk: APK):
    # Build one androguard analysis over every classesN.dex in the APK
    # Dalvik Cross-References
    dx = Analysis()
    for dex_bytes in apk.get_all_dex():
        dx.add(DalvikVMFormat(dex_bytes))
    dx.create_xref()

    return dx


def _api_is_referenced(dx: Analysis, class_regex: str, method_regex: str) -> bool:
    for method_analysis in dx.find_methods(classname=class_regex, methodname=method_regex):
        for _ in method_analysis.get_xref_from():
            return True
    return False


def _check_dex_api_calls(dx: Analysis) -> list:
    findings = []

    for category in SUSPICIOUS_API_CATEGORIES:
        found = False
        for class_regex, method_regex in category["apis"]:
            try:
                if _api_is_referenced(dx, class_regex, method_regex):
                    found = True
                    break
            except Exception as e:
                logger.warning(f"API check failed for {class_regex} -> {method_regex}: {e}")

        if found:
            findings.append({
                "type": "suspicious_api_call",
                "name": category["name"],
                "detail": category["detail"],
                "severity": category["severity"],
            })

    return findings


def _filter_unused_referenced_strings(dx: Analysis):
    try:
        string_analyses = dx.get_strings()
    except Exception as e:
        logger.warning(f"Failed to enumerate DEX strings: {e}")
        return

    for sa in string_analyses:
        try:
            # If xref info is available and empty, skip
            xrefs = sa.get_xref_from()
            if xrefs is not None and len(list(xrefs)) == 0:
                continue
        except Exception:
            pass  # xref unavailable in this androguard build, keep

        try:
            value = sa.get_value()
        except Exception:
            continue

        if value:
            if isinstance(value, bytes):
                value = value.decode('utf-8', errors='ignore')
            yield value # Generator


def _check_strings(dx: Analysis) -> list:
    findings = []
    ip_urls = set()
    payload_urls = set()

    for value in _filter_unused_referenced_strings(dx):
        for match in URL_RE.finditer(value):
            url = match.group(0)[:MAX_URL_LEN]

            if IP_URL_RE.match(url):
                ip_urls.add(url)
            if PAYLOAD_URL_RE.search(url):
                payload_urls.add(url)

    if ip_urls:
        findings.append({
            "type": "suspicious_string",
            "name": "Hardcoded IP-address URL",
            "detail": f"{len(ip_urls)} URL(s) pointing at raw IPs (possible C2)",
            "samples": sorted(ip_urls)[:MAX_URL_SAMPLES],
            "severity": "medium",
        })

    if payload_urls:
        findings.append({
            "type": "suspicious_string",
            "name": "Executable-payload URL (.apk/.dex/.jar)",
            "detail": f"{len(payload_urls)} URL(s) that fetch runnable code (staged dropper)",
            "samples": sorted(payload_urls)[:MAX_URL_SAMPLES],
            "severity": "high",
        })

    return findings


# Measures the degree of randomness / unpredictability of data
def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = collections.Counter(data)
    length = len(data)

    # - sum(i)(probability(i)*log(2)(probability(i)))
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _check_packer(apk: APK, dx: Analysis) -> list:
    findings = []

    detected = []
    for signature, label in KNOWN_PACKER_SIGNATURES.items():
        try:
            for _ in dx.find_classes(signature):
                detected.append(label)
                break
        except Exception as e:
            logger.warning(f"Packer signature check failed for {signature}: {e}")

    if detected:
        findings.append({
            "type": "obfuscation",
            "name": "Known packer/protector detected",
            "detail": ", ".join(sorted(set(detected))),
            "severity": "medium",
        })

    # High-entropy DEX: supporting signal
    try:
        for dex_bytes in apk.get_all_dex():
            entropy = _shannon_entropy(dex_bytes)

            if entropy >= ENTROPY_THRESHOLD:
                findings.append({
                    "type": "obfuscation",
                    "name": "High-entropy DEX (possible encryption/packing)",
                    "detail": f"entropy={entropy:.2f} bits/byte",
                    "severity": "low",
                })
                break
    except Exception as e:
        logger.warning(f"DEX entropy check failed: {e}")

    return findings


def _check_sms_interception(apk: APK, dx: Analysis) -> list:
    # Detect the SMS-hiding behaviours that separate a trojan from a legit app
    markers = []

    # abortBroadcast() in code actively suppresses the incoming SMS so it never reaches the user or other apps
    # Classic OTP-stealer behaviour
    try:
        if _api_is_referenced(dx, r"Landroid/content/BroadcastReceiver;", r"abortBroadcast"):
            markers.append("abortBroadcast() call (suppresses incoming SMS)")
    except Exception as e:
        logger.warning(f"abortBroadcast check failed: {e}")

    # High-priority SMS receiver registers to receive SMS before other apps so it can intercept/hide
    try:
        root = apk.get_android_manifest_xml()

        if root is not None:
            for receiver in root.iter("receiver"):
                for intent_filter in receiver.iter("intent-filter"):
                    priority = intent_filter.get(MANIFEST_NS + "priority")

                    if priority is None:
                        continue

                    actions = {a.get(MANIFEST_NS + "name") for a in intent_filter.iter("action")}
                    if SMS_RECEIVED_ACTION not in actions:
                        continue

                    try:
                        if int(priority) >= SMS_RECEIVER_PRIORITY_THRESHOLD:
                            markers.append(f"high-priority SMS receiver (priority={priority})")
                    except (ValueError, TypeError):
                        continue
    except Exception as e:
        logger.warning(f"SMS receiver priority check failed: {e}")

    if not markers:
        return []

    return [{
        "type": "sms_interception",
        "name": "SMS interception markers",
        "detail": ", ".join(sorted(set(markers))), # Eliminate duplicates
        "severity": "high",
    }]


def analyze(apk: APK) -> dict:
    findings = []
    permissions = []

    try:
        permissions = [_short_perm(p) for p in apk.get_permissions()]
    except Exception as e:
        logger.warning(f"Failed to read permissions: {e}")

    findings.extend(_check_permission_combos(permissions))
    findings.extend(_check_exported_components(apk))
    findings.extend(_check_certificates(apk))

    # All DEX-based analysis shares one analysis object
    try:
        dx = _build_dex_analysis(apk)

        findings.extend(_check_dex_api_calls(dx))
        findings.extend(_check_strings(dx))
        findings.extend(_check_packer(apk, dx))
        findings.extend(_check_sms_interception(apk, dx))
    except Exception as e:
        logger.warning(f"Failed to run DEX-based analysis: {e}")

    high = [f for f in findings if f["severity"] == "high"]
    medium = [f for f in findings if f["severity"] == "medium"]
    low = [f for f in findings if f["severity"] == "low"]

    return {
        "status": "completed",
        "findings": findings,
        "permissions": permissions,
        "high_severity_count": len(high),
        "medium_severity_count": len(medium),
        "low_severity_count": len(low),
        "has_significant_findings": len(high) > 0 or len(medium) > 0,
    }
