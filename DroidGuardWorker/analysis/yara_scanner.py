import os
import json
import yara
import logging
from pathlib import Path

from concurrent.futures import ThreadPoolExecutor, as_completed

from config import RULES_DIR, RULE_CONFIDENCE_FILE

logger = logging.getLogger(__name__)

# Max matched-string instances to include per rule identifier per match, so a
# rule that matches hundreds of times in one file doesn't blow up the report
MAX_INSTANCES_PER_STRING = 5
# Max length of decoded matched text before truncation, for readability
MAX_MATCHED_TEXT_LEN = 120


def _load_confidence_config() -> dict:
    """Load rule -> confidence overrides. Falls back to an all-medium default
    if the file is missing or malformed, so a bad config never breaks scanning"""
    default_config = {"default": "medium", "overrides": {}}

    if not RULE_CONFIDENCE_FILE.exists():
        logger.info(
            f"No rule confidence config found at {RULE_CONFIDENCE_FILE}; using default confidence for all rules.")
        return default_config

    try:
        with open(RULE_CONFIDENCE_FILE, "r") as f:
            loaded = json.load(f)

        default_config["default"] = loaded.get("default", "medium")
        default_config["overrides"] = loaded.get("overrides", {})

        logger.info(
            f"Loaded {len(default_config['overrides'])} rule confidence override(s) from {RULE_CONFIDENCE_FILE}")

        return default_config
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load rule confidence config ({e}); using default confidence for all rules.")
        return default_config


CONFIDENCE_CONFIG = _load_confidence_config()


def _get_confidence(rule_name: str) -> str:
    return CONFIDENCE_CONFIG["overrides"].get(rule_name, CONFIDENCE_CONFIG["default"])


def _discover_rule_files() -> list:
    if not RULES_DIR.exists():
        logger.warning(f"Rules directory not found at {RULES_DIR}")
        return []

    found = []
    for root, _dirs, files in os.walk(RULES_DIR):
        for file in files:
            if file.endswith((".yar", ".yara")):
                found.append(Path(root) / file)
    return found


def _initialize_rules():
    candidates = _discover_rule_files()

    if not candidates:
        logger.warning("No YARA rules found under the rules directory.")
        return None

    logger.info(f"Discovered {len(candidates)} candidate rule file(s). Validating individually...")

    good_files = {}
    rejected = []

    for path in candidates:
        namespace = str(path.relative_to(RULES_DIR))

        try:
            yara.compile(filepath=str(path))
            good_files[namespace] = str(path)
        except yara.SyntaxError as e:
            rejected.append((namespace, str(e)))
        except Exception as e:
            rejected.append((namespace, f"Unexpected error: {e}"))

    if rejected:
        logger.warning(f"Skipping {len(rejected)} rule file(s) that failed to compile:")

        for namespace, reason in rejected:
            logger.warning(f"  - {namespace}: {reason}")

    if not good_files:
        logger.error("No rule files compiled successfully. Scanning will be disabled.")
        return None

    try:
        logger.info(f"Pre-compiling {len(good_files)} validated YARA rule file(s) into memory...")
        return yara.compile(filepaths=good_files)
    except yara.SyntaxError as e:
        logger.error(f"Syntax error compiling merged YARA ruleset: {str(e)}")
        raise


COMPILED_RULES = _initialize_rules()

VALID_EXTENSIONS = {".dex", ".so", ".xml", ".js", ".json", ".html"}


def _extract_string_matches(match) -> list:
    """Pull out exactly what triggered the match — which string identifier,
    where in the file, and the actual bytes matched — so a hit can be
    manually triaged instead of trusted blindly off the rule name alone"""
    extracted = []
    for string_match in match.strings:
        instances = []

        for instance in string_match.instances[:MAX_INSTANCES_PER_STRING]:
            raw = instance.matched_data
            text = raw.decode("utf-8", errors="replace")

            if len(text) > MAX_MATCHED_TEXT_LEN:
                text = text[:MAX_MATCHED_TEXT_LEN] + "...(truncated)"

            instances.append({
                "offset": instance.offset,
                "matched_text": text,
                "matched_hex": raw.hex()
            })

        extracted.append({
            "identifier": string_match.identifier,
            "instances": instances
        })

    return extracted


def _scan_single_file(file_path: str, target_dir: Path) -> list:
    local_matches = []

    try:
        matches = COMPILED_RULES.match(file_path)
        for match in matches:
            local_matches.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "description": match.meta.get("description", "No description provided"),
                "file": os.path.relpath(file_path, target_dir),
                "confidence": _get_confidence(match.rule),
                "matched_strings": _extract_string_matches(match)
            })
    except Exception as e:
        logger.warning(f"Failed to scan file {file_path}: {str(e)}")

    return local_matches


def scan_directory(target_dir: Path) -> dict:
    if not COMPILED_RULES:
        return {"status": "error", "message": "No valid YARA rules compiled."}

    logger.info("Starting multithreaded YARA scan...")

    files_to_scan = []
    files_skipped = 0

    for root, dirs, files in os.walk(target_dir):
        for file in files:
            file_path = os.path.join(root, file)

            if Path(file_path).suffix.lower() not in VALID_EXTENSIONS:
                files_skipped += 1
            else:
                files_to_scan.append(file_path)

    matches_found = []
    files_scanned = len(files_to_scan)

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_file = {executor.submit(_scan_single_file, fp, target_dir): fp for fp in files_to_scan}

        for future in as_completed(future_to_file):
            result = future.result()
            if result:
                matches_found.extend(result)

    logger.info(f"Scan complete. Scanned: {files_scanned} files. Skipped: {files_skipped} files")

    high_confidence_matches = [m for m in matches_found if m["confidence"] in ("high", "medium")]
    low_confidence_matches = [m for m in matches_found if m["confidence"] == "low"]

    return {
        "status": "completed",
        "is_clean": len(high_confidence_matches) == 0,
        "needs_review": len(low_confidence_matches) > 0,
        "scanned_files_count": files_scanned,
        "skipped_files_count": files_skipped,
        "threats_found": len(high_confidence_matches),
        "low_confidence_matches_found": len(low_confidence_matches),
        "matches": matches_found
    }
