import os
import yara
import logging
from pathlib import Path

from concurrent.futures import ThreadPoolExecutor, as_completed

from config import RULES_DIR

logger = logging.getLogger(__name__)


def _initialize_rules():
    rule_files = {}
    if not RULES_DIR.exists():
        logger.warning(f"Rules directory not found at {RULES_DIR}")
        return None

    for file in os.listdir(RULES_DIR):
        if file.endswith(".yar"):
            rule_files[file] = str(RULES_DIR / file)

    if not rule_files:
        logger.warning("No YARA rules found in the rules directory.")
        return None

    try:
        logger.info(f"Pre-compiling {len(rule_files)} YARA rule files into memory...")
        return yara.compile(filepaths=rule_files)
    except yara.SyntaxError as e:
        logger.error(f"Syntax error compiling YARA rules: {str(e)}")
        raise


COMPILED_RULES = _initialize_rules()

VALID_EXTENSIONS = {".dex", ".so", ".xml", ".smali", ".js", ".json", ".html" }

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
                "file": os.path.relpath(file_path, target_dir)
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

    return {
        "status": "completed",
        "is_clean": len(matches_found) == 0,
        "scanned_files_count": files_scanned,
        "skipped_files_count": files_skipped,
        "threats_found": len(matches_found),
        "matches": matches_found
    }
