import os
import yara
import logging
from pathlib import Path

from config import RULES_DIR

logger = logging.getLogger(__name__)


def _compile_rules():
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
        logger.info(f"Compiling {len(rule_files)} YARA rule files...")
        return yara.compile(filepaths=rule_files)
    except yara.SyntaxError as e:
        logger.error(f"Syntax error compiling YARA rules: {str(e)}")
        raise


def scan_directory(target_dir: Path) -> dict:
    compiled_rules = _compile_rules()

    if not compiled_rules:
        return {
            "status": "error",
            "message": "No valid YARA rules compiled on the worker."
        }

    matches_found = []
    files_scanned = 0

    for root, dirs, files in os.walk(target_dir):
        for file in files:
            file_path = os.path.join(root, file)
            files_scanned += 1

            try:
                matches = compiled_rules.match(file_path)

                for match in matches:
                    matches_found.append({
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": match.tags,
                        "description": match.meta.get("description", "No description provided"),
                        "file": os.path.relpath(file_path, target_dir)
                    })
            except Exception as e:
                logger.warning(f"Failed to scan file {file_path}: {str(e)}")

    is_clean = len(matches_found) == 0

    return {
        "status": "completed",
        "is_clean": is_clean,
        "scanned_files_count": files_scanned,
        "threats_found": len(matches_found),
        "matches": matches_found
    }