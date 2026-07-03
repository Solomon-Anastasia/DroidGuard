# DroidGuardWorker/analysis/extractor.py

import shutil
import zipfile
import logging
from pathlib import Path
from androguard.core.bytecodes.apk import APK

from config import TEMP_EXTRACT_DIR

logger = logging.getLogger(__name__)


def extract_apk(apk_path: str, job_id: str) -> Path:
    """
    Unzips the APK and decodes the AndroidManifest.xml into readable text.
    Returns the Path to the directory containing the extracted files.
    """
    job_dir = TEMP_EXTRACT_DIR / str(job_id)
    job_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Unzip the raw files (classes.dex, lib/, assets/, etc.)
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            zip_ref.extractall(job_dir)

        # 2. Use Androguard to decode the binary AndroidManifest.xml
        # This is critical so YARA can scan for suspicious permissions or intents
        logger.info(f"Decoding binary AndroidManifest for job {job_id}...")
        parsed_apk = APK(apk_path)
        manifest_xml = parsed_apk.get_android_manifest_xml()

        if manifest_xml is not None:
            # Overwrite the binary manifest with the decoded XML tree
            manifest_path = job_dir / "AndroidManifest.xml"
            with open(manifest_path, "wb") as f:
                f.write(manifest_xml.toprettyxml(encoding="utf-8"))

        logger.info(f"Successfully extracted APK to {job_dir}")
        return job_dir

    except zipfile.BadZipFile:
        logger.error(f"Job {job_id} failed: File at {apk_path} is not a valid ZIP/APK.")
        raise
    except Exception as e:
        logger.error(f"Failed to extract APK {apk_path}: {str(e)}")
        raise


def cleanup_temp_dir(job_id: str):
    """
    Deletes the temporary extraction folder after analysis is complete.
    """
    job_dir = TEMP_EXTRACT_DIR / str(job_id)
    if job_dir.exists() and job_dir.is_dir():
        try:
            shutil.rmtree(job_dir)
            logger.info(f"Cleaned up temporary directory for job {job_id}")
        except Exception as e:
            logger.error(f"Failed to clean up {job_dir}: {str(e)}")