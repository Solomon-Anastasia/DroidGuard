import shutil

import zipfile

import logging
from androguard.core.bytecodes.apk import APK
from lxml import etree

from api import gateway_client
from config import TEMP_EXTRACT_DIR

# Monkey patching
# Ignore CRC-32 checks: checksum corruption
zipfile.ZipExtFile._update_crc = lambda *args, **kwargs: None

_original_infolist = zipfile.ZipFile.infolist
_original_getinfo = zipfile.ZipFile.getinfo


# Sanitize fake compression headers: BadPack
def _sanitized_infolist(self):
    infos = _original_infolist(self)

    for info in infos:
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            info.compress_type = zipfile.ZIP_STORED

    return infos


def _sanitized_getinfo(self, name):
    info = _original_getinfo(self, name)

    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        info.compress_type = zipfile.ZIP_STORED

    return info


zipfile.ZipFile.infolist = _sanitized_infolist
zipfile.ZipFile.getinfo = _sanitized_getinfo

logger = logging.getLogger(__name__)


def extract_apk(apk_path: str, job_id: str):
    job_dir = TEMP_EXTRACT_DIR / str(job_id)
    job_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            zip_ref.extractall(job_dir)

        logger.info(f"Decoding binary AndroidManifest for job {job_id}...")
        parsed_apk = APK(apk_path)
        manifest_xml = parsed_apk.get_android_manifest_xml()

        if manifest_xml is not None:
            manifest_path = job_dir / "AndroidManifest.xml"  # Join dir

            # Transform binary XML into readable XML
            with open(manifest_path, "wb") as f:
                f.write(etree.tostring(manifest_xml, pretty_print=True, encoding="utf-8"))

        logger.info(f"Successfully extracted APK to {job_dir}")
        return job_dir, parsed_apk

    except zipfile.BadZipFile:
        logger.error(f"Job {job_id} failed: File at {apk_path} is not a valid ZIP/APK")
        gateway_client.report_job_failed(job_id, "Job failed, not a valid ZIP/APK")
        raise
    except Exception as e:
        logger.error(f"Failed to extract APK {apk_path}: {str(e)}")
        gateway_client.report_job_failed(job_id, "Job failed, not a valid ZIP/APK")
        raise


def cleanup_temp_dir(job_id: str):
    job_dir = TEMP_EXTRACT_DIR / str(job_id)

    if job_dir.exists() and job_dir.is_dir():
        try:
            shutil.rmtree(job_dir)
            logger.info(f"Cleaned up temporary directory for job {job_id}")
        except Exception as e:
            logger.error(f"Failed to clean up {job_dir}: {str(e)}")
