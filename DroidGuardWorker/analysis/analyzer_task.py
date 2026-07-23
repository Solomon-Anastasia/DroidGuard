import logging
import traceback
import multiprocessing

from analysis import extract_apk, scan_directory
from analysis import manifest_analyzer
import verdict


def run_heavy_analysis(apk_path: str, job_id: str, result_queue: multiprocessing.Queue):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] [WorkerProcess] %(message)s'
    )

    logger = logging.getLogger(__name__)
    logger.info(f"Subprocess started for job {job_id}. Target: {apk_path}")

    try:
        logger.info(f"Extracting APK for job {job_id}...")
        extracted_dir, parsed_apk = extract_apk(apk_path, job_id)

        logger.info(f"Running YARA scan for job {job_id}...")
        yara_report = scan_directory(extracted_dir)

        logger.info(f"Running Androguard heuristics for job {job_id}...")
        heuristic_report = manifest_analyzer.analyze(parsed_apk)

        logger.info(f"Compiling final verdict for job {job_id}...")
        report_dict = verdict.build_verdict(yara_report, heuristic_report)

        result_queue.put({
            "status": "success",
            "report": report_dict
        })
        logger.info(f"Subprocess finished analysis for job {job_id} successfully")

    except Exception as e:
        logger.error(f"Critical failure in subprocess for job {job_id}: {str(e)}")
        logger.error(traceback.format_exc())

        result_queue.put({
            "status": "error",
            "error_message": str(e)
        })
