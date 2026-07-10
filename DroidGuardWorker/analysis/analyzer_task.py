import logging
import traceback
import multiprocessing

# Import your existing analysis modules
from analysis import extract_apk, scan_directory
from analysis import manifest_analyzer
import verdict


def run_heavy_analysis(apk_path: str, job_id: str, result_queue: multiprocessing.Queue):
    """
    Executes the heavy CPU-bound analysis inside an isolated process.
    This entire function gets destroyed instantly if the parent calls terminate().
    """
    # 1. Set up a dedicated logger for the child process
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] [WorkerProcess] %(message)s'
    )
    logger = logging.getLogger(__name__)

    logger.info(f"Subprocess started for Job {job_id}. Target: {apk_path}")

    try:
        # 2. Extraction Phase
        logger.info(f"Extracting APK for Job {job_id}...")
        extracted_dir, parsed_apk = extract_apk(apk_path, job_id)

        # 3. YARA Scanning Phase
        logger.info(f"Running YARA scan for Job {job_id}...")
        yara_report = scan_directory(extracted_dir)

        # 4. Androguard Heuristic Phase (The heavily blocking part)
        logger.info(f"Running Androguard heuristics for Job {job_id}...")
        heuristic_report = manifest_analyzer.analyze(parsed_apk)

        # 5. Verdict Fusion
        logger.info(f"Compiling final verdict for Job {job_id}...")
        report_dict = verdict.build_verdict(yara_report, heuristic_report)

        # 6. Send the successful result back to the parent process
        result_queue.put({
            "status": "success",
            "report": report_dict
        })
        logger.info(f"Subprocess finished analysis for Job {job_id} successfully.")

    except Exception as e:
        # If Androguard crashes on a malformed DEX file, catch it safely
        logger.error(f"Critical failure in subprocess for Job {job_id}: {str(e)}")
        logger.error(traceback.format_exc())

        # Send the error back to the parent process so it can clean up
        result_queue.put({
            "status": "error",
            "error_message": str(e)
        })