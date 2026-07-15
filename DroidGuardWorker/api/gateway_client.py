import logging
import requests
import json
from config import API_TIMEOUT, GATEWAY_URL

logger = logging.getLogger(__name__)


class GatewayClient:
    def __init__(self):
        self.base_url = GATEWAY_URL
        self.timeout = API_TIMEOUT

    def send_analysis_report(self, job_id: str, yara_report: dict) -> bool:
        url = f"{self.base_url}/complete"
        payload = {"jobId": job_id, "yaraReport": yara_report}

        try:
            logger.info(f"Sending completion callback for job {job_id} to Gateway...")

            response = requests.post(
                url,
                json=payload,
                timeout=self.timeout
            )

            response.raise_for_status()

            logger.info(f"Successfully updated Gateway for job {job_id}")
            return True

        except requests.exceptions.ConnectionError:
            logger.error(f"Failed to connect to Gateway at {url}. Is Spring Boot running?")
            return False
        except requests.exceptions.Timeout:
            logger.error(f"Gateway callback timed out after {self.timeout} seconds for job {job_id}.")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending report to Gateway for job {job_id}: {str(e)}")
            return False

    def check_job_status(self, job_id: str) -> str:
        try:
            url = f"{self.base_url}/status/{job_id}"
            response = requests.get(url, timeout=self.timeout)

            if response.status_code == 200:
                status_text = response.text.strip().strip('"').upper()

                if "{" in status_text and "STATUS" in status_text:
                    status_text = json.loads(response.text).get("status", "UNKNOWN").upper()

                return status_text
            else:
                logger.warning(f"[GatewayClient] Status check failed: HTTP {response.status_code}")
                return "UNKNOWN"

        except Exception as e:
            logger.error(f"[GatewayClient] Exception during status check: {str(e)}")
            return "UNKNOWN"

    def report_job_failed(self, job_id, error_message):
        try:
            url = f"{self.base_url}/status/failed"
            payload = {"jobId": job_id, "errorMessage": error_message}

            response = requests.post(
                url,
                json=payload,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                logger.info(f"[GATEWAY] Successfully reported failure for job {job_id}")
                return True
            else:
                logger.error(f"[GATEWAY] Gateway rejected failure report for job {job_id}: {response.text}")
                return False

        except Exception as e:
            logger.error(f"[GATEWAY] Failed to connect to Gateway to report job failure: {str(e)}")
            return False


gateway_client = GatewayClient()
