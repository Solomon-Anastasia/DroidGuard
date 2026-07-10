import logging
import requests
from config import CALLBACK_ENDPOINT, API_TIMEOUT

logger = logging.getLogger(__name__)


class GatewayClient:
    def __init__(self):
        self.callback_url = CALLBACK_ENDPOINT
        self.timeout = API_TIMEOUT

    def send_analysis_report(self, job_id: str, yara_report: dict) -> bool:
        payload = {
            "jobId": job_id,
            "yaraReport": yara_report
        }

        try:
            logger.info(f"Sending completion callback for job {job_id} to Gateway...")

            response = requests.post(
                self.callback_url,
                json=payload,
                timeout=self.timeout
            )

            response.raise_for_status()

            logger.info(f"Successfully updated Gateway for job {job_id}.")
            return True

        except requests.exceptions.ConnectionError:
            logger.error(f"Failed to connect to Gateway at {self.callback_url}. Is Spring Boot running?")
            return False
        except requests.exceptions.Timeout:
            logger.error(f"Gateway callback timed out after {self.timeout} seconds for job {job_id}.")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending report to Gateway for job {job_id}: {str(e)}")
            return False

    def check_job_status(self, job_id: str) -> str:
        try:
            url = self.callback_url.replace("/complete", f"/status/{job_id}")

            response = requests.get(url, timeout=self.timeout)

            if response.status_code == 200:
                # Clean up the string and force uppercase for safe matching
                status_text = response.text.strip().strip('"').upper()

                # Fallback: If it accidentally hit the JSON endpoint instead of the internal one
                if "{" in status_text and "STATUS" in status_text:
                    import json
                    status_text = json.loads(response.text).get("status", "UNKNOWN").upper()

                # logger.info(f"[GatewayClient] Gateway reports status for Job {job_id} is: {status_text}")
                return status_text
            else:
                logger.warning(f"[GatewayClient] Status check failed: HTTP {response.status_code}")
                return "UNKNOWN"

        except Exception as e:
            logger.error(f"[GatewayClient] Exception during status check: {str(e)}")
            return "UNKNOWN"

gateway_client = GatewayClient()
