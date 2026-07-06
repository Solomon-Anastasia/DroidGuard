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

gateway_client = GatewayClient()