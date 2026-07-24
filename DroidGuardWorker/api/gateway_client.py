import logging
import requests
from config import API_TIMEOUT, GATEWAY_URL

logger = logging.getLogger(__name__)


class GatewayClient:
    def __init__(self):
        self.base_url = GATEWAY_URL
        self.timeout = API_TIMEOUT

    def send_analysis_report(self, job_id: str, yara_report: dict) -> bool:
        url = f"{self.base_url}/complete"

        # Include full YARA + Androguard report
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
            logger.error(f"Failed to connect to Gateway at {url}")
            return False
        except requests.exceptions.Timeout:
            logger.error(f"Gateway callback timed out after {self.timeout} seconds for job {job_id}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending report to Gateway for job {job_id}: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to Gateway to report job failure: {str(e)}")
            return False

    def check_job_status(self, job_id: str) -> str:
        try:
            url = f"{self.base_url}/status/{job_id}"

            response = requests.get(
                url,
                timeout=self.timeout
            )
            response.raise_for_status()

            return response.text.strip().strip('"').upper()

        except requests.exceptions.ConnectionError:
            logger.error(f"Failed to connect to Gateway at {url}.")
            return "UNKNOWN"
        except requests.exceptions.Timeout:
            logger.error(f"Status check timed out for job {job_id}.")
            return "UNKNOWN"
        except requests.exceptions.RequestException as e:
            logger.error(f"Status check failed for job {job_id}: {str(e)}")
            return "UNKNOWN"

    def report_job_failed(self, job_id, error_message):
        try:
            url = f"{self.base_url}/status/failed"
            payload = {"jobId": job_id, "errorMessage": error_message}

            response = requests.post(
                url,
                json=payload
            )
            response.raise_for_status()

            logger.info(f"Successfully reported failure for job {job_id}")
            return True

        except requests.exceptions.ConnectionError:
            logger.error(f"Failed to connect to Gateway at {url}.")
            return False
        except requests.exceptions.Timeout:
            logger.error(f"Gateway callback timed out for job {job_id}.")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Gateway rejected failure report for job {job_id}: {str(e)}")
            return False


gateway_client = GatewayClient()
