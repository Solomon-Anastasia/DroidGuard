import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
RULES_DIR = BASE_DIR / "rules"
TEMP_EXTRACT_DIR = BASE_DIR / "tmp"
RULE_CONFIDENCE_FILE = BASE_DIR / "rule_confidence.json"

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8081/api/internal")
CALLBACK_ENDPOINT = f"{GATEWAY_URL}/complete"
API_TIMEOUT = int(os.getenv("API_TIMEOUT", 10))

MQ_HOST = os.getenv("MQ_HOST", "localhost")
MQ_PORT = int(os.getenv("MQ_PORT", 5672))
MQ_QUEUE = os.getenv("MQ_QUEUE", "analysis.jobs.queue")
MQ_USER = os.getenv("MQ_USER", "guest")
MQ_PASSWORD = os.getenv("MQ_PASSWORD", "guest")

TEMP_EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
