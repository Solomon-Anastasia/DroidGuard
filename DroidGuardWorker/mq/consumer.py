import json
import pika
import logging
import traceback

from config import MQ_HOST, MQ_PORT, MQ_QUEUE, MQ_USER, MQ_PASSWORD
from api import gateway_client
from analysis import extract_apk, scan_directory, cleanup_temp_dir

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


def process_analysis_job(ch, method, properties, body):
    job_id = "UNKNOWN"

    try:
        message = json.loads(body.decode('utf-8'))
        job_id = message.get("jobId")
        sha256 = message.get("sha256")
        apk_path = message.get("storagePath")
        app_name = message.get("appName")

        logger.info(f"--- Received Job {job_id} ---")
        logger.info(f"Target APK: {app_name} | Path: {apk_path}")

        logger.info(f"Extracting APK for Job {job_id}...")
        extracted_dir = extract_apk(apk_path, job_id)

        logger.info(f"Scanning extracted files for Job {job_id}...")
        report_dict = scan_directory(extracted_dir)

        report_dict = {
            "status": "clean",
            "matches": [],
            "scanned_files": 150,
            "message": "Mock report: YARA scanner not yet implemented."
        }

        logger.info(f"Sending results to Gateway for Job {job_id}...")
        success = gateway_client.send_analysis_report(job_id, report_dict)

        if success:
            ch.basic_ack(delivery_tag=method.delivery_tag)
            logger.info(f"--- Job {job_id} Completed & Acknowledged ---")
        else:
            logger.warning(f"Failed to update Gateway. Re-queuing Job {job_id}.")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

    except json.JSONDecodeError:
        logger.error("Failed to decode message body as JSON. Discarding message.")
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        logger.error(f"Critical error processing Job {job_id}: {str(e)}")
        logger.error(traceback.format_exc())
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    finally:
        cleanup_temp_dir(job_id)
        pass


def start_consuming():
    credentials = pika.PlainCredentials(MQ_USER, MQ_PASSWORD)
    parameters = pika.ConnectionParameters(
        host=MQ_HOST,
        port=MQ_PORT,
        credentials=credentials,
        heartbeat=600
    )

    try:
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()

        channel.queue_declare(
            queue=MQ_QUEUE,
            durable=True,
            arguments={'x-max-length': 10_000}
        )

        channel.basic_qos(prefetch_count=1)

        channel.basic_consume(
            queue=MQ_QUEUE,
            on_message_callback=process_analysis_job,
            auto_ack=False
        )

        logger.info(f"[*] Waiting for messages on '{MQ_QUEUE}'. To exit press CTRL+C")
        channel.start_consuming()

    except pika.exceptions.AMQPConnectionError:
        logger.error(f"Failed to connect to RabbitMQ at {MQ_HOST}:{MQ_PORT}. Is it running?")
    except KeyboardInterrupt:
        logger.info("Worker stopped by user.")
        if 'connection' in locals() and connection.is_open:
            connection.close()