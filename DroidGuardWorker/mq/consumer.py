import json
import logging
import queue
import time
import multiprocessing
import traceback

import pika
from pika.exceptions import AMQPConnectionError

from config import MQ_HOST, MQ_PORT, MQ_QUEUE, MQ_USER, MQ_PASSWORD
from api import gateway_client
from analysis import cleanup_temp_dir
from analysis.analyzer_task import run_heavy_analysis

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)


def process_analysis_job(ch, method, _properties, body):
    job_id = "UNKNOWN"

    try:
        message = json.loads(body.decode('utf-8'))
        job_id = message.get("jobId")
        apk_path = message.get("storagePath")

        logger.info(f"Received job {job_id}")

        if gateway_client.check_job_status(job_id) == "ABORTED":
            logger.info(f"Job {job_id} aborted before execution. Dropping")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        # Help to share data between consumer and analyzer
        result_queue = multiprocessing.Queue()
        analysis_process = multiprocessing.Process(
            target=run_heavy_analysis,
            args=(apk_path, job_id, result_queue)
        )

        analysis_process.start()

        final_payload = None
        while analysis_process.is_alive():
            current_status = gateway_client.check_job_status(job_id)
            if current_status == "ABORTED":
                logger.warning(f"Job {job_id} aborted by user mid-analysis! Killing subprocess")

                analysis_process.terminate()
                analysis_process.join()
                ch.basic_ack(delivery_tag=method.delivery_tag)
                return

            try:
                final_payload = result_queue.get(timeout=3)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Unexpected error reading from queue: {e}")
                break

        logger.info(f"Analysis process for job {job_id} finished or payload received. Joining...")
        analysis_process.join()
        logger.info(f"Process joined successfully for job {job_id}")

        if final_payload is None:
            try:
                final_payload = result_queue.get(timeout=1)
            except queue.Empty:
                pass

        # Handle the results
        if final_payload and final_payload.get("status") == "success":
            report_dict = final_payload.get("report")

            logger.info(f"Analysis succeeded. Sending final results to Gateway for job {job_id}...")
            success = gateway_client.send_analysis_report(job_id, report_dict)

            if success:
                ch.basic_ack(delivery_tag=method.delivery_tag)
                logger.info(f"Job {job_id} completed and acknowledged")
            else:
                logger.error("Gateway is offline. Waiting 10 seconds before requeueing...")
                time.sleep(10)
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

        else:
            if final_payload:
                error_msg = final_payload.get("error_message", "Unknown error")
            else:
                error_msg = "No result in queue after process finished"

            logger.error(f"Analysis failed internally for job {job_id}: {error_msg}")
            gateway_client.report_job_failed(job_id, error_msg)
            ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        logger.error(f"Critical error in main consumer for job {job_id}: {str(e)}")
        logger.error(traceback.format_exc())

        if job_id != "UNKNOWN":
            gateway_client.report_job_failed(job_id, str(e))

        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    finally:
        logger.info(f"Cleaning up temporary directory for job {job_id}")
        cleanup_temp_dir(job_id)


def start_consuming():
    credentials = pika.PlainCredentials(MQ_USER, MQ_PASSWORD)
    parameters = pika.ConnectionParameters(
        host=MQ_HOST,
        port=MQ_PORT,
        credentials=credentials,
        heartbeat=600  # 10 min
    )

    connection = None

    try:
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()

        channel.queue_declare(
            queue=MQ_QUEUE,
            durable=True,
            arguments={'x-max-length': 10_000}
        )

        # One message at a time
        channel.basic_qos(prefetch_count=1)

        channel.basic_consume(
            queue=MQ_QUEUE,
            on_message_callback=process_analysis_job,
            auto_ack=False
        )

        logger.info(f"Waiting for messages on '{MQ_QUEUE}'. To exit press CTRL+C")
        channel.start_consuming()

    except pika.exceptions.AMQPConnectionError:
        logger.error(f"Failed to connect to RabbitMQ at {MQ_HOST}:{MQ_PORT}")

    except KeyboardInterrupt:
        logger.info("Worker stopped by user")

        if connection is not None and connection.is_open:
            connection.close()
