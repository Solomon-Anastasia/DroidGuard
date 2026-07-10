import json
import pika
import logging
import time
import multiprocessing
from analysis.analyzer_task import run_heavy_analysis

from config import MQ_HOST, MQ_PORT, MQ_QUEUE, MQ_USER, MQ_PASSWORD
from api import gateway_client
from analysis import cleanup_temp_dir

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
        apk_path = message.get("storagePath")

        logger.info(f"[CONSUMER] Received job {job_id}")

        if gateway_client.check_job_status(job_id) == "ABORTED":
            logger.info(f"Job {job_id} aborted before execution. Dropping")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        # Prepare the Subprocess
        result_queue = multiprocessing.Queue()
        analysis_process = multiprocessing.Process(
            target=run_heavy_analysis,
            args=(apk_path, job_id, result_queue)
        )

        # Start the isolated process
        analysis_process.start()

        final_payload = None

        # The polling loop
        while analysis_process.is_alive():
            time.sleep(3)

            current_status = gateway_client.check_job_status(job_id)
            if current_status == "ABORTED":
                logger.warning(f"Job {job_id} aborted by user mid-analysis! Killing Subprocess")

                analysis_process.terminate()
                analysis_process.join()

                ch.basic_ack(delivery_tag=method.delivery_tag)
                return

        # Process finished naturally
        analysis_process.join()

        # Extract the results from the queue
        if not result_queue.empty():
            final_payload = result_queue.get()

        # Handle the results
        if final_payload and final_payload.get("status") == "success":
            report_dict = final_payload.get("report")

            logger.info(f"Sending final results to Gateway for Job {job_id}...")
            success = gateway_client.send_analysis_report(job_id, report_dict)

            if success:
                ch.basic_ack(delivery_tag=method.delivery_tag)
                logger.info(f"[CONSUMER] Job {job_id} completed and acknowledged")
            else:
                logger.warning(f"Failed to update Gateway. Re-queuing Job {job_id}")
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

        else:
            error_msg = final_payload.get("error_message") if final_payload else "Unknown Queue Error"
            logger.error(f"Analysis failed internally for job {job_id}: {error_msg}")

            # Do not requeue if the APK itself caused a fatal crash, just acknowledge to drop it
            ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        logger.error(f"Critical error in main consumer for job {job_id}: {str(e)}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    finally:
        cleanup_temp_dir(job_id)


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

        logger.info(f"[CONSUMER] Waiting for messages on '{MQ_QUEUE}'. To exit press CTRL+C")
        channel.start_consuming()

    except pika.exceptions.AMQPConnectionError:
        logger.error(f"Failed to connect to RabbitMQ at {MQ_HOST}:{MQ_PORT}. Is it running?")
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
        if 'connection' in locals() and connection.is_open:
            connection.close()
