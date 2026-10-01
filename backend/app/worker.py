"""
Asynchronous worker architecture for StegoSentinel.
Supports Redis queue mode for containerized/multi-worker deployments,
and thread/in-process background execution for zero-config local development and testing.
"""

import logging
import threading
import time

import redis

from app.core.config import settings
from app.core.database import SessionLocal
from app.services.analysis_service import analysis_service

logger = logging.getLogger(__name__)

REDIS_QUEUE_KEY = "stegosentinel_analysis_queue"


def get_redis_client() -> redis.Redis | None:
    """Obtain Redis client if available."""
    try:
        r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        r.ping()
        return r
    except Exception:
        return None


def run_worker_task(analysis_id: str):
    """Execute analysis job within isolated DB session."""
    db = SessionLocal()
    try:
        logger.info(f"Worker starting execution for analysis {analysis_id}")
        analysis_service.execute_analysis(db, analysis_id)
        logger.info(f"Worker completed execution for analysis {analysis_id}")
    except Exception as e:
        logger.error(f"Worker encountered failure on analysis {analysis_id}: {e!s}")
    finally:
        db.close()


def dispatch_analysis_job(analysis_id: str):
    """
    Dispatch an analysis job.
    Uses Redis if ASYNC_MODE=redis and available;
    Executes synchronously if ASYNC_MODE=sync;
    Skips if ASYNC_MODE=manual (for test control);
    Otherwise uses background thread.
    """
    if settings.ASYNC_MODE == "manual":
        logger.info(
            f"Manual mode active: Analysis {analysis_id} dispatch deferred to test harness."
        )
        return

    if settings.ASYNC_MODE == "sync":
        logger.info(f"Sync mode active: Executing analysis {analysis_id} synchronously.")
        run_worker_task(analysis_id)
        return

    if settings.ASYNC_MODE == "redis":
        r = get_redis_client()
        if r:
            r.rpush(REDIS_QUEUE_KEY, analysis_id)
            logger.info(f"Pushed analysis {analysis_id} to Redis queue.")
            return

    # Fallback to local background thread
    t = threading.Thread(target=run_worker_task, args=(analysis_id,), daemon=True)
    t.start()
    logger.info(f"Dispatched analysis {analysis_id} via local background thread.")


def start_redis_worker_loop():
    """Continuously poll Redis queue for jobs (used in standalone worker container)."""
    logger.info("Starting StegoSentinel Redis worker daemon...")
    while True:
        r = get_redis_client()
        if not r:
            logger.warning("Redis unavailable. Retrying connection in 5 seconds...")
            time.sleep(5)
            continue

        try:
            # Blocking pop with 5s timeout
            item = r.blpop(REDIS_QUEUE_KEY, timeout=5)
            if item:
                _, analysis_id = item
                run_worker_task(analysis_id)
        except Exception as e:
            logger.error(f"Worker error in Redis poll loop: {e!s}")
            time.sleep(2)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start_redis_worker_loop()
