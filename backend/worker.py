"""Single-owner persistent scan worker for production deployments."""
import logging
import signal
import time

from sqlalchemy import text

from backend.core.config import settings
from backend.database.models import Scan, SessionLocal, engine, utcnow
from backend.scanner.orchestrator import execute_scan_task

logger = logging.getLogger("exposuregraph.worker")
_stopping = False
_POSTGRES_LOCK_ID = 741_290_115_205


def _stop(_signum, _frame):
    global _stopping
    _stopping = True


def _acquire_single_worker_lock():
    if engine.dialect.name != "postgresql":
        raise RuntimeError("The production scan worker requires PostgreSQL advisory locks.")
    lock_connection = engine.connect()
    acquired = bool(lock_connection.execute(
        text("SELECT pg_try_advisory_lock(:lock_id)"), {"lock_id": _POSTGRES_LOCK_ID},
    ).scalar())
    lock_connection.commit()
    if not acquired:
        lock_connection.close()
        return None
    return lock_connection


def _recover_interrupted_scans() -> int:
    db = SessionLocal()
    try:
        changed = db.query(Scan).filter(Scan.status == "RUNNING").update({
            Scan.status: "FAILED",
            Scan.error_message: "The scan worker restarted before this assessment completed. Start a new assessment.",
            Scan.completed_at: utcnow(),
        }, synchronize_session=False)
        db.commit()
        return changed
    finally:
        db.close()


def _claim_next_scan() -> int | None:
    db = SessionLocal()
    try:
        scan = db.query(Scan.id).filter(Scan.status == "PENDING").order_by(Scan.id.asc()).first()
        if not scan:
            return None
        scan_id = scan[0]
        claimed = db.query(Scan).filter(Scan.id == scan_id, Scan.status == "PENDING").update(
            {Scan.status: "RUNNING"}, synchronize_session=False,
        )
        db.commit()
        return scan_id if claimed == 1 else None
    finally:
        db.close()


def run_worker() -> None:
    if settings.scan_execution_mode != "worker":
        raise RuntimeError("Set SCAN_EXECUTION_MODE=worker before starting the scan worker.")
    lock_connection = _acquire_single_worker_lock()
    if lock_connection is None:
        raise RuntimeError("Another ExposureGraph scan worker already holds the worker lock.")
    try:
        interrupted = _recover_interrupted_scans()
        if interrupted:
            logger.warning("Marked %d interrupted scan(s) as failed.", interrupted)
        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)
        logger.info("ExposureGraph scan worker started.")

        while not _stopping:
            scan_id = _claim_next_scan()
            if scan_id is None:
                time.sleep(max(0.1, settings.scan_worker_poll_seconds))
                continue
            try:
                execute_scan_task(scan_id)
            except Exception:
                logger.exception("Unhandled error while processing scan %s", scan_id)
    finally:
        lock_connection.execute(
            text("SELECT pg_advisory_unlock(:lock_id)"), {"lock_id": _POSTGRES_LOCK_ID},
        )
        lock_connection.commit()
        lock_connection.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_worker()
