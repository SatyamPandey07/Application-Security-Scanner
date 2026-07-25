import time
from datetime import datetime, timezone
from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.db.models import Scan


@celery_app.task(name="run_stub_scan_task")
def run_stub_scan_task(scan_id: int):
    scan = None
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return {"status": "error", "message": f"Scan ID {scan_id} not found"}

        # Update status to running
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        # Simulate scanning delay
        time.sleep(0.5)

        # Mark scan as completed
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()

        return {"status": "success", "scan_id": scan_id}
    except Exception as e:
        db.rollback()
        if scan:
            scan.status = "failed"
            db.commit()
        raise e
    finally:
        db.close()
