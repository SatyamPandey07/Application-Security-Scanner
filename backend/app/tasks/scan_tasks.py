import time
from datetime import datetime, timezone
from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.db.models import Scan, Finding
from app.engine.sast_engine import run_sast_scan


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

        if scan.target_type == "repo":
            # Real SAST scan via Semgrep
            sast_results = run_sast_scan(scan.target)
            for item in sast_results:
                finding = Finding(
                    scan_id=scan.id,
                    source=item.get("source", "sast"),
                    rule_id=item.get("rule_id", "sast-rule"),
                    file_path=item.get("file_path"),
                    line_number=item.get("line_number"),
                    code_snippet=item.get("code_snippet"),
                    severity_raw=item.get("severity_raw", "WARNING"),
                    status="open",
                )
                db.add(finding)
        else:
            # URL target stub for now (PR 5 DAST)
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
