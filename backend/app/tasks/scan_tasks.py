from datetime import datetime, timezone
from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.db.models import Scan, Finding
from app.engine.sast_engine import run_sast_scan
from app.engine.dast_engine import run_dast_scan
from app.engine.dependency_secrets_engine import run_dependency_scan, run_secrets_scan


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

        results = []
        if scan.target_type == "repo":
            # Correlated Scanning: SAST + Dependency + Secrets
            sast_findings = run_sast_scan(scan.target)
            dep_findings = run_dependency_scan(scan.target)
            secret_findings = run_secrets_scan(scan.target)
            results = sast_findings + dep_findings + secret_findings

        elif scan.target_type == "url":
            # DAST baseline scan via OWASP ZAP / Passive HTTP check
            results = run_dast_scan(scan.target)

        # Store all findings in DB
        for item in results:
            finding = Finding(
                scan_id=scan.id,
                source=item.get("source", "sast"),
                rule_id=item.get("rule_id", "security-rule"),
                file_path=item.get("file_path"),
                line_number=item.get("line_number", 1),
                code_snippet=item.get("code_snippet"),
                severity_raw=item.get("severity_raw", "MEDIUM"),
                status="open",
            )
            db.add(finding)

        # Mark scan as completed
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()

        return {"status": "success", "scan_id": scan_id, "findings_count": len(results)}

    except Exception as e:
        db.rollback()
        if scan:
            scan.status = "failed"
            db.commit()
        raise e
    finally:
        db.close()
