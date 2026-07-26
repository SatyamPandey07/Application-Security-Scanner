import os
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.db.models import Scan, Finding
from app.engine.sast_engine import run_sast_scan
from app.engine.dast_engine import run_dast_scan
from app.engine.dependency_secrets_engine import run_dependency_scan, run_secrets_scan
from app.engine.ai_remediation import validate_and_remediate_finding
from app.engine.cvss_calculator import map_finding_to_cvss
from app.engine.idor_engine import run_authenticated_idor_scan


@celery_app.task(name="run_stub_scan_task")
def run_stub_scan_task(scan_id: int, auth_credentials: Optional[Dict[str, Any]] = None):
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
            dast_findings = run_dast_scan(scan.target)
            results = dast_findings

            # Authenticated IDOR / BOLA Check if credentials provided
            if auth_credentials and "user_a" in auth_credentials and "user_b" in auth_credentials:
                idor_findings = run_authenticated_idor_scan(
                    target_url=scan.target,
                    user_a_creds=auth_credentials["user_a"],
                    user_b_creds=auth_credentials["user_b"],
                    auth_login_endpoint=auth_credentials.get("login_endpoint", "/auth/login"),
                    test_resource_endpoints=auth_credentials.get("test_endpoints"),
                )
                results.extend(idor_findings)

        # Store all findings in DB with AI validation post-processing & CVSS scoring
        for item in results:
            file_path = item.get("file_path")
            line_number = item.get("line_number", 1)
            code_snippet = item.get("code_snippet", "")
            severity_raw = item.get("severity_raw", "MEDIUM")
            rule_id = item.get("rule_id", "security-rule")
            source = item.get("source", "sast")

            # Extract surrounding code context if scanning local file repo
            surrounding_code = ""
            if scan.target_type == "repo" and file_path and os.path.exists(os.path.join(scan.target, file_path)):
                try:
                    full_p = os.path.join(scan.target, file_path)
                    with open(full_p, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        start_l = max(0, line_number - 10)
                        end_l = min(len(lines), line_number + 10)
                        surrounding_code = "".join(lines[start_l:end_l])
                except Exception:
                    pass

            # Run AI Validation & Remediation Layer
            ai_data = validate_and_remediate_finding(
                rule_id=rule_id,
                file_path=file_path,
                line_number=line_number,
                code_snippet=code_snippet,
                surrounding_code=surrounding_code,
            )

            # Determine finding status based on AI confirmation and confidence threshold (>= 0.6)
            is_true_pos = ai_data.get("is_likely_true_positive", True)
            conf_val = float(ai_data.get("confidence", 0.7))
            status_val = "confirmed" if (is_true_pos and conf_val >= 0.6) else "low_confidence"

            # Calculate CVSS v3.1 Score
            cvss_info = map_finding_to_cvss(source=source, severity_raw=severity_raw, rule_id=rule_id)

            finding = Finding(
                scan_id=scan.id,
                source=source,
                rule_id=rule_id,
                file_path=file_path,
                line_number=line_number,
                code_snippet=code_snippet,
                severity_raw=severity_raw,
                cvss_score=cvss_info["cvss_score"],
                ai_confidence=f"{conf_val:.2f}",
                ai_explanation=ai_data.get("plain_english_explanation"),
                ai_fix_diff=ai_data.get("suggested_fix_diff"),
                status=status_val,
                # Plain-language fields (PR 8 & enhanced)
                plain_title=ai_data.get("plain_title"),
                plain_location=ai_data.get("plain_location"),
                plain_whats_wrong=ai_data.get("plain_whats_wrong"),
                plain_why_it_exists=ai_data.get("plain_why_it_exists"),
                plain_real_world_impact=ai_data.get("plain_real_world_impact"),
                plain_risk_level=ai_data.get("plain_risk_level"),
                plain_what_to_do=ai_data.get("plain_what_to_do"),
                feature_area=ai_data.get("feature_area"),
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
