import re
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import User, Scan, Finding
from app.core.security import get_current_user
from app.core.rate_limiter import check_rate_limit
from app.schemas.scans import ScanCreate, ScanOut, FindingOut
from app.tasks.scan_tasks import run_stub_scan_task
from app.engine.cvss_calculator import calculate_priority_score
from app.engine.compliance_mapper import generate_compliance_report, generate_compliance_csv

router = APIRouter(prefix="/scans", tags=["Scans"])

# Target Input Validation Regexes
URL_REGEX = re.compile(r'^https?://[a-zA-Z0-9.\-]+(?::\d+)?(?:/.*)?$')
SAFE_REPO_REGEX = re.compile(r'^(?:https?://|git@)[a-zA-Z0-9.\-:/_]+\.git$|^[a-zA-Z0-9._/\-]+$')


def validate_target_input(target: str, target_type: str):
    """
    Validates scan target URLs and repository targets against dangerous traversal paths and invalid formats.
    """
    clean_target = target.strip()
    if ".." in clean_target or ";" in clean_target or "|" in clean_target or "`" in clean_target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target string contains invalid shell characters or directory traversal patterns."
        )

    if target_type == "url":
        if not URL_REGEX.match(clean_target):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid URL target format. Must be a valid HTTP or HTTPS URL (e.g., https://example.com)."
            )
    elif target_type == "repo":
        if not SAFE_REPO_REGEX.match(clean_target):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid repository target format. Must be a valid Git repository URL or local repository path."
            )


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def submit_scan(
    scan_data: ScanCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Enforce Rate Limiting (10 requests per 60 seconds per user)
    check_rate_limit(f"submit_scan_{current_user.id}", max_requests=10, window_seconds=60)

    if not scan_data.authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Explicit authorization confirmation ('authorized': true) is required before submitting a scan."
        )

    if scan_data.target_type not in ["url", "repo"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid target_type. Must be 'url' or 'repo'."
        )

    clean_target = scan_data.target.strip()
    validate_target_input(clean_target, scan_data.target_type)

    # 1. Log explicit authorization consent
    from app.db.models import ConsentLog
    consent = ConsentLog(
        user_id=current_user.id,
        target=clean_target,
        target_type=scan_data.target_type,
    )
    db.add(consent)
    db.commit()

    # 2. Create scan record
    scan = Scan(
        user_id=current_user.id,
        target=clean_target,
        target_type=scan_data.target_type,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 3. Enqueue background task with optional auth credentials
    run_stub_scan_task.delay(scan.id, auth_credentials=scan_data.auth_credentials)

    return scan


@router.get("", response_model=List[ScanOut])
def list_user_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.started_at.desc()).all()


@router.get("/trends")
def get_target_scan_trends(
    target: str = Query(..., description="Target URL or repository path to calculate historical trends for"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns historical trend analytics (findings found vs fixed over time) for repeat scans against the same target.
    """
    scans = (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id, Scan.target == target.strip())
        .order_by(Scan.started_at.asc())
        .all()
    )

    history = []
    for s in scans:
        findings = db.query(Finding).filter(Finding.scan_id == s.id).all()
        confirmed_count = sum(1 for f in findings if f.status == "confirmed")
        critical_high_count = sum(1 for f in findings if f.severity_raw in ["CRITICAL", "HIGH", "ERROR"])
        avg_cvss = round(sum(f.cvss_score or 5.0 for f in findings) / max(len(findings), 1), 1)

        history.append({
            "scan_id": s.id,
            "started_at": s.started_at,
            "status": s.status,
            "total_findings": len(findings),
            "confirmed_findings": confirmed_count,
            "critical_high_findings": critical_high_count,
            "average_cvss": avg_cvss,
        })

    return {
        "target": target.strip(),
        "total_scans_conducted": len(scans),
        "trend_history": history,
    }


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan_by_id(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found."
        )
    return scan


@router.get("/{scan_id}/findings", response_model=List[FindingOut])
def get_scan_findings(
    scan_id: int,
    source: Optional[str] = Query(None, description="Filter by finding source (sast, dast, dependency, secret, access_control)"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    finding_status: Optional[str] = Query(None, alias="status", description="Filter by status (confirmed, low_confidence)"),
    sort_by: str = Query("priority", description="Sort by field (priority, cvss, severity, status)"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found."
        )

    query = db.query(Finding).filter(Finding.scan_id == scan_id)

    if source:
        query = query.filter(Finding.source == source.lower())
    if severity:
        query = query.filter(Finding.severity_raw == severity.upper())
    if finding_status:
        query = query.filter(Finding.status == finding_status.lower())

    raw_findings = query.all()
    results = []

    for f in raw_findings:
        cvss_val = f.cvss_score or 5.0
        conf_val = float(f.ai_confidence) if f.ai_confidence else 0.7
        p_score = calculate_priority_score(cvss_val, conf_val)

        f_out = FindingOut.from_orm(f)
        f_out.priority_score = p_score
        results.append(f_out)

    # Sorting
    if sort_by == "priority":
        results.sort(key=lambda x: x.priority_score or 0.0, reverse=True)
    elif sort_by == "cvss":
        results.sort(key=lambda x: x.cvss_score or 0.0, reverse=True)
    elif sort_by == "severity":
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "ERROR": 3, "MEDIUM": 2, "WARNING": 2, "LOW": 1, "INFO": 0}
        results.sort(key=lambda x: sev_rank.get(x.severity_raw.upper(), 0), reverse=True)

    return results


@router.get("/{scan_id}/compliance")
def get_scan_compliance_report(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found.")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    finding_dicts = [
        {"source": f.source, "status": f.status, "rule_id": f.rule_id, "severity_raw": f.severity_raw, "file_path": f.file_path}
        for f in findings
    ]
    return generate_compliance_report(finding_dicts)


@router.get("/{scan_id}/compliance/export")
def export_scan_compliance_csv(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found.")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    finding_dicts = [
        {"source": f.source, "status": f.status, "rule_id": f.rule_id, "severity_raw": f.severity_raw, "file_path": f.file_path}
        for f in findings
    ]
    csv_data = generate_compliance_csv(finding_dicts)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sentinel_compliance_scan_{scan_id}.csv"}
    )
