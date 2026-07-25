from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import User, Scan, Finding
from app.core.security import get_current_user
from app.schemas.scans import ScanCreate, ScanOut, FindingOut
from app.tasks.scan_tasks import run_stub_scan_task
from app.engine.cvss_calculator import calculate_priority_score

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def submit_scan(
    scan_data: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
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

    if not scan_data.target or not scan_data.target.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL or repository path cannot be empty."
        )

    # 1. Log explicit authorization consent
    from app.db.models import ConsentLog
    consent = ConsentLog(
        user_id=current_user.id,
        target=scan_data.target.strip(),
        target_type=scan_data.target_type,
    )
    db.add(consent)
    db.commit()

    # 2. Create scan record
    scan = Scan(
        user_id=current_user.id,
        target=scan_data.target.strip(),
        target_type=scan_data.target_type,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 3. Enqueue background task
    run_stub_scan_task.delay(scan.id)

    return scan


@router.get("", response_model=List[ScanOut])
def list_user_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.started_at.desc()).all()


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
    source: Optional[str] = Query(None, description="Filter by finding source (sast, dast, dependency, secret)"),
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
