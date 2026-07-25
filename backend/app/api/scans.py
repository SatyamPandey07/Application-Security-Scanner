from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import User, Scan, ConsentLog
from app.core.security import get_current_user
from app.schemas.scans import ScanCreate, ScanOut
from app.tasks.scan_tasks import run_stub_scan_task

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

    # 3. Enqueue background stub job
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
