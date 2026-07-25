from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import User, ConsentLog
from app.core.security import get_current_user
from app.schemas.auth_consent import ConsentCreate, ConsentOut

router = APIRouter(prefix="/consent", tags=["Authorization & Consent"])


@router.post("", response_model=ConsentOut, status_code=status.HTTP_201_CREATED)
def record_consent(consent_data: ConsentCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if consent_data.target_type not in ["url", "repo"]:
        raise HTTPException(status_code=400, detail="Invalid target_type. Must be 'url' or 'repo'")

    if not consent_data.target or not consent_data.target.strip():
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    consent = ConsentLog(
        user_id=current_user.id,
        target=consent_data.target.strip(),
        target_type=consent_data.target_type,
    )
    db.add(consent)
    db.commit()
    db.refresh(consent)
    return consent


@router.get("", response_model=List[ConsentOut])
def list_consents(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(ConsentLog).filter(ConsentLog.user_id == current_user.id).all()
