from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import User, Finding, Scan
from app.core.security import get_current_user
from app.engine.github_pr_engine import create_github_fix_pr

router = APIRouter(prefix="/findings", tags=["Findings"])


class CreatePRRequest(BaseModel):
    github_token: str = Field(..., description="GitHub Personal Access Token or OAuth token with repo scope")
    repo_name: str = Field(..., description="GitHub repository in 'owner/repo' format", example="SatyamPandey07/Application-Security-Scanner")


class CreatePRResponse(BaseModel):
    pr_url: str
    branch_name: str
    status: str


@router.post("/{finding_id}/create-pr", response_model=CreatePRResponse)
def open_finding_github_pr(
    finding_id: int,
    req_data: CreatePRRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID {finding_id} not found."
        )

    # Verify scan belongs to user
    scan = db.query(Scan).filter(Scan.id == finding.scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to remediate findings from this scan."
        )

    if not finding.ai_fix_diff:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This finding does not have an AI-suggested fix diff available."
        )

    try:
        result = create_github_fix_pr(
            github_token=req_data.github_token.strip(),
            repo_name=req_data.repo_name.strip(),
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=finding.file_path or "vulnerable_code.py",
            fix_diff=finding.ai_fix_diff,
            ai_explanation=finding.ai_explanation or "Sentinel AI Fix",
        )
        return result
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error creating GitHub PR: {str(e)}"
        )
