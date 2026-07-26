from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any


class ScanCreate(BaseModel):
    target: str = Field(..., json_schema_extra={"example": "https://example.com"})
    target_type: str = Field(..., json_schema_extra={"example": "url"})  # url or repo
    authorized: bool = Field(False, description="Explicit user confirmation of ownership or authorization")
    auth_credentials: Optional[Dict[str, Any]] = None  # Optional login credentials for authenticated DAST / IDOR checks


class FindingOut(BaseModel):
    id: int
    scan_id: int
    source: str
    rule_id: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    severity_raw: str
    cvss_score: Optional[float] = None
    priority_score: Optional[float] = None
    ai_confidence: Optional[str] = None
    ai_explanation: Optional[str] = None
    ai_fix_diff: Optional[str] = None
    status: str
    plain_title: Optional[str] = None
    plain_location: Optional[str] = None
    plain_whats_wrong: Optional[str] = None
    plain_why_it_exists: Optional[str] = None
    plain_real_world_impact: Optional[str] = None
    plain_risk_level: Optional[str] = None
    plain_what_to_do: Optional[str] = None
    feature_area: Optional[str] = None

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    user_id: int
    target: str
    target_type: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True
