from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List


class ScanCreate(BaseModel):
    target: str = Field(..., example="https://example.com")
    target_type: str = Field(..., example="url")  # url or repo
    authorized: bool = Field(False, description="Explicit user confirmation of ownership or authorization")


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
