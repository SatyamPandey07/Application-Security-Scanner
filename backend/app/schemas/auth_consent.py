from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional


class UserRegister(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    created_at: datetime

    class Config:
        from_attributes = True


class ConsentCreate(BaseModel):
    target: str
    target_type: str  # url or repo


class ConsentOut(BaseModel):
    id: int
    user_id: int
    target: str
    target_type: str
    confirmed_at: datetime

    class Config:
        from_attributes = True
