from datetime import timedelta
import pytest
from fastapi import Depends, APIRouter
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.core.security import create_access_token, require_roles
from app.db.models import User

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_auth_adv.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

dummy_router = APIRouter()


@dummy_router.get("/dummy/admin-only")
def admin_only_endpoint(user: User = Depends(require_roles(["admin"]))):
    return {"message": "Welcome Admin"}


app.include_router(dummy_router)


@pytest.fixture(autouse=True)
def prepare_test_db():
    Base.metadata.create_all(bind=engine)

    def override_db():
        try:
            db = TestingSessionLocal()
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


client = TestClient(app)


def test_invalid_credentials():
    # User does not exist
    resp = client.post("/auth/login", data={"username": "nonexistent@example.com", "password": "wrong"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Incorrect email or password"

    # User exists but wrong password
    client.post("/auth/register", json={"email": "tester1@example.com", "password": "correctpassword"})
    wrong_pass_resp = client.post("/auth/login", data={"username": "tester1@example.com", "password": "wrongpassword"})
    assert wrong_pass_resp.status_code == 401


def test_expired_token():
    client.post("/auth/register", json={"email": "expired@example.com", "password": "password123"})
    expired_token = create_access_token(data={"sub": "expired@example.com"}, expires_delta=timedelta(seconds=-10))

    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Token has expired"


def test_role_enforcement():
    # Tester user (default role)
    client.post("/auth/register", json={"email": "tester_role@example.com", "password": "password123"})
    login_resp = client.post("/auth/login", data={"username": "tester_role@example.com", "password": "password123"})
    tester_token = login_resp.json()["access_token"]

    # Attempt to access admin endpoint
    forbidden_resp = client.get("/dummy/admin-only", headers={"Authorization": f"Bearer {tester_token}"})
    assert forbidden_resp.status_code == 403
    assert "not authorized" in forbidden_resp.json()["detail"]
