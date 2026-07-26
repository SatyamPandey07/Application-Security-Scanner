import pytest
from fastapi import FastAPI, Header, HTTPException, Form
from fastapi.testclient import TestClient
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.celery_app import celery_app

celery_app.conf.update(
    task_always_eager=True,
    task_eager_propagates=True,
    broker_url="memory://",
    result_backend="rpc://",
)

from app.db.base import Base
from app.db.models import User, Scan, Finding
from app.tasks.scan_tasks import run_stub_scan_task
from app.engine.idor_engine import run_authenticated_idor_scan

# 1. Throwaway Mock App with Intentional IDOR Vulnerability
mock_app = FastAPI()

TOKENS = {
    "usera_token_123": "user_a@example.com",
    "userb_token_456": "user_b@example.com",
}

@mock_app.post("/auth/login")
def mock_login(username: str = Form(...), password: str = Form(...)):
    if username == "user_a@example.com" and password == "pass_a":
        return {"access_token": "usera_token_123"}
    elif username == "user_b@example.com" and password == "pass_b":
        return {"access_token": "userb_token_456"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@mock_app.get("/api/user/profile")
def mock_broken_profile_endpoint(authorization: str = Header(...)):
    # Vulnerable endpoint: Intentionally leaks User B's profile data even when requested by User A
    token = authorization.replace("Bearer ", "")
    if token not in TOKENS:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Broken BOLA logic: always returns User B's profile data
    return {"id": 2, "email": "user_b@example.com", "role": "user_b_private_data"}


SQLALCHEMY_DATABASE_URL = "sqlite:///./test_idor.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def prepare_test_db():
    Base.metadata.create_all(bind=engine)
    with patch("app.tasks.scan_tasks.SessionLocal", TestingSessionLocal):
        yield
    Base.metadata.drop_all(bind=engine)


def test_authenticated_idor_detection():
    # Use FastAPI TestClient transport to test mock app
    test_client = TestClient(mock_app)

    class MockResponse:
        def __init__(self, starlette_res):
            self.status_code = starlette_res.status_code
            self.text = starlette_res.text
            self._json = starlette_res.json()

        def json(self):
            return self._json

    class MockClientContext:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, **kwargs):
            path = url.replace("http://mock-target.local", "")
            res = test_client.post(path, **kwargs)
            return MockResponse(res)
        def get(self, url, **kwargs):
            path = url.replace("http://mock-target.local", "")
            res = test_client.get(path, **kwargs)
            return MockResponse(res)

    with patch("httpx.Client", return_value=MockClientContext()):
        findings = run_authenticated_idor_scan(
            target_url="http://mock-target.local",
            user_a_creds={"username": "user_a@example.com", "password": "pass_a"},
            user_b_creds={"username": "user_b@example.com", "password": "pass_b"},
            auth_login_endpoint="/auth/login",
            test_resource_endpoints=["/api/user/profile"]
        )

    assert len(findings) == 1
    idor_finding = findings[0]
    assert idor_finding["source"] == "access_control"
    assert idor_finding["rule_id"] == "access-control-idor-bola"
    assert "user_b@example.com" in idor_finding["code_snippet"]
