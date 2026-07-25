import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.celery_app import celery_app

celery_app.conf.update(
    task_always_eager=True,
    task_eager_propagates=True,
    broker_url="memory://",
    result_backend="rpc://",
)

from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.db.models import ConsentLog, Scan

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_scans.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


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

    with patch("app.tasks.scan_tasks.SessionLocal", TestingSessionLocal):
        yield

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


client = TestClient(app)


def get_auth_token():
    client.post("/auth/register", json={"email": "audit_user@example.com", "password": "password123"})
    login_resp = client.post("/auth/login", data={"username": "audit_user@example.com", "password": "password123"})
    return login_resp.json()["access_token"]


def test_submit_scan_without_authorization_rejected():
    token = get_auth_token()

    # Attempt to create scan with authorized=False
    resp = client.post(
        "/scans",
        json={"target": "https://example.com", "target_type": "url", "authorized": False},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert resp.status_code == 400
    assert "Explicit authorization confirmation" in resp.json()["detail"]

    # Verify NO consent_log entry was created
    db = TestingSessionLocal()
    consent_count = db.query(ConsentLog).count()
    scan_count = db.query(Scan).count()
    db.close()

    assert consent_count == 0
    assert scan_count == 0


def test_submit_scan_with_authorization_success():
    token = get_auth_token()

    # Submit scan with authorized=True
    resp = client.post(
        "/scans",
        json={"target": "https://example.com", "target_type": "url", "authorized": True},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert resp.status_code == 201
    scan_data = resp.json()
    assert scan_data["target"] == "https://example.com"
    assert scan_data["target_type"] == "url"

    # Verify consent_log entry WAS created
    db = TestingSessionLocal()
    consent_entry = db.query(ConsentLog).filter(ConsentLog.target == "https://example.com").first()
    assert consent_entry is not None
    assert consent_entry.target_type == "url"

    # Verify scan query returns updated status
    query_resp = client.get(f"/scans/{scan_data['id']}", headers={"Authorization": f"Bearer {token}"})
    assert query_resp.status_code == 200
    assert query_resp.json()["id"] == scan_data["id"]
    assert query_resp.json()["status"] == "completed"
    db.close()
