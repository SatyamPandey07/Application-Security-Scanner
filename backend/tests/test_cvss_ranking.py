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
from app.db.models import User, Scan, Finding
from app.db.session import get_db
from app.engine.cvss_calculator import calculate_cvss31_score, calculate_priority_score

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_cvss.db"

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
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


client = TestClient(app)


def test_cvss31_formula_against_official_spec_vectors():
    # FIRST.org Official CVSS v3.1 Spec Vectors
    vec1 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert calculate_cvss31_score(vec1) == 9.8

    vec2 = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    assert calculate_cvss31_score(vec2) == 3.1

    vec3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
    assert calculate_cvss31_score(vec3) == 6.4


def test_priority_score_weighting():
    cvss_score = 9.8
    ai_confidence = 0.95
    p_score = calculate_priority_score(cvss_score, ai_confidence)
    assert p_score == 9.31


def test_scan_findings_api_sorting_and_filtering():
    db = TestingSessionLocal()

    user = User(email="cvss_user@example.com", password_hash="hash", role="tester")
    db.add(user)
    db.commit()

    scan = Scan(user_id=user.id, target="https://test.com", target_type="url", status="completed")
    db.add(scan)
    db.commit()
    scan_id = scan.id

    f1 = Finding(
        scan_id=scan_id,
        source="sast",
        rule_id="sqli-critical",
        file_path="db.py",
        line_number=10,
        severity_raw="CRITICAL",
        cvss_score=9.8,
        ai_confidence="0.90",
        status="confirmed",
    )
    f2 = Finding(
        scan_id=scan_id,
        source="dast",
        rule_id="missing-header",
        file_path="https://test.com",
        line_number=1,
        severity_raw="LOW",
        cvss_score=4.3,
        ai_confidence="0.50",
        status="low_confidence",
    )
    db.add_all([f1, f2])
    db.commit()

    # Register and login to get JWT token
    client.post("/auth/register", json={"email": "cvss_api@example.com", "password": "password123"})
    login_resp = client.post("/auth/login", data={"username": "cvss_api@example.com", "password": "password123"})
    token = login_resp.json()["access_token"]

    # Re-assign scan to current authenticated user
    auth_user = db.query(User).filter(User.email == "cvss_api@example.com").first()
    scan.user_id = auth_user.id
    db.commit()
    db.close()

    # Query GET /scans/{id}/findings sorted by priority
    resp = client.get(f"/scans/{scan_id}/findings?sort_by=priority", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    findings_list = resp.json()

    assert len(findings_list) == 2
    # f1 priority = 9.8 * 0.90 = 8.82; f2 priority = 4.3 * 0.50 = 2.15
    assert findings_list[0]["rule_id"] == "sqli-critical"
    assert findings_list[0]["priority_score"] == 8.82

    # Query GET /scans/{id}/findings filtered by status=confirmed
    filter_resp = client.get(f"/scans/{scan_id}/findings?status=confirmed", headers={"Authorization": f"Bearer {token}"})
    assert filter_resp.status_code == 200
    filtered_list = filter_resp.json()
    assert len(filtered_list) == 1
    assert filtered_list[0]["rule_id"] == "sqli-critical"
