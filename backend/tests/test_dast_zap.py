import pytest
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
from app.engine.dast_engine import run_dast_scan

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_dast.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def prepare_test_db():
    Base.metadata.create_all(bind=engine)
    with patch("app.tasks.scan_tasks.SessionLocal", TestingSessionLocal):
        yield
    Base.metadata.drop_all(bind=engine)


def test_dast_scan_unreachable_target_fails():
    db = TestingSessionLocal()
    user = User(email="dast_user1@example.com", password_hash="hash", role="tester")
    db.add(user)
    db.commit()

    scan = Scan(
        user_id=user.id,
        target="http://localhost:59999/unreachable-endpoint",
        target_type="url",
        status="pending",
    )
    db.add(scan)
    db.commit()

    # Attempt execution against unreachable endpoint
    with pytest.raises(Exception) as excinfo:
        run_stub_scan_task(scan.id)

    assert "unreachable" in str(excinfo.value).lower() or "timed out" in str(excinfo.value).lower()

    db.refresh(scan)
    assert scan.status == "failed"
    db.close()


def test_dast_scan_produces_findings():
    db = TestingSessionLocal()
    user = User(email="dast_user2@example.com", password_hash="hash", role="tester")
    db.add(user)
    db.commit()

    # Use public target for DAST baseline check
    scan = Scan(
        user_id=user.id,
        target="https://example.com",
        target_type="url",
        status="pending",
    )
    db.add(scan)
    db.commit()

    result = run_stub_scan_task(scan.id)
    assert result["status"] == "success"

    db.refresh(scan)
    assert scan.status == "completed"

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(findings) >= 1
    dast_finding = findings[0]
    assert dast_finding.source == "dast"
    assert dast_finding.severity_raw in ["HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    db.close()
