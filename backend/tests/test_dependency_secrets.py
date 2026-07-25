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

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_dep_sec.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def prepare_test_db():
    Base.metadata.create_all(bind=engine)
    with patch("app.tasks.scan_tasks.SessionLocal", TestingSessionLocal):
        yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def vulnerable_dep_sec_repo(tmp_path):
    repo_dir = tmp_path / "dep_sec_repo"
    repo_dir.mkdir()

    # Known vulnerable dependency manifest
    req_file = repo_dir / "requirements.txt"
    req_file.write_text("requests==2.20.0\n")

    # Hardcoded secret key
    config_file = repo_dir / "config.py"
    config_file.write_text("AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")

    return str(repo_dir)


def test_dependency_and_secrets_scanning(vulnerable_dep_sec_repo):
    db = TestingSessionLocal()

    user = User(email="dep_sec_tester@example.com", password_hash="hash", role="tester")
    db.add(user)
    db.commit()

    scan = Scan(
        user_id=user.id,
        target=vulnerable_dep_sec_repo,
        target_type="repo",
        status="pending",
    )
    db.add(scan)
    db.commit()

    result = run_stub_scan_task(scan.id)
    assert result["status"] == "success"

    db.refresh(scan)
    assert scan.status == "completed"

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    db.close()

    sources = [f.source for f in findings]
    assert "dependency" in sources
    assert "secret" in sources

    dep_finding = next(f for f in findings if f.source == "dependency")
    assert "requests" in dep_finding.code_snippet.lower() or "requirements.txt" in dep_finding.file_path

    secret_finding = next(f for f in findings if f.source == "secret")
    assert "AKIAIOSFODNN7EXAMPLE" in secret_finding.code_snippet or secret_finding.rule_id == "aws-access-key-id"
