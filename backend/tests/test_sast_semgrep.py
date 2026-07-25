import os
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

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_sast.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def prepare_test_db():
    Base.metadata.create_all(bind=engine)
    with patch("app.tasks.scan_tasks.SessionLocal", TestingSessionLocal):
        yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def vulnerable_repo(tmp_path):
    repo_dir = tmp_path / "vulnerable_repo"
    repo_dir.mkdir()
    vuln_file = repo_dir / "command_handler.py"
    vuln_file.write_text(
        "import os\n"
        "import subprocess\n"
        "def execute_user_command(user_input):\n"
        "    # Intentional code injection and shell injection for SAST test\n"
        "    eval(user_input)\n"
        "    subprocess.call('ping ' + user_input, shell=True)\n"
    )
    return str(repo_dir)


def test_semgrep_sast_scan_detects_vulnerability(vulnerable_repo):
    db = TestingSessionLocal()

    # Register user and scan
    user = User(email="sast_tester@example.com", password_hash="hash", role="tester")
    db.add(user)
    db.commit()

    scan = Scan(
        user_id=user.id,
        target=vulnerable_repo,
        target_type="repo",
        status="pending",
    )
    db.add(scan)
    db.commit()

    # Execute SAST task synchronously
    result = run_stub_scan_task(scan.id)
    assert result["status"] == "success"

    # Query DB scan and findings
    db.refresh(scan)
    assert scan.status == "completed"

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    db.close()

    assert len(findings) >= 1
    sast_finding = findings[0]
    assert sast_finding.source == "sast"
    assert "command_handler.py" in sast_finding.file_path
    assert sast_finding.line_number > 0
    assert "eval(user_input)" in sast_finding.code_snippet or "subprocess.call" in sast_finding.code_snippet
