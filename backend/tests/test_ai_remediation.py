import os
import pytest
from unittest.mock import patch, MagicMock
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
from app.engine.ai_remediation import validate_and_remediate_finding, parse_ai_json_response

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_ai.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def prepare_test_db():
    Base.metadata.create_all(bind=engine)
    with patch("app.tasks.scan_tasks.SessionLocal", TestingSessionLocal):
        yield
    Base.metadata.drop_all(bind=engine)


def test_ai_validation_valid_json_response():
    mock_json_str = """
```json
{
  "is_likely_true_positive": true,
  "confidence": 0.95,
  "plain_english_explanation": "Direct string interpolation into SQL query leads to SQL Injection.",
  "exploit_scenario": "Attacker submits ' OR 1=1 -- to bypass authentication.",
  "suggested_fix_diff": "--- a/db.py\\n+++ b/db.py\\n- query = 'SELECT * FROM users WHERE name = ' + name\\n+ query = 'SELECT * FROM users WHERE name = %s'"
}
```
"""
    with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy_key"}):
        with patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = MagicMock()
            mock_anthropic.return_value = mock_client
            mock_message = MagicMock()
            mock_message.content = [MagicMock(text=mock_json_str)]
            mock_client.messages.create.return_value = mock_message

            res = validate_and_remediate_finding(
                rule_id="sqli-rule",
                file_path="db.py",
                line_number=10,
                code_snippet="query = 'SELECT * FROM users WHERE name = ' + name",
            )

            assert res["is_likely_true_positive"] is True
            assert res["confidence"] == 0.95
            assert "SQL Injection" in res["plain_english_explanation"]
            assert "--- a/db.py" in res["suggested_fix_diff"]


def test_ai_validation_malformed_json_fallback():
    malformed_text = "Sorry, I cannot parse this code: { invalid_json_without_quotes: true "
    fallback = {
        "is_likely_true_positive": True,
        "confidence": 0.7,
        "plain_english_explanation": "Fallback explanation",
        "exploit_scenario": "Fallback scenario",
        "suggested_fix_diff": None,
    }

    parsed = parse_ai_json_response(malformed_text, fallback)
    assert parsed["is_likely_true_positive"] is True
    assert parsed["confidence"] == 0.7
    assert parsed["plain_english_explanation"] == "Fallback explanation"


def test_ai_validation_low_confidence_relabeling(tmp_path):
    # Repo with vulnerable code
    repo_dir = tmp_path / "test_low_conf_repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("eval(user_input)\n")

    mock_low_conf_json = """
{
  "is_likely_true_positive": false,
  "confidence": 0.30,
  "plain_english_explanation": "Input is sanitized prior to evaluation.",
  "exploit_scenario": "N/A",
  "suggested_fix_diff": null
}
"""
    db = TestingSessionLocal()
    user = User(email="ai_tester@example.com", password_hash="hash", role="tester")
    db.add(user)
    db.commit()

    scan = Scan(user_id=user.id, target=str(repo_dir), target_type="repo", status="pending")
    db.add(scan)
    db.commit()

    with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy_key"}):
        with patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = MagicMock()
            mock_anthropic.return_value = mock_client
            mock_message = MagicMock()
            mock_message.content = [MagicMock(text=mock_low_conf_json)]
            mock_client.messages.create.return_value = mock_message

            run_stub_scan_task(scan.id)

    db.refresh(scan)
    assert scan.status == "completed"

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    db.close()

    assert len(findings) >= 1
    finding = findings[0]
    # Finding must NOT be deleted, only relabeled as low_confidence
    assert finding.status == "low_confidence"
    assert finding.ai_confidence == "0.30"
