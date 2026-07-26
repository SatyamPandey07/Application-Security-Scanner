import pytest
import base64
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
from app.engine.github_pr_engine import create_github_fix_pr, apply_diff_patch

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_gh_pr.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def prepare_test_db():
    Base.metadata.create_all(bind=engine)
    with patch("app.tasks.scan_tasks.SessionLocal", TestingSessionLocal):
        yield
    Base.metadata.drop_all(bind=engine)


def test_apply_diff_patch_success():
    orig_code = "import os\neval(user_input)\nprint('done')\n"
    diff_patch = "--- a/app.py\n+++ b/app.py\n- eval(user_input)\n+ parse_safe_input(user_input)\n"

    new_code = apply_diff_patch(orig_code, diff_patch)
    assert "parse_safe_input(user_input)" in new_code
    assert "eval(user_input)" not in new_code


def test_apply_diff_patch_content_drift_failure():
    orig_code = "import os\nsafe_func()\n"
    diff_patch = "--- a/app.py\n+++ b/app.py\n- eval(user_input)\n+ parse_safe_input(user_input)\n"

    with pytest.raises(RuntimeError) as excinfo:
        apply_diff_patch(orig_code, diff_patch)

    assert "Diff application failed" in str(excinfo.value)
    assert "Target line 'eval(user_input)' was not found" in str(excinfo.value)


def test_create_github_fix_pr_mocked_sequence():
    mock_file_content_b64 = base64.b64encode("eval(user_input)\n".encode("utf-8")).decode("utf-8")

    class MockResponse:
        def __init__(self, status_code, json_data):
            self.status_code = status_code
            self._json = json_data
            self.text = str(json_data)

        def json(self):
            return self._json

    def mock_httpx_requests(url, **kwargs):
        if url.endswith("/repos/owner/repo"):
            return MockResponse(200, {"default_branch": "main"})
        elif "/git/ref/heads/main" in url:
            return MockResponse(200, {"object": {"sha": "main_base_sha_123"}})
        elif "/contents/vulnerable.py" in url:
            return MockResponse(200, {"sha": "file_blob_sha_456", "content": mock_file_content_b64})
        return MockResponse(404, {})

    def mock_httpx_post(url, **kwargs):
        if "/git/refs" in url:
            return MockResponse(201, {"ref": "refs/heads/sentinel/fix-finding-1"})
        elif "/pulls" in url:
            return MockResponse(201, {"html_url": "https://github.com/owner/repo/pull/42"})
        return MockResponse(404, {})

    def mock_httpx_put(url, **kwargs):
        return MockResponse(200, {"content": {"sha": "new_sha_789"}})

    class MockClientContext:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def get(self, url, **kwargs):
            return mock_httpx_requests(url, **kwargs)
        def post(self, url, **kwargs):
            return mock_httpx_post(url, **kwargs)
        def put(self, url, **kwargs):
            return mock_httpx_put(url, **kwargs)

    with patch("httpx.Client", return_value=MockClientContext()):
        res = create_github_fix_pr(
            github_token="dummy_token_123",
            repo_name="owner/repo",
            finding_id=1,
            rule_id="eval-injection",
            file_path="vulnerable.py",
            fix_diff="- eval(user_input)\n+ parse_safe_input(user_input)",
            ai_explanation="Replaced dangerous eval with parse_safe_input.",
        )

    assert res["status"] == "created"
    assert res["branch_name"] == "sentinel/fix-finding-1"
    assert res["pr_url"] == "https://github.com/owner/repo/pull/42"
