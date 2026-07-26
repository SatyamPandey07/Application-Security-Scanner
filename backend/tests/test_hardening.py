import pytest
from app.core.rate_limiter import check_rate_limit
from app.api.scans import validate_target_input
from fastapi import HTTPException


def test_rate_limiter_exceeded():
    key = "test_rate_limit_user_1"
    # First 5 calls pass
    for _ in range(5):
        check_rate_limit(key, max_requests=5, window_seconds=60)

    # 6th call raises 429
    with pytest.raises(HTTPException) as excinfo:
        check_rate_limit(key, max_requests=5, window_seconds=60)

    assert excinfo.value.status_code == 429
    assert "Rate limit exceeded" in excinfo.value.detail


def test_target_input_validation_command_injection_rejected():
    with pytest.raises(HTTPException) as excinfo:
        validate_target_input("https://example.com; rm -rf /", "url")
    assert excinfo.value.status_code == 400
    assert "invalid shell characters" in excinfo.value.detail


def test_target_input_validation_directory_traversal_rejected():
    with pytest.raises(HTTPException) as excinfo:
        validate_target_input("../../etc/passwd", "repo")
    assert excinfo.value.status_code == 400
    assert "directory traversal" in excinfo.value.detail
