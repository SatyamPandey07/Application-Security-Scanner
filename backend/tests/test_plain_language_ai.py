"""
Tests for the plain-language AI validation layer (PR 8).

Coverage:
  1. Both technical AND plain fields are present for every finding.
  2. Jargon denylist correctly detects offenders in plain_* fields.
  3. Jargon detection triggers exactly one rewrite API call.
  4. After rewrite, clean fields are kept, jargon fields are replaced.
  5. plain_location is never a file path (regex check).
  6. feature_area is always one of the valid fixed set.
  7. Malformed / empty AI responses fall back to safe defaults that
     still satisfy the schema (all plain fields present).
  8. Full scan pipeline persists all plain fields in the DB.
  9. plain_location path-guard replaces path-like values automatically.
 10. Existing test: low-confidence relabeling still works unchanged.
"""
import os
import re
import pytest
from unittest.mock import patch, MagicMock, call
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
from app.engine.ai_remediation import (
    validate_and_remediate_finding,
    parse_ai_json_response,
    find_jargon_offenders,
    plain_location_looks_like_path,
    PLAIN_JARGON_DENYLIST,
    PLAIN_FIELD_NAMES,
    VALID_FEATURE_AREAS,
    _default_result,
)

# ---------------------------------------------------------------------------
# Test DB setup
# ---------------------------------------------------------------------------
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_plain_lang.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

ALL_PLAIN_FIELDS = [
    "plain_title",
    "plain_location",
    "plain_whats_wrong",
    "plain_real_world_impact",
    "plain_risk_level",
    "plain_what_to_do",
]
ALL_TECHNICAL_FIELDS = [
    "is_likely_true_positive",
    "confidence",
    "plain_english_explanation",
    "exploit_scenario",
    "suggested_fix_diff",
]
ALL_REQUIRED_FIELDS = ALL_TECHNICAL_FIELDS + ALL_PLAIN_FIELDS + ["feature_area"]


@pytest.fixture(autouse=True)
def prepare_test_db():
    Base.metadata.create_all(bind=engine)
    with patch("app.tasks.scan_tasks.SessionLocal", TestingSessionLocal):
        yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Fixtures: good AI JSON response (no jargon in plain fields)
# ---------------------------------------------------------------------------
CLEAN_AI_RESPONSE = """{
  "is_likely_true_positive": true,
  "confidence": 0.90,
  "plain_english_explanation": "The application does not properly validate user input before using it in a database query, creating a SQL Injection vulnerability.",
  "exploit_scenario": "An attacker submits a specially crafted string like ' OR 1=1 -- to bypass authentication and access all accounts.",
  "suggested_fix_diff": "--- a/db.py\\n+++ b/db.py\\n- query = 'SELECT * FROM users WHERE name = ' + name\\n+ query = 'SELECT * FROM users WHERE name = %s'",
  "plain_title": "Your login form can be tricked into letting strangers in",
  "plain_location": "The login page where customers type their email and password",
  "plain_whats_wrong": "Someone can type a clever trick into the login box and your website will treat them as if they entered the right password, letting them in without one.",
  "plain_real_world_impact": "A stranger could log into any customer account without knowing the password, access personal information, and make changes on their behalf.",
  "plain_risk_level": "Fix this now - anyone can try this trick from anywhere, and it could expose every customer account.",
  "plain_what_to_do": "Ask your developer to make sure anything a customer types into a form gets checked before the website acts on it. This is a well-known type of bug with a standard fix.",
  "feature_area": "Login & Accounts"
}"""

JARGON_AI_RESPONSE = """{
  "is_likely_true_positive": true,
  "confidence": 0.85,
  "plain_english_explanation": "Reflected XSS via unsanitized query parameter allows script injection.",
  "exploit_scenario": "Attacker crafts a URL with a payload that injects JavaScript into the DOM.",
  "suggested_fix_diff": null,
  "plain_title": "Reflected XSS via unsanitized query parameter",
  "plain_location": "The search endpoint at /api/search?q=",
  "plain_whats_wrong": "Missing input sanitization allows arbitrary script injection into the DOM via the XSS vector.",
  "plain_real_world_impact": "An attacker can craft a payload that exfiltrates session cookies.",
  "plain_risk_level": "Fix this soon - CVSS 6.1, medium severity XSS",
  "plain_what_to_do": "Sanitize all user inputs and implement a Content Security Policy to block injection vectors.",
  "feature_area": "Search & Browsing"
}"""

CLEAN_REWRITE_RESPONSE = """{
  "plain_title": "Your search box can be tricked into running harmful code",
  "plain_location": "The search bar at the top of your website",
  "plain_whats_wrong": "Someone can type a hidden trick into the search box and your website will run their code instead of just performing a normal search.",
  "plain_real_world_impact": "A stranger could steal a customer's login session and get into their account, or use your site to spread harmful content to visitors.",
  "plain_risk_level": "Fix this soon - this is relatively easy to find and could affect customers browsing your site.",
  "plain_what_to_do": "Ask your developer to make sure anything typed into the search box is treated as text only and cannot change how the page works. This is a well-known type of bug with a standard fix."
}"""


def _make_mock_client(first_response: str, second_response: str = None):
    """Build a mock Anthropic client that returns first_response on call 1,
    and optionally second_response on call 2."""
    mock_client = MagicMock()

    def side_effect(**kwargs):
        msg = MagicMock()
        # Determine which call this is
        call_count = mock_client.messages.create.call_count
        if call_count == 1:
            msg.content = [MagicMock(text=first_response)]
        else:
            msg.content = [MagicMock(text=second_response or first_response)]
        return msg

    mock_client.messages.create.side_effect = side_effect
    return mock_client


# ===========================================================================
# 1. Both technical AND plain fields present in every result
# ===========================================================================

class TestAllFieldsPresent:
    def test_default_result_has_all_fields(self):
        """_default_result() satisfies the full schema without any API call."""
        result = _default_result()
        for field in ALL_REQUIRED_FIELDS:
            assert field in result, f"Missing field: {field}"
            assert result[field] is not None or field == "suggested_fix_diff"

    def test_parse_clean_response_has_all_fields(self):
        """parse_ai_json_response extracts all fields from a well-formed response."""
        result = parse_ai_json_response(CLEAN_AI_RESPONSE, _default_result())
        for field in ALL_REQUIRED_FIELDS:
            assert field in result, f"Missing field: {field}"

    def test_validate_with_ai_returns_all_fields(self):
        """validate_and_remediate_finding returns all required fields when AI responds cleanly."""
        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy"}):
            with patch("anthropic.Anthropic") as mock_cls:
                mock_client = _make_mock_client(CLEAN_AI_RESPONSE)
                mock_cls.return_value = mock_client

                result = validate_and_remediate_finding(
                    rule_id="sqli-001",
                    file_path="app/models.py",
                    line_number=42,
                    code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_id",
                )

        for field in ALL_REQUIRED_FIELDS:
            assert field in result, f"Missing field in AI result: {field}"

    def test_validate_disabled_ai_returns_all_fields(self):
        """When AI is disabled, fallback result still has all required fields."""
        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "False"}):
            result = validate_and_remediate_finding(
                rule_id="sqli-001",
                file_path="app/models.py",
                line_number=42,
                code_snippet="eval(input())",
            )
        for field in ALL_REQUIRED_FIELDS:
            assert field in result, f"Missing field in disabled-AI fallback: {field}"

    def test_validate_missing_api_key_returns_all_fields(self):
        """When ANTHROPIC_API_KEY is absent, fallback result has all required fields."""
        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": ""}):
            result = validate_and_remediate_finding(
                rule_id="xss-002",
                file_path=None,
                line_number=None,
                code_snippet=None,
            )
        for field in ALL_REQUIRED_FIELDS:
            assert field in result


# ===========================================================================
# 2. Jargon denylist detection
# ===========================================================================

class TestJargonDenylist:
    @pytest.mark.parametrize("jargon_word,field", [
        ("injection", "plain_title"),
        ("XSS", "plain_whats_wrong"),
        ("CSRF", "plain_what_to_do"),
        ("payload", "plain_real_world_impact"),
        ("sanitize", "plain_what_to_do"),
        ("vector", "plain_whats_wrong"),
        ("CVSS", "plain_risk_level"),
        ("endpoint", "plain_location"),
        ("deserialization", "plain_whats_wrong"),
        ("SSTI", "plain_title"),
        ("exfiltration", "plain_real_world_impact"),  # full word triggers the stem match
        ("traversal", "plain_whats_wrong"),
        ("OWASP", "plain_risk_level"),
        ("zero-day", "plain_risk_level"),
        ("attack surface", "plain_whats_wrong"),
    ])
    def test_jargon_word_detected(self, jargon_word, field):
        """Each denylist term is correctly detected in the relevant field."""
        result = _default_result()
        result[field] = f"This contains the word {jargon_word} in context."
        offenders = find_jargon_offenders(result)
        assert field in offenders, (
            f"Expected '{field}' to be flagged for jargon word '{jargon_word}'"
        )

    def test_clean_result_has_no_offenders(self):
        """A result with no jargon returns an empty offenders list."""
        result = parse_ai_json_response(CLEAN_AI_RESPONSE, _default_result())
        offenders = find_jargon_offenders(result)
        assert offenders == [], f"Unexpected jargon offenders: {offenders}"

    def test_jargon_response_has_offenders(self):
        """The jargon-filled response is correctly identified as containing offenders."""
        result = parse_ai_json_response(JARGON_AI_RESPONSE, _default_result())
        offenders = find_jargon_offenders(result)
        assert len(offenders) > 0, "Expected jargon offenders but found none"
        # Specifically: plain_title, plain_whats_wrong, plain_risk_level all contain jargon
        assert "plain_title" in offenders
        assert "plain_whats_wrong" in offenders

    def test_case_insensitive_detection(self):
        """Jargon detection is case-insensitive."""
        result = _default_result()
        result["plain_title"] = "This is about INJECTION attacks"
        offenders = find_jargon_offenders(result)
        assert "plain_title" in offenders

        result["plain_title"] = "This is about Injection attacks"
        offenders = find_jargon_offenders(result)
        assert "plain_title" in offenders


# ===========================================================================
# 3. Jargon triggers exactly one retry call
# ===========================================================================

class TestJargonRetry:
    def test_jargon_triggers_one_rewrite_call(self):
        """When jargon is detected, the client is called exactly twice: once for main, once for rewrite."""
        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy"}):
            with patch("anthropic.Anthropic") as mock_cls:
                mock_client = _make_mock_client(JARGON_AI_RESPONSE, CLEAN_REWRITE_RESPONSE)
                mock_cls.return_value = mock_client

                validate_and_remediate_finding(
                    rule_id="xss-003",
                    file_path="app/views.py",
                    line_number=10,
                    code_snippet='return f"<div>{request.args[\'q\']}</div>"',
                )

        assert mock_client.messages.create.call_count == 2, (
            f"Expected 2 API calls (main + rewrite) but got {mock_client.messages.create.call_count}"
        )

    def test_clean_response_triggers_only_one_call(self):
        """When no jargon is detected, only one API call is made."""
        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy"}):
            with patch("anthropic.Anthropic") as mock_cls:
                mock_client = _make_mock_client(CLEAN_AI_RESPONSE)
                mock_cls.return_value = mock_client

                validate_and_remediate_finding(
                    rule_id="sqli-001",
                    file_path="db.py",
                    line_number=5,
                    code_snippet="query = 'SELECT * FROM users WHERE id = ' + uid",
                )

        assert mock_client.messages.create.call_count == 1, (
            f"Expected exactly 1 API call but got {mock_client.messages.create.call_count}"
        )

    def test_rewrite_replaces_jargon_fields(self):
        """After jargon rewrite, previously jargon-filled fields are replaced."""
        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy"}):
            with patch("anthropic.Anthropic") as mock_cls:
                mock_client = _make_mock_client(JARGON_AI_RESPONSE, CLEAN_REWRITE_RESPONSE)
                mock_cls.return_value = mock_client

                result = validate_and_remediate_finding(
                    rule_id="xss-003",
                    file_path="app/views.py",
                    line_number=10,
                    code_snippet='return user_input',
                )

        # The rewritten plain_title should NOT contain jargon
        offenders = find_jargon_offenders(result)
        assert offenders == [], f"Jargon still present after rewrite in fields: {offenders}"
        # And the rewritten title should be the new clean one
        assert "XSS" not in result["plain_title"]
        assert "injection" not in result["plain_title"].lower()

    def test_technical_fields_preserved_after_rewrite(self):
        """Technical fields are not touched by the jargon rewrite call."""
        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy"}):
            with patch("anthropic.Anthropic") as mock_cls:
                mock_client = _make_mock_client(JARGON_AI_RESPONSE, CLEAN_REWRITE_RESPONSE)
                mock_cls.return_value = mock_client

                result = validate_and_remediate_finding(
                    rule_id="xss-003",
                    file_path="app/views.py",
                    line_number=10,
                    code_snippet='return user_input',
                )

        # Technical fields from original response must be preserved
        assert result["is_likely_true_positive"] is True
        assert result["confidence"] == 0.85
        assert "XSS" in result["plain_english_explanation"]  # technical field, jargon allowed


# ===========================================================================
# 4. plain_location is never a file path
# ===========================================================================

class TestPlainLocationNotAPath:
    @pytest.mark.parametrize("path_like", [
        "app/routes/search.py, line 42",
        "src/utils/auth.js",
        "backend/app/engine/foo.py",
        "controllers/user_controller.php at line 10",
        "views.py, line 7",
    ])
    def test_path_like_strings_detected(self, path_like):
        assert plain_location_looks_like_path(path_like), (
            f"Expected '{path_like}' to be detected as a file path"
        )

    @pytest.mark.parametrize("good_location", [
        "The login page where customers type their email and password",
        "The search bar on your homepage",
        "The 'Forgot password' page",
        "Where customers enter their shipping address at checkout",
        "Behind the scenes in your order-processing system",
        "The contact form on your website",
    ])
    def test_user_visible_locations_not_flagged(self, good_location):
        assert not plain_location_looks_like_path(good_location), (
            f"Expected '{good_location}' NOT to be flagged as a file path"
        )

    def test_path_in_plain_location_gets_replaced(self):
        """When the AI returns a file path in plain_location, the guard replaces it."""
        pathlike_response = CLEAN_AI_RESPONSE.replace(
            '"plain_location": "The login page where customers type their email and password"',
            '"plain_location": "app/routes/login.py, line 42"'
        )
        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy"}):
            with patch("anthropic.Anthropic") as mock_cls:
                mock_client = _make_mock_client(pathlike_response)
                mock_cls.return_value = mock_client

                result = validate_and_remediate_finding(
                    rule_id="sqli-001",
                    file_path="app/routes/login.py",
                    line_number=42,
                    code_snippet="query = 'SELECT ...' + uid",
                )

        assert not plain_location_looks_like_path(result["plain_location"]), (
            f"plain_location still looks like a file path after guard: {result['plain_location']}"
        )
        assert "Behind the scenes" in result["plain_location"]


# ===========================================================================
# 5. feature_area is always in the valid fixed set
# ===========================================================================

class TestFeatureArea:
    def test_valid_feature_areas_accepted(self):
        for area in VALID_FEATURE_AREAS:
            result = _default_result()
            result["feature_area"] = area
            # Simulate parsing
            assert result["feature_area"] in VALID_FEATURE_AREAS

    def test_invalid_feature_area_from_ai_falls_back_to_other(self):
        """If the AI returns an invalid feature_area value, it is coerced to 'Other'."""
        bad_response = CLEAN_AI_RESPONSE.replace(
            '"feature_area": "Login & Accounts"',
            '"feature_area": "Authentication Layer"'  # not in valid set
        )
        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy"}):
            with patch("anthropic.Anthropic") as mock_cls:
                mock_client = _make_mock_client(bad_response)
                mock_cls.return_value = mock_client

                result = validate_and_remediate_finding(
                    rule_id="sqli-001",
                    file_path="app/login.py",
                    line_number=10,
                    code_snippet="query = uid",
                )

        assert result["feature_area"] in VALID_FEATURE_AREAS
        assert result["feature_area"] == "Other"

    def test_clean_response_preserves_feature_area(self):
        result = parse_ai_json_response(CLEAN_AI_RESPONSE, _default_result())
        assert result["feature_area"] == "Login & Accounts"


# ===========================================================================
# 6. Malformed AI response falls back to safe defaults
# ===========================================================================

class TestMalformedResponseFallback:
    def test_empty_response_returns_default(self):
        result = parse_ai_json_response("", _default_result())
        for field in ALL_REQUIRED_FIELDS:
            assert field in result

    def test_non_json_response_returns_default(self):
        result = parse_ai_json_response(
            "Sorry, I cannot process this request.", _default_result()
        )
        for field in ALL_REQUIRED_FIELDS:
            assert field in result

    def test_partial_json_uses_fallback_for_missing_plain_fields(self):
        """A response with only technical fields still returns defaults for plain fields."""
        partial = """{
          "is_likely_true_positive": true,
          "confidence": 0.80,
          "plain_english_explanation": "SQL injection via string concatenation.",
          "exploit_scenario": "Attacker submits ' OR 1=1 --",
          "suggested_fix_diff": null
        }"""
        result = parse_ai_json_response(partial, _default_result())
        # Technical fields present and correct
        assert result["is_likely_true_positive"] is True
        assert result["confidence"] == 0.80
        # Plain fields fall back to defaults (not None, not empty)
        for field in ALL_PLAIN_FIELDS:
            assert result[field], f"Expected non-empty fallback for {field}"


# ===========================================================================
# 7. Full pipeline persists plain fields in DB
# ===========================================================================

class TestPipelinePersistsPlainFields:
    def test_scan_pipeline_stores_plain_fields(self, tmp_path):
        """After a full scan pipeline run, all plain fields are stored on Finding rows."""
        repo_dir = tmp_path / "test_plain_repo"
        repo_dir.mkdir()
        (repo_dir / "app.py").write_text("eval(user_input)\n")

        db = TestingSessionLocal()
        user = User(email="plain_test@example.com", password_hash="hash", role="tester")
        db.add(user)
        db.commit()

        scan = Scan(user_id=user.id, target=str(repo_dir), target_type="repo", status="pending")
        db.add(scan)
        db.commit()

        _STUB_FINDING = [{
            "source": "sast",
            "rule_id": "eval-injection",
            "file_path": "app.py",
            "line_number": 1,
            "code_snippet": "eval(user_input)",
            "severity_raw": "HIGH",
        }]

        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy"}):
            with patch("app.tasks.scan_tasks.run_sast_scan", return_value=_STUB_FINDING), \
                 patch("app.tasks.scan_tasks.run_dependency_scan", return_value=[]), \
                 patch("app.tasks.scan_tasks.run_secrets_scan", return_value=[]), \
                 patch("anthropic.Anthropic") as mock_cls:
                mock_client = _make_mock_client(CLEAN_AI_RESPONSE)
                mock_cls.return_value = mock_client
                run_stub_scan_task(scan.id)

        db.refresh(scan)
        assert scan.status == "completed"

        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        db.close()

        assert len(findings) >= 1
        for finding in findings:
            # All new plain fields must be non-None
            for field in ALL_PLAIN_FIELDS:
                val = getattr(finding, field, None)
                assert val is not None, f"Finding {finding.id}: {field} is None in DB"
                assert len(val) > 0, f"Finding {finding.id}: {field} is empty in DB"
            # feature_area must be a valid value
            assert finding.feature_area in VALID_FEATURE_AREAS, (
                f"Finding {finding.id}: invalid feature_area '{finding.feature_area}'"
            )
            # plain_location must NOT look like a file path
            assert not plain_location_looks_like_path(finding.plain_location or ""), (
                f"Finding {finding.id}: plain_location looks like a file path: {finding.plain_location}"
            )

    def test_existing_technical_fields_unchanged(self, tmp_path):
        """PR 7 technical fields are still correctly persisted after PR 8 changes."""
        repo_dir = tmp_path / "test_tech_fields_repo"
        repo_dir.mkdir()
        (repo_dir / "db.py").write_text("query = 'SELECT * FROM users WHERE id = ' + uid\n")

        db = TestingSessionLocal()
        user = User(email="tech_check@example.com", password_hash="hash", role="tester")
        db.add(user)
        db.commit()

        scan = Scan(user_id=user.id, target=str(repo_dir), target_type="repo", status="pending")
        db.add(scan)
        db.commit()

        _STUB_FINDING = [{
            "source": "sast",
            "rule_id": "sqli",
            "file_path": "db.py",
            "line_number": 1,
            "code_snippet": "query = 'SELECT * FROM users WHERE id = ' + uid",
            "severity_raw": "HIGH",
        }]

        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy"}):
            with patch("app.tasks.scan_tasks.run_sast_scan", return_value=_STUB_FINDING), \
                 patch("app.tasks.scan_tasks.run_dependency_scan", return_value=[]), \
                 patch("app.tasks.scan_tasks.run_secrets_scan", return_value=[]), \
                 patch("anthropic.Anthropic") as mock_cls:
                mock_client = _make_mock_client(CLEAN_AI_RESPONSE)
                mock_cls.return_value = mock_client
                run_stub_scan_task(scan.id)

        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        db.close()

        assert len(findings) >= 1
        for finding in findings:
            assert finding.ai_confidence is not None
            assert finding.ai_explanation is not None
            assert finding.status in ("confirmed", "low_confidence", "open")
            assert finding.rule_id is not None


# ===========================================================================
# 8. Existing regression: low-confidence relabeling still works (from PR 7)
# ===========================================================================

class TestLowConfidenceRelabeling:
    def test_low_confidence_finding_gets_relabeled(self, tmp_path):
        repo_dir = tmp_path / "test_low_conf_repo"
        repo_dir.mkdir()
        (repo_dir / "app.py").write_text("eval(user_input)\n")

        # Use a response that has low confidence AND includes plain fields
        low_conf_response = """{
          "is_likely_true_positive": false,
          "confidence": 0.30,
          "plain_english_explanation": "Input is checked prior to evaluation.",
          "exploit_scenario": "N/A",
          "suggested_fix_diff": null,
          "plain_title": "A possible security concern was found",
          "plain_location": "Behind the scenes in the application",
          "plain_whats_wrong": "A potential issue was found that a developer should review.",
          "plain_real_world_impact": "This could affect the security of your users if confirmed.",
          "plain_risk_level": "Worth fixing - a developer should review this to be sure.",
          "plain_what_to_do": "Ask your developer to look at this and confirm whether it needs fixing.",
          "feature_area": "Admin & Backend"
        }"""

        db = TestingSessionLocal()
        user = User(email="low_conf_plain@example.com", password_hash="hash", role="tester")
        db.add(user)
        db.commit()

        scan = Scan(user_id=user.id, target=str(repo_dir), target_type="repo", status="pending")
        db.add(scan)
        db.commit()

        _STUB_FINDING = [{
            "source": "sast",
            "rule_id": "eval-injection",
            "file_path": "app.py",
            "line_number": 1,
            "code_snippet": "eval(user_input)",
            "severity_raw": "HIGH",
        }]

        with patch.dict("os.environ", {"AI_VALIDATION_ENABLED": "True", "ANTHROPIC_API_KEY": "dummy"}):
            with patch("app.tasks.scan_tasks.run_sast_scan", return_value=_STUB_FINDING), \
                 patch("app.tasks.scan_tasks.run_dependency_scan", return_value=[]), \
                 patch("app.tasks.scan_tasks.run_secrets_scan", return_value=[]), \
                 patch("anthropic.Anthropic") as mock_cls:
                mock_client = _make_mock_client(low_conf_response)
                mock_cls.return_value = mock_client
                run_stub_scan_task(scan.id)

        db.refresh(scan)
        assert scan.status == "completed"

        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        db.close()

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.status == "low_confidence"
        assert finding.ai_confidence == "0.30"
        # Plain fields should still be populated even on low-confidence findings
        assert finding.plain_title is not None
        assert finding.feature_area == "Admin & Backend"
