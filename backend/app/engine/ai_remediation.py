import os
import re
import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("sentinel.ai_remediation")

# ---------------------------------------------------------------------------
# Jargon denylist — any plain_* field containing these tokens must be retried.
# Case-insensitive whole-word match.
# ---------------------------------------------------------------------------
PLAIN_JARGON_DENYLIST: List[str] = [
    "injection",
    r"\bxss\b",
    r"\bcsrf\b",
    "payload",
    "sanitize",
    "sanitise",
    "sanitization",
    "sanitisation",
    r"\bvector\b",
    r"\bcvss\b",
    "endpoint",
    "deserialization",
    "deserialisation",
    r"\bssti\b",
    r"\bssrf\b",
    r"\blfi\b",
    r"\brfi\b",
    r"\brce\b",
    r"\bidor\b",
    r"\bbola\b",
    r"\bdom\b",
    "traversal",
    r"enumerat\w*",      # enumeration / enumerate / enumerating
    r"exfiltrat\w*",     # exfiltrate / exfiltration / exfiltrating
    "parameterize",
    "parameterise",
    r"\borm\b",
    r"\bapi\b",
    r"\bcve-\d",
    r"\bowasp\b",
    "vulnerability class",
    "attack surface",
    "threat actor",
    "zero.?day",
    "buffer overflow",
    "race condition",
]

# Fixed set of feature_area values
VALID_FEATURE_AREAS = frozenset([
    "Login & Accounts",
    "Payments & Checkout",
    "Customer Data & Privacy",
    "Search & Browsing",
    "Contact & Forms",
    "Admin & Backend",
    "Other",
])

PLAIN_FIELD_NAMES = [
    "plain_title",
    "plain_location",
    "plain_whats_wrong",
    "plain_why_it_exists",
    "plain_real_world_impact",
    "plain_risk_level",
    "plain_what_to_do",
]

# ---------------------------------------------------------------------------
# Rule-Based Layman Knowledge Base (Rule ID -> Detailed Layman Explanation)
# ---------------------------------------------------------------------------
RULE_LAYMAN_MAP: Dict[str, Dict[str, str]] = {
    "10020": {
        "plain_title": "Your website pages can be framed inside fraudulent websites",
        "plain_whats_wrong": "Your web server is missing a protective header (X-Frame-Options) that stops other sites from embedding your web pages inside hidden frames. Without this header, malicious actors can overlay invisible click traps over your site.",
        "plain_why_it_exists": "Web servers by default allow any website to embed your pages in an iframe unless you explicitly configure security response headers to block framing.",
        "plain_real_world_impact": "Attackers could create a fake website that looks like a prize giveaway, put your real login form invisibly underneath it, and trick users into clicking buttons that transfer money or delete their accounts without realizing it.",
        "plain_risk_level": "Worth fixing — prevents deceptive click-trap attacks against site visitors.",
        "plain_what_to_do": "Ask your web host or developer to add the 'X-Frame-Options: DENY' or 'SAMEORIGIN' header to all web server responses.",
        "feature_area": "Customer Data & Privacy",
    },
    "10038": {
        "plain_title": "Your website lacks a security policy guard against untrusted scripts",
        "plain_whats_wrong": "Your web server does not send a Content Security Policy (CSP) header. This header acts as a browser whitelist that tells visitors' browsers which scripts and images are safe to load.",
        "plain_why_it_exists": "Most modern web applications do not enable a restrictive Content Security Policy by default because it requires defining allowed domain origins for external scripts.",
        "plain_real_world_impact": "If an attacker ever finds a way to insert malicious text into your site, the visitor's browser will execute their scripts without restriction, potentially stealing login tokens or credit card inputs.",
        "plain_risk_level": "Fix this soon — adding a Content Security Policy stops many browser-based attacks in their tracks.",
        "plain_what_to_do": "Have your developer configure a Content Security Policy (CSP) header that restricts script execution to trusted domains.",
        "feature_area": "Search & Browsing",
    },
    "90003": {
        "plain_title": "Third-party software libraries loaded without integrity checks",
        "plain_whats_wrong": "Your website loads external software code from another web server (like a public CDN) without verifying if that code has been altered or tampered with before running it.",
        "plain_why_it_exists": "Developers often link to external script files for speed, but forget to include cryptographic hash checks that verify the file hasn't changed on the remote server.",
        "plain_real_world_impact": "If the external library server gets compromised, hackers could replace the library file with a malicious version that runs inside every visitor's browser.",
        "plain_risk_level": "Worth fixing — protects your users if a third-party server is compromised.",
        "plain_what_to_do": "Ask your developer to add 'integrity' cryptographic hashes to all external script and style links.",
        "feature_area": "Other",
    },
    "10015": {
        "plain_title": "User login session cookies missing automatic browser protection flags",
        "plain_whats_wrong": "The session cookies your site gives to logged-in users are missing safety flags (HttpOnly or Secure). These flags prevent malicious scripts from reading the cookie and ensure it is only sent over encrypted connections.",
        "plain_why_it_exists": "Cookie settings often default to basic permissions unless developer code explicitly attaches HttpOnly, Secure, and SameSite attributes during login.",
        "plain_real_world_impact": "If a visitor clicks a suspicious link or runs an untrusted script, their active login session could be intercepted or hijacked.",
        "plain_risk_level": "Fix this now — login session cookies should always be locked down.",
        "plain_what_to_do": "Configure your session cookie settings to include HttpOnly, Secure, and SameSite=Lax flags.",
        "feature_area": "Login & Accounts",
    },
    "python-sql-injection": {
        "plain_title": "Database form fields can be tricked into exposing private records",
        "plain_whats_wrong": "A text input field passes what users type directly into database commands without checking it first. Instead of treating input as simple text, the database reads it as instructions.",
        "plain_why_it_exists": "This happens when developer code combines raw text strings into database queries instead of using safe parameterized query placeholders.",
        "plain_real_world_impact": "An attacker could type special database commands into a search bar or login form to view, modify, or erase all user accounts and private data.",
        "plain_risk_level": "Fix this now — this is a critical issue that threatens database privacy.",
        "plain_what_to_do": "Instruct your development team to use prepared statements or parameterized queries for all database interactions.",
        "feature_area": "Login & Accounts",
    },
    "hardcoded-secret": {
        "plain_title": "Private password or secret key exposed in application code",
        "plain_whats_wrong": "A confidential password, API key, or encryption secret was written directly inside the application's source files instead of being stored safely in an environment vault.",
        "plain_why_it_exists": "Developers often hardcode secret keys during local testing and accidentally push them into the application codebase.",
        "plain_real_world_impact": "Anyone who gains access to the code repository or site assets can copy the secret key to access backend services or forge user credentials.",
        "plain_risk_level": "Fix this now — secret keys should be revoked and moved out of code immediately.",
        "plain_what_to_do": "Immediately revoke the exposed key, generate a new one, and store it in an environment variable file (.env).",
        "feature_area": "Admin & Backend",
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _jargon_pattern() -> re.Pattern:
    """Compile the denylist into a single case-insensitive OR pattern."""
    parts = []
    for term in PLAIN_JARGON_DENYLIST:
        is_raw_regex = (
            term.startswith(r"\b")
            or any(c in term for c in r"?.*+([\\")
        )
        if is_raw_regex:
            parts.append(term)
        else:
            parts.append(r"\b" + re.escape(term) + r"\b")
    return re.compile("|".join(parts), re.IGNORECASE)


_JARGON_RE = _jargon_pattern()

_FILE_PATH_RE = re.compile(
    r"[\/\\][^\s]*\.[a-zA-Z]{1,5}(?:\s|$|,|;)"
    r"|[a-zA-Z0-9_\-]+\.[a-zA-Z]{1,5}\s*,?\s*line",
    re.IGNORECASE,
)


def find_jargon_offenders(result: Dict[str, Any]) -> List[str]:
    """Return list of plain_* field names that contain denylist terms."""
    offenders = []
    for field in PLAIN_FIELD_NAMES:
        val = result.get(field, "") or ""
        if _JARGON_RE.search(val):
            offenders.append(field)
    return offenders


def plain_location_looks_like_path(location: str) -> bool:
    """Return True if plain_location accidentally looks like a code file path."""
    return bool(_FILE_PATH_RE.search(location or ""))


def get_rule_layman_fallback(rule_id: str) -> Dict[str, str]:
    """Lookup rule ID in knowledge base or generate rich layman fallback."""
    clean_id = str(rule_id).strip().lower()
    for key, val in RULE_LAYMAN_MAP.items():
        if key.lower() in clean_id or clean_id in key.lower():
            return val

    # Keyword-based dynamic fallback generator
    if any(k in clean_id for k in ["sql", "query", "database", "orm"]):
        return {
            "plain_title": "Database input fields can be manipulated by strangers",
            "plain_whats_wrong": "A search or input form sends user text directly into database commands without validating it. This allows commands to run instead of plain text search.",
            "plain_why_it_exists": "The code combines text strings into database queries instead of using safe placeholder parameters.",
            "plain_real_world_impact": "An attacker could view, alter, or delete private database records or customer accounts.",
            "plain_risk_level": "Fix this now — severe risk to database confidentiality.",
            "plain_what_to_do": "Have your development team update database queries to use safe parameterized placeholders.",
            "feature_area": "Login & Accounts",
        }
    if any(k in clean_id for k in ["secret", "key", "password", "token", "credential"]):
        return {
            "plain_title": "Private secret key or password exposed in application configuration",
            "plain_whats_wrong": "A secret security key or internal password was written directly in the code files instead of a safe environment vault.",
            "plain_why_it_exists": "Keys are frequently written in code during development testing and left behind by accident.",
            "plain_real_world_impact": "Anyone viewing your application files could copy the key and access administrative services.",
            "plain_risk_level": "Fix this now — secret keys should never be present in public code files.",
            "plain_what_to_do": "Revoke the exposed key, generate a new secret key, and store it in environment variable files.",
            "feature_area": "Admin & Backend",
        }
    if any(k in clean_id for k in ["header", "cookie", "csp", "frame", "cors"]):
        return {
            "plain_title": "Web server security configuration is missing recommended protection settings",
            "plain_whats_wrong": "Your web server is missing security configuration headers that instruct browsers to enforce strict safety policies on scripts and cookies.",
            "plain_why_it_exists": "Web server software defaults to broad permissions unless custom security response headers are added.",
            "plain_real_world_impact": "Visitors browsing your website are less protected against click traps or unauthorized script execution.",
            "plain_risk_level": "Worth fixing — enhances automatic browser security for all visitors.",
            "plain_what_to_do": "Ask your web host or developer to add standard security headers to your server responses.",
            "feature_area": "Customer Data & Privacy",
        }

    return _default_result()


def _build_main_prompt(
    rule_id: str,
    file_path: Optional[str],
    line_number: Optional[int],
    code_snippet: Optional[str],
    surrounding_code: str,
    route_context: Optional[str],
) -> str:
    return f"""You are Sentinel's AI Security Engine. Review the following security finding flagged by an automated scanner.

Finding Details:
- Rule ID: {rule_id}
- File Path: {file_path or 'N/A'}
- Line Number: {line_number or 1}
- Route / URL context (if known): {route_context or file_path or 'N/A'}
- Flagged Code Snippet:
```
{code_snippet or 'N/A'}
```

Surrounding Code Context (~20 lines):
```
{surrounding_code or code_snippet or 'N/A'}
```

Respond with STRICT JSON containing ONLY the following keys (no markdown, no commentary outside the JSON):
{{
  "is_likely_true_positive": boolean,
  "confidence": float between 0.0 and 1.0,
  "plain_english_explanation": "concise technical explanation of why this is or is not a real security issue",
  "exploit_scenario": "short step-by-step description of how an attacker could exploit this vulnerability",
  "suggested_fix_diff": "unified git diff patch string fixing the issue, or null",

  "plain_title": "A short plain-English headline, max 10 words, NO technical jargon. Example: 'Your search box can be tricked into running harmful code'",
  "plain_location": "WHERE a normal user would find this — describe the page, button, or form they would click, NEVER use a file path or line number. If there is no live page, say what part of the system is affected in plain terms.",
  "plain_whats_wrong": "A detailed 2 to 3 sentence layman explanation answering 'What is this bug in simple everyday terms?'. Explain what is happening without using any technical jargon so any non-technical site owner immediately understands.",
  "plain_why_it_exists": "A 1 to 2 sentence layman explanation answering 'Why does this issue exist in the website or code?' (e.g. how it was created or why default settings allowed it).",
  "plain_real_world_impact": "What could actually happen to the business or customers if this is exploited? Be concrete and specific.",
  "plain_risk_level": "One of: 'Fix this now', 'Fix this soon', 'Worth fixing', 'Minor' — followed by a dash and a one-line plain reason. Example: 'Fix this now — this is easy to find and could expose customer passwords.'",
  "plain_what_to_do": "1-2 plain-language next steps written for someone who will hire a developer, not do it themselves.",
  "feature_area": "One of exactly: 'Login & Accounts', 'Payments & Checkout', 'Customer Data & Privacy', 'Search & Browsing', 'Contact & Forms', 'Admin & Backend', 'Other'. Infer from the route/page context."
}}

CRITICAL RULES for plain_* fields:
- NEVER use these words or abbreviations in plain_* fields: injection, XSS, CSRF, payload, sanitize, sanitise, vector, CVSS, endpoint, deserialization, SSTI, SSRF, LFI, RFI, RCE, IDOR, BOLA, DOM, traversal, parameterize, ORM, API, CVE, OWASP, zero-day, buffer overflow, attack surface.
- plain_location must describe a user-visible page or feature, NEVER a file path or line number.
- All plain_* fields must be written as if explaining to someone who has never heard security terms.
"""


def _build_rewrite_prompt(offending_fields: Dict[str, str], context_summary: str) -> str:
    fields_block = json.dumps(offending_fields, indent=2)
    return f"""You previously wrote the following plain-language security descriptions, but they contain technical jargon that must be removed.

Context: {context_summary}

Fields that need rewriting (current values):
{fields_block}

Rewrite ONLY these fields. Return STRICT JSON with the same keys and new values that:
- Use absolutely NO technical terms (no injection, XSS, CSRF, payload, sanitize, sanitise, vector, CVSS, endpoint, deserialization, IDOR, BOLA, DOM, traversal, ORM, API, CVE, OWASP, zero-day, buffer overflow, attack surface)
- Are written as if explaining to a relative who does not work in technology
- Keep plain_location describing a user-visible page/feature, never a file path

Respond with STRICT JSON only, no commentary.
"""


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def validate_and_remediate_finding(
    rule_id: str,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    code_snippet: Optional[str] = None,
    surrounding_code: str = "",
    route_context: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Calls Anthropic API to validate a security finding, generate a technical
    explanation and fix diff, AND generate a full set of plain-language fields
    for non-technical audiences. Jargon in plain_* fields triggers one retry.
    """
    rule_fallback = get_rule_layman_fallback(rule_id)
    default_result = _default_result(rule_fallback)

    ai_enabled = os.getenv("AI_VALIDATION_ENABLED", "True").lower() in ["true", "1"]
    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    if not ai_enabled or not api_key:
        logger.info("AI validation disabled or ANTHROPIC_API_KEY not set. Using rule fallback.")
        return default_result

    prompt = _build_main_prompt(
        rule_id=rule_id,
        file_path=file_path,
        line_number=line_number,
        code_snippet=code_snippet,
        surrounding_code=surrounding_code,
        route_context=route_context,
    )

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)

        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=1500,
            temperature=0.0,
            messages=[{"role": "user", "content": prompt}],
        )

        content_text = ""
        if response.content:
            content_text = response.content[0].text.strip()

        result = parse_ai_json_response(content_text, default_result)

        # ── Jargon validation pass ──────────────────────────────────────────
        offenders = find_jargon_offenders(result)
        if offenders:
            logger.info(
                f"Jargon detected in plain fields {offenders} for rule {rule_id}. "
                "Issuing one rewrite call."
            )
            offending_values = {f: result.get(f, "") for f in offenders}
            context_summary = (
                f"Rule: {rule_id}, "
                f"location context: {route_context or file_path or 'unknown'}"
            )
            rewrite_prompt = _build_rewrite_prompt(offending_values, context_summary)

            rewrite_response = client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=800,
                temperature=0.0,
                messages=[{"role": "user", "content": rewrite_prompt}],
            )

            rewrite_text = ""
            if rewrite_response.content:
                rewrite_text = rewrite_response.content[0].text.strip()

            rewritten = _parse_plain_rewrite(rewrite_text, offenders)
            for field, val in rewritten.items():
                result[field] = val

        # ── plain_location path check ───────────────────────────────────────
        loc = result.get("plain_location", "")
        if plain_location_looks_like_path(loc):
            result["plain_location"] = (
                "Behind the scenes in the application — not something customers see "
                "directly, but it affects how their data is processed."
            )

        # ── feature_area guard ──────────────────────────────────────────────
        if result.get("feature_area") not in VALID_FEATURE_AREAS:
            result["feature_area"] = "Other"

        return result

    except Exception as e:
        logger.error(f"Anthropic API call failed: {e}. Falling back to defaults.")
        return default_result


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_ai_json_response(raw_text: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
    """
    Defensively parse the LLM JSON response, extracting technical fields
    and plain_* / feature_area fields.
    """
    if not raw_text:
        return fallback

    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
    if json_match:
        clean_text = json_match.group(1)
    else:
        json_match_outer = re.search(r"(\{.*\})", raw_text, re.DOTALL)
        clean_text = json_match_outer.group(1) if json_match_outer else raw_text

    try:
        parsed = json.loads(clean_text)
    except Exception as e:
        logger.warning(f"Failed to parse LLM JSON: {e}. Raw: {raw_text[:200]}")
        return fallback

    fb = fallback

    return {
        # Technical fields
        "is_likely_true_positive": bool(parsed.get("is_likely_true_positive", True)),
        "confidence": float(parsed.get("confidence", 0.7)),
        "plain_english_explanation": str(
            parsed.get("plain_english_explanation", fb.get("plain_english_explanation", ""))
        ),
        "exploit_scenario": str(
            parsed.get("exploit_scenario", fb.get("exploit_scenario", ""))
        ),
        "suggested_fix_diff": parsed.get("suggested_fix_diff"),

        # Plain-language fields
        "plain_title": str(
            parsed.get("plain_title", fb.get("plain_title", "Security issue detected"))
        ),
        "plain_location": str(
            parsed.get("plain_location", fb.get("plain_location", "Behind the scenes in the application"))
        ),
        "plain_whats_wrong": str(
            parsed.get("plain_whats_wrong", fb.get("plain_whats_wrong", "A security issue was found that needs attention."))
        ),
        "plain_why_it_exists": str(
            parsed.get("plain_why_it_exists", fb.get("plain_why_it_exists", "This usually happens when default configuration settings leave security rules turned off."))
        ),
        "plain_real_world_impact": str(
            parsed.get("plain_real_world_impact", fb.get("plain_real_world_impact", "This could affect the security of your users or data."))
        ),
        "plain_risk_level": str(
            parsed.get("plain_risk_level", fb.get("plain_risk_level", "Worth fixing — a security issue was detected."))
        ),
        "plain_what_to_do": str(
            parsed.get("plain_what_to_do", fb.get("plain_what_to_do", "Ask your developer to review and fix this issue."))
        ),
        "feature_area": str(
            parsed.get("feature_area", fb.get("feature_area", "Other"))
        ),
    }


def _parse_plain_rewrite(raw_text: str, expected_fields: List[str]) -> Dict[str, str]:
    """Parse a jargon-rewrite response, extracting only the expected field keys."""
    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
    if json_match:
        clean_text = json_match.group(1)
    else:
        json_match_outer = re.search(r"(\{.*\})", raw_text, re.DOTALL)
        clean_text = json_match_outer.group(1) if json_match_outer else raw_text

    try:
        parsed = json.loads(clean_text)
        return {f: str(parsed[f]) for f in expected_fields if f in parsed}
    except Exception as e:
        logger.warning(f"Failed to parse jargon-rewrite JSON: {e}. Raw: {raw_text[:200]}")
        return {}


def _default_result(override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    base = {
        # Technical
        "is_likely_true_positive": True,
        "confidence": 0.7,
        "plain_english_explanation": "Raw finding detected by security rules engine.",
        "exploit_scenario": "Standard vulnerability scenario associated with rule.",
        "suggested_fix_diff": None,
        # Plain language
        "plain_title": "A security issue was detected",
        "plain_location": "Behind the scenes in the application",
        "plain_whats_wrong": "A security issue was found on your website. This happens when certain safety checks are missing or turned off, leaving a weakness that could be used inappropriately.",
        "plain_why_it_exists": "This usually happens when default configuration settings leave security rules turned off or when form inputs are processed directly without validation.",
        "plain_real_world_impact": "This could affect the security of your users or data if someone attempts to misuse this vulnerability.",
        "plain_risk_level": "Worth fixing — a security issue was detected.",
        "plain_what_to_do": "Ask your developer to review and fix this issue by turning on recommended safety settings.",
        "feature_area": "Other",
    }
    if override:
        base.update({k: v for k, v in override.items() if v is not None})
    return base
