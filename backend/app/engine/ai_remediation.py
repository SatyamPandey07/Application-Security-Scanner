import os
import re
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("sentinel.ai_remediation")


def validate_and_remediate_finding(
    rule_id: str,
    file_path: Optional[str],
    line_number: Optional[int],
    code_snippet: Optional[str],
    surrounding_code: str = "",
) -> Dict[str, Any]:
    """
    Calls Anthropic API to validate a security finding, generate a plain English explanation,
    describe an exploit scenario, and propose a git patch diff fix.
    """
    default_result = {
        "is_likely_true_positive": True,
        "confidence": 0.7,
        "plain_english_explanation": "Raw finding detected by security rules engine.",
        "exploit_scenario": "Standard vulnerability scenario associated with rule.",
        "suggested_fix_diff": None,
    }

    ai_enabled = os.getenv("AI_VALIDATION_ENABLED", "True").lower() in ["true", "1"]
    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    if not ai_enabled or not api_key:
        logger.info("AI validation is disabled or ANTHROPIC_API_KEY is not set. Returning raw finding.")
        return default_result

    prompt = f"""You are Sentinel's AI Security Engine. Review the following security finding flagged by an automated scanner.

Finding Details:
- Rule ID: {rule_id}
- File Path: {file_path or 'N/A'}
- Line Number: {line_number or 1}
- Flagged Code Snippet:
```
{code_snippet or 'N/A'}
```

Surrounding Code Context (~20 lines):
```
{surrounding_code or code_snippet or 'N/A'}
```

Respond with STRICT JSON containing ONLY the following keys (no markdown formatting outside JSON):
{{
  "is_likely_true_positive": boolean,
  "confidence": float between 0.0 and 1.0,
  "plain_english_explanation": "concise explanation of why this is or is not a real security issue in this code",
  "exploit_scenario": "short step-by-step description of how an attacker could exploit this vulnerability",
  "suggested_fix_diff": "unified git diff patch string fixing the issue, or null"
}}
"""

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=1000,
            temperature=0.0,
            messages=[{"role": "user", "content": prompt}],
        )

        content_text = ""
        if response.content and len(response.content) > 0:
            content_text = response.content[0].text.strip()

        return parse_ai_json_response(content_text, default_result)

    except Exception as e:
        logger.error(f"Anthropic API call failed: {e}. Falling back to raw finding.")
        return default_result


def parse_ai_json_response(raw_text: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
    """
    Defensively parses LLM JSON response string, handling markdown wrappers, extra whitespace, or malformed JSON.
    """
    if not raw_text:
        return fallback

    # Extract JSON string if wrapped in markdown codeblocks
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_text, re.DOTALL)
    if json_match:
        clean_text = json_match.group(1)
    else:
        # Fallback regex extracting outermost json object
        json_match_outer = re.search(r'(\{.*\})', raw_text, re.DOTALL)
        clean_text = json_match_outer.group(1) if json_match_outer else raw_text

    try:
        parsed = json.loads(clean_text)
        return {
            "is_likely_true_positive": bool(parsed.get("is_likely_true_positive", True)),
            "confidence": float(parsed.get("confidence", 0.7)),
            "plain_english_explanation": str(parsed.get("plain_english_explanation", fallback["plain_english_explanation"])),
            "exploit_scenario": str(parsed.get("exploit_scenario", fallback["exploit_scenario"])),
            "suggested_fix_diff": parsed.get("suggested_fix_diff"),
        }
    except Exception as e:
        logger.warning(f"Failed to parse LLM JSON response: {e}. Raw: {raw_text[:150]}")
        return fallback
