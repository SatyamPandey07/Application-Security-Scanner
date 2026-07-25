import math
from typing import Dict, Any
from cvss import CVSS3


def calculate_cvss31_score(vector_string: str) -> float:
    """
    Pure unit-testable CVSS v3.1 base score calculator.
    Verifies input vector against FIRST.org official spec formula.
    """
    c = CVSS3(vector_string)
    return float(c.base_score)


def map_finding_to_cvss(source: str, severity_raw: str, rule_id: str = "") -> Dict[str, Any]:
    """
    Maps raw finding severity to CVSS 3.1 vector string and numerical base score.
    Flags as estimated when vector components are derived from raw qualitative severity.
    """
    sev_upper = (severity_raw or "MEDIUM").upper()

    if sev_upper == "CRITICAL":
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    elif sev_upper in ["HIGH", "ERROR"]:
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    elif sev_upper in ["MEDIUM", "WARNING"]:
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    elif sev_upper == "LOW":
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
    else:  # INFO / INFORMATIONAL
        vector_str = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N"

    score = calculate_cvss31_score(vector_str)
    return {
        "cvss_score": score,
        "vector_string": vector_str,
        "is_estimated": True,
    }


def calculate_priority_score(cvss_score: float, ai_confidence: float) -> float:
    """
    Computes combined priority score: CVSS 3.1 base score weighted by AI confidence signal.
    """
    return round(float(cvss_score) * float(ai_confidence), 2)
