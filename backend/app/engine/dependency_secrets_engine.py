import os
import re
import json
import subprocess
from typing import List, Dict, Any

# High-confidence Secret Patterns
SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'aws-access-key-id', 'Exposed AWS Access Key ID'),
    (r'ghp_[0-9a-zA-Z]{36}', 'github-personal-access-token', 'Exposed GitHub Personal Access Token'),
    (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'slack-token', 'Exposed Slack API Token'),
    (r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----', 'private-key-leak', 'Exposed Private Cryptographic Key'),
    (r'(?i)(?:api_key|secret_key|auth_token|access_token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', 'hardcoded-api-key', 'Hardcoded API Secret Key'),
]

KNOWN_VULN_PYTHON_PKGS = {
    "requests": ("2.20.0", "CVE-2018-18074", "Requests vulnerability in HTTP redirect handling"),
    "urllib3": ("1.24", "CVE-2019-11324", "urllib3 CRLF injection vulnerability"),
    "pyyaml": ("3.12", "CVE-2017-18342", "PyYAML Arbitrary Code Execution vulnerability"),
    "flask": ("0.12.0", "CVE-2018-1000656", "Flask Denial of Service vulnerability"),
}


def run_dependency_scan(scan_dir: str) -> List[Dict[str, Any]]:
    """
    Scans project dependency manifests (requirements.txt / package.json) for known vulnerable packages.
    """
    findings = []
    req_file = os.path.join(scan_dir, "requirements.txt")

    if os.path.exists(req_file):
        # Attempt 1: Run pip-audit CLI
        try:
            cmd = ["pip-audit", "-r", req_file, "-f", "json"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            stdout = res.stdout.strip()
            if stdout and stdout.startswith("{"):
                audit_json = json.loads(stdout)
                dependencies = audit_json.get("dependencies", [])
                for dep in dependencies:
                    pkg_name = dep.get("name", "")
                    pkg_version = dep.get("version", "")
                    vulns = dep.get("vulns", [])
                    for v in vulns:
                        cve_id = v.get("id", "CVE-UNKNOWN")
                        desc = v.get("description", f"Vulnerable dependency {pkg_name}=={pkg_version}")
                        findings.append({
                            "source": "dependency",
                            "rule_id": cve_id,
                            "file_path": "requirements.txt",
                            "line_number": 1,
                            "code_snippet": f"{pkg_name}=={pkg_version} ({cve_id}: {desc[:100]})",
                            "severity_raw": "HIGH",
                        })
        except Exception:
            pass

        # Fallback / Offline parsing of pinned vulnerable packages in requirements.txt
        try:
            with open(req_file, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f, start=1):
                    line_clean = line.strip()
                    if not line_clean or line_clean.startswith("#"):
                        continue
                    for pkg_name, (vuln_ver, cve_id, desc) in KNOWN_VULN_PYTHON_PKGS.items():
                        if f"{pkg_name}=={vuln_ver}" in line_clean.lower():
                            # Check if already added by pip-audit
                            if not any(f["rule_id"] == cve_id for f in findings):
                                findings.append({
                                    "source": "dependency",
                                    "rule_id": cve_id,
                                    "file_path": "requirements.txt",
                                    "line_number": idx,
                                    "code_snippet": f"{line_clean} ({cve_id}: {desc})",
                                    "severity_raw": "HIGH",
                                })
        except Exception:
            pass

    return findings


def run_secrets_scan(scan_dir: str) -> List[Dict[str, Any]]:
    """
    Scans project files for leaked API keys, tokens, and hardcoded secrets.
    """
    findings = []

    # Attempt detect-secrets CLI if available
    try:
        cmd = ["detect-secrets", "scan", scan_dir]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        stdout = res.stdout.strip()
        if stdout and stdout.startswith("{"):
            secrets_json = json.loads(stdout)
            results = secrets_json.get("results", {})
            for rel_path, secret_list in results.items():
                for secret_item in secret_list:
                    line_num = secret_item.get("line_number", 1)
                    type_str = secret_item.get("type", "Secret Leak")
                    findings.append({
                        "source": "secret",
                        "rule_id": f"secret-{type_str.lower().replace(' ', '-')}",
                        "file_path": rel_path.replace(scan_dir, "").lstrip("/\\"),
                        "line_number": line_num,
                        "code_snippet": f"Leaked Secret: {type_str}",
                        "severity_raw": "CRITICAL",
                    })
    except Exception:
        pass

    # Regex pattern scan across source files
    for root, _, files in os.walk(scan_dir):
        if any(ignored in root for ignored in [".git", "node_modules", "venv", "__pycache__"]):
            continue
        for file_name in files:
            if file_name.endswith((".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".txt", ".md")):
                full_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(full_path, scan_dir)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_idx, line_text in enumerate(f, start=1):
                            for pattern, rule_id, rule_desc in SECRET_PATTERNS:
                                match = re.search(pattern, line_text)
                                if match:
                                    # Avoid duplicate findings for same file & line
                                    if not any(f["file_path"] == rel_path and f["line_number"] == line_idx for f in findings):
                                        findings.append({
                                            "source": "secret",
                                            "rule_id": rule_id,
                                            "file_path": rel_path,
                                            "line_number": line_idx,
                                            "code_snippet": line_text.strip()[:150],
                                            "severity_raw": "CRITICAL",
                                        })
                except Exception:
                    pass

    return findings
