import os
import json
import shutil
import tempfile
import subprocess
from typing import List, Dict, Any


def run_sast_scan(target: str) -> List[Dict[str, Any]]:
    """
    Executes a Semgrep SAST scan on a target repository (remote URL or local directory).
    Returns a list of parsed finding dictionaries.
    """
    is_temp_dir = False
    scan_dir = target

    # Handle git remote URL clone
    if target.startswith("http://") or target.startswith("https://") or target.startswith("git@"):
        temp_dir = tempfile.mkdtemp(prefix="sentinel_sast_")
        is_temp_dir = True
        scan_dir = temp_dir
        try:
            clone_cmd = ["git", "clone", "--depth", "1", target, temp_dir]
            res = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=120)
            if res.returncode != 0:
                raise RuntimeError(f"Git clone failed for {target}: {res.stderr.strip()}")
        except Exception as e:
            if is_temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            raise e

    try:
        # Run Semgrep CLI with security-audit ruleset
        semgrep_cmd = ["semgrep", "scan", "--config", "p/security-audit", "--json", scan_dir]
        res = subprocess.run(semgrep_cmd, capture_output=True, text=True, timeout=300)

        stdout = res.stdout.strip()

        # If security-audit yields nothing, try python ruleset fallback
        if not stdout or stdout == "[]":
            fallback_cmd = ["semgrep", "scan", "--config", "p/python", "--json", scan_dir]
            fallback_res = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=180)
            stdout = fallback_res.stdout.strip()

        if not stdout:
            return []

        try:
            results_json = json.loads(stdout)
        except json.JSONDecodeError:
            raise RuntimeError(f"Failed to parse Semgrep JSON output: {stdout[:200]}")

        raw_results = results_json.get("results", [])
        findings = []

        for item in raw_results:
            file_path = item.get("path", "")
            start_info = item.get("start", {})
            line_number = start_info.get("line", 1)

            extra = item.get("extra", {})
            rule_id = item.get("check_id", "sast-finding")
            severity_raw = extra.get("severity", "WARNING").upper()

            code_snippet = ""
            # Pull actual line from file
            full_file = os.path.join(scan_dir, file_path) if not os.path.isabs(file_path) else file_path
            if os.path.exists(full_file):
                try:
                    with open(full_file, "r", encoding="utf-8", errors="ignore") as f:
                        all_lines = f.readlines()
                        if 0 < line_number <= len(all_lines):
                            code_snippet = all_lines[line_number - 1].strip()
                except Exception:
                    pass

            if not code_snippet:
                code_snippet = extra.get("message", "Semgrep SAST finding")

            findings.append({
                "source": "sast",
                "rule_id": rule_id,
                "file_path": file_path,
                "line_number": line_number,
                "code_snippet": code_snippet,
                "severity_raw": severity_raw,
            })

        return findings

    finally:
        if is_temp_dir and os.path.exists(scan_dir):
            shutil.rmtree(scan_dir, ignore_errors=True)
