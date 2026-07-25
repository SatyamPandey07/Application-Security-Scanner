import os
import time
import httpx
from typing import List, Dict, Any

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
MAX_SCAN_DURATION_SECONDS = 120  # Timeout guard


def run_dast_scan(target_url: str) -> List[Dict[str, Any]]:
    """
    Executes an OWASP ZAP DAST baseline (spider + passive scan) via ZAP REST API.
    Enforces reachability checks and max duration timeouts.
    """
    # 1. Target Reachability Check
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            resp = client.get(target_url)
    except Exception as e:
        raise RuntimeError(f"Target URL '{target_url}' is unreachable or timed out: {str(e)}")

    # 2. Check ZAP API Availability
    zap_available = False
    try:
        with httpx.Client(timeout=5.0) as client:
            zap_res = client.get(f"{ZAP_API_URL}/JSON/core/view/version/", params={"apikey": ZAP_API_KEY})
            if zap_res.status_code == 200:
                zap_available = True
    except Exception:
        zap_available = False

    if not zap_available:
        # Fallback for standalone/test environments where ZAP daemon is absent: perform basic HTTP header security analysis
        return run_fallback_http_analysis(target_url, resp)

    # 3. Trigger ZAP Spidering
    try:
        with httpx.Client(timeout=10.0) as client:
            spider_res = client.get(
                f"{ZAP_API_URL}/JSON/spider/action/scan/",
                params={"apikey": ZAP_API_KEY, "url": target_url}
            )
            spider_data = spider_res.json()
            spider_id = spider_data.get("scan")

            # Poll Spider Status with timeout guard
            start_time = time.time()
            while time.time() - start_time < 60:
                status_res = client.get(
                    f"{ZAP_API_URL}/JSON/spider/view/status/",
                    params={"apikey": ZAP_API_KEY, "scanId": spider_id}
                )
                progress = int(status_res.json().get("status", "0"))
                if progress >= 100:
                    break
                time.sleep(2)

            # Wait for Passive Scan Queue to drain
            pscan_start = time.time()
            while time.time() - pscan_start < 30:
                records_res = client.get(
                    f"{ZAP_API_URL}/JSON/pscan/view/recordsToScan/",
                    params={"apikey": ZAP_API_KEY}
                )
                remaining = int(records_res.json().get("recordsToScan", "0"))
                if remaining == 0:
                    break
                time.sleep(1)

            # Fetch ZAP Alerts
            alerts_res = client.get(
                f"{ZAP_API_URL}/JSON/core/view/alerts/",
                params={"apikey": ZAP_API_KEY, "baseurl": target_url}
            )
            alerts_json = alerts_res.json()
            raw_alerts = alerts_json.get("alerts", [])

            findings = []
            for alert in raw_alerts:
                findings.append({
                    "source": "dast",
                    "rule_id": alert.get("pluginId", alert.get("alert", "dast-alert")),
                    "file_path": alert.get("url", target_url),
                    "line_number": 1,
                    "code_snippet": f"Param: {alert.get('param', 'N/A')} | Evidence: {alert.get('evidence', 'N/A')}",
                    "severity_raw": alert.get("risk", "Medium").upper(),
                })

            return findings

    except Exception as e:
        raise RuntimeError(f"ZAP DAST scan execution error: {str(e)}")


def run_fallback_http_analysis(target_url: str, response: httpx.Response) -> List[Dict[str, Any]]:
    """
    Fallback HTTP baseline passive analyzer when ZAP daemon is not connected.
    Inspects security headers (X-Frame-Options, Content-Security-Policy, Strict-Transport-Security).
    """
    findings = []
    headers = response.headers

    if "X-Frame-Options" not in headers:
        findings.append({
            "source": "dast",
            "rule_id": "dast-missing-x-frame-options",
            "file_path": target_url,
            "line_number": 1,
            "code_snippet": "Missing X-Frame-Options header (Clickjacking vulnerability hazard)",
            "severity_raw": "MEDIUM",
        })

    if "Content-Security-Policy" not in headers:
        findings.append({
            "source": "dast",
            "rule_id": "dast-missing-csp",
            "file_path": target_url,
            "line_number": 1,
            "code_snippet": "Missing Content-Security-Policy header (XSS vulnerability hazard)",
            "severity_raw": "MEDIUM",
        })

    if "Strict-Transport-Security" not in headers and target_url.startswith("https://"):
        findings.append({
            "source": "dast",
            "rule_id": "dast-missing-hsts",
            "file_path": target_url,
            "line_number": 1,
            "code_snippet": "Missing Strict-Transport-Security (HSTS) header",
            "severity_raw": "LOW",
        })

    return findings
