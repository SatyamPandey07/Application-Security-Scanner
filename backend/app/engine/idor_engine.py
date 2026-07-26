import httpx
from typing import List, Dict, Any, Optional


def run_authenticated_idor_scan(
    target_url: str,
    user_a_creds: Dict[str, str],
    user_b_creds: Dict[str, str],
    auth_login_endpoint: str = "/auth/login",
    test_resource_endpoints: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Executes authenticated IDOR/BOLA vulnerability testing using explicit user-provided test credentials.
    Contained strictly to provided test accounts User A and User B.
    """
    findings = []
    if not test_resource_endpoints:
        test_resource_endpoints = ["/users/me", "/api/user/profile", "/api/orders/1"]

    base_url = target_url.rstrip("/")

    # 1. Authenticate User A and User B to obtain session tokens
    token_a = None
    token_b = None

    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            resp_a = client.post(f"{base_url}{auth_login_endpoint}", data=user_a_creds)
            if resp_a.status_code in [200, 201]:
                data_a = resp_a.json()
                token_a = data_a.get("access_token") or data_a.get("token")

            resp_b = client.post(f"{base_url}{auth_login_endpoint}", data=user_b_creds)
            if resp_b.status_code in [200, 201]:
                data_b = resp_b.json()
                token_b = data_b.get("access_token") or data_b.get("token")
    except Exception as e:
        pass

    if not token_a or not token_b:
        return findings

    # 2. Cross-account authorization test (User A's token accessing User B's resource endpoint)
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            for ep in test_resource_endpoints:
                target_ep_url = f"{base_url}{ep}"

                # Request using User A token
                headers_a = {"Authorization": f"Bearer {token_a}"}
                res_a = client.get(target_ep_url, headers=headers_a)

                # Request using User B token
                headers_b = {"Authorization": f"Bearer {token_b}"}
                res_b = client.get(target_ep_url, headers=headers_b)

                # Flag IDOR if User A gets 200 OK for resource containing User B identifiers/email
                if res_a.status_code == 200 and res_b.status_code == 200:
                    body_a = res_a.text
                    email_b = user_b_creds.get("username") or user_b_creds.get("email", "")

                    if email_b and email_b in body_a:
                        findings.append({
                            "source": "access_control",
                            "rule_id": "access-control-idor-bola",
                            "file_path": target_ep_url,
                            "line_number": 1,
                            "code_snippet": f"IDOR Vulnerability: Endpoint '{ep}' returned User B data ({email_b}) when authenticated as User A.",
                            "severity_raw": "CRITICAL",
                        })
    except Exception as e:
        pass

    return findings
