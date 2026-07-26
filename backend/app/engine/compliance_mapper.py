from typing import List, Dict, Any

COMPLIANCE_FRAMEWORKS = {
    "SOC 2": [
        {
            "id": "SOC2-CC6.1",
            "name": "Logical Access Security & Authentication",
            "description": "Requires logical access controls to prevent unauthorized access and secret leaks.",
            "matching_sources": ["secret", "access_control"],
        },
        {
            "id": "SOC2-CC6.6",
            "name": "Boundary Protection & Web Application Security",
            "description": "Requires web application protections against common web threats and missing security headers.",
            "matching_sources": ["dast"],
        },
        {
            "id": "SOC2-CC6.8",
            "name": "Vulnerability Management & Secure Coding",
            "description": "Requires static analysis code audits and third-party vulnerability remediation.",
            "matching_sources": ["sast", "dependency"],
        },
    ],
    "PCI DSS v4.0": [
        {
            "id": "PCI-6.2",
            "name": "Bespoke & Custom Software Security",
            "description": "Bespoke custom software must be protected against software vulnerabilities.",
            "matching_sources": ["sast"],
        },
        {
            "id": "PCI-6.4",
            "name": "Web Application Attack Protection",
            "description": "Public-facing web applications are protected against web application attacks.",
            "matching_sources": ["dast", "access_control"],
        },
        {
            "id": "PCI-6.5",
            "name": "Software Component & Dependency Management",
            "description": "Third-party components and libraries are monitored for active vulnerabilities.",
            "matching_sources": ["dependency"],
        },
    ],
    "OWASP ASVS v4.0": [
        {
            "id": "ASVS-V1.1",
            "name": "Architecture & Access Control",
            "description": "Enforce access controls across all application endpoints.",
            "matching_sources": ["access_control", "secret"],
        },
        {
            "id": "ASVS-V5.1",
            "name": "Input Validation & Encoding",
            "description": "Verify all user input is validated and sanitized prior to processing.",
            "matching_sources": ["sast"],
        },
        {
            "id": "ASVS-V14.4",
            "name": "Dependency Security",
            "description": "Verify all third-party libraries do not contain known vulnerabilities.",
            "matching_sources": ["dependency"],
        },
    ],
}


def generate_compliance_report(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Maps findings to SOC 2, PCI DSS 4.0, and OWASP ASVS control frameworks.
    Returns pass/fail status per control and lists blocking findings.
    """
    report = {}

    for fw_name, controls in COMPLIANCE_FRAMEWORKS.items():
        fw_report = []
        passed_count = 0
        failed_count = 0

        for ctrl in controls:
            blocking = [
                f for f in findings
                if f.get("source") in ctrl["matching_sources"] and f.get("status") == "confirmed"
            ]

            status = "FAIL" if len(blocking) > 0 else "PASS"
            if status == "PASS":
                passed_count += 1
            else:
                failed_count += 1

            fw_report.append({
                "control_id": ctrl["id"],
                "control_name": ctrl["name"],
                "description": ctrl["description"],
                "status": status,
                "blocking_count": len(blocking),
                "blocking_findings": [
                    {
                        "rule_id": b.get("rule_id"),
                        "severity": b.get("severity_raw"),
                        "file_path": b.get("file_path"),
                    }
                    for b in blocking
                ],
            })

        report[fw_name] = {
            "total_controls": len(controls),
            "passed_controls": passed_count,
            "failed_controls": failed_count,
            "overall_status": "FAIL" if failed_count > 0 else "PASS",
            "controls": fw_report,
        }

    return report


def generate_compliance_csv(findings: List[Dict[str, Any]]) -> str:
    """
    Generates downloadable CSV export of compliance framework mappings.
    """
    lines = ["Framework,Control ID,Control Name,Status,Blocking Findings Count"]
    report = generate_compliance_report(findings)

    for fw_name, data in report.items():
        for ctrl in data["controls"]:
            lines.append(f'"{fw_name}","{ctrl["control_id"]}","{ctrl["control_name"]}","{ctrl["status"]}",{ctrl["blocking_count"]}')

    return "\n".join(lines)
