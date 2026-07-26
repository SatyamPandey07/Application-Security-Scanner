import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import Finding
from app.engine.compliance_mapper import generate_compliance_report, generate_compliance_csv


def test_compliance_report_generation_pass():
    findings = [
        {"source": "sast", "status": "low_confidence", "rule_id": "rule-1", "severity_raw": "LOW", "file_path": "a.py"}
    ]
    report = generate_compliance_report(findings)

    assert "SOC 2" in report
    assert "PCI DSS v4.0" in report
    assert "OWASP ASVS v4.0" in report

    assert report["SOC 2"]["overall_status"] == "PASS"
    assert report["PCI DSS v4.0"]["overall_status"] == "PASS"


def test_compliance_report_generation_fail_blocking_finding():
    findings = [
        {"source": "secret", "status": "confirmed", "rule_id": "aws-key-leak", "severity_raw": "CRITICAL", "file_path": "config.py"}
    ]
    report = generate_compliance_report(findings)

    soc2_cc61 = next(c for c in report["SOC 2"]["controls"] if c["control_id"] == "SOC2-CC6.1")
    assert soc2_cc61["status"] == "FAIL"
    assert soc2_cc61["blocking_count"] == 1
    assert report["SOC 2"]["overall_status"] == "FAIL"


def test_compliance_csv_export():
    findings = [
        {"source": "access_control", "status": "confirmed", "rule_id": "idor-vuln", "severity_raw": "CRITICAL", "file_path": "/api/user"}
    ]
    csv_str = generate_compliance_csv(findings)

    assert "Framework,Control ID,Control Name,Status,Blocking Findings Count" in csv_str
    assert "SOC 2" in csv_str
    assert "FAIL" in csv_str
