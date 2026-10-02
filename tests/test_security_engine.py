import json
import pytest
from security.parsers.base import Finding, Severity, Category, ConsolidatedReport
from security.parsers.gitleaks_parser import parse_gitleaks_json
from security.parsers.semgrep_parser import parse_semgrep_json
from security.parsers.trivy_parser import parse_trivy_json
from security.parsers.zap_parser import parse_zap_json
from security.policy_engine import SecurityPolicyEngine
from security.reporters.html_reporter import generate_html_dashboard
from security.reporters.markdown_reporter import generate_markdown_summary
from security.reporters.sarif_reporter import generate_consolidated_sarif

def test_semgrep_parser():
    sample_json = json.dumps({
        "results": [
            {
                "check_id": "python.lang.security.audit.sqli",
                "path": "app/database.py",
                "start": {"line": 42},
                "extra": {
                    "message": "SQL query format string detected",
                    "severity": "ERROR",
                    "metadata": {"cwe": "CWE-89"}
                }
            }
        ]
    })
    findings = parse_semgrep_json(sample_json)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cwe == "CWE-89"
    assert "app/database.py:42" in findings[0].location

def test_gitleaks_parser():
    sample_json = json.dumps([
        {
            "RuleID": "aws-access-key-id",
            "Description": "AWS Access Key",
            "File": "config/aws.env",
            "StartLine": 5,
            "Secret": "AKIAIOSFODNN7EXAMPLE"
        }
    ])
    findings = parse_gitleaks_json(sample_json)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].category == Category.SECRETS
    assert "AKIA" in findings[0].description

def test_trivy_parser():
    sample_json = json.dumps({
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-45803",
                        "PkgName": "urllib3",
                        "InstalledVersion": "1.26.17",
                        "FixedVersion": "1.26.18",
                        "Severity": "HIGH",
                        "Title": "Request body not stripped after 303 redirect",
                        "CweIDs": ["CWE-200"]
                    }
                ]
            }
        ]
    })
    findings = parse_trivy_json(sample_json)
    assert len(findings) == 1
    assert findings[0].cve == "CVE-2023-45803"
    assert findings[0].severity == Severity.HIGH

def test_policy_engine_gate_failure_on_critical():
    engine = SecurityPolicyEngine()
    report = ConsolidatedReport()
    report.findings.append(Finding(
        id="crit-1",
        tool="gitleaks",
        category=Category.SECRETS,
        title="Hardcoded API Key",
        description="Found key",
        severity=Severity.CRITICAL,
        location="app/config.py:10"
    ))
    
    passed, reasons = engine.evaluate_gate(report)
    assert passed is False
    assert len(reasons) >= 1
    assert report.risk_score >= 25.0

def test_policy_engine_gate_pass_on_clean_report():
    engine = SecurityPolicyEngine()
    report = ConsolidatedReport()
    passed, reasons = engine.evaluate_gate(report)
    assert passed is True
    assert len(reasons) == 0
    assert report.risk_score == 0.0

def test_reporters_generation():
    report = ConsolidatedReport()
    report.findings.append(Finding(
        id="f-1",
        tool="semgrep",
        category=Category.SAST,
        title="SQL Injection Vulnerability",
        description="String formatting in query",
        severity=Severity.HIGH,
        location="app/database.py:45",
        cwe="CWE-89",
        remediation="Use parameterized queries."
    ))
    
    # Test HTML reporter
    html_out = generate_html_dashboard(report)
    assert "<!DOCTYPE html>" in html_out
    assert "SQL Injection Vulnerability" in html_out
    assert "CWE-89" in html_out

    # Test Markdown reporter
    md_out = generate_markdown_summary(report)
    assert "DevSecOps Security Gatekeeper Summary" in md_out
    assert "HIGH" in md_out

    # Test SARIF reporter
    sarif_out = generate_consolidated_sarif(report)
    sarif_data = json.loads(sarif_out)
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == 1
