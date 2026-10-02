import json
from typing import List
from security.parsers.base import Finding, Severity, Category

def map_semgrep_severity(semgrep_sev: str) -> Severity:
    s = semgrep_sev.upper()
    if s in ["ERROR", "CRITICAL"]:
        return Severity.HIGH
    elif s in ["WARNING"]:
        return Severity.MEDIUM
    elif s in ["INFO"]:
        return Severity.LOW
    return Severity.MEDIUM

def parse_semgrep_json(json_content: str) -> List[Finding]:
    findings: List[Finding] = []
    if not json_content.strip():
        return findings

    try:
        data = json.loads(json_content)
    except Exception:
        return findings

    results = data.get("results", [])
    for idx, item in enumerate(results):
        check_id = item.get("check_id", "semgrep-rule")
        path = item.get("path", "unknown")
        start = item.get("start", {})
        line = start.get("line", 1)
        extra = item.get("extra", {})
        message = extra.get("message", "Semgrep security finding")
        raw_sev = extra.get("severity", "WARNING")
        metadata = extra.get("metadata", {})
        cwe = metadata.get("cwe", "CWE-Unknown")
        if isinstance(cwe, list) and cwe:
            cwe = cwe[0]

        finding = Finding(
            id=f"semgrep-{check_id.replace('.', '-')}-{idx}",
            tool="semgrep",
            category=Category.SAST,
            title=f"SAST: {check_id}",
            description=message,
            severity=map_semgrep_severity(raw_sev),
            location=f"{path}:{line}",
            line_number=line,
            cwe=str(cwe),
            remediation="Refactor code to use secure patterns (e.g. parameterized queries, strict validation, safe API libraries).",
            raw_data=item
        )
        findings.append(finding)

    return findings
