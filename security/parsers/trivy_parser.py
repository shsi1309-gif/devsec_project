import json
from typing import List
from security.parsers.base import Finding, Severity, Category

def map_trivy_severity(trivy_sev: str) -> Severity:
    s = trivy_sev.upper()
    if s == "CRITICAL":
        return Severity.CRITICAL
    elif s == "HIGH":
        return Severity.HIGH
    elif s == "MEDIUM":
        return Severity.MEDIUM
    elif s == "LOW":
        return Severity.LOW
    return Severity.INFO

def parse_trivy_json(json_content: str, category: Category = Category.SCA) -> List[Finding]:
    findings: List[Finding] = []
    if not json_content.strip():
        return findings

    try:
        data = json.loads(json_content)
    except Exception:
        return findings

    results = data.get("Results", [])
    if not results and isinstance(data, list):
        results = data

    for result in results:
        target = result.get("Target", "dependencies")
        vulnerabilities = result.get("Vulnerabilities", []) or []
        for idx, vuln in enumerate(vulnerabilities):
            cve_id = vuln.get("VulnerabilityID", "CVE-Unknown")
            pkg_name = vuln.get("PkgName", "package")
            installed_ver = vuln.get("InstalledVersion", "")
            fixed_ver = vuln.get("FixedVersion", "N/A")
            title = vuln.get("Title", f"Vulnerability in {pkg_name}")
            desc = vuln.get("Description", f"Vulnerable package {pkg_name} ({installed_ver}) has known security issues.")
            raw_sev = vuln.get("Severity", "MEDIUM")
            cwe_ids = vuln.get("CweIDs", [])
            cwe_str = cwe_ids[0] if cwe_ids else "CWE-937"

            remediation = f"Upgrade {pkg_name} to version {fixed_ver} or higher." if fixed_ver != "N/A" else f"Update {pkg_name} to a secure release."

            finding = Finding(
                id=f"trivy-{cve_id}-{pkg_name}-{idx}",
                tool="trivy",
                category=category,
                title=f"{category.value}: {pkg_name} - {cve_id}",
                description=f"{title}. {desc[:200]}...",
                severity=map_trivy_severity(raw_sev),
                location=f"{target} ({pkg_name}@{installed_ver})",
                cve=cve_id,
                cwe=cwe_str,
                remediation=remediation,
                raw_data=vuln
            )
            findings.append(finding)

    return findings
