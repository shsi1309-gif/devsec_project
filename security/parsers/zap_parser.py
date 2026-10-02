import json
from typing import List
from security.parsers.base import Finding, Severity, Category

def map_zap_risk(risk_code: str, risk_desc: str = "") -> Severity:
    code = str(risk_code)
    desc = risk_desc.upper()
    if code == "3" or "HIGH" in desc:
        return Severity.HIGH
    elif code == "2" or "MEDIUM" in desc:
        return Severity.MEDIUM
    elif code == "1" or "LOW" in desc:
        return Severity.LOW
    elif code == "0" or "INFO" in desc:
        return Severity.INFO
    return Severity.LOW

def parse_zap_json(json_content: str) -> List[Finding]:
    findings: List[Finding] = []
    if not json_content.strip():
        return findings

    try:
        data = json.loads(json_content)
    except Exception:
        return findings

    # Handles both standard ZAP JSON and Baseline JSON formats
    site_list = data.get("site", [])
    if isinstance(site_list, dict):
        site_list = [site_list]

    for site in site_list:
        alerts = site.get("alerts", [])
        for idx, alert in enumerate(alerts):
            name = alert.get("name", alert.get("alert", "ZAP Alert"))
            risk_code = alert.get("riskcode", "1")
            risk_desc = alert.get("riskdesc", "")
            desc = alert.get("desc", alert.get("description", "Dynamic security alert identified by OWASP ZAP crawler."))
            solution = alert.get("solution", "Review endpoint headers, input validation, and access controls.")
            cwe_id = alert.get("cweid", "")
            cwe_str = f"CWE-{cwe_id}" if cwe_id and cwe_id != "0" else "CWE-693"
            
            instances = alert.get("instances", [])
            uri = instances[0].get("uri", site.get("@name", "/")) if instances else site.get("@name", "/")

            finding = Finding(
                id=f"zap-{alert.get('pluginid', 'alert')}-{idx}",
                tool="owasp-zap",
                category=Category.DAST,
                title=f"DAST: {name}",
                description=desc[:250] + ("..." if len(desc) > 250 else ""),
                severity=map_zap_risk(risk_code, risk_desc),
                location=uri,
                cwe=cwe_str,
                remediation=solution[:300],
                raw_data=alert
            )
            findings.append(finding)

    return findings
