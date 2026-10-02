import json
from typing import List
from security.parsers.base import Finding, Severity, Category

def parse_gitleaks_json(json_content: str) -> List[Finding]:
    findings: List[Finding] = []
    if not json_content.strip():
        return findings

    try:
        data = json.loads(json_content)
    except Exception:
        return findings

    if not isinstance(data, list):
        return findings

    for idx, item in enumerate(data):
        rule_id = item.get("RuleID", "leaked-secret")
        desc = item.get("Description", "Detected plaintext secret or high-entropy credential")
        file_path = item.get("File", "unknown")
        start_line = item.get("StartLine", 0)
        secret_match = item.get("Secret", "")
        masked_secret = secret_match[:4] + ("*" * max(0, len(secret_match) - 6)) + secret_match[-2:] if len(secret_match) > 6 else "****"
        
        finding = Finding(
            id=f"gitleaks-{rule_id}-{idx}",
            tool="gitleaks",
            category=Category.SECRETS,
            title=f"Exposed Secret: {rule_id}",
            description=f"{desc}. (Sample: {masked_secret})",
            severity=Severity.CRITICAL, # Secret leaks are critical
            location=f"{file_path}:{start_line}",
            line_number=start_line,
            cwe="CWE-798",
            remediation="Revoke and rotate the exposed credential immediately. Remove token from Git history and migrate to environment variables or secret vaults (e.g. AWS Secrets Manager, HashiCorp Vault).",
            raw_data=item
        )
        findings.append(finding)

    return findings
