import json
from security.parsers.base import ConsolidatedReport, Severity

def generate_consolidated_sarif(report: ConsolidatedReport) -> str:
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DevSecOps Unified Security Gatekeeper",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/shsi1309-gif/devsecops-security-pipeline",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    rules_dict = {}
    results = []

    for f in report.findings:
        rule_id = f.cwe or f.cve or f.id
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation or "Review code and apply security hardening."}
            }

        level = "error" if f.severity in [Severity.CRITICAL, Severity.HIGH] else ("warning" if f.severity == Severity.MEDIUM else "note")
        
        # Parse location
        loc_parts = f.location.split(":")
        uri = loc_parts[0] if len(loc_parts) > 0 else "source"
        line = int(loc_parts[1]) if len(loc_parts) > 1 and loc_parts[1].isdigit() else 1

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{f.description} ({f.tool.upper()})"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": line}
                    }
                }
            ]
        })

    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules_dict.values())
    sarif["runs"][0]["results"] = results

    return json.dumps(sarif, indent=2)
