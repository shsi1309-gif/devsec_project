import yaml
import os
from typing import Dict, Any, List, Tuple
from security.parsers.base import ConsolidatedReport, Severity, Category

class SecurityPolicyEngine:
    DEFAULT_POLICY = {
        "thresholds": {
            "fail_on": {
                "critical": 0,
                "high": 0,
                "medium": 5,
                "low": 15
            },
            "fail_on_secrets": True,
            "max_acceptable_risk_score": 25.0
        },
        "remediation_sla_days": {
            "CRITICAL": 1,
            "HIGH": 7,
            "MEDIUM": 30,
            "LOW": 90
        }
    }

    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 25.0,
        Severity.HIGH: 10.0,
        Severity.MEDIUM: 3.0,
        Severity.LOW: 1.0,
        Severity.INFO: 0.0
    }

    def __init__(self, policy_path: str = "security_policy.yml"):
        self.policy_path = policy_path
        self.policy = self.load_policy()

    def load_policy(self) -> Dict[str, Any]:
        if os.path.exists(self.policy_path):
            try:
                with open(self.policy_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    return data or self.DEFAULT_POLICY
            except Exception as e:
                print(f"[WARN] Failed to read {self.policy_path}, using defaults: {e}")
                return self.DEFAULT_POLICY
        return self.DEFAULT_POLICY

    def calculate_risk_score(self, report: ConsolidatedReport) -> float:
        score = 0.0
        for finding in report.findings:
            score += self.SEVERITY_WEIGHTS.get(finding.severity, 0.0)
        # Normalize to 100 max scale
        return min(100.0, score)

    def evaluate_gate(self, report: ConsolidatedReport) -> Tuple[bool, List[str]]:
        reasons = []
        passed = True
        
        thresholds = self.policy.get("thresholds", {})
        fail_on = thresholds.get("fail_on", {})
        
        sev_counts = report.severity_counts
        
        # Check Critical Threshold
        max_crit = fail_on.get("critical", 0)
        if sev_counts.get("CRITICAL", 0) > max_crit:
            passed = False
            reasons.append(f"CRITICAL findings limit exceeded: {sev_counts.get('CRITICAL', 0)} found (max allowed: {max_crit})")

        # Check High Threshold
        max_high = fail_on.get("high", 0)
        if sev_counts.get("HIGH", 0) > max_high:
            passed = False
            reasons.append(f"HIGH findings limit exceeded: {sev_counts.get('HIGH', 0)} found (max allowed: {max_high})")

        # Check Medium Threshold
        max_med = fail_on.get("medium", 5)
        if sev_counts.get("MEDIUM", 0) > max_med:
            passed = False
            reasons.append(f"MEDIUM findings limit exceeded: {sev_counts.get('MEDIUM', 0)} found (max allowed: {max_med})")

        # Check Secrets Leakage Gate
        if thresholds.get("fail_on_secrets", True):
            secret_findings = [f for f in report.findings if f.category == Category.SECRETS]
            if len(secret_findings) > 0:
                passed = False
                reasons.append(f"Secret scanning detected {len(secret_findings)} exposed secrets/credentials")

        # Check Overall Risk Score Gate
        risk_score = self.calculate_risk_score(report)
        report.risk_score = risk_score
        max_score = float(thresholds.get("max_acceptable_risk_score", 25.0))
        if risk_score > max_score:
            passed = False
            reasons.append(f"Risk score {risk_score:.1f} exceeds policy threshold {max_score:.1f}")

        report.gate_passed = passed
        report.gate_reasons = reasons
        return passed, reasons
