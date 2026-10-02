#!/usr/bin/env python3
"""
DevSecOps Security Pipeline CLI
Usage:
    python run_pipeline.py --all
    python run_pipeline.py --sast --sca --secrets
    python run_pipeline.py --gate-only
"""
import sys
import argparse
from security.orchestrator import SecurityOrchestrator

def main():
    parser = argparse.ArgumentParser(
        description="Enterprise DevSecOps Security Pipeline & Automated Gatekeeper",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--all", action="store_true", help="Run all security scanners (Secrets, SAST, SCA, DAST)")
    parser.add_argument("--secrets", action="store_true", help="Run Secret scanning (Gitleaks)")
    parser.add_argument("--sast", action="store_true", help="Run Static Application Security Testing (Semgrep)")
    parser.add_argument("--sca", action="store_true", help="Run Software Composition Analysis (Trivy / pip-audit)")
    parser.add_argument("--dast", action="store_true", help="Run Dynamic Application Security Testing (OWASP ZAP)")
    parser.add_argument("--gate-only", action="store_true", help="Only parse existing reports and evaluate the security gate")
    parser.add_argument("--policy", default="security_policy.yml", help="Path to security policy YAML file (default: security_policy.yml)")
    parser.add_argument("--reports-dir", default="reports", help="Directory to read/store scan reports (default: reports)")
    parser.add_argument("--fail-on-gate", action="store_true", help="Exit with non-zero code if security gate fails (for CI/CD pipelines)")

    args = parser.parse_args()

    orchestrator = SecurityOrchestrator(policy_path=args.policy, reports_dir=args.reports_dir)

    # Determine which scans to run
    if args.all:
        scan_secrets = True
        scan_sast = True
        scan_sca = True
        scan_dast = True
    elif args.gate_only:
        scan_secrets = False
        scan_sast = False
        scan_sca = False
        scan_dast = False
    else:
        # Default to running secrets, SAST, and SCA if no specific flag was given
        if not (args.secrets or args.sast or args.sca or args.dast):
            scan_secrets = True
            scan_sast = True
            scan_sca = True
            scan_dast = False
        else:
            scan_secrets = args.secrets
            scan_sast = args.sast
            scan_sca = args.sca
            scan_dast = args.dast

    report = orchestrator.run_live_scans(
        scan_secrets=scan_secrets,
        scan_sast=scan_sast,
        scan_sca=scan_sca,
        scan_dast=scan_dast
    )

    if args.fail_on_gate and not report.gate_passed:
        print("[PIPELINE ALERT] Security gate failed. Blocking build/deployment.")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
