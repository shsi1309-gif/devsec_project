import os
import sys
import argparse
import time
from typing import List
from security.parsers.base import ConsolidatedReport, Finding, ScanReport, Category
from security.parsers.gitleaks_parser import parse_gitleaks_json
from security.parsers.semgrep_parser import parse_semgrep_json
from security.parsers.trivy_parser import parse_trivy_json
from security.parsers.zap_parser import parse_zap_json
from security.policy_engine import SecurityPolicyEngine
from security.reporters.html_reporter import generate_html_dashboard
from security.reporters.markdown_reporter import generate_markdown_summary
from security.reporters.sarif_reporter import generate_consolidated_sarif
from security.tools.run_gitleaks import execute_gitleaks_scan
from security.tools.run_semgrep import execute_semgrep_scan
from security.tools.run_trivy import execute_trivy_scan
from security.tools.run_zap import execute_zap_scan

class SecurityOrchestrator:
    def __init__(self, policy_path: str = "security_policy.yml", reports_dir: str = "reports"):
        self.policy_engine = SecurityPolicyEngine(policy_path)
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def run_live_scans(self, scan_secrets: bool = True, scan_sast: bool = True, scan_sca: bool = True, scan_dast: bool = False, target_dir: str = ".") -> ConsolidatedReport:
        consolidated = ConsolidatedReport()
        
        print("\n=======================================================")
        print("🚀  DevSecOps Security Pipeline Orchestrator Starting ")
        print("=======================================================\n")

        # 1. Secret Scanning (Gitleaks)
        if scan_secrets:
            print("[1/4] 🔑 Running Secret Scanning (Gitleaks)...")
            rep = execute_gitleaks_scan(target_dir=target_dir, output_file=os.path.join(self.reports_dir, "gitleaks.json"))
            consolidated.reports.append(rep)
            consolidated.findings.extend(rep.findings)
            print(f"      Status: {rep.status} | Findings: {len(rep.findings)} | Time: {rep.execution_time_seconds}s")

        # 2. Static Analysis (Semgrep SAST)
        if scan_sast:
            print("[2/4] 🔍 Running Static Application Security Testing (Semgrep SAST)...")
            rep = execute_semgrep_scan(target_dir=target_dir, output_file=os.path.join(self.reports_dir, "semgrep.json"))
            consolidated.reports.append(rep)
            consolidated.findings.extend(rep.findings)
            print(f"      Status: {rep.status} | Findings: {len(rep.findings)} | Time: {rep.execution_time_seconds}s")

        # 3. Dependency Analysis (Trivy SCA)
        if scan_sca:
            print("[3/4] 📦 Running Software Composition Analysis (Trivy SCA)...")
            rep = execute_trivy_scan(target_dir=target_dir, output_file=os.path.join(self.reports_dir, "trivy.json"))
            consolidated.reports.append(rep)
            consolidated.findings.extend(rep.findings)
            print(f"      Status: {rep.status} | Findings: {len(rep.findings)} | Time: {rep.execution_time_seconds}s")

        # 4. Dynamic Analysis (OWASP ZAP DAST)
        if scan_dast:
            print("[4/4] 🌐 Running Dynamic Analysis (OWASP ZAP DAST)...")
            rep = execute_zap_scan(output_file=os.path.join(self.reports_dir, "zap-report.json"))
            consolidated.reports.append(rep)
            consolidated.findings.extend(rep.findings)
            print(f"      Status: {rep.status} | Findings: {len(rep.findings)} | Time: {rep.execution_time_seconds}s")

        # Ingest pre-existing report files if present
        self.ingest_existing_reports(consolidated)

        # Evaluate Security Policy Gate
        self.policy_engine.evaluate_gate(consolidated)
        self.export_reports(consolidated)
        self.print_summary_terminal(consolidated)

        return consolidated

    def ingest_existing_reports(self, consolidated: ConsolidatedReport):
        """Pulls in any report files present in the reports/ directory that weren't captured."""
        existing_tools = {r.tool for r in consolidated.reports}

        # Check for ZAP JSON report
        zap_file = os.path.join(self.reports_dir, "zap-report.json")
        if "owasp-zap" not in existing_tools and os.path.exists(zap_file):
            with open(zap_file, "r", encoding="utf-8") as f:
                findings = parse_zap_json(f.read())
                consolidated.findings.extend(findings)
                consolidated.reports.append(ScanReport(tool="owasp-zap", category=Category.DAST, status="INGESTED", execution_time_seconds=0.0, findings=findings))

        # Check for Trivy Image report
        trivy_img_file = os.path.join(self.reports_dir, "trivy-image.json")
        if os.path.exists(trivy_img_file):
            with open(trivy_img_file, "r", encoding="utf-8") as f:
                findings = parse_trivy_json(f.read(), Category.CONTAINER)
                consolidated.findings.extend(findings)

    def export_reports(self, report: ConsolidatedReport):
        # 1. HTML Dashboard
        html_out = os.path.join(self.reports_dir, "security-dashboard.html")
        with open(html_out, "w", encoding="utf-8") as f:
            f.write(generate_html_dashboard(report))

        # 2. Markdown Summary
        md_out = os.path.join(self.reports_dir, "security-summary.md")
        with open(md_out, "w", encoding="utf-8") as f:
            f.write(generate_markdown_summary(report))

        # 3. Consolidated SARIF
        sarif_out = os.path.join(self.reports_dir, "consolidated.sarif")
        with open(sarif_out, "w", encoding="utf-8") as f:
            f.write(generate_consolidated_sarif(report))

        # Also write to GitHub Step Summary if running in GitHub Actions
        gh_step_summary = os.getenv("GITHUB_STEP_SUMMARY")
        if gh_step_summary:
            try:
                with open(gh_step_summary, "a", encoding="utf-8") as f:
                    f.write(generate_markdown_summary(report))
            except Exception as e:
                print(f"[WARN] Failed writing to GITHUB_STEP_SUMMARY: {e}")

    def print_summary_terminal(self, report: ConsolidatedReport):
        sev_counts = report.severity_counts
        status_symbol = "🟢 PASSED" if report.gate_passed else "🔴 FAILED"

        print("\n" + "=" * 60)
        print("          🛡️  DEVSECOPS SECURITY GATEKEEPER REPORT         ")
        print("=" * 60)
        print(f"Overall Gate Status : {status_symbol}")
        print(f"Composite Risk Score: {report.risk_score:.1f} / 100.0")
        print(f"Total Findings      : {len(report.findings)}")
        print("-" * 60)
        print(f"  CRITICAL : {sev_counts.get('CRITICAL', 0):<4} (SLA: 1 Day)")
        print(f"  HIGH     : {sev_counts.get('HIGH', 0):<4} (SLA: 7 Days)")
        print(f"  MEDIUM   : {sev_counts.get('MEDIUM', 0):<4} (SLA: 30 Days)")
        print(f"  LOW/INFO : {sev_counts.get('LOW', 0) + sev_counts.get('INFO', 0):<4} (SLA: 90 Days)")
        print("-" * 60)

        if not report.gate_passed:
            print("\n⚠️  GATE FAILURE REASONS:")
            for reason in report.gate_reasons:
                print(f"  - ❌ {reason}")

        print(f"\n📁 Artifacts generated:")
        print(f"  - HTML Dashboard : {os.path.join(self.reports_dir, 'security-dashboard.html')}")
        print(f"  - Markdown Report: {os.path.join(self.reports_dir, 'security-summary.md')}")
        print(f"  - SARIF Export   : {os.path.join(self.reports_dir, 'consolidated.sarif')}")
        print("=" * 60 + "\n")
