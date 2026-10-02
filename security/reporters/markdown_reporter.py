from security.parsers.base import ConsolidatedReport, Severity

def generate_markdown_summary(report: ConsolidatedReport) -> str:
    sev_counts = report.severity_counts
    gate_badge = "🟢 **PASSED**" if report.gate_passed else "🔴 **FAILED**"
    
    md = [
        f"## 🛡️ DevSecOps Security Gatekeeper Summary",
        f"",
        f"**Gate Status:** {gate_badge} | **Risk Score:** `{report.risk_score:.1f}/100` | **Scanned At:** `{report.timestamp}`",
        f"",
        f"### 📊 Vulnerability Breakdown",
        f"| Severity | Findings Count | Policy SLA |",
        f"| :--- | :---: | :--- |",
        f"| 🚨 **CRITICAL** | `{sev_counts.get('CRITICAL', 0)}` | **1 Day** |",
        f"| 🔴 **HIGH** | `{sev_counts.get('HIGH', 0)}` | **7 Days** |",
        f"| 🟡 **MEDIUM** | `{sev_counts.get('MEDIUM', 0)}` | **30 Days** |",
        f"| 🔵 **LOW / INFO** | `{sev_counts.get('LOW', 0) + sev_counts.get('INFO', 0)}` | **90 Days** |",
        f"| 📋 **TOTAL** | `{len(report.findings)}` | - |",
        f"",
    ]

    if not report.gate_passed and report.gate_reasons:
        md.append("### ⚠️ Security Gate Violations")
        for r in report.gate_reasons:
            md.append(f"- ❌ {r}")
        md.append("")

    if report.findings:
        md.append("### 🔍 Top Findings & Remediation")
        md.append("| Severity | Tool | Vulnerability | Location | Remediation |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        
        # Display top 15 findings
        for f in report.findings[:15]:
            sev_icon = "🚨" if f.severity == Severity.CRITICAL else ("🔴" if f.severity == Severity.HIGH else ("🟡" if f.severity == Severity.MEDIUM else "🔵"))
            md.append(f"| {sev_icon} {f.severity.value} | `{f.tool}` | **{f.title}** | `{f.location}` | {f.remediation or 'N/A'} |")
        
        if len(report.findings) > 15:
            md.append(f"\n*...and {len(report.findings) - 15} more findings. Download the complete HTML security report artifact for details.*")
    else:
        md.append("🎉 **No vulnerabilities detected across SAST, DAST, SCA, and Secret Scanning!**")

    return "\n".join(md)
