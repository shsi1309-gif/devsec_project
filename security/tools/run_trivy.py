import os
import sys
import shutil
import subprocess
import time
from security.parsers.base import ScanReport, Category, Finding, Severity
from security.parsers.trivy_parser import parse_trivy_json

def get_trivy_binary() -> str:
    bin_path = shutil.which("trivy")
    return bin_path if bin_path else "trivy"

def get_pip_audit_binary() -> str:
    bin_path = shutil.which("pip-audit")
    if bin_path:
        return bin_path
    venv_bin = os.path.join(os.path.dirname(sys.executable), "pip-audit")
    if os.path.exists(venv_bin):
        return venv_bin
    return "pip-audit"

def execute_trivy_scan(target_dir: str = ".", output_file: str = "reports/trivy.json") -> ScanReport:
    start_time = time.time()
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    trivy_bin = get_trivy_binary()
    cmd = [trivy_bin, "fs", "--format", "json", "--output", output_file, target_dir]
    
    findings = []
    status = "SUCCESS"
    err_msg = None
    
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8") as f:
                findings = parse_trivy_json(f.read(), Category.SCA)
    except FileNotFoundError:
        status = "FALLBACK"
        err_msg = "Trivy binary not found in PATH; falling back to Python pip-audit."
        findings = run_pip_audit_fallback(target_dir)
    except Exception as e:
        status = "FAILED"
        err_msg = str(e)

    duration = time.time() - start_time
    return ScanReport(
        tool="trivy",
        category=Category.SCA,
        status=status,
        execution_time_seconds=round(duration, 2),
        findings=findings,
        error_message=err_msg
    )

def run_pip_audit_fallback(target_dir: str) -> list[Finding]:
    findings = []
    req_file = os.path.join(target_dir, "requirements.txt")
    if not os.path.exists(req_file):
        return findings
        
    try:
        import json
        pip_audit_bin = get_pip_audit_binary()
        cmd = [pip_audit_bin, "-r", req_file, "--format", "json"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if res.stdout:
            data = json.loads(res.stdout)
            deps = data.get("dependencies", [])
            for dep in deps:
                vulns = dep.get("vulns", [])
                pkg_name = dep.get("name", "")
                version = dep.get("version", "")
                for v in vulns:
                    cve_id = v.get("id", "CVE-Unknown")
                    desc = v.get("description", "Vulnerability detected in Python package.")
                    fix_vers = v.get("fix_versions", [])
                    fix_str = ", ".join(fix_vers) if fix_vers else "N/A"
                    findings.append(Finding(
                        id=f"sca-audit-{cve_id}",
                        tool="pip-audit",
                        category=Category.SCA,
                        title=f"SCA: {pkg_name} ({version}) - {cve_id}",
                        description=desc[:200] + "...",
                        severity=Severity.HIGH,
                        location=f"requirements.txt ({pkg_name}=={version})",
                        cve=cve_id,
                        cwe="CWE-937",
                        remediation=f"Upgrade {pkg_name} to version {fix_str} or latest release."
                    ))
    except Exception:
        pass
    return findings
