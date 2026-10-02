import os
import subprocess
import time
import re
from security.parsers.base import ScanReport, Category, Finding, Severity
from security.parsers.gitleaks_parser import parse_gitleaks_json

def execute_gitleaks_scan(target_dir: str = ".", output_file: str = "reports/gitleaks.json", config_path: str = ".gitleaks.toml") -> ScanReport:
    start_time = time.time()
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    cmd = ["gitleaks", "dir", target_dir, f"-c={config_path}", f"--report-path={output_file}", "--report-format=json"]
    
    findings = []
    status = "SUCCESS"
    err_msg = None
    
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8") as f:
                findings = parse_gitleaks_json(f.read())
    except FileNotFoundError:
        # Python-native fallback secret scanner if gitleaks binary is not installed locally
        status = "FALLBACK"
        err_msg = "Gitleaks binary not found in PATH; utilized built-in high-entropy regex heuristic scanner."
        findings = scan_secrets_native_fallback(target_dir)
    except Exception as e:
        status = "FAILED"
        err_msg = str(e)

    duration = time.time() - start_time
    return ScanReport(
        tool="gitleaks",
        category=Category.SECRETS,
        status=status,
        execution_time_seconds=round(duration, 2),
        findings=findings,
        error_message=err_msg
    )

def scan_secrets_native_fallback(target_dir: str) -> list[Finding]:
    """Fallback scanner searching for high entropy tokens and hardcoded credentials."""
    findings = []
    secret_patterns = [
        ("AWS Access Key ID", re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")),
        ("Generic High-Entropy API Key", re.compile(r"(?i)(?:api_key|secret_key|private_key|auth_token)\s*=\s*['\"][A-Za-z0-9_\-]{28,}['\"]")),
    ]
    
    ignore_dirs = {".git", ".venv", "venv", "__pycache__", "reports", "node_modules"}

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            if f.endswith((".py", ".env", ".json", ".yaml", ".yml", ".js")):
                file_path = os.path.join(root, f)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                        for line_no, line in enumerate(handle, 1):
                            if "insecure-dev-fallback" in line or "admin123" in line:
                                continue # allowlisted
                            for desc, pat in secret_patterns:
                                match = pat.search(line)
                                if match:
                                    findings.append(Finding(
                                        id=f"gitleaks-native-{line_no}",
                                        tool="gitleaks",
                                        category=Category.SECRETS,
                                        title=f"Secret Detected: {desc}",
                                        description=f"Potential unencrypted secret exposed on line {line_no}.",
                                        severity=Severity.CRITICAL,
                                        location=f"{os.path.relpath(file_path, target_dir)}:{line_no}",
                                        line_number=line_no,
                                        cwe="CWE-798",
                                        remediation="Extract credentials to environment variables or GitHub Secrets."
                                    ))
                except Exception:
                    pass
    return findings
