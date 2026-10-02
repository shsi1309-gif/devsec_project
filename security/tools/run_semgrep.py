import os
import sys
import shutil
import subprocess
import time
from security.parsers.base import ScanReport, Category
from security.parsers.semgrep_parser import parse_semgrep_json

def get_semgrep_binary() -> str:
    # 1. Direct which lookup
    bin_path = shutil.which("semgrep")
    if bin_path:
        return bin_path
    
    # 2. Check virtualenv bin
    venv_bin = os.path.join(os.path.dirname(sys.executable), "semgrep")
    if os.path.exists(venv_bin):
        return venv_bin

    return "semgrep"

def execute_semgrep_scan(target_dir: str = ".", output_file: str = "reports/semgrep.json", custom_rules: str = ".semgrep/rules.yml") -> ScanReport:
    start_time = time.time()
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    semgrep_bin = get_semgrep_binary()
    cmd = [semgrep_bin, "scan", f"--config={custom_rules}", "--json", f"-o={output_file}", target_dir]
    
    findings = []
    status = "SUCCESS"
    err_msg = None
    
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8") as f:
                findings = parse_semgrep_json(f.read())
        elif res.stdout:
            findings = parse_semgrep_json(res.stdout)
    except FileNotFoundError:
        status = "FALLBACK"
        err_msg = "Semgrep binary not found in PATH. Install with `pip install semgrep`."
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8") as f:
                findings = parse_semgrep_json(f.read())
    except Exception as e:
        status = "FAILED"
        err_msg = str(e)

    duration = time.time() - start_time
    return ScanReport(
        tool="semgrep",
        category=Category.SAST,
        status=status,
        execution_time_seconds=round(duration, 2),
        findings=findings,
        error_message=err_msg
    )
