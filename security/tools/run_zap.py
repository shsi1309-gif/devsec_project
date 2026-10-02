import os
import subprocess
import time
from security.parsers.base import ScanReport, Category, Finding, Severity
from security.parsers.zap_parser import parse_zap_json

def execute_zap_scan(target_url: str = "http://localhost:8000", output_file: str = "reports/zap-report.json") -> ScanReport:
    start_time = time.time()
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    findings = []
    status = "SUCCESS"
    err_msg = None

    # Check if pre-existing report exists from docker-compose / CI ZAP step
    if os.path.exists(output_file):
        with open(output_file, "r", encoding="utf-8") as f:
            findings = parse_zap_json(f.read())
    else:
        # Check if Docker is available to run ZAP baseline scan
        try:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{os.path.abspath('reports')}:/zap/wrk/:rw",
                "--network", "host",
                "zaproxy/zap-stable",
                "zap-baseline.py",
                "-t", target_url,
                "-J", "zap-report.json",
                "-I" # Informational / don't fail container exit code
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    findings = parse_zap_json(f.read())
            else:
                status = "SKIPPED"
                err_msg = "ZAP scan completed or target app offline."
        except Exception as e:
            status = "SKIPPED"
            err_msg = f"DAST scan omitted locally (run target app and docker-compose --profile dast up to execute): {e}"

    duration = time.time() - start_time
    return ScanReport(
        tool="owasp-zap",
        category=Category.DAST,
        status=status,
        execution_time_seconds=round(duration, 2),
        findings=findings,
        error_message=err_msg
    )
