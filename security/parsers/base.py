from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Category(str, Enum):
    SAST = "SAST"
    DAST = "DAST"
    SCA = "SCA"
    SECRETS = "SECRETS"
    CONTAINER = "CONTAINER"
    IAC = "IAC"

@dataclass
class Finding:
    id: str
    tool: str                          # semgrep, gitleaks, trivy, owasp-zap
    category: Category                 # SAST, DAST, SCA, SECRETS, etc.
    title: str
    description: str
    severity: Severity
    location: str                      # file path:line or URL endpoint
    line_number: Optional[int] = None
    cwe: Optional[str] = None          # e.g., "CWE-89"
    cve: Optional[str] = None          # e.g., "CVE-2023-1234"
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    fingerprint: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        return d

@dataclass
class ScanReport:
    tool: str
    category: Category
    status: str                        # SUCCESS, FAILED, SKIPPED
    execution_time_seconds: float
    findings: List[Finding] = field(default_factory=list)
    error_message: Optional[str] = None

@dataclass
class ConsolidatedReport:
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reports: List[ScanReport] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    gate_passed: bool = True
    gate_reasons: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    
    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def category_counts(self) -> Dict[str, int]:
        counts = {c.value: 0 for c in Category}
        for f in self.findings:
            counts[f.category.value] += 1
        return counts
