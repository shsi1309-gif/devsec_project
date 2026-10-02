import json
import html
from typing import Dict, Any
from security.parsers.base import ConsolidatedReport, Severity

def generate_html_dashboard(report: ConsolidatedReport) -> str:
    sev_counts = report.severity_counts
    cat_counts = report.category_counts
    total_findings = len(report.findings)
    status_class = "gate-pass" if report.gate_passed else "gate-fail"
    status_text = "PASSED" if report.gate_passed else "FAILED"
    status_icon = "🛡️ PASSED" if report.gate_passed else "⚠️ FAILED"

    findings_rows = []
    for f in report.findings:
        sev_class = f"sev-{f.severity.value.lower()}"
        cat_class = f"cat-{f.category.value.lower()}"
        cwe_badge = f"<span class='badge badge-cwe'>{html.escape(f.cwe)}</span>" if f.cwe else ""
        cve_badge = f"<span class='badge badge-cve'>{html.escape(f.cve)}</span>" if f.cve else ""
        
        row = f"""
        <tr class="finding-row" data-severity="{f.severity.value}" data-category="{f.category.value}" data-tool="{f.tool}">
            <td><span class="badge {sev_class}">{f.severity.value}</span></td>
            <td><span class="badge {cat_class}">{f.category.value}</span></td>
            <td><strong>{html.escape(f.tool)}</strong></td>
            <td>
                <div class="finding-title">{html.escape(f.title)}</div>
                <div class="finding-desc">{html.escape(f.description)}</div>
                <div class="finding-meta">{cwe_badge} {cve_badge}</div>
            </td>
            <td><code class="loc-code">{html.escape(f.location)}</code></td>
            <td><div class="remediation-box">{html.escape(f.remediation or 'N/A')}</div></td>
        </tr>
        """
        findings_rows.append(row)

    findings_table_content = "\n".join(findings_rows) if findings_rows else "<tr><td colspan='6' class='no-findings'>🎉 Clean scan! No security vulnerabilities detected.</td></tr>"

    reasons_list = ""
    if report.gate_reasons:
        reasons_list = "<div class='gate-reasons'><h4>Security Gate Failure Reasons:</h4><ul>" + "".join([f"<li>{html.escape(r)}</li>" for r in report.gate_reasons]) + "</ul></div>"

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevSecOps Security Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-hover: #1f293d;
            --border: rgba(255, 255, 255, 0.08);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --crit: #ef4444;
            --high: #f97316;
            --med: #eab308;
            --low: #3b82f6;
            --info: #64748b;
            --pass: #10b981;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: var(--bg);
            color: var(--text-main);
            padding: 32px 20px;
            min-height: 100vh;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px 32px;
            margin-bottom: 24px;
        }}
        .header-title h1 {{ font-size: 1.6rem; font-weight: 800; }}
        .header-title p {{ color: var(--text-muted); font-size: 0.88rem; margin-top: 4px; }}
        .gate-badge {{
            padding: 10px 24px;
            border-radius: 9999px;
            font-weight: 800;
            font-size: 1.1rem;
            letter-spacing: 0.04em;
        }}
        .gate-pass {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1.5px solid #10b981; }}
        .gate-fail {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1.5px solid #ef4444; }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 18px;
            text-align: center;
        }}
        .stat-value {{ font-size: 2rem; font-weight: 800; margin-top: 4px; }}
        .stat-label {{ font-size: 0.82rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted); }}

        .val-crit {{ color: var(--crit); }}
        .val-high {{ color: var(--high); }}
        .val-med {{ color: var(--med); }}
        .val-low {{ color: var(--low); }}
        .val-total {{ color: #38bdf8; }}
        .val-risk {{ color: #ec4899; }}

        .filter-bar {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 16px 24px;
            margin-bottom: 24px;
            display: flex;
            gap: 16px;
            align-items: center;
            flex-wrap: wrap;
        }}
        .filter-bar input, .filter-bar select {{
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid var(--border);
            color: #fff;
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 0.9rem;
            outline: none;
        }}
        .filter-bar input {{ flex: 1; min-width: 250px; }}

        .table-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
        }}
        th {{
            background: rgba(255, 255, 255, 0.02);
            text-align: left;
            padding: 14px 18px;
            color: var(--text-muted);
            font-weight: 700;
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 14px 18px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        tr:hover td {{ background: var(--surface-hover); }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .sev-critical {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .sev-high {{ background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.4); }}
        .sev-medium {{ background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.4); }}
        .sev-low {{ background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.4); }}
        .sev-info {{ background: rgba(100, 116, 139, 0.2); color: #cbd5e1; border: 1px solid rgba(100, 116, 139, 0.4); }}
        
        .cat-sast {{ background: rgba(168, 85, 247, 0.2); color: #d8b4fe; }}
        .cat-dast {{ background: rgba(6, 182, 212, 0.2); color: #67e8f9; }}
        .cat-sca {{ background: rgba(16, 185, 129, 0.2); color: #6ee7b7; }}
        .cat-secrets {{ background: rgba(244, 63, 94, 0.2); color: #fda4af; }}
        .cat-container {{ background: rgba(245, 158, 11, 0.2); color: #fcd34d; }}

        .badge-cwe, .badge-cve {{
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-muted);
            font-size: 0.72rem;
            margin-right: 4px;
        }}
        .finding-title {{ font-weight: 700; color: #fff; margin-bottom: 3px; font-size: 0.92rem; }}
        .finding-desc {{ color: var(--text-muted); font-size: 0.82rem; margin-bottom: 6px; line-height: 1.4; }}
        .loc-code {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            color: #38bdf8;
            background: rgba(0, 0, 0, 0.3);
            padding: 3px 6px;
            border-radius: 4px;
            word-break: break-all;
        }}
        .remediation-box {{
            background: rgba(16, 185, 129, 0.08);
            border-left: 3px solid #10b981;
            padding: 6px 10px;
            font-size: 0.8rem;
            color: #d1fae5;
            border-radius: 0 6px 6px 0;
            line-height: 1.35;
        }}
        .gate-reasons {{
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 24px;
        }}
        .gate-reasons h4 {{ color: #f87171; margin-bottom: 8px; }}
        .gate-reasons ul {{ margin-left: 20px; color: #fca5a5; font-size: 0.88rem; }}
        .no-findings {{ text-align: center; padding: 40px; color: #10b981; font-size: 1.1rem; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title">
                <h1>DevSecOps Unified Security Audit</h1>
                <p>Generated: {report.timestamp} | Target: Automated CI/CD Pipeline</p>
            </div>
            <div class="gate-badge {status_class}">{status_icon}</div>
        </div>

        {reasons_list}

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Critical</div>
                <div class="stat-value val-crit">{sev_counts.get("CRITICAL", 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High</div>
                <div class="stat-value val-high">{sev_counts.get("HIGH", 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Medium</div>
                <div class="stat-value val-med">{sev_counts.get("MEDIUM", 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Low / Info</div>
                <div class="stat-value val-low">{sev_counts.get("LOW", 0) + sev_counts.get("INFO", 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value val-total">{total_findings}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Risk Score</div>
                <div class="stat-value val-risk">{report.risk_score:.1f} / 100</div>
            </div>
        </div>

        <div class="filter-bar">
            <input type="text" id="searchInput" placeholder="Search findings by title, file, CWE, CVE, or keyword..." oninput="filterTable()">
            <select id="sevFilter" onchange="filterTable()">
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
            </select>
            <select id="catFilter" onchange="filterTable()">
                <option value="ALL">All Categories</option>
                <option value="SAST">SAST</option>
                <option value="DAST">DAST</option>
                <option value="SCA">SCA</option>
                <option value="SECRETS">Secrets</option>
                <option value="CONTAINER">Container</option>
            </select>
        </div>

        <div class="table-card">
            <table>
                <thead>
                    <tr>
                        <th style="width: 100px;">Severity</th>
                        <th style="width: 100px;">Category</th>
                        <th style="width: 110px;">Scanner</th>
                        <th>Finding & Vulnerability Details</th>
                        <th style="width: 240px;">Location</th>
                        <th style="width: 280px;">Remediation SLA & Guide</th>
                    </tr>
                </thead>
                <tbody id="findingsBody">
                    {findings_table_content}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function filterTable() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const sev = document.getElementById('sevFilter').value;
            const cat = document.getElementById('catFilter').value;
            const rows = document.querySelectorAll('.finding-row');

            rows.forEach(row => {{
                const rowSev = row.getAttribute('data-severity');
                const rowCat = row.getAttribute('data-category');
                const text = row.innerText.toLowerCase();

                const matchQuery = !query || text.includes(query);
                const matchSev = sev === 'ALL' || rowSev === sev;
                const matchCat = cat === 'ALL' || rowCat === cat;

                if (matchQuery && matchSev && matchCat) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"""
    return html_template
