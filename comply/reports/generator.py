"""Report generator — JSON and HTML compliance reports."""

import json
import os
from datetime import datetime, timezone
from jinja2 import Template

from comply.frameworks.mappings import get_framework_summary


class ReportGenerator:
    """Generates compliance scan reports in JSON and HTML formats."""

    def __init__(self, findings: list, output_dir: str = "reports"):
        self.findings = findings
        self.output_dir = output_dir
        self.timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.scan_time = datetime.now(timezone.utc).isoformat()
        os.makedirs(output_dir, exist_ok=True)

    def get_summary(self) -> dict:
        """Generate overall scan summary statistics."""
        total = len(self.findings)
        by_status = {}
        by_severity = {}

        for f in self.findings:
            status = f.get("status", "UNKNOWN")
            severity = f.get("severity", "UNKNOWN")
            by_status[status] = by_status.get(status, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1

        return {
            "scan_timestamp": self.scan_time,
            "total_findings": total,
            "by_status": by_status,
            "by_severity": by_severity,
            "framework_compliance": get_framework_summary(self.findings),
        }

    def generate_json(self) -> str:
        """Generate JSON report and return file path.

        FIX: report now includes top-level scan_time so the dashboard
        can read it directly from report["scan_time"].
        """
        summary = self.get_summary()
        report = {
            "scan_time": self.scan_time,   # top-level for dashboard compatibility
            "summary": summary,
            "findings": self.findings,
        }

        filepath = os.path.join(self.output_dir, f"comply_report_{self.timestamp}.json")
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=str)

        return filepath

    def generate_html(self) -> str:
        """Generate a styled HTML compliance report."""
        summary = self.get_summary()

        html_template = Template(REPORT_HTML_TEMPLATE)
        html_content = html_template.render(
            summary=summary,
            findings=self.findings,
            timestamp=datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC"),
        )

        filepath = os.path.join(self.output_dir, f"comply_report_{self.timestamp}.html")
        with open(filepath, "w") as f:
            f.write(html_content)

        return filepath


# ── HTML Report Template ──────────────────────────────────────
REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comply.dev — Compliance Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { font-size: 2rem; color: #38bdf8; margin-bottom: 0.5rem; }
        .subtitle { color: #94a3b8; margin-bottom: 2rem; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: #1e293b; border-radius: 12px; padding: 1.5rem; text-align: center; }
        .card .number { font-size: 2.5rem; font-weight: bold; }
        .card .label { color: #94a3b8; font-size: 0.9rem; }
        .critical { color: #ef4444; } .high { color: #f97316; }
        .medium { color: #eab308; } .low { color: #22c55e; }
        .pass { color: #22c55e; } .fail { color: #ef4444; }
        .framework-section { background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; }
        .framework-bar { background: #334155; border-radius: 8px; height: 24px; margin: 0.5rem 0; overflow: hidden; }
        .framework-fill { height: 100%; border-radius: 8px; display: flex;
                         align-items: center; padding-left: 8px; font-size: 0.8rem; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th { background: #334155; color: #38bdf8; padding: 12px; text-align: left; }
        td { padding: 12px; border-bottom: 1px solid #334155; }
        tr:hover { background: #1e293b; }
        .badge { padding: 4px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; }
        .badge-critical { background: #450a0a; color: #ef4444; }
        .badge-high { background: #431407; color: #f97316; }
        .badge-medium { background: #422006; color: #eab308; }
        .badge-low { background: #052e16; color: #22c55e; }
        .badge-pass { background: #052e16; color: #22c55e; }
        .badge-fail { background: #450a0a; color: #ef4444; }
        .badge-warning { background: #422006; color: #eab308; }
        .badge-info { background: #1e293b; color: #94a3b8; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Comply.dev — Compliance Report</h1>
        <p class="subtitle">Generated {{ timestamp }}</p>

        <div class="cards">
            <div class="card">
                <div class="number">{{ summary.total_findings }}</div>
                <div class="label">Total Checks</div>
            </div>
            <div class="card">
                <div class="number pass">{{ summary.by_status.get('PASS', 0) }}</div>
                <div class="label">Passed</div>
            </div>
            <div class="card">
                <div class="number fail">{{ summary.by_status.get('FAIL', 0) }}</div>
                <div class="label">Failed</div>
            </div>
            <div class="card">
                <div class="number medium">{{ summary.by_status.get('WARNING', 0) }}</div>
                <div class="label">Warnings</div>
            </div>
        </div>

        <div class="framework-section">
            <h2 style="color: #38bdf8; margin-bottom: 1rem;">📊 Framework Compliance</h2>
            {% for key, fw in summary.framework_compliance.items() %}
            <div style="margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between;">
                    <strong>{{ fw.name }}</strong>
                    <span>{{ fw.compliance_score }}%</span>
                </div>
                <div class="framework-bar">
                    <div class="framework-fill" style="width: {{ fw.compliance_score }}%;
                        background: {% if fw.compliance_score >= 80 %}#22c55e{% elif fw.compliance_score >= 50 %}#eab308{% else %}#ef4444{% endif %};">
                        {{ fw.controls_passed }}/{{ fw.controls_tested }} controls
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>

        <h2 style="color: #38bdf8; margin-bottom: 1rem;">🔍 Detailed Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Check ID</th><th>Title</th><th>Resource</th>
                    <th>Status</th><th>Severity</th><th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {% for f in findings %}
                <tr>
                    <td><code>{{ f.check_id }}</code></td>
                    <td>{{ f.title }}</td>
                    <td><code>{{ f.resource }}</code></td>
                    <td><span class="badge badge-{{ f.status|lower }}">{{ f.status }}</span></td>
                    <td><span class="badge badge-{{ f.severity|lower }}">{{ f.severity }}</span></td>
                    <td>{{ f.remediation }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>"""
