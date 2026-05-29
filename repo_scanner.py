"""JSON and HTML compliance report generator."""
import json, os
from datetime import datetime, timezone
from jinja2 import Template
from comply.frameworks.mappings import get_framework_summary

_TPL = Template(r"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Comply.dev Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#0e1117;color:#e6e6e6;padding:2rem}
h1{color:#58a6ff;margin-bottom:.5rem}
.meta{color:#8b949e;margin-bottom:2rem}
.row{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.2rem;flex:1;min-width:150px;text-align:center}
.card .val{font-size:2rem;font-weight:700}
.card .lbl{color:#8b949e;font-size:.85rem}
.finding{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:.8rem}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;margin-right:4px}
.badge-FAIL{background:#f8514933;color:#f85149}.badge-PASS{background:#3fb95033;color:#3fb950}
.badge-WARNING{background:#d2992233;color:#d29922}
.badge-CRITICAL{background:#f8514933;color:#f85149}.badge-HIGH{background:#db6d2833;color:#db6d28}
.badge-MEDIUM{background:#d2992233;color:#d29922}.badge-LOW{background:#3fb95033;color:#3fb950}
.badge-INFO{background:#58a6ff33;color:#58a6ff}
.reason{background:#1c2129;border-left:3px solid #58a6ff;padding:.8rem;margin-top:.5rem;font-size:.85rem;line-height:1.6}
</style></head><body>
<h1>&#x1f6e1; Comply.dev Report</h1>
<p class="meta">{{ scan_time }}</p>
<div class="row">
<div class="card"><div class="val" style="color:#3fb950">{{ summary.passed }}</div><div class="lbl">Passed</div></div>
<div class="card"><div class="val" style="color:#f85149">{{ summary.failed }}</div><div class="lbl">Failed</div></div>
<div class="card"><div class="val" style="color:#d29922">{{ summary.warnings }}</div><div class="lbl">Warnings</div></div>
<div class="card"><div class="val" style="color:#58a6ff">{{ summary.pass_rate }}%</div><div class="lbl">Pass Rate</div></div>
</div>
<div class="row">
{% for k,fw in framework_summary.items() %}
<div class="card"><div class="val" style="color:{% if fw.compliance_score>=80 %}#3fb950{% elif fw.compliance_score>=50 %}#d29922{% else %}#f85149{% endif %}">{{ fw.compliance_score }}%</div><div class="lbl">{{ fw.name }}</div></div>
{% endfor %}
</div>
{% for f in findings %}
<div class="finding">
<span class="badge badge-{{ f.status }}">{{ f.status }}</span>
<span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
<strong>{{ f.check_id }}</strong> — {{ f.title }}<br>
<small style="color:#8b949e">{{ f.resource }} | {{ f.control_domain }}</small>
<p style="margin:.5rem 0">{{ f.description }}</p>
{% if f.status != 'PASS' %}<p><b>Remediation:</b> {{ f.remediation }}</p>{% endif %}
{% if f.reasoning %}<div class="reason">{{ f.reasoning }}</div>{% endif %}
</div>
{% endfor %}
<p style="text-align:center;color:#484f58;margin-top:2rem;font-size:.8rem">Comply.dev</p>
</body></html>""")

class ReportGenerator:
    """Generates JSON and HTML compliance reports."""
    def __init__(self, findings: list, output_dir: str = "reports"):
        self.findings = findings
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def _build(self):
        t = len(self.findings)
        p = sum(1 for f in self.findings if f.get("status") == "PASS")
        fl = sum(1 for f in self.findings if f.get("status") == "FAIL")
        w = sum(1 for f in self.findings if f.get("status") == "WARNING")
        pr = round((p / t) * 100, 1) if t > 0 else 0
        sc = {}
        for f in self.findings:
            s = f.get("severity", "UNKNOWN"); sc[s] = sc.get(s, 0) + 1
        return {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "summary": {"total": t, "passed": p, "failed": fl, "warnings": w, "pass_rate": pr, "severity_counts": sc},
            "framework_summary": get_framework_summary(self.findings),
            "findings": self.findings,
        }

    def generate_json(self) -> str:
        data = self._build()
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.output_dir, f"comply_report_{ts}.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def generate_html(self) -> str:
        data = self._build()
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.output_dir, f"comply_report_{ts}.html")
        with open(path, "w") as f:
            f.write(_TPL.render(**data))
        return path
