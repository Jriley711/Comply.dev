import os
import json
import requests
from datetime import datetime

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


# ─────────────────────────────────────────────────────────────
# Secrets helper
# ─────────────────────────────────────────────────────────────

def get_secret(key: str, default: str = "") -> str:
    try:
        return st.secrets[key]
    except (KeyError, FileNotFoundError):
        return os.getenv(key, default)


AWS_ACCESS_KEY_ID     = get_secret("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = get_secret("AWS_SECRET_ACCESS_KEY")
AWS_DEFAULT_REGION    = get_secret("AWS_DEFAULT_REGION", "us-east-1")
GITHUB_TOKEN          = get_secret("GITHUB_TOKEN") or get_secret("GH_TOKEN")
GITHUB_REPOS          = get_secret("GITHUB_REPOS") or get_secret("GH_REPOS")
GITHUB_USERNAME       = get_secret("GITHUB_USERNAME") or get_secret("GH_USERNAME", "Jriley711")
GITHUB_REPO           = get_secret("GITHUB_REPO") or get_secret("GH_REPO", "Comply.dev")

REPORT_URL = (
    f"https://raw.githubusercontent.com/"
    f"{GITHUB_USERNAME}/{GITHUB_REPO}/reports-data/reports/latest.json"
)


# ─────────────────────────────────────────────────────────────
# Master check registry — every possible check in the scanner
# ─────────────────────────────────────────────────────────────

ALL_CHECKS = {
    # ── Security Groups ──────────────────────────────────────
    "SG-INV-001": {
        "title": "Security group inventory",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Enumerates all security groups in the account.",
        "expected": "PASS",
    },
    "SG-001-PASS": {
        "title": "No unrestricted inbound rules",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Security group has no inbound rules open to 0.0.0.0/0 or ::/0.",
        "expected": "PASS",
    },
    "SG-001-22": {
        "title": "SSH (port 22) open to internet",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Inbound SSH access is allowed from 0.0.0.0/0.",
        "expected": "FAIL",
    },
    "SG-001-3389": {
        "title": "RDP (port 3389) open to internet",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Inbound RDP access is allowed from 0.0.0.0/0.",
        "expected": "FAIL",
    },
    "SG-001-3306": {
        "title": "MySQL (port 3306) open to internet",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Inbound MySQL access is allowed from 0.0.0.0/0.",
        "expected": "FAIL",
    },
    "SG-001-5432": {
        "title": "PostgreSQL (port 5432) open to internet",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Inbound PostgreSQL access is allowed from 0.0.0.0/0.",
        "expected": "FAIL",
    },
    "SG-001-1433": {
        "title": "MSSQL (port 1433) open to internet",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Inbound MSSQL access is allowed from 0.0.0.0/0.",
        "expected": "FAIL",
    },
    "SG-001-27017": {
        "title": "MongoDB (port 27017) open to internet",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Inbound MongoDB access is allowed from 0.0.0.0/0.",
        "expected": "FAIL",
    },
    "SG-001-6379": {
        "title": "Redis (port 6379) open to internet",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Inbound Redis access is allowed from 0.0.0.0/0.",
        "expected": "FAIL",
    },
    "SG-002": {
        "title": "All ports open to internet",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Security group allows ALL inbound traffic (ports 0-65535) from 0.0.0.0/0.",
        "expected": "FAIL",
    },
    "SG-003": {
        "title": "Unrestricted egress to internet",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Security group allows all outbound traffic to 0.0.0.0/0.",
        "expected": "WARNING",
    },
    "SG-004": {
        "title": "Default security group has inbound rules",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "The default security group should have no rules per CIS AWS 4.3.",
        "expected": "FAIL",
    },
    "SG-004-PASS": {
        "title": "Default security group restricts all traffic",
        "domain": "Network Security",
        "category": "AWS · Security Groups",
        "description": "Default security group has no inbound rules configured.",
        "expected": "PASS",
    },

    # ── Encryption ───────────────────────────────────────────
    "ENC-S3-PASS": {
        "title": "S3 bucket encryption enabled",
        "domain": "Data Protection",
        "category": "AWS · Encryption",
        "description": "S3 bucket has server-side encryption enabled.",
        "expected": "PASS",
    },
    "ENC-S3-001": {
        "title": "S3 bucket missing encryption",
        "domain": "Data Protection",
        "category": "AWS · Encryption",
        "description": "S3 bucket has no default server-side encryption configured.",
        "expected": "FAIL",
    },
    "ENC-EBS-PASS": {
        "title": "EBS volume encrypted",
        "domain": "Data Protection",
        "category": "AWS · Encryption",
        "description": "EBS volume has encryption at rest enabled.",
        "expected": "PASS",
    },
    "ENC-EBS-001": {
        "title": "EBS volume not encrypted",
        "domain": "Data Protection",
        "category": "AWS · Encryption",
        "description": "EBS volume is not encrypted at rest.",
        "expected": "FAIL",
    },
    "ENC-RDS-PASS": {
        "title": "RDS instance encrypted",
        "domain": "Data Protection",
        "category": "AWS · Encryption",
        "description": "RDS instance has storage encryption enabled.",
        "expected": "PASS",
    },
    "ENC-RDS-001": {
        "title": "RDS instance not encrypted at rest",
        "domain": "Data Protection",
        "category": "AWS · Encryption",
        "description": "RDS instance does not have storage encryption enabled.",
        "expected": "FAIL",
    },

    # ── Backups ──────────────────────────────────────────────
    "BKP-RDS-PASS": {
        "title": "RDS backup retention adequate",
        "domain": "Backup & Availability",
        "category": "AWS · Backups",
        "description": "RDS instance has automated backups with sufficient retention.",
        "expected": "PASS",
    },
    "BKP-RDS-001": {
        "title": "RDS automated backups disabled",
        "domain": "Backup & Availability",
        "category": "AWS · Backups",
        "description": "RDS instance has automated backups completely disabled (retention = 0).",
        "expected": "FAIL",
    },
    "BKP-RDS-002": {
        "title": "RDS backup retention below minimum",
        "domain": "Backup & Availability",
        "category": "AWS · Backups",
        "description": "RDS backup retention is set but below the 7-day minimum.",
        "expected": "WARNING",
    },
    "BKP-RDS-PASS-AZ": {
        "title": "RDS Multi-AZ enabled",
        "domain": "Backup & Availability",
        "category": "AWS · Backups",
        "description": "RDS instance is deployed across multiple Availability Zones.",
        "expected": "PASS",
    },
    "BKP-RDS-003": {
        "title": "RDS instance not Multi-AZ",
        "domain": "Backup & Availability",
        "category": "AWS · Backups",
        "description": "RDS instance is single-AZ with no automatic failover.",
        "expected": "WARNING",
    },

    # ── IAM ──────────────────────────────────────────────────
    "IAM-001-PASS": {
        "title": "Root account MFA enabled",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "The AWS root account has MFA enabled.",
        "expected": "PASS",
    },
    "IAM-001": {
        "title": "Root account MFA not enabled",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "The AWS root account does not have MFA configured.",
        "expected": "FAIL",
    },
    "IAM-002-PASS": {
        "title": "Console user has MFA",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "IAM user with console access has MFA enabled.",
        "expected": "PASS",
    },
    "IAM-002": {
        "title": "Console user without MFA",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "IAM user has console access but no MFA device registered.",
        "expected": "FAIL",
    },
    "IAM-002-NA": {
        "title": "Programmatic-only user (no console access)",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "IAM user has no console login — MFA check not applicable.",
        "expected": "PASS",
    },
    "IAM-003-PASS": {
        "title": "Access key within rotation policy",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "Active access key is within the 90-day rotation window.",
        "expected": "PASS",
    },
    "IAM-003": {
        "title": "Access key not rotated",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "Active access key is older than 90 days.",
        "expected": "FAIL",
    },
    "IAM-004-PASS": {
        "title": "Password policy meets all requirements",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "Account password policy meets all CIS benchmark thresholds.",
        "expected": "PASS",
    },
    "IAM-004": {
        "title": "No password policy configured",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "No custom IAM password policy exists — AWS defaults apply.",
        "expected": "FAIL",
    },
    "IAM-004a": {
        "title": "Minimum password length too short",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "Password policy minimum length is below 14 characters.",
        "expected": "FAIL",
    },
    "IAM-004b": {
        "title": "Uppercase characters not required",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "Password policy does not require uppercase characters.",
        "expected": "FAIL",
    },
    "IAM-004c": {
        "title": "Lowercase characters not required",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "Password policy does not require lowercase characters.",
        "expected": "FAIL",
    },
    "IAM-004d": {
        "title": "Numbers not required in password",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "Password policy does not require numeric characters.",
        "expected": "FAIL",
    },
    "IAM-004e": {
        "title": "Symbols not required in password",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "Password policy does not require symbol characters.",
        "expected": "FAIL",
    },
    "IAM-004f": {
        "title": "Password max age too long",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "Password policy maximum age exceeds 90 days.",
        "expected": "FAIL",
    },
    "IAM-004g": {
        "title": "Password reuse prevention too low",
        "domain": "Identity & Access Management",
        "category": "AWS · IAM",
        "description": "Password policy allows reuse within the last 24 passwords.",
        "expected": "FAIL",
    },

    # ── GitHub ───────────────────────────────────────────────
    "GH-BP-PASS": {
        "title": "Branch protection properly configured",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": "Default branch has full protection: PR reviews, status checks, no force push.",
        "expected": "PASS",
    },
    "GH-BP-001": {
        "title": "No branch protection on default branch",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": "Default branch has no protection rules — direct push allowed.",
        "expected": "FAIL",
    },
    "GH-BP-002": {
        "title": "Branch protection incomplete",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": "Default branch has protection but is missing required controls.",
        "expected": "WARNING",
    },
    "GH-SEC-PASS": {
        "title": "Security policy present",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": "SECURITY.md file found — vulnerability reporting process documented.",
        "expected": "PASS",
    },
    "GH-SEC-001": {
        "title": "Missing security policy",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": "No SECURITY.md file — no documented vulnerability reporting process.",
        "expected": "FAIL",
    },
    "GH-GI-PASS": {
        "title": ".gitignore present",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": ".gitignore file found — reduces risk of accidental secret commits.",
        "expected": "PASS",
    },
    "GH-GI-001": {
        "title": "Missing .gitignore",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": "No .gitignore — sensitive files may be accidentally committed.",
        "expected": "WARNING",
    },
    "GH-ENV-PASS": {
        "title": "No sensitive environment files committed",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": "No .env files found in the repository.",
        "expected": "PASS",
    },
    "GH-ENV-001": {
        "title": "Sensitive file committed (.env)",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": "A .env file is committed — may contain exposed credentials.",
        "expected": "FAIL",
    },
    "GH-DEP-PASS": {
        "title": "Dependabot configured",
        "domain": "Vulnerability Management",
        "category": "GitHub · Repositories",
        "description": "Dependabot is configured for automated dependency vulnerability scanning.",
        "expected": "PASS",
    },
    "GH-DEP-001": {
        "title": "Dependabot not configured",
        "domain": "Vulnerability Management",
        "category": "GitHub · Repositories",
        "description": "No Dependabot config — dependency vulnerabilities not automatically tracked.",
        "expected": "WARNING",
    },
    "GH-LIC-PASS": {
        "title": "LICENSE file present",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": "LICENSE file found — usage terms are clearly defined.",
        "expected": "PASS",
    },
    "GH-LIC-001": {
        "title": "Missing LICENSE file",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": "No LICENSE file — usage terms are legally ambiguous.",
        "expected": "WARNING",
    },
    "GH-BR-001": {
        "title": "Default branch is 'master'",
        "domain": "Source Code Management",
        "category": "GitHub · Repositories",
        "description": "Default branch uses legacy 'master' name instead of 'main'.",
        "expected": "WARNING",
    },
}

CATEGORY_ORDER = [
    "AWS · Security Groups",
    "AWS · Encryption",
    "AWS · Backups",
    "AWS · IAM",
    "GitHub · Repositories",
]


# ─────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Comply.dev",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
[data-testid="stAppViewContainer"] {
    background: linear-gradient(135deg, #0f172a 0%, #1a1f35 100%);
}
[data-testid="stSidebar"] {
    background: #0f172a !important;
    border-right: 1px solid #1e293b;
}
[data-testid="metric-container"] {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 1rem 1.25rem;
}
[data-testid="metric-container"]:hover {
    border-color: #38bdf8;
    transition: border-color 0.2s;
}
.section-header {
    font-size: 0.8rem;
    font-weight: 600;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.75rem;
    margin-top: 0.25rem;
}
/* Check card styles */
.check-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 8px;
    display: flex;
    align-items: flex-start;
    gap: 12px;
}
.check-card:hover { border-color: #475569; }
.check-card.fail  { border-left: 4px solid #ef4444; }
.check-card.pass  { border-left: 4px solid #22c55e; }
.check-card.warning { border-left: 4px solid #eab308; }
.check-card.not-run { border-left: 4px solid #334155; opacity: 0.55; }
.check-icon { font-size: 1.3rem; min-width: 28px; margin-top: 1px; }
.check-body { flex: 1; min-width: 0; }
.check-title {
    font-weight: 600;
    color: #e2e8f0;
    font-size: 0.9rem;
    margin-bottom: 2px;
}
.check-id {
    font-family: monospace;
    font-size: 0.72rem;
    color: #64748b;
    margin-bottom: 4px;
}
.check-desc { font-size: 0.82rem; color: #94a3b8; margin-bottom: 0; }
.check-resource {
    font-size: 0.78rem;
    color: #7dd3fc;
    font-family: monospace;
    margin-top: 4px;
}
.check-remediation {
    font-size: 0.8rem;
    color: #fbbf24;
    margin-top: 6px;
    padding: 6px 10px;
    background: #1a1400;
    border-radius: 6px;
    border-left: 3px solid #eab308;
}
.check-reasoning {
    font-size: 0.78rem;
    color: #94a3b8;
    margin-top: 6px;
    padding: 6px 10px;
    background: #0f1929;
    border-radius: 6px;
    border-left: 3px solid #334155;
}
.category-header {
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 10px 14px;
    margin: 16px 0 10px 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.category-title {
    font-weight: 700;
    color: #e2e8f0;
    font-size: 0.95rem;
}
.category-stats {
    font-size: 0.8rem;
    color: #64748b;
    display: flex;
    gap: 12px;
}
.not-run-label {
    font-size: 0.75rem;
    color: #475569;
    font-style: italic;
}
.pill {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 999px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}
.pill-pass     { background: #052e16; color: #4ade80; }
.pill-fail     { background: #450a0a; color: #f87171; }
.pill-warning  { background: #422006; color: #fbbf24; }
.pill-not-run  { background: #1e293b; color: #475569; }
.pill-critical { background: #450a0a; color: #f87171; }
.pill-high     { background: #431407; color: #fb923c; }
.pill-medium   { background: #422006; color: #fbbf24; }
.pill-low      { background: #052e16; color: #4ade80; }
.pill-info     { background: #1e3a5f; color: #7dd3fc; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=3600)
def load_report_from_github() -> dict | None:
    try:
        resp = requests.get(REPORT_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if "scan_time" not in data and "summary" in data:
            data["scan_time"] = data["summary"].get("scan_timestamp", "Unknown")
        return data
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return None
        st.error(f"Failed to load report from GitHub: {e}")
        return None
    except Exception as e:
        st.error(f"Unexpected error loading report: {e}")
        return None


@st.cache_data(ttl=3600)
def load_report_from_upload(uploaded_bytes: bytes) -> dict | None:
    try:
        data = json.loads(uploaded_bytes)
        if "scan_time" not in data and "summary" in data:
            data["scan_time"] = data["summary"].get("scan_timestamp", "Unknown")
        return data
    except json.JSONDecodeError as e:
        st.error(f"Invalid JSON file: {e}")
        return None


def run_live_scan() -> dict | None:
    import boto3
    from comply.scanner import ComplyScanner

    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
        st.error("AWS credentials not configured.")
        return None

    try:
        session = boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_DEFAULT_REGION,
        )
        github_repos = [r.strip() for r in GITHUB_REPOS.split(",")] if GITHUB_REPOS else []
        scanner = ComplyScanner(
            aws_session=session,
            github_token=GITHUB_TOKEN or None,
            github_repos=github_repos,
        )
        return scanner.run_full_scan()
    except Exception as e:
        st.error(f"Scan failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

SEVERITY_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
    "INFO": "#64748b",
}

STATUS_COLORS = {
    "PASS": "#22c55e",
    "FAIL": "#ef4444",
    "WARNING": "#eab308",
    "ERROR": "#64748b"
}


PLOTLY_BASE = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#e2e8f0", family="Inter, system-ui, sans-serif"),
)


STATUS_ICON = {
    "PASS": "✅",
    "FAIL": "❌",
    "WARNING": "⚠️",
    "ERROR": "❗",
    "NOT RUN": "⬜"
}


def fmt_score_color(score):
    return "#22c55e" if score >= 80 else "#eab308" if score >= 50 else "#ef4444"

def fmt_datetime(iso_str):
    try:
        ts = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return ts.strftime("%B %d, %Y at %H:%M UTC")
    except Exception:
        return iso_str

def pill(label, kind):
    return f'<span class="pill pill-{kind.lower()}">{label}</span>'


# ─────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown(
        "<h2 style='color:#38bdf8;margin-bottom:0'>🛡️ Comply.dev</h2>"
        "<p style='color:#64748b;font-size:0.8rem;margin-top:2px'>Cloud Compliance Scanner</p>",
        unsafe_allow_html=True,
    )
    st.divider()

    page = st.radio(
        "**View**",
        ["📊 Dashboard", "🔍 Checks"],
        index=0,
    )

    st.divider()

    data_source = st.radio(
        "**Data source**",
        ["📡 Latest scan (GitHub)", "📂 Upload report", "⚡ Run live scan"],
        index=0,
    )

    uploaded_file = None
    if data_source == "📂 Upload report":
        uploaded_file = st.file_uploader("Upload JSON report", type=["json"])

    st.divider()
    st.markdown(
        f"<div style='color:#64748b;font-size:0.8rem'>"
        f"🌎 Region: <code style='color:#7dd3fc'>{AWS_DEFAULT_REGION}</code><br/>"
        + (f"📦 Repos: <code style='color:#7dd3fc'>{GITHUB_REPOS}</code>" if GITHUB_REPOS else "")
        + "</div>",
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────
# Load data
# ─────────────────────────────────────────────────────────────

report = None

if data_source == "📡 Latest scan (GitHub)":
    with st.spinner("Fetching latest scan from GitHub..."):
        report = load_report_from_github()
    if report is None:
        st.error("🚨 No scan report found from GitHub")
        st.write("Check if latest.json exists in reports-data branch")

elif data_source == "📂 Upload report":
    if uploaded_file:
        report = load_report_from_upload(uploaded_file.read())
    else:
        st.info("Upload a JSON report file from the sidebar.", icon="📂")

elif data_source == "⚡ Run live scan":
    if st.button("▶ Run scan now", type="primary", use_container_width=True):
        with st.spinner("Running compliance scan… this takes 30–60 seconds."):
            report = run_live_scan()
        if report:
            st.success("Scan complete!", icon="✅")
    else:
        st.info("Click **Run scan now** to trigger a live scan.", icon="⚡")


# ✅ DEBUG — ADD THIS
st.write("DEBUG: Report loaded?", report is not None)

if report:
    st.write("DEBUG: Findings count:", len(report.get("findings", [])))
    st.write("DEBUG: First record:", report.get("findings", [None])[0])


# ✅ SAFER STOP CONDITION
if report is None:
    st.stop()

# ─────────────────────────────────────────────────────────────
# Parse report
# ─────────────────────────────────────────────────────────────
try:
    findings   = report.get("findings", [])
    scan_time  = report.get("scan_time", "Unknown")
    summary    = report.get("summary", {})
    fw_summary = summary.get("framework_compliance", {})

    df = pd.DataFrame(findings) if findings else pd.DataFrame()

    total    = len(findings)
    passed   = int(df["status"].eq("PASS").sum()) if "status" in df.columns else 0
    failed   = int(df["status"].eq("FAIL").sum()) if "status" in df.columns else 0
    warnings = int(df["status"].eq("WARNING").sum()) if "status" in df.columns else 0
    critical = int((df["status"].eq("FAIL") & df["severity"].eq("CRITICAL")).sum()) \
               if {"status", "severity"}.issubset(df.columns) else 0
    score    = round(passed / total * 100) if total > 0 else 0

except Exception as e:
    st.error("🚨 App crashed")
    st.write(str(e))
    st.stop()

# Build lookup: check_id → list of findings (one check_id can fire multiple times
# e.g. ENC-S3-PASS once per bucket)
findings_by_id: dict[str, list] = {}
for f in findings:
    cid = f.get("check_id", "")
    findings_by_id.setdefault(cid, []).append(f)


# ═══════════════════════════════════════════════════════════════
# SHARED HEADER
# ═══════════════════════════════════════════════════════════════

col_title, col_score = st.columns([3, 1])
with col_title:
    st.markdown(
        "<h1 style='color:#f1f5f9;font-size:2rem;margin-bottom:0'>🛡️ Comply.dev</h1>",
        unsafe_allow_html=True,
    )
    if scan_time != "Unknown":
        st.markdown(
            f"<p style='color:#64748b;font-size:0.85rem;margin-top:4px'>"
            f"Last scan: {fmt_datetime(scan_time)}</p>",
            unsafe_allow_html=True,
        )
with col_score:
    sc = fmt_score_color(score)
    st.markdown(
        f"<div style='text-align:right;padding-top:8px'>"
        f"<span style='font-size:2.5rem;font-weight:800;color:{sc}'>{score}%</span>"
        f"<br/><span style='color:#64748b;font-size:0.8rem'>overall score</span></div>",
        unsafe_allow_html=True,
    )

st.divider()


# ═══════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ═══════════════════════════════════════════════════════════════

if page == "📊 Dashboard":

    # ── KPIs ─────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Checks", total)
    c2.metric("✅ Passed", passed)
    c3.metric("❌ Failed", failed)
    c4.metric("⚠️ Warnings", warnings)
    c5.metric("🔴 Critical", critical)

    st.divider()

    # ── Framework gauges ─────────────────────────────────────
    st.markdown("<p class='section-header'>Framework Compliance</p>", unsafe_allow_html=True)

    FW_DISPLAY = {"SOC2": "SOC 2", "ISO27001": "ISO 27001", "CIS_AWS": "CIS AWS"}
    fw_cols = st.columns(len(FW_DISPLAY))

    for i, (fw_key, fw_label) in enumerate(FW_DISPLAY.items()):
        fw_data   = fw_summary.get(fw_key, {})
        fw_score  = fw_data.get("compliance_score", 0)
        fw_passed = fw_data.get("controls_passed", 0)
        fw_total  = fw_data.get("controls_tested", 0)
        bar_color = fmt_score_color(fw_score)

        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=fw_score,
            number={"suffix": "%", "font": {"size": 28, "color": "#f1f5f9"}},
            title={"text": fw_label, "font": {"size": 14, "color": "#94a3b8"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#334155",
                         "tickfont": {"color": "#64748b", "size": 10}},
                "bar": {"color": bar_color, "thickness": 0.25},
                "bgcolor": "#1e293b",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 50],   "color": "#1a1f2e"},
                    {"range": [50, 80],  "color": "#1e2a1a"},
                    {"range": [80, 100], "color": "#1a2e1e"},
                ],
                "threshold": {
                    "line": {"color": "#22c55e", "width": 2},
                    "thickness": 0.75,
                    "value": 80,
                },
            },
        ))
        fig.update_layout(
            height=200,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            margin=dict(t=40, b=10, l=30, r=30),
        )
        with fw_cols[i]:
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            st.markdown(
                f"<div style='text-align:center;margin-top:-16px;color:#64748b;font-size:0.78rem'>"
                f"{fw_passed}/{fw_total} controls passing</div>",
                unsafe_allow_html=True,
            )

    st.divider()

    # ── Charts ───────────────────────────────────────────────
    chart_l, chart_r = st.columns(2)

    with chart_l:
        st.markdown("<p class='section-header'>Failed Findings by Severity</p>", unsafe_allow_html=True)
        if "severity" in df.columns and "status" in df.columns:
            fail_df = df[df["status"] == "FAIL"]
            if not fail_df.empty:
                sev_counts = (
                    fail_df["severity"].value_counts()
                    .reindex(SEVERITY_ORDER).dropna().reset_index()
                )
                sev_counts.columns = ["severity", "count"]
                fig_sev = go.Figure(go.Bar(
                    x=sev_counts["severity"],
                    y=sev_counts["count"],
                    marker_color=[SEVERITY_COLORS.get(s, "#64748b") for s in sev_counts["severity"]],
                    text=sev_counts["count"],
                    textposition="outside",
                    textfont=dict(color="#e2e8f0"),
                ))
                fig_sev.update_layout(
                    height=280, showlegend=False,
                    xaxis=dict(tickfont=dict(color="#94a3b8"), gridcolor="#1e293b"),
                    yaxis=dict(tickfont=dict(color="#94a3b8"), gridcolor="#334155", zeroline=False),
                    **PLOTLY_BASE, margin=dict(t=10, b=10, l=10, r=10),
                )
                st.plotly_chart(fig_sev, use_container_width=True, config={"displayModeBar": False})
            else:
                st.success("No failed findings!", icon="✅")

    with chart_r:
        st.markdown("<p class='section-header'>Pass / Fail Breakdown</p>", unsafe_allow_html=True)
        if "status" in df.columns:
            sc_counts = df["status"].value_counts().reset_index()
            sc_counts.columns = ["status", "count"]
            fig_pie = go.Figure(go.Pie(
                labels=sc_counts["status"],
                values=sc_counts["count"],
                marker=dict(
                    colors=[STATUS_COLORS.get(s, "#64748b") for s in sc_counts["status"]],
                    line=dict(color="#0f172a", width=2),
                ),
                hole=0.55,
                textfont=dict(color="#e2e8f0"),
                hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
            ))
            fig_pie.update_layout(
                height=280,
                legend=dict(font=dict(color="#94a3b8"), bgcolor="rgba(0,0,0,0)"),
                **PLOTLY_BASE, margin=dict(t=10, b=10, l=10, r=10),
            )
            st.plotly_chart(fig_pie, use_container_width=True, config={"displayModeBar": False})

    st.divider()

    # ── Domain breakdown ─────────────────────────────────────
    if "control_domain" in df.columns and "status" in df.columns:
        st.markdown("<p class='section-header'>Results by Control Domain</p>", unsafe_allow_html=True)
        domain_stats = (
            df.groupby("control_domain")["status"]
            .value_counts().unstack(fill_value=0).reset_index()
        )
        for col in ["PASS", "FAIL", "WARNING"]:
            if col not in domain_stats.columns:
                domain_stats[col] = 0
        domain_stats["total"] = domain_stats[["PASS", "FAIL", "WARNING"]].sum(axis=1)
        domain_stats["score"] = (domain_stats["PASS"] / domain_stats["total"] * 100).round(0)
        domain_stats = domain_stats.sort_values("score")

        fig_dom = go.Figure()
        fig_dom.add_trace(go.Bar(
            y=domain_stats["control_domain"], x=domain_stats["PASS"],
            name="Pass", orientation="h", marker_color="#22c55e"
        ))
        fig_dom.add_trace(go.Bar(
            y=domain_stats["control_domain"], x=domain_stats["FAIL"],
            name="Fail", orientation="h", marker_color="#ef4444"
        ))
        fig_dom.add_trace(go.Bar(
            y=domain_stats["control_domain"], x=domain_stats["WARNING"],
            name="Warning", orientation="h", marker_color="#eab308"
        ))
        fig_dom.update_layout(
            barmode="stack", height=max(220, len(domain_stats) * 52),
            xaxis=dict(tickfont=dict(color="#94a3b8"), gridcolor="#334155"),
            yaxis=dict(tickfont=dict(color="#e2e8f0")),
            legend=dict(font=dict(color="#94a3b8"), bgcolor="rgba(0,0,0,0)"),
            **PLOTLY_BASE, margin=dict(t=10, b=10, l=10, r=10),
        )
        st.plotly_chart(fig_dom, use_container_width=True, config={"displayModeBar": False})
        st.divider()

    # ── Critical callout ─────────────────────────────────────
    if {"status", "severity"}.issubset(df.columns):
        crit_df = df[(df["status"] == "FAIL") & (df["severity"] == "CRITICAL")]
        if not crit_df.empty:
            with st.expander(f"🔴 {len(crit_df)} Critical Findings — click to review", expanded=True):
                for _, row in crit_df.iterrows():
                    st.markdown(
                        f"**{row.get('check_id', '')} — {row.get('title', '')}**  \n"
                        f"Resource: `{row.get('resource', 'N/A')}`  \n"
                        f"🔧 {row.get('remediation', 'No remediation provided.')}",
                    )
                    st.divider()

    # ── Downloads ────────────────────────────────────────────
    st.markdown("<p class='section-header'>Export</p>", unsafe_allow_html=True)
    dl1, dl2, dl3 = st.columns(3)
    with dl1:
        st.download_button(
            "⬇ Download JSON",
            data=json.dumps(report, indent=2, default=str),
            file_name=f"comply_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
    with dl2:
        st.download_button(
            "⬇ Download CSV",
            data=df.to_csv(index=False),
            file_name=f"comply_findings_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    with dl3:
        if {"status", "severity"}.issubset(df.columns):
            crit_csv = df[(df["status"] == "FAIL") & (df["severity"].isin(["CRITICAL", "HIGH"]))]
            st.download_button(
                "⬇ Critical/High CSV",
                data=crit_csv.to_csv(index=False),
                file_name=f"comply_critical_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )


# ═══════════════════════════════════════════════════════════════
# PAGE: CHECKS
# ═══════════════════════════════════════════════════════════════

elif page == "🔍 Checks":

    st.markdown("<p class='section-header'>All Compliance Checks</p>", unsafe_allow_html=True)
    st.markdown(
        "<p style='color:#94a3b8;font-size:0.85rem;margin-bottom:1rem'>"
        "Every check the scanner can run — showing what was tested, what passed, "
        "what failed, and what wasn't reached in this scan.</p>",
        unsafe_allow_html=True,
    )

    # ── Filter bar ───────────────────────────────────────────
    f1, f2, f3 = st.columns([1, 1, 2])
    with f1:
        cat_filter = st.multiselect(
            "Category",
            options=CATEGORY_ORDER,
            default=CATEGORY_ORDER,
        )
    with f2:
        status_filter = st.multiselect(
            "Result",
            options=["PASS", "FAIL", "WARNING", "ERROR", "NOT RUN"],
            default=["PASS", "FAIL", "WARNING", "NOT RUN"],
        )
    with f3:
        search = st.text_input("🔍 Search checks", placeholder="e.g. MFA, encryption, S3, branch…")

    # ── Summary counts ───────────────────────────────────────
    total_checks = len(ALL_CHECKS)
    ran_ids = set(findings_by_id.keys())
    not_run_count = sum(1 for cid in ALL_CHECKS if cid not in ran_ids)

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Possible Checks", total_checks)
    m2.metric("✅ Passed", passed)
    m3.metric("❌ Failed", failed)
    m4.metric("⚠️ Warnings", warnings)
    m5.metric("⬜ Not Run", not_run_count)

    st.divider()

    # ── Render checks grouped by category ────────────────────
    for category in CATEGORY_ORDER:
        if category not in cat_filter:
            continue

        # Collect checks in this category
        cat_checks = {cid: meta for cid, meta in ALL_CHECKS.items()
                      if meta["category"] == category}

        # Apply search filter
        if search:
            cat_checks = {
                cid: meta for cid, meta in cat_checks.items()
                if search.lower() in meta["title"].lower()
                or search.lower() in meta["description"].lower()
                or search.lower() in cid.lower()
            }
        if not cat_checks:
            continue

        # Compute category stats
        cat_pass = cat_fail = cat_warn = cat_notrun = 0
        for cid in cat_checks:
            if cid not in ran_ids:
                cat_notrun += 1
            else:
                for f in findings_by_id[cid]:
                    s = f.get("status", "")
                    if s == "PASS":
                        cat_pass += 1
                    elif s == "FAIL":
                        cat_fail += 1
                    elif s == "WARNING":
                        cat_warn += 1

        # Apply status filter at category level — skip entire category if
        # none of its checks match the selected statuses
        visible = []
        for cid, meta in cat_checks.items():
            if cid not in ran_ids:
                eff_status = "NOT RUN"
            else:
                statuses = {f.get("status", "") for f in findings_by_id[cid]}
                if "FAIL" in statuses:
                    eff_status = "FAIL"
                elif "WARNING" in statuses:
                    eff_status = "WARNING"
                else:
                    eff_status = "PASS"
            if eff_status in status_filter:
                visible.append((cid, meta, eff_status))

        if not visible:
            continue

        # Category header
        icon = {
            "AWS · Security Groups": "🔒",
            "AWS · Encryption": "🔐",
            "AWS · Backups": "💾",
            "AWS · IAM": "👤",
            "GitHub · Repositories": "🐙",
        }.get(category, "📋")

        st.markdown(
            f"<div class='category-header'>"
            f"<span class='category-title'>{icon} {category}</span>"
            f"<span class='category-stats'>"
            f"<span style='color:#4ade80'>✅ {cat_pass}</span>"
            f"<span style='color:#f87171'>❌ {cat_fail}</span>"
            f"<span style='color:#fbbf24'>⚠️ {cat_warn}</span>"
            f"<span style='color:#475569'>⬜ {cat_notrun} not run</span>"
            f"</span></div>",
            unsafe_allow_html=True,
        )

        # Render each check
        for cid, meta, eff_status in visible:
            not_run = cid not in ran_ids

            if not_run:
                # Check was never triggered (resource doesn't exist or wasn't reached)
                st.markdown(
                    f"<div class='check-card not-run'>"
                    f"<div class='check-icon'>⬜</div>"
                    f"<div class='check-body'>"
                    f"<div class='check-title'>{meta['title']}</div>"
                    f"<div class='check-id'>{cid}</div>"
                    f"<div class='check-desc'>{meta['description']}</div>"
                    f"<div class='check-desc not-run-label'>Not run in this scan "
                    f"(resource may not exist in your account)</div>"
                    f"</div>"
                    f"<div>{pill('NOT RUN', 'not-run')}</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
            else:
                # One check_id can have multiple findings (e.g. one per bucket/user/SG)
                instance_findings = findings_by_id[cid]

                for f in instance_findings:
                    status = f.get("status", "")
                    severity = f.get("severity", "INFO")
                    resource = f.get("resource", "")
                    desc = f.get("description", meta["description"])
                    remediation = f.get("remediation", "")
                    reasoning = f.get("reasoning", "")

                    card_class = {"PASS": "pass", "FAIL": "fail", "WARNING": "warning"}.get(status, "not-run")
                    icon_map = {"PASS": "✅", "FAIL": "❌", "WARNING": "⚠️"}
                    icon_char = icon_map.get(status, "⬜")

                    # Pills row
                    pills_html = (
                        pill(status, status.lower()) + " &nbsp; " +
                        pill(severity, severity.lower())
                    )

                    # Resource line
                    resource_html = (
                        f"<div class='check-resource'>📦 {resource}</div>"
                        if resource and resource != "N/A" else ""
                    )

                    # Remediation (only on FAIL/WARNING)
                    remediation_html = ""
                    if status in ("FAIL", "WARNING") and remediation:
                        remediation_html = (
                            f"<div class='check-remediation'>"
                            f"🔧 <strong>Remediation:</strong> {remediation}</div>"
                        )

                    st.markdown(
                        f"<div class='check-card {card_class}'>"
                        f"<div class='check-icon'>{icon_char}</div>"
                        f"<div class='check-body'>"
                        f"<div class='check-title'>{meta['title']}</div>"
                        f"<div class='check-id'>{cid}</div>"
                        f"<div class='check-desc'>{desc}</div>"
                        f"{resource_html}"
                        f"{remediation_html}"
                        f"</div>"
                        f"<div style='white-space:nowrap'>{pills_html}</div>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

                    # Reasoning in expander (keeps layout clean)
                    if reasoning:
                        with st.expander("📋 View audit reasoning", expanded=False):
                            st.markdown(
                                f"<div class='check-reasoning'>{reasoning}</div>",
                                unsafe_allow_html=True,
                            )


import sys
import os
import json
from datetime import datetime

if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "scan":
    from comply.scanner import ComplyScanner
    import boto3

    print("Starting compliance scan...")

    session = boto3.Session()

    github_repos = os.getenv("GITHUB_REPOS", "")
    github_repos = [r.strip() for r in github_repos.split(",")] if github_repos else []

    scanner = ComplyScanner(
        aws_session=session,
        github_token=os.getenv("GITHUB_TOKEN"),
        github_repos=github_repos,
    )

    results = scanner.run_full_scan()

    # ✅ critical missing piece
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filepath = f"reports/comply_report_{timestamp}.json"

    with open(filepath, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"✅ Report saved: {filepath}")

    sys.exit(0)

