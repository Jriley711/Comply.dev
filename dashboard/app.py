"""
Comply.dev — Streamlit Compliance Dashboard

Credentials are read from st.secrets (Streamlit Cloud) first,
then fall back to environment variables for local development.

FIXES applied vs original:
  1. REPORT_URL typo: raw.GitHubusercontent → raw.githubusercontent
  2. load_report_from_github: now reads top-level scan_time from JSON
  3. run_live_scan: fixed github_repos casing (was GitHub_repos)
  4. Framework gauge: fixed DataFrame column filtering logic
  5. applymap → map (pandas ≥ 2.1 deprecation)
  6. Secret keys normalised: GH_TOKEN→GITHUB_TOKEN, GH_REPOS→GITHUB_REPOS
     (matching what the scanner and GitHub Actions actually read)
"""

import os
import json
import requests
from datetime import datetime

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


# ─────────────────────────────────────────────────────────────
# Secrets helper — works on Streamlit Cloud AND locally
# ─────────────────────────────────────────────────────────────

def get_secret(key: str, default: str = "") -> str:
    """Read from st.secrets first, fall back to env vars for local dev."""
    try:
        return st.secrets[key]
    except (KeyError, FileNotFoundError):
        return os.getenv(key, default)


AWS_ACCESS_KEY_ID     = get_secret("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = get_secret("AWS_SECRET_ACCESS_KEY")
AWS_DEFAULT_REGION    = get_secret("AWS_DEFAULT_REGION", "us-east-1")
# FIX: normalised key names to GITHUB_TOKEN / GITHUB_REPOS
GITHUB_TOKEN  = get_secret("GITHUB_TOKEN")
GITHUB_REPOS  = get_secret("GITHUB_REPOS")

GITHUB_USERNAME = get_secret("GITHUB_USERNAME", "Jriley711")
GITHUB_REPO     = get_secret("GITHUB_REPO", "Comply.dev")

# FIX: was raw.GitHubusercontent.com (wrong capitalisation → 404)
REPORT_URL = (
    f"https://raw.githubusercontent.com/"
    f"{GITHUB_USERNAME}/{GITHUB_REPO}/reports-data/reports/latest.json"
)


# ─────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Comply.dev",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ───────────────────────────────────────────────
st.markdown("""
<style>
/* ── Global ── */
[data-testid="stAppViewContainer"] {
    background: linear-gradient(135deg, #0f172a 0%, #1a1f35 100%);
}
[data-testid="stSidebar"] {
    background: #0f172a !important;
    border-right: 1px solid #1e293b;
}

/* ── Metric cards ── */
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

/* ── Section headers ── */
.section-header {
    font-size: 1.1rem;
    font-weight: 600;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 0.75rem;
}

/* ── Score ring ── */
.score-ring-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 16px;
    padding: 1.5rem;
    height: 100%;
}
.score-ring-label {
    color: #94a3b8;
    font-size: 0.85rem;
    margin-top: 0.5rem;
    letter-spacing: 0.04em;
}

/* ── Severity badges ── */
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
.badge-critical { background: #450a0a; color: #f87171; }
.badge-high     { background: #431407; color: #fb923c; }
.badge-medium   { background: #422006; color: #fbbf24; }
.badge-low      { background: #052e16; color: #4ade80; }
.badge-pass     { background: #052e16; color: #4ade80; }
.badge-fail     { background: #450a0a; color: #f87171; }
.badge-warning  { background: #422006; color: #fbbf24; }
.badge-info     { background: #1e3a5f; color: #7dd3fc; }

/* ── Dataframe override ── */
[data-testid="stDataFrame"] {
    border: 1px solid #334155;
    border-radius: 8px;
    overflow: hidden;
}

/* ── Sidebar nav ── */
.sidebar-nav-item {
    padding: 0.5rem 0.75rem;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.9rem;
    color: #94a3b8;
    margin-bottom: 0.25rem;
}
.sidebar-nav-item:hover { background: #1e293b; color: #e2e8f0; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=3600)
def load_report_from_github() -> dict | None:
    """Fetch the latest scan report JSON from the reports-data branch."""
    try:
        resp = requests.get(REPORT_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        # FIX: report JSON has top-level scan_time from the fixed generator
        # If not present (old report format), fall back gracefully
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
    """Parse an uploaded JSON report file."""
    try:
        data = json.loads(uploaded_bytes)
        if "scan_time" not in data and "summary" in data:
            data["scan_time"] = data["summary"].get("scan_timestamp", "Unknown")
        return data
    except json.JSONDecodeError as e:
        st.error(f"Invalid JSON file: {e}")
        return None


def run_live_scan() -> dict | None:
    """Trigger a live scan using stored credentials."""
    import boto3
    from comply.scanner import ComplyScanner

    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
        st.error("AWS credentials not configured. Add them to Streamlit Secrets.")
        return None

    try:
        session = boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_DEFAULT_REGION,
        )
        # FIX: was GitHub_repos (capital G) — now github_repos (lowercase)
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
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "INFO":     "#64748b",
}
STATUS_COLORS = {"PASS": "#22c55e", "FAIL": "#ef4444", "WARNING": "#eab308"}

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#e2e8f0", family="Inter, system-ui, sans-serif"),
    margin=dict(t=20, b=20, l=20, r=20),
)


def fmt_score_color(score: float) -> str:
    if score >= 80:
        return "#22c55e"
    if score >= 50:
        return "#eab308"
    return "#ef4444"


def fmt_datetime(iso_str: str) -> str:
    try:
        ts = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return ts.strftime("%B %d, %Y at %H:%M UTC")
    except Exception:
        return iso_str


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

    data_source = st.radio(
        "**Data source**",
        ["📡 Latest scan (GitHub)", "📂 Upload report", "⚡ Run live scan"],
        index=0,
    )

    uploaded_file = None
    if data_source == "📂 Upload report":
        uploaded_file = st.file_uploader(
            "Upload JSON report", type=["json"],
            help="Upload a comply_report_*.json file",
        )

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
        st.info(
            "No scan report found yet. Run the GitHub Actions workflow "
            "(**Actions → Compliance Scan → Run workflow**) to generate one.",
            icon="ℹ️",
        )

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
        st.info(
            "Click **Run scan now** to trigger a live scan against your AWS account.",
            icon="⚡",
        )


# ─────────────────────────────────────────────────────────────
# Dashboard — only renders when we have data
# ─────────────────────────────────────────────────────────────

if not report:
    st.stop()

findings   = report.get("findings", [])
scan_time  = report.get("scan_time", "Unknown")
summary    = report.get("summary", {})
fw_summary = summary.get("framework_compliance", {})

df = pd.DataFrame(findings) if findings else pd.DataFrame()

# ── Derived stats ────────────────────────────────────────────
total    = len(findings)
passed   = int(df["status"].eq("PASS").sum())  if "status"   in df.columns else 0
failed   = int(df["status"].eq("FAIL").sum())  if "status"   in df.columns else 0
warnings = int(df["status"].eq("WARNING").sum()) if "status" in df.columns else 0
critical = int((df["status"].eq("FAIL") & df["severity"].eq("CRITICAL")).sum()) \
           if {"status", "severity"}.issubset(df.columns) else 0
score    = round(passed / total * 100) if total > 0 else 0


# ═══════════════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════════════

col_title, col_meta = st.columns([3, 1])
with col_title:
    st.markdown(
        "<h1 style='color:#f1f5f9;font-size:2rem;margin-bottom:0'>🛡️ Compliance Dashboard</h1>",
        unsafe_allow_html=True,
    )
    if scan_time != "Unknown":
        st.markdown(
            f"<p style='color:#64748b;font-size:0.85rem;margin-top:4px'>"
            f"Last scan: {fmt_datetime(scan_time)}</p>",
            unsafe_allow_html=True,
        )
with col_meta:
    # Big score pill
    score_color = fmt_score_color(score)
    st.markdown(
        f"<div style='text-align:right;padding-top:8px'>"
        f"<span style='font-size:2.5rem;font-weight:800;color:{score_color}'>{score}%</span>"
        f"<br/><span style='color:#64748b;font-size:0.8rem'>overall score</span></div>",
        unsafe_allow_html=True,
    )

st.divider()

# ═══════════════════════════════════════════════════════════════
# KPI METRICS ROW
# ═══════════════════════════════════════════════════════════════

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Checks", total)
c2.metric("✅ Passed",    passed,    delta=None)
c3.metric("❌ Failed",    failed,    delta=None)
c4.metric("⚠️ Warnings",  warnings,  delta=None)
c5.metric("🔴 Critical",  critical,  delta=None)

st.divider()

# ═══════════════════════════════════════════════════════════════
# FRAMEWORK GAUGES
# ═══════════════════════════════════════════════════════════════

st.markdown("<p class='section-header'>Framework Compliance</p>", unsafe_allow_html=True)

FW_DISPLAY = {
    "SOC2":     "SOC 2",
    "ISO27001": "ISO 27001",
    "CIS_AWS":  "CIS AWS",
}

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
        **PLOTLY_LAYOUT,
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

# ═══════════════════════════════════════════════════════════════
# CHARTS ROW
# ═══════════════════════════════════════════════════════════════

chart_l, chart_r = st.columns(2)

with chart_l:
    st.markdown("<p class='section-header'>Findings by Severity</p>", unsafe_allow_html=True)
    if "severity" in df.columns and "status" in df.columns:
        fail_df = df[df["status"] == "FAIL"]
        if not fail_df.empty:
            sev_counts = (
                fail_df["severity"]
                .value_counts()
                .reindex(SEVERITY_ORDER)
                .dropna()
                .reset_index()
            )
            sev_counts.columns = ["severity", "count"]
            colors = [SEVERITY_COLORS.get(s, "#64748b") for s in sev_counts["severity"]]

            fig_sev = go.Figure(go.Bar(
                x=sev_counts["severity"],
                y=sev_counts["count"],
                marker_color=colors,
                text=sev_counts["count"],
                textposition="outside",
                textfont=dict(color="#e2e8f0"),
            ))
            fig_sev.update_layout(
                height=300,
                showlegend=False,
                xaxis=dict(tickfont=dict(color="#94a3b8"), gridcolor="#1e293b"),
                yaxis=dict(tickfont=dict(color="#94a3b8"), gridcolor="#334155", zeroline=False),
                **PLOTLY_LAYOUT,
            )
            st.plotly_chart(fig_sev, use_container_width=True, config={"displayModeBar": False})
        else:
            st.success("No failed findings to display.", icon="✅")
    else:
        st.info("No severity data available.")

with chart_r:
    st.markdown("<p class='section-header'>Pass / Fail Breakdown</p>", unsafe_allow_html=True)
    if "status" in df.columns:
        status_counts = df["status"].value_counts().reset_index()
        status_counts.columns = ["status", "count"]
        colors = [STATUS_COLORS.get(s, "#64748b") for s in status_counts["status"]]

        fig_pie = go.Figure(go.Pie(
            labels=status_counts["status"],
            values=status_counts["count"],
            marker=dict(colors=colors, line=dict(color="#0f172a", width=2)),
            hole=0.55,
            textfont=dict(color="#e2e8f0"),
            hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
        ))
        fig_pie.update_layout(
            height=300,
            showlegend=True,
            legend=dict(font=dict(color="#94a3b8"), bgcolor="rgba(0,0,0,0)"),
            **PLOTLY_LAYOUT,
        )
        st.plotly_chart(fig_pie, use_container_width=True, config={"displayModeBar": False})
    else:
        st.info("No status data available.")

st.divider()

# ═══════════════════════════════════════════════════════════════
# DOMAIN BREAKDOWN
# ═══════════════════════════════════════════════════════════════

if "control_domain" in df.columns and "status" in df.columns:
    st.markdown("<p class='section-header'>Results by Control Domain</p>", unsafe_allow_html=True)

    domain_stats = (
        df.groupby("control_domain")["status"]
        .value_counts()
        .unstack(fill_value=0)
        .reset_index()
    )
    # Ensure columns exist
    for col in ["PASS", "FAIL", "WARNING"]:
        if col not in domain_stats.columns:
            domain_stats[col] = 0

    domain_stats["total"] = domain_stats[["PASS", "FAIL", "WARNING"]].sum(axis=1)
    domain_stats["score"] = (domain_stats["PASS"] / domain_stats["total"] * 100).round(0)
    domain_stats = domain_stats.sort_values("score")

    fig_domain = go.Figure()
    fig_domain.add_trace(go.Bar(
        y=domain_stats["control_domain"], x=domain_stats["PASS"],
        name="Pass", orientation="h", marker_color="#22c55e",
    ))
    fig_domain.add_trace(go.Bar(
        y=domain_stats["control_domain"], x=domain_stats["FAIL"],
        name="Fail", orientation="h", marker_color="#ef4444",
    ))
    fig_domain.add_trace(go.Bar(
        y=domain_stats["control_domain"], x=domain_stats["WARNING"],
        name="Warning", orientation="h", marker_color="#eab308",
    ))
    fig_domain.update_layout(
        barmode="stack",
        height=max(250, len(domain_stats) * 55),
        xaxis=dict(tickfont=dict(color="#94a3b8"), gridcolor="#334155"),
        yaxis=dict(tickfont=dict(color="#e2e8f0")),
        legend=dict(font=dict(color="#94a3b8"), bgcolor="rgba(0,0,0,0)"),
        **PLOTLY_LAYOUT,
    )
    st.plotly_chart(fig_domain, use_container_width=True, config={"displayModeBar": False})
    st.divider()

# ═══════════════════════════════════════════════════════════════
# FINDINGS TABLE
# ═══════════════════════════════════════════════════════════════

st.markdown("<p class='section-header'>All Findings</p>", unsafe_allow_html=True)

# ── Filters ──────────────────────────────────────────────────
f1, f2, f3, f4 = st.columns([1, 1, 1, 2])

with f1:
    status_opts = sorted(df["status"].unique().tolist()) if "status" in df.columns else []
    status_filter = st.multiselect("Status", options=status_opts, default=status_opts)
with f2:
    sev_opts = [s for s in SEVERITY_ORDER if s in df.get("severity", pd.Series()).unique()] \
               if "severity" in df.columns else []
    sev_filter = st.multiselect("Severity", options=sev_opts, default=sev_opts)
with f3:
    domain_opts = sorted(df["control_domain"].unique().tolist()) if "control_domain" in df.columns else []
    domain_filter = st.multiselect("Domain", options=domain_opts, default=domain_opts)
with f4:
    search = st.text_input("🔍 Search", placeholder="Filter by name, resource, check ID…")

# ── Apply filters ─────────────────────────────────────────────
filtered = df.copy()
if status_filter and "status" in filtered.columns:
    filtered = filtered[filtered["status"].isin(status_filter)]
if sev_filter and "severity" in filtered.columns:
    filtered = filtered[filtered["severity"].isin(sev_filter)]
if domain_filter and "control_domain" in filtered.columns:
    filtered = filtered[filtered["control_domain"].isin(domain_filter)]
if search and not filtered.empty:
    mask = filtered.apply(
        lambda row: row.astype(str).str.contains(search, case=False, na=False).any(), axis=1
    )
    filtered = filtered[mask]

# ── Render table ──────────────────────────────────────────────
display_cols = [c for c in ["check_id", "title", "status", "severity", "control_domain", "resource", "remediation"]
                if c in filtered.columns]

def _color_row(row):
    """Row-level styling based on status."""
    base = "color: #e2e8f0;"
    if row.get("status") == "FAIL":
        return [f"background-color: #1f0f0f; {base}"] * len(row)
    if row.get("status") == "WARNING":
        return [f"background-color: #1f1800; {base}"] * len(row)
    if row.get("status") == "PASS":
        return [f"background-color: #0a1a0f; {base}"] * len(row)
    return [base] * len(row)

def _color_cell(val):
    """Cell-level badge coloring for status/severity columns."""
    colors = {
        "FAIL":     "color: #f87171; font-weight: 700;",
        "PASS":     "color: #4ade80; font-weight: 700;",
        "WARNING":  "color: #fbbf24; font-weight: 700;",
        "CRITICAL": "color: #f87171; font-weight: 700;",
        "HIGH":     "color: #fb923c; font-weight: 700;",
        "MEDIUM":   "color: #fbbf24;",
        "LOW":      "color: #4ade80;",
        "INFO":     "color: #7dd3fc;",
    }
    return colors.get(val, "")

if not filtered.empty:
    style_cols = [c for c in ["status", "severity"] if c in display_cols]
    styled = (
        filtered[display_cols]
        .style
        .apply(_color_row, axis=1)
        # FIX: use .map() not deprecated .applymap()
        .map(_color_cell, subset=style_cols if style_cols else [])
    )
    st.dataframe(styled, use_container_width=True, hide_index=True, height=420)
    st.caption(f"Showing **{len(filtered)}** of **{len(df)}** findings")
else:
    st.info("No findings match the current filters.", icon="🔍")

st.divider()

# ═══════════════════════════════════════════════════════════════
# CRITICAL FINDINGS CALLOUT
# ═══════════════════════════════════════════════════════════════

if {"status", "severity"}.issubset(df.columns):
    crit_df = df[(df["status"] == "FAIL") & (df["severity"] == "CRITICAL")]
    if not crit_df.empty:
        with st.expander(f"🔴 {len(crit_df)} Critical Findings — Click to review", expanded=False):
            for _, row in crit_df.iterrows():
                st.markdown(
                    f"**{row.get('check_id', '')} — {row.get('title', '')}**  \n"
                    f"Resource: `{row.get('resource', 'N/A')}`  \n"
                    f"🔧 {row.get('remediation', 'No remediation provided.')}",
                )
                st.divider()

# ═══════════════════════════════════════════════════════════════
# DOWNLOADS
# ═══════════════════════════════════════════════════════════════

st.markdown("<p class='section-header'>Export</p>", unsafe_allow_html=True)
dl1, dl2, dl3 = st.columns(3)

with dl1:
    st.download_button(
        label="⬇ Download JSON",
        data=json.dumps(report, indent=2, default=str),
        file_name=f"comply_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
        use_container_width=True,
    )
with dl2:
    st.download_button(
        label="⬇ Download CSV",
        data=df.to_csv(index=False),
        file_name=f"comply_findings_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        use_container_width=True,
    )
with dl3:
    # Critical-only CSV for quick triage
    if {"status", "severity"}.issubset(df.columns):
        crit_csv = df[(df["status"] == "FAIL") & (df["severity"].isin(["CRITICAL", "HIGH"]))]
        st.download_button(
            label="⬇ Critical/High Only CSV",
            data=crit_csv.to_csv(index=False),
            file_name=f"comply_critical_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )
