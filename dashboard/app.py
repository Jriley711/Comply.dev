"""
Comply.dev — Streamlit Compliance Dashboard

Credentials are read from st.secrets (Streamlit Cloud) first,
then fall back to environment variables for local development.
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
GH_TOKEN          = get_secret("GH_TOKEN")
GH_REPOS          = get_secret("GH_REPOS")

# GH raw URL for the latest scan report (written by GH Actions)
GH_USERNAME = get_secret("GH_USERNAME", "Jriley711")
GH_REPO     = get_secret("GH_REPO", "Comply.dev")
REPORT_URL = (
    f"https://raw.GHusercontent.com/"
    f"{GH_USERNAME}/{GH_REPO}/reports-data/reports/latest.json"
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


# ─────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=3600)
def load_report_from_GH() -> dict | None:
    """Fetch the latest scan report JSON from the reports-data branch."""
    try:
        resp = requests.get(REPORT_URL, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        if resp.status_code == 404:
            return None  # no report yet — first run
        st.error(f"Failed to load report from GH: {e}")
        return None
    except Exception as e:
        st.error(f"Unexpected error loading report: {e}")
        return None


@st.cache_data(ttl=3600)
def load_report_from_upload(uploaded_bytes: bytes) -> dict | None:
    """Parse an uploaded JSON report file."""
    try:
        return json.loads(uploaded_bytes)
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
        gh_repos = [r.strip() for r in GH_REPOS.split(",")] if GH_REPOS else []
        scanner = ComplyScanner(
            aws_session=session,
            GH_token=GH_TOKEN or None,
            GH_repos=gh_repos,
        )
        return scanner.run_full_scan()
    except Exception as e:
        st.error(f"Scan failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🛡️ Comply.dev")
    st.caption("Cloud Compliance Scanner")
    st.divider()

    data_source = st.radio(
        "Data source",
        ["Latest scan (GH)", "Upload report", "Run live scan"],
        index=0,
    )

    uploaded_file = None
    if data_source == "Upload report":
        uploaded_file = st.file_uploader("Upload JSON report", type=["json"])

    st.divider()
    st.caption(f"Region: `{AWS_DEFAULT_REGION}`")
    if GH_REPOS:
        st.caption(f"Repos: `{GH_REPOS}`")


# ─────────────────────────────────────────────────────────────
# Load data
# ─────────────────────────────────────────────────────────────

report = None

if data_source == "Latest scan (GH)":
    with st.spinner("Loading latest scan from GH..."):
        report = load_report_from_GH()
    if report is None:
        st.info(
            "No scan report found yet. Run the GH Actions workflow "
            "(`Actions → Compliance Scan → Run workflow`) to generate one.",
            icon="ℹ️",
        )

elif data_source == "Upload report":
    if uploaded_file:
        report = load_report_from_upload(uploaded_file.read())
    else:
        st.info("Upload a JSON report file from the sidebar.", icon="ℹ️")

elif data_source == "Run live scan":
    if st.button("▶ Run scan now", type="primary"):
        with st.spinner("Running compliance scan… this takes 30–60 seconds."):
            report = run_live_scan()
        if report:
            st.success("Scan complete!")
    else:
        st.info("Click 'Run scan now' to trigger a live scan against your AWS account.", icon="ℹ️")


# ─────────────────────────────────────────────────────────────
# Dashboard — only renders when we have data
# ─────────────────────────────────────────────────────────────

if report:
    findings = report.get("findings", [])
    scan_time = report.get("scan_time", "Unknown")
    df = pd.DataFrame(findings)

    # ── Header ──────────────────────────────────────────────
    st.title("🛡️ Compliance Dashboard")
    if scan_time != "Unknown":
        try:
            ts = datetime.fromisoformat(scan_time)
            st.caption(f"Last scan: {ts.strftime('%B %d, %Y at %H:%M UTC')}")
        except ValueError:
            st.caption(f"Last scan: {scan_time}")

    # ── Summary metrics ─────────────────────────────────────
    total     = len(findings)
    passed    = len(df[df["status"] == "PASS"]) if "status" in df.columns else 0
    failed    = len(df[df["status"] == "FAIL"]) if "status" in df.columns else 0
    critical  = len(df[(df["status"] == "FAIL") & (df["severity"] == "CRITICAL")]) if "severity" in df.columns else 0
    score     = round((passed / total * 100)) if total > 0 else 0

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Overall Score",   f"{score}%")
    col2.metric("Total Checks",    total)
    col3.metric("Passed",          passed,   delta=None)
    col4.metric("Failed",          f"⚠ {failed}" if failed else "0")
    col5.metric("Critical",        f"🔴 {critical}" if critical else "0")

    st.divider()

    # ── Framework gauges ────────────────────────────────────
    st.subheader("Framework compliance")

    frameworks = ["SOC 2", "ISO 27001", "CIS AWS"]
    fw_col = st.columns(len(frameworks))

    for i, fw in enumerate(frameworks):
        fw_findings = df[df.get("frameworks", pd.Series(dtype=str)).apply(
            lambda x: fw in x if isinstance(x, list) else False
        )] if "frameworks" in df.columns else df

        fw_total  = len(fw_findings)
        fw_passed = len(fw_findings[fw_findings["status"] == "PASS"]) if "status" in fw_findings.columns else 0
        fw_score  = round(fw_passed / fw_total * 100) if fw_total > 0 else 0

        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=fw_score,
            number={"suffix": "%"},
            title={"text": fw, "font": {"size": 14}},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#1f77b4"},
                "steps": [
                    {"range": [0, 50],  "color": "#ffcccc"},
                    {"range": [50, 80], "color": "#fff3cc"},
                    {"range": [80, 100],"color": "#ccffcc"},
                ],
                "threshold": {
                    "line": {"color": "green", "width": 2},
                    "thickness": 0.75,
                    "value": 80,
                },
            },
        ))
        fig.update_layout(height=200, margin=dict(t=40, b=10, l=20, r=20))
        fw_col[i].plotly_chart(fig, use_container_width=True)

    st.divider()

    # ── Charts ──────────────────────────────────────────────
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Findings by severity")
        if "severity" in df.columns:
            sev_counts = df[df["status"] == "FAIL"]["severity"].value_counts().reset_index()
            sev_counts.columns = ["severity", "count"]
            color_map = {"CRITICAL": "#d62728", "HIGH": "#ff7f0e", "MEDIUM": "#ffbb78", "LOW": "#aec7e8"}
            fig2 = px.bar(sev_counts, x="severity", y="count", color="severity",
                          color_discrete_map=color_map, text="count")
            fig2.update_layout(showlegend=False, height=300, margin=dict(t=10, b=10))
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No severity data available.")

    with chart_col2:
        st.subheader("Pass / Fail breakdown")
        if "status" in df.columns:
            status_counts = df["status"].value_counts().reset_index()
            status_counts.columns = ["status", "count"]
            fig3 = px.pie(status_counts, names="status", values="count",
                          color="status", color_discrete_map={"PASS": "#2ca02c", "FAIL": "#d62728"})
            fig3.update_layout(height=300, margin=dict(t=10, b=10))
            st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info("No status data available.")

    st.divider()

    # ── Findings table ──────────────────────────────────────
    st.subheader("All findings")

    # Filters
    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        status_filter = st.multiselect(
            "Status", options=df["status"].unique().tolist() if "status" in df.columns else [],
            default=df["status"].unique().tolist() if "status" in df.columns else [],
        )
    with filter_col2:
        sev_filter = st.multiselect(
            "Severity", options=df["severity"].unique().tolist() if "severity" in df.columns else [],
            default=df["severity"].unique().tolist() if "severity" in df.columns else [],
        )
    with filter_col3:
        search = st.text_input("Search", placeholder="Filter by name or description…")

    filtered = df.copy()
    if status_filter and "status" in filtered.columns:
        filtered = filtered[filtered["status"].isin(status_filter)]
    if sev_filter and "severity" in filtered.columns:
        filtered = filtered[filtered["severity"].isin(sev_filter)]
    if search and not filtered.empty:
        mask = filtered.apply(
            lambda row: row.astype(str).str.contains(search, case=False).any(), axis=1
        )
        filtered = filtered[mask]

    display_cols = [c for c in ["check_id", "name", "status", "severity", "resource", "description"]
                    if c in filtered.columns]

    def highlight_status(val):
        if val == "FAIL":
            return "background-color: #ffcccc; color: #8b0000;"
        if val == "PASS":
            return "background-color: #ccffcc; color: #006400;"
        return ""

    if not filtered.empty:
        st.dataframe(
            filtered[display_cols].style.applymap(
                highlight_status, subset=["status"] if "status" in display_cols else []
            ),
            use_container_width=True,
            hide_index=True,
        )
        st.caption(f"Showing {len(filtered)} of {len(df)} findings")
    else:
        st.info("No findings match the current filters.")

    # ── Download ─────────────────────────────────────────────
    st.divider()
    dl_col1, dl_col2 = st.columns(2)
    with dl_col1:
        st.download_button(
            label="⬇ Download JSON report",
            data=json.dumps(report, indent=2),
            file_name=f"comply_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
        )
    with dl_col2:
        st.download_button(
            label="⬇ Download CSV",
            data=df.to_csv(index=False),
            file_name=f"comply_findings_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )
