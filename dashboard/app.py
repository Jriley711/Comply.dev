"""Comply.dev — Streamlit Compliance Dashboard."""

import json
import glob
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

# ── Page Config ───────────────────────────────────────────────
st.set_page_config(
    page_title="Comply.dev Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────
st.markdown("""
<style>
    .stMetric { background-color: #1e293b; padding: 1rem; border-radius: 12px; }
    .block-container { padding-top: 2rem; }
</style>
""", unsafe_allow_html=True)

# ── Load Report Data ──────────────────────────────────────────
def load_latest_report():
    """Load the most recent JSON report."""
    reports = sorted(glob.glob("reports/comply_report_*.json"), reverse=True)
    if not reports:
        return None
    with open(reports[0], "r") as f:
        return json.load(f)


def load_report_from_upload(uploaded_file):
    """Load report from uploaded file."""
    return json.load(uploaded_file)


# ── Sidebar ───────────────────────────────────────────────────
st.sidebar.title("🛡️ Comply.dev")
st.sidebar.markdown("**Cloud Compliance Dashboard**")
st.sidebar.markdown("---")

data_source = st.sidebar.radio("Data Source", ["Latest Scan", "Upload Report"])

if data_source == "Upload Report":
    uploaded = st.sidebar.file_uploader("Upload JSON report", type=["json"])
    if uploaded:
        report = load_report_from_upload(uploaded)
    else:
        report = None
else:
    report = load_latest_report()

if report is None:
    st.title("🛡️ Comply.dev Dashboard")
    st.warning("No scan data found. Run a scan first:")
    st.code("python main.py scan", language="bash")
    st.info("Or upload a JSON report using the sidebar.")
    st.stop()

summary = report["summary"]
findings = report["findings"]

# ── Header ────────────────────────────────────────────────────
st.title("🛡️ Comply.dev — Compliance Dashboard")
st.caption(f"Scan: {summary.get('scan_timestamp', 'Unknown')}")
st.markdown("---")

# ── Top Metrics ───────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)

total = summary["total_findings"]
passed = summary["by_status"].get("PASS", 0)
failed = summary["by_status"].get("FAIL", 0)
warnings = summary["by_status"].get("WARNING", 0)
critical = summary["by_severity"].get("CRITICAL", 0)

col1.metric("Total Checks", total)
col2.metric("✅ Passed", passed)
col3.metric("❌ Failed", failed, delta=f"-{failed}" if failed > 0 else None, delta_color="inverse")
col4.metric("⚠️ Warnings", warnings)
col5.metric("🔴 Critical", critical, delta=f"-{critical}" if critical > 0 else None, delta_color="inverse")

st.markdown("---")

# ── Framework Compliance ──────────────────────────────────────
st.subheader("📊 Framework Compliance Scores")

fw_data = summary.get("framework_compliance", {})
if fw_data:
    cols = st.columns(len(fw_data))
    for i, (key, fw) in enumerate(fw_data.items()):
        with cols[i]:
            score = fw["compliance_score"]
            color = "#22c55e" if score >= 80 else "#eab308" if score >= 50 else "#ef4444"

            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                title={"text": fw["name"].split("—")[0].strip(), "font": {"size": 14}},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": color},
                    "bgcolor": "#1e293b",
                    "steps": [
                        {"range": [0, 50], "color": "#450a0a"},
                        {"range": [50, 80], "color": "#422006"},
                        {"range": [80, 100], "color": "#052e16"},
                    ],
                },
                number={"suffix": "%"},
            ))
            fig.update_layout(
                height=200,
                margin=dict(l=20, r=20, t=40, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                font={"color": "#e2e8f0"},
            )
            st.plotly_chart(fig, use_container_width=True)
            st.caption(f"{fw['controls_passed']}/{fw['controls_tested']} controls passed")

st.markdown("---")

# ── Charts Row ────────────────────────────────────────────────
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("🚨 Findings by Severity")
    severity_data = summary.get("by_severity", {})
    if severity_data:
        df_sev = pd.DataFrame([
            {"Severity": k, "Count": v} for k, v in severity_data.items()
        ])
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        severity_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e", "INFO": "#94a3b8"}
        df_sev["order"] = df_sev["Severity"].map({s: i for i, s in enumerate(severity_order)})
        df_sev = df_sev.sort_values("order")

        fig_sev = px.bar(
            df_sev, x="Severity", y="Count",
            color="Severity",
            color_discrete_map=severity_colors,
        )
        fig_sev.update_layout(
            showlegend=False,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={"color": "#e2e8f0"},
            height=300,
        )
        st.plotly_chart(fig_sev, use_container_width=True)

with chart_col2:
    st.subheader("📋 Findings by Status")
    status_data = summary.get("by_status", {})
    if status_data:
        df_status = pd.DataFrame([
            {"Status": k, "Count": v} for k, v in status_data.items()
        ])
        status_colors = {"PASS": "#22c55e", "FAIL": "#ef4444", "WARNING": "#eab308", "INFO": "#94a3b8"}

        fig_status = px.pie(
            df_status, values="Count", names="Status",
            color="Status",
            color_discrete_map=status_colors,
            hole=0.4,
        )
        fig_status.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font={"color": "#e2e8f0"},
            height=300,
        )
        st.plotly_chart(fig_status, use_container_width=True)

st.markdown("---")

# ── Findings Table ────────────────────────────────────────────
st.subheader("🔍 All Findings")

# Filters
filter_col1, filter_col2, filter_col3 = st.columns(3)
with filter_col1:
    status_filter = st.multiselect(
        "Filter by Status",
        options=["PASS", "FAIL", "WARNING"],
        default=["FAIL", "WARNING"],
    )
with filter_col2:
    severity_filter = st.multiselect(
        "Filter by Severity",
        options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=["CRITICAL", "HIGH", "MEDIUM"],
    )
with filter_col3:
    search_term = st.text_input("Search findings", "")

# Apply filters
filtered = [
    f for f in findings
    if f.get("status") in status_filter
    and f.get("severity") in severity_filter
    and (search_term.lower() in f.get("title", "").lower()
         or search_term.lower() in f.get("resource", "").lower()
         or search_term == "")
]

if filtered:
    df_findings = pd.DataFrame(filtered)
    display_cols = ["check_id", "title", "resource", "status", "severity", "remediation"]
    available_cols = [c for c in display_cols if c in df_findings.columns]
    st.dataframe(
        df_findings[available_cols],
        use_container_width=True,
        height=400,
    )
    st.caption(f"Showing {len(filtered)} of {len(findings)} findings")
else:
    st.info("No findings match the current filters.")

# ── Footer ────────────────────────────────────────────────────
st.markdown("---")
st.caption("Built with ❤️ by Jonathan Riley | Comply.dev v0.1.0")
