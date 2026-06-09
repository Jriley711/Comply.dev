"""
Comply.dev — Cloud Compliance Dashboard
Streamlit multi-page app. Entry point.
"""

import streamlit as st

st.set_page_config(
    page_title="Comply.dev",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global styles ──────────────────────────────────────────────
st.markdown("""
<style>
    /* Sidebar nav */
    [data-testid="stSidebarNav"] { padding-top: 1rem; }

    /* Remove default top padding */
    .block-container { padding-top: 1.5rem; }

    /* Metric cards */
    [data-testid="stMetric"] {
        background: #F1EFE8;
        border-radius: 8px;
        padding: 12px 16px;
    }

    /* Expander headers */
    .streamlit-expanderHeader {
        font-size: 14px !important;
        font-weight: 500 !important;
    }

    /* Dataframe — tighten it up */
    [data-testid="stDataFrame"] { border-radius: 8px; }

    /* Hide Streamlit branding */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Comply.dev")
    st.markdown(
        "<div style='font-size:12px;color:#888780;margin-bottom:1.5rem;'>"
        "Cloud compliance automation<br>for AWS &amp; GitHub"
        "</div>",
        unsafe_allow_html=True,
    )
    st.markdown("---")
    st.markdown("**Navigation**")
    st.page_link("app.py",                        label="Overview",    icon="🏠")
    st.page_link("pages/1_findings.py",            label="Findings",    icon="🔍")
    st.page_link("pages/2_frameworks.py",          label="Frameworks",  icon="📋")
    st.page_link("pages/3_drift.py",               label="Drift",       icon="📊")
    st.page_link("pages/4_scan.py",                label="Run Scan",    icon="⚡")
    st.markdown("---")
    st.markdown(
        "<div style='font-size:11px;color:#B4B2A9;'>"
        "<a href='https://github.com/Jriley711/Comply.dev' "
        "style='color:#B4B2A9;text-decoration:none;'>github.com/Jriley711/Comply.dev</a>"
        "</div>",
        unsafe_allow_html=True,
    )

# ── Load data ──────────────────────────────────────────────────
from dashboard.data import load_latest, load_previous, parse_report, format_scan_time
from dashboard.components import (
    score_gauge, severity_bar_chart, framework_scores_chart,
    status_donut, metric_card,
)

with st.spinner("Loading latest scan report…"):
    latest   = load_latest()
    previous = load_previous()

if latest is None:
    st.error("No scan report found. Run a scan or upload a report.")
    st.markdown(
        "Go to **⚡ Run Scan** in the sidebar to trigger your first scan, "
        "or upload a JSON report directly."
    )
    st.stop()

data = parse_report(latest)
df   = data["df"]

# ── Header ─────────────────────────────────────────────────────
col_title, col_time = st.columns([3, 1])
with col_title:
    st.markdown("## Compliance Overview")
with col_time:
    st.markdown(
        f"<div style='text-align:right;font-size:12px;color:#888780;padding-top:12px;'>"
        f"Last scan: {format_scan_time(data['scan_time'])}</div>",
        unsafe_allow_html=True,
    )

# ── Critical alert banner ───────────────────────────────────────
if data["critical"] > 0:
    st.error(
        f"🚨 **{data['critical']} critical issue{'s' if data['critical'] != 1 else ''} require immediate attention.** "
        f"See the Findings page for details."
    )

# ── Top metrics ─────────────────────────────────────────────────
m1, m2, m3, m4, m5 = st.columns(5)
with m1:
    metric_card("Compliance score", f"{data['score']}%",
                color="#1D9E75" if data["score"] >= 80 else "#EF9F27" if data["score"] >= 50 else "#E24B4A")
with m2:
    metric_card("Total checks", str(data["total"]))
with m3:
    metric_card("Passed", str(data["passed"]), color="#1D9E75")
with m4:
    metric_card("Failed", str(data["failed"]), color="#E24B4A")
with m5:
    metric_card("Warnings", str(data["warnings"]), color="#EF9F27")

st.markdown("<div style='margin-top:1.5rem;'></div>", unsafe_allow_html=True)

# ── Charts row ──────────────────────────────────────────────────
ch1, ch2, ch3 = st.columns([1, 1, 1])

with ch1:
    st.markdown("##### Compliance score")
    st.plotly_chart(score_gauge(data["score"]), use_container_width=True, config={"displayModeBar": False})

with ch2:
    st.markdown("##### Findings by severity")
    st.plotly_chart(severity_bar_chart(df), use_container_width=True, config={"displayModeBar": False})

with ch3:
    st.markdown("##### Pass / Fail / Warning")
    st.plotly_chart(
        status_donut(data["passed"], data["failed"], data["warnings"]),
        use_container_width=True,
        config={"displayModeBar": False},
    )

st.markdown("---")

# ── Framework scores ────────────────────────────────────────────
st.markdown("##### Framework compliance")

fw_summary = data["framework_summary"]
if fw_summary:
    st.plotly_chart(
        framework_scores_chart(fw_summary),
        use_container_width=True,
        config={"displayModeBar": False},
    )

    fw_cols = st.columns(len(fw_summary))
    from dashboard.config import FRAMEWORK_LABELS
    for i, (fw_key, fw_data) in enumerate(fw_summary.items()):
        score = fw_data.get("compliance_score", 0)
        color = "#1D9E75" if score >= 80 else "#EF9F27" if score >= 50 else "#E24B4A"
        with fw_cols[i]:
            metric_card(
                FRAMEWORK_LABELS.get(fw_key, fw_key),
                f"{score}%",
                delta=f"{fw_data.get('controls_passed',0)}/{fw_data.get('controls_tested',0)} controls",
                color=color,
            )
else:
    st.info("Framework summary not available in this report. Re-run a scan to generate it.")

st.markdown("---")

# ── Critical findings preview ───────────────────────────────────
if not df.empty and "status" in df.columns and "severity" in df.columns:
    critical_df = df[(df["status"] == "FAIL") & (df["severity"] == "CRITICAL")]
    if not critical_df.empty:
        st.markdown("##### Critical findings")
        from dashboard.components import finding_expander
        for _, row in critical_df.head(5).iterrows():
            finding_expander(row)
        if len(critical_df) > 5:
            st.caption(f"Showing 5 of {len(critical_df)} critical findings. See Findings page for all.")
