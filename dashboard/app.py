"""Comply.dev — Streamlit Compliance Dashboard with Controls Detail."""

import json
import glob
import pathlib
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd


import os

# Load secrets from Streamlit Cloud
if hasattr(st, "secrets"):
    try:
        os.environ["AWS_ACCESS_KEY_ID"] = st.secrets["aws"]["AWS_ACCESS_KEY_ID"]
        os.environ["AWS_SECRET_ACCESS_KEY"] = st.secrets["aws"]["AWS_SECRET_ACCESS_KEY"]
        os.environ["AWS_DEFAULT_REGION"] = st.secrets["aws"]["AWS_DEFAULT_REGION"]
    except Exception:
        pass


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
    .block-container { padding-top: 2rem; }
    .domain-header { font-size: 1.3rem; font-weight: bold; margin-top: 1.5rem; margin-bottom: 0.5rem; }
    .reasoning-box { background-color: #1e293b; padding: 1rem; border-radius: 8px;
                     border-left: 4px solid #38bdf8; margin: 0.5rem 0; font-size: 0.9rem; }
    .pass-box { border-left-color: #22c55e !important; }
    .fail-box { border-left-color: #ef4444 !important; }
    .warn-box { border-left-color: #eab308 !important; }
    .control-card { background-color: #1e293b; padding: 1rem; border-radius: 12px; margin: 0.5rem 0; }
    .framework-tag { display: inline-block; background: #334155; padding: 2px 8px; border-radius: 4px;
                     font-size: 0.75rem; margin: 2px; }
</style>
""", unsafe_allow_html=True)

# ── Load Report Data ──────────────────────────────────────────
def load_latest_report():
    root = pathlib.Path(__file__).parent.parent
    reports = sorted(glob.glob(str(root / "reports" / "comply_report_*.json")), reverse=True)
    if not reports:
        reports = sorted(glob.glob("reports/comply_report_*.json"), reverse=True)
    if not reports:
        return None
    with open(reports[0], "r") as f:
        return json.load(f)


def load_report_from_upload(uploaded_file):
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

# ── Navigation ────────────────────────────────────────────────
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigate", [
    "📊 Overview",
    "🔒 Controls Detail",
    "🔍 All Findings",
])

# ── Helper Functions ──────────────────────────────────────────
DOMAIN_ICONS = {
    "Network Security": "🌐",
    "Data Protection": "🔐",
    "Backup & Availability": "💾",
    "Identity & Access Management": "👤",
    "Source Code Management": "📝",
    "Vulnerability Management": "🛡️",
    "Access Control": "🔑",
    "General": "📋",
}

STATUS_EMOJI = {
    "PASS": "✅",
    "FAIL": "❌",
    "WARNING": "⚠️",
    "ERROR": "🔴",
    "INFO": "ℹ️",
}


def get_status_color(status):
    return {"PASS": "#22c55e", "FAIL": "#ef4444", "WARNING": "#eab308"}.get(status, "#94a3b8")


def format_frameworks(frameworks):
    if not frameworks:
        return ""
    tags = []
    for fw, controls in frameworks.items():
        for ctrl in controls:
            tags.append(f"{fw}: {ctrl}")
    return " | ".join(tags)


# ══════════════════════════════════════════════════════════════
# PAGE: OVERVIEW
# ══════════════════════════════════════════════════════════════
if page == "📊 Overview":
    st.title("🛡️ Comply.dev — Compliance Dashboard")
    st.caption(f"Scan: {summary.get('scan_timestamp', 'Unknown')}")
    st.markdown("---")

    # Top Metrics
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

    # Framework Compliance Gauges
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

    # Charts Row
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("🚨 Findings by Severity")
        severity_data = summary.get("by_severity", {})
        if severity_data:
            df_sev = pd.DataFrame([{"Severity": k, "Count": v} for k, v in severity_data.items()])
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            severity_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e", "INFO": "#94a3b8"}
            df_sev["order"] = df_sev["Severity"].map({s: i for i, s in enumerate(severity_order)})
            df_sev = df_sev.sort_values("order")
            fig_sev = px.bar(df_sev, x="Severity", y="Count", color="Severity", color_discrete_map=severity_colors)
            fig_sev.update_layout(showlegend=False, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#e2e8f0"}, height=300)
            st.plotly_chart(fig_sev, use_container_width=True)

    with chart_col2:
        st.subheader("📋 Findings by Status")
        status_data = summary.get("by_status", {})
        if status_data:
            df_status = pd.DataFrame([{"Status": k, "Count": v} for k, v in status_data.items()])
            status_colors = {"PASS": "#22c55e", "FAIL": "#ef4444", "WARNING": "#eab308", "INFO": "#94a3b8"}
            fig_status = px.pie(df_status, values="Count", names="Status", color="Status", color_discrete_map=status_colors, hole=0.4)
            fig_status.update_layout(paper_bgcolor="rgba(0,0,0,0)", font={"color": "#e2e8f0"}, height=300)
            st.plotly_chart(fig_status, use_container_width=True)

    st.markdown("---")

    # Control Domain Summary
    st.subheader("🏗️ Control Domains")
    domains = {}
    for f in findings:
        domain = f.get("control_domain", "General")
        if domain not in domains:
            domains[domain] = {"total": 0, "pass": 0, "fail": 0, "warn": 0}
        domains[domain]["total"] += 1
        if f.get("status") == "PASS":
            domains[domain]["pass"] += 1
        elif f.get("status") == "FAIL":
            domains[domain]["fail"] += 1
        elif f.get("status") == "WARNING":
            domains[domain]["warn"] += 1

    if domains:
        domain_cols = st.columns(min(len(domains), 4))
        for i, (domain, counts) in enumerate(sorted(domains.items())):
            with domain_cols[i % len(domain_cols)]:
                icon = DOMAIN_ICONS.get(domain, "📋")
                total = counts["total"]
                pass_pct = round((counts["pass"] / total) * 100) if total > 0 else 0
                st.markdown(f"### {icon} {domain}")
                st.progress(pass_pct / 100)
                st.caption(f"✅ {counts['pass']} passed | ❌ {counts['fail']} failed | ⚠️ {counts['warn']} warnings")


# ══════════════════════════════════════════════════════════════
# PAGE: CONTROLS DETAIL
# ══════════════════════════════════════════════════════════════
elif page == "🔒 Controls Detail":
    st.title("🔒 Controls Detail — Audit Evidence")
    st.caption("Each control shows its pass/fail status with detailed reasoning mapped to compliance frameworks.")
    st.markdown("---")

    # Group findings by control domain
    domains = {}
    for f in findings:
        domain = f.get("control_domain", "General")
        if domain not in domains:
            domains[domain] = []
        domains[domain].append(f)

    # Domain filter
    all_domains = sorted(domains.keys())
    selected_domains = st.multiselect(
        "Filter by Control Domain",
        options=all_domains,
        default=all_domains,
    )

    # Status filter
    show_pass = st.checkbox("Show passing controls", value=True)
    show_fail = st.checkbox("Show failing controls", value=True)
    show_warn = st.checkbox("Show warnings", value=True)

    for domain in selected_domains:
        domain_findings = domains.get(domain, [])
        if not domain_findings:
            continue

        icon = DOMAIN_ICONS.get(domain, "📋")
        domain_pass = sum(1 for f in domain_findings if f.get("status") == "PASS")
        domain_fail = sum(1 for f in domain_findings if f.get("status") == "FAIL")
        domain_warn = sum(1 for f in domain_findings if f.get("status") == "WARNING")
        domain_total = len(domain_findings)

        st.markdown(f"## {icon} {domain}")
        st.caption(f"✅ {domain_pass} passed | ❌ {domain_fail} failed | ⚠️ {domain_warn} warnings | Total: {domain_total} checks")

        # Progress bar for domain
        pass_pct = (domain_pass / domain_total) * 100 if domain_total > 0 else 0
        st.progress(pass_pct / 100)

        # Sort: FAIL first, then WARNING, then PASS
        status_order = {"FAIL": 0, "WARNING": 1, "ERROR": 2, "PASS": 3, "INFO": 4}
        sorted_findings = sorted(domain_findings, key=lambda x: status_order.get(x.get("status", "INFO"), 5))

        for f in sorted_findings:
            status = f.get("status", "UNKNOWN")
            reasoning = f.get("reasoning", "")
            title = f.get("title", "")
            resource = f.get("resource", "")
            severity = f.get("severity", "")
            remediation = f.get("remediation", "")
            check_id = f.get("check_id", "")
            frameworks = f.get("frameworks", {})

            # Apply filters
            if status == "PASS" and not show_pass:
                continue
            if status == "FAIL" and not show_fail:
                continue
            if status == "WARNING" and not show_warn:
                continue

            emoji = STATUS_EMOJI.get(status, "❓")
            color = get_status_color(status)
            css_class = "pass-box" if status == "PASS" else "fail-box" if status == "FAIL" else "warn-box"

            with st.expander(f"{emoji} **{title}** — `{resource}` [{severity}]", expanded=(status == "FAIL")):
                # Status badge row
                col_a, col_b, col_c = st.columns([1, 1, 2])
                with col_a:
                    st.markdown(f"**Check ID:** `{check_id}`")
                with col_b:
                    st.markdown(f"**Status:** :{('green' if status == 'PASS' else 'red' if status == 'FAIL' else 'orange')}[{status}]")
                with col_c:
                    st.markdown(f"**Severity:** {severity}")

                # Resource
                st.markdown(f"**Resource:** `{resource}`")

                # Framework mappings
                if frameworks:
                    fw_tags = []
                    for fw, controls in frameworks.items():
                        for ctrl in controls:
                            fw_tags.append(f"`{fw}: {ctrl}`")
                    st.markdown("**Framework Controls:** " + " ".join(fw_tags))

                # Reasoning — the key differentiator
                st.markdown("---")
                st.markdown("**📋 Audit Reasoning:**")
                if reasoning:
                    st.info(reasoning)
                else:
                    st.caption("No detailed reasoning available for this check.")

                # Remediation (for failures)
                if status in ("FAIL", "WARNING") and remediation and remediation != "No action required.":
                    st.markdown("**🔧 Remediation:**")
                    st.warning(remediation)

        st.markdown("---")


# ══════════════════════════════════════════════════════════════
# PAGE: ALL FINDINGS
# ══════════════════════════════════════════════════════════════
elif page == "🔍 All Findings":
    st.title("🔍 All Findings")
    st.markdown("---")

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

    filtered = [
        f for f in findings
        if f.get("status") in status_filter
        and f.get("severity") in severity_filter
        and (search_term.lower() in f.get("title", "").lower()
             or search_term.lower() in f.get("resource", "").lower()
             or search_term.lower() in f.get("control_domain", "").lower()
             or search_term == "")
    ]

    if filtered:
        df_findings = pd.DataFrame(filtered)
        display_cols = ["check_id", "control_domain", "title", "resource", "status", "severity", "remediation"]
        available_cols = [c for c in display_cols if c in df_findings.columns]
        st.dataframe(
            df_findings[available_cols],
            use_container_width=True,
            height=500,
        )
        st.caption(f"Showing {len(filtered)} of {len(findings)} findings")

        # Export option
        st.download_button(
            "📥 Download filtered findings as CSV",
            df_findings[available_cols].to_csv(index=False),
            "comply_findings.csv",
            "text/csv",
        )
    else:
        st.info("No findings match the current filters.")

# ── Footer ────────────────────────────────────────────────────
st.markdown("---")
st.caption("Built with ❤️ by Jonathan Riley | Comply.dev v0.2.0")
