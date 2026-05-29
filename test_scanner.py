"""Comply.dev — Streamlit Compliance Dashboard."""

import os
import json
import requests
from datetime import datetime

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# ── Secrets helper ──────────────────────────────────────────
def get_secret(key: str, default: str = "") -> str:
    try:
        return st.secrets[key]
    except (KeyError, FileNotFoundError):
        return os.getenv(key, default)

AWS_ACCESS_KEY_ID = get_secret("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = get_secret("AWS_SECRET_ACCESS_KEY")
AWS_DEFAULT_REGION = get_secret("AWS_DEFAULT_REGION", "us-east-1")
GITHUB_TOKEN = get_secret("GITHUB_TOKEN")
GITHUB_REPOS = get_secret("GITHUB_REPOS")
GH_USERNAME = get_secret("GITHUB_USERNAME", "Jriley711")
GH_REPO = get_secret("GITHUB_REPO", "Comply.dev")

REPORT_URL = (
    f"https://raw.githubusercontent.com/{GH_USERNAME}/{GH_REPO}"
    f"/reports-data/reports/latest.json"
)

# ── Page config ─────────────────────────────────────────────
st.set_page_config(page_title="Comply.dev", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

SEV_COLORS = {"CRITICAL": "#f85149", "HIGH": "#db6d28", "MEDIUM": "#d29922", "LOW": "#3fb950", "INFO": "#58a6ff"}
STATUS_COLORS = {"FAIL": "#f85149", "PASS": "#3fb950", "WARNING": "#d29922"}

# ── Data loading ────────────────────────────────────────────
@st.cache_data(ttl=3600)
def load_report_from_github() -> dict | None:
    try:
        resp = requests.get(REPORT_URL, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError:
        return None
    except Exception:
        return None

def load_report_from_upload(uploaded_bytes: bytes) -> dict | None:
    try:
        return json.loads(uploaded_bytes)
    except json.JSONDecodeError:
        st.error("Invalid JSON file.")
        return None

def run_live_scan() -> dict | None:
    import boto3
    from comply.scanner import ComplyScanner
    try:
        session = boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_DEFAULT_REGION,
        )
        gh_repos = [r.strip() for r in GITHUB_REPOS.split(",")] if GITHUB_REPOS else []
        scanner = ComplyScanner(aws_session=session, github_token=GITHUB_TOKEN, github_repos=gh_repos)
        results = scanner.run_full_scan()
        return {
            "scan_time": datetime.utcnow().isoformat(),
            "findings": results["findings"],
            "framework_summary": {},
        }
    except Exception as e:
        st.error(f"Scan failed: {e}")
        return None

# ── Sidebar ─────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ Comply.dev")
    st.caption("Cloud Compliance Scanner")
    st.divider()
    data_source = st.radio("Data Source", ["Latest scan (GitHub)", "Upload report", "Run live scan"])
    uploaded_file = None
    if data_source == "Upload report":
        uploaded_file = st.file_uploader("Upload JSON report", type=["json"])

# ── Load data ───────────────────────────────────────────────
report = None

if data_source == "Latest scan (GitHub)":
    with st.spinner("Loading latest scan from GitHub..."):
        report = load_report_from_github()
    if report is None:
        st.info("No scan report found yet. Run the GitHub Actions workflow to generate one.", icon="ℹ️")

elif data_source == "Upload report":
    if uploaded_file:
        report = load_report_from_upload(uploaded_file.read())
    else:
        st.info("Upload a JSON report file from the sidebar.", icon="ℹ️")

elif data_source == "Run live scan":
    scan_pw = get_secret("SCAN_PASSWORD", "comply2026")
    pw_input = st.text_input("Scan password", type="password")
    if st.button("▶ Run scan now", type="primary"):
        if pw_input == scan_pw:
            with st.spinner("Running compliance scan... this takes 30-60 seconds."):
                report = run_live_scan()
            if report:
                st.success("Scan complete!")
        else:
            st.error("Incorrect password.")

# ── Dashboard ───────────────────────────────────────────────
if report:
    findings = report.get("findings", [])
    scan_time = report.get("scan_time", "Unknown")
    df = pd.DataFrame(findings)

    # Scan info banner
    st.info(f"📅 **Scan Time:** {scan_time}  |  📊 **Total Findings:** {len(findings)}", icon="🛡️")

    # KPI metrics
    total = len(findings)
    passed = sum(1 for f in findings if f.get("status") == "PASS")
    failed = sum(1 for f in findings if f.get("status") == "FAIL")
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL" and f.get("status") == "FAIL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH" and f.get("status") == "FAIL")
    pass_rate = round((passed / total) * 100, 1) if total > 0 else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Findings", total)
    c2.metric("Pass Rate", f"{pass_rate}%")
    c3.metric("Critical Failures", critical)
    c4.metric("High Failures", high)

    # Framework compliance gauges
    fw_summary = report.get("framework_summary", {})
    if not fw_summary and findings:
        from comply.frameworks.mappings import get_framework_summary
        fw_summary = get_framework_summary(findings)

    if fw_summary:
        st.subheader("📊 Framework Compliance")
        fw_cols = st.columns(len(fw_summary))
        for i, (key, data) in enumerate(fw_summary.items()):
            score = data.get("compliance_score", 0)
            color = "#3fb950" if score >= 80 else "#d29922" if score >= 50 else "#f85149"
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                title={"text": data.get("name", key), "font": {"size": 14, "color": "#c9d1d9"}},
                number={"suffix": "%", "font": {"color": color}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#30363d"},
                    "bar": {"color": color},
                    "bgcolor": "#161b22",
                    "bordercolor": "#30363d",
                    "steps": [
                        {"range": [0, 50], "color": "#f8514922"},
                        {"range": [50, 80], "color": "#d2992222"},
                        {"range": [80, 100], "color": "#3fb95022"},
                    ],
                },
            ))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#c9d1d9"}, height=250, margin=dict(l=20, r=20, t=60, b=20),
            )
            fw_cols[i].plotly_chart(fig, use_container_width=True)
            fw_cols[i].caption(f"{data.get('controls_passed', 0)}/{data.get('controls_tested', 0)} controls passed")

    # Charts row
    if not df.empty:
        col_a, col_b = st.columns(2)

        # Severity donut
        with col_a:
            st.subheader("🚨 Severity Breakdown")
            sev_counts = df["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            sev_counts["Severity"] = pd.Categorical(sev_counts["Severity"], categories=sev_order, ordered=True)
            sev_counts = sev_counts.sort_values("Severity").dropna()
            colors = [SEV_COLORS.get(s, "#888") for s in sev_counts["Severity"]]
            fig_sev = px.pie(sev_counts, names="Severity", values="Count", hole=0.4,
                             color_discrete_sequence=colors, template="plotly_dark")
            fig_sev.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=350)
            st.plotly_chart(fig_sev, use_container_width=True)

        # Domain bar chart
        with col_b:
            st.subheader("📂 Control Domains")
            if "control_domain" in df.columns:
                domain_df = df.groupby(["control_domain", "status"]).size().reset_index(name="Count")
                colors_map = {"FAIL": "#f85149", "PASS": "#3fb950", "WARNING": "#d29922"}
                fig_dom = px.bar(domain_df, x="control_domain", y="Count", color="status",
                                 color_discrete_map=colors_map, template="plotly_dark",
                                 barmode="stack")
                fig_dom.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                      xaxis_title="", yaxis_title="Findings", height=350)
                st.plotly_chart(fig_dom, use_container_width=True)

    # Findings explorer
    st.divider()
    st.subheader("🔍 Findings Explorer")

    if not df.empty:
        fc1, fc2, fc3 = st.columns(3)
        statuses = fc1.multiselect("Status", df["status"].unique().tolist(), default=df["status"].unique().tolist())
        severities = fc2.multiselect("Severity", df["severity"].unique().tolist(), default=df["severity"].unique().tolist())
        domains = df["control_domain"].unique().tolist() if "control_domain" in df.columns else []
        selected_domains = fc3.multiselect("Domain", domains, default=domains)

        filtered = df[
            df["status"].isin(statuses) &
            df["severity"].isin(severities) &
            (df["control_domain"].isin(selected_domains) if "control_domain" in df.columns else True)
        ]

        st.caption(f"Showing {len(filtered)} of {len(df)} findings")

        for _, row in filtered.iterrows():
            status_emoji = "❌" if row["status"] == "FAIL" else "✅" if row["status"] == "PASS" else "⚠️"
            label = f"{status_emoji} {row.get('check_id', '')} — {row.get('title', '')}"
            with st.expander(label):
                sc1, sc2, sc3 = st.columns([1, 1, 2])
                sc1.markdown(f"**Status:** `{row['status']}`")
                sc2.markdown(f"**Severity:** `{row['severity']}`")
                sc3.markdown(f"**Resource:** `{row.get('resource', 'N/A')}`")

                st.markdown(f"**Description:** {row.get('description', '')}")

                if row["status"] != "PASS":
                    st.markdown(f"**Remediation:** {row.get('remediation', '')}")

                frameworks = row.get("frameworks", {})
                if frameworks and isinstance(frameworks, dict):
                    fw_str = " | ".join(f"**{k}:** {', '.join(v)}" for k, v in frameworks.items())
                    st.markdown(f"**Frameworks:** {fw_str}")

                reasoning = row.get("reasoning", "")
                if reasoning:
                    st.info(reasoning, icon="🧠")
    else:
        st.info("No findings to display.")
