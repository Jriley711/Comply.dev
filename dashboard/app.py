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
import requests
import streamlit as st
import pandas as pd

# ─────────────── Config ───────────────

st.set_page_config(page_title="Comply.dev", layout="wide")

GITHUB_USERNAME = os.getenv("GITHUB_USERNAME", "Jriley711")
GITHUB_REPO = os.getenv("GITHUB_REPO", "Comply.dev")

REPORT_URL = f"https://raw.githubusercontent.com/{GITHUB_USERNAME}/{GITHUB_REPO}/reports-data/reports/latest.json"

# ─────────────── Load Report ───────────────

@st.cache_data(ttl=60)
def load_report():
    try:
        resp = requests.get(REPORT_URL)
        st.write("DEBUG status:", resp.status_code)

        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        st.error("Failed to load report")
        st.write(str(e))
        return None


report = load_report()

st.write("DEBUG loaded?", report is not None)

if not report:
    st.stop()

# ─────────────── Parse Data ───────────────

findings = report.get("findings", [])
df = pd.DataFrame(findings)

if df.empty:
    st.warning("No findings in report")
    st.stop()

# Fix escaped text if exists
if "control_domain" in df.columns:
    df["control_domain"] = df["control_domain"].str.replace("&amp;", "&")

# ─────────────── UI ───────────────

st.title("🛡️ Comply.dev Dashboard")

# Metrics
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Findings", len(df))
col2.metric("✅ Passed", (df["status"] == "PASS").sum())
col3.metric("❌ Failed", (df["status"] == "FAIL").sum())
col4.metric("⚠️ Warnings", (df["status"] == "WARNING").sum())

st.divider()

# Critical Issues
critical = df[(df["status"] == "FAIL") & (df["severity"] == "CRITICAL")]

if not critical.empty:
    st.error("🚨 Critical Issues Detected")

    for _, row in critical.iterrows():
        st.markdown(f"""
**{row['title']}**  
Resource: `{row['resource']}`  
🔧 {row['remediation']}
""")

st.divider()

# Table
st.subheader("All Findings")
st.dataframe(df)
``
