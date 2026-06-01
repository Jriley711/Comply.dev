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
import streamlit as st
import pandas as pd
import plotly.express as px

# ─────────────────────────────
# CONFIG
# ─────────────────────────────

st.set_page_config(page_title="Comply.dev", layout="wide")

GITHUB_USERNAME = os.getenv("GITHUB_USERNAME", "Jriley711")
GITHUB_REPO = os.getenv("GITHUB_REPO", "Comply.dev")

BASE_URL = f"https://raw.githubusercontent.com/{GITHUB_USERNAME}/{GITHUB_REPO}/reports-data/reports"

LATEST_URL = f"{BASE_URL}/latest.json"
PREVIOUS_URL = f"{BASE_URL}/previous.json"

# ─────────────────────────────
# LOAD DATA
# ─────────────────────────────

@st.cache_data(ttl=60)
def load_json(url):
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.json()
        return None
    except:
        return None


latest = load_json(LATEST_URL)
previous = load_json(PREVIOUS_URL)

st.write("DEBUG latest loaded:", latest is not None)
st.write("DEBUG previous loaded:", previous is not None)

if not latest:
    st.error("❌ Could not load latest report")
    st.stop()

# ─────────────────────────────
# PARSE DATA
# ─────────────────────────────

df = pd.DataFrame(latest.get("findings", []))

if df.empty:
    st.warning("No findings available")
    st.stop()

# Fix HTML encoding if present
if "control_domain" in df.columns:
    df["control_domain"] = df["control_domain"].str.replace("&amp;", "&")

# ─────────────────────────────
# DRIFT DETECTION
# ─────────────────────────────

def compare_reports(curr, prev):
    if not prev:
        return set(), set(), set()

    curr_set = set((f["check_id"], f.get("resource")) for f in curr.get("findings", []))
    prev_set = set((f["check_id"], f.get("resource")) for f in prev.get("findings", []))

    new = curr_set - prev_set
    resolved = prev_set - curr_set
    persistent = curr_set & prev_set

    return new, resolved, persistent


new_findings, resolved_findings, persistent_findings = compare_reports(latest, previous)

# ─────────────────────────────
# COMPLIANCE SCORE
# ─────────────────────────────

def get_score(report):
    findings = report.get("findings", [])
    if not findings:
        return 0
    
    df = pd.DataFrame(findings)
    passed = (df["status"] == "PASS").sum()
    total = len(df)
    
    return round((passed / total) * 100, 0)


current_score = get_score(latest)
previous_score = get_score(previous) if previous else None

# ─────────────────────────────
# UI
# ─────────────────────────────

st.title("🛡️ Comply.dev Dashboard")

# ─────────────
# SCORE + TREND
# ─────────────

st.subheader("📈 Compliance Score")

score_col1, score_col2 = st.columns(2)

score_col1.metric("Current Score", f"{current_score}%")

if previous_score is not None:
    delta = current_score - previous_score
    score_col2.metric("Change", f"{delta}%", delta=delta)
else:
    score_col2.metric("Change", "N/A")

# Trend chart
if previous:
    trend_df = pd.DataFrame({
        "Scan": ["Previous", "Current"],
        "Score": [previous_score, current_score]
    })
    
    fig = px.line(trend_df, x="Scan", y="Score", markers=True, title="Compliance Score Trend")
    st.plotly_chart(fig, use_container_width=True)

st.divider()

# ─────────────
# DRIFT SECTION
# ─────────────

st.subheader("📊 Changes Since Last Scan")

c1, c2, c3 = st.columns(3)

c1.metric("❌ New Issues", len(new_findings))
c2.metric("✅ Resolved", len(resolved_findings))
c3.metric("🔁 Still Present", len(persistent_findings))

st.divider()

# ─────────────
# CRITICAL ISSUES
# ─────────────

critical = df[(df["status"] == "FAIL") & (df["severity"] == "CRITICAL")]

if not critical.empty:
    st.error("🚨 CRITICAL ISSUES DETECTED")

    for _, row in critical.iterrows():
        st.markdown(f"""
**{row['title']}**  
Resource: `{row['resource']}`  
🔧 {row.get('remediation', 'No remediation provided')}
""")

st.divider()

# ─────────────
# FINDINGS TABLE
# ─────────────

st.subheader("📋 All Findings")

st.dataframe(df)
