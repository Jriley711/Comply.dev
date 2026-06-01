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
import plotly.graph_objects as go


# ─────────────────────────────────────────────────────────────
# Secrets helper
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


# ✅ DEBUG (leave this for now)
st.write("DEBUG: Report loaded?", report is not None)

if report:
    st.write("DEBUG: Findings count:", len(report.get("findings", [])))

