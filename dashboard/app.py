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

def get_secret(key: str, default: str = "") -> str:
    try:
        return st.secrets[key]
    except (KeyError, FileNotFoundError):
        return os.getenv(key, default)


AWS_ACCESS_KEY_ID     = get_secret("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = get_secret("AWS_SECRET_ACCESS_KEY")
AWS_DEFAULT_REGION    = get_secret("AWS_DEFAULT_REGION", "us-east-1")
