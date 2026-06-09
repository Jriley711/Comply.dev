"""Shared configuration and helpers for the Comply.dev dashboard."""

import os
import streamlit as st

GITHUB_USERNAME = os.getenv("GITHUB_USERNAME", "Jriley711")
GITHUB_REPO     = os.getenv("GITHUB_REPO", "Comply.dev")

REPORTS_BASE_URL = (
    f"https://raw.githubusercontent.com/{GITHUB_USERNAME}/{GITHUB_REPO}"
    f"/reports-data/reports"
)

SEVERITY_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": "#E24B4A",
    "HIGH":     "#EF9F27",
    "MEDIUM":   "#378ADD",
    "LOW":      "#639922",
    "INFO":     "#888780",
}
STATUS_COLORS = {
    "PASS":    "#1D9E75",
    "FAIL":    "#E24B4A",
    "WARNING": "#EF9F27",
    "ERROR":   "#888780",
}

FRAMEWORK_LABELS = {
    "SOC2":    "SOC 2",
    "ISO27001": "ISO 27001",
    "CIS_AWS": "CIS AWS",
}


def get_secret(key: str, default: str = "") -> str:
    """Read from st.secrets first, fall back to env var."""
    try:
        return st.secrets[key]
    except (KeyError, FileNotFoundError):
        return os.getenv(key, default)


def mask(value: str) -> str:
    """Mask a secret for display — show only last 4 chars."""
    if not value:
        return "not set"
    if len(value) <= 4:
        return "****"
    return f"{'*' * (len(value) - 4)}{value[-4:]}"
