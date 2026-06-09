"""Data loading and parsing for the Comply.dev dashboard."""

import json
import logging
import requests
import streamlit as st
import pandas as pd
from datetime import datetime, timezone

from config import REPORTS_BASE_URL, SEVERITY_ORDER

logger = logging.getLogger(__name__)


@st.cache_data(ttl=120, show_spinner=False)
def fetch_report(url: str) -> dict | None:
    """Fetch a JSON report from a URL. Returns None on any failure."""
    try:
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None


def load_latest() -> dict | None:
    return fetch_report(f"{REPORTS_BASE_URL}/latest.json")


def load_previous() -> dict | None:
    return fetch_report(f"{REPORTS_BASE_URL}/previous.json")


def load_from_upload(raw_bytes: bytes) -> dict | None:
    try:
        return json.loads(raw_bytes)
    except Exception:
        return None


def parse_report(report: dict) -> dict:
    """Parse a raw report dict into structured data ready for the UI."""
    findings = report.get("findings", [])
    scan_time = report.get("scan_time", "")

    df = pd.DataFrame(findings) if findings else pd.DataFrame()

    if df.empty:
        return {
            "df": df,
            "findings": [],
            "scan_time": scan_time,
            "summary": {},
            "score": 0,
            "total": 0,
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "critical": 0,
            "framework_summary": {},
        }

    # Normalise HTML entities
    for col in ("control_domain", "title"):
        if col in df.columns:
            df[col] = df[col].str.replace("&amp;", "&", regex=False)

    total    = len(df)
    passed   = int(df["status"].eq("PASS").sum()) if "status" in df.columns else 0
    failed   = int(df["status"].eq("FAIL").sum()) if "status" in df.columns else 0
    warnings = int(df["status"].eq("WARNING").sum()) if "status" in df.columns else 0
    critical = int(
        (df["status"].eq("FAIL") & df["severity"].eq("CRITICAL")).sum()
    ) if {"status", "severity"}.issubset(df.columns) else 0
    score = round(passed / total * 100) if total > 0 else 0

    summary = report.get("summary", {})
    fw_summary = summary.get("framework_compliance", {})

    return {
        "df": df,
        "findings": findings,
        "scan_time": scan_time,
        "summary": summary,
        "score": score,
        "total": total,
        "passed": passed,
        "failed": failed,
        "warnings": warnings,
        "critical": critical,
        "framework_summary": fw_summary,
    }


def compute_drift(current: dict, previous: dict) -> dict:
    """Compare two reports and return new / resolved / persistent finding sets."""
    if not previous:
        return {"new": set(), "resolved": set(), "persistent": set()}

    curr_set = {
        (f["check_id"], f.get("resource", ""))
        for f in current.get("findings", [])
    }
    prev_set = {
        (f["check_id"], f.get("resource", ""))
        for f in previous.get("findings", [])
    }

    return {
        "new":        curr_set - prev_set,
        "resolved":   prev_set - curr_set,
        "persistent": curr_set & prev_set,
    }


def format_scan_time(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%B %d, %Y at %H:%M UTC")
    except Exception:
        return iso or "Unknown"
