"""Frameworks page — per-framework compliance detail."""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from data import load_latest, parse_report, format_scan_time
from components import severity_badge, status_badge, metric_card
from config import FRAMEWORK_LABELS

st.markdown("## 📋 Framework Compliance")

with st.spinner("Loading…"):
    report = load_latest()

if report is None:
    st.info("No report available. Run a scan first.")
    st.stop()

data = parse_report(report)
df   = data["df"]
fw_summary = data["framework_summary"]

st.caption(f"Scan: {format_scan_time(data['scan_time'])}")

if not fw_summary:
    st.warning("Framework summary not in this report. Re-run a scan to generate it.")
    st.stop()

# ── Framework selector ──────────────────────────────────────────
fw_options = {FRAMEWORK_LABELS.get(k, k): k for k in fw_summary}
selected_label = st.selectbox("Select framework", list(fw_options.keys()))
selected_key   = fw_options[selected_label]
fw_data        = fw_summary[selected_key]

# ── Framework header ────────────────────────────────────────────
score = fw_data.get("compliance_score", 0)
score_color = "#1D9E75" if score >= 80 else "#EF9F27" if score >= 50 else "#E24B4A"

h1, h2, h3, h4 = st.columns(4)
with h1:
    metric_card("Score", f"{score}%", color=score_color)
with h2:
    metric_card("Controls tested", str(fw_data.get("controls_tested", 0)))
with h3:
    metric_card("Controls passed", str(fw_data.get("controls_passed", 0)), color="#1D9E75")
with h4:
    metric_card("Controls failed", str(fw_data.get("controls_failed", 0)), color="#E24B4A")

st.markdown("<div style='margin-top:1rem;'></div>", unsafe_allow_html=True)
st.progress(score / 100)
st.markdown("<div style='margin-bottom:1.5rem;'></div>", unsafe_allow_html=True)

# ── Findings for this framework ─────────────────────────────────
if not df.empty and "frameworks" in df.columns:
    fw_findings = df[df["frameworks"].apply(
        lambda x: selected_key in x if isinstance(x, dict) else False
    )].copy()

    if fw_findings.empty:
        st.info("No findings mapped to this framework in the current report.")
        st.stop()

    # Extract the specific controls that fired
    def extract_controls(row):
        fws = row.get("frameworks", {})
        if isinstance(fws, dict):
            return ", ".join(fws.get(selected_key, []))
        return ""

    fw_findings["matched_controls"] = fw_findings.apply(extract_controls, axis=1)

    # Group by control
    st.markdown("##### Findings by control")

    all_controls = set()
    for controls in fw_findings["matched_controls"]:
        for c in controls.split(", "):
            if c:
                all_controls.add(c.strip())

    for control in sorted(all_controls):
        control_findings = fw_findings[fw_findings["matched_controls"].str.contains(control, na=False)]
        fails = int(control_findings["status"].eq("FAIL").sum()) if "status" in control_findings.columns else 0
        icon  = "❌" if fails > 0 else "✅"

        with st.expander(f"{icon}  **{selected_label} {control}** — {len(control_findings)} checks, {fails} failures"):
            for _, row in control_findings.iterrows():
                c1, c2, c3 = st.columns([3, 1, 1])
                with c1:
                    st.markdown(f"<span style='font-size:13px;'>{row.get('title','')}</span>", unsafe_allow_html=True)
                with c2:
                    st.markdown(status_badge(row.get("status","")), unsafe_allow_html=True)
                with c3:
                    st.markdown(severity_badge(row.get("severity","INFO")), unsafe_allow_html=True)
                if row.get("status") == "FAIL" and row.get("remediation"):
                    st.markdown(
                        f"<div style='font-size:12px;color:#5F5E5A;margin-left:0;padding:6px 0;'>"
                        f"↳ {row['remediation']}</div>",
                        unsafe_allow_html=True,
                    )
                st.markdown("<hr style='margin:4px 0;border-color:#F1EFE8;'>", unsafe_allow_html=True)
else:
    st.info("Findings data not available for framework breakdown.")
