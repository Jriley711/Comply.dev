"""Findings page — filterable, searchable findings table with drill-down."""

import streamlit as st
import pandas as pd

from dashboard.data import load_latest, load_from_upload, parse_report, format_scan_time
from dashboard.components import finding_expander, severity_badge, status_badge, metric_card
from dashboard.config import SEVERITY_ORDER, SEVERITY_COLORS, STATUS_COLORS

st.markdown("## 🔍 Findings")

# ── Source selector ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("---")
    st.markdown("**Data source**")
    source = st.radio(
        "source",
        ["Latest scan", "Upload report"],
        label_visibility="collapsed",
    )
    uploaded = None
    if source == "Upload report":
        uploaded = st.file_uploader("Upload JSON report", type=["json"], label_visibility="collapsed")

# ── Load data ───────────────────────────────────────────────────
if source == "Upload report" and uploaded:
    report = load_from_upload(uploaded.read())
elif source == "Latest scan":
    with st.spinner("Loading…"):
        report = load_latest()
else:
    report = None

if report is None:
    st.info("No report loaded. Select a data source in the sidebar.")
    st.stop()

data = parse_report(report)
df   = data["df"]

if df.empty:
    st.warning("No findings in this report.")
    st.stop()

st.caption(f"Scan: {format_scan_time(data['scan_time'])}  ·  {data['total']} total checks")

# ── Filters ─────────────────────────────────────────────────────
f1, f2, f3, f4 = st.columns(4)

with f1:
    status_opts = ["All"] + sorted(df["status"].unique().tolist()) if "status" in df.columns else ["All"]
    status_filter = st.selectbox("Status", status_opts)

with f2:
    sev_opts = ["All"] + [s for s in SEVERITY_ORDER if s in df.get("severity", pd.Series()).unique()]
    sev_filter = st.selectbox("Severity", sev_opts)

with f3:
    domain_opts = ["All"]
    if "control_domain" in df.columns:
        domain_opts += sorted(df["control_domain"].dropna().unique().tolist())
    domain_filter = st.selectbox("Domain", domain_opts)

with f4:
    search = st.text_input("Search", placeholder="title, resource, check ID…")

# ── Apply filters ───────────────────────────────────────────────
filtered = df.copy()

if status_filter != "All" and "status" in filtered.columns:
    filtered = filtered[filtered["status"] == status_filter]

if sev_filter != "All" and "severity" in filtered.columns:
    filtered = filtered[filtered["severity"] == sev_filter]

if domain_filter != "All" and "control_domain" in filtered.columns:
    filtered = filtered[filtered["control_domain"] == domain_filter]

if search:
    mask = pd.Series(False, index=filtered.index)
    for col in ("title", "resource", "check_id"):
        if col in filtered.columns:
            mask |= filtered[col].astype(str).str.contains(search, case=False, na=False)
    filtered = filtered[mask]

# ── Summary metrics ─────────────────────────────────────────────
st.markdown(f"<div style='margin-bottom:1rem;font-size:13px;color:#888780;'>{len(filtered)} findings shown</div>", unsafe_allow_html=True)

m1, m2, m3, m4 = st.columns(4)
with m1:
    metric_card("Showing", str(len(filtered)))
with m2:
    fails = int(filtered["status"].eq("FAIL").sum()) if "status" in filtered.columns else 0
    metric_card("Failed", str(fails), color="#E24B4A")
with m3:
    crits = int((filtered["status"].eq("FAIL") & filtered["severity"].eq("CRITICAL")).sum()) if {"status","severity"}.issubset(filtered.columns) else 0
    metric_card("Critical", str(crits), color="#E24B4A")
with m4:
    passes = int(filtered["status"].eq("PASS").sum()) if "status" in filtered.columns else 0
    metric_card("Passed", str(passes), color="#1D9E75")

st.markdown("<div style='margin-top:1rem;'></div>", unsafe_allow_html=True)

# ── View toggle ─────────────────────────────────────────────────
view = st.radio("View", ["Detailed", "Table"], horizontal=True, label_visibility="collapsed")

if view == "Detailed":
    # Group by domain
    if "control_domain" in filtered.columns:
        for domain, group in filtered.groupby("control_domain", sort=True):
            fail_count = int(group["status"].eq("FAIL").sum()) if "status" in group.columns else 0
            icon = "🔴" if fail_count > 0 else "🟢"
            st.markdown(f"**{icon} {domain}** — {len(group)} checks, {fail_count} failures")
            for _, row in group.iterrows():
                finding_expander(row)
            st.markdown("")
    else:
        for _, row in filtered.iterrows():
            finding_expander(row)

else:
    # Clean table view
    table_cols = [c for c in ["check_id", "title", "resource", "status", "severity", "control_domain"] if c in filtered.columns]
    st.dataframe(
        filtered[table_cols].reset_index(drop=True),
        use_container_width=True,
        height=500,
        column_config={
            "check_id":      st.column_config.TextColumn("Check ID", width="small"),
            "title":         st.column_config.TextColumn("Title", width="large"),
            "resource":      st.column_config.TextColumn("Resource", width="medium"),
            "status":        st.column_config.TextColumn("Status", width="small"),
            "severity":      st.column_config.TextColumn("Severity", width="small"),
            "control_domain":st.column_config.TextColumn("Domain", width="medium"),
        },
    )
