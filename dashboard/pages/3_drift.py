"""Drift page — changes between scans."""

import streamlit as st
import pandas as pd

from data import load_latest, load_previous, parse_report, compute_drift, format_scan_time
from components import severity_badge, status_badge, metric_card

st.markdown("## 📊 Compliance Drift")

with st.spinner("Loading reports…"):
    latest   = load_latest()
    previous = load_previous()

if latest is None:
    st.info("No scan report available. Run a scan first.")
    st.stop()

curr_data = parse_report(latest)
prev_data = parse_report(previous) if previous else None

col1, col2 = st.columns(2)
with col1:
    st.markdown(f"**Current scan:** {format_scan_time(curr_data['scan_time'])}")
with col2:
    if prev_data:
        st.markdown(f"**Previous scan:** {format_scan_time(prev_data['scan_time'])}")
    else:
        st.markdown("**Previous scan:** Not available")

if prev_data is None:
    st.info("No previous scan to compare against. Run a second scan to see drift.")

    st.markdown("##### Current snapshot")
    m1, m2, m3 = st.columns(3)
    with m1:
        metric_card("Score", f"{curr_data['score']}%")
    with m2:
        metric_card("Failed", str(curr_data["failed"]), color="#E24B4A")
    with m3:
        metric_card("Warnings", str(curr_data["warnings"]), color="#EF9F27")
    st.stop()

# ── Drift metrics ───────────────────────────────────────────────
drift = compute_drift(latest, previous)

score_delta = curr_data["score"] - prev_data["score"]
delta_str   = f"+{score_delta}%" if score_delta > 0 else f"{score_delta}%"
delta_color = "#1D9E75" if score_delta > 0 else "#E24B4A" if score_delta < 0 else "#888780"

m1, m2, m3, m4 = st.columns(4)
with m1:
    metric_card("Score change", delta_str, color=delta_color)
with m2:
    metric_card("New issues", str(len(drift["new"])), color="#E24B4A" if drift["new"] else "#888780")
with m3:
    metric_card("Resolved", str(len(drift["resolved"])), color="#1D9E75" if drift["resolved"] else "#888780")
with m4:
    metric_card("Persistent", str(len(drift["persistent"])))

st.markdown("<div style='margin-top:1.5rem;'></div>", unsafe_allow_html=True)

# ── Score trend ─────────────────────────────────────────────────
import plotly.graph_objects as go

trend_fig = go.Figure()
trend_fig.add_trace(go.Scatter(
    x=["Previous", "Current"],
    y=[prev_data["score"], curr_data["score"]],
    mode="lines+markers+text",
    text=[f"{prev_data['score']}%", f"{curr_data['score']}%"],
    textposition="top center",
    line=dict(color="#1D9E75" if score_delta >= 0 else "#E24B4A", width=2),
    marker=dict(size=10),
))
trend_fig.update_layout(
    height=200,
    margin=dict(t=20, b=20, l=20, r=20),
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    yaxis=dict(range=[0, 110], showgrid=False, showticklabels=False),
    xaxis=dict(showgrid=False),
    showlegend=False,
    font=dict(color="#5F5E5A", size=13),
)
st.plotly_chart(trend_fig, use_container_width=True, config={"displayModeBar": False})

st.markdown("---")

# ── New issues ──────────────────────────────────────────────────
curr_df = curr_data["df"]

if drift["new"]:
    st.markdown(f"##### 🔴 New issues ({len(drift['new'])})")
    new_ids = {(cid, res) for cid, res in drift["new"]}
    new_df  = curr_df[curr_df.apply(
        lambda r: (r.get("check_id",""), r.get("resource","")) in new_ids, axis=1
    )] if not curr_df.empty else pd.DataFrame()

    if not new_df.empty:
        for _, row in new_df.iterrows():
            c1, c2, c3, c4 = st.columns([3, 1, 1, 2])
            with c1:
                st.markdown(f"<span style='font-size:13px;font-weight:500;'>{row.get('title','')}</span>", unsafe_allow_html=True)
            with c2:
                st.markdown(status_badge(row.get("status","")), unsafe_allow_html=True)
            with c3:
                st.markdown(severity_badge(row.get("severity","INFO")), unsafe_allow_html=True)
            with c4:
                st.markdown(f"<span style='font-size:12px;color:#888780;'>{row.get('resource','')}</span>", unsafe_allow_html=True)
    st.markdown("")

# ── Resolved ────────────────────────────────────────────────────
if drift["resolved"]:
    st.markdown(f"##### ✅ Resolved ({len(drift['resolved'])})")
    prev_df = prev_data["df"]
    res_ids = {(cid, res) for cid, res in drift["resolved"]}
    res_df  = prev_df[prev_df.apply(
        lambda r: (r.get("check_id",""), r.get("resource","")) in res_ids, axis=1
    )] if not prev_df.empty else pd.DataFrame()

    if not res_df.empty:
        for _, row in res_df.iterrows():
            c1, c2 = st.columns([4, 2])
            with c1:
                st.markdown(f"<span style='font-size:13px;color:#888780;text-decoration:line-through;'>{row.get('title','')}</span>", unsafe_allow_html=True)
            with c2:
                st.markdown(f"<span style='font-size:12px;color:#888780;'>{row.get('resource','')}</span>", unsafe_allow_html=True)

if not drift["new"] and not drift["resolved"]:
    st.success("No changes between scans. Compliance posture is stable.")
