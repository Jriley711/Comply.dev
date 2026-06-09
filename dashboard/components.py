"""Reusable UI components for the Comply.dev dashboard."""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

from config import SEVERITY_COLORS, STATUS_COLORS, SEVERITY_ORDER, FRAMEWORK_LABELS


def score_gauge(score: int, label: str = "Compliance Score") -> go.Figure:
    color = "#1D9E75" if score >= 80 else "#EF9F27" if score >= 50 else "#E24B4A"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"suffix": "%", "font": {"size": 48, "color": color}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#B4B2A9"},
            "bar": {"color": color, "thickness": 0.25},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 50],  "color": "#FCEBEB"},
                {"range": [50, 80], "color": "#FAEEDA"},
                {"range": [80, 100],"color": "#EAF3DE"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.75,
                "value": score,
            },
        },
        title={"text": label, "font": {"size": 14, "color": "#888780"}},
    ))
    fig.update_layout(
        height=220,
        margin=dict(t=40, b=0, l=20, r=20),
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#2C2C2A",
    )
    return fig


def severity_bar_chart(df: pd.DataFrame) -> go.Figure:
    counts = {s: 0 for s in SEVERITY_ORDER}
    if "severity" in df.columns:
        for s, c in df["severity"].value_counts().items():
            if s in counts:
                counts[s] = c

    fig = go.Figure(go.Bar(
        x=list(counts.keys()),
        y=list(counts.values()),
        marker_color=[SEVERITY_COLORS.get(s, "#888780") for s in counts],
        text=list(counts.values()),
        textposition="outside",
    ))
    fig.update_layout(
        height=220,
        margin=dict(t=10, b=10, l=0, r=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        yaxis=dict(showgrid=False, showticklabels=False),
        xaxis=dict(showgrid=False),
        font=dict(color="#5F5E5A", size=12),
    )
    return fig


def framework_scores_chart(fw_summary: dict) -> go.Figure:
    if not fw_summary:
        return None

    labels = [FRAMEWORK_LABELS.get(k, k) for k in fw_summary]
    scores = [v.get("compliance_score", 0) for v in fw_summary.values()]
    colors = ["#1D9E75" if s >= 80 else "#EF9F27" if s >= 50 else "#E24B4A" for s in scores]

    fig = go.Figure(go.Bar(
        x=labels,
        y=scores,
        marker_color=colors,
        text=[f"{s}%" for s in scores],
        textposition="outside",
    ))
    fig.update_layout(
        height=240,
        yaxis=dict(range=[0, 110], showgrid=False, showticklabels=False),
        xaxis=dict(showgrid=False),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=10, b=10, l=0, r=0),
        font=dict(color="#5F5E5A", size=13),
        showlegend=False,
    )
    return fig


def status_donut(passed: int, failed: int, warnings: int) -> go.Figure:
    labels = ["Pass", "Fail", "Warning"]
    values = [passed, failed, warnings]
    colors = [STATUS_COLORS["PASS"], STATUS_COLORS["FAIL"], STATUS_COLORS["WARNING"]]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.65,
        marker_colors=colors,
        textinfo="none",
        hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
    ))
    fig.update_layout(
        height=220,
        margin=dict(t=10, b=10, l=10, r=10),
        paper_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend=dict(orientation="h", x=0.5, xanchor="center", y=-0.05, font=dict(size=11)),
        font=dict(color="#5F5E5A"),
    )
    return fig


def severity_badge(severity: str) -> str:
    bg = {
        "CRITICAL": "#FCEBEB", "HIGH": "#FAEEDA",
        "MEDIUM": "#E6F1FB", "LOW": "#EAF3DE", "INFO": "#F1EFE8",
    }
    fg = {
        "CRITICAL": "#A32D2D", "HIGH": "#854F0B",
        "MEDIUM": "#185FA5", "LOW": "#3B6D11", "INFO": "#5F5E5A",
    }
    b = bg.get(severity, "#F1EFE8")
    f = fg.get(severity, "#5F5E5A")
    return f'<span style="background:{b};color:{f};padding:2px 8px;border-radius:12px;font-size:11px;font-weight:500;">{severity}</span>'


def status_badge(status: str) -> str:
    bg = {"PASS": "#EAF3DE", "FAIL": "#FCEBEB", "WARNING": "#FAEEDA", "ERROR": "#F1EFE8"}
    fg = {"PASS": "#3B6D11", "FAIL": "#A32D2D", "WARNING": "#854F0B", "ERROR": "#5F5E5A"}
    b = bg.get(status, "#F1EFE8")
    f = fg.get(status, "#5F5E5A")
    return f'<span style="background:{b};color:{f};padding:2px 8px;border-radius:12px;font-size:11px;font-weight:500;">{status}</span>'


def metric_card(label: str, value: str, delta: str = None, color: str = None):
    delta_html = ""
    if delta is not None:
        delta_color = "#1D9E75" if str(delta).startswith("+") else "#E24B4A" if str(delta).startswith("-") else "#888780"
        delta_html = f'<div style="font-size:12px;color:{delta_color};margin-top:2px;">{delta}</div>'
    val_color = color or "var(--text-color, #2C2C2A)"
    st.markdown(f"""
    <div style="background:var(--background-color,#F1EFE8);border-radius:8px;padding:14px 16px;">
        <div style="font-size:12px;color:#888780;margin-bottom:4px;">{label}</div>
        <div style="font-size:24px;font-weight:500;color:{val_color};">{value}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)


def finding_expander(row: pd.Series):
    """Render a single finding as a styled expander."""
    status  = row.get("status", "")
    sev     = row.get("severity", "INFO")
    title   = row.get("title", "Unknown check")
    resource = row.get("resource", "—")

    icon = {"PASS": "✅", "FAIL": "❌", "WARNING": "⚠️", "ERROR": "⚙️"}.get(status, "•")
    label = f"{icon}  {title}"

    with st.expander(label, expanded=False):
        c1, c2, c3 = st.columns(3)
        c1.markdown(status_badge(status), unsafe_allow_html=True)
        c2.markdown(severity_badge(sev), unsafe_allow_html=True)
        c3.markdown(f"<span style='font-size:12px;color:#888780;'>{resource}</span>", unsafe_allow_html=True)

        st.markdown("---")
        desc = row.get("description", "")
        if desc:
            st.markdown(f"**Description**\n\n{desc}")

        remediation = row.get("remediation", "")
        if remediation and status != "PASS":
            st.markdown(f"**Remediation**\n\n{remediation}")

        reasoning = row.get("reasoning", "")
        if reasoning:
            with st.expander("Audit reasoning", expanded=False):
                st.markdown(f"<div style='font-size:13px;color:#5F5E5A;line-height:1.6;'>{reasoning}</div>", unsafe_allow_html=True)

        frameworks = row.get("frameworks", {})
        if frameworks:
            tags = []
            for fw, controls in frameworks.items():
                label_fw = FRAMEWORK_LABELS.get(fw, fw)
                for c in controls:
                    tags.append(f"`{label_fw} {c}`")
            st.markdown("**Framework controls:** " + "  ".join(tags))
