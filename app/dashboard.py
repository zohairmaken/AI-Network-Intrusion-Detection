# =============================================================================
# app/dashboard.py
# Dashboard UI components — charts, stat cards, tables for Streamlit
# =============================================================================

import time
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

from config.constants import ALL_CLASSES
from config.config import SEVERITY_COLORS
from config.config import CHART_HEIGHT

# ─── Color constants ──────────────────────────────────────────────────────────
BG       = "#0a0e1a"
CARD_BG  = "#121929"
BORDER   = "#1e3a5f"
TEXT     = "#e2e8f0"
ACCENT   = "#00aaff"
GREEN    = "#00ff88"
RED      = "#ff4444"
ORANGE   = "#ff8800"
YELLOW   = "#ffdd00"

PLOTLY_LAYOUT = dict(
    plot_bgcolor  = CARD_BG,
    paper_bgcolor = BG,
    font          = dict(color=TEXT, family="Inter, sans-serif"),
    margin        = dict(l=20, r=20, t=40, b=20),
    legend        = dict(bgcolor=CARD_BG, bordercolor=BORDER, borderwidth=1)
)


# ─── Metric Cards ─────────────────────────────────────────────────────────────

def stat_card(label: str, value: str, delta: str = "", color: str = ACCENT, icon: str = "📊"):
    """Render a styled metric stat card."""
    delta_html = (
        f'<div style="font-size:0.75rem; color:{GREEN}; margin-top:4px;">{delta}</div>'
        if delta else ""
    )
    st.markdown(f"""
    <div style="
        background: linear-gradient(135deg, {CARD_BG} 0%, #0d1b2a 100%);
        border: 1px solid {BORDER};
        border-left: 4px solid {color};
        border-radius: 12px;
        padding: 18px 20px;
        margin: 4px 0;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        transition: transform 0.2s;
    ">
        <div style="font-size:0.78rem; color:#64748b; text-transform:uppercase;
                    letter-spacing:1px; margin-bottom:6px;">{icon} {label}</div>
        <div style="font-size:1.8rem; font-weight:800; color:{color};
                    line-height:1;">{value}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)


def threat_level_gauge(risk_score: float) -> go.Figure:
    """
    Render a Plotly gauge chart for overall threat level.
    risk_score: 0.0 (safe) to 1.0 (critical)
    """
    pct = round(risk_score * 100, 1)
    color = GREEN if pct < 25 else YELLOW if pct < 50 else ORANGE if pct < 75 else RED

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=pct,
        number={"suffix": "%", "font": {"color": color, "size": 28}},
        title={"text": "Threat Level", "font": {"color": TEXT, "size": 14}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": TEXT,
                     "tickfont": {"color": TEXT}},
            "bar":  {"color": color},
            "bgcolor": CARD_BG,
            "bordercolor": BORDER,
            "steps": [
                {"range": [0, 25],  "color": "rgba(0, 255, 136, 0.15)"},
                {"range": [25, 50], "color": "rgba(255, 221, 0, 0.15)"},
                {"range": [50, 75], "color": "rgba(255, 136, 0, 0.15)"},
                {"range": [75, 100],"color": "rgba(255, 68, 68, 0.15)"}
            ],
            "threshold": {
                "line":  {"color": RED, "width": 3},
                "thickness": 0.75,
                "value": 75
            }
        }
    ))
    fig.update_layout(**PLOTLY_LAYOUT, height=220)
    return fig


def live_traffic_chart(labels: list, packets: list, attacks: list) -> go.Figure:
    """
    Dual-line chart: total packets vs attack packets over time.
    """
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=labels, y=packets,
        name="Total Packets",
        line=dict(color=ACCENT, width=2),
        fill="tozeroy",
        fillcolor="rgba(0, 170, 255, 0.1)",
        mode="lines"
    ))
    fig.add_trace(go.Scatter(
        x=labels, y=attacks,
        name="Attack Packets",
        line=dict(color=RED, width=2),
        fill="tozeroy",
        fillcolor="rgba(255, 68, 68, 0.1)",
        mode="lines"
    ))

    fig.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text="Live Traffic Monitor", font=dict(color=TEXT, size=14)),
        xaxis=dict(gridcolor=BORDER, showgrid=True),
        yaxis=dict(gridcolor=BORDER, showgrid=True),
        height=CHART_HEIGHT,
        hovermode="x unified"
    )
    return fig


def attack_distribution_pie(stats: dict) -> go.Figure:
    """
    Donut chart of attack type distribution from traffic stats.

    Args:
        stats: dict from traffic_monitor.get_traffic_stats()
    """
    labels = ["Normal", "DoS Attack", "Port Scan", "Brute Force", "Suspicious"]
    values = [
        stats.get("normal_packets", 0),
        stats.get("dos_count", 0),
        stats.get("port_scan_count", 0),
        stats.get("brute_force_count", 0),
        stats.get("suspicious_count", 0)
    ]
    colors = [GREEN, RED, ORANGE, "#ff2266", YELLOW]

    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        hole=0.55,
        marker=dict(colors=colors, line=dict(color=BG, width=2)),
        textfont=dict(color=TEXT),
        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>"
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text="Traffic Distribution", font=dict(color=TEXT, size=14)),
        showlegend=True,
        height=CHART_HEIGHT,
        annotations=[dict(
            text=f"<b>{sum(values)}</b><br>Total",
            x=0.5, y=0.5, font_size=14, showarrow=False, font_color=TEXT
        )]
    )
    return fig


def packets_per_second_chart(pps_history: list) -> go.Figure:
    """Line chart showing packets-per-second over time."""
    fig = go.Figure(go.Scatter(
        y=pps_history,
        mode="lines+markers",
        line=dict(color=GREEN, width=2),
        fill="tozeroy",
        fillcolor="rgba(0, 255, 136, 0.1)",
        marker=dict(size=4, color=GREEN)
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text="Packets / Second", font=dict(color=TEXT, size=14)),
        xaxis=dict(showgrid=False, showticklabels=False),
        yaxis=dict(gridcolor=BORDER),
        height=220,
        showlegend=False
    )
    return fig


def severity_bar_chart(alert_stats: dict) -> go.Figure:
    """Horizontal bar chart of alert counts by severity."""
    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    values = [
        alert_stats.get("critical", 0),
        alert_stats.get("high", 0),
        alert_stats.get("medium", 0),
        alert_stats.get("low", 0)
    ]
    colors = ["#ff2266", RED, ORANGE, YELLOW]

    fig = go.Figure(go.Bar(
        y=labels, x=values,
        orientation="h",
        marker=dict(color=colors),
        text=values, textposition="auto",
        textfont=dict(color=TEXT)
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text="Alerts by Severity", font=dict(color=TEXT, size=14)),
        xaxis=dict(gridcolor=BORDER),
        yaxis=dict(gridcolor=BORDER),
        height=280,
        showlegend=False
    )
    return fig


def model_accuracy_bar(results: dict) -> go.Figure:
    """Grouped bar chart comparing model performance metrics."""
    if not results:
        fig = go.Figure()
        fig.update_layout(**PLOTLY_LAYOUT, height=300)
        return fig

    models  = list(results.keys())
    metrics = ["accuracy", "precision", "recall", "f1_score"]
    m_labels = ["Accuracy", "Precision", "Recall", "F1-Score"]
    colors  = [ACCENT, GREEN, YELLOW, ORANGE]

    fig = go.Figure()
    for metric, label, color in zip(metrics, m_labels, colors):
        fig.add_trace(go.Bar(
            name=label,
            x=models,
            y=[results[m].get(metric, 0) for m in models],
            marker_color=color,
            opacity=0.85,
            text=[f"{results[m].get(metric, 0):.1f}%" for m in models],
            textposition="outside",
            textfont=dict(color=TEXT, size=10)
        ))

    fig.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text="ML Model Performance Comparison", font=dict(color=TEXT, size=14)),
        barmode="group",
        yaxis=dict(range=[0, 115], gridcolor=BORDER),
        height=CHART_HEIGHT
    )
    return fig


def recent_alerts_table(alerts: list):
    """Render a styled HTML table of recent alerts."""
    if not alerts:
        st.info("No alerts yet. Start monitoring to detect threats.")
        return

    severity_colors = {
        "CRITICAL": "#ff2266", "HIGH": RED,
        "MEDIUM": ORANGE, "LOW": YELLOW
    }

    rows_html = ""
    for a in alerts[:20]:
        sev_col = severity_colors.get(a["severity"], "#94a3b8")
        att_col = SEVERITY_COLORS.get(a["prediction"], "#94a3b8")
        ack_badge = (
            '<span style="color:#00ff88; font-size:0.7rem;">✓ ACK</span>'
            if a.get("acknowledged") else
            '<span style="color:#64748b; font-size:0.7rem;">Pending</span>'
        )
        rows_html += f"""
        <tr style="border-bottom: 1px solid {BORDER};">
            <td style="padding:8px; color:#94a3b8; font-size:0.78rem;">{a['timestamp']}</td>
            <td style="padding:8px;">
                <span style="color:{att_col}; font-weight:600;">{a['prediction']}</span>
            </td>
            <td style="padding:8px;">
                <span style="background:{sev_col}22; color:{sev_col};
                    border:1px solid {sev_col}44; border-radius:10px;
                    padding:2px 8px; font-size:0.75rem; font-weight:700;">
                    {a['severity']}
                </span>
            </td>
            <td style="padding:8px; color:{TEXT}; font-family:monospace; font-size:0.8rem;">
                {a.get('src_ip','N/A')}
            </td>
            <td style="padding:8px; color:{TEXT}; font-family:monospace; font-size:0.8rem;">
                {a.get('dst_ip','N/A')}:{a.get('dst_port',0)}
            </td>
            <td style="padding:8px; color:{ACCENT};">{a['confidence']*100:.0f}%</td>
            <td style="padding:8px;">{ack_badge}</td>
        </tr>
        """

    table_html = f"""
    <div style="overflow-x:auto; border-radius:10px; border:1px solid {BORDER};">
    <table style="width:100%; border-collapse:collapse; background:{CARD_BG};">
        <thead>
            <tr style="background:#0d1b2a; border-bottom:2px solid {BORDER};">
                <th style="padding:10px 8px; text-align:left; color:#64748b;
                           font-size:0.75rem; text-transform:uppercase; letter-spacing:1px;">
                    Time</th>
                <th style="padding:10px 8px; text-align:left; color:#64748b;
                           font-size:0.75rem; text-transform:uppercase; letter-spacing:1px;">
                    Attack Type</th>
                <th style="padding:10px 8px; text-align:left; color:#64748b;
                           font-size:0.75rem; text-transform:uppercase; letter-spacing:1px;">
                    Severity</th>
                <th style="padding:10px 8px; text-align:left; color:#64748b;
                           font-size:0.75rem; text-transform:uppercase; letter-spacing:1px;">
                    Source IP</th>
                <th style="padding:10px 8px; text-align:left; color:#64748b;
                           font-size:0.75rem; text-transform:uppercase; letter-spacing:1px;">
                    Destination</th>
                <th style="padding:10px 8px; text-align:left; color:#64748b;
                           font-size:0.75rem; text-transform:uppercase; letter-spacing:1px;">
                    Confidence</th>
                <th style="padding:10px 8px; text-align:left; color:#64748b;
                           font-size:0.75rem; text-transform:uppercase; letter-spacing:1px;">
                    Status</th>
            </tr>
        </thead>
        <tbody>{rows_html}</tbody>
    </table>
    </div>
    """
    st.markdown(table_html, unsafe_allow_html=True)


def render_header(username: str = "admin", role: str = "Administrator"):
    """Render the top navigation bar."""
    st.markdown(f"""
    <div style="
        display:flex; align-items:center; justify-content:space-between;
        background:linear-gradient(90deg,{CARD_BG} 0%,#0d1b2a 100%);
        border-bottom:1px solid {BORDER};
        padding:14px 24px; margin-bottom:20px; border-radius:10px;
        box-shadow:0 2px 20px rgba(0,0,0,0.4);
    ">
        <div style="display:flex; align-items:center; gap:12px;">
            <div style="font-size:1.8rem;">🛡</div>
            <div>
                <div style="font-size:1.1rem; font-weight:800; color:{ACCENT};
                            letter-spacing:-0.5px;">AI-NIDS</div>
                <div style="font-size:0.7rem; color:#64748b;">
                    Network Intrusion Detection System</div>
            </div>
        </div>
        <div style="display:flex; align-items:center; gap:20px;">
            <div style="text-align:right;">
                <div style="font-size:0.8rem; font-weight:600; color:{TEXT};">
                    {username}</div>
                <div style="font-size:0.7rem; color:#64748b;">{role}</div>
            </div>
            <div style="
                width:36px; height:36px; border-radius:50%;
                background:linear-gradient(135deg,{ACCENT},{GREEN});
                display:flex; align-items:center; justify-content:center;
                font-size:1rem; font-weight:800; color:{BG};
            ">{username[0].upper()}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
