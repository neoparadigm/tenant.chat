"""Enterprise-grade report generation — Enterprise aesthetic with AI differentiator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Template
from rich.console import Console

from tenantchat.models import AssessmentResult, CheckStatus, Severity, TenantState

console = Console()

# ── Microsoft colour palette ──────────────────────────────────────────────────
C_ORANGE      = "#e8721c"
C_ORANGE_L    = "#f4a460"
C_GREEN       = "#107c10"
C_GREEN_L     = "#bad80a"
C_RED         = "#a4262c"
C_RED_L       = "#d13438"
C_BLUE        = "#0078d4"
C_BLUE_L      = "#2b88d8"
C_PURPLE      = "#6b69d6"
C_GREY        = "#8a8886"
C_GREY_L      = "#c8c6c4"
C_BG_PAGE     = "#f3f2f1"
C_BG_CARD     = "#ffffff"
C_TEXT        = "#323130"
C_TEXT_MUTED  = "#605e5c"
C_BORDER      = "#edebe9"

SEVERITY_COLORS = {
    "critical": C_RED,
    "high":     C_ORANGE,
    "medium":   C_BLUE,
    "low":      C_GREY,
    "pass":     C_GREEN,
    "unknown":  C_GREY_L,
}

# ── Page CSS ──────────────────────────────────────────────────────────────────
PAGE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
  background: #f3f2f1;
  color: #323130;
  font-size: 14px;
  line-height: 1.5;
  padding: 24px;
}

.page-header {
  background: #0078d4;
  color: white;
  padding: 32px 40px;
  margin: -24px -24px 24px -24px;
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
}

.page-header h1 {
  font-size: 28px;
  font-weight: 600;
  letter-spacing: -0.5px;
  margin-bottom: 4px;
}

.page-header .subtitle {
  font-size: 14px;
  opacity: 0.85;
}

.page-header .meta {
  text-align: right;
  font-size: 13px;
  opacity: 0.85;
}

.section-title {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: #605e5c;
  margin: 28px 0 12px;
  padding-bottom: 6px;
  border-bottom: 1px solid #edebe9;
}

.card-grid {
  display: grid;
  gap: 16px;
  margin-bottom: 16px;
}

.card-grid-2 { grid-template-columns: 1fr 1fr; }
.card-grid-3 { grid-template-columns: 1fr 1fr 1fr; }
.card-grid-4 { grid-template-columns: 1fr 1fr 1fr 1fr; }
.card-grid-1 { grid-template-columns: 1fr; }

.card {
  background: #ffffff;
  border-radius: 2px;
  box-shadow: 0 1.6px 3.6px rgba(0,0,0,0.132), 0 0.3px 0.9px rgba(0,0,0,0.108);
  padding: 20px;
  position: relative;
}

.card-title {
  font-size: 13px;
  font-weight: 600;
  color: #323130;
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.card-caption {
  font-size: 11px;
  color: #605e5c;
  margin-top: 10px;
  line-height: 1.4;
}

.metric-card {
  text-align: center;
  padding: 20px 16px;
}

.metric-value {
  font-size: 42px;
  font-weight: 700;
  line-height: 1;
  margin-bottom: 4px;
  font-variant-numeric: tabular-nums;
}

.metric-label {
  font-size: 11px;
  color: #605e5c;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.metric-delta {
  font-size: 11px;
  margin-top: 4px;
}

.progress-bar {
  height: 4px;
  background: #edebe9;
  border-radius: 2px;
  margin-top: 8px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  border-radius: 2px;
  transition: width 0.6s ease;
}

/* Findings table */
.findings-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}

.findings-table th {
  text-align: left;
  padding: 8px 12px;
  background: #faf9f8;
  border-bottom: 2px solid #edebe9;
  font-size: 10px;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: #605e5c;
  font-weight: 600;
}

.findings-table td {
  padding: 10px 12px;
  border-bottom: 1px solid #f3f2f1;
  vertical-align: top;
}

.findings-table tr:hover td { background: #faf9f8; }

.severity-pill {
  display: inline-block;
  font-size: 10px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 10px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: white;
}

.drift-bar-wrap {
  display: flex;
  align-items: center;
  gap: 8px;
}

.drift-bar-mini {
  width: 60px;
  height: 4px;
  background: #edebe9;
  border-radius: 2px;
  overflow: hidden;
}

.drift-fill-mini {
  height: 100%;
  border-radius: 2px;
}

/* AI differentiator */
.ai-section {
  background: #f0f6ff;
  border: 1px solid #cce0f5;
  border-left: 4px solid #0078d4;
  padding: 14px 16px;
  margin-top: 10px;
  font-size: 12px;
}

.ai-section-title {
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: #0078d4;
  margin-bottom: 10px;
}

.ai-row {
  display: flex;
  gap: 8px;
  margin-bottom: 8px;
  align-items: flex-start;
}

.ai-icon {
  flex-shrink: 0;
  width: 16px;
  font-size: 12px;
}

.ai-content { color: #323130; line-height: 1.5; }
.ai-label { font-weight: 600; color: #323130; }

.community-cite {
  font-style: italic;
  color: #605e5c;
  border-left: 2px solid #0078d4;
  padding-left: 8px;
  margin-top: 4px;
}

/* Finding card */
.finding-card {
  border: 1px solid #edebe9;
  margin-bottom: 12px;
  border-radius: 2px;
  overflow: hidden;
}

.finding-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  background: #faf9f8;
  border-bottom: 1px solid #edebe9;
}

.finding-card-body { padding: 14px 16px; }

.finding-title {
  font-size: 14px;
  font-weight: 600;
  color: #323130;
}

.finding-id {
  font-size: 11px;
  color: #605e5c;
  font-family: 'Cascadia Code', 'Consolas', monospace;
}

.finding-delta {
  font-size: 12px;
  color: #323130;
  margin: 8px 0;
  padding: 8px 12px;
  background: #fff4ce;
  border-left: 3px solid #f7630c;
}

.blast-items { margin: 6px 0; }

.blast-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 12px;
  color: #323130;
  margin-bottom: 4px;
}

.blast-item::before {
  content: '⚠';
  color: #f7630c;
  flex-shrink: 0;
  font-size: 11px;
}

.fix-steps {
  counter-reset: step;
  margin: 6px 0;
}

.fix-step {
  display: flex;
  gap: 10px;
  margin-bottom: 6px;
  font-size: 12px;
  color: #323130;
  align-items: flex-start;
}

.step-num {
  background: #0078d4;
  color: white;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  font-weight: 700;
  flex-shrink: 0;
}

/* Confidence badge */
.confidence-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 10px;
  color: #107c10;
  background: #dff6dd;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 600;
}

/* Framework badge */
.framework-badge {
  display: inline-block;
  font-size: 10px;
  padding: 2px 8px;
  border: 1px solid #edebe9;
  border-radius: 2px;
  color: #605e5c;
  margin-right: 4px;
}

/* Footer */
.report-footer {
  margin-top: 32px;
  padding-top: 16px;
  border-top: 1px solid #edebe9;
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: #a19f9d;
}

@media print {
  body { padding: 0; background: white; }
  .page-header { margin: 0 0 24px 0; }
  .card { box-shadow: none; border: 1px solid #edebe9; }
  .finding-card { page-break-inside: avoid; }
}
"""
# ── Plotly chart helpers ──────────────────────────────────────────────────────

def _plotly_to_html(fig, width=600, height=None) -> str:
    """Convert a Plotly figure to base64 PNG — renders in WeasyPrint PDF."""
    import base64
    h = height or fig.layout.height or 300
    try:
        img_bytes = fig.to_image(format="png", width=width, height=h, scale=2)
        b64 = base64.b64encode(img_bytes).decode("utf-8")
        return f'<img src="data:image/png;base64,{b64}" style="width:100%;height:auto;display:block">' 
    except Exception as e:
        return f'<div style="color:#a4262c;font-size:11px">Chart unavailable: {e}</div>'


def _gauge_chart(score: float, previous: float | None = None) -> str:
    """Posture score gauge — Microsoft style."""
    import plotly.graph_objects as go

    color = C_RED if score < 50 else C_ORANGE if score < 75 else C_GREEN
    delta_val = score - previous if previous is not None else None

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta" if delta_val is not None else "gauge+number",
        value=score,
        delta={
            "reference": previous,
            "valueformat": ".1f",
            "increasing": {"color": C_GREEN},
            "decreasing": {"color": C_RED},
        } if delta_val is not None else None,
        number={"suffix": "/100", "font": {"size": 40, "color": C_TEXT, "family": "Segoe UI"}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": C_GREY_L,
                     "tickfont": {"size": 10, "color": C_TEXT_MUTED}},
            "bar": {"color": color, "thickness": 0.25},
            "bgcolor": "white",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 50],  "color": "#fde7e9"},
                {"range": [50, 75], "color": "#fff4ce"},
                {"range": [75, 100],"color": "#dff6dd"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.75,
                "value": score,
            },
        },
    ))
    fig.update_layout(
        height=240,
        margin=dict(l=30, r=30, t=30, b=30),
        paper_bgcolor="white",
        font={"family": "Segoe UI", "color": C_TEXT},
    )
    return _plotly_to_html(fig)


def _findings_donut(
    critical: int, high: int, medium: int, low: int, passing: int
) -> str:
    """Findings severity donut."""
    import plotly.graph_objects as go

    labels = ["Critical", "High", "Medium", "Low", "Passing"]
    values = [critical, high, medium, low, passing]
    colors = [C_RED, C_ORANGE, C_BLUE, C_GREY, C_GREEN]

    # Filter zero values
    filtered = [(l, v, c) for l, v, c in zip(labels, values, colors) if v > 0]
    if not filtered:
        return ""
    labels, values, colors = zip(*filtered)

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.6,
        marker=dict(colors=list(colors), line=dict(color="white", width=2)),
        textinfo="percent",
        textfont=dict(size=11, color="white", family="Segoe UI"),
        hovertemplate="<b>%{label}</b><br>%{value} findings<br>%{percent}<extra></extra>",
    ))
    total = sum(values)
    fig.update_layout(
        height=260,
        margin=dict(l=10, r=10, t=20, b=10),
        paper_bgcolor="white",
        showlegend=True,
        legend=dict(
            orientation="v", x=1.0, y=0.5,
            font=dict(size=11, color=C_TEXT, family="Segoe UI"),
        ),
        annotations=[dict(
            text=f"<b>{total}</b><br><span style='font-size:10px'>controls</span>",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=16, color=C_TEXT, family="Segoe UI"),
        )],
    )
    return _plotly_to_html(fig)


def _framework_radar(framework_scores: dict[str, float]) -> str:
    """Framework coverage radar chart."""
    import plotly.graph_objects as go

    if len(framework_scores) < 2:
        return ""

    categories = list(framework_scores.keys())
    values     = [round(v, 1) for v in framework_scores.values()]
    categories_closed = categories + [categories[0]]
    values_closed     = values + [values[0]]

    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=values_closed,
        theta=categories_closed,
        fill="toself",
        fillcolor=f"rgba(0,120,212,0.15)",
        line=dict(color=C_BLUE, width=2),
        marker=dict(size=6, color=C_BLUE),
        name="Coverage %",
        hovertemplate="<b>%{theta}</b><br>%{r:.1f}%<extra></extra>",
    ))
    fig.update_layout(
        height=300,
        margin=dict(l=60, r=60, t=30, b=30),
        paper_bgcolor="white",
        polar=dict(
            bgcolor="white",
            radialaxis=dict(
                visible=True,
                range=[0, 100],
                ticksuffix="%",
                tickfont=dict(size=9, color=C_TEXT_MUTED),
                gridcolor=C_BORDER,
                linecolor=C_BORDER,
            ),
            angularaxis=dict(
                tickfont=dict(size=10, color=C_TEXT, family="Segoe UI"),
                linecolor=C_BORDER,
                gridcolor=C_BORDER,
            ),
        ),
        showlegend=False,
    )
    return _plotly_to_html(fig)


def _drift_bar(findings: list) -> str:
    """Drift scores per failing control — horizontal bar."""
    import plotly.graph_objects as go

    failing = [f for f in findings if f.status == CheckStatus.FAIL][:15]
    if not failing:
        return ""

    failing_sorted = sorted(failing, key=lambda f: f.drift_score)
    labels  = [f"{f.control_id}" for f in failing_sorted]
    values  = [round((1 - f.drift_score) * 100, 1) for f in failing_sorted]
    colors  = [SEVERITY_COLORS.get(f.severity.value, C_GREY) for f in failing_sorted]
    texts   = [f.title[:40] + "..." if len(f.title) > 40 else f.title for f in failing_sorted]

    fig = go.Figure(go.Bar(
        x=values,
        y=labels,
        orientation="h",
        marker=dict(color=colors, line=dict(width=0)),
        text=[f"{v:.0f}%" for v in values],
        textposition="outside",
        textfont=dict(size=10, color=C_TEXT, family="Segoe UI"),
        customdata=texts,
        hovertemplate="<b>%{y}</b><br>%{customdata}<br>Drift: %{x:.1f}%<extra></extra>",
    ))
    fig.update_layout(
        height=max(200, len(failing_sorted) * 36 + 60),
        margin=dict(l=10, r=80, t=10, b=10),
        paper_bgcolor="white",
        plot_bgcolor="white",
        xaxis=dict(
            range=[0, 130],
            showgrid=True,
            gridcolor=C_BORDER,
            ticksuffix="%",
            tickfont=dict(size=10, color=C_TEXT_MUTED),
            linecolor=C_BORDER,
        ),
        yaxis=dict(
            tickfont=dict(size=10, color=C_TEXT, family="Consolas"),
            linecolor=C_BORDER,
        ),
        bargap=0.3,
    )
    return _plotly_to_html(fig)


def _effort_scatter(findings: list) -> str:
    """Effort vs impact scatter — quick wins quadrant."""
    import plotly.graph_objects as go

    failing = [f for f in findings if f.status == CheckStatus.FAIL]
    if len(failing) < 3:
        return ""

    effort_map   = {"low": 1, "medium": 2, "high": 3}
    severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    x, y, colors, texts, sizes = [], [], [], [], []
    for f in failing:
        ex = effort_map.get(f.effort, 2)
        sy = severity_map.get(f.severity.value, 1)
        x.append(ex + (hash(f.control_id) % 100) / 200)
        y.append(sy + (hash(f.title) % 100) / 200)
        colors.append(SEVERITY_COLORS.get(f.severity.value, C_GREY))
        texts.append(f"{f.control_id}<br>{f.title[:35]}")
        sizes.append(14 + f.affected_count * 0.5 if f.affected_count else 14)

    fig = go.Figure()

    # Quadrant background — quick wins
    fig.add_shape(type="rect", x0=0.5, y0=2.5, x1=1.5, y1=4.5,
                  fillcolor="rgba(16,124,16,0.06)", line=dict(width=0))
    fig.add_annotation(x=1.0, y=4.3, text="Quick Wins",
                       font=dict(size=9, color=C_GREEN), showarrow=False)

    fig.add_trace(go.Scatter(
        x=x, y=y, mode="markers",
        marker=dict(color=colors, size=sizes, line=dict(color="white", width=1.5),
                    opacity=0.85),
        text=[f.control_id for f in failing],
        customdata=texts,
        hovertemplate="<b>%{customdata}</b><extra></extra>",
    ))

    fig.update_layout(
        height=300,
        margin=dict(l=40, r=20, t=20, b=40),
        paper_bgcolor="white",
        plot_bgcolor="white",
        xaxis=dict(
            tickvals=[1, 2, 3], ticktext=["Low", "Medium", "High"],
            title=dict(text="Effort to Fix", font=dict(size=11, color=C_TEXT_MUTED)),
            range=[0.5, 3.5], gridcolor=C_BORDER, linecolor=C_BORDER,
            tickfont=dict(size=10, color=C_TEXT_MUTED),
        ),
        yaxis=dict(
            tickvals=[1, 2, 3, 4], ticktext=["Low", "Medium", "High", "Critical"],
            title=dict(text="Security Impact", font=dict(size=11, color=C_TEXT_MUTED)),
            range=[0.5, 4.5], gridcolor=C_BORDER, linecolor=C_BORDER,
            tickfont=dict(size=10, color=C_TEXT_MUTED),
        ),
        showlegend=False,
    )
    return _plotly_to_html(fig)


def _cluster_bar(clusters: list) -> str:
    """User risk segments horizontal bar."""
    import plotly.graph_objects as go

    if not clusters:
        return ""

    risk_colors = {
        "critical": C_RED,
        "high":     C_ORANGE,
        "medium":   C_BLUE,
        "low":      C_GREEN,
    }

    labels  = [c.label for c in clusters]
    values  = [c.user_count for c in clusters]
    colors  = [risk_colors.get(c.risk_level, C_GREY) for c in clusters]
    actions = [c.recommended_action[:60] for c in clusters]

    fig = go.Figure(go.Bar(
        x=values,
        y=labels,
        orientation="h",
        marker=dict(color=colors, line=dict(width=0)),
        text=[f"{v} users" for v in values],
        textposition="outside",
        textfont=dict(size=11, color=C_TEXT, family="Segoe UI"),
        customdata=actions,
        hovertemplate="<b>%{y}</b><br>%{x} users<br>%{customdata}<extra></extra>",
    ))
    fig.update_layout(
        height=max(180, len(clusters) * 50 + 40),
        margin=dict(l=10, r=80, t=10, b=10),
        paper_bgcolor="white",
        plot_bgcolor="white",
        xaxis=dict(
            showgrid=True, gridcolor=C_BORDER,
            tickfont=dict(size=10, color=C_TEXT_MUTED),
            linecolor=C_BORDER,
        ),
        yaxis=dict(
            tickfont=dict(size=11, color=C_TEXT, family="Segoe UI"),
            linecolor=C_BORDER,
        ),
        bargap=0.35,
    )
    return _plotly_to_html(fig)


def _sankey_auth(mfa_data: list) -> str:
    """Auth methods Sankey — Users → MFA method → Strength."""
    import plotly.graph_objects as go

    if not mfa_data:
        return ""

    phish_resistant = sum(1 for u in mfa_data if u.get("isMfaCapable", False))
    authenticator   = sum(1 for u in mfa_data
                         if u.get("isMfaRegistered", False)
                         and not u.get("isMfaCapable", False))
    no_mfa          = sum(1 for u in mfa_data if not u.get("isMfaRegistered", False))
    total           = len(mfa_data)

    if total == 0:
        return ""

    nodes = [
        {"label": f"Users ({total})",           "color": C_ORANGE},
        {"label": "Phishing Resistant",          "color": C_GREEN},
        {"label": "Authenticator App",           "color": C_BLUE},
        {"label": "No MFA",                      "color": C_RED},
    ]

    links = []
    if phish_resistant > 0:
        links.append({"source": 0, "target": 1, "value": phish_resistant,
                      "color": f"rgba(16,124,16,0.3)"})
    if authenticator > 0:
        links.append({"source": 0, "target": 2, "value": authenticator,
                      "color": f"rgba(0,120,212,0.3)"})
    if no_mfa > 0:
        links.append({"source": 0, "target": 3, "value": no_mfa,
                      "color": f"rgba(164,38,44,0.3)"})

    if not links:
        return ""

    fig = go.Figure(go.Sankey(
        arrangement="snap",
        node=dict(
            pad=20, thickness=28,
            line=dict(color="white", width=0.5),
            label=[n["label"] for n in nodes],
            color=[n["color"] for n in nodes],
            hovertemplate="<b>%{label}</b><br>%{value} users<extra></extra>",
        ),
        link=dict(
            source=[l["source"] for l in links],
            target=[l["target"] for l in links],
            value=[l["value"] for l in links],
            color=[l["color"] for l in links],
            hovertemplate="%{value} users<extra></extra>",
        ),
    ))
    fig.update_layout(
        height=240,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="white",
        font=dict(family="Segoe UI", size=11, color=C_TEXT),
    )
    return _plotly_to_html(fig)


def _sankey_devices(devices: list) -> str:
    """Device compliance Sankey — Devices → Compliance state."""
    import plotly.graph_objects as go

    if not devices:
        return ""

    compliant     = sum(1 for d in devices if d.get("complianceState") == "compliant")
    noncompliant  = sum(1 for d in devices if d.get("complianceState") == "noncompliant")
    other         = len(devices) - compliant - noncompliant
    total         = len(devices)

    if total == 0:
        return ""

    nodes = [
        {"label": f"Devices ({total})", "color": C_ORANGE},
        {"label": "Compliant",          "color": C_GREEN},
        {"label": "Non-compliant",      "color": C_RED},
        {"label": "Not evaluated",      "color": C_GREY},
    ]

    links = []
    if compliant > 0:
        links.append({"source": 0, "target": 1, "value": compliant,
                      "color": "rgba(16,124,16,0.3)"})
    if noncompliant > 0:
        links.append({"source": 0, "target": 2, "value": noncompliant,
                      "color": "rgba(164,38,44,0.3)"})
    if other > 0:
        links.append({"source": 0, "target": 3, "value": other,
                      "color": "rgba(138,136,134,0.3)"})

    if not links:
        return ""

    fig = go.Figure(go.Sankey(
        arrangement="snap",
        node=dict(
            pad=20, thickness=28,
            line=dict(color="white", width=0.5),
            label=[n["label"] for n in nodes],
            color=[n["color"] for n in nodes],
            hovertemplate="<b>%{label}</b><br>%{value} devices<extra></extra>",
        ),
        link=dict(
            source=[l["source"] for l in links],
            target=[l["target"] for l in links],
            value=[l["value"] for l in links],
            color=[l["color"] for l in links],
        ),
    ))
    fig.update_layout(
        height=240,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="white",
        font=dict(family="Segoe UI", size=11, color=C_TEXT),
    )
    return _plotly_to_html(fig)


def _device_os_bar(devices: list) -> str:
    """Device OS breakdown horizontal bar."""
    import plotly.graph_objects as go

    if not devices:
        return ""

    from collections import Counter
    os_counts = Counter(
        d.get("operatingSystem", "Unknown") for d in devices
    )

    os_colors = {
        "Windows": C_BLUE,
        "macOS":   C_ORANGE,
        "iOS":     C_GREEN,
        "Android": C_ORANGE_L,
        "Linux":   C_PURPLE,
    }

    items = sorted(os_counts.items(), key=lambda x: x[1], reverse=True)[:6]
    labels = [i[0] for i in items]
    values = [i[1] for i in items]
    colors = [os_colors.get(l, C_GREY) for l in labels]

    fig = go.Figure(go.Bar(
        x=values, y=labels, orientation="h",
        marker=dict(color=colors, line=dict(width=0)),
        text=values, textposition="outside",
        textfont=dict(size=11, color=C_TEXT, family="Segoe UI"),
        hovertemplate="<b>%{y}</b><br>%{x} devices<extra></extra>",
    ))
    fig.update_layout(
        height=max(180, len(items) * 40 + 40),
        margin=dict(l=10, r=60, t=10, b=10),
        paper_bgcolor="white",
        plot_bgcolor="white",
        xaxis=dict(showgrid=True, gridcolor=C_BORDER,
                   tickfont=dict(size=10, color=C_TEXT_MUTED), linecolor=C_BORDER),
        yaxis=dict(tickfont=dict(size=11, color=C_TEXT, family="Segoe UI"),
                   linecolor=C_BORDER),
        bargap=0.3,
    )
    return _plotly_to_html(fig)
# ── AI differentiator ─────────────────────────────────────────────────────────

async def _generate_ai_analysis(
    finding,
    state: TenantState,
    use_ollama: bool = True,
) -> dict:
    """Generate AI analysis for a single finding."""
    import httpx
    import os

    prompt = f"""You are a Microsoft 365 security expert writing a concise analysis for an enterprise security report.

Finding: {finding.title}
Control: {finding.control_id} ({finding.framework})
Severity: {finding.severity.value}
What is wrong: {finding.delta or 'Configuration does not meet baseline requirement'}
Affected objects: {finding.affected_count} objects
Blast radius: {', '.join(finding.blast_radius[:3]) if finding.blast_radius else 'Unknown'}

Write a JSON response with these exact keys:
{{
  "explanation": "2 sentences max. Plain English. What this means for the organisation. No jargon.",
  "risk_context": "1 sentence. Why this matters from a threat perspective.",
  "fix_summary": "1 sentence. The safest way to fix this.",
  "confidence": "A percentage like 87% representing community confidence in this recommendation."
}}

Respond ONLY with valid JSON. No other text."""

    try:
        if use_ollama:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    "http://localhost:11434/api/generate",
                    json={
                        "model": os.environ.get("TENANTCHAT_MODEL", "gemma4"),
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                        "options": {"temperature": 0.2},
                    },
                )
                resp.raise_for_status()
                raw = resp.json().get("response", "{}")
                return json.loads(raw)
    except Exception:
        pass

    return {
        "explanation": f"This control requires {finding.title.lower()}. The current configuration does not meet the baseline requirement.",
        "risk_context": "This misconfiguration increases the attack surface and may allow unauthorised access.",
        "fix_summary": f"Review and remediate {finding.control_id} according to the baseline definition.",
        "confidence": "N/A",
    }


def _blast_radius_section(finding, state: TenantState) -> str:
    """Generate tenant-specific blast radius HTML."""
    from tenantchat.blast import BlastAnalyzer
    analyzer = BlastAnalyzer()
    result   = analyzer.analyze(finding.title, state)

    tenant_specific = [
        o for o in result.affected_objects
        if o["type"] == "tenant_specific" and o.get("count", 0)
    ]
    generic = [
        o for o in result.affected_objects
        if o["type"] == "generic"
    ][:3]

    lines = []
    for o in tenant_specific:
        lines.append(
            f'<div class="blast-item" style="color:{C_RED_L}">'
            f'<strong>{o["description"]}</strong>'
            f'{ " — " + str(o["count"]) + " objects" if o.get("count") else "" }'
            f'</div>'
        )
    for o in generic:
        lines.append(
            f'<div class="blast-item">{o["description"]}</div>'
        )

    return "".join(lines) if lines else "<div style='color:#605e5c;font-size:12px'>No specific blast radius data available for this change.</div>"


def _fix_sequence_html(finding) -> str:
    """Generate fix sequence HTML from blast radius data."""
    from tenantchat.blast import BLAST_KNOWLEDGE

    change_lower = finding.title.lower()
    matched_data = None
    for key, data in BLAST_KNOWLEDGE.items():
        if any(kw in change_lower for kw in data["keywords"]):
            matched_data = data
            break

    if not matched_data:
        return "<div style='color:#605e5c;font-size:12px'>Review Microsoft documentation for remediation steps.</div>"

    steps = matched_data.get("fix_sequence", [])[:5]
    html  = ""
    for i, step in enumerate(steps, 1):
        clean = step.replace(f"{i}. ", "")
        html += (
            f'<div class="fix-step">'
            f'<div class="step-num">{i}</div>'
            f'<div>{clean}</div>'
            f'</div>'
        )
    return html


# ── HTML template ─────────────────────────────────────────────────────────────

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>tenant.chat — Security Assessment Report</title>
<style>{{ css }}</style>
</head>
<body>

<!-- PAGE HEADER -->
<div class="page-header">
  <div>
    <div style="font-size:12px; opacity:0.7; margin-bottom:6px; letter-spacing:1px">TENANT.CHAT · SECURITY ASSESSMENT</div>
    <h1>{{ tenant_domain }}</h1>
    <div class="subtitle">{{ report_type_label }} Report &nbsp;·&nbsp; {{ frameworks }}</div>
  </div>
  <div class="meta">
    <div style="font-size:13px; margin-bottom:4px">{{ assessed_at }}</div>
    <div style="font-size:12px; opacity:0.7">Local-first · Private · AI-powered</div>
  </div>
</div>

<!-- SCORE METRICS -->
<div class="section-title">Security Posture Overview</div>
<div class="card-grid card-grid-4">
  <div class="card metric-card">
    <div class="metric-value" style="color:{{ score_color }}">{{ score }}</div>
    <div class="metric-label">Posture Score</div>
    <div class="progress-bar">
      <div class="progress-fill" style="width:{{ score }}%; background:{{ score_color }}"></div>
    </div>
    {% if trend %}
    <div class="metric-delta" style="color:{% if '+' in trend %}{{ green }}{% else %}{{ red }}{% endif %}">
      {{ trend }}
    </div>
    {% endif %}
  </div>
  <div class="card metric-card">
    <div class="metric-value" style="color:{{ red }}">{{ critical }}</div>
    <div class="metric-label">Critical</div>
  </div>
  <div class="card metric-card">
    <div class="metric-value" style="color:{{ orange }}">{{ high }}</div>
    <div class="metric-label">High</div>
  </div>
  <div class="card metric-card">
    <div class="metric-value" style="color:{{ green }}">{{ passing }}/{{ total }}</div>
    <div class="metric-label">Passing</div>
  </div>
</div>

<!-- CHARTS ROW 1 -->
<div class="section-title">Posture Analysis</div>
<div class="card-grid card-grid-2">

  {% if gauge_chart %}
  <div class="card">
    <div class="card-title">📊 Overall Posture Score</div>
    {{ gauge_chart }}
    <div class="card-caption">Security posture score against all assessed frameworks. Target: 75+</div>
  </div>
  {% endif %}

  {% if donut_chart %}
  <div class="card">
    <div class="card-title">🔍 Findings by Severity</div>
    {{ donut_chart }}
    <div class="card-caption">Distribution of {{ total }} assessed controls across severity levels.</div>
  </div>
  {% endif %}

</div>

<!-- CHARTS ROW 2 -->
{% if radar_chart or drift_chart %}
<div class="card-grid card-grid-2">

  {% if radar_chart %}
  <div class="card">
    <div class="card-title">🎯 Framework Coverage</div>
    {{ radar_chart }}
    <div class="card-caption">Percentage of controls passing per security framework.</div>
  </div>
  {% endif %}

  {% if drift_chart %}
  <div class="card">
    <div class="card-title">📉 Configuration Drift by Control</div>
    {{ drift_chart }}
    <div class="card-caption">Controls sorted by drift severity. Longer bars indicate greater deviation from baseline.</div>
  </div>
  {% endif %}

</div>
{% endif %}

<!-- CHARTS ROW 3 — Sankey flows -->
{% if sankey_auth or sankey_devices %}
<div class="section-title">Identity & Device Intelligence</div>
<div class="card-grid card-grid-2">

  {% if sankey_auth %}
  <div class="card">
    <div class="card-title">👤 User Authentication Methods</div>
    {{ sankey_auth }}
    <div class="card-caption">Distribution of MFA registration across your user population.</div>
  </div>
  {% endif %}

  {% if sankey_devices %}
  <div class="card">
    <div class="card-title">💻 Device Compliance Flow</div>
    {{ sankey_devices }}
    <div class="card-caption">Compliance state of all Intune-managed devices.</div>
  </div>
  {% endif %}

</div>
{% endif %}

<!-- CHARTS ROW 4 -->
{% if scatter_chart or cluster_chart or os_chart %}
<div class="card-grid card-grid-{% if scatter_chart and (cluster_chart or os_chart) %}2{% else %}1{% endif %}">

  {% if scatter_chart %}
  <div class="card">
    <div class="card-title">⚡ Effort vs Security Impact</div>
    {{ scatter_chart }}
    <div class="card-caption">Controls in the top-left quadrant are quick wins — high impact, low effort. Prioritise these first.</div>
  </div>
  {% endif %}

  {% if cluster_chart %}
  <div class="card">
    <div class="card-title">👥 User Risk Segments (K-means)</div>
    {{ cluster_chart }}
    <div class="card-caption">Users segmented by security posture using K-means clustering. Each segment requires a different remediation approach.</div>
  </div>
  {% endif %}

  {% if os_chart and not cluster_chart %}
  <div class="card">
    <div class="card-title">🖥 Device Summary by OS</div>
    {{ os_chart }}
    <div class="card-caption">Managed device distribution by operating system.</div>
  </div>
  {% endif %}

</div>
{% endif %}

<!-- CRITICAL FINDINGS WITH AI ANALYSIS -->
{% if critical_findings %}
<div class="section-title">Critical Findings — Immediate Action Required</div>
{% for f in critical_findings %}
<div class="finding-card">
  <div class="finding-card-header">
    <div>
      <div class="finding-title">{{ f.title }}</div>
      <div class="finding-id">{{ f.control_id }} &nbsp;·&nbsp; {{ f.framework }}</div>
    </div>
    <div style="display:flex; align-items:center; gap:8px">
      <span class="severity-pill" style="background:{{ red }}">CRITICAL</span>
      <span class="framework-badge">{{ f.effort }} effort</span>
    </div>
  </div>
  <div class="finding-card-body">
    {% if f.delta %}
    <div class="finding-delta">{{ f.delta }}</div>
    {% endif %}

    <!-- AI ANALYSIS SECTION -->
    <div class="ai-section">
      <div class="ai-section-title">🤖 AI Analysis — Powered by Gemma 4</div>

      <div class="ai-row">
        <div class="ai-icon">💬</div>
        <div class="ai-content">
          <span class="ai-label">What this means: </span>
          {{ f.ai_explanation }}
        </div>
      </div>

      <div class="ai-row">
        <div class="ai-icon">⚠️</div>
        <div class="ai-content">
          <span class="ai-label">Risk context: </span>
          {{ f.ai_risk_context }}
        </div>
      </div>

      {% if f.blast_html %}
      <div class="ai-row">
        <div class="ai-icon">💥</div>
        <div class="ai-content">
          <span class="ai-label">Blast radius — your tenant: </span>
          <div class="blast-items">{{ f.blast_html }}</div>
        </div>
      </div>
      {% endif %}

      {% if f.cluster_note %}
      <div class="ai-row">
        <div class="ai-icon">👥</div>
        <div class="ai-content">
          <span class="ai-label">User segment impact: </span>
          {{ f.cluster_note }}
        </div>
      </div>
      {% endif %}

      {% if f.community_ref %}
      <div class="ai-row">
        <div class="ai-icon">📚</div>
        <div class="ai-content">
          <span class="ai-label">Community context: </span>
          <div class="community-cite">{{ f.community_ref }}</div>
        </div>
      </div>
      {% endif %}

      <div class="ai-row">
        <div class="ai-icon">✅</div>
        <div class="ai-content">
          <span class="ai-label">Recommended sequence: </span>
          <div class="fix-steps">{{ f.fix_html }}</div>
        </div>
      </div>

      {% if f.confidence %}
      <div style="margin-top:8px">
        <span class="confidence-badge">✓ {{ f.confidence }} community confidence</span>
      </div>
      {% endif %}

    </div>
  </div>
</div>
{% endfor %}
{% endif %}

<!-- HIGH FINDINGS -->
{% if high_findings %}
<div class="section-title">High Findings — Fix This Month</div>
{% for f in high_findings %}
<div class="finding-card">
  <div class="finding-card-header">
    <div>
      <div class="finding-title">{{ f.title }}</div>
      <div class="finding-id">{{ f.control_id }} &nbsp;·&nbsp; {{ f.framework }}</div>
    </div>
    <div style="display:flex; align-items:center; gap:8px">
      <span class="severity-pill" style="background:{{ orange }}">HIGH</span>
      <span class="framework-badge">{{ f.effort }} effort</span>
    </div>
  </div>
  <div class="finding-card-body">
    {% if f.delta %}
    <div class="finding-delta">{{ f.delta }}</div>
    {% endif %}
    <div class="ai-section">
      <div class="ai-section-title">🤖 AI Analysis — Powered by Gemma 4</div>
      <div class="ai-row">
        <div class="ai-icon">💬</div>
        <div class="ai-content">
          <span class="ai-label">What this means: </span>{{ f.ai_explanation }}
        </div>
      </div>
      {% if f.blast_html %}
      <div class="ai-row">
        <div class="ai-icon">💥</div>
        <div class="ai-content">
          <span class="ai-label">Blast radius: </span>
          <div class="blast-items">{{ f.blast_html }}</div>
        </div>
      </div>
      {% endif %}
      <div class="ai-row">
        <div class="ai-icon">✅</div>
        <div class="ai-content">
          <span class="ai-label">Fix: </span>{{ f.ai_fix_summary }}
        </div>
      </div>
    </div>
  </div>
</div>
{% endfor %}
{% endif %}

<!-- ALL FINDINGS TABLE -->
<div class="section-title">Complete Assessment Results</div>
<div class="card">
  <table class="findings-table">
    <thead>
      <tr>
        <th style="width:100px">Control</th>
        <th>Finding</th>
        <th style="width:80px">Framework</th>
        <th style="width:70px">Status</th>
        <th style="width:70px">Severity</th>
        <th style="width:100px">Drift</th>
        <th style="width:60px">Effort</th>
      </tr>
    </thead>
    <tbody>
      {% for f in all_findings %}
      <tr>
        <td style="font-family:Consolas,monospace; font-size:11px; color:#605e5c">{{ f.control_id }}</td>
        <td>
          <div style="font-weight:500; color:#323130">{{ f.title }}</div>
          {% if f.delta %}
          <div style="font-size:11px; color:#605e5c; margin-top:2px">{{ f.delta[:80] }}{% if f.delta|length > 80 %}...{% endif %}</div>
          {% endif %}
        </td>
        <td style="font-size:11px; color:#605e5c">{{ f.framework_short }}</td>
        <td>
          <span class="severity-pill" style="background:{{ f.status_color }}; font-size:9px">
            {{ f.status }}
          </span>
        </td>
        <td>
          <span class="severity-pill" style="background:{{ f.severity_color }}; font-size:9px">
            {{ f.severity }}
          </span>
        </td>
        <td>
          <div class="drift-bar-wrap">
            <div class="drift-bar-mini">
              <div class="drift-fill-mini" style="width:{{ f.drift_pct }}%; background:{{ f.drift_color }}"></div>
            </div>
            <span style="font-size:10px; color:#605e5c">{{ f.drift_pct }}%</span>
          </div>
        </td>
        <td style="font-size:11px; color:#605e5c">{{ f.effort }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<!-- FOOTER -->
<div class="report-footer">
  <div>Generated by tenant.chat v0.1.0 &nbsp;·&nbsp; github.com/neoparadigm/tenant.chat</div>
  <div>Local-first · AI-powered · Open source · No data transmitted</div>
</div>

</body>
</html>"""


# ── Reporter class ────────────────────────────────────────────────────────────

class Reporter:
    """Enterprise-grade report generator — Microsoft ZTA aesthetic with AI."""

    def generate(
        self,
        result,
        state,
        report_type: str = "technical",
        output_path: str = "report.pdf",
    ) -> str:
        """Generate report — runs in isolated thread to avoid event loop conflicts."""
        import asyncio
        import concurrent.futures

        def _run():
            return asyncio.run(
                self._generate_async(result, state, report_type, output_path)
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(_run).result(timeout=300)

    async def _generate_async(
        self,
        result,
        state,
        report_type: str,
        output_path: str,
    ) -> str:
        """Generate the full report asynchronously."""
        from tenantchat.models import CheckStatus, Severity

        # Score and trend
        score       = result.posture_score
        score_color = C_RED if score < 50 else C_ORANGE if score < 75 else C_GREEN

        previous = None
        trend    = ""
        try:
            from tenantchat.memory import Memory
            mem     = Memory(tenant_id=result.tenant_id)
            history = mem.get_assessment_history(result.tenant_id)
            if len(history) >= 2:
                previous = history[-2]["score"]
                delta    = score - previous
                trend    = f"+{delta:.1f} since last assessment" if delta > 0 else f"{delta:.1f} since last assessment"
        except Exception:
            pass

        # Framework scores
        framework_scores = {}
        for fw in result.frameworks:
            fw_findings = [f for f in result.findings if f.framework == fw]
            if fw_findings:
                passing = sum(1 for f in fw_findings if f.status == CheckStatus.PASS)
                framework_scores[fw.replace("Microsoft ", "").replace(" v3.1", "")] = (
                    passing / len(fw_findings) * 100
                )

        # Generate charts
        gauge_chart   = _gauge_chart(score, previous)
        donut_chart   = _findings_donut(
            result.critical_count, result.high_count,
            result.medium_count, result.low_count, result.pass_count
        )
        radar_chart   = _framework_radar(framework_scores) if len(framework_scores) > 1 else ""
        drift_chart   = _drift_bar(result.findings)
        scatter_chart = _effort_scatter(result.findings)
        sankey_auth   = _sankey_auth(state.mfa_registration)
        sankey_dev    = _sankey_devices(state.managed_devices)
        os_chart      = _device_os_bar(state.managed_devices)

        # K-means clusters
        clusters      = []
        cluster_chart = ""
        try:
            from tenantchat.cluster import Clusterer
            clusterer = Clusterer()
            clusters  = clusterer.cluster_users(
                state.users, state.mfa_registration, state.managed_devices
            )
            cluster_chart = _cluster_bar(clusters)
        except Exception:
            pass

        # AI analysis for critical + high findings
        critical_findings_data = []
        high_findings_data     = []

        for f in result.findings:
            if f.status != CheckStatus.FAIL:
                continue
            if f.severity not in (Severity.CRITICAL, Severity.HIGH):
                continue

            ai         = await _generate_ai_analysis(f, state)
            blast_html = _blast_radius_section(f, state)
            fix_html   = _fix_sequence_html(f)

            cluster_note = ""
            if clusters:
                high_risk = [c for c in clusters if c.risk_level in ("critical", "high")]
                if high_risk:
                    total_at_risk = sum(c.user_count for c in high_risk)
                    cluster_note = (
                        f"{total_at_risk} users in high-risk segments are affected. "
                        f"Prioritise the '{high_risk[0].label}' cluster ({high_risk[0].user_count} users) first."
                    )

            finding_data = {
                "title":           f.title,
                "control_id":      f.control_id,
                "framework":       f.framework,
                "severity":        f.severity.value,
                "effort":          f.effort,
                "delta":           f.delta,
                "blast_html":      blast_html,
                "fix_html":        fix_html,
                "cluster_note":    cluster_note,
                "community_ref":   f.community_ref or "",
                "ai_explanation":  ai.get("explanation", ""),
                "ai_risk_context": ai.get("risk_context", ""),
                "ai_fix_summary":  ai.get("fix_summary", ""),
                "confidence":      ai.get("confidence", ""),
            }

            if f.severity == Severity.CRITICAL:
                critical_findings_data.append(finding_data)
            else:
                high_findings_data.append(finding_data)

        # All findings table
        status_colors = {
            CheckStatus.PASS:    C_GREEN,
            CheckStatus.FAIL:    C_RED,
            CheckStatus.PARTIAL: C_ORANGE,
            CheckStatus.UNKNOWN: C_GREY,
        }

        all_findings_data = []
        for f in result.findings:
            drift_pct   = round((1 - f.drift_score) * 100) if f.status == CheckStatus.FAIL else round(f.drift_score * 100)
            drift_color = C_RED if drift_pct > 60 else C_ORANGE if drift_pct > 30 else C_GREEN
            all_findings_data.append({
                "control_id":      f.control_id,
                "title":           f.title,
                "framework_short": f.framework.replace("Microsoft ", "").replace(" v3.1", "")[:12],
                "status":          f.status.value.upper(),
                "status_color":    status_colors.get(f.status, C_GREY),
                "severity":        f.severity.value.upper(),
                "severity_color":  SEVERITY_COLORS.get(f.severity.value, C_GREY),
                "delta":           f.delta or "",
                "drift_pct":       drift_pct,
                "drift_color":     drift_color,
                "effort":          f.effort,
            })

        # Render template
        report_type_labels = {
            "exec":      "Executive",
            "technical": "Technical",
            "audit":     "Audit Trail",
        }

        template = Template(REPORT_TEMPLATE)
        html = template.render(
            css=PAGE_CSS,
            tenant_domain=state.tenant_domain,
            report_type_label=report_type_labels.get(report_type, "Technical"),
            frameworks=", ".join(result.frameworks),
            assessed_at=result.assessed_at.strftime("%d %B %Y %H:%M UTC"),
            score=score,
            score_color=score_color,
            trend=trend,
            critical=result.critical_count,
            high=result.high_count,
            passing=result.pass_count,
            total=result.total_controls,
            red=C_RED, orange=C_ORANGE, green=C_GREEN, blue=C_BLUE,
            gauge_chart=gauge_chart,
            donut_chart=donut_chart,
            radar_chart=radar_chart,
            drift_chart=drift_chart,
            scatter_chart=scatter_chart,
            sankey_auth=sankey_auth,
            sankey_devices=sankey_dev,
            os_chart=os_chart,
            cluster_chart=cluster_chart,
            critical_findings=critical_findings_data,
            high_findings=high_findings_data,
            all_findings=all_findings_data,
        )

        # Write output
        if output_path.endswith(".html"):
            from pathlib import Path
            Path(output_path).write_text(html, encoding="utf-8")
            return output_path

        try:
            from weasyprint import HTML as WP_HTML
            WP_HTML(string=html).write_pdf(output_path)
            return output_path
        except Exception as e:
            from pathlib import Path
            html_path = output_path.replace(".pdf", ".html")
            Path(html_path).write_text(html, encoding="utf-8")
            return html_path
