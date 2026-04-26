"""Report generation — executive, technical, and audit trail PDF reports."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template
from rich.console import Console

from tenantchat.models import AssessmentResult, CheckStatus, Severity, TenantState

console = Console()

# ── HTML Templates ────────────────────────────────────────────────────────────

EXEC_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body { font-family: Arial, sans-serif; margin: 0; padding: 0; color: #1a1a1a; }
  .cover { background: #1a2744; color: white; padding: 60px 48px; }
  .cover h1 { font-size: 36px; margin: 0 0 8px; letter-spacing: -0.5px; }
  .cover .sub { color: #93c5fd; font-size: 16px; }
  .cover .meta { color: #64748b; font-size: 13px; margin-top: 24px; }
  .section { padding: 32px 48px; }
  .score-row { display: flex; gap: 24px; margin: 24px 0; }
  .score-card { background: #f8fafc; border: 1px solid #e2e8f0;
                border-radius: 6px; padding: 20px 24px; flex: 1; }
  .score-card .number { font-size: 42px; font-weight: 700; line-height: 1; }
  .score-card .label { font-size: 12px; color: #64748b; 
                       text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
  .critical { color: #dc2626; }
  .high     { color: #d97706; }
  .medium   { color: #2563eb; }
  .green    { color: #16a34a; }
  .finding  { border-left: 3px solid #e2e8f0; padding: 12px 16px; 
               margin-bottom: 12px; background: #f8fafc; }
  .finding.critical { border-color: #dc2626; }
  .finding.high     { border-color: #d97706; }
  .finding.medium   { border-color: #2563eb; }
  .finding-title    { font-weight: 600; font-size: 14px; }
  .finding-delta    { font-size: 13px; color: #475569; margin-top: 4px; }
  .finding-id       { font-size: 11px; color: #94a3b8; font-family: monospace; }
  .badge { display: inline-block; font-size: 11px; font-weight: 700;
           padding: 2px 8px; border-radius: 3px; text-transform: uppercase;
           letter-spacing: 0.5px; }
  .badge.critical { background: #fee2e2; color: #dc2626; }
  .badge.high     { background: #fef3c7; color: #d97706; }
  .badge.medium   { background: #dbeafe; color: #2563eb; }
  .badge.pass     { background: #dcfce7; color: #16a34a; }
  h2 { font-size: 18px; color: #1a2744; border-bottom: 2px solid #e2e8f0;
       padding-bottom: 8px; margin-top: 0; }
  .footer { background: #f8fafc; border-top: 1px solid #e2e8f0;
            padding: 16px 48px; font-size: 12px; color: #94a3b8; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 12px; background: #1a2744;
       color: white; font-size: 11px; letter-spacing: 1px;
       text-transform: uppercase; }
  td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }
  tr:nth-child(even) td { background: #f8fafc; }
  .progress-bar { height: 8px; background: #e2e8f0; border-radius: 4px;
                  overflow: hidden; margin-top: 8px; }
  .progress-fill { height: 100%; border-radius: 4px; }
</style>
</head>
<body>

<div class="cover">
  <h1>{{ tenant_domain }}</h1>
  <div class="sub">Security Assessment Report</div>
  <div class="meta">
    {{ report_type }} Report &nbsp;|&nbsp; 
    {{ assessed_at }} &nbsp;|&nbsp;
    Frameworks: {{ frameworks }}
  </div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="score-row">
    <div class="score-card">
      <div class="number" style="color: {{ score_color }}">{{ score }}</div>
      <div class="label">Security Score</div>
      <div class="progress-bar">
        <div class="progress-fill" 
             style="width: {{ score }}%; background: {{ score_color }}"></div>
      </div>
    </div>
    <div class="score-card">
      <div class="number critical">{{ critical_count }}</div>
      <div class="label">Critical Findings</div>
    </div>
    <div class="score-card">
      <div class="number high">{{ high_count }}</div>
      <div class="label">High Findings</div>
    </div>
    <div class="score-card">
      <div class="number green">{{ pass_count }}/{{ total }}</div>
      <div class="label">Controls Passing</div>
    </div>
  </div>
</div>

{% if critical_findings %}
<div class="section" style="padding-top: 0">
  <h2>Critical Findings — Fix This Week</h2>
  {% for f in critical_findings %}
  <div class="finding critical">
    <div style="display:flex; justify-content:space-between; align-items:center">
      <div class="finding-title">{{ f.title }}</div>
      <span class="badge critical">Critical</span>
    </div>
    <div class="finding-id">{{ f.control_id }} · {{ f.framework }}</div>
    {% if f.delta %}
    <div class="finding-delta">{{ f.delta }}</div>
    {% endif %}
    {% if f.blast_radius %}
    <div class="finding-delta" style="margin-top:6px">
      <strong>Blast radius:</strong> 
      {{ f.blast_radius[0] }}{% if f.blast_radius|length > 1 %} 
      and {{ f.blast_radius|length - 1 }} more{% endif %}
    </div>
    {% endif %}
  </div>
  {% endfor %}
</div>
{% endif %}

{% if high_findings %}
<div class="section" style="padding-top: 0">
  <h2>High Findings — Fix This Month</h2>
  {% for f in high_findings %}
  <div class="finding high">
    <div style="display:flex; justify-content:space-between; align-items:center">
      <div class="finding-title">{{ f.title }}</div>
      <span class="badge high">High</span>
    </div>
    <div class="finding-id">{{ f.control_id }} · {{ f.framework }}</div>
    {% if f.delta %}
    <div class="finding-delta">{{ f.delta }}</div>
    {% endif %}
  </div>
  {% endfor %}
</div>
{% endif %}

{% if all_findings %}
<div class="section" style="padding-top: 0">
  <h2>All Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Control</th>
        <th>Title</th>
        <th>Framework</th>
        <th>Status</th>
        <th>Severity</th>
        <th>Effort</th>
      </tr>
    </thead>
    <tbody>
      {% for f in all_findings %}
      <tr>
        <td style="font-family:monospace; font-size:11px">{{ f.control_id }}</td>
        <td>{{ f.title }}</td>
        <td style="font-size:11px; color:#64748b">{{ f.framework }}</td>
        <td><span class="badge {{ f.status_class }}">{{ f.status }}</span></td>
        <td><span class="badge {{ f.severity }}">{{ f.severity }}</span></td>
        <td style="font-size:12px; color:#64748b">{{ f.effort }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

<div class="footer">
  Generated by tenant.chat v0.1.0 &nbsp;·&nbsp;
  github.com/neoparadigm/tenantchat &nbsp;·&nbsp;
  Local-first · Open source · No data transmitted
</div>

</body>
</html>
"""


class Reporter:
    """Generates PDF and HTML security assessment reports."""

    def generate(
        self,
        result:      AssessmentResult,
        state:       TenantState,
        report_type: str = "technical",
        output_path: str = "report.pdf",
    ) -> str:
        """Generate a report and save to output_path."""
        html = self._render_html(result, state, report_type)

        if output_path.endswith(".html"):
            Path(output_path).write_text(html, encoding="utf-8")
            return output_path

        # Generate PDF via WeasyPrint
        try:
            from weasyprint import HTML
            HTML(string=html).write_pdf(output_path)
        except Exception as e:
            # Fallback to HTML if WeasyPrint fails
            html_path = output_path.replace(".pdf", ".html")
            Path(html_path).write_text(html, encoding="utf-8")
            console.print(
                f"[yellow]PDF generation failed ({e}). "
                f"HTML saved: {html_path}[/yellow]"
            )
            return html_path

        return output_path

    def _render_html(
        self,
        result:      AssessmentResult,
        state:       TenantState,
        report_type: str,
    ) -> str:
        """Render assessment result as HTML."""
        score_color = (
            "#dc2626" if result.posture_score < 50
            else "#d97706" if result.posture_score < 75
            else "#16a34a"
        )

        critical_findings = [
            f for f in result.findings
            if f.status == CheckStatus.FAIL
            and f.severity == Severity.CRITICAL
        ]
        high_findings = [
            f for f in result.findings
            if f.status == CheckStatus.FAIL
            and f.severity == Severity.HIGH
        ]

        status_class_map = {
            CheckStatus.PASS:    "pass",
            CheckStatus.FAIL:    "critical",
            CheckStatus.PARTIAL: "high",
            CheckStatus.UNKNOWN: "medium",
        }

        all_findings = [
            {
                "control_id":   f.control_id,
                "title":        f.title,
                "framework":    f.framework,
                "status":       f.status.value,
                "status_class": status_class_map.get(f.status, ""),
                "severity":     f.severity.value,
                "effort":       f.effort,
                "delta":        f.delta,
                "blast_radius": f.blast_radius,
            }
            for f in result.findings
        ]

        template = Template(EXEC_TEMPLATE)
        return template.render(
            tenant_domain=state.tenant_domain,
            report_type=report_type.capitalize(),
            assessed_at=result.assessed_at.strftime("%Y-%m-%d %H:%M UTC"),
            frameworks=", ".join(result.frameworks),
            score=result.posture_score,
            score_color=score_color,
            critical_count=result.critical_count,
            high_count=result.high_count,
            pass_count=result.pass_count,
            total=result.total_controls,
            critical_findings=critical_findings,
            high_findings=high_findings,
            all_findings=all_findings,
        )
