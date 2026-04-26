"""Keyboard-first CLI — slash commands, tab completion, rich output."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

load_dotenv()

console = Console()


@click.group(invoke_without_command=True)
@click.version_option(version="0.1.0", prog_name="tenantchat")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """tenant.chat — Local-first M365 security assessment agent.

    Connect to your tenant and start a conversation:

      tenantchat auth login
      tenantchat assess
      tenantchat

    Or run a quick assessment:

      tenantchat assess --baseline cis
    """
    if ctx.invoked_subcommand is None:
        asyncio.run(_interactive_mode())


# ── auth ──────────────────────────────────────────────────────────────────────

@cli.group()
def auth() -> None:
    """Manage Microsoft 365 tenant authentication."""


@auth.command("login")
@click.option("--client-id",  default=None, help="Entra app client ID (BYOA).")
@click.option("--tenant-id",  default=None, help="Target tenant ID.")
def auth_login(client_id: str | None, tenant_id: str | None) -> None:
    """Authenticate via browser — no client secret required."""
    from tenantchat.auth import AuthManager
    cid = client_id or os.environ.get("TENANTCHAT_CLIENT_ID", "")
    tid = tenant_id or os.environ.get("TENANTCHAT_TENANT_ID", "organizations")
    if not cid:
        console.print(
            "[red]No client ID.[/red] Set TENANTCHAT_CLIENT_ID or "
            "pass --client-id"
        )
        raise SystemExit(1)
    mgr   = AuthManager(client_id=cid, tenant_id=tid)
    state = mgr.login()
    if state.authenticated:
        console.print(
            f"[green]Authenticated[/green] as "
            f"[bold]{state.account}[/bold] "
            f"({state.tenant_id})"
        )
    else:
        console.print("[red]Authentication failed.[/red]")


@auth.command("status")
def auth_status() -> None:
    """Show current authentication state."""
    from tenantchat.auth import AuthManager
    state = AuthManager().status()
    if state.authenticated:
        console.print(f"[green]Connected[/green]: {state.account}")
        console.print(f"Tenant : {state.tenant_id}")
    else:
        console.print(
            "[yellow]Not connected.[/yellow] Run: tenantchat auth login"
        )


@auth.command("logout")
def auth_logout() -> None:
    """Remove stored credentials from OS keychain."""
    from tenantchat.auth import AuthManager
    AuthManager().logout()
    console.print("[green]Logged out.[/green]")


# ── assess ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--baseline",
    default="all",
    type=click.Choice(
        ["all", "microsoft", "cis", "zero-trust", "nist"],
        case_sensitive=False,
    ),
    help="Baseline framework to assess against.",
    show_default=True,
)
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def assess(baseline: str, as_json: bool) -> None:
    """Run a full security assessment against your tenant."""
    asyncio.run(_run_assessment(baseline=baseline, as_json=as_json))


async def _run_assessment(
    baseline: str = "all",
    as_json:  bool = False,
) -> None:
    from tenantchat.assessor import Assessor
    from tenantchat.auth import AuthManager
    from tenantchat.cluster import Clusterer
    from tenantchat.collector import Collector
    from tenantchat.memory import Memory
    from tenantchat.scrubber import Scrubber
    from tenantchat.models import CheckStatus, Severity

    auth = AuthManager()
    if not auth.status().authenticated:
        console.print(
            "[red]Not authenticated.[/red] Run: tenantchat auth login"
        )
        return

    # Collect
    collector = Collector(auth)
    with console.status("Connecting to tenant..."):
        state = await collector.collect()

    # Scrub PII
    scrubber = Scrubber()
    state.users   = scrubber.scrub_list(state.users,   "user")
    state.guests  = scrubber.scrub_list(state.guests,  "user")
    state.managed_devices = scrubber.scrub_list(
        state.managed_devices, "device"
    )
    state.mfa_registration = scrubber.scrub_list(
        state.mfa_registration, "user"
    )

    # Assess
    assessor = Assessor()
    frameworks = {
        "all":        None,
        "microsoft":  ["Microsoft Baseline Security Mode"],
        "cis":        ["CIS Microsoft 365 v3.1"],
        "zero-trust": ["Microsoft Zero Trust RaMP"],
        "nist":       ["NIST 800-53 M365"],
    }.get(baseline)

    with console.status("Running assessment..."):
        assessor.load_baselines(frameworks=frameworks)
        result = assessor.assess(state)

    # Save to memory
    memory = Memory(tenant_id=state.tenant_id)
    memory.save_assessment(
        tenant_id=state.tenant_id,
        score=result.posture_score,
        critical=result.critical_count,
        high=result.high_count,
        frameworks=result.frameworks,
        finding_count=result.total_controls,
    )

    if as_json:
        import json
        console.print_json(json.dumps({
            "tenant":    state.tenant_domain,
            "score":     result.posture_score,
            "critical":  result.critical_count,
            "high":      result.high_count,
            "findings":  [
                {
                    "id":       f.control_id,
                    "title":    f.title,
                    "status":   f.status.value,
                    "severity": f.severity.value,
                    "delta":    f.delta,
                }
                for f in result.findings
            ],
        }, default=str))
        return

    # Display results
    _display_assessment(result, state)

    # User clusters
    clusterer = Clusterer()
    clusters  = clusterer.cluster_users(
        state.users,
        state.mfa_registration,
        state.managed_devices,
    )
    if clusters:
        _display_clusters(clusters)

    # Score trend
    trend = memory.get_score_trend(state.tenant_id)
    console.print(f"\n[dim]{trend}[/dim]")
    console.print(
        "\n[dim]Run [bold]tenantchat[/bold] for interactive mode "
        "or [bold]tenantchat report[/bold] to generate PDF.[/dim]"
    )


def _display_assessment(result, state) -> None:
    from tenantchat.models import CheckStatus, Severity

    # Header
    score_color = (
        "red"    if result.posture_score < 50
        else "yellow" if result.posture_score < 75
        else "green"
    )
    console.print()
    console.print(Panel(
        f"[bold]TENANT HEALTH — {state.tenant_domain}[/bold]\n"
        f"Score: [{score_color}]{result.posture_score}/100[/{score_color}]  "
        f"Critical: [red]{result.critical_count}[/red]  "
        f"High: [yellow]{result.high_count}[/yellow]  "
        f"Medium: [blue]{result.medium_count}[/blue]  "
        f"Pass: [green]{result.pass_count}[/green]/{result.total_controls}\n"
        f"Frameworks: {', '.join(result.frameworks)}",
        title="tenant.chat",
        border_style="blue",
    ))

    # Critical findings
    critical = [
        f for f in result.findings
        if f.status == CheckStatus.FAIL
        and f.severity == Severity.CRITICAL
    ]
    if critical:
        console.print("\n[bold red]CRITICAL — Fix this week[/bold red]")
        for i, f in enumerate(critical, 1):
            console.print(
                f"  [red]{i}.[/red] {f.title}  "
                f"[dim][{f.control_id}][/dim]"
            )
            if f.delta:
                console.print(f"     [dim]{f.delta}[/dim]")

    # High findings
    high = [
        f for f in result.findings
        if f.status == CheckStatus.FAIL
        and f.severity == Severity.HIGH
    ]
    if high:
        console.print("\n[bold yellow]HIGH — Fix this month[/bold yellow]")
        for i, f in enumerate(high, 1):
            console.print(
                f"  [yellow]{i}.[/yellow] {f.title}  "
                f"[dim][{f.control_id}][/dim]"
            )

    # Medium findings
    medium = [
        f for f in result.findings
        if f.status == CheckStatus.FAIL
        and f.severity == Severity.MEDIUM
    ]
    if medium:
        console.print("\n[bold blue]MEDIUM — Review this quarter[/bold blue]")
        for i, f in enumerate(medium, 1):
            console.print(
                f"  [blue]{i}.[/blue] {f.title}  "
                f"[dim][{f.control_id}][/dim]"
            )


def _display_clusters(clusters) -> None:
    console.print("\n[bold]USER RISK SEGMENTS[/bold]")
    t = Table(
        "Cluster", "Users", "Risk", "Characteristics", "Action",
        show_header=True,
        header_style="bold blue",
    )
    risk_colors = {
        "critical": "red",
        "high":     "yellow",
        "medium":   "blue",
        "low":      "green",
    }
    for c in clusters:
        color = risk_colors.get(c.risk_level, "white")
        t.add_row(
            c.label,
            str(c.user_count),
            f"[{color}]{c.risk_level.upper()}[/{color}]",
            "\n".join(c.characteristics[:2]),
            c.recommended_action[:60] + "..."
            if len(c.recommended_action) > 60
            else c.recommended_action,
        )
    console.print(t)


# ── report ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--type", "report_type",
    default="technical",
    type=click.Choice(["exec", "technical", "audit"], case_sensitive=False),
    help="Report type.",
    show_default=True,
)
@click.option("--output", "-o", default=None, help="Output file path.")
def report(report_type: str, output: str | None) -> None:
    """Generate a PDF security assessment report."""
    asyncio.run(_run_report(report_type=report_type, output=output))


async def _run_report(
    report_type: str = "technical",
    output: str | None = None,
) -> None:
    from tenantchat.auth import AuthManager
    from tenantchat.collector import Collector
    from tenantchat.assessor import Assessor
    from tenantchat.reporter import Reporter
    from tenantchat.scrubber import Scrubber

    auth = AuthManager()
    if not auth.status().authenticated:
        console.print("[red]Not authenticated.[/red] Run: tenantchat auth login")
        return

    collector = Collector(auth)
    with console.status("Collecting tenant state..."):
        state = await collector.collect()

    scrubber = Scrubber()
    state.users  = scrubber.scrub_list(state.users, "user")
    state.guests = scrubber.scrub_list(state.guests, "user")
    state.managed_devices = scrubber.scrub_list(
        state.managed_devices, "device"
    )

    assessor = Assessor()
    with console.status("Running assessment..."):
        assessor.load_baselines()
        result = assessor.assess(state)

    reporter = Reporter()
    out_path = output or (
        f"tenantchat-{report_type}-"
        f"{state.tenant_domain}-"
        f"{result.assessed_at.strftime('%Y%m%d')}.pdf"
    )

    with console.status(f"Generating {report_type} report..."):
        reporter.generate(result, state, report_type, out_path)

    console.print(f"[green]Report saved:[/green] {out_path}")


# ── interactive mode ──────────────────────────────────────────────────────────

async def _interactive_mode() -> None:
    """Full interactive conversational mode."""
    from tenantchat.agent import Agent
    from tenantchat.assessor import Assessor
    from tenantchat.auth import AuthManager
    from tenantchat.collector import Collector
    from tenantchat.memory import Memory
    from tenantchat.scrubber import Scrubber

    console.print(Panel(
        "[bold blue]tenant.chat[/bold blue] v0.1.0\n"
        "Local-first M365 security assessment agent\n\n"
        "Commands: /assess  /blast <change>  /report  "
        "/why <id>  /fix <id>  /history  /quit",
        border_style="blue",
    ))

    auth = AuthManager()
    if not auth.status().authenticated:
        console.print(
            "[yellow]Not connected.[/yellow] "
            "Run: tenantchat auth login"
        )
        return

    state      = None
    assessment = None
    tenant_id  = auth.status().tenant_id
    memory     = Memory(tenant_id=tenant_id)
    agent      = Agent()

    # Show score trend if available
    trend = memory.get_score_trend(tenant_id)
    if "First" not in trend:
        console.print(f"[dim]{trend}[/dim]")

    console.print()

    while True:
        try:
            user_input = console.input("[bold blue]>[/bold blue] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        if not user_input:
            continue

        if user_input.lower() in ("/quit", "/exit", "quit", "exit"):
            console.print("[dim]Goodbye.[/dim]")
            break

        # Collect on first assess
        if "/assess" in user_input.lower() or (
            state is None and "assess" in user_input.lower()
        ):
            collector = Collector(auth)
            scrubber  = Scrubber()
            with console.status("Collecting tenant state..."):
                state = await collector.collect()
                state.users  = scrubber.scrub_list(state.users, "user")
                state.guests = scrubber.scrub_list(state.guests, "user")
                state.managed_devices = scrubber.scrub_list(
                    state.managed_devices, "device"
                )
                state.mfa_registration = scrubber.scrub_list(
                    state.mfa_registration, "user"
                )

            assessor = Assessor()
            with console.status("Running assessment..."):
                assessor.load_baselines()
                assessment = assessor.assess(state)

            _display_assessment(assessment, state)
            memory.save_assessment(
                tenant_id=state.tenant_id,
                score=assessment.posture_score,
                critical=assessment.critical_count,
                high=assessment.high_count,
                frameworks=assessment.frameworks,
                finding_count=assessment.total_controls,
            )
            console.print(
                "\n[dim]Ask me about any finding, or type "
                "/blast <change> to check impact.[/dim]\n"
            )
            continue

        if user_input.startswith("/report"):
            parts       = user_input.split()
            report_type = parts[1] if len(parts) > 1 else "technical"
            await _run_report(report_type=report_type)
            continue

        if user_input.startswith("/history"):
            history = memory.get_assessment_history(tenant_id)
            if not history:
                console.print("[dim]No assessment history yet.[/dim]")
            else:
                for h in history[-5:]:
                    console.print(
                        f"  {h['assessed_at'][:10]}  "
                        f"Score: {h['score']}  "
                        f"Critical: {h['critical']}"
                    )
            continue

        # All other input — send to agent
        with console.status("Thinking..."):
            response = await agent.chat(
                message=user_input,
                tenant_state=state,
                assessment=assessment,
                memory=memory,
                tenant_id=tenant_id,
            )

        console.print(f"\n[bold]tenant.chat[/bold]: {response}\n")
