"""Rich terminal reporter for AIA scan results."""
from __future__ import annotations
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from ..models import ScanResult, Severity, Finding, Exposure


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bright_red",
    Severity.MEDIUM: "bright_yellow",
    Severity.LOW: "bright_cyan",
    Severity.INFO: "bright_black",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: "!",
    Severity.MEDIUM: "~",
    Severity.LOW: "-",
    Severity.INFO: ".",
}


def print_report(
    result: ScanResult,
    console: Console | None = None,
    trust_graph: dict | None = None,
) -> None:
    """Print a full AIA scan report to the terminal.

    Args:
        result: The scan result to display.
        console: Rich console instance.
        trust_graph: Optional trust graph dict for ASCII display.
    """
    console = console or Console()

    # Header
    console.print()
    console.print(Panel.fit(
        "[bold]Agent Identity Auditor (AIA)[/bold]\n"
        f"Scan: {result.scan_id}\n"
        f"Time: {result.scan_time}\n"
        f"Source: {result.source_path}\n"
        f"Frameworks: {', '.join(f.value for f in result.frameworks_detected)}",
        title="AIA Scan Report",
        border_style="blue",
    ))

    # Summary stats
    summary = result.to_dict()["summary"]
    stats_table = Table(show_header=False, box=None, padding=(0, 2))
    stats_table.add_row("Agents discovered:", str(summary["total_agents"]))
    stats_table.add_row("Credentials found:", str(summary["total_credentials"]))
    stats_table.add_row("Trust relationships:", str(summary["total_trust_relationships"]))
    stats_table.add_row("Findings:", str(summary["total_findings"]))
    console.print(Panel(stats_table, title="Summary", border_style="green"))

    # Agents table
    if result.agents:
        agent_table = Table(title="Agents", show_lines=True)
        agent_table.add_column("ID", style="cyan", max_width=40)
        agent_table.add_column("Name", style="bold")
        agent_table.add_column("Framework")
        agent_table.add_column("Identity Type")
        agent_table.add_column("Credentials", justify="center")

        for agent in result.agents:
            identity_style = "bold red" if agent.identity_type == "none" else "green"
            agent_table.add_row(
                agent.id,
                agent.name,
                agent.framework.value,
                Text(agent.identity_type, style=identity_style),
                str(len(agent.credentials)),
            )
        console.print(agent_table)

    # Trust relationships table
    if result.trust_relationships:
        trust_table = Table(title="Trust Relationships", show_lines=True)
        trust_table.add_column("Agent", style="cyan")
        trust_table.add_column("Target", style="yellow")
        trust_table.add_column("Auth Method")
        trust_table.add_column("Mutual?", justify="center")
        trust_table.add_column("Verified?", justify="center")

        for tr in result.trust_relationships:
            mutual = "yes" if tr.mutual else "no"
            verified = "yes" if tr.verified else "no"
            mutual_style = "green" if tr.mutual else "red"
            verified_style = "green" if tr.verified else "red"
            agent_name = tr.source_agent.split(":")[-1] if ":" in tr.source_agent else tr.source_agent
            trust_table.add_row(
                agent_name,
                tr.target,
                tr.auth_method,
                Text(mutual, style=mutual_style),
                Text(verified, style=verified_style),
            )
        console.print(trust_table)

    # --- Trust Chain Map (ASCII) ---
    if trust_graph:
        from .graph import print_ascii_trust_graph
        console.print()
        print_ascii_trust_graph(trust_graph, console)

    # --- Credential Scope Summary ---
    if result.credentials:
        console.print()
        scope_table = Table(title="Credential Scope Analysis", show_lines=True)
        scope_table.add_column("Credential", style="cyan")
        scope_table.add_column("Type")
        scope_table.add_column("Target Service", style="yellow")
        scope_table.add_column("Scope")
        scope_table.add_column("Shared?", justify="center")
        scope_table.add_column("Expires?", justify="center")
        scope_table.add_column("Rotatable?", justify="center")

        for cred in result.credentials:
            shared = Text("YES", style="red") if cred.is_shared else Text("no", style="green")
            expires = Text(cred.expires, style="green") if cred.expires else Text("NEVER", style="red")
            rotatable = Text("yes", style="green") if cred.rotatable else Text("no", style="yellow")
            scope_text = cred.scope or "[unknown]"

            scope_table.add_row(
                cred.source,
                cred.cred_type.value,
                cred.target_service,
                scope_text,
                shared,
                expires,
                rotatable,
            )
        console.print(scope_table)

    # Findings by severity
    if result.findings:
        # Group by category for better organization
        categories = {}
        for f in result.findings:
            categories.setdefault(f.category, []).append(f)

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            sev_findings = [f for f in result.findings if f.severity == severity]
            if not sev_findings:
                continue

            console.print()
            icon = SEVERITY_ICONS[severity]
            color = SEVERITY_COLORS[severity]
            console.print(f"\n[{color}][{icon}] {severity.value.upper()} FINDINGS ({len(sev_findings)})[/{color}]")

            for finding in sev_findings:
                console.print(f"\n  [{color}]{finding.title}[/{color}]")
                console.print(f"    {finding.description}")
                if finding.affected:
                    affected_short = [a.split(":")[-1] for a in finding.affected[:5]]
                    suffix = f" (+{len(finding.affected) - 5} more)" if len(finding.affected) > 5 else ""
                    console.print(f"    Affected: {', '.join(affected_short)}{suffix}")
                if finding.locations:
                    locs_short = [loc.replace(str(Path.home()), "~") for loc in finding.locations[:3]]
                    suffix = f" (+{len(finding.locations) - 3} more)" if len(finding.locations) > 3 else ""
                    console.print(f"    [bold white]Location: {', '.join(locs_short)}{suffix}[/bold white]")
                exp_color = {"internet": "bold red", "network": "yellow", "local": "bright_cyan", "theoretical": "bright_black"}.get(finding.exposure.value, "bright_black")
                console.print(f"    [bright_black]Category: {finding.category}[/bright_black]  [{exp_color}]Exposure: {finding.exposure.value}[/{exp_color}]")
                console.print(f"    [white]Recommendation: {finding.recommendation}[/white]")

    # Risk score (weighted by exploitability)
    console.print()
    score, breakdown = result.risk_score()
    crit = len([f for f in result.findings if f.severity == Severity.CRITICAL])
    high = len([f for f in result.findings if f.severity == Severity.HIGH])
    med = len([f for f in result.findings if f.severity == Severity.MEDIUM])
    score_color = "green" if score < 30 else "yellow" if score < 60 else "red"

    # Exposure breakdown line
    exposure_parts = []
    for exp_name in ["internet", "network", "local", "theoretical"]:
        exp_data = breakdown.get("by_exposure", {}).get(exp_name)
        if exp_data:
            exposure_parts.append(f"{exp_data['count']} {exp_name}")
    exposure_line = " / ".join(exposure_parts) if exposure_parts else "none"

    console.print(Panel(
        f"[bold {score_color}]{score}/100[/bold {score_color}]\n"
        f"{crit} critical / {high} high / {med} medium\n"
        f"[dim]Exposure: {exposure_line}[/dim]\n"
        f"[dim]Score weighted by external exploitability (internet > network > local > theoretical)[/dim]",
        title="Risk Score",
        border_style=score_color,
    ))
    console.print()
