"""AIA CLI -- Agent Identity Auditor.

Three core capabilities:
1. Trust Chain Mapping - Map authentication trust chains across agent deployments
2. Credential Scope Analysis - Detect excess privilege and credential hygiene issues
3. Identity Spoofing Detection - Find impersonation and injection vectors
"""
from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console

from .models import ScanResult, Framework
from .scanners.base import is_broad_scan
from .scanners.mcp import MCPScanner
from .scanners.langchain import LangChainScanner
from .scanners.crewai import CrewAIScanner
from .scanners.autogen import AutoGenScanner
from .scanners.openclaw import OpenClawScanner
from .scanners.openai_agents import OpenAIAgentsScanner
from .scanners.anthropic_agents import AnthropicAgentsScanner
from .scanners.pi_agent import PiAgentScanner
from .analyzers.aaip import check_aaip_compliance
from .analyzers.spoofing import analyze_spoofing_risks, analyze_delegation_risks
from .analyzers.trust_chain import analyze_trust_chain
from .analyzers.credential_scope import analyze_credential_scope
from .analyzers.exposure import classify_all_findings
from .reporters.terminal import print_report
from .reporters.html import write_html
from .reporters.graph import write_dot, print_ascii_trust_graph


SCANNERS = [
    MCPScanner(),
    LangChainScanner(),
    CrewAIScanner(),
    AutoGenScanner(),
    OpenClawScanner(),
    OpenAIAgentsScanner(),
    AnthropicAgentsScanner(),
    PiAgentScanner(),
]

console = Console()


def _run_scanners(scan_path: Path, include_system: bool = True):
    """Run all scanners against a path and return raw results.
    
    By default, runs all scanners regardless of detect() results to ensure
    system-wide configs (Claude Desktop, OpenClaw, etc.) are always checked.
    Scanners that check hardcoded system paths will find configs even if the
    scan_path doesn't contain framework-specific files.
    """
    all_agents = []
    all_credentials = []
    all_trust = []
    all_findings = []
    detected_frameworks = []

    broad = is_broad_scan(scan_path)

    for scanner in SCANNERS:
        # On broad scans (home dir), only run config-based scanners
        # Source-code scanners would rglob the entire home dir
        if broad and not scanner.config_based:
            continue

        should_run = scanner.detect(scan_path) or include_system
        if should_run:
            detected_frameworks.append(scanner.framework)
            agents, creds, trust, findings = scanner.scan(scan_path)
            all_agents.extend(agents)
            all_credentials.extend(creds)
            all_trust.extend(trust)
            all_findings.extend(findings)

    if broad:
        console.print("[dim]Broad scan: checking system configs (Claude Desktop, OpenClaw, etc.)[/dim]")
        console.print("[dim]To scan source code for framework patterns, use --dir with a project path[/dim]")

    if not all_agents:
        console.print("[yellow]No agent configurations found.[/yellow]")

    return all_agents, all_credentials, all_trust, all_findings, detected_frameworks


def _build_result(scan_path, agents, credentials, trust, findings, frameworks, run_analyzers=True):
    """Build a ScanResult, optionally running all analyzers."""
    trust_graph = None

    if run_analyzers and agents:
        findings.extend(check_aaip_compliance(agents))
        findings.extend(analyze_spoofing_risks(agents, trust))
        findings.extend(analyze_delegation_risks(agents, trust))

        tc_findings, trust_graph = analyze_trust_chain(agents, credentials, trust)
        findings.extend(tc_findings)

        findings.extend(analyze_credential_scope(agents, credentials))

    # Post-process: resolve affected IDs to file locations
    agent_locations = {a.id: a.source_file for a in agents if a.source_file}
    cred_locations = {}
    for c in credentials:
        # Credentials don't have source_file directly; resolve via agents that use them
        for a in agents:
            if c.id in a.credentials and a.source_file:
                cred_locations[c.id] = a.source_file
                break
        if c.id not in cred_locations and c.source:
            cred_locations[c.id] = c.source  # fallback to credential source field

    for finding in findings:
        if not finding.locations:
            locs = set()
            for affected_id in finding.affected:
                if affected_id in agent_locations:
                    locs.add(agent_locations[affected_id])
                elif affected_id in cred_locations:
                    locs.add(cred_locations[affected_id])
            finding.locations = sorted(locs)

    # Post-process: classify exposure/exploitability for risk scoring
    classify_all_findings(findings)

    result = ScanResult(
        scan_id=str(uuid.uuid4())[:8],
        scan_time=datetime.now(timezone.utc).isoformat(),
        source_path=str(scan_path.resolve()) if hasattr(scan_path, 'resolve') else str(scan_path),
        frameworks_detected=frameworks,
        agents=agents,
        credentials=credentials,
        trust_relationships=trust,
        findings=findings,
    )

    return result, trust_graph


@click.group()
@click.version_option(version="0.2.0")
def main():
    """AIA -- Agent Identity Auditor

    Map authentication trust chains, analyze credential scope, and detect
    identity spoofing risks in AI agent deployments.

    Supports: MCP, LangChain, CrewAI, AutoGen, OpenClaw, OpenAI Agents,
    Anthropic, and Pi Agent frameworks.

    Core capabilities:
      1. Trust Chain Mapping   - Map auth chains, shared creds, single points of failure
      2. Credential Scope      - Detect excess privilege, missing expiry, hardcoded secrets
      3. Identity Spoofing     - Find impersonation vectors, missing message auth
    """
    pass


@main.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to a specific config file")
@click.option("--dir", "-d", "directory", type=click.Path(exists=True), default=None, help="Directory to scan (default: home directory)")
@click.option("--format", "-f", "output_format", type=click.Choice(["terminal", "json", "html", "both"]), default="terminal", help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file path (for json/html format)")
@click.option("--include-system", is_flag=True, default=True, help="Also scan system-wide configs (default: True)")
@click.option("--no-system", is_flag=True, help="Skip system-wide configs, only scan target directory")
@click.option("--graph", type=click.Path(), help="Output DOT file for trust chain graph (Graphviz)")
def scan(config, directory, output_format, output, include_system, no_system, graph):
    """Scan agent configurations for identity and authentication issues.

    By default, scans from the home directory and includes all system-wide
    agent configs (Claude Desktop, OpenClaw, etc.). Use --dir to target a
    specific directory, or --no-system to skip system configs.

    Runs all three analysis capabilities: trust chain mapping,
    credential scope analysis, and identity spoofing detection.
    """
    if config:
        scan_path = Path(config)
    elif directory:
        scan_path = Path(directory)
    else:
        scan_path = Path.home()

    if no_system:
        include_system = False

    console.print(f"\n[bold blue]AIA Scanning:[/bold blue] {scan_path.resolve()}")
    if include_system:
        console.print("[dim]Including system-wide configs[/dim]")

    agents, creds, trust, findings, frameworks = _run_scanners(scan_path, include_system)
    result, trust_graph = _build_result(scan_path, agents, creds, trust, findings, frameworks)

    # Output
    if output_format in ("terminal", "both"):
        print_report(result, console, trust_graph=trust_graph)

    if output_format in ("json", "both"):
        json_output = result.to_json()
        if output:
            out_path = output if output.endswith(".json") else output + ".json"
            Path(out_path).write_text(json_output)
            console.print(f"\n[green]JSON report written to {out_path}[/green]")
        else:
            if output_format == "json":
                click.echo(json_output)

    if output_format == "html" or (output_format == "both" and output):
        html_path = output or f"aia-report-{result.scan_id}.html"
        if not html_path.endswith(".html"):
            html_path += ".html"
        write_html(result, html_path, trust_graph=trust_graph)
        console.print(f"\n[green]HTML report written to {html_path}[/green]")

    if graph and trust_graph:
        write_dot(trust_graph, graph)
        console.print(f"\n[green]Trust chain DOT graph written to {graph}[/green]")
        console.print(f"[dim]Render with: dot -Tpng {graph} -o trust-chain.png[/dim]")

    return result


@main.command(name="trust-map")
@click.option("--dir", "-d", "directory", type=click.Path(exists=True), default=None, help="Directory to scan (default: home)")
@click.option("--graph", type=click.Path(), help="Output DOT file")
def trust_map(directory, graph):
    """Map trust chains between agents, credentials, and services.

    Shows which agents share credentials, where single points of failure
    exist, and which trust relationships lack mutual authentication.
    """
    scan_path = Path(directory) if directory else Path.home()
    console.print(f"\n[bold blue]AIA Trust Chain Map:[/bold blue] {scan_path.resolve()}")

    agents, creds, trust, findings, frameworks = _run_scanners(scan_path)

    if not agents:
        console.print("[yellow]No agents found.[/yellow]")
        return

    tc_findings, trust_graph = analyze_trust_chain(agents, creds, trust)

    if trust_graph:
        print_ascii_trust_graph(trust_graph, console)

    if graph and trust_graph:
        write_dot(trust_graph, graph)
        console.print(f"\n[green]DOT graph written to {graph}[/green]")

    if tc_findings:
        console.print(f"\n[bold]Trust Chain Findings ({len(tc_findings)}):[/bold]")
        for f in tc_findings:
            icon = {"critical": "[red]!![/red]", "high": "[red]![/red]", "medium": "[yellow]~[/yellow]", "low": "[cyan]-[/cyan]"}.get(f.severity.value, " ")
            console.print(f"  {icon} {f.title}")
            console.print(f"    [dim]{f.recommendation}[/dim]")


@main.command()
@click.option("--dir", "-d", "directory", type=click.Path(exists=True), default=None, help="Directory to scan (default: home)")
def scope(directory):
    """Analyze credential scope for excess privilege and hygiene issues.

    Checks for overly broad scopes, missing expiry, hardcoded credentials,
    non-rotatable secrets, and user-inherited credentials.
    """
    scan_path = Path(directory) if directory else Path.home()
    console.print(f"\n[bold blue]AIA Credential Scope Analysis:[/bold blue] {scan_path.resolve()}")

    agents, creds, trust, findings, frameworks = _run_scanners(scan_path)

    if not creds:
        console.print("[yellow]No credentials found.[/yellow]")
        return

    scope_findings = analyze_credential_scope(agents, creds)

    console.print(f"\n[bold]Credentials analyzed: {len(creds)}[/bold]")
    console.print(f"[bold]Findings: {len(scope_findings)}[/bold]\n")

    for f in scope_findings:
        icon = {"critical": "[red]!![/red]", "high": "[red]![/red]", "medium": "[yellow]~[/yellow]", "low": "[cyan]-[/cyan]"}.get(f.severity.value, " ")
        console.print(f"  {icon} [{f.severity.value.upper()}] {f.title}")
        console.print(f"    {f.description}")
        console.print(f"    [dim]{f.recommendation}[/dim]\n")


@main.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["terminal", "html", "json"]), default="terminal", help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def report(input_file, output_format, output):
    """Render a report from a previous JSON scan.

    Re-renders a saved JSON scan as a polished terminal display, HTML
    report, or pretty-printed JSON.
    """
    from .models import ScanResult, Severity, CredentialType, Framework, Exposure, Agent, Credential, TrustRelationship, Finding

    with open(input_file) as f:
        data = json.load(f)

    # Reconstruct ScanResult from JSON
    agents = [
        Agent(
            id=a["id"], name=a["name"],
            framework=Framework(a["framework"]),
            identity_type=a["identity_type"],
            credentials=a.get("credentials", []),
            communicates_with=a.get("communicates_with", []),
            source_file=a.get("source_file"),
        )
        for a in data.get("agents", [])
    ]
    credentials = [
        Credential(
            id=c["id"], cred_type=CredentialType(c["type"]),
            source=c["source"], target_service=c["target_service"],
            shared_by=c.get("shared_by", []),
            scope=c.get("scope"),
        )
        for c in data.get("credentials", [])
    ]
    trust = [
        TrustRelationship(
            source_agent=t["source_agent"], target=t["target"],
            credential_id=t.get("credential_id"),
            auth_method=t["auth_method"],
            mutual=t.get("mutual_auth", False),
            verified=t.get("identity_verified", False),
        )
        for t in data.get("trust_relationships", [])
    ]
    findings = [
        Finding(
            severity=Severity(f["severity"]), title=f["title"],
            description=f["description"], affected=f.get("affected", []),
            recommendation=f["recommendation"], category=f["category"],
            exposure=Exposure(f["exposure"]) if "exposure" in f else Exposure.LOCAL,
            locations=f.get("locations", []),
        )
        for f in data.get("findings", [])
    ]

    result = ScanResult(
        scan_id=data.get("scan_id", "unknown"),
        scan_time=data.get("scan_time", "unknown"),
        source_path=data.get("source_path", "unknown"),
        frameworks_detected=[Framework(f) for f in data.get("frameworks_detected", [])],
        agents=agents, credentials=credentials,
        trust_relationships=trust, findings=findings,
    )

    if output_format == "terminal":
        print_report(result, console)
    elif output_format == "html":
        html_path = output or f"aia-report-{result.scan_id}.html"
        if not html_path.endswith(".html"):
            html_path += ".html"
        write_html(result, html_path)
        console.print(f"[green]HTML report written to {html_path}[/green]")
    else:
        click.echo(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
