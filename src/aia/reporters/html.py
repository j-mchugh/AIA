"""HTML report generator for AIA scan results."""
from __future__ import annotations
from pathlib import Path
from ..models import ScanResult, Severity, Finding

SEVERITY_COLORS = {
    Severity.CRITICAL: "#e74c3c",
    Severity.HIGH: "#e67e22",
    Severity.MEDIUM: "#f1c40f",
    Severity.LOW: "#3498db",
    Severity.INFO: "#95a5a6",
}

SEVERITY_BG = {
    Severity.CRITICAL: "#2d1215",
    Severity.HIGH: "#2d1f0e",
    Severity.MEDIUM: "#2d2a0e",
    Severity.LOW: "#0e1f2d",
    Severity.INFO: "#161b22",
}


def generate_html(result: ScanResult, trust_graph: dict | None = None) -> str:
    """Generate a self-contained HTML report."""
    summary = result.to_dict()["summary"]
    sev = summary["findings_by_severity"]
    crit = sev.get("critical", 0)
    high = sev.get("high", 0)
    med = sev.get("medium", 0)
    score, risk_breakdown = result.risk_score()
    score_color = "#2ecc71" if score < 30 else "#f1c40f" if score < 60 else "#e74c3c"

    # Build findings HTML
    findings_html = ""
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        sev_findings = [f for f in result.findings if f.severity == severity]
        if not sev_findings:
            continue
        color = SEVERITY_COLORS[severity]
        bg = SEVERITY_BG[severity]
        findings_html += f'<h3 style="color:{color};margin-top:24px">{severity.value.upper()} ({len(sev_findings)})</h3>\n'
        for f in sev_findings:
            affected = ", ".join(a.split(":")[-1] for a in f.affected[:5])
            if len(f.affected) > 5:
                affected += f" (+{len(f.affected)-5} more)"
            findings_html += f'''<div class="finding" style="border-left:4px solid {color};background:{bg}">
  <div class="finding-title">{f.title}</div>
  <div class="finding-desc">{f.description}</div>
  {f'<div class="finding-affected">Affected: {affected}</div>' if affected else ''}
  {f'<div class="finding-location">Location: {", ".join(f.locations[:3])}{" (+" + str(len(f.locations)-3) + " more)" if len(f.locations) > 3 else ""}</div>' if f.locations else ''}
  <div class="finding-rec">Recommendation: {f.recommendation}</div>
  <div class="finding-cat">Category: {f.category} | Exposure: {f.exposure.value}</div>
</div>
'''

    # Build agents table
    agents_rows = ""
    for a in result.agents:
        id_style = 'color:#e74c3c;font-weight:bold' if a.identity_type == 'none' else 'color:#2ecc71'
        agents_rows += f'''<tr>
  <td class="mono">{a.id}</td>
  <td><strong>{a.name}</strong></td>
  <td>{a.framework.value}</td>
  <td style="{id_style}">{a.identity_type}</td>
  <td style="text-align:center">{len(a.credentials)}</td>
</tr>'''

    # Build trust table
    trust_rows = ""
    for t in result.trust_relationships:
        agent_short = t.source_agent.split(":")[-1] if ":" in t.source_agent else t.source_agent
        m_style = "color:#2ecc71" if t.mutual else "color:#e74c3c"
        v_style = "color:#2ecc71" if t.verified else "color:#e74c3c"
        trust_rows += f'''<tr>
  <td>{agent_short}</td>
  <td>{t.target}</td>
  <td>{t.auth_method}</td>
  <td style="{m_style};text-align:center">{"yes" if t.mutual else "no"}</td>
  <td style="{v_style};text-align:center">{"yes" if t.verified else "no"}</td>
</tr>'''

    # Build credential scope table
    cred_rows = ""
    for c in result.credentials:
        shared_style = "color:#e74c3c;font-weight:bold" if c.is_shared else "color:#2ecc71"
        exp_style = "color:#2ecc71" if c.expires else "color:#e74c3c;font-weight:bold"
        cred_rows += f'''<tr>
  <td class="mono">{c.source}</td>
  <td>{c.cred_type.value}</td>
  <td>{c.target_service}</td>
  <td>{c.scope or '<span style="color:#95a5a6">unknown</span>'}</td>
  <td style="{shared_style};text-align:center">{"YES" if c.is_shared else "no"}</td>
  <td style="{exp_style};text-align:center">{c.expires or "NEVER"}</td>
</tr>'''

    # Trust chain ASCII (if available)
    trust_chain_section = ""
    if trust_graph:
        nodes = trust_graph.get("nodes", [])
        edges = trust_graph.get("edges", [])
        node_labels = {n["id"]: n.get("label", n["id"]) for n in nodes}
        by_source = {}
        for edge in edges:
            by_source.setdefault(edge["source"], []).append(edge)

        lines = []
        for node in nodes:
            if node["type"] != "agent":
                continue
            aid = node["id"]
            fw = node.get("framework", "?")
            lines.append(f'[{fw}] {node_labels[aid]}')
            agent_edges = by_source.get(aid, [])
            for i, edge in enumerate(agent_edges):
                connector = "  +--" if i == len(agent_edges) - 1 else "  |--"
                tgt = node_labels.get(edge["target"], edge["target"])
                auth = edge.get("auth_method", "?")
                if edge.get("auth_method") == "none":
                    status = "NO AUTH"
                elif edge.get("shared"):
                    status = "SHARED"
                elif edge.get("verified"):
                    status = "verified"
                else:
                    status = "unverified"
                lines.append(f'{connector}> {tgt}  [{auth}] {status}')
            lines.append("")

        if lines:
            trust_chain_section = f'''<div class="section">
  <h2>Trust Chain Map</h2>
  <pre class="trust-chain">{chr(10).join(lines)}</pre>
</div>'''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIA Scan Report - {result.scan_id}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 40px; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ color: #58a6ff; font-size: 28px; margin-bottom: 4px; }}
  h2 {{ color: #58a6ff; font-size: 20px; margin-bottom: 16px; border-bottom: 1px solid #21262d; padding-bottom: 8px; }}
  h3 {{ font-size: 16px; }}
  .header {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
  .header-meta {{ color: #8b949e; font-size: 14px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }}
  .stat-value {{ font-size: 36px; font-weight: bold; }}
  .stat-label {{ color: #8b949e; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }}
  .score-card {{ background: #161b22; border: 2px solid {score_color}; border-radius: 8px; padding: 24px; text-align: center; margin-bottom: 24px; }}
  .score-value {{ font-size: 48px; font-weight: bold; color: {score_color}; }}
  .score-breakdown {{ color: #8b949e; margin-top: 8px; }}
  .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th {{ background: #21262d; color: #8b949e; text-align: left; padding: 10px 12px; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; }}
  tr:hover td {{ background: #1c2128; }}
  .mono {{ font-family: "SF Mono", "Fira Code", monospace; font-size: 13px; }}
  .finding {{ padding: 14px 16px; margin-bottom: 10px; border-radius: 6px; }}
  .finding-title {{ font-weight: 600; font-size: 15px; margin-bottom: 4px; color: #e6edf3; }}
  .finding-desc {{ font-size: 14px; color: #b1bac4; margin-bottom: 6px; }}
  .finding-affected {{ font-size: 13px; color: #b1bac4; font-family: monospace; }}
  .finding-location {{ font-size: 13px; color: #d2a8ff; font-family: monospace; margin-top: 4px; }}
  .finding-rec {{ font-size: 13px; color: #79c0ff; margin-top: 6px; }}
  .finding-cat {{ font-size: 12px; color: #768390; margin-top: 4px; }}
  .trust-chain {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 16px; font-family: "SF Mono", monospace; font-size: 13px; white-space: pre; overflow-x: auto; color: #58a6ff; }}
  .footer {{ text-align: center; color: #484f58; font-size: 12px; margin-top: 32px; padding-top: 16px; border-top: 1px solid #21262d; }}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>Agent Identity Auditor</h1>
  <div class="header-meta">
    Scan ID: {result.scan_id} | {result.scan_time}<br>
    Path: {result.source_path}<br>
    Frameworks: {', '.join(f.value for f in result.frameworks_detected)}
  </div>
</div>

<div class="score-card">
  <div class="stat-label">Risk Score</div>
  <div class="score-value">{score}/100</div>
  <div class="score-breakdown">{crit} critical / {high} high / {med} medium</div>
  <div style="color:#8b949e;font-size:13px;margin-top:6px">Score weighted by external exploitability (internet &gt; network &gt; local &gt; theoretical)</div>
</div>

<div class="stats">
  <div class="stat-card">
    <div class="stat-value" style="color:#58a6ff">{summary['total_agents']}</div>
    <div class="stat-label">Agents</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:#f1c40f">{summary['total_credentials']}</div>
    <div class="stat-label">Credentials</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:#e67e22">{summary['total_trust_relationships']}</div>
    <div class="stat-label">Trust Relationships</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color:#e74c3c">{summary['total_findings']}</div>
    <div class="stat-label">Findings</div>
  </div>
</div>

{trust_chain_section}

<div class="section">
  <h2>Agents</h2>
  <table>
    <tr><th>ID</th><th>Name</th><th>Framework</th><th>Identity</th><th>Creds</th></tr>
    {agents_rows}
  </table>
</div>

<div class="section">
  <h2>Trust Relationships</h2>
  <table>
    <tr><th>Agent</th><th>Target</th><th>Auth Method</th><th>Mutual</th><th>Verified</th></tr>
    {trust_rows}
  </table>
</div>

<div class="section">
  <h2>Credential Scope</h2>
  <table>
    <tr><th>Credential</th><th>Type</th><th>Target</th><th>Scope</th><th>Shared</th><th>Expires</th></tr>
    {cred_rows}
  </table>
</div>

<div class="section">
  <h2>Findings</h2>
  {findings_html}
</div>

<div class="footer">
  Generated by Agent Identity Auditor (AIA) by Preamble | {result.scan_time}
</div>

</div>
</body>
</html>'''
    return html


def write_html(result: ScanResult, output_path: str | Path, trust_graph: dict | None = None) -> None:
    """Write HTML report to file."""
    html = generate_html(result, trust_graph)
    Path(output_path).write_text(html)
