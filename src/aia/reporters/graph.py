"""Trust chain graph output in DOT (Graphviz) and ASCII formats."""
from __future__ import annotations
from pathlib import Path
from io import StringIO
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


# Framework -> color for DOT output
FRAMEWORK_COLORS = {
    "mcp": "#4A90D9",
    "langchain": "#2ECC71",
    "crewai": "#E67E22",
    "autogen": "#9B59B6",
    "openclaw": "#1ABC9C",
    "openai_agents": "#F39C12",
    "anthropic": "#E74C3C",
    "pi_agent": "#3498DB",
    None: "#95A5A6",
}

# Edge color based on security posture
EDGE_COLORS = {
    "no_auth": "#E74C3C",       # red
    "shared": "#E67E22",         # orange
    "unverified": "#F1C40F",     # yellow
    "verified": "#2ECC71",       # green
    "default": "#95A5A6",        # gray
}


def _edge_color(edge: dict) -> str:
    """Determine edge color based on auth status."""
    if edge.get("auth_method") == "none":
        return EDGE_COLORS["no_auth"]
    if edge.get("shared"):
        return EDGE_COLORS["shared"]
    if edge.get("verified"):
        return EDGE_COLORS["verified"]
    if edge.get("mutual"):
        return EDGE_COLORS["verified"]
    return EDGE_COLORS["unverified"]


def _edge_style_label(edge: dict) -> str:
    """Build edge label for DOT."""
    parts = []
    if edge.get("auth_method"):
        parts.append(edge["auth_method"])
    if edge.get("credential_type"):
        parts.append(edge["credential_type"])
    return "\\n".join(parts) if parts else ""


def generate_dot(trust_graph: dict) -> str:
    """Generate DOT format string from trust_graph.

    Args:
        trust_graph: dict with 'nodes' and 'edges' lists.

    Returns:
        Valid Graphviz DOT format string.
    """
    out = StringIO()
    out.write("digraph trust_chain {\n")
    out.write('  rankdir=LR;\n')
    out.write('  bgcolor="#1a1a2e";\n')
    out.write('  node [style=filled, fontname="Helvetica", fontsize=10];\n')
    out.write('  edge [fontname="Helvetica", fontsize=8];\n\n')

    # Legend
    out.write('  subgraph cluster_legend {\n')
    out.write('    label="Legend";\n')
    out.write('    fontcolor=white;\n')
    out.write('    color=white;\n')
    out.write('    style=dashed;\n')
    out.write('    leg_noauth [label="No Auth" fillcolor="#E74C3C" fontcolor=white shape=plaintext];\n')
    out.write('    leg_shared [label="Shared Creds" fillcolor="#E67E22" fontcolor=white shape=plaintext];\n')
    out.write('    leg_unverified [label="Unverified" fillcolor="#F1C40F" shape=plaintext];\n')
    out.write('    leg_verified [label="Verified" fillcolor="#2ECC71" fontcolor=white shape=plaintext];\n')
    out.write('  }\n\n')

    # Nodes
    for node in trust_graph.get("nodes", []):
        nid = _dot_id(node["id"])
        label = node.get("label", node["id"])
        if node["type"] == "agent":
            color = FRAMEWORK_COLORS.get(node.get("framework"), FRAMEWORK_COLORS[None])
            shape = "box"
            fw = node.get("framework", "")
            label = f"{label}\\n({fw})"
        else:
            color = "#34495E"
            shape = "ellipse"

        out.write(
            f'  {nid} [label="{label}" fillcolor="{color}" '
            f'fontcolor="white" shape={shape}];\n'
        )

    out.write("\n")

    # Edges
    for edge in trust_graph.get("edges", []):
        src = _dot_id(edge["source"])
        tgt = _dot_id(edge["target"])
        color = _edge_color(edge)
        label = _edge_style_label(edge)
        style = "bold" if edge.get("shared") else "solid"
        penwidth = "2.5" if edge.get("shared") else "1.5"

        out.write(
            f'  {src} -> {tgt} [label="{label}" color="{color}" '
            f'fontcolor="{color}" style={style} penwidth={penwidth}];\n'
        )

    out.write("}\n")
    return out.getvalue()


def write_dot(trust_graph: dict, output_path: str | Path) -> None:
    """Write DOT file to disk.

    Args:
        trust_graph: dict with 'nodes' and 'edges'.
        output_path: file path for the .dot output.
    """
    dot = generate_dot(trust_graph)
    Path(output_path).write_text(dot)


def print_ascii_trust_graph(trust_graph: dict, console: Console | None = None) -> None:
    """Print a simple ASCII representation of the trust chain.

    Args:
        trust_graph: dict with 'nodes' and 'edges'.
        console: Rich console for output.
    """
    console = console or Console()

    nodes = trust_graph.get("nodes", [])
    edges = trust_graph.get("edges", [])

    if not nodes:
        console.print("[dim]No trust chain data to display.[/dim]")
        return

    node_labels = {n["id"]: n.get("label", n["id"]) for n in nodes}

    # Group edges by source
    by_source: dict[str, list[dict]] = {}
    for edge in edges:
        by_source.setdefault(edge["source"], []).append(edge)

    lines = []
    agent_nodes = [n for n in nodes if n["type"] == "agent"]
    service_nodes = [n for n in nodes if n["type"] == "service"]

    for agent in agent_nodes:
        aid = agent["id"]
        fw = agent.get("framework", "?")
        ident = agent.get("identity_type", "?")
        lines.append(f"  [{fw}] {node_labels[aid]} (identity: {ident})")

        agent_edges = by_source.get(aid, [])
        for i, edge in enumerate(agent_edges):
            is_last = i == len(agent_edges) - 1
            connector = "  +--" if is_last else "  |--"
            target_label = node_labels.get(edge["target"], edge["target"])
            auth = edge.get("auth_method", "?")
            cred_type = edge.get("credential_type", "")

            # Status indicator
            if edge.get("auth_method") == "none":
                status = "[!] NO AUTH"
            elif edge.get("shared"):
                status = "[!] SHARED"
            elif edge.get("verified"):
                status = "[ok] verified"
            else:
                status = "[~] unverified"

            detail = f"{auth}"
            if cred_type:
                detail += f" ({cred_type})"

            lines.append(f"  {connector}> {target_label}  [{detail}] {status}")
        lines.append("")

    if service_nodes:
        lines.append("  Services:")
        for svc in service_nodes:
            incoming = sum(1 for e in edges if e["target"] == svc["id"])
            lines.append(f"    - {node_labels[svc['id']]} ({incoming} incoming connections)")

    ascii_text = "\n".join(lines)
    console.print(Panel(
        ascii_text,
        title="Trust Chain Map",
        border_style="blue",
    ))


def _dot_id(raw: str) -> str:
    """Sanitize an ID for DOT format."""
    sanitized = raw.replace("-", "_").replace(":", "_").replace("/", "_").replace(".", "_").replace(" ", "_")
    # Ensure it starts with a letter or underscore
    if sanitized and sanitized[0].isdigit():
        sanitized = "n_" + sanitized
    return f'"{raw}"' if not sanitized.isidentifier() else sanitized
