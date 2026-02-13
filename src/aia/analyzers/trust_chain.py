"""Trust Chain Mapping analyzer.

Maps authentication trust chains across multi-agent deployments,
identifies shared credentials, single points of failure, and
missing mutual authentication.
"""
from __future__ import annotations
from collections import defaultdict
from ..models import (
    Agent, Credential, TrustRelationship, Finding, Severity,
)


def analyze_trust_chain(
    agents: list[Agent],
    credentials: list[Credential],
    trust_relationships: list[TrustRelationship],
) -> tuple[list[Finding], dict]:
    """Analyze trust chains and return findings plus a trust graph.

    Returns:
        A tuple of (findings, trust_graph) where trust_graph is a dict
        with 'nodes' and 'edges' suitable for visualization.
    """
    findings: list[Finding] = []
    cred_by_id = {c.id: c for c in credentials}
    agent_by_id = {a.id: a for a in agents}

    # Build graph structure
    nodes: list[dict] = []
    edges: list[dict] = []
    services: set[str] = set()

    # Add agent nodes
    for agent in agents:
        nodes.append({
            "id": agent.id,
            "label": agent.name,
            "type": "agent",
            "framework": agent.framework.value,
            "identity_type": agent.identity_type,
        })

    # Add service/target nodes and edges from trust relationships
    for tr in trust_relationships:
        if tr.target not in agent_by_id and tr.target not in services:
            services.add(tr.target)
            nodes.append({
                "id": tr.target,
                "label": tr.target,
                "type": "service",
                "framework": None,
                "identity_type": None,
            })

        cred = cred_by_id.get(tr.credential_id) if tr.credential_id else None
        edges.append({
            "source": tr.source_agent,
            "target": tr.target,
            "auth_method": tr.auth_method,
            "credential_id": tr.credential_id,
            "credential_type": cred.cred_type.value if cred else None,
            "mutual": tr.mutual,
            "verified": tr.verified,
            "shared": cred.is_shared if cred else False,
        })

    trust_graph = {"nodes": nodes, "edges": edges}

    # --- Finding: Shared credentials ---
    shared_creds = [c for c in credentials if c.is_shared]
    if shared_creds:
        for cred in shared_creds:
            agent_names = []
            for aid in cred.shared_by:
                a = agent_by_id.get(aid)
                agent_names.append(a.name if a else aid)
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Shared credential: '{cred.source}' used by {len(cred.shared_by)} agents",
                description=(
                    f"Credential '{cred.source}' ({cred.cred_type.value}) targeting "
                    f"'{cred.target_service}' is shared by: {', '.join(agent_names)}. "
                    "If one agent is compromised, all agents sharing this credential "
                    "are effectively compromised. The target service cannot distinguish "
                    "which agent made a request."
                ),
                affected=[cred.id] + cred.shared_by,
                recommendation=(
                    "Issue per-agent credentials. Each agent should authenticate "
                    "with its own unique token or key to enable attribution and "
                    "independent revocation."
                ),
                category="shared_credentials",
            ))

    # --- Finding: Credential chains (transitive access) ---
    # Build adjacency: agent -> set of agents it can reach
    agent_peers: dict[str, set[str]] = defaultdict(set)
    for a in agents:
        for peer in a.communicates_with:
            agent_peers[a.id].add(peer)
    for tr in trust_relationships:
        if tr.target in agent_by_id:
            agent_peers[tr.source_agent].add(tr.target)

    # Find transitive credential reach
    agent_creds: dict[str, set[str]] = {a.id: set(a.credentials) for a in agents}
    for agent in agents:
        reachable = _bfs_reachable(agent.id, agent_peers)
        transitive_creds: set[str] = set()
        for r in reachable:
            transitive_creds |= agent_creds.get(r, set())
        extra = transitive_creds - agent_creds.get(agent.id, set())
        if len(extra) > 2:  # Only flag significant chains
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"Credential chain: '{agent.name}' can transitively reach {len(extra)} additional credentials",
                description=(
                    f"Agent '{agent.name}' can reach {len(reachable)} other agents "
                    f"through communication paths, gaining transitive access to "
                    f"{len(extra)} credentials it does not hold directly."
                ),
                affected=[agent.id],
                recommendation=(
                    "Implement delegation policies that restrict which agents can "
                    "request actions from others. Audit transitive trust paths."
                ),
                category="credential_chain",
            ))

    # --- Finding: Missing mutual auth ---
    no_mutual = [tr for tr in trust_relationships if not tr.mutual]
    if no_mutual:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"{len(no_mutual)} trust relationships lack mutual authentication",
            description=(
                f"Out of {len(trust_relationships)} trust relationships, "
                f"{len(no_mutual)} are one-way: the agent authenticates to the "
                "target but the target does not verify the agent's specific "
                "identity. Any holder of the same credential is indistinguishable."
            ),
            affected=list(set(tr.source_agent for tr in no_mutual)),
            recommendation=(
                "Enable mutual TLS (mTLS) or per-agent tokens where possible. "
                "Services should verify which specific agent is calling."
            ),
            category="missing_mutual_auth",
        ))

    # --- Finding: Single points of failure ---
    # A service that all agents depend on through a single credential
    service_agents: dict[str, set[str]] = defaultdict(set)
    for tr in trust_relationships:
        service_agents[tr.target].add(tr.source_agent)
    for service, agent_ids in service_agents.items():
        if len(agent_ids) >= len(agents) and len(agents) > 1:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"Single point of failure: all agents depend on '{service}'",
                description=(
                    f"All {len(agents)} agents have trust relationships with "
                    f"'{service}'. If this service is compromised or goes down, "
                    "the entire agent system is affected."
                ),
                affected=list(agent_ids),
                recommendation=(
                    "Consider redundancy for critical services. Implement "
                    "circuit breakers and fallback strategies."
                ),
                category="single_point_of_failure",
            ))

    # --- Finding: No-auth relationships ---
    no_auth = [tr for tr in trust_relationships if tr.auth_method == "none"]
    if no_auth:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"{len(no_auth)} trust relationships have NO authentication",
            description=(
                "Some agent-to-service or agent-to-agent connections use no "
                "authentication at all. Any process on the network can access "
                "these services as if it were the agent."
            ),
            affected=list(set(tr.source_agent for tr in no_auth)),
            recommendation=(
                "Add authentication to all trust relationships. Even internal "
                "services should require at minimum API key authentication."
            ),
            category="no_authentication",
        ))

    return findings, trust_graph


def _bfs_reachable(start: str, adjacency: dict[str, set[str]]) -> set[str]:
    """Return all nodes reachable from start via BFS (excluding start)."""
    visited: set[str] = set()
    queue = list(adjacency.get(start, set()))
    while queue:
        node = queue.pop(0)
        if node in visited or node == start:
            continue
        visited.add(node)
        queue.extend(adjacency.get(node, set()) - visited)
    return visited
