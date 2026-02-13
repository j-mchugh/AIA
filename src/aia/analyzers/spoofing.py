"""Identity spoofing analysis for multi-agent systems.

Covers:
- Self-asserted identity (string-only identity, no crypto verification)
- Cross-agent impersonation paths
- Missing mutual authentication
- Prompt injection to agent spoofing vectors
- Framework-specific identity weaknesses
- Message authentication gaps enabling rogue agent injection
"""
from __future__ import annotations
from ..models import Agent, TrustRelationship, Finding, Severity, Framework


def analyze_spoofing_risks(
    agents: list[Agent],
    trust_relationships: list[TrustRelationship],
) -> list[Finding]:
    """Analyze identity spoofing risks across discovered agents."""
    findings = []

    # 1. Self-asserted identity analysis
    string_identity_agents = [a for a in agents if a.identity_type in ("string", "none")]
    if string_identity_agents:
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"Identity spoofing possible: {len(string_identity_agents)} agents use self-asserted identity",
            description=(
                f"Out of {len(agents)} agents discovered, {len(string_identity_agents)} use self-asserted "
                "identity (name strings or no identity at all). Any process that can inject a message "
                "into the agent communication channel can impersonate these agents. There is no "
                "cryptographic verification of sender identity."
            ),
            affected=[a.id for a in string_identity_agents],
            recommendation=(
                "Implement cryptographic agent identity. Each agent should have a unique keypair, "
                "and all messages should be signed. Recipients must verify signatures before processing."
            ),
            category="identity_spoofing",
        ))

    # 2. Cross-agent impersonation paths
    communicating_agents = [a for a in agents if a.communicates_with]
    if communicating_agents:
        for agent in communicating_agents:
            if agent.identity_type in ("string", "none"):
                peer_names = []
                for peer_id in agent.communicates_with:
                    peer = next((a for a in agents if a.id == peer_id), None)
                    if peer:
                        peer_names.append(peer.name)
                if peer_names:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"Agent '{agent.name}' can impersonate: {', '.join(peer_names)}",
                        description=(
                            f"Agent '{agent.name}' communicates with {len(peer_names)} other agents "
                            f"({', '.join(peer_names)}) and uses {agent.identity_type} identity. "
                            "It could send messages claiming to be any of these agents. "
                            "Recipients have no way to verify the true sender."
                        ),
                        affected=[agent.id] + agent.communicates_with,
                        recommendation=(
                            "Implement mutual authentication between agents. "
                            "Use signed messages with per-agent keypairs."
                        ),
                        category="identity_spoofing",
                    ))

    # 3. No mutual authentication on trust relationships
    unverified = [t for t in trust_relationships if not t.mutual]
    if unverified:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"No mutual authentication on {len(unverified)} trust relationships",
            description=(
                f"Of {len(trust_relationships)} trust relationships discovered, {len(unverified)} "
                "have no mutual authentication. The agent authenticates to the service, but the "
                "service does not verify the specific agent's identity. Any agent with the same "
                "credentials is indistinguishable."
            ),
            affected=list(set(t.source_agent for t in unverified)),
            recommendation=(
                "Implement mutual authentication (mTLS) where possible. "
                "Use per-agent credentials so services can distinguish between agents."
            ),
            category="identity_spoofing",
        ))

    # 4. Prompt injection -> agent spoofing vector
    if len(agents) > 1:
        findings.append(Finding(
            severity=Severity.HIGH,
            title="Prompt injection could enable agent impersonation",
            description=(
                f"This system has {len(agents)} agents. If any agent processes untrusted input "
                "(user prompts, retrieved documents, tool outputs), a prompt injection could "
                "cause that agent to send messages impersonating another agent. Without message "
                "authentication, the receiving agent or service cannot detect the impersonation."
            ),
            affected=[a.id for a in agents],
            recommendation=(
                "1. Implement message signing between agents. "
                "2. Validate all inter-agent messages against expected schemas. "
                "3. Apply prompt injection defenses on all agents that process untrusted input."
            ),
            category="identity_spoofing",
        ))

    # 5. Framework-specific identity weaknesses
    framework_agents: dict[Framework, list[Agent]] = {}
    for a in agents:
        framework_agents.setdefault(a.framework, []).append(a)

    # Frameworks with known weak identity models
    weak_identity_frameworks = {
        Framework.MCP: "MCP servers identify via name strings only; no built-in auth between client and server",
        Framework.LANGCHAIN: "LangChain agents use class names as identity; no message signing between chains",
        Framework.CREWAI: "CrewAI agents identified by role strings; crew membership is not cryptographically verified",
        Framework.AUTOGEN: "AutoGen agents use name strings; group chat messages are not authenticated",
        Framework.OPENAI_AGENTS: "OpenAI Agents SDK uses name strings; handoffs have no identity verification",
        Framework.ANTHROPIC: "Anthropic tool-use agents have no persistent identity across turns",
        Framework.PI_AGENT: "Pi agent toolkit agents identified by config; no built-in inter-agent auth",
    }

    for fw, description in weak_identity_frameworks.items():
        fw_agents = framework_agents.get(fw, [])
        if fw_agents:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"Framework identity weakness: {fw.value} ({len(fw_agents)} agents)",
                description=(
                    f"{description}. "
                    f"Affected agents: {', '.join(a.name for a in fw_agents)}."
                ),
                affected=[a.id for a in fw_agents],
                recommendation=(
                    "Implement application-level identity verification on top of "
                    "the framework. Use signed messages or mTLS between agents."
                ),
                category="framework_identity_weakness",
            ))

    # 6. Missing message authentication (rogue agent injection)
    multi_agent_comms = [a for a in agents if a.communicates_with]
    if multi_agent_comms:
        # Check if any trust relationship has verified=True
        has_any_verified = any(tr.verified for tr in trust_relationships)
        if not has_any_verified:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="No message authentication between agents -- rogue injection possible",
                description=(
                    f"{len(multi_agent_comms)} agents communicate with peers, but "
                    "no inter-agent trust relationship uses verified identity. "
                    "A rogue process could inject messages into agent workflows "
                    "by mimicking the expected message format. There is no "
                    "cryptographic proof of message origin."
                ),
                affected=[a.id for a in multi_agent_comms],
                recommendation=(
                    "Implement message-level authentication (HMAC, digital signatures) "
                    "for all inter-agent communication. Validate message origin before processing."
                ),
                category="rogue_injection",
            ))

    return findings


def analyze_delegation_risks(
    agents: list[Agent],
    trust_relationships: list[TrustRelationship],
) -> list[Finding]:
    """Analyze credential delegation and confused deputy risks."""
    findings = []

    # Find transitive trust paths
    # If Agent A can talk to Agent B, and Agent B has credentials Agent A doesn't,
    # Agent A can effectively access those resources through Agent B
    agent_creds = {a.id: set(a.credentials) for a in agents}
    agent_peers = {a.id: set(a.communicates_with) for a in agents}

    for agent in agents:
        if not agent.communicates_with:
            continue

        own_creds = agent_creds.get(agent.id, set())
        for peer_id in agent.communicates_with:
            peer_creds = agent_creds.get(peer_id, set())
            extra_creds = peer_creds - own_creds
            if extra_creds:
                peer = next((a for a in agents if a.id == peer_id), None)
                peer_name = peer.name if peer else peer_id
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"Confused deputy: '{agent.name}' can access '{peer_name}' credentials via delegation",
                    description=(
                        f"Agent '{agent.name}' can communicate with '{peer_name}', which holds "
                        f"{len(extra_creds)} credential(s) that '{agent.name}' does not have directly. "
                        f"'{agent.name}' could ask '{peer_name}' to make requests on its behalf, "
                        "effectively bypassing credential boundaries. There is no delegation policy "
                        "to prevent or audit this."
                    ),
                    affected=[agent.id, peer_id],
                    recommendation=(
                        "Implement explicit delegation policies. Agent B should verify whether "
                        "Agent A is authorized to request delegated actions. Log all delegation events."
                    ),
                    category="confused_deputy",
                ))

    return findings
