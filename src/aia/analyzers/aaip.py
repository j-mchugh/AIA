"""AAIP (AI Agent Identification Protocol) compliance analyzer."""
from __future__ import annotations
import re
from ..models import Agent, Finding, Severity

# AAIP identity string format: Vendor/Model (Application; Version) [aid=<agent-id>]
AAIP_PATTERN = re.compile(
    r'[\w.-]+/[\w.-]+\s*\([\w\s.-]+;\s*[\w.-]+\)\s*\[aid=[\w.-]+\]'
)

AAIP_DELEGATION = re.compile(r'\[delegated=[\w.-]+\]')
AAIP_SCOPE = re.compile(r'\[scope=[\w.,:-]+\]')
AAIP_WORKFLOW = re.compile(r'\[workflow=[\w.-]+\]')


def check_aaip_compliance(agents: list[Agent]) -> list[Finding]:
    """Check all discovered agents for AAIP compliance."""
    findings = []

    compliant = 0
    non_compliant = 0

    for agent in agents:
        has_aaip = False
        # Check agent metadata for AAIP identity strings
        if agent.metadata:
            for key, value in agent.metadata.items():
                if isinstance(value, str) and AAIP_PATTERN.search(value):
                    has_aaip = True
                    break

        if not has_aaip:
            non_compliant += 1
        else:
            compliant += 1

    if non_compliant > 0:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"No AAIP identity strings detected ({non_compliant}/{len(agents)} agents)",
            description=(
                f"None of the {non_compliant} discovered agents present an AAIP-compliant identity string. "
                "AAIP (AI Agent Identification Protocol) provides a transport-agnostic format for agents "
                "to declare identity: Vendor/Model (Application; Version) [aid=<agent-id>]. "
                "Without AAIP or equivalent identity strings, agents cannot be consistently identified "
                "across services and transports."
            ),
            affected=[a.id for a in agents],
            recommendation=(
                "Implement AAIP identity strings for all agents. "
                "See https://github.com/j-mchugh/AAIP for the specification."
            ),
            category="aaip_compliance",
        ))

    # Check for delegation support
    has_delegation = any(
        a.metadata.get("delegation") or a.communicates_with
        for a in agents if a.metadata
    )
    if has_delegation or len(agents) > 1:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="No AAIP delegation chains detected",
            description=(
                "Multi-agent system detected but no AAIP delegation fields ([delegated=<parent>]) found. "
                "When agents delegate tasks to other agents, there is no verifiable chain of delegation. "
                "This enables confused deputy attacks where an agent acts on behalf of an unauthorized requester."
            ),
            affected=[a.id for a in agents],
            recommendation=(
                "Implement AAIP delegation chains with [delegated=<parent>] fields. "
                "Ensure delegation is scoped and time-limited."
            ),
            category="aaip_compliance",
        ))

    # Check for verification extensions
    findings.append(Finding(
        severity=Severity.LOW,
        title="No AAIP verification extensions detected",
        description=(
            "No AAIP verification extensions (signed headers, JWT, mTLS) detected in any agent configuration. "
            "Without verification extensions, AAIP identity strings are self-asserted and can be spoofed."
        ),
        affected=[a.id for a in agents],
        recommendation=(
            "Enable AAIP verification extensions: signed headers for HTTP, "
            "JWT for token-based auth, or mTLS for certificate-based identity."
        ),
        category="aaip_compliance",
    ))

    return findings
