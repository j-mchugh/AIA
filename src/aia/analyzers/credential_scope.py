"""Credential Scope analyzer.

Evaluates credential privileges against agent requirements,
flagging excess privilege, missing expiry, non-rotatable credentials,
and unknown or unlimited scope.
"""
from __future__ import annotations
from ..models import (
    Agent, Credential, Finding, Severity, CredentialType,
)


# Credential types that are inherently non-rotatable or risky
NON_ROTATABLE_TYPES = {CredentialType.HARDCODED, CredentialType.USER_INHERITED}

# Scope keywords that suggest broad/admin access
BROAD_SCOPE_KEYWORDS = [
    "admin", "full", "write", "all", "*", "root", "owner",
    "manage", "delete", "sudo", "superuser",
]

# Scope keywords that suggest read-only / limited access
NARROW_SCOPE_KEYWORDS = [
    "read", "readonly", "viewer", "list", "get",
]


def analyze_credential_scope(
    agents: list[Agent],
    credentials: list[Credential],
) -> list[Finding]:
    """Analyze credential scopes for excess privilege and hygiene issues.

    Checks each credential for:
    - Excess privilege (broad scope when agent likely needs narrow)
    - Missing expiry
    - Non-rotatable credentials
    - Unknown or unlimited scope
    """
    findings: list[Finding] = []
    agent_by_id = {a.id: a for a in agents}

    # --- Unknown/missing scope ---
    no_scope = [c for c in credentials if not c.scope]
    if no_scope:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"{len(no_scope)} credentials have unknown or undeclared scope",
            description=(
                f"Out of {len(credentials)} credentials discovered, "
                f"{len(no_scope)} have no declared scope or permissions. "
                "Without knowing what a credential can access, it is impossible "
                "to verify least-privilege or detect excess access."
            ),
            affected=[c.id for c in no_scope],
            recommendation=(
                "Audit all credentials and document their scope. Use scoped "
                "tokens where possible (e.g., GitHub fine-grained tokens, "
                "OAuth scopes, IAM policies with least privilege)."
            ),
            category="unknown_scope",
        ))

    # --- Excess privilege ---
    for cred in credentials:
        if not cred.scope:
            continue
        scope_lower = cred.scope.lower()
        is_broad = any(kw in scope_lower for kw in BROAD_SCOPE_KEYWORDS)
        if is_broad:
            agent_names = []
            for aid in cred.shared_by:
                a = agent_by_id.get(aid)
                agent_names.append(a.name if a else aid)
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Excess privilege: '{cred.source}' has broad scope '{cred.scope}'",
                description=(
                    f"Credential '{cred.source}' targeting '{cred.target_service}' "
                    f"has scope '{cred.scope}' which includes broad/admin permissions. "
                    f"Used by: {', '.join(agent_names) if agent_names else 'unknown'}. "
                    "Agents should use the minimum scope required for their function."
                ),
                affected=[cred.id] + cred.shared_by,
                recommendation=(
                    "Reduce credential scope to minimum required permissions. "
                    "Create separate credentials with narrow scopes for each agent."
                ),
                category="excess_privilege",
            ))

    # --- No expiry ---
    no_expiry = [c for c in credentials if not c.expires and c.cred_type != CredentialType.NONE]
    if no_expiry:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"{len(no_expiry)} credentials have no expiry configured",
            description=(
                f"{len(no_expiry)} credentials have no expiration date. "
                "Long-lived credentials increase the window of exposure if "
                "compromised. API keys and tokens should be rotated regularly."
            ),
            affected=[c.id for c in no_expiry],
            recommendation=(
                "Set expiry on all credentials. Use short-lived tokens "
                "(hours/days) where possible. Implement automated rotation."
            ),
            category="no_expiry",
        ))

    # --- Non-rotatable ---
    non_rotatable = [
        c for c in credentials
        if not c.rotatable and c.cred_type not in (CredentialType.NONE, CredentialType.UNKNOWN)
    ]
    if non_rotatable:
        hardcoded = [c for c in non_rotatable if c.cred_type == CredentialType.HARDCODED]
        if hardcoded:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title=f"{len(hardcoded)} hardcoded credentials detected",
                description=(
                    "Hardcoded credentials cannot be rotated without code changes "
                    "and redeployment. If exposed (e.g., in version control), "
                    "they require emergency rotation and code updates."
                ),
                affected=[c.id for c in hardcoded],
                recommendation=(
                    "Move all credentials to environment variables or a secrets "
                    "manager. Never commit credentials to source control."
                ),
                category="hardcoded_credentials",
            ))

        env_non_rotatable = [c for c in non_rotatable if c.cred_type != CredentialType.HARDCODED]
        if env_non_rotatable:
            findings.append(Finding(
                severity=Severity.LOW,
                title=f"{len(env_non_rotatable)} credentials are not marked as rotatable",
                description=(
                    "These credentials do not have automated rotation configured. "
                    "Manual rotation is error-prone and often neglected."
                ),
                affected=[c.id for c in env_non_rotatable],
                recommendation=(
                    "Implement automated credential rotation using a secrets manager "
                    "(e.g., AWS Secrets Manager, HashiCorp Vault, 1Password)."
                ),
                category="non_rotatable",
            ))

    # --- User-inherited credentials ---
    inherited = [c for c in credentials if c.cred_type == CredentialType.USER_INHERITED]
    if inherited:
        findings.append(Finding(
            severity=Severity.HIGH,
            title=f"{len(inherited)} agents use user-inherited credentials",
            description=(
                "These agents operate with the user's own credentials rather than "
                "dedicated service credentials. This means agents have the same "
                "access as the user, violating least privilege. Actions taken by "
                "the agent are indistinguishable from user actions in audit logs."
            ),
            affected=[c.id for c in inherited],
            recommendation=(
                "Create dedicated service accounts or API keys for agents. "
                "Apply the principle of least privilege to agent credentials."
            ),
            category="user_inherited",
        ))

    return findings
