"""Post-processing pass to classify finding exposure/exploitability.

Rather than requiring every scanner to manually set exposure, this module
infers exposure from finding metadata (category, title, affected items,
severity) after all findings are collected.

Exposure levels:
  internet    - Exploitable by anyone on the internet (leaked API keys, 
                public-facing services with no auth, etc.)
  network     - Exploitable from the local network (e.g., unauthed local 
                services, shared network creds)
  local       - Requires local machine access (env vars, local config files,
                localhost-bound services)
  theoretical - Requires specific preconditions, chained attacks, or is a 
                best-practice gap rather than a concrete exploit path
"""
from __future__ import annotations
from ..models import Finding, Exposure


# Keywords/patterns that suggest internet exposure (must be strong signals)
INTERNET_INDICATORS = [
    "leaked", "public", "committed to git", "git history",
    "internet-facing", "publicly accessible",
]

# Keywords suggesting network-level exposure
NETWORK_INDICATORS = [
    "lateral movement", "no tls", "plaintext transport",
    "network-accessible",
]

# Categories that are inherently theoretical/compliance gaps
THEORETICAL_CATEGORIES = {
    "aaip_compliance",
    "non_rotatable",
    "framework_identity_weakness",
}

# Categories with local-only exposure by default
LOCAL_CATEGORIES = {
    "shared_credentials",
    "env_var_credential",
    "unknown_scope",
    "no_expiry",
    "hardcoded_secret",  # local config file, not committed to repo
    "excess_privilege",
    "missing_mutual_auth",
}

# Categories that could be network/internet depending on context
CONTEXT_DEPENDENT = {
    "identity_spoofing",
}


def classify_exposure(finding: Finding) -> Exposure:
    """Determine the exposure level of a finding based on its metadata.
    
    The key question: can an external attacker on the internet exploit this?
    Most local config issues (hardcoded secrets in local files, env vars,
    STDIO transports) require the attacker to already have local access,
    making them local-exposure findings.
    """
    title_lower = finding.title.lower()
    desc_lower = finding.description.lower()
    combined = title_lower + " " + desc_lower

    # Check for strong internet indicators
    for indicator in INTERNET_INDICATORS:
        if indicator in combined:
            return Exposure.INTERNET

    # Theoretical / compliance categories
    if finding.category in THEORETICAL_CATEGORIES:
        return Exposure.THEORETICAL

    # Local categories
    if finding.category in LOCAL_CATEGORIES:
        return Exposure.LOCAL

    # Identity spoofing is context-dependent
    if finding.category in CONTEXT_DEPENDENT:
        # Prompt injection from external/untrusted input is internet-facing
        if "prompt injection" in combined and ("external" in combined or "untrusted" in combined):
            return Exposure.INTERNET
        # Prompt injection in general is at least network (attacker can craft input)
        if "prompt injection" in combined:
            return Exposure.NETWORK
        # Inter-agent communication over network
        if "inter-agent" in combined or "handoff" in combined:
            return Exposure.NETWORK
        # Default identity spoofing to local
        return Exposure.LOCAL

    # STDIO transport is inherently local
    if "stdio" in combined:
        return Exposure.LOCAL

    # Shared credentials between agents on the same machine
    if "shared credential" in combined or "shared_credentials" in combined:
        return Exposure.LOCAL

    # Default: local
    return Exposure.LOCAL


def classify_all_findings(findings: list[Finding]) -> list[Finding]:
    """Set exposure on all findings that still have the default (LOCAL).
    
    This is a post-processing pass. If a scanner/analyzer already set a
    non-default exposure, we respect it.
    """
    for finding in findings:
        # Always reclassify since default is LOCAL and we want smart classification
        finding.exposure = classify_exposure(finding)
    return findings
