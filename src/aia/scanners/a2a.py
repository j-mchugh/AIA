# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jeremy McHugh
"""A2A (Agent-to-Agent) protocol scanner."""
from __future__ import annotations
import json
import re
from pathlib import Path

from .base import BaseScanner, safe_rglob
from ..models import (
    Agent, Credential, TrustRelationship, Finding,
    Framework, CredentialType, Severity,
)

A2A_FILE_PATTERNS = ["*.json", "*.py", "*.yaml", "*.yml"]
AGENT_CARD_INDICATORS = ["agentCard", "agent_card", "AgentCard"]
SECURITY_SCHEMES_PATTERN = re.compile(r'"securitySchemes"|security_schemes|SecurityScheme', re.IGNORECASE)
A2A_IMPORT_PATTERN = re.compile(r'from\s+a2a|import\s+a2a|from\s+google\.a2a')
AGENT_CARD_JSON_PATTERN = re.compile(r'"name".*"url".*"skills"|"skills".*"name".*"url"', re.DOTALL)
WELL_KNOWN_PATTERN = re.compile(r'\.well-known/agent\.json|agent_card_url')


class A2AScanner(BaseScanner):
    framework = Framework.A2A

    def detect(self, path: Path) -> bool:
        if path.is_file():
            return self._file_has_a2a(path)
        for pattern in A2A_FILE_PATTERNS:
            for f in safe_rglob(path, pattern):
                if self._file_has_a2a(f):
                    return True
        return False

    def _file_has_a2a(self, path: Path) -> bool:
        try:
            content = path.read_text(errors="ignore")
            if any(ind in content for ind in AGENT_CARD_INDICATORS):
                return True
            if A2A_IMPORT_PATTERN.search(content):
                return True
            if WELL_KNOWN_PATTERN.search(content):
                return True
            return False
        except Exception:
            return False

    def scan(self, path: Path) -> tuple[
        list[Agent], list[Credential], list[TrustRelationship], list[Finding]
    ]:
        agents = []
        credentials = []
        trust_rels = []
        findings = []

        files = [path] if path.is_file() else [
            f for pat in A2A_FILE_PATTERNS for f in safe_rglob(path, pat)
        ]

        for src_file in files:
            if not self._file_has_a2a(src_file):
                continue
            try:
                a, c, t, f = self._scan_file(src_file)
                agents.extend(a)
                credentials.extend(c)
                trust_rels.extend(t)
                findings.extend(f)
            except Exception as e:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"Parse error: {src_file.name}",
                    description=str(e),
                    affected=[],
                    recommendation="Check file for syntax errors",
                    category="scan_error",
                ))

        return agents, credentials, trust_rels, findings

    def _scan_file(self, path: Path) -> tuple[
        list[Agent], list[Credential], list[TrustRelationship], list[Finding]
    ]:
        agents = []
        credentials = []
        trust_rels = []
        findings = []
        content = path.read_text(errors="ignore")

        agent_id = f"a2a:{path.stem}"
        agent = Agent(
            id=agent_id,
            name=path.stem,
            framework=Framework.A2A,
            identity_type="none",
            source_file=str(path),
            metadata={"protocol": "a2a"},
        )

        has_security = bool(SECURITY_SCHEMES_PATTERN.search(content))

        # Credential acquisition out of band
        findings.append(Finding(
            severity=Severity.HIGH,
            title="A2A credential acquisition is out of band",
            description=f"File '{path.name}' defines or references an A2A AgentCard. The A2A protocol specifies security schemes in the AgentCard but credential acquisition (obtaining tokens/keys) happens out of band. There is no standard mechanism for agents to securely bootstrap trust.",
            affected=[agent_id],
            recommendation="Implement a secure credential bootstrapping protocol; consider mutual TLS or DID-based identity",
            category="identity_spoofing",
            locations=[str(path)],
        ))

        # No per-instance cryptographic identity
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="No per-instance cryptographic identity for A2A agents",
            description=f"File '{path.name}' uses A2A patterns. A2A AgentCards identify agent types but not specific instances. Multiple instances of the same agent share the same card and cannot be cryptographically distinguished.",
            affected=[agent_id],
            recommendation="Extend AgentCard with per-instance identity (e.g., instance-specific public keys or DIDs)",
            category="identity_spoofing",
            locations=[str(path)],
        ))

        # AgentCard integrity
        if WELL_KNOWN_PATTERN.search(content) or AGENT_CARD_JSON_PATTERN.search(content):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="AgentCard integrity not cryptographically verified",
                description=f"File '{path.name}' serves or fetches an AgentCard. AgentCards are fetched over HTTPS but are not signed. A compromised or MITM'd server can serve a modified AgentCard, redirecting tasks to a malicious agent.",
                affected=[agent_id],
                recommendation="Sign AgentCards with a verifiable key; clients should verify signatures before trusting capabilities",
                category="identity_spoofing",
                locations=[str(path)],
            ))

        # Security schemes
        if has_security:
            cred_id = f"cred:{agent_id}:security_scheme"
            credentials.append(Credential(
                id=cred_id,
                cred_type=CredentialType.UNKNOWN,
                source="a2a_security_scheme",
                target_service="a2a_peer",
                shared_by=[agent_id],
            ))
            agent.credentials.append(cred_id)
            trust_rels.append(TrustRelationship(
                source_agent=agent_id,
                target="a2a_peer",
                credential_id=cred_id,
                auth_method="a2a_security_scheme",
                mutual=False,
                verified=False,
            ))

        agents.append(agent)
        return agents, credentials, trust_rels, findings
