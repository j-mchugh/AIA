# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jeremy McHugh
"""Copilot Studio / Power Virtual Agents scanner."""
from __future__ import annotations
import json
import re
from pathlib import Path

from .base import BaseScanner, safe_rglob
from ..models import (
    Agent, Credential, TrustRelationship, Finding,
    Framework, CredentialType, Severity,
)

COPILOT_FILE_PATTERNS = ["*.json", "*.yaml", "*.yml"]
COPILOT_INDICATORS = [
    "microsoft.powerplatform", "copilot", "power virtual agents",
    "botcomponent", "connectionreference", "Microsoft.PowerApps",
]
OAUTH_PATTERN = re.compile(r'"oAuth"|oauth2|"connectionId"|"connectorId"', re.IGNORECASE)
DATAVERSE_PATTERN = re.compile(r'dataverse|"entityName"|commonDataService', re.IGNORECASE)
SHARED_CONNECTOR_PATTERN = re.compile(r'"sharedWith"|"connectionRoleAssignment"|"shared_"', re.IGNORECASE)


class CopilotStudioScanner(BaseScanner):
    framework = Framework.COPILOT_STUDIO

    def detect(self, path: Path) -> bool:
        if path.is_file():
            return self._file_has_copilot(path)
        for pattern in COPILOT_FILE_PATTERNS:
            for f in safe_rglob(path, pattern):
                if self._file_has_copilot(f):
                    return True
        return False

    def _file_has_copilot(self, path: Path) -> bool:
        try:
            content = path.read_text(errors="ignore").lower()
            return any(ind in content for ind in COPILOT_INDICATORS)
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
            f for pat in COPILOT_FILE_PATTERNS for f in safe_rglob(path, pat)
        ]

        for config_file in files:
            if not self._file_has_copilot(config_file):
                continue
            try:
                a, c, t, f = self._scan_file(config_file)
                agents.extend(a)
                credentials.extend(c)
                trust_rels.extend(t)
                findings.extend(f)
            except Exception as e:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"Parse error: {config_file.name}",
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

        agent_id = f"copilot_studio:{path.stem}"
        agent = Agent(
            id=agent_id,
            name=path.stem,
            framework=Framework.COPILOT_STUDIO,
            identity_type="none",
            source_file=str(path),
            metadata={"platform": "power_platform"},
        )

        # OAuth identifies user, not agent
        if OAUTH_PATTERN.search(content):
            cred_id = f"cred:{agent_id}:oauth_connector"
            credentials.append(Credential(
                id=cred_id,
                cred_type=CredentialType.USER_INHERITED,
                source="oauth_connector",
                target_service="power_platform",
                shared_by=[agent_id],
            ))
            agent.credentials.append(cred_id)
            trust_rels.append(TrustRelationship(
                source_agent=agent_id,
                target="power_platform",
                credential_id=cred_id,
                auth_method="oauth",
                mutual=False,
                verified=False,
            ))
            findings.append(Finding(
                severity=Severity.HIGH,
                title="OAuth connector identifies user, not agent",
                description=f"File '{path.name}' configures OAuth connectors. In Copilot Studio, OAuth connections authenticate as the configuring user or a shared service account, not as the agent itself. Actions taken by the agent are attributed to the human identity.",
                affected=[agent_id],
                recommendation="Use service principals with per-agent credentials and audit logging that distinguishes agent actions from user actions",
                category="identity_spoofing",
                locations=[str(path)],
            ))

        # Shared connectors
        if SHARED_CONNECTOR_PATTERN.search(content):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Shared connectors across multiple agents",
                description=f"File '{path.name}' references shared connection configurations. Multiple agents or flows sharing the same connector cannot be distinguished at the target service.",
                affected=[agent_id],
                recommendation="Assign per-agent service principal connections with scoped permissions",
                category="shared_credentials",
                locations=[str(path)],
            ))

        # Dataverse connections
        if DATAVERSE_PATTERN.search(content):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Dataverse access without per-agent identity",
                description=f"File '{path.name}' references Dataverse/Common Data Service. The agent accesses Dataverse through the connection owner's identity, granting it the same data access as the human user.",
                affected=[agent_id],
                recommendation="Configure application-level Dataverse access with minimal table and column permissions",
                category="excess_privilege",
                locations=[str(path)],
            ))

        # General: no per-agent identity
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="No per-agent cryptographic identity in Copilot Studio",
            description=f"File '{path.name}' defines a Copilot Studio component. Copilot Studio agents have no independent cryptographic identity; they inherit the identity of the Power Platform environment and connection owner.",
            affected=[agent_id],
            recommendation="Implement agent-level identity through Azure Managed Identity or certificate-based authentication",
            category="identity_spoofing",
            locations=[str(path)],
        ))

        agents.append(agent)
        return agents, credentials, trust_rels, findings
