"""OpenAI Agents SDK scanner."""
from __future__ import annotations
import re
from pathlib import Path

from .base import BaseScanner, safe_rglob
from ..models import (
    Agent, Credential, TrustRelationship, Finding,
    Framework, CredentialType, Severity,
)

OPENAI_AGENTS_IMPORTS = [
    "openai_agents", "agents", "from agents import", "from agents.",
]

AGENT_DEF_PATTERN = re.compile(r'Agent\s*\(')
HANDOFF_PATTERN = re.compile(r'Handoff\s*\(|handoff|handoffs\s*=')
RUNNER_PATTERN = re.compile(r'Runner\.run')
GUARDRAIL_PATTERN = re.compile(r'Guardrail\s*\(|guardrail|InputGuardrail|OutputGuardrail')
SESSION_PATTERN = re.compile(r'Session\s*\(|session')

ENV_VAR_PATTERNS = [
    re.compile(r'os\.environ\[[\"\'](\w+)[\"\']\]'),
    re.compile(r'os\.environ\.get\([\"\'](\w+)[\"\']'),
    re.compile(r'os\.getenv\([\"\'](\w+)[\"\']'),
]


class OpenAIAgentsScanner(BaseScanner):
    framework = Framework.OPENAI_AGENTS

    def detect(self, path: Path) -> bool:
        if path.is_file():
            return self._file_has_agents_sdk(path)
        for py_file in safe_rglob(path, "*.py"):
            if self._file_has_agents_sdk(py_file):
                return True
        return False

    def _file_has_agents_sdk(self, path: Path) -> bool:
        try:
            content = path.read_text(errors="ignore")
            return any(imp in content for imp in OPENAI_AGENTS_IMPORTS)
        except Exception:
            return False

    def scan(self, path: Path) -> tuple[
        list[Agent], list[Credential], list[TrustRelationship], list[Finding]
    ]:
        agents = []
        credentials = []
        trust_rels = []
        findings = []

        py_files = [path] if path.is_file() else list(safe_rglob(path, "*.py"))

        for py_file in py_files:
            if not self._file_has_agents_sdk(py_file):
                continue
            try:
                a, c, t, f = self._scan_file(py_file)
                agents.extend(a)
                credentials.extend(c)
                trust_rels.extend(t)
                findings.extend(f)
            except Exception as e:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"Parse error: {py_file.name}",
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

        agent_id = f"openai_agents:{path.stem}"

        has_agent = bool(AGENT_DEF_PATTERN.search(content))
        if not has_agent:
            return agents, credentials, trust_rels, findings

        agent = Agent(
            id=agent_id,
            name=path.stem,
            framework=Framework.OPENAI_AGENTS,
            identity_type="none",
            source_file=str(path),
            metadata={"sdk": "openai_agents"},
        )

        # Check for handoff patterns (no inter-agent auth)
        if HANDOFF_PATTERN.search(content):
            findings.append(Finding(
                severity=Severity.HIGH,
                title="No inter-agent authentication on handoffs",
                description=f"File '{path.name}' uses agent handoffs. The receiving agent trusts the handoff implicitly. There is no cryptographic verification of the handing-off agent's identity.",
                affected=[agent_id],
                recommendation="Implement signed handoff tokens or mutual authentication between agents",
                category="identity_spoofing",
            ))

        # Check for session usage (no identity binding)
        if SESSION_PATTERN.search(content):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="No agent identity verification in sessions",
                description=f"File '{path.name}' uses sessions. Sessions store conversation history but do not bind to a verified agent identity.",
                affected=[agent_id],
                recommendation="Bind sessions to cryptographically verified agent identities",
                category="identity_spoofing",
            ))

        # Scan for env var credentials
        for pattern in ENV_VAR_PATTERNS:
            for match in pattern.finditer(content):
                env_name = match.group(1)
                cred_id = f"cred:{agent_id}:{env_name}"
                cred = Credential(
                    id=cred_id,
                    cred_type=CredentialType.ENV_VAR,
                    source=f"env:{env_name}",
                    target_service=self._infer_service(env_name),
                    shared_by=[agent_id],
                )
                credentials.append(cred)
                agent.credentials.append(cred_id)
                trust_rels.append(TrustRelationship(
                    source_agent=agent_id,
                    target=cred.target_service,
                    credential_id=cred_id,
                    auth_method="env_var",
                    mutual=False,
                    verified=False,
                ))

        # Credential inheritance from environment
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Credential inheritance from environment",
            description=f"OpenAI Agents SDK agent in '{path.name}' inherits credentials from the host environment. All agents in the workflow share the same credential context.",
            affected=[agent_id],
            recommendation="Use unique, least-privilege credentials per agent instance",
            category="shared_credentials",
        ))

        agents.append(agent)
        return agents, credentials, trust_rels, findings

    def _infer_service(self, env_name: str) -> str:
        name = env_name.upper()
        service_map = {
            "OPENAI": "openai", "ANTHROPIC": "anthropic", "GOOGLE": "google",
            "AZURE": "azure", "AWS": "aws", "GITHUB": "github",
        }
        for key, service in service_map.items():
            if key in name:
                return service
        return "unknown"
