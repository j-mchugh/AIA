"""CrewAI project scanner."""
from __future__ import annotations
import re
from pathlib import Path

from .base import BaseScanner, safe_rglob
from ..models import (
    Agent, Credential, TrustRelationship, Finding,
    Framework, CredentialType, Severity,
)

CREWAI_IMPORTS = ["crewai", "CrewBase", "crew_base"]

AGENT_DEF_PATTERN = re.compile(
    r'Agent\s*\(\s*[^)]*?role\s*=\s*[\"\']([^\"\']+)[\"\']', re.DOTALL
)
CREW_PATTERN = re.compile(r'Crew\s*\(', re.DOTALL)
TASK_PATTERN = re.compile(r'Task\s*\(', re.DOTALL)


class CrewAIScanner(BaseScanner):
    framework = Framework.CREWAI

    def detect(self, path: Path) -> bool:
        if path.is_file():
            return self._file_has_crewai(path)
        for py_file in safe_rglob(path, "*.py"):
            if self._file_has_crewai(py_file):
                return True
        return False

    def _file_has_crewai(self, path: Path) -> bool:
        try:
            content = path.read_text(errors="ignore")
            return any(imp in content for imp in CREWAI_IMPORTS)
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
            if not self._file_has_crewai(py_file):
                continue
            try:
                content = py_file.read_text(errors="ignore")
                a, c, t, f = self._scan_content(content, py_file)
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

    def _scan_content(self, content: str, path: Path) -> tuple[
        list[Agent], list[Credential], list[TrustRelationship], list[Finding]
    ]:
        agents = []
        credentials = []
        trust_rels = []
        findings = []

        # Find all Agent definitions
        agent_roles = AGENT_DEF_PATTERN.findall(content)
        has_crew = bool(CREW_PATTERN.search(content))

        for role in agent_roles:
            agent_id = f"crewai:{path.stem}:{role.lower().replace(' ', '_')}"
            agent = Agent(
                id=agent_id,
                name=role,
                framework=Framework.CREWAI,
                identity_type="string",  # CrewAI uses role strings
                source_file=str(path),
                metadata={"role": role},
            )

            # String-based identity finding
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="String-based agent identity",
                description=f"CrewAI agent '{role}' is identified by a role string. This string is not cryptographically bound to anything. Any agent can claim this role by setting the same string.",
                affected=[agent_id],
                recommendation="Implement cryptographic identity binding for agent roles",
                category="identity_spoofing",
            ))

            agents.append(agent)

        # Multi-agent implicit trust
        if has_crew and len(agent_roles) > 1:
            agent_ids = [f"crewai:{path.stem}:{r.lower().replace(' ', '_')}" for r in agent_roles]

            findings.append(Finding(
                severity=Severity.HIGH,
                title="Implicit trust between crew agents",
                description=f"Crew in '{path.name}' contains {len(agent_roles)} agents ({', '.join(agent_roles)}). Agents in the same crew trust each other implicitly because they run in the same process. There is no inter-agent authentication or message signing.",
                affected=agent_ids,
                recommendation="Implement message authentication between agents. Verify sender identity before acting on instructions from other agents.",
                category="identity_spoofing",
            ))

            # All agents can communicate with each other
            for agent in agents:
                agent.communicates_with = [a.id for a in agents if a.id != agent.id]

            # Shared process = shared credentials
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Shared credential context in crew",
                description=f"All {len(agent_roles)} agents in this crew share the same process environment. Any credential available to one agent is available to all agents. There is no per-agent credential scoping.",
                affected=agent_ids,
                recommendation="Implement per-agent credential isolation. Each agent should have its own scoped credentials.",
                category="shared_credentials",
            ))

        # Scan for env var usage
        env_pattern = re.compile(r'os\.environ\.get\([\"\'](\w+)[\"\']|os\.environ\[[\"\'](\w+)[\"\']\]|os\.getenv\([\"\'](\w+)[\"\']')
        for match in env_pattern.finditer(content):
            env_name = match.group(1) or match.group(2) or match.group(3)
            for agent in agents:
                cred_id = f"cred:{agent.id}:{env_name}"
                cred = Credential(
                    id=cred_id,
                    cred_type=CredentialType.ENV_VAR,
                    source=f"env:{env_name}",
                    target_service=env_name.lower().split("_")[0],
                    shared_by=[a.id for a in agents],  # Shared by all agents in crew
                )
                credentials.append(cred)
                agent.credentials.append(cred_id)
                break  # Only add once, mark as shared by all

        return agents, credentials, trust_rels, findings
