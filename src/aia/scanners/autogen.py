"""AutoGen project scanner."""
from __future__ import annotations
import re
from pathlib import Path

from .base import BaseScanner, safe_rglob
from ..models import (
    Agent, Credential, TrustRelationship, Finding,
    Framework, CredentialType, Severity,
)

AUTOGEN_IMPORTS = ["autogen", "autogen_agentchat", "autogen_core", "AssistantAgent", "UserProxyAgent"]

AGENT_PATTERNS = [
    re.compile(r'AssistantAgent\s*\(\s*[^)]*?name\s*=\s*[\"\']([^\"\']+)[\"\']', re.DOTALL),
    re.compile(r'UserProxyAgent\s*\(\s*[^)]*?name\s*=\s*[\"\']([^\"\']+)[\"\']', re.DOTALL),
    re.compile(r'ConversableAgent\s*\(\s*[^)]*?name\s*=\s*[\"\']([^\"\']+)[\"\']', re.DOTALL),
    re.compile(r'GroupChatManager\s*\(', re.DOTALL),
]

LLM_CONFIG_PATTERN = re.compile(r'llm_config\s*=\s*\{[^}]*\}', re.DOTALL)


class AutoGenScanner(BaseScanner):
    framework = Framework.AUTOGEN

    def detect(self, path: Path) -> bool:
        if path.is_file():
            return self._file_has_autogen(path)
        for py_file in safe_rglob(path, "*.py"):
            if self._file_has_autogen(py_file):
                return True
        return False

    def _file_has_autogen(self, path: Path) -> bool:
        try:
            content = path.read_text(errors="ignore")
            return any(imp in content for imp in AUTOGEN_IMPORTS)
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
            if not self._file_has_autogen(py_file):
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

        # Find all agent definitions
        agent_names = []
        for pattern in AGENT_PATTERNS[:3]:  # Named agent patterns
            agent_names.extend(pattern.findall(content))

        has_group_chat = bool(AGENT_PATTERNS[3].search(content))

        for name in agent_names:
            agent_id = f"autogen:{path.stem}:{name.lower().replace(' ', '_')}"
            agent = Agent(
                id=agent_id,
                name=name,
                framework=Framework.AUTOGEN,
                identity_type="string",
                source_file=str(path),
            )

            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Name-based agent identity only",
                description=f"AutoGen agent '{name}' is identified by a name string. The runtime does not verify sender identity on messages. If a message is injected into the conversation, the runtime routes it without verification.",
                affected=[agent_id],
                recommendation="Implement message signing and sender verification in the agent runtime",
                category="identity_spoofing",
            ))

            agents.append(agent)

        # Group chat = implicit trust
        if has_group_chat and len(agent_names) > 1:
            agent_ids = [f"autogen:{path.stem}:{n.lower().replace(' ', '_')}" for n in agent_names]

            findings.append(Finding(
                severity=Severity.HIGH,
                title="GroupChat with no message authentication",
                description=f"AutoGen GroupChat in '{path.name}' with {len(agent_names)} agents. Message routing is based on agent name strings. Any participant can send messages claiming to be any other participant. The GroupChatManager does not cryptographically verify message origins.",
                affected=agent_ids,
                recommendation="Implement message authentication. Each agent should sign messages, and the GroupChatManager should verify signatures before routing.",
                category="identity_spoofing",
            ))

            # Mark communication relationships
            for agent in agents:
                agent.communicates_with = [a.id for a in agents if a.id != agent.id]

        # Check for code execution
        if "code_execution_config" in content or "UserProxyAgent" in content:
            affected = [a.id for a in agents] if agents else [f"autogen:{path.stem}"]
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Code execution enabled without agent identity verification",
                description=f"AutoGen agents in '{path.name}' have code execution capabilities. Code execution requests are not authenticated. A compromised or spoofed agent could request execution of malicious code.",
                affected=affected,
                recommendation="Implement strict approval workflows for code execution. Verify the identity of the requesting agent before executing code.",
                category="excess_privilege",
            ))

        # Check for API key patterns in llm_config
        api_key_inline = re.findall(r'[\"\']api_key[\"\']\s*:\s*[\"\']([^\"\']{10,})[\"\']', content)
        if api_key_inline:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Hardcoded API key in llm_config",
                description=f"File '{path.name}' contains a hardcoded API key in the LLM configuration.",
                affected=[a.id for a in agents] if agents else [],
                recommendation="Use environment variables or a secrets manager for API keys",
                category="hardcoded_secret",
            ))

        return agents, credentials, trust_rels, findings
