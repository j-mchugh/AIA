"""Anthropic tool-use / agent patterns scanner."""
from __future__ import annotations
import re
from pathlib import Path

from .base import BaseScanner, safe_rglob
from ..models import (
    Agent, Credential, TrustRelationship, Finding,
    Framework, CredentialType, Severity,
)

ANTHROPIC_IMPORTS = ["anthropic", "from anthropic"]

MESSAGES_CREATE_PATTERN = re.compile(r'\.messages\.create|client\.messages')
TOOL_USE_PATTERN = re.compile(r'tool_use|tool_choice|tools\s*=')
COMPUTER_USE_PATTERN = re.compile(r'computer_use|computer_20|ComputerTool')
MULTI_TURN_PATTERN = re.compile(r'while.*tool_use|for.*tool_use|stop_reason.*tool_use')

ENV_VAR_PATTERNS = [
    re.compile(r'os\.environ\[[\"\'](\w+)[\"\']\]'),
    re.compile(r'os\.environ\.get\([\"\'](\w+)[\"\']'),
    re.compile(r'os\.getenv\([\"\'](\w+)[\"\']'),
]


class AnthropicAgentsScanner(BaseScanner):
    framework = Framework.ANTHROPIC

    def detect(self, path: Path) -> bool:
        if path.is_file():
            return self._file_has_anthropic(path)
        for py_file in safe_rglob(path, "*.py"):
            if self._file_has_anthropic(py_file):
                return True
        return False

    def _file_has_anthropic(self, path: Path) -> bool:
        try:
            content = path.read_text(errors="ignore")
            return any(imp in content for imp in ANTHROPIC_IMPORTS)
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
            if not self._file_has_anthropic(py_file):
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

        has_messages = bool(MESSAGES_CREATE_PATTERN.search(content))
        has_tool_use = bool(TOOL_USE_PATTERN.search(content))
        if not (has_messages or has_tool_use):
            return agents, credentials, trust_rels, findings

        agent_id = f"anthropic:{path.stem}"
        agent = Agent(
            id=agent_id,
            name=path.stem,
            framework=Framework.ANTHROPIC,
            identity_type="none",
            source_file=str(path),
            metadata={"sdk": "anthropic"},
        )

        # Tool execution inherits host credentials
        if has_tool_use:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Tool execution inherits host credentials",
                description=f"File '{path.name}' uses Anthropic tool_use. Tool execution happens in the host application's context with the host's credentials. The model is a component, not an authenticated principal.",
                affected=[agent_id],
                recommendation="Scope tool execution to least-privilege credentials distinct from the host",
                category="shared_credentials",
            ))

        # Computer use detection
        if COMPUTER_USE_PATTERN.search(content):
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Computer use grants broad system access without agent identity binding",
                description=f"File '{path.name}' uses Anthropic computer_use. This grants the agent broad access to the system (screen, keyboard, mouse) with no agent-level identity binding. The agent operates with the full permissions of the hosting environment.",
                affected=[agent_id],
                recommendation="Isolate computer_use in a sandboxed environment with minimal privileges. Implement agent identity binding for audit trails.",
                category="identity_spoofing",
            ))

        # Multi-agent / multi-turn patterns
        if MULTI_TURN_PATTERN.search(content) or content.count("messages.create") > 1:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="No agent-level identity in multi-agent setup",
                description=f"File '{path.name}' appears to implement multi-turn or multi-agent patterns with Anthropic. Agent identity is application-defined and not cryptographically verifiable across trust boundaries.",
                affected=[agent_id],
                recommendation="Implement cryptographic agent identity for multi-agent coordination",
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
