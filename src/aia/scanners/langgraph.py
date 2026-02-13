# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jeremy McHugh
"""LangGraph scanner."""
from __future__ import annotations
import re
from pathlib import Path

from .base import BaseScanner, safe_rglob
from ..models import (
    Agent, Credential, TrustRelationship, Finding,
    Framework, CredentialType, Severity,
)

LANGGRAPH_IMPORTS = ["from langgraph", "import langgraph"]
STATEGRAPH_PATTERN = re.compile(r'\bStateGraph\s*\(')
COMPILED_PATTERN = re.compile(r'\bCompiledGraph\b|\.compile\s*\(')
TOOL_NODE_PATTERN = re.compile(r'\bToolNode\s*\(|\badd_node\s*\(')
CHECKPOINTER_PATTERN = re.compile(r'checkpointer|MemorySaver|SqliteSaver|PostgresSaver')
SHARED_STATE_PATTERN = re.compile(r'MessagesState|TypedDict|Annotated\[')

ENV_VAR_PATTERNS = [
    re.compile(r'os\.environ\[[\"\'](\w+)[\"\']\]'),
    re.compile(r'os\.environ\.get\([\"\'](\w+)[\"\']'),
    re.compile(r'os\.getenv\([\"\'](\w+)[\"\']'),
]


class LangGraphScanner(BaseScanner):
    framework = Framework.LANGGRAPH

    def detect(self, path: Path) -> bool:
        if path.is_file():
            return self._file_has_langgraph(path)
        for py_file in safe_rglob(path, "*.py"):
            if self._file_has_langgraph(py_file):
                return True
        return False

    def _file_has_langgraph(self, path: Path) -> bool:
        try:
            content = path.read_text(errors="ignore")
            return any(imp in content for imp in LANGGRAPH_IMPORTS)
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
            if not self._file_has_langgraph(py_file):
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

        has_stategraph = bool(STATEGRAPH_PATTERN.search(content))
        has_compiled = bool(COMPILED_PATTERN.search(content))
        if not (has_stategraph or has_compiled):
            return agents, credentials, trust_rels, findings

        agent_id = f"langgraph:{path.stem}"
        agent = Agent(
            id=agent_id,
            name=path.stem,
            framework=Framework.LANGGRAPH,
            identity_type="none",
            source_file=str(path),
            metadata={"sdk": "langgraph"},
        )

        # Shared state across nodes
        if SHARED_STATE_PATTERN.search(content):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Shared mutable state across graph nodes",
                description=f"File '{path.name}' uses shared state (MessagesState/TypedDict) across LangGraph nodes. All nodes in the graph read and write the same state object, meaning a compromised node can poison state for downstream nodes.",
                affected=[agent_id],
                recommendation="Implement per-node state validation and consider state signing to detect tampering between nodes",
                category="shared_credentials",
                locations=[str(path)],
            ))

        # Tool nodes
        if TOOL_NODE_PATTERN.search(content):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Tool nodes execute with shared credentials",
                description=f"File '{path.name}' binds tools to graph nodes. Tool execution inherits the host process credentials with no per-node identity scoping.",
                affected=[agent_id],
                recommendation="Scope tool credentials per node; avoid sharing API keys across the entire graph",
                category="shared_credentials",
                locations=[str(path)],
            ))

        # Checkpointer (persistent state)
        if CHECKPOINTER_PATTERN.search(content):
            findings.append(Finding(
                severity=Severity.LOW,
                title="Checkpointer persists state without integrity verification",
                description=f"File '{path.name}' uses a LangGraph checkpointer. Persisted state is not cryptographically signed, allowing state tampering if the storage backend is compromised.",
                affected=[agent_id],
                recommendation="Sign checkpointed state and verify integrity on resume",
                category="identity_spoofing",
                locations=[str(path)],
            ))

        # No per-node identity
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="No per-node identity in LangGraph",
            description=f"File '{path.name}' defines a LangGraph state graph. Individual nodes have no cryptographic identity; they are Python functions sharing the same process and credentials.",
            affected=[agent_id],
            recommendation="Implement node-level identity and credential scoping for multi-agent graphs",
            category="identity_spoofing",
            locations=[str(path)],
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
            "TAVILY": "tavily", "LANGCHAIN": "langchain",
        }
        for key, service in service_map.items():
            if key in name:
                return service
        return "unknown"
