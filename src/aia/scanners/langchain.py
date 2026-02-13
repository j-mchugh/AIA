"""LangChain/LangGraph project scanner."""
from __future__ import annotations
import ast
import re
from pathlib import Path

from .base import BaseScanner, safe_rglob
from ..models import (
    Agent, Credential, TrustRelationship, Finding,
    Framework, CredentialType, Severity,
)

# Patterns for credential usage in Python code
ENV_VAR_PATTERNS = [
    re.compile(r'os\.environ\[[\"\'](\w+)[\"\']\]'),
    re.compile(r'os\.environ\.get\([\"\'](\w+)[\"\']'),
    re.compile(r'os\.getenv\([\"\'](\w+)[\"\']'),
    re.compile(r'environ\[[\"\'](\w+)[\"\']\]'),
]

API_KEY_PATTERNS = [
    re.compile(r'api_key\s*=\s*[\"\']([^\"\']+)[\"\']'),
    re.compile(r'openai_api_key\s*=\s*[\"\']([^\"\']+)[\"\']'),
    re.compile(r'anthropic_api_key\s*=\s*[\"\']([^\"\']+)[\"\']'),
]

LANGCHAIN_IMPORTS = [
    "langchain", "langchain_core", "langchain_community",
    "langchain_openai", "langchain_anthropic", "langgraph",
]

TOOL_PATTERNS = [
    re.compile(r'@tool'),
    re.compile(r'Tool\('),
    re.compile(r'StructuredTool'),
    re.compile(r'create_.*_agent'),
    re.compile(r'AgentExecutor'),
    re.compile(r'ChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI'),
]


class LangChainScanner(BaseScanner):
    framework = Framework.LANGCHAIN

    def detect(self, path: Path) -> bool:
        if path.is_file():
            return self._file_has_langchain(path)
        for py_file in safe_rglob(path, "*.py"):
            if self._file_has_langchain(py_file):
                return True
        return False

    def _file_has_langchain(self, path: Path) -> bool:
        try:
            content = path.read_text(errors="ignore")
            return any(imp in content for imp in LANGCHAIN_IMPORTS)
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
            if not self._file_has_langchain(py_file):
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

        agent_id = f"langchain:{path.stem}"

        # Detect agent patterns
        has_agent = any(p.search(content) for p in TOOL_PATTERNS)
        if has_agent:
            agent = Agent(
                id=agent_id,
                name=path.stem,
                framework=Framework.LANGCHAIN,
                identity_type="none",
                source_file=str(path),
            )

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

            # Scan for hardcoded API keys
            for pattern in API_KEY_PATTERNS:
                for match in pattern.finditer(content):
                    value = match.group(1)
                    if not value.startswith("$") and not value.startswith("{") and len(value) > 10:
                        cred_id = f"cred:{agent_id}:hardcoded_{hash(value) % 10000}"
                        credentials.append(Credential(
                            id=cred_id,
                            cred_type=CredentialType.HARDCODED,
                            source=f"hardcoded in {path.name}",
                            target_service="unknown",
                            shared_by=[agent_id],
                        ))
                        agent.credentials.append(cred_id)
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            title="Hardcoded API key in source code",
                            description=f"File '{path.name}' contains what appears to be a hardcoded API key passed directly to a LangChain component.",
                            affected=[agent_id],
                            recommendation="Use environment variables or a secrets manager. Never commit API keys to source code.",
                            category="hardcoded_secret",
                        ))

            # No agent identity
            findings.append(Finding(
                severity=Severity.LOW,
                title="No agent identity mechanism",
                description=f"LangChain agent in '{path.name}' has no cryptographic identity. The framework provides no way to verify which agent made a request to downstream services.",
                affected=[agent_id],
                recommendation="Implement per-agent credentials and identity headers (see AAIP)",
                category="identity_spoofing",
            ))

            # Check for multi-agent patterns
            if "AgentExecutor" in content and content.count("Agent") > 2:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Multi-agent system with no inter-agent authentication",
                    description=f"File '{path.name}' appears to define multiple agents. LangChain provides no mechanism for agents to verify each other's identity.",
                    affected=[agent_id],
                    recommendation="Implement signed messages between agents and verify sender identity",
                    category="identity_spoofing",
                ))

            agents.append(agent)

        return agents, credentials, trust_rels, findings

    def _infer_service(self, env_name: str) -> str:
        name = env_name.upper()
        service_map = {
            "OPENAI": "openai", "ANTHROPIC": "anthropic", "GOOGLE": "google",
            "AZURE": "azure", "AWS": "aws", "GITHUB": "github",
            "SLACK": "slack", "BRAVE": "brave", "SERP": "serpapi",
            "TAVILY": "tavily", "PINECONE": "pinecone", "WEAVIATE": "weaviate",
            "POSTGRES": "database", "DATABASE": "database", "REDIS": "redis",
        }
        for key, service in service_map.items():
            if key in name:
                return service
        return "unknown"
