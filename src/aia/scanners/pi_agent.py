"""Pi agent toolkit (pi-mono) scanner."""
from __future__ import annotations
import json
import re
from pathlib import Path

from .base import BaseScanner, safe_rglob
from ..models import (
    Agent, Credential, TrustRelationship, Finding,
    Framework, CredentialType, Severity,
)

PI_MONO_PACKAGES = [
    "@pi-mono/", "pi-mono", "opencode", "@opencode/",
]

PI_MONO_IMPORT_PATTERNS = [
    re.compile(r'from\s+["\']@pi-mono/'),
    re.compile(r'import\s+.*from\s+["\']@pi-mono/'),
    re.compile(r'require\(["\']@pi-mono/'),
    re.compile(r'from\s+["\']opencode'),
    re.compile(r'import\s+.*from\s+["\']opencode'),
]

AGENT_RUNTIME_PATTERNS = [
    re.compile(r'createAgent|AgentRuntime|defineAgent'),
    re.compile(r'defineTool|createTool|tool\s*\('),
    re.compile(r'llm\.chat|llm\.complete|generateText'),
]


class PiAgentScanner(BaseScanner):
    framework = Framework.PI_AGENT

    def detect(self, path: Path) -> bool:
        if path.is_file():
            return self._file_has_pi_mono(path)
        # Check package.json
        pkg = path / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text(errors="ignore"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                if any(p in dep for dep in deps for p in PI_MONO_PACKAGES):
                    return True
            except Exception:
                pass
        # Check TS/JS files
        for ext in ("*.ts", "*.tsx", "*.js", "*.jsx"):
            for f in safe_rglob(path, ext):
                if self._file_has_pi_mono(f):
                    return True
        return False

    def _file_has_pi_mono(self, path: Path) -> bool:
        try:
            content = path.read_text(errors="ignore")
            if path.name == "package.json":
                return any(p in content for p in PI_MONO_PACKAGES)
            return any(p.search(content) for p in PI_MONO_IMPORT_PATTERNS)
        except Exception:
            return False

    def scan(self, path: Path) -> tuple[
        list[Agent], list[Credential], list[TrustRelationship], list[Finding]
    ]:
        agents = []
        credentials = []
        trust_rels = []
        findings = []

        if path.is_file():
            files = [path]
        else:
            files = []
            for ext in ("*.ts", "*.tsx", "*.js", "*.jsx"):
                files.extend(safe_rglob(path, ext))

        for f in files:
            try:
                content = f.read_text(errors="ignore")
            except Exception:
                continue

            has_import = any(p.search(content) for p in PI_MONO_IMPORT_PATTERNS)
            has_runtime = any(p.search(content) for p in AGENT_RUNTIME_PATTERNS)
            if not (has_import or has_runtime):
                continue

            agent_id = f"pi_mono:{f.stem}"
            agent = Agent(
                id=agent_id,
                name=f.stem,
                framework=Framework.PI_AGENT,
                identity_type="none",
                source_file=str(f),
                metadata={"sdk": "pi-mono"},
            )

            # Agent identity is developer-defined strings
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Agent identity is developer-defined strings",
                description=f"File '{f.name}' uses the Pi agent toolkit. Agent identity is a developer-defined string with no cryptographic backing. The runtime manages state and tool calls but does not provide verifiable identity across trust boundaries.",
                affected=[agent_id],
                recommendation="Implement cryptographic agent identity (see AAIP) for cross-boundary interactions",
                category="identity_spoofing",
            ))

            # Credentials passed from environment
            env_patterns = [
                re.compile(r'process\.env\.(\w+)'),
                re.compile(r'process\.env\[["\'](\w+)["\']\]'),
            ]
            env_vars_found = set()
            for pattern in env_patterns:
                for match in pattern.finditer(content):
                    env_vars_found.add(match.group(1))

            if env_vars_found:
                for env_name in env_vars_found:
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

            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Credentials passed from environment",
                description=f"Pi agent toolkit agent in '{f.name}' inherits credentials from the host environment. The agent operates with whatever permissions its hosting process has.",
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
