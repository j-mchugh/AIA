"""MCP configuration scanner."""
from __future__ import annotations
import json
import os
import re
from pathlib import Path
from typing import Any

from .base import BaseScanner
from ..models import (
    Agent, Credential, TrustRelationship, Finding,
    Framework, CredentialType, Severity,
)


# Common MCP config locations
MCP_CONFIG_PATHS = [
    "mcp.json",
    "mcp_config.json",
    ".mcp.json",
    "claude_desktop_config.json",
]

# Claude Desktop config paths
CLAUDE_DESKTOP_CONFIGS = [
    Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
    Path.home() / ".config" / "claude" / "claude_desktop_config.json",
]

# OpenClaw config
OPENCLAW_CONFIG = Path.home() / ".openclaw" / "openclaw.json"

# Patterns that suggest hardcoded secrets
SECRET_PATTERNS = [
    re.compile(r'sk-[a-zA-Z0-9]{20,}'),  # OpenAI-style
    re.compile(r'[a-f0-9]{32,64}'),  # hex tokens
    re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ'),  # JWT
    re.compile(r'ghp_[a-zA-Z0-9]{36}'),  # GitHub PAT
    re.compile(r'gho_[a-zA-Z0-9]{36}'),  # GitHub OAuth
    re.compile(r'xox[bsp]-[a-zA-Z0-9-]+'),  # Slack
]


class MCPScanner(BaseScanner):
    config_based = True
    framework = Framework.MCP

    def detect(self, path: Path) -> bool:
        if path.is_file():
            return path.name in MCP_CONFIG_PATHS or "mcp" in path.name.lower()
        # Check project-local configs
        for name in MCP_CONFIG_PATHS:
            if (path / name).exists():
                return True
        # Check system-wide configs (Claude Desktop, OpenClaw)
        for cdc in CLAUDE_DESKTOP_CONFIGS:
            if cdc.exists():
                return True
        if OPENCLAW_CONFIG.exists():
            return True
        return False

    def scan(self, path: Path) -> tuple[
        list[Agent], list[Credential], list[TrustRelationship], list[Finding]
    ]:
        agents: list[Agent] = []
        credentials: list[Credential] = []
        trust_rels: list[TrustRelationship] = []
        findings: list[Finding] = []

        # Find all MCP configs to scan
        configs_to_scan: list[tuple[Path, str]] = []

        if path.is_file():
            configs_to_scan.append((path, "user-specified"))
        else:
            for name in MCP_CONFIG_PATHS:
                cfg = path / name
                if cfg.exists():
                    configs_to_scan.append((cfg, "project"))

        # Also scan Claude Desktop config if it exists
        for cdc in CLAUDE_DESKTOP_CONFIGS:
            if cdc.exists():
                configs_to_scan.append((cdc, "claude-desktop"))

        # Scan OpenClaw config
        if OPENCLAW_CONFIG.exists():
            configs_to_scan.append((OPENCLAW_CONFIG, "openclaw"))

        for config_path, source in configs_to_scan:
            try:
                a, c, t, f = self._scan_config(config_path, source)
                agents.extend(a)
                credentials.extend(c)
                trust_rels.extend(t)
                findings.extend(f)
            except Exception as e:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"Config parse error: {config_path}",
                    description=str(e),
                    affected=[],
                    recommendation="Verify config file is valid JSON",
                    category="scan_error",
                ))

        # Cross-config analysis: find shared credentials
        self._analyze_shared_credentials(credentials, findings)

        return agents, credentials, trust_rels, findings

    def _scan_config(self, config_path: Path, source: str) -> tuple[
        list[Agent], list[Credential], list[TrustRelationship], list[Finding]
    ]:
        agents = []
        credentials = []
        trust_rels = []
        findings = []

        with open(config_path) as f:
            config = json.load(f)

        # Handle different config formats
        servers = {}
        if "mcpServers" in config:
            servers = config["mcpServers"]
        elif "mcp" in config and isinstance(config["mcp"], dict):
            servers = config["mcp"].get("servers", {})
        elif "servers" in config:
            servers = config["servers"]

        for server_name, server_config in servers.items():
            agent_id = f"mcp:{source}:{server_name}"

            # Determine transport type
            transport = "stdio"
            if "url" in server_config:
                transport = "http"
            elif "command" in server_config:
                transport = "stdio"

            agent = Agent(
                id=agent_id,
                name=server_name,
                framework=Framework.MCP,
                identity_type="none",  # MCP servers have no agent identity
                source_file=str(config_path),
                metadata={
                    "transport": transport,
                    "source": source,
                    "command": server_config.get("command"),
                },
            )

            # Analyze environment variables for credentials
            env = server_config.get("env", {})
            args = server_config.get("args", [])

            for env_key, env_value in env.items():
                cred_id = f"cred:{agent_id}:{env_key}"
                cred_type, cred_findings = self._classify_credential(
                    env_key, env_value, agent_id, str(config_path)
                )

                cred = Credential(
                    id=cred_id,
                    cred_type=cred_type,
                    source=f"env:{env_key}",
                    target_service=self._infer_service(env_key, server_name, server_config),
                    shared_by=[agent_id],
                )
                credentials.append(cred)
                agent.credentials.append(cred_id)
                findings.extend(cred_findings)

                trust_rels.append(TrustRelationship(
                    source_agent=agent_id,
                    target=cred.target_service,
                    credential_id=cred_id,
                    auth_method=cred_type.value,
                    mutual=False,
                    verified=False,
                ))

            # Check args for inline secrets
            for i, arg in enumerate(args):
                if isinstance(arg, str):
                    for pattern in SECRET_PATTERNS:
                        if pattern.search(arg):
                            findings.append(Finding(
                                severity=Severity.CRITICAL,
                                title="Hardcoded secret in command args",
                                description=f"Server '{server_name}' has what appears to be a hardcoded secret in args[{i}] in {config_path}",
                                affected=[agent_id],
                                recommendation="Move secrets to environment variables or a secrets manager",
                                category="hardcoded_secret",
                            ))
                            break

            # STDIO transport findings
            if transport == "stdio":
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="STDIO transport — no network authentication",
                    description=f"MCP server '{server_name}' uses STDIO transport. Per MCP spec, auth is handled by 'retrieving credentials from the environment.' No client-server authentication occurs.",
                    affected=[agent_id],
                    recommendation="For sensitive operations, prefer HTTP transport with OAuth 2.1 authentication",
                    category="no_auth",
                ))

            # No env vars at all = likely inheriting user environment
            if not env:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="No explicit credentials — inherits user environment",
                    description=f"MCP server '{server_name}' has no explicit env vars configured. It inherits the full user environment, which may include credentials for other services.",
                    affected=[agent_id],
                    recommendation="Explicitly scope environment variables. Use allowlists, not inheritance.",
                    category="user_inherited",
                ))

                cred_id = f"cred:{agent_id}:user_env"
                credentials.append(Credential(
                    id=cred_id,
                    cred_type=CredentialType.USER_INHERITED,
                    source="process_environment",
                    target_service="all_user_services",
                    shared_by=[agent_id],
                    scope="full_user_environment",
                ))
                agent.credentials.append(cred_id)

            # Self-asserted identity finding
            findings.append(Finding(
                severity=Severity.LOW,
                title="Self-asserted identity only",
                description=f"MCP server '{server_name}' identifies itself by name string only. No cryptographic identity binding. Any server could claim this name.",
                affected=[agent_id],
                recommendation="Implement server identity verification via certificates or signed manifests",
                category="identity_spoofing",
            ))

            agents.append(agent)

        return agents, credentials, trust_rels, findings

    def _classify_credential(
        self, key: str, value: str, agent_id: str, config_path: str
    ) -> tuple[CredentialType, list[Finding]]:
        findings = []
        key_upper = key.upper()

        # Check if value is an env var reference vs actual value
        is_reference = value.startswith("${") or value.startswith("$")

        # Check for hardcoded secrets
        if not is_reference and value and len(value) > 10:
            for pattern in SECRET_PATTERNS:
                if pattern.search(value):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title="Hardcoded secret in config",
                        description=f"Credential '{key}' appears to contain a hardcoded secret in {config_path}. This value is stored in plaintext.",
                        affected=[agent_id],
                        recommendation="Use environment variable references or a secrets manager instead of hardcoded values",
                        category="hardcoded_secret",
                    ))
                    return CredentialType.HARDCODED, findings

        # Classify by key name
        if any(k in key_upper for k in ["API_KEY", "APIKEY", "SECRET_KEY"]):
            return CredentialType.API_KEY, findings
        elif any(k in key_upper for k in ["TOKEN", "ACCESS_TOKEN", "AUTH_TOKEN"]):
            return CredentialType.OAUTH_TOKEN, findings
        elif any(k in key_upper for k in ["SERVICE_ACCOUNT", "CREDENTIALS_FILE"]):
            return CredentialType.SERVICE_ACCOUNT, findings
        elif any(k in key_upper for k in ["PASSWORD", "SECRET", "PRIVATE_KEY"]):
            return CredentialType.API_KEY, findings

        return CredentialType.ENV_VAR, findings

    def _infer_service(self, env_key: str, server_name: str, config: dict) -> str:
        key_upper = env_key.upper()
        if "OPENAI" in key_upper:
            return "openai"
        elif "ANTHROPIC" in key_upper:
            return "anthropic"
        elif "GITHUB" in key_upper:
            return "github"
        elif "SLACK" in key_upper:
            return "slack"
        elif "GOOGLE" in key_upper:
            return "google"
        elif "AWS" in key_upper:
            return "aws"
        elif "AZURE" in key_upper:
            return "azure"
        elif "BRAVE" in key_upper:
            return "brave"
        elif "SERP" in key_upper:
            return "serpapi"
        elif "POSTGRES" in key_upper or "DATABASE" in key_upper:
            return "database"
        return server_name

    def _analyze_shared_credentials(
        self, credentials: list[Credential], findings: list[Finding]
    ) -> None:
        """Find credentials shared across multiple agents."""
        # Group by source (env var name)
        by_source: dict[str, list[Credential]] = {}
        for cred in credentials:
            if cred.source not in by_source:
                by_source[cred.source] = []
            by_source[cred.source].append(cred)

        # Non-credential env vars that shouldn't be flagged as shared secrets
        NON_CREDENTIAL_SOURCES = {
            "process_environment", "env:PATH", "env:HOME", "env:USER",
            "env:SHELL", "env:LANG", "env:TERM", "env:TMPDIR",
            "env:LOGNAME", "env:PWD", "env:EDITOR",
        }

        for source, creds in by_source.items():
            if len(creds) > 1:
                # Skip non-credential environment variables
                if source in NON_CREDENTIAL_SOURCES:
                    continue

                all_agents = []
                for c in creds:
                    all_agents.extend(c.shared_by)
                    c.shared_by = list(set(c.shared_by + [a for cc in creds for a in cc.shared_by]))

                # Severity based on credential type
                is_api_key = any(c.cred_type in (CredentialType.API_KEY, CredentialType.HARDCODED) for c in creds)
                severity = Severity.CRITICAL if is_api_key else Severity.HIGH

                findings.append(Finding(
                    severity=severity,
                    title=f"Shared credential: {source}",
                    description=f"Credential '{source}' is used by {len(creds)} agents. Revoking this credential affects all of them. Agents cannot be individually distinguished by downstream services.",
                    affected=list(set(all_agents)),
                    recommendation="Issue unique credentials per agent instance",
                    category="shared_credentials",
                ))
