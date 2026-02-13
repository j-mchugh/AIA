"""OpenClaw configuration scanner."""
from __future__ import annotations
import json
import os
from pathlib import Path

from .base import BaseScanner
from ..models import (
    Agent, Credential, TrustRelationship, Finding,
    Framework, CredentialType, Severity,
)

OPENCLAW_CONFIG = Path.home() / ".openclaw" / "openclaw.json"
OPENCLAW_CREDS_DIR = Path.home() / ".openclaw" / "credentials"


class OpenClawScanner(BaseScanner):
    config_based = True
    framework = Framework.OPENCLAW

    def detect(self, path: Path) -> bool:
        if path.is_file() and "openclaw" in path.name.lower():
            return True
        return OPENCLAW_CONFIG.exists()

    def scan(self, path: Path) -> tuple[
        list[Agent], list[Credential], list[TrustRelationship], list[Finding]
    ]:
        agents = []
        credentials = []
        trust_rels = []
        findings = []

        config_path = path if path.is_file() and "openclaw" in path.name.lower() else OPENCLAW_CONFIG
        if not config_path.exists():
            return agents, credentials, trust_rels, findings

        try:
            # OpenClaw uses JSON5 (comments + trailing commas)
            content = config_path.read_text()
            try:
                import json5
                config = json5.loads(content)
            except ImportError:
                # Fallback: strip comments manually
                import re
                content = re.sub(r'//.*?\n', '\n', content)
                content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
                config = json.loads(content)
        except Exception as e:
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"Config parse error: {config_path}",
                description=str(e),
                affected=[],
                recommendation="Verify config is valid JSON/JSON5",
                category="scan_error",
            ))
            return agents, credentials, trust_rels, findings

        # The OpenClaw gateway itself is an agent system
        agent_id = "openclaw:gateway"
        agent = Agent(
            id=agent_id,
            name="OpenClaw Gateway",
            framework=Framework.OPENCLAW,
            identity_type="token",
            source_file=str(config_path),
            metadata={"config_path": str(config_path)},
        )

        # === GATEWAY AUTH ===
        gateway = config.get("gateway", {})
        auth = gateway.get("auth", {})
        bind = gateway.get("bind", "loopback")
        port = gateway.get("port", 18789)

        auth_mode = auth.get("mode", "token")
        auth_token = auth.get("token", "")

        if auth_token:
            cred_id = "cred:openclaw:gateway_token"
            cred = Credential(
                id=cred_id,
                cred_type=CredentialType.API_KEY,
                source=f"config:{config_path}:gateway.auth.token",
                target_service="openclaw_gateway",
                shared_by=[agent_id],
                scope="full_gateway_control",
            )
            credentials.append(cred)
            agent.credentials.append(cred_id)

            # Check token strength
            if len(auth_token) < 32:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Weak gateway auth token",
                    description=(
                        f"Gateway auth token is {len(auth_token)} characters. "
                        f"Location: {config_path} → gateway.auth.token"
                    ),
                    affected=[agent_id],
                    recommendation="Use a token of at least 32 random characters",
                    category="weak_auth",
                ))

            # Token in plaintext config
            if not auth_token.startswith("${"):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Gateway token stored in plaintext config",
                    description=(
                        f"The gateway auth token is stored as a literal value in {config_path} → gateway.auth.token. "
                        f"Anyone with read access to this file has full gateway control."
                    ),
                    affected=[agent_id],
                    recommendation="Use env var substitution: \"${OPENCLAW_GATEWAY_TOKEN}\"",
                    category="hardcoded_secret",
                ))

        # Bind exposure
        if bind in ("lan", "0.0.0.0"):
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Gateway bound to network interface: {bind}",
                description=(
                    f"Gateway is bound to '{bind}' on port {port}. "
                    f"Location: {config_path} → gateway.bind = \"{bind}\"\n"
                    f"This exposes the gateway to other devices on the network. "
                    f"Any device on the LAN can attempt to connect."
                ),
                affected=[agent_id],
                recommendation="Use bind: \"loopback\" unless remote access is required. Use Tailscale for secure remote access.",
                category="network_exposure",
            ))

        # === CHANNEL CREDENTIALS ===
        channels = config.get("channels", {})

        # Telegram
        tg = channels.get("telegram", {})
        if tg:
            tg_token = tg.get("botToken", "")
            if tg_token and not tg_token.startswith("${"):
                cred_id = "cred:openclaw:telegram_bot_token"
                credentials.append(Credential(
                    id=cred_id,
                    cred_type=CredentialType.API_KEY,
                    source=f"config:{config_path}:channels.telegram.botToken",
                    target_service="telegram",
                    shared_by=[agent_id],
                ))
                agent.credentials.append(cred_id)
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Telegram bot token in plaintext config",
                    description=(
                        f"Telegram bot token is stored as a literal value.\n"
                        f"Location: {config_path} → channels.telegram.botToken\n"
                        f"This token grants full control of the Telegram bot."
                    ),
                    affected=[agent_id],
                    recommendation="Use env var: TELEGRAM_BOT_TOKEN or \"${TELEGRAM_BOT_TOKEN}\" in config",
                    category="hardcoded_secret",
                ))
                trust_rels.append(TrustRelationship(
                    source_agent=agent_id,
                    target="telegram",
                    credential_id=cred_id,
                    auth_method="api_key",
                    mutual=False,
                    verified=False,
                ))

            # DM policy check
            dm_policy = tg.get("dmPolicy", "pairing")
            if dm_policy == "open":
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Telegram DMs open to everyone",
                    description=(
                        f"Telegram dmPolicy is set to 'open'. Anyone can message the bot and trigger agent actions.\n"
                        f"Location: {config_path} → channels.telegram.dmPolicy = \"open\""
                    ),
                    affected=[agent_id],
                    recommendation="Use dmPolicy: \"pairing\" or \"allowlist\" with explicit allowFrom list",
                    category="open_access",
                ))

        # Discord
        discord = channels.get("discord", {})
        if discord:
            dc_token = discord.get("token", "")
            if dc_token and not dc_token.startswith("${"):
                cred_id = "cred:openclaw:discord_bot_token"
                credentials.append(Credential(
                    id=cred_id,
                    cred_type=CredentialType.API_KEY,
                    source=f"config:{config_path}:channels.discord.token",
                    target_service="discord",
                    shared_by=[agent_id],
                ))
                agent.credentials.append(cred_id)
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Discord bot token in plaintext config",
                    description=(
                        f"Discord bot token stored as literal value.\n"
                        f"Location: {config_path} → channels.discord.token"
                    ),
                    affected=[agent_id],
                    recommendation="Use env var: DISCORD_BOT_TOKEN",
                    category="hardcoded_secret",
                ))

        # WhatsApp
        wa = channels.get("whatsapp", {})
        if wa:
            allow_from = wa.get("allowFrom", [])
            if "*" in allow_from:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="WhatsApp open to all senders",
                    description=(
                        f"WhatsApp allowFrom contains wildcard \"*\". Anyone can message the bot.\n"
                        f"Location: {config_path} → channels.whatsapp.allowFrom = [\"*\"]"
                    ),
                    affected=[agent_id],
                    recommendation="Replace \"*\" with specific phone numbers",
                    category="open_access",
                ))

        # Slack
        slack = channels.get("slack", {})
        if slack:
            slack_token = slack.get("botToken", "")
            if slack_token and not slack_token.startswith("${"):
                cred_id = "cred:openclaw:slack_bot_token"
                credentials.append(Credential(
                    id=cred_id,
                    cred_type=CredentialType.API_KEY,
                    source=f"config:{config_path}:channels.slack.botToken",
                    target_service="slack",
                    shared_by=[agent_id],
                ))
                agent.credentials.append(cred_id)

        # === MODEL API KEYS ===
        models = config.get("models", {})
        providers = models.get("providers", {})
        for provider_name, provider_config in providers.items():
            api_key = provider_config.get("apiKey", "")
            if api_key and not api_key.startswith("${"):
                cred_id = f"cred:openclaw:model_{provider_name}"
                credentials.append(Credential(
                    id=cred_id,
                    cred_type=CredentialType.HARDCODED,
                    source=f"config:{config_path}:models.providers.{provider_name}.apiKey",
                    target_service=provider_name,
                    shared_by=[agent_id],
                ))
                agent.credentials.append(cred_id)
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"Model API key for '{provider_name}' in plaintext config",
                    description=(
                        f"API key for {provider_name} is stored as a literal value.\n"
                        f"Location: {config_path} → models.providers.{provider_name}.apiKey\n"
                        f"This key is used for all agent sessions and cannot be scoped per-agent."
                    ),
                    affected=[agent_id],
                    recommendation=f"Use env var substitution: \"${{{provider_name.upper()}_API_KEY}}\"",
                    category="hardcoded_secret",
                ))
                trust_rels.append(TrustRelationship(
                    source_agent=agent_id,
                    target=provider_name,
                    credential_id=cred_id,
                    auth_method="api_key",
                    mutual=False,
                    verified=False,
                ))

        # === ENV VARS IN CONFIG ===
        env_config = config.get("env", {})
        env_vars = env_config.get("vars", {})
        for var_name, var_value in env_vars.items():
            if any(k in var_name.upper() for k in ["KEY", "TOKEN", "SECRET", "PASSWORD"]):
                cred_id = f"cred:openclaw:env_{var_name}"
                credentials.append(Credential(
                    id=cred_id,
                    cred_type=CredentialType.HARDCODED,
                    source=f"config:{config_path}:env.vars.{var_name}",
                    target_service=var_name.lower().split("_")[0],
                    shared_by=[agent_id],
                ))
                agent.credentials.append(cred_id)
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"Inline env var '{var_name}' contains credential",
                    description=(
                        f"Credential stored inline in config env vars section.\n"
                        f"Location: {config_path} → env.vars.{var_name}\n"
                        f"Accessible to all agent sessions and tools."
                    ),
                    affected=[agent_id],
                    recommendation="Store in ~/.openclaw/.env or system environment instead of config file",
                    category="hardcoded_secret",
                ))

        # === TOOL ACCESS ===
        tools = config.get("tools", {})
        if tools:
            # Check for elevated tool permissions
            elevated = tools.get("elevated", {})
            if elevated.get("allow"):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Elevated tool execution enabled",
                    description=(
                        f"Tools can run with elevated (sudo/admin) privileges.\n"
                        f"Location: {config_path} → tools.elevated\n"
                        f"A prompt injection could escalate to system-level access."
                    ),
                    affected=[agent_id],
                    recommendation="Disable elevated tools unless absolutely required. Use sandboxing.",
                    category="excess_privilege",
                ))

        # === AGENT IDENTITY ===
        # OpenClaw agents authenticate via gateway token but have no per-agent identity
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Single gateway identity for all agent sessions",
            description=(
                f"OpenClaw uses a single gateway auth token for all connections.\n"
                f"Location: {config_path} → gateway.auth.token\n"
                f"All sessions (main, subagents, cron jobs) share the same identity. "
                f"Downstream systems cannot distinguish between different agent sessions. "
                f"A compromised session has the same privileges as all other sessions."
            ),
            affected=[agent_id],
            recommendation="Implement per-session identity tokens. Use AAIP identity strings for agent identification.",
            category="identity_spoofing",
        ))

        # === FILE PERMISSIONS ===
        try:
            config_stat = config_path.stat()
            mode = oct(config_stat.st_mode)[-3:]
            if mode not in ("600", "400"):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"Config file permissions too open: {mode}",
                    description=(
                        f"Config file has permissions {mode}.\n"
                        f"Location: {config_path}\n"
                        f"This file contains auth tokens and API keys. "
                        f"Other users on this system may be able to read it."
                    ),
                    affected=[agent_id],
                    recommendation=f"Run: chmod 600 {config_path}",
                    category="file_permissions",
                ))
        except Exception:
            pass

        # Check credentials directory
        if OPENCLAW_CREDS_DIR.exists():
            try:
                creds_mode = oct(OPENCLAW_CREDS_DIR.stat().st_mode)[-3:]
                if creds_mode not in ("700", "500"):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title=f"Credentials directory permissions too open: {creds_mode}",
                        description=(
                            f"Credentials directory has permissions {creds_mode}.\n"
                            f"Location: {OPENCLAW_CREDS_DIR}\n"
                            f"Contains WhatsApp auth, OAuth tokens, and pairing data."
                        ),
                        affected=[agent_id],
                        recommendation=f"Run: chmod 700 {OPENCLAW_CREDS_DIR}",
                        category="file_permissions",
                    ))
            except Exception:
                pass

        agents.append(agent)
        return agents, credentials, trust_rels, findings
