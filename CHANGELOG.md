# Changelog

## v0.3.0 (2026-02-13)

### Features

- **11 Framework Scanners** - Added Google A2A, LangGraph, and Microsoft Copilot Studio scanners
- **Anthropic Agent SDK** - Renamed from "Anthropic Claude/MCP" to reflect the new Agent SDK; added detection for Agent(), handoffs, and guardrails with 3 new finding types
- **Consistent CLI flags** - `--include-system` / `--no-system` now available on all commands (scan, trust-map, scope)

### Frameworks Now Supported

MCP, Google A2A, LangChain, LangGraph, CrewAI, AutoGen, OpenClaw, OpenAI Agents SDK, Anthropic Agent SDK, Microsoft Copilot Studio, Pi Agent

---

## v0.2.0 (2026-02-12)

### Features

- **Trust Chain Mapping** - Visualize authentication chains between agents, credentials, and services; detect shared credentials, single points of failure, and missing mutual authentication
- **Credential Scope Analysis** - Identify excess privilege, missing expiry, hardcoded secrets, non-rotatable credentials, and user-inherited permissions
- **Identity Spoofing Detection** - Find impersonation vectors, missing message authentication, delegation chain gaps, and injection risks
- **8 Framework Scanners** - MCP (Model Context Protocol), LangChain, CrewAI, AutoGen, OpenClaw, OpenAI Agents SDK, Anthropic Claude/MCP, Pi Agent
- **Multiple Output Formats** - Rich terminal output, JSON, standalone HTML reports, Graphviz DOT trust graphs
- **Risk Scoring** - Weighted severity scoring factoring in exploitability and exposure (network-exposed vs local-only)
- **AAIP Compliance Checks** - Agent Authentication and Identity Protocol baseline validation
- **CLI Commands** - `scan` (full analysis), `trust-map` (chain visualization), `scope` (credential audit), `report` (re-render saved JSON)
