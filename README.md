# Agent Identity Auditor (AIA)

**Map trust chains, analyze credentials, and detect identity spoofing across AI agent frameworks.**

AIA is a security auditing tool that examines how AI agents authenticate, what credentials they hold, and where identity-based attacks can occur. It scans your agent configurations and produces actionable findings with risk scores.

## What It Does

1. **Trust Chain Mapping** - Traces authentication relationships between agents, credentials, and external services. Identifies shared credentials, single points of failure, and missing mutual authentication.

2. **Credential Scope Analysis** - Detects overly broad permissions, missing expiry, hardcoded secrets, non-rotatable credentials, and user-inherited privileges that violate least-privilege principles.

3. **Identity Spoofing Detection** - Finds impersonation vectors, missing message authentication, delegation chain gaps, and prompt injection risks that could allow one agent to act as another.

## Supported Frameworks

| Framework | What AIA Scans |
|-----------|---------------|
| **MCP** (Model Context Protocol) | Server configs, tool permissions, credential delegation |
| **LangChain** | Tool bindings, API key usage, chain-of-trust patterns |
| **CrewAI** | Agent roles, shared credentials, delegation settings |
| **AutoGen** | Multi-agent configs, code execution permissions |
| **OpenClaw** | Gateway configs, agent identity, tool policies |
| **OpenAI Agents SDK** | Agent definitions, tool auth, handoff patterns |
| **Anthropic Claude/MCP** | Claude Desktop configs, MCP server trust |
| **Pi Agent** | Agent manifests, capability declarations |

## Installation

**From source (recommended for now):**

```bash
git clone https://github.com/j-mchugh/AIA.git
cd aia
pip install -e .
```

**Via pip (coming soon):**

```bash
pip install aia-tool
```

Requires Python 3.10+.

## Usage

### Full Scan

Run all three analysis capabilities against your home directory (picks up system-wide agent configs automatically):

```bash
aia scan
```

Scan a specific project directory:

```bash
aia scan --dir ./my-agent-project
```

Output as JSON or HTML:

```bash
aia scan --format json --output results.json
aia scan --format html --output report.html
```

Generate a Graphviz trust chain graph:

```bash
aia scan --dir ./project --graph trust-chain.dot
dot -Tpng trust-chain.dot -o trust-chain.png
```

### Trust Chain Map

Visualize authentication chains without running the full analysis:

```bash
aia trust-map
aia trust-map --dir ./project --graph chain.dot
```

### Credential Scope Audit

Focus on credential hygiene and privilege issues:

```bash
aia scope
aia scope --dir ./project
```

### Re-render a Saved Report

Convert a previously saved JSON scan to other formats:

```bash
aia report results.json
aia report results.json --format html --output report.html
```

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| **Terminal** | `--format terminal` | Rich colored output with tables and ASCII trust graphs (default) |
| **JSON** | `--format json` | Machine-readable structured output |
| **HTML** | `--format html` | Standalone single-file report with embedded styles |
| **Graphviz DOT** | `--graph file.dot` | Directed graph of trust relationships for visualization |

## Example Output

```
AIA Scanning: /Users/you

Frameworks detected: MCP, OpenClaw, Anthropic

Agents found: 5
Credentials found: 8
Trust relationships: 12

== Findings (14) ==

!! [CRITICAL] Hardcoded API key in MCP server config
   credential: openai-api-key
   location: ~/.config/claude/claude_desktop_config.json
   -> Move to environment variable or secrets manager

!  [HIGH] Credential shared across 3 agents without scoping
   credential: github-token
   -> Issue per-agent tokens with minimum required scopes

~  [MEDIUM] No expiry set on long-lived token
   credential: slack-bot-token
   -> Set token rotation policy

-  [LOW] Agent lacks explicit identity declaration
   agent: research-assistant
   -> Add identity metadata to agent config

== Risk Score: 72/100 (High) ==
```

## Risk Scoring

AIA produces a weighted risk score from 0 to 100 based on:

- **Severity** - Critical, High, Medium, Low findings carry different base weights
- **Exploitability** - Network-exposed credentials score higher than local-only configs
- **Exposure classification** - Each finding is tagged as network-exposed, locally exploitable, or configuration-only

The score gives you a quick read on overall posture. Individual findings include specific remediation steps.

## Development

```bash
git clone https://github.com/j-mchugh/AIA.git
cd aia
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Verify
aia scan --help
aia trust-map --help
aia scope --help
aia report --help
```

## License

Apache 2.0 - see [LICENSE](LICENSE).

---

Built by [j-mchugh](https://mchugh.ai)
