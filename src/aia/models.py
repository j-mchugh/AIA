"""Core data models for AIA scan results."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import json


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CredentialType(str, Enum):
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    SERVICE_ACCOUNT = "service_account"
    ENV_VAR = "env_var"
    HARDCODED = "hardcoded"
    USER_INHERITED = "user_inherited"
    NONE = "none"
    UNKNOWN = "unknown"


class Framework(str, Enum):
    MCP = "mcp"
    LANGCHAIN = "langchain"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    OPENCLAW = "openclaw"
    OPENAI_AGENTS = "openai_agents"
    ANTHROPIC = "anthropic"
    PI_AGENT = "pi_agent"
    UNKNOWN = "unknown"


@dataclass
class Credential:
    id: str
    cred_type: CredentialType
    source: str  # where it comes from (env var name, config path, etc.)
    target_service: str  # what service it authenticates to
    shared_by: list[str] = field(default_factory=list)  # agent IDs sharing this cred
    scope: Optional[str] = None  # known scope/permissions
    rotatable: bool = False
    expires: Optional[str] = None

    @property
    def is_shared(self) -> bool:
        return len(self.shared_by) > 1


@dataclass
class Agent:
    id: str
    name: str
    framework: Framework
    identity_type: str  # "string", "cryptographic", "certificate", "none"
    credentials: list[str] = field(default_factory=list)  # credential IDs
    communicates_with: list[str] = field(default_factory=list)  # other agent IDs
    source_file: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class TrustRelationship:
    source_agent: str  # agent ID
    target: str  # service name or agent ID
    credential_id: Optional[str]
    auth_method: str  # "oauth", "api_key", "none", "inherited", "implicit"
    mutual: bool = False  # does the target verify the source?
    verified: bool = False  # is the identity cryptographically verified?


class Exposure(str, Enum):
    """How exploitable is this finding from an external attacker's perspective."""
    INTERNET = "internet"      # Directly exploitable from the internet
    NETWORK = "network"        # Exploitable from the local network
    LOCAL = "local"            # Requires local access to the machine
    THEORETICAL = "theoretical"  # Requires specific preconditions or chained attacks


# Base weight for each exposure level (multiplier on severity score)
EXPOSURE_WEIGHTS = {
    Exposure.INTERNET: 1.0,
    Exposure.NETWORK: 0.6,
    Exposure.LOCAL: 0.25,
    Exposure.THEORETICAL: 0.1,
}

# Base points per severity
SEVERITY_POINTS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    severity: Severity
    title: str
    description: str
    affected: list[str]  # agent/credential IDs
    recommendation: str
    category: str  # "shared_credentials", "identity_spoofing", "excess_privilege", etc.
    exposure: Exposure = Exposure.LOCAL  # default to local; scanners/analyzers should set appropriately
    locations: list[str] = field(default_factory=list)  # file paths where affected assets are defined


@dataclass
class ScanResult:
    scan_id: str
    scan_time: str
    source_path: str
    frameworks_detected: list[Framework]
    agents: list[Agent] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    trust_relationships: list[TrustRelationship] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def risk_score(self) -> tuple[int, dict]:
        """Calculate risk score weighted by exploitability.

        Returns (score 0-100, breakdown dict).
        Score reflects how exploitable findings are from the internet.
        A machine with only local-access findings scores much lower than
        one with internet-exposed critical issues.
        """
        if not self.findings:
            return 0, {}

        raw_points = 0.0
        # Max baseline: 5 internet-facing criticals (100pts) + 5 internet highs (50pts) = 150
        # This means a purely local setup needs a LOT of findings to hit 100
        max_baseline = 150.0

        exposure_breakdown = {}
        for f in self.findings:
            pts = SEVERITY_POINTS.get(f.severity, 0) * EXPOSURE_WEIGHTS.get(f.exposure, 0.1)
            raw_points += pts
            exp_key = f.exposure.value
            exposure_breakdown.setdefault(exp_key, {"count": 0, "weighted_points": 0.0})
            exposure_breakdown[exp_key]["count"] += 1
            exposure_breakdown[exp_key]["weighted_points"] += pts

        # Normalize: 100 raw points = score of 100
        score = min(100, int(round(raw_points * 100.0 / max_baseline)))

        breakdown = {
            "raw_points": round(raw_points, 1),
            "max_baseline": max_baseline,
            "by_exposure": exposure_breakdown,
        }
        return score, breakdown

    def to_dict(self) -> dict:
        """Serialize to dict for JSON output."""
        return {
            "scan_id": self.scan_id,
            "scan_time": self.scan_time,
            "source_path": self.source_path,
            "frameworks_detected": [f.value for f in self.frameworks_detected],
            "summary": {
                "total_agents": len(self.agents),
                "total_credentials": len(self.credentials),
                "total_trust_relationships": len(self.trust_relationships),
                "total_findings": len(self.findings),
                "findings_by_severity": {
                    s.value: len([f for f in self.findings if f.severity == s])
                    for s in Severity
                },
                "risk_score": self.risk_score()[0],
                "risk_breakdown": self.risk_score()[1],
            },
            "agents": [
                {
                    "id": a.id,
                    "name": a.name,
                    "framework": a.framework.value,
                    "identity_type": a.identity_type,
                    "credentials": a.credentials,
                    "communicates_with": a.communicates_with,
                    "source_file": a.source_file,
                }
                for a in self.agents
            ],
            "credentials": [
                {
                    "id": c.id,
                    "type": c.cred_type.value,
                    "source": c.source,
                    "target_service": c.target_service,
                    "shared_by": c.shared_by,
                    "is_shared": c.is_shared,
                    "scope": c.scope,
                }
                for c in self.credentials
            ],
            "trust_relationships": [
                {
                    "source_agent": t.source_agent,
                    "target": t.target,
                    "credential_id": t.credential_id,
                    "auth_method": t.auth_method,
                    "mutual_auth": t.mutual,
                    "identity_verified": t.verified,
                }
                for t in self.trust_relationships
            ],
            "findings": [
                {
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "affected": f.affected,
                    "recommendation": f.recommendation,
                    "category": f.category,
                    "exposure": f.exposure.value,
                    "locations": f.locations,
                }
                for f in self.findings
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
