"""
Data models for the Vulnerability Triage Agent.

Findings are modeled on real scanner output shapes (Semgrep/Trivy/SAST-style)
so the agent can be pointed at real tool output with minimal glue code.
"""
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Priority(str, Enum):
    P0 = "P0"  # fix now / page someone
    P1 = "P1"  # fix this sprint
    P2 = "P2"  # backlog
    P3 = "P3"  # accept / wontfix candidate


class Finding(BaseModel):
    """Raw input as it would arrive from a scanner (SAST/DAST/dependency scanner)."""
    id: str
    source: str  # e.g. "semgrep", "trivy", "dependabot"
    title: str
    description: str
    file_path: Optional[str] = None
    line: Optional[int] = None
    raw_severity: Optional[str] = None  # scanner's own severity label, if any
    cve: Optional[str] = None
    package: Optional[str] = None


class TriageResult(BaseModel):
    """
    Structured output the agent MUST produce for every finding.
    This is the "tool-use / structured output" contract the JD calls out —
    downstream systems (ticketing, dashboards) depend on this schema being stable.
    """
    finding_id: str
    is_true_positive: bool
    severity: Severity
    priority: Priority
    business_impact: str = Field(..., description="One-sentence plain-English impact statement")
    recommended_action: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    escalate_to_human: bool = Field(
        ..., description="True when the agent is not confident enough to act autonomously"
    )
    reasoning: str
