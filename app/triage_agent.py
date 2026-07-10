"""
TriageAgent: the core "agent harness" described in the JD.

Design goals this maps directly to:
  - Reads scanner-style output and reasons about severity/business impact.
  - Produces a STRUCTURED, schema-validated output (not free text) so it can
    safely drive downstream actions (open ticket, assign owner, update tracker).
  - Escalates to a human when confidence is low, instead of guessing.
  - Runs identically whether backed by a live LLM or a deterministic stub,
    so the eval harness (tests/test_api.py) can validate the CONTRACT even
    without live API access — this is the "how do you know the agent
    triaged correctly" guardrail the JD calls out.
"""
import json
import os
from typing import List

from anthropic import Anthropic

from app.models import Finding, TriageResult, Severity, Priority

SYSTEM_PROMPT = """You are a security triage agent. Given a single vulnerability
finding from an automated scanner (SAST/DAST/dependency scanner), decide:
- whether it is likely a true positive
- its real-world severity and remediation priority
- a one-sentence business-impact statement a non-security stakeholder would understand
- a concrete recommended action
- your confidence (0-1), and whether a human should review it

Respond with ONLY a JSON object matching this schema, no prose, no markdown fences:
{
  "finding_id": string,
  "is_true_positive": boolean,
  "severity": "critical"|"high"|"medium"|"low"|"info",
  "priority": "P0"|"P1"|"P2"|"P3",
  "business_impact": string,
  "recommended_action": string,
  "confidence": number (0-1),
  "escalate_to_human": boolean,
  "reasoning": string
}
Escalate to human (escalate_to_human=true) whenever confidence < 0.7 or the
finding touches auth, payments, or secrets handling.
"""


class TriageAgent:
    """
    Wraps a single LLM call per finding behind a stable interface.
    live=True  -> calls Claude (claude-sonnet-4-6) with the finding as input.
    live=False -> deterministic rule-based stub with the SAME output contract,
                  used for CI/eval runs where no API key is available.
    """

    def __init__(self):
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        self.live = bool(api_key)
        if self.live:
            self.client = Anthropic(api_key=api_key)

    def triage(self, finding: Finding) -> TriageResult:
        if self.live:
            return self._triage_live(finding)
        return self._triage_stub(finding)

    # ---- live path -------------------------------------------------
    def _triage_live(self, finding: Finding) -> TriageResult:
        message = self.client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=500,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": finding.model_dump_json()}],
        )
        text = "".join(block.text for block in message.content if block.type == "text")
        data = json.loads(text)
        return TriageResult(**data)

    # ---- deterministic fallback / eval stub -------------------------
    def _triage_stub(self, finding: Finding) -> TriageResult:
        text = f"{finding.title} {finding.description}".lower()
        sensitive = any(k in text for k in ("auth", "payment", "secret", "token", "password", "key"))
        raw = (finding.raw_severity or "").lower()

        if raw in ("critical",) or "rce" in text or "remote code execution" in text:
            severity, priority, confidence = Severity.CRITICAL, Priority.P0, 0.9
        elif raw in ("high",) or "sql injection" in text or "sqli" in text:
            severity, priority, confidence = Severity.HIGH, Priority.P1, 0.85
        elif raw in ("medium",) or "xss" in text:
            severity, priority, confidence = Severity.MEDIUM, Priority.P2, 0.75
        elif raw in ("low", "info"):
            severity, priority, confidence = Severity.LOW, Priority.P3, 0.8
        else:
            severity, priority, confidence = Severity.MEDIUM, Priority.P2, 0.6

        escalate = confidence < 0.7 or sensitive
        is_tp = severity != Severity.INFO

        return TriageResult(
            finding_id=finding.id,
            is_true_positive=is_tp,
            severity=severity,
            priority=priority,
            business_impact=(
                f"Could expose {finding.package or 'the affected component'} "
                f"to exploitation if left unpatched."
            ),
            recommended_action=f"Patch/upgrade {finding.package or finding.file_path or 'affected component'}"
            + (f" (tracked as {finding.cve})" if finding.cve else ""),
            confidence=confidence,
            escalate_to_human=escalate,
            reasoning=(
                "Rule-based stub triage (no live LLM key configured): "
                f"matched on raw_severity='{raw}', sensitive_area={sensitive}."
            ),
        )

    def triage_batch(self, findings: List[Finding]) -> List[TriageResult]:
        return [self.triage(f) for f in findings]
