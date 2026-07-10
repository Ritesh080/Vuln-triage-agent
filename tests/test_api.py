"""
Eval harness for the triage agent — this is the "how do you know the agent
triaged correctly" guardrail the JD asks for.

Two things are checked, deliberately kept separate:
1. STRUCTURAL correctness: every single output must validate against the
   TriageResult schema. This must always be 100% or the agent is unsafe to
   wire into downstream automation (tickets, trackers) at all.
2. LABELING accuracy: agent output compared against a small hand-labeled
   ground-truth set, reported as a percentage (not hard-coded to pass) so
   a regression in the agent's judgment is visible, not silently accepted.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models import Finding
from app.triage_agent import TriageAgent

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_PATH = os.path.join(HERE, "..", "sample_data", "findings.json")

# Hand-labeled ground truth for the 8 sample findings: (severity, priority, should_escalate)
GROUND_TRUTH = {
    "F-001": ("high", "P1", False),      # SQLi, not auth/payment/secret-tagged
    "F-002": ("critical", "P0", False),  # RCE via image lib
    "F-003": ("medium", "P2", False),    # reflected XSS
    "F-004": ("high", "P1", True),       # JWT bypass touches auth
    "F-005": ("critical", "P0", True),   # hardcoded secret in payment context
    "F-006": ("low", "P3", False),       # verbose error / stack trace
    "F-007": ("low", "P3", False),       # stale dep, no known exploit
    "F-008": ("medium", "P2", True),     # missing rate limit on login/auth route
}


def load_findings():
    with open(SAMPLE_PATH) as fh:
        data = json.load(fh)
    return [Finding(**f) for f in data["findings"]]


def test_all_outputs_are_schema_valid():
    agent = TriageAgent()
    findings = load_findings()
    results = agent.triage_batch(findings)
    assert len(results) == len(findings)
    for r in results:
        assert 0.0 <= r.confidence <= 1.0
        assert r.severity is not None
        assert r.priority is not None
        assert isinstance(r.escalate_to_human, bool)


def test_triage_agreement_against_labeled_set():
    agent = TriageAgent()
    findings = load_findings()
    results = {r.finding_id: r for r in agent.triage_batch(findings)}

    total = len(GROUND_TRUTH)
    severity_priority_matches = 0
    escalation_matches = 0

    for fid, (exp_sev, exp_pri, exp_escalate) in GROUND_TRUTH.items():
        result = results[fid]
        if result.severity.value == exp_sev and result.priority.value == exp_pri:
            severity_priority_matches += 1
        if result.escalate_to_human == exp_escalate:
            escalation_matches += 1

    sev_pri_accuracy = severity_priority_matches / total
    escalation_accuracy = escalation_matches / total

    print(f"\nSeverity+Priority agreement: {severity_priority_matches}/{total} "
          f"({sev_pri_accuracy:.0%})")
    print(f"Escalation-decision agreement: {escalation_matches}/{total} "
          f"({escalation_accuracy:.0%})")

    # Guardrail threshold: build should fail if agent judgment regresses badly.
    assert sev_pri_accuracy >= 0.75
    assert escalation_accuracy >= 0.75


def test_sensitive_findings_always_escalate():
    """Auth/payment/secret-related findings must never be auto-actioned
    without a human — this is the safety guardrail from the JD."""
    agent = TriageAgent()
    findings = load_findings()
    results = {r.finding_id: r for r in agent.triage_batch(findings)}

    sensitive_ids = ["F-004", "F-005", "F-008"]  # auth / payment
    -secret / auth
    for fid in sensitive_ids:
        assert results[fid].escalate_to_human is True, f"{fid} should escalate to a human"
