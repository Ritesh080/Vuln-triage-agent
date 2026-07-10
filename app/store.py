"""Minimal in-memory store. Swappable for a real DB (SQLite/Postgres) later —
kept in-memory here so the project runs anywhere with zero setup."""
from typing import Dict, Optional
from app.models import Finding, TriageResult


class Store:
    def __init__(self):
        self.findings: Dict[str, Finding] = {}
        self.results: Dict[str, TriageResult] = {}

    def add_finding(self, finding: Finding):
        self.findings[finding.id] = finding

    def add_result(self, result: TriageResult):
        self.results[result.finding_id] = result

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        return self.findings.get(finding_id)

    def get_result(self, finding_id: str) -> Optional[TriageResult]:
        return self.results.get(finding_id)

    def all_findings(self):
        return list(self.findings.values())

    def all_results(self):
        return list(self.results.values())


store = Store()
