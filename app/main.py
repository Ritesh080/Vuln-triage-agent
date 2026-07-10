"""
REST API for the Vulnerability Triage Agent.

Endpoints:
  POST /findings/ingest        -> bulk-load raw scanner findings
  POST /findings/{id}/triage   -> run the agent on one finding
  POST /findings/triage-all    -> run the agent on every un-triaged finding
  GET  /findings               -> list findings + their triage state
  GET  /findings/{id}          -> single finding + triage result
  GET  /report                 -> aggregated risk report for stakeholders
"""
from collections import Counter
from typing import List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.models import Finding, TriageResult
from app.store import store
from app.triage_agent import TriageAgent

app = FastAPI(title="Vulnerability Triage Agent", version="1.0.0")
agent = TriageAgent()


class IngestPayload(BaseModel):
    findings: List[Finding]


@app.post("/findings/ingest")
def ingest(payload: IngestPayload):
    for f in payload.findings:
        store.add_finding(f)
    return {"ingested": len(payload.findings)}


@app.post("/findings/{finding_id}/triage", response_model=TriageResult)
def triage_one(finding_id: str):
    finding = store.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    result = agent.triage(finding)
    store.add_result(result)
    return result


@app.post("/findings/triage-all")
def triage_all():
    pending = [f for f in store.all_findings() if not store.get_result(f.id)]
    results = agent.triage_batch(pending)
    for r in results:
        store.add_result(r)
    return {"triaged": len(results)}


@app.get("/findings")
def list_findings():
    out = []
    for f in store.all_findings():
        result = store.get_result(f.id)
        out.append({"finding": f, "triage": result})
    return out


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str):
    finding = store.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    return {"finding": finding, "triage": store.get_result(finding_id)}


@app.get("/report")
def report():
    results = store.all_results()
    if not results:
        return {"total": 0, "message": "No triaged findings yet."}

    by_priority = Counter(r.priority.value for r in results)
    by_severity = Counter(r.severity.value for r in results)
    escalated = sum(1 for r in results if r.escalate_to_human)
    auto_actionable = len(results) - escalated

    return {
        "total_triaged": len(results),
        "by_priority": dict(by_priority),
        "by_severity": dict(by_severity),
        "escalated_to_human": escalated,
        "auto_actionable": auto_actionable,
        "automation_rate": round(auto_actionable / len(results), 2),
    }
