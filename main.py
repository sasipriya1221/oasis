"""
SentinelGuard - main.py
FastAPI gateway. Run with: uvicorn main:app --reload --port 8001
"""

from fastapi import FastAPI
from pydantic import BaseModel
from scanners import GuardScanners
import requests
from datetime import datetime

app = FastAPI(title="SentinelGuard")

# ── Splunk config ──────────────────────────────────────
SPLUNK_HEC_URL = "https://localhost:8088/services/collector/event"
SPLUNK_TOKEN = "650b8078-2310-4ffb-bfd4-7d54c73599a2"
# ──────────────────────────────────────────────────────

scanner = GuardScanners()

class AgentEvent(BaseModel):
    agent_id: str
    text:     str
    action:   str
    evidence: str

def send_to_splunk(event: dict):
    payload = {"event": event, "sourcetype": "sentinelguard", "index": "main"}
    headers = {"Authorization": f"Splunk {SPLUNK_TOKEN}"}
    try:
        requests.post(SPLUNK_HEC_URL, json=payload, headers=headers, verify=False, timeout=3)
        print(f"  ✅ Sent to Splunk")
    except Exception:
        print(f"  ⚠️  Splunk not connected yet — running in local mode")

@app.get("/")
def root():
    return {"project": "SentinelGuard", "status": "online", "version": "1.0.0"}

@app.post("/check_decision")
def check_decision(form: AgentEvent):
    print(f"\n{'='*55}")
    print(f"  Agent  : {form.agent_id}")
    print(f"  Action : {form.action}")
    print(f"  Text   : {form.text[:80]}")

    inj  = scanner.check_for_fake_notes(form.text)
    hall = scanner.check_for_hallucination(form.text, form.evidence)
    perm = scanner.check_permissions(form.agent_id, form.action)

    is_blocked = any(r["result"] in ["BLOCKED", "FLAGGED"] for r in [inj, hall, perm])
    verdict    = "BLOCKED" if is_blocked else "APPROVED"

    icon = "🔴 BLOCKED" if is_blocked else "🟢 APPROVED"
    print(f"  Verdict: {icon}")
    for r in [inj, hall, perm]:
        symbol = "❌" if r["result"] in ["BLOCKED", "FLAGGED"] else "✅"
        print(f"    {symbol} {r['check'].upper()}: {r['result']} — {r['reason']}")

    splunk_event = {
        "timestamp":     datetime.now().isoformat(),
        "agent_id":      form.agent_id,
        "action":        form.action,
        "input_text":    form.text[:120],
        "final_verdict": verdict,
        "injection":     inj,
        "hallucination": hall,
        "permissions":   perm,
    }
    send_to_splunk(splunk_event)

    return {"status": verdict, "checks": [inj, hall, perm], "agent_id": form.agent_id}