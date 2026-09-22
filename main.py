"""OASIS runtime security gateway and demonstration dashboard.

Run with: python -m uvicorn main:app --reload --port 8001
"""

import os
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

from scanners import GuardScanners

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(
    title="OASIS - AI Agent Security Guard",
    description="Runtime policy enforcement for autonomous AI-agent actions.",
    version="1.0.0",
)

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_HEC_PORT = os.getenv("SPLUNK_HEC_PORT", "8088")
SPLUNK_HEC_URL = f"https://{SPLUNK_HOST}:{SPLUNK_HEC_PORT}/services/collector/event"
SPLUNK_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "main")
SPLUNK_SOURCETYPE = os.getenv("SPLUNK_SOURCETYPE", "sentinelguard")

scanner = GuardScanners()


class AgentEvent(BaseModel):
    agent_id: str
    text: str
    action: str
    evidence: str


def send_to_splunk(event: dict) -> bool:
    """Send a verdict to Splunk when HEC is configured."""
    if not SPLUNK_TOKEN:
        print("  Splunk token not configured - running in local mode")
        return False

    payload = {
        "event": event,
        "sourcetype": SPLUNK_SOURCETYPE,
        "index": SPLUNK_INDEX,
    }
    headers = {"Authorization": f"Splunk {SPLUNK_TOKEN}"}
    try:
        response = requests.post(
            SPLUNK_HEC_URL,
            json=payload,
            headers=headers,
            verify=False,
            timeout=3,
        )
        response.raise_for_status()
        print("  Sent to Splunk")
        return True
    except requests.RequestException:
        print("  Splunk not connected - running in local mode")
        return False


@app.get("/", include_in_schema=False)
def dashboard():
    """Serve the OASIS presentation dashboard."""
    return FileResponse(BASE_DIR / "dashboard.html")


@app.get("/health")
def health():
    return {"project": "OASIS", "status": "online", "version": "1.0.0"}


@app.post("/check_decision")
def check_decision(form: AgentEvent):
    inj = scanner.check_for_fake_notes(form.text)
    hall = scanner.check_for_hallucination(form.text, form.evidence)
    perm = scanner.check_permissions(form.agent_id, form.action)

    checks = [inj, hall, perm]
    is_blocked = any(result["result"] in {"BLOCKED", "FLAGGED"} for result in checks)
    verdict = "BLOCKED" if is_blocked else "APPROVED"

    splunk_event = {
        "timestamp": datetime.now().isoformat(),
        "agent_id": form.agent_id,
        "action": form.action,
        "input_text": form.text[:120],
        "final_verdict": verdict,
        "injection": inj,
        "hallucination": hall,
        "permissions": perm,
    }
    splunk_logged = send_to_splunk(splunk_event)

    return {
        "status": verdict,
        "checks": checks,
        "agent_id": form.agent_id,
        "action": form.action,
        "timestamp": splunk_event["timestamp"],
        "splunk_logged": splunk_logged,
    }
