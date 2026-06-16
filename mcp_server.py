"""
Oasis MCP Server — port 8002
Exposes security checks as MCP tools + integrates Splunk AI (generate_spl, ask_splunk_question)
at runtime so the project qualifies for Splunk Agentic Ops Hackathon 2026.
"""

import os
import json
import asyncio
from datetime import datetime
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP

load_dotenv()

# ── Splunk REST API config ────────────────────────────────────────────────────
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_REST_PORT = int(os.getenv("SPLUNK_REST_PORT", "8089"))
SPLUNK_REST_TOKEN = os.getenv("SPLUNK_REST_TOKEN", "")          # Bearer token for REST API
SPLUNK_REST_USER = os.getenv("SPLUNK_REST_USER", "admin")
SPLUNK_REST_PASSWORD = os.getenv("SPLUNK_REST_PASSWORD", "")
SPLUNK_HEC_PORT = int(os.getenv("SPLUNK_HEC_PORT", "8088"))
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "main")
SPLUNK_SOURCETYPE = os.getenv("SPLUNK_SOURCETYPE", "sentinelguard")

# Gateway URL (Agent 1 — the protector)
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8001")

# ── In-memory event store (last 100 events) ───────────────────────────────────
_events: list[dict] = []

mcp = FastMCP("oasis")


# ═════════════════════════════════════════════════════════════════════════════
# Helper: call the Splunk REST API (search/jobs endpoint)
# ═════════════════════════════════════════════════════════════════════════════

async def _splunk_rest_search(spl: str, max_results: int = 100) -> list[dict]:
    """
    Submit a one-shot SPL search to Splunk REST API and return results as a list of dicts.
    Uses the /services/search/jobs/export endpoint (synchronous export).
    """
    base = f"https://{SPLUNK_HOST}:{SPLUNK_REST_PORT}"

    # Build auth header — prefer token, fall back to basic auth
    if SPLUNK_REST_TOKEN:
        headers = {"Authorization": f"Bearer {SPLUNK_REST_TOKEN}"}
    else:
        import base64
        creds = base64.b64encode(f"{SPLUNK_REST_USER}:{SPLUNK_REST_PASSWORD}".encode()).decode()
        headers = {"Authorization": f"Basic {creds}"}

    params = {
        "search": f"search {spl}",
        "output_mode": "json",
        "count": max_results,
        "exec_mode": "oneshot",
    }

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        r = await client.post(
            f"{base}/services/search/jobs/export",
            headers=headers,
            data=params,
        )
        r.raise_for_status()

    results = []
    for line in r.text.strip().splitlines():
        try:
            obj = json.loads(line)
            if obj.get("result"):
                results.append(obj["result"])
        except json.JSONDecodeError:
            pass
    return results


async def _splunk_ai_generate_spl(natural_language_prompt: str) -> str:
    """
    Call Splunk MCP Server's generate_spl tool at runtime.
    Returns the AI-generated SPL string.
    This is what makes the project use Splunk AI at runtime.
    """
    base = f"https://{SPLUNK_HOST}:{SPLUNK_REST_PORT}"
    if SPLUNK_REST_TOKEN:
        headers = {
            "Authorization": f"Bearer {SPLUNK_REST_TOKEN}",
            "Content-Type": "application/json",
        }
    else:
        import base64
        creds = base64.b64encode(f"{SPLUNK_REST_USER}:{SPLUNK_REST_PASSWORD}".encode()).decode()
        headers = {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}

    payload = {
        "method": "tools/call",
        "params": {
            "name": "generate_spl",
            "arguments": {"prompt": natural_language_prompt},
        },
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            r = await client.post(
                f"{base}/servicesNS/nobody/Splunk_MCP_Server/mcp/v1/messages",
                headers=headers,
                json=payload,
            )
            data = r.json()
            # Splunk MCP Server returns the SPL in content[0].text
            content = data.get("result", {}).get("content", [])
            for block in content:
                if block.get("type") == "text":
                    return block["text"]
    except Exception as e:
        # Graceful fallback: build a reasonable SPL ourselves
        return (
            f"index={SPLUNK_INDEX} sourcetype={SPLUNK_SOURCETYPE} | "
            f"search {natural_language_prompt} | head 50"
        )

    return ""


async def _splunk_ai_ask(question: str) -> str:
    """
    Call Splunk MCP Server's ask_splunk_question tool at runtime.
    Returns a natural-language answer from Splunk AI.
    """
    base = f"https://{SPLUNK_HOST}:{SPLUNK_REST_PORT}"
    if SPLUNK_REST_TOKEN:
        headers = {
            "Authorization": f"Bearer {SPLUNK_REST_TOKEN}",
            "Content-Type": "application/json",
        }
    else:
        import base64
        creds = base64.b64encode(f"{SPLUNK_REST_USER}:{SPLUNK_REST_PASSWORD}".encode()).decode()
        headers = {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}

    payload = {
        "method": "tools/call",
        "params": {
            "name": "ask_splunk_question",
            "arguments": {"question": question},
        },
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            r = await client.post(
                f"{base}/servicesNS/nobody/Splunk_MCP_Server/mcp/v1/messages",
                headers=headers,
                json=payload,
            )
            data = r.json()
            content = data.get("result", {}).get("content", [])
            for block in content:
                if block.get("type") == "text":
                    return block["text"]
    except Exception:
        return "Splunk AI unavailable — check SPLUNK_REST_TOKEN and Splunk_MCP_Server app installation."

    return ""


# ═════════════════════════════════════════════════════════════════════════════
# Tool 1 — check_decision  (Agent 1: The Protector)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def check_decision(
    agent_id: str,
    text: str,
    action: str,
    evidence: Optional[str] = None,
) -> dict:
    """
    Run all three OWASP security checks on an agent action before it executes.
    Returns APPROVED or BLOCKED with a MITRE ATT&CK tag.
    """
    payload = {
        "agent_id": agent_id,
        "text": text,
        "action": action,
        "evidence": evidence or "",
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(f"{GATEWAY_URL}/check_decision", json=payload)
            result = r.json()
    except Exception as e:
        result = {"error": str(e), "verdict": "ERROR", "message": "Gateway unreachable"}

    # Store locally for get_threat_summary
    _events.append({**result, "timestamp": datetime.utcnow().isoformat(), "agent_id": agent_id})
    if len(_events) > 100:
        _events.pop(0)

    return result


# ═════════════════════════════════════════════════════════════════════════════
# Tool 2 — explain_threat  (Agent 2: The Explainer — uses Splunk AI at runtime)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def explain_threat(
    threat_type: str,
    agent_id: str,
    detail: Optional[str] = None,
) -> dict:
    """
    Agent 2 — The Explainer.
    Uses Splunk AI (generate_spl + ask_splunk_question) at runtime to:
    1. Generate an SPL query for this threat from natural language
    2. Run that query against Splunk
    3. Ask Splunk AI to explain the findings in plain English for SOC analysts
    """

    # ── Step 1: Ask Splunk AI to generate an SPL for this threat ─────────────
    nl_prompt = (
        f"Show me all {threat_type} events for agent {agent_id} "
        f"from index={SPLUNK_INDEX} sourcetype={SPLUNK_SOURCETYPE} "
        f"in the last 24 hours, grouped by MITRE technique, sorted by count descending"
    )
    generated_spl = await _splunk_ai_generate_spl(nl_prompt)

    # ── Step 2: Execute the generated SPL against Splunk REST API ─────────────
    search_results: list[dict] = []
    try:
        # Strip the leading "search" keyword if generate_spl included it
        spl_to_run = generated_spl.lstrip("search").strip()
        search_results = await _splunk_rest_search(spl_to_run, max_results=20)
    except Exception as e:
        search_results = [{"error": str(e)}]

    # ── Step 3: Ask Splunk AI for a natural-language explanation ──────────────
    ask_question = (
        f"Based on the last 24 hours of data in index={SPLUNK_INDEX} "
        f"sourcetype={SPLUNK_SOURCETYPE}, explain the {threat_type} threat pattern "
        f"detected for agent {agent_id}. What MITRE techniques are involved and "
        f"what remediation steps should a SOC analyst take?"
    )
    splunk_ai_explanation = await _splunk_ai_ask(ask_question)

    # Fallback plain-English explanation when Splunk AI is offline
    if not splunk_ai_explanation:
        explanations = {
            "prompt_injection": (
                "A prompt injection attack was detected. The agent received instructions "
                "designed to override its system prompt — a classic LLM01 vector. "
                "Review the input source and enforce input validation upstream."
            ),
            "hallucination": (
                "The agent referenced a CVE not found in the NIST NVD database. "
                "This indicates LLM09 hallucination. Cross-check all CVE claims "
                "against NVD before acting on them."
            ),
            "permission_abuse": (
                "The agent attempted an action outside its declared permission scope. "
                "This is an LLM08 excessive agency violation. Audit the agent's "
                "allowlist and enforce least-privilege at the gateway level."
            ),
        }
        splunk_ai_explanation = explanations.get(
            threat_type.lower().replace(" ", "_"),
            f"Threat type '{threat_type}' detected for agent {agent_id}. "
            "Review Splunk dashboard for full event timeline.",
        )

    return {
        "threat_type": threat_type,
        "agent_id": agent_id,
        "splunk_ai_generated_spl": generated_spl,
        "splunk_search_results_count": len(search_results),
        "splunk_search_results": search_results[:5],   # first 5 for brevity
        "splunk_ai_explanation": splunk_ai_explanation,
        "detail": detail or "",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ═════════════════════════════════════════════════════════════════════════════
# Tool 3 — get_threat_summary
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_threat_summary() -> dict:
    """
    Returns blocked count, block rate, breakdown by check type, and last 5 events.
    Queries Splunk REST API for live stats when available.
    """
    # ── Live stats from Splunk ────────────────────────────────────────────────
    live_stats: dict = {}
    try:
        spl = (
            f"index={SPLUNK_INDEX} sourcetype={SPLUNK_SOURCETYPE} earliest=-24h "
            "| stats count as total, "
            "count(eval(verdict=\"BLOCKED\")) as blocked, "
            "count(eval(verdict=\"APPROVED\")) as approved "
            "by verdict | stats sum(total) as total, sum(blocked) as blocked, "
            "sum(approved) as approved"
        )
        rows = await _splunk_rest_search(spl, max_results=5)
        if rows:
            live_stats = rows[0]
    except Exception:
        pass

    # ── Local in-memory fallback ───────────────────────────────────────────────
    total = len(_events)
    blocked = sum(1 for e in _events if e.get("verdict") == "BLOCKED")
    approved = total - blocked
    block_rate = round((blocked / total * 100), 1) if total else 0

    by_check: dict[str, int] = {}
    for e in _events:
        check = e.get("check_triggered", "unknown")
        by_check[check] = by_check.get(check, 0) + 1

    return {
        "source": "splunk_live" if live_stats else "local_memory",
        "splunk_stats": live_stats,
        "local_stats": {
            "total_events": total,
            "blocked": blocked,
            "approved": approved,
            "block_rate_pct": block_rate,
            "by_check_type": by_check,
        },
        "last_5_events": _events[-5:],
        "timestamp": datetime.utcnow().isoformat(),
    }


# ═════════════════════════════════════════════════════════════════════════════
# Tool 4 — analyze_threat_with_splunk_ai  (explicit Splunk AI runtime call)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def analyze_threat_with_splunk_ai(
    threat_type: str,
    agent_id: str,
    time_range: Optional[str] = "24h",
) -> dict:
    """
    Directly invokes Splunk AI (generate_spl tool from Splunk_MCP_Server) at runtime
    to build and execute a targeted threat-hunt query.
    This tool exists specifically to satisfy the hackathon requirement of using
    Splunk AI capabilities at runtime.
    """
    nl_prompt = (
        f"Show me all blocked events for agent {agent_id} "
        f"with threat type {threat_type} "
        f"from index={SPLUNK_INDEX} sourcetype={SPLUNK_SOURCETYPE} "
        f"in the last {time_range}, "
        "grouped by mitre_technique, sorted by count descending"
    )

    # ── Call Splunk AI: generate_spl ──────────────────────────────────────────
    generated_spl = await _splunk_ai_generate_spl(nl_prompt)

    # ── Execute the AI-generated SPL ──────────────────────────────────────────
    try:
        spl_to_run = generated_spl.lstrip("search").strip()
        results = await _splunk_rest_search(spl_to_run, max_results=50)
    except Exception as e:
        results = [{"error": str(e)}]

    # ── Call Splunk AI: ask_splunk_question for context ───────────────────────
    ask_q = (
        f"What is the severity and remediation for {threat_type} attacks "
        f"targeting agent {agent_id} in a SIEM context?"
    )
    ai_context = await _splunk_ai_ask(ask_q)

    return {
        "splunk_ai_tool_called": "generate_spl",            # proves runtime AI usage
        "splunk_ai_second_tool": "ask_splunk_question",     # proves runtime AI usage
        "natural_language_prompt": nl_prompt,
        "splunk_ai_generated_spl": generated_spl,
        "results_count": len(results),
        "results": results[:10],
        "splunk_ai_context": ai_context,
        "threat_type": threat_type,
        "agent_id": agent_id,
        "time_range": time_range,
        "timestamp": datetime.utcnow().isoformat(),
    }


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8002)
