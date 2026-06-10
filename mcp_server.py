"""
Oasis - mcp_server.py
Exposes SentinelGuard security checks as MCP tools.
Any AI agent (Claude, Copilot, custom Splunk agent) can call
these tools before taking action — making Oasis a security
node in the entire AI agent ecosystem.

Run with: python mcp_server.py
Runs on : http://localhost:8002
"""

from fastmcp import FastMCP
from scanners import GuardScanners
from datetime import datetime

mcp     = FastMCP("Oasis Security Gateway")
scanner = GuardScanners()

# ─────────────────────────────────────────────
# TOOL 1 — check_decision
# Full security scan: injection + hallucination + permissions
# ─────────────────────────────────────────────
@mcp.tool()
def check_decision(
    agent_id: str,
    text: str,
    action: str,
    evidence: str
) -> dict:
    """
    Run all 3 security checks on an agent decision.
    Returns verdict (APPROVED/BLOCKED), all check results,
    and MITRE ATT&CK technique tags.

    Args:
        agent_id : ID of the agent making the request
        text     : The agent's message or claim
        action   : The action the agent wants to perform
        evidence : Supporting evidence for the claim
    """
    inj  = scanner.check_for_fake_notes(text)
    hall = scanner.check_for_hallucination(text, evidence)
    perm = scanner.check_permissions(agent_id, action)

    is_blocked = any(r["result"] in ["BLOCKED", "FLAGGED"] for r in [inj, hall, perm])
    verdict    = "BLOCKED" if is_blocked else "APPROVED"

    return {
        "timestamp":    datetime.now().isoformat(),
        "agent_id":     agent_id,
        "action":       action,
        "verdict":      verdict,
        "call_source":  "mcp",
        "checks": {
            "injection":     inj,
            "hallucination": hall,
            "permissions":   perm
        }
    }


# ─────────────────────────────────────────────
# TOOL 2 — explain_threat
# Returns a human-readable explanation of a threat
# ─────────────────────────────────────────────
@mcp.tool()
def explain_threat(
    threat_type: str,
    agent_id: str,
    detail: str
) -> dict:
    """
    Explain a detected threat in plain language for SOC analysts.

    Args:
        threat_type : One of: injection, hallucination, permission
        agent_id    : The agent that triggered the threat
        detail      : The reason string from the check result
    """
    explanations = {
        "injection": (
            f"Agent '{agent_id}' submitted text containing a prompt injection pattern. "
            f"This is an attempt to override the agent's instructions and make it "
            f"perform unauthorized actions. Detail: {detail}"
        ),
        "hallucination": (
            f"Agent '{agent_id}' referenced a CVE that does not exist in the NVD database. "
            f"This indicates the agent fabricated a vulnerability, which could lead to "
            f"false alerts or wasted incident response effort. Detail: {detail}"
        ),
        "permission": (
            f"Agent '{agent_id}' attempted an action outside its permitted scope. "
            f"This violates the least-privilege principle and could indicate a "
            f"compromised or misbehaving agent. Detail: {detail}"
        )
    }

    explanation = explanations.get(
        threat_type,
        f"Unknown threat type '{threat_type}'. Detail: {detail}"
    )

    return {
        "agent_id":     agent_id,
        "threat_type":  threat_type,
        "explanation":  explanation,
        "call_source":  "mcp",
        "timestamp":    datetime.now().isoformat()
    }


# ─────────────────────────────────────────────
# TOOL 3 — get_threat_summary
# Returns current threat stats from the session
# ─────────────────────────────────────────────

_session_log: list = []

@mcp.tool()
def get_threat_summary() -> dict:
    """
    Returns a summary of all threats detected in the current session.
    Includes counts by type, block rate, and last 5 events.
    """
    if not _session_log:
        return {
            "total_checks":  0,
            "total_blocked": 0,
            "block_rate":    "0%",
            "by_type":       {},
            "last_5_events": [],
            "call_source":   "mcp"
        }

    total    = len(_session_log)
    blocked  = sum(1 for e in _session_log if e["verdict"] == "BLOCKED")
    by_type  = {}

    for e in _session_log:
        for check_name, check_data in e.get("checks", {}).items():
            if check_data.get("result") in ["BLOCKED", "FLAGGED"]:
                by_type[check_name] = by_type.get(check_name, 0) + 1

    return {
        "total_checks":  total,
        "total_blocked": blocked,
        "block_rate":    f"{round((blocked/total)*100, 1)}%",
        "by_type":       by_type,
        "last_5_events": _session_log[-5:],
        "call_source":   "mcp"
    }


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  OASIS — MCP Security Server")
    print("  Tools: check_decision | explain_threat | get_threat_summary")
    print("  Running on: http://localhost:8002")
    print("="*55 + "\n")
    mcp.run(transport="sse", host="0.0.0.0", port=8002)
