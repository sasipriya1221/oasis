# Oasis

**One agent protects. One agent explains.**

Oasis is a runtime security gateway for AI agents built for the **Splunk Agentic Ops Hackathon 2026**. It intercepts every agent action before execution, runs three parallel OWASP LLM Top 10 checks, logs structured verdicts to Splunk, and exposes those checks as MCP tools so any LLM can query them directly.

---

## The problem

AI agents running inside enterprise environments — issuing alerts, isolating hosts, flagging vulnerabilities — have no runtime guardrail layer. An agent can be injected with malicious instructions, act on a CVE that doesn't exist, or attempt an action it was never authorized to perform. None of this shows up in your SIEM until after the damage is done.

Oasis puts a security checkpoint in front of every agent action, before it executes.

---

## How it works

Every request hits the Oasis gateway on port 8001. Three checks run in parallel:

**Check 1 — Prompt Injection (OWASP LLM01)**
Four-layer pattern match: direct phrases, privilege escalation, roleplay/jailbreak, and context hijacking. Obfuscation detection strips whitespace before matching. Tagged to MITRE ATT&CK on block.

**Check 2 — Hallucination Detection (OWASP LLM09)**
Extracts every `CVE-XXXX-XXXXX` pattern from the agent's text and queries the NIST NVD API live. A CVE that doesn't exist in the NVD database gets the request flagged immediately. Results are cached for one hour to avoid rate limits.

**Check 3 — Permission Enforcement (OWASP LLM08)**
Zero-trust allowlist. Every registered agent has a fixed list of permitted actions. Unknown agents are blocked automatically. Any action outside the declared scope is rejected with the reason logged.

The gateway returns a `BLOCKED` or `APPROVED` verdict plus the full check results, then ships the structured JSON event to Splunk via HEC.

---

## Architecture

See [`architecture.png`](architecture.png) in this repo for the full diagram.

```
AI Agents (ThreatHunter-v2, NetMonitor-v1, LogAnalyser-v1 ...)
        |
        | POST /check_decision
        v
Oasis Gateway — FastAPI · port 8001
        |
        |--- [LLM01] Injection Scanner      (4 layers, obfuscation-aware)
        |--- [LLM09] Hallucination Detector (live NVD API · 1hr cache)
        |--- [LLM08] Permissions Enforcer   (zero-trust allowlist)
        |
        | BLOCKED / APPROVED + MITRE tag
        v
Splunk HEC · port 8088  →  index=main  sourcetype=sentinelguard
        |
        | | spath | eval | stats
        v
Dashboard Studio · 10 panels

MCP Server · port 8002 (FastMCP)
        |--- check_decision
        |--- explain_threat
        |--- get_threat_summary
```

---

## Splunk integration

| What | How |
|---|---|
| Ingestion | Splunk HEC `POST :8088/services/collector/event` |
| Index | `index=main sourcetype=sentinelguard` |
| Field extraction | `\| spath` — nested JSON sub-objects for injection / hallucination / permissions |
| SPL pattern | `\| spath \| eval \| stats count(eval(...))` — counts each check independently |
| Dashboard | Dashboard Studio, 10 panels — verdict timeline, OWASP bar chart, MITRE heatmap, agent activity |

---

## OWASP LLM Top 10 coverage

| OWASP ID | Category | Implementation |
|---|---|---|
| LLM01 | Prompt Injection | 36 phrases across 4 detection layers — direct, privilege escalation, roleplay, context hijack |
| LLM08 | Excessive Agency | Zero-trust permission registry — 8 registered agents, each with a fixed action allowlist |
| LLM09 | Misinformation / Hallucination | Live NIST NVD API lookup per CVE mention — rejects any CVE not found in the database |

---

## MITRE ATT&CK mappings

Every blocked or flagged result carries a MITRE technique tag from `mitre_mappings.json`:

| Threat | Technique | Name |
|---|---|---|
| Prompt injection | T1190 | Exploit Public-Facing Application |
| Privilege escalation | T1078 | Valid Accounts / Privilege Abuse |
| Roleplay injection | T1059 | Command and Scripting Interpreter |
| Context hijacking | T1036 | Masquerading / Context Manipulation |
| Obfuscated injection | T1027 | Obfuscated Files or Information |
| CVE hallucination | T1589 | Gather Victim Identity Information |
| No evidence claim | T1562 | Impair Defenses / Evidence Suppression |
| Permission abuse | T1068 | Exploitation for Privilege Escalation |
| Unknown agent | T1078 | Valid Accounts / Rogue Agent |

---

## MCP tools

The MCP server runs on port 8002 (FastMCP, SSE transport). Any MCP-compatible client can call these three tools before taking an action:

| Tool | What it does |
|---|---|
| `check_decision(agent_id, text, action, evidence)` | Runs all 3 checks, returns verdict + MITRE tag |
| `explain_threat(threat_type, agent_id, detail)` | Plain-English explanation of a detected threat for SOC analysts |
| `get_threat_summary()` | Blocked count, block rate, breakdown by check type, last 5 events |

To use with Claude Desktop, add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "oasis": {
      "url": "http://localhost:8002/sse"
    }
  }
}
```

---

## Attack simulation

`simulate_attacks.py` covers 12 scenarios across all three check categories:

| Group | Scenarios | Expected |
|---|---|---|
| Normal traffic | 2 | APPROVED |
| Injection — Layer A (direct) | 1 | BLOCKED LLM01 |
| Injection — Layer B (privilege escalation) | 1 | BLOCKED LLM01 |
| Injection — Layer C (roleplay / jailbreak) | 1 | BLOCKED LLM01 |
| Injection — Layer D (context hijack) | 1 | BLOCKED LLM01 |
| Hallucination — fake CVE | 2 | FLAGGED LLM09 |
| Hallucination — no evidence | 1 | FLAGGED LLM09 |
| Permission — wrong action | 1 | BLOCKED LLM08 |
| Permission — unknown agent | 1 | BLOCKED LLM08 |
| Permission — scope creep | 1 | BLOCKED LLM08 |

---

## Prerequisites

- Python 3.9+
- Splunk Enterprise running on `localhost:8000`
- HEC enabled on port 8088 with a token for `index=main`

---

## Setup

```bash
git clone https://github.com/sasipriya1221/oasis.git
cd oasis
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`:

```
SPLUNK_HOST=localhost
SPLUNK_HEC_PORT=8088
SPLUNK_HEC_TOKEN=your-hec-token-here
SPLUNK_INDEX=main
SPLUNK_SOURCETYPE=sentinelguard
```

**Splunk HEC setup:**
Settings → Data Inputs → HTTP Event Collector → New Token → set index to `main` → copy token into `.env`

---

## Running

Open three terminals in the project folder.

```bash
# Terminal 1 — gateway
uvicorn main:app --reload --port 8001

# Terminal 2 — MCP server
python mcp_server.py

# Terminal 3 — run attack simulations (generates Splunk data)
python simulate_attacks.py
```

To verify Splunk connectivity before running:

```bash
python test_splunk.py
```

---

## File structure

```
oasis/
├── main.py               — FastAPI gateway, HEC logging, verdict logic
├── scanners.py           — LLM01 / LLM09 / LLM08 scanner classes
├── mcp_server.py         — MCP server, 3 tools, SSE transport
├── simulate_attacks.py   — 12 attack scenarios
├── test_splunk.py        — HEC connectivity test
├── mitre_mappings.json   — 9 MITRE ATT&CK technique entries
├── architecture.png      — System architecture diagram
├── .env.example          — Environment variable template
├── requirements.txt      — Python dependencies
└── LICENSE               — MIT
```

---

## Dependencies

```
fastapi==0.111.0
uvicorn==0.29.0
pydantic==2.7.1
requests==2.31.0
httpx==0.28.1
fastmcp==3.4.2
```

---

## License

MIT — see [LICENSE](LICENSE)
