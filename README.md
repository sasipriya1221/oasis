# Oasis
**One agent protects. One agent explains.**

Oasis is a runtime security gateway for AI agents built for the **Splunk Agentic Ops Hackathon 2026**. It intercepts every agent action before execution, runs three parallel OWASP LLM Top 10 checks, logs structured verdicts to Splunk, and exposes those checks as MCP tools so any LLM can query them directly.

---

## The problem

AI agents running inside enterprise environments — issuing alerts, isolating hosts, flagging vulnerabilities — have no runtime guardrail layer. An agent can be injected with malicious instructions, act on a CVE that doesn't exist, or attempt an action it was never authorized to perform. None of this shows up in your SIEM until after the damage is done.

Oasis puts a security checkpoint in front of every agent action, **before it executes**.

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

![Architecture](architecture.png)

```
AI Agents (ThreatHunter-v2, NetMonitor-v1, LogAnalyser-v1 ...)
        |
        | POST /check_decision
        v
┌──────────────────────────────────────────────────────────┐
│          Oasis Gateway — FastAPI · port 8001             │
│                                                          │
│  Agent 1 — The Protector                                 │
│  ├── [LLM01] Injection Scanner   (4 layers, obfuscation) │
│  ├── [LLM09] Hallucination Det.  (live NVD API · 1h cache│
│  └── [LLM08] Permissions Enforcer(zero-trust allowlist)  │
└──────────────────────────────────────────────────────────┘
        |
        | BLOCKED / APPROVED + MITRE tag
        |
        ├──→  Splunk HEC · port 8088  →  index=main  sourcetype=sentinelguard
        │            |
        │            └──→  Dashboard Studio · 10 panels
        │
        └──→  Oasis MCP Server · port 8002 (FastMCP + SSE)
                  |
                  ├── check_decision
                  ├── explain_threat             ← Agent 2: The Explainer
                  ├── get_threat_summary
                  └── analyze_threat_with_splunk_ai
                            |
                            ↓  calls at runtime via splunk_mcp_client.py
                  ┌─────────────────────────────────┐
                  │  Splunk MCP Server · port 8089  │
                  │  ├── generate_spl    (Splunk AI) │
                  │  ├── ask_splunk_question (AI)    │
                  │  └── search_splunk              │
                  └─────────────────────────────────┘
                            |
                            ↓
                  Splunk REST API → live index data
```

---

## Splunk AI Integration (runtime)

This is what makes Oasis use **Splunk AI at runtime**, satisfying the hackathon requirement.

### Tools called at runtime via `splunk_mcp_client.py`

| Splunk AI Tool | Called from | What it does |
|---|---|---|
| `generate_spl` | `explain_threat`, `analyze_threat_with_splunk_ai` | Converts a natural-language threat description into SPL using Splunk AI |
| `ask_splunk_question` | `explain_threat`, `analyze_threat_with_splunk_ai` | Returns a plain-English explanation of threat patterns from live Splunk data |
| `search_splunk` | `get_threat_summary`, `demo.py` | Runs SPL against the live index and returns results |

### How it works (step by step)

When `explain_threat(threat_type="prompt_injection", agent_id="ThreatHunter-v2")` is called:

1. Oasis builds a natural-language prompt: *"Show me all prompt_injection events for agent ThreatHunter-v2 from index=main sourcetype=sentinelguard in the last 24 hours, grouped by MITRE technique"*
2. Calls **`generate_spl`** on the Splunk MCP Server — Splunk AI returns an SPL string
3. Executes that AI-generated SPL against Splunk REST API
4. Calls **`ask_splunk_question`** — Splunk AI returns a plain-English explanation of the findings
5. Returns the AI-generated SPL, search results, and AI explanation to the calling agent

### Installing Splunk MCP Server

```bash
cp -r Splunk_MCP_Server $SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/bin/splunk restart

# Verify the MCP endpoint is live
curl -k -H "Authorization: Bearer $SPLUNK_REST_TOKEN" \
     https://localhost:8089/servicesNS/nobody/Splunk_MCP_Server/mcp/v1/tools/list
```

---

## Splunk integration

| What | How |
|---|---|
| Ingestion | Splunk HEC POST `:8088/services/collector/event` |
| Index | `index=main` `sourcetype=sentinelguard` |
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

The MCP server runs on port 8002 (FastMCP, SSE transport). Any MCP-compatible client can call these four tools:

| Tool | What it does |
|---|---|
| `check_decision(agent_id, text, action, evidence)` | Runs all 3 checks, returns verdict + MITRE tag |
| `explain_threat(threat_type, agent_id, detail)` | **Calls Splunk AI at runtime** — generates SPL, runs it, returns AI explanation |
| `get_threat_summary()` | Blocked count, block rate, breakdown by check type, last 5 events |
| `analyze_threat_with_splunk_ai(threat_type, agent_id, time_range)` | Explicit Splunk AI call — invokes `generate_spl` + `ask_splunk_question` at runtime |

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
- Splunk REST API accessible on port 8089
- `Splunk_MCP_Server` app installed in `$SPLUNK_HOME/etc/apps/`

---

## Setup

```bash
git clone https://github.com/sasipriya1221/oasis.git
cd oasis
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`:

```env
SPLUNK_HOST=localhost
SPLUNK_HEC_PORT=8088
SPLUNK_HEC_TOKEN=your-hec-token-here
SPLUNK_INDEX=main
SPLUNK_SOURCETYPE=sentinelguard

SPLUNK_REST_PORT=8089
SPLUNK_REST_TOKEN=your-splunk-rest-bearer-token-here
```

**Splunk HEC setup:** Settings → Data Inputs → HTTP Event Collector → New Token → set index to `main` → copy token into `.env`

**Splunk REST token:** Settings → Tokens → New Token

**Install Splunk MCP Server:**
```bash
cp -r Splunk_MCP_Server $SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/bin/splunk restart
```

---

## Running

```bash
# Terminal 1 — gateway (Agent 1: The Protector)
uvicorn main:app --reload --port 8001

# Terminal 2 — MCP server (Agent 2: The Explainer)
python mcp_server.py

# Terminal 3 — populate Splunk with attack data
python simulate_attacks.py

# Terminal 4 — run the end-to-end demo
python demo.py --agent ThreatHunter-v2
```

Verify Splunk connectivity before running:

```bash
python test_splunk.py
```

---

## File structure

```
oasis/
├── main.py                 — FastAPI gateway, HEC logging, verdict logic
├── scanners.py             — LLM01 / LLM09 / LLM08 scanner classes
├── mcp_server.py           — MCP server, 4 tools, Splunk AI integration
├── splunk_mcp_client.py    — MCP client connecting to Splunk MCP Server
├── demo.py                 — End-to-end demo, 5 labelled steps for judges
├── simulate_attacks.py     — 12 attack scenarios
├── test_splunk.py          — HEC + REST + MCP Server connectivity test
├── mitre_mappings.json     — 9 MITRE ATT&CK technique entries
├── architecture.png        — System architecture diagram
├── .env.example            — Environment variable template
├── requirements.txt        — Python dependencies
└── LICENSE                 — MIT
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
python-dotenv==1.0.1
```

---

## License

MIT — see LICENSE
