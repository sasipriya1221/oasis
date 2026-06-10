# Oasis 🛡️

**One agent protects. One agent explains.**

Oasis is a Splunk-native agentic security system built for the Splunk Agentic Ops Hackathon 2026. It deploys two AI agents that work together to secure and explain every action taken inside a Splunk environment.

- **Aegis Guard** — intercepts every AI agent action before execution, running three OWASP LLM Top 10 security checks in under 200ms
- **Aegis Lens** — reads Splunk logs and explains every detected threat in plain English for SOC analysts, powered by Splunk's Foundation-sec AI model

---

## What it does

AI agents are being deployed inside enterprise Splunk environments to automate security responses, run SPL searches, and execute remediation playbooks. These agents are powerful — and completely ungoverned.

Oasis sits between every AI agent and your Splunk infrastructure. Before any agent action executes, Oasis checks:

1. **LLM01 — Prompt injection** — was the agent secretly given malicious instructions?
2. **LLM09 — Hallucinated CVEs** — is the agent acting on a fake vulnerability with a live NIST NVD lookup?
3. **LLM08 — Permission violations** — does the agent have the right to do what it's trying to do?

Every blocked event is tagged with a MITRE ATT&CK technique ID and explained in plain English by Splunk's Foundation-sec AI model. SOC analysts see everything in a real-time Dashboard Studio interface.

---

## Architecture

```
AI Agent / MCP Client
        ↓
Oasis Gateway (FastAPI · Port 8001)
        ↓
┌─────────────────────────────────────┐
│  Aegis Guard — 3 Security Scanners  │
│  LLM01 · LLM09 + NVD API · LLM08   │
│  MITRE ATT&CK Tagger · CVSS Scorer  │
└─────────────────────────────────────┘
        ↓
Splunk HEC (Port 8088) → index=main
        ↓
┌─────────────────────────────────────┐
│  Aegis Lens — Foundation-sec AI     │
│  Plain-English threat explanations  │
│  Dashboard Studio · 13 panels       │
└─────────────────────────────────────┘
        ↓
SOC Analyst Dashboard

MCP Server (Port 8002) ← External AI agents
```

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Gateway | Python 3.12, FastAPI, Uvicorn |
| Security checks | Custom scanners — LLM01, LLM08, LLM09 |
| Threat intelligence | NIST NVD CVE API 2.0 (live, no auth) |
| MITRE mapping | ATT&CK technique JSON (local) |
| MCP server | FastMCP — exposes 3 tools to any MCP client |
| Data platform | Splunk Enterprise 10.4 |
| Ingestion | Splunk HEC port 8088 |
| AI model | Foundation-sec-1.1-8b-instruct (Splunk hosted) |
| Dashboard | Splunk Dashboard Studio |
| Alerting | Splunk Alert actions → HITL queue |

---

## OWASP LLM Top 10 coverage

| OWASP ID | Threat | Oasis check |
|----------|--------|-------------|
| LLM01 | Prompt Injection | 4-layer regex + semantic pattern detection |
| LLM08 | Excessive Agency | Role-based permission enforcement matrix |
| LLM09 | Misinformation / Hallucination | Live NIST NVD CVE lookup — rejects fabricated CVE IDs |

---

## MITRE ATT&CK mappings

| Threat type | Technique ID | Name |
|-------------|-------------|------|
| Prompt injection | T1190 | Exploit Public-Facing Application |
| Privilege escalation | T1078 | Valid Accounts |
| Data exfiltration | T1041 | Exfiltration Over C2 Channel |
| CVE hallucination | T1589.002 | Gather Victim Host Info |
| Permission abuse | T1068 | Exploitation for Privilege Escalation |
| Instruction override | T1195 | Supply Chain Compromise |
| Jailbreak attempt | T1059 | Command and Scripting Interpreter |

---

## Prerequisites

- Python 3.12+
- Splunk Enterprise 10.4 running on `localhost:8000`
- Splunk HEC enabled on port 8088
- Splunk AI Toolkit 5.6.4+ installed from Splunkbase
- Foundation-sec connection configured in AI Toolkit (name: `sg_foundation_sec`)

---

## Installation

**1. Clone the repo**

```bash
git clone https://github.com/sasipriya1221/oasis.git
cd oasis
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Configure environment**

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Open `.env` and set your Splunk HEC token:

```
SPLUNK_HOST=localhost
SPLUNK_HEC_PORT=8088
SPLUNK_HEC_TOKEN=your-actual-hec-token
SPLUNK_INDEX=main
SPLUNK_SOURCETYPE=sentinelguard
```

**4. Splunk setup**

- Enable HEC: Settings → Data Inputs → HTTP Event Collector → Enable
- Create a HEC token with index=main
- Install AI Toolkit 5.6.4 from Splunkbase
- In AI Toolkit → Connection Management → Add Connection → Splunk Hosted Models → `foundation-sec-1.1-8b-instruct` → name it `sg_foundation_sec`

---

## Running Oasis

Open three PowerShell terminals in the `sg1` folder.

**Terminal 1 — Start the gateway**

```bash
uvicorn main:app --reload --port 8001
```

**Terminal 2 — Run attack simulations**

```bash
python simulate_attacks.py
```

**Terminal 3 — Start the MCP server**

```bash
python mcp_server.py
```

---

## MCP tools

Oasis exposes three MCP tools on port 8002. Any MCP-compatible AI client (Claude Desktop, Cursor, custom agents) can call these before taking any action:

| Tool | What it does |
|------|-------------|
| `check_decision` | Run all 3 security checks on an agent action. Returns verdict, severity, MITRE technique. |
| `explain_threat` | Generate a plain-English SOC analyst explanation for a blocked event. |
| `get_threat_summary` | Get a summary of all threats detected in the last N hours. |

**Claude Desktop config** (`~/.config/claude/claude_desktop_config.json`):

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

## Performance

Tested across 500 simulated attack requests:

| Metric | Result |
|--------|--------|
| Attack scenarios covered | 12 / 12 |
| Mean detection latency | ~150ms |
| False positives | 0 |
| Verdicts: BLOCK / WARN / ALLOW | ~75% / ~15% / ~10% |

---

## Splunk Dashboard

Oasis includes a 13-panel Dashboard Studio interface split into three rows:

- **Row 1 — Live overview:** Total requests, block rate %, critical event count, mean latency
- **Row 2 — Threat intelligence:** MITRE ATT&CK heatmap, OWASP breakdown, live CVE feed (CVSS ≥ 7.0), threat timeline
- **Row 3 — AI analyst tools:** Foundation-sec explanations, MCP agent call log, HITL approval queue, audit trail

---

## Hackathon tracks

This project targets five prize tracks in the Splunk Agentic Ops Hackathon 2026:

| Track | How Oasis qualifies |
|-------|-------------------|
| Grand Prize | Spans Security + Platform + AI. Uses all three special Splunk capabilities. Solves a novel enterprise problem. |
| Best of Security | OWASP LLM01/08/09 + MITRE ATT&CK + live NIST CVE intelligence + HITL SOC workflow |
| Best Use of Splunk MCP Server | Exposes own MCP server (port 8002) + connects to Splunk MCP Server app bidirectionally |
| Best Use of Splunk Hosted Models | Foundation-sec-1.1-8b-instruct via `\| ai` SPL command for live threat explanation |
| Best Use of Splunk Developer Tools | Dashboard Studio (13 panels), custom SPL, Splunk Alerts, AI Toolkit, HEC |

---

## Repo structure

```
oasis/
├── README.md
├── LICENSE
├── .env.example
├── .gitignore
├── requirements.txt
├── main.py              ← FastAPI gateway (port 8001)
├── mcp_server.py        ← MCP server (port 8002)
├── scanners.py          ← LLM01 + LLM09 + LLM08 scanners
├── simulate_attacks.py  ← 12 attack scenarios
├── test_splunk.py       ← Splunk connectivity test
└── mitre_mappings.json  ← MITRE ATT&CK technique mappings
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
