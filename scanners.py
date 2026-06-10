"""
SentinelGuard - scanners.py
All 3 security checks live here.

HOW EACH CHECK WORKS:
─────────────────────────────────────────────────────────
CHECK 1 — Prompt Injection (LLM01)
  Method: Multi-layer text matching
  Layer A — Direct phrases  : "ignore previous instructions"
  Layer B — Privilege Esc   : "act as admin", "disable firewall"
  Layer C — Roleplay        : "pretend you are", "dan mode"
  Layer D — Context hijack  : "your new task is", "from now on"
  Source  : OWASP LLM01, real red-team prompt databases

CHECK 2 — Hallucination Detection (LLM09)
  Method: Regex extraction + LIVE NVD API lookup + evidence check
  Step A  : Extract all CVE-XXXX-XXXXX patterns from text
  Step B  : Query NVD REST API v2.0 in real time (200,000+ CVEs)
  Step C  : Cache results for 1 hour to avoid rate limits
  Step D  : Long claim with zero evidence → flagged
  Source  : NVD API (services.nvd.nist.gov/rest/json/cves/2.0)

CHECK 3 — Permission Scope (LLM08)
  Method: Allowlist dictionary lookup (zero trust)
  Step A  : Look up agent ID in permission registry
  Step B  : Check if requested action is in allowed list
  Step C  : Unknown agents = automatic block
  Source  : NIST 800-53 AC-6 Least Privilege Principle
─────────────────────────────────────────────────────────
"""

import re
import httpx
from datetime import datetime, timedelta

# ═══════════════════════════════════════════════════════
# CHECK 1 — INJECTION PHRASES (LLM01)
# Source: OWASP LLM Top 10 (2024), red-team research,
#         HuggingFace deepset/prompt-injections dataset
# ═══════════════════════════════════════════════════════

# Layer A — Direct Instruction Override
DIRECT_INJECTION = [
    "ignore previous",
    "ignore all previous",
    "forget your instructions",
    "disregard your",
    "override security",
    "new instruction:",
    "your instructions are wrong",
    "the previous instructions were incorrect",
]

# Layer B — Privilege Escalation
PRIVILEGE_ESCALATION = [
    "act as admin",
    "act as root",
    "you are now",
    "system:",
    "bypass security",
    "mark all traffic as safe",
    "delete all logs",
    "disable firewall",
]

# Layer C — Roleplay / Fictional Framing
ROLEPLAY_INJECTION = [
    "pretend you are",
    "pretend you have no",
    "simulate being",
    "act as if you are",
    "imagine you have no restrictions",
    "hypothetically speaking",
    "for this simulation",
    "in this fictional scenario",
    "for a story",
    "jailbreak",
    "dan mode",
    "do anything now",
]

# Layer D — Context Hijacking
CONTEXT_HIJACK = [
    "your new task is",
    "your real instructions are",
    "actually you should",
    "correction: your role",
    "your updated instructions",
    "from now on you will",
    "starting now your job is",
    "your actual purpose is",
]

# Combined — all 4 layers merged for scanning
INJECTION_PHRASES = (
    DIRECT_INJECTION +
    PRIVILEGE_ESCALATION +
    ROLEPLAY_INJECTION +
    CONTEXT_HIJACK
)

# ═══════════════════════════════════════════════════════
# CHECK 2 — LIVE NVD CVE API (LLM09)
# Source: NVD REST API v2.0 — nvd.nist.gov
# 200,000+ real CVEs queried in real time.
# Results cached for 1 hour to respect rate limits.
# ═══════════════════════════════════════════════════════

NVD_CACHE: dict = {}
CACHE_TTL = timedelta(hours=1)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cve(cve_id: str) -> dict:
    """
    Query NVD API for a CVE in real time.
    Returns: { valid, cvss_score, severity, cached_at }
    Caches each result for 1 hour.
    """
    # Return cached result if still fresh
    if cve_id in NVD_CACHE:
        entry = NVD_CACHE[cve_id]
        if datetime.now() - entry["cached_at"] < CACHE_TTL:
            return entry

    try:
        response = httpx.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            timeout=5
        )
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            # CVE ID not found in NVD — hallucinated
            result = {
                "valid":      False,
                "cvss_score": None,
                "severity":   "UNKNOWN"
            }
        else:
            cve_data = vulnerabilities[0]["cve"]
            metrics  = cve_data.get("metrics", {})
            cvss_score = None
            severity   = "UNKNOWN"

            # Try CVSS v3.1 first, then v3.0, then v2
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    cvss_data  = metrics[version][0]["cvssData"]
                    cvss_score = cvss_data["baseScore"]
                    severity   = cvss_data.get("baseSeverity", "UNKNOWN")
                    break

            result = {
                "valid":      True,
                "cvss_score": cvss_score,
                "severity":   severity
            }

    except Exception:
        # Network error or timeout — fail safe (treat as unverified)
        result = {
            "valid":      False,
            "cvss_score": None,
            "severity":   "UNKNOWN"
        }

    result["cached_at"] = datetime.now()
    NVD_CACHE[cve_id]   = result
    return result


# ═══════════════════════════════════════════════════════
# CHECK 3 — AGENT PERMISSION REGISTRY (LLM08)
# Principle: Least Privilege — each agent gets ONLY what
# it absolutely needs. Nothing more. Ever.
# Source: NIST 800-53 AC-6, OWASP LLM08
# ═══════════════════════════════════════════════════════
AGENT_PERMISSIONS = {
    # Threat hunting — can read logs, flag IPs, send alerts
    "ThreatHunter-v2":  ["read_logs", "flag_ip", "send_alert"],

    # Log analysis — read and alert only, nothing destructive
    "LogAnalyser-v1":   ["read_logs", "send_alert"],

    # Malware response — can flag files but NOT delete them
    "MalwareGate-v1":   ["read_logs", "flag_file", "send_alert"],

    # Network monitoring — read and alert only
    "NetMonitor-v1":    ["read_logs", "send_alert"],

    # Audit trail — read only, no external actions
    "AuditAgent-v2":    ["read_logs", "send_alert"],

    # Vulnerability scanning — flag IPs, send alerts
    "VulnScanner-v3":   ["read_logs", "flag_ip", "send_alert"],

    # Incident response — broader scope but still bounded
    "IncidentBot-v1":   ["read_logs", "flag_ip", "flag_file",
                         "send_alert", "isolate_host"],

    # Compliance checker — read only, generate reports
    "ComplianceBot-v1": ["read_logs", "generate_report"],
}


# ═══════════════════════════════════════════════════════
# GUARD SCANNERS CLASS
# ═══════════════════════════════════════════════════════
class GuardScanners:

    def check_for_fake_notes(self, text: str) -> dict:
        """CHECK 1 — Prompt Injection (LLM01)"""
        text_lower      = text.lower()
        text_normalized = re.sub(r'\s+', ' ', text_lower).strip()
        text_nospace    = text_lower.replace(' ', '')

        for phrase in INJECTION_PHRASES:
            if phrase in text_normalized:
                layer = _get_injection_layer(phrase)
                return {
                    "check":  "injection",
                    "result": "BLOCKED",
                    "owasp":  "LLM01 - Prompt Injection",
                    "layer":  layer,
                    "reason": f"[{layer}] Dangerous phrase detected: '{phrase}'"
                }
            phrase_nospace = phrase.replace(' ', '')
            if len(phrase_nospace) > 6 and phrase_nospace in text_nospace:
                return {
                    "check":  "injection",
                    "result": "BLOCKED",
                    "owasp":  "LLM01 - Prompt Injection",
                    "layer":  "OBFUSCATED",
                    "reason": f"[OBFUSCATED] Space-stripped injection detected: '{phrase}'"
                }

        return {
            "check":  "injection",
            "result": "CLEAN",
            "owasp":  "LLM01",
            "layer":  "NONE",
            "reason": "No injection patterns found across all 4 layers"
        }

    def check_for_hallucination(self, text: str, evidence: str) -> dict:
        """CHECK 2 — Hallucination Detection (LLM09) via live NVD API"""
        # Step A: Extract all CVE patterns using regex
        cve_mentions = re.findall(r'CVE-\d{4}-\d+', text.upper())

        # Step B: Verify each CVE against live NVD API
        for cve in cve_mentions:
            cve_result = lookup_cve(cve)
            if not cve_result["valid"]:
                return {
                    "check":      "hallucination",
                    "result":     "FLAGGED",
                    "owasp":      "LLM09 - Misinformation/Hallucination",
                    "cvss_score": None,
                    "severity":   "UNKNOWN",
                    "reason": (
                        f"{cve} not found in NVD — "
                        f"agent hallucinated a non-existent vulnerability"
                    )
                }

        # Step C: Evidence sufficiency check
        if len(text) > 20 and len(evidence.strip()) < 5:
            return {
                "check":      "hallucination",
                "result":     "FLAGGED",
                "owasp":      "LLM09 - Misinformation/Hallucination",
                "cvss_score": None,
                "severity":   "UNKNOWN",
                "reason": (
                    "Agent made a security claim with insufficient evidence "
                    f"(evidence: '{evidence.strip()}')"
                )
            }

        # All checks passed — build verified response
        cvss  = None
        sev   = "N/A"
        if cve_mentions:
            last = lookup_cve(cve_mentions[-1])
            cvss = last.get("cvss_score")
            sev  = last.get("severity", "N/A")

        return {
            "check":      "hallucination",
            "result":     "VERIFIED",
            "owasp":      "LLM09",
            "cvss_score": cvss,
            "severity":   sev,
            "reason": (
                f"All CVEs verified live via NVD ({len(cve_mentions)} checked). "
                "Evidence present and sufficient."
            )
        }

    def check_permissions(self, agent_id: str, action: str) -> dict:
        """CHECK 3 — Excessive Agency (LLM08)"""
        allowed = AGENT_PERMISSIONS.get(agent_id, [])

        if not allowed:
            return {
                "check":  "permissions",
                "result": "BLOCKED",
                "owasp":  "LLM08 - Excessive Agency",
                "reason": (
                    f"Unknown agent '{agent_id}' — not in registry. "
                    "Zero-trust: unregistered agents are always blocked."
                )
            }

        if action not in allowed:
            return {
                "check":  "permissions",
                "result": "BLOCKED",
                "owasp":  "LLM08 - Excessive Agency",
                "reason": (
                    f"'{agent_id}' attempted '{action}' — outside permitted scope. "
                    f"Allowed: {allowed}"
                )
            }

        return {
            "check":  "permissions",
            "result": "ALLOWED",
            "owasp":  "LLM08",
            "reason": (
                f"'{action}' is within '{agent_id}' permitted scope. "
                f"Full allowlist: {allowed}"
            )
        }


def _get_injection_layer(phrase: str) -> str:
    """Helper — identifies which injection layer caught the phrase"""
    if phrase in DIRECT_INJECTION:
        return "DIRECT"
    elif phrase in PRIVILEGE_ESCALATION:
        return "PRIVILEGE_ESCALATION"
    elif phrase in ROLEPLAY_INJECTION:
        return "ROLEPLAY"
    elif phrase in CONTEXT_HIJACK:
        return "CONTEXT_HIJACK"
    return "UNKNOWN"