"""
test_splunk.py — verify Splunk HEC and REST connectivity before running the demo.

Usage:
    python test_splunk.py
"""

import os
import json
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

SPLUNK_HOST      = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_HEC_PORT  = int(os.getenv("SPLUNK_HEC_PORT", "8088"))
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_REST_PORT = int(os.getenv("SPLUNK_REST_PORT", "8089"))
SPLUNK_REST_TOKEN = os.getenv("SPLUNK_REST_TOKEN", "")
SPLUNK_INDEX     = os.getenv("SPLUNK_INDEX", "main")
SPLUNK_SOURCETYPE = os.getenv("SPLUNK_SOURCETYPE", "sentinelguard")


def check_hec():
    print("1. Testing Splunk HEC (port 8088) ...")
    if not SPLUNK_HEC_TOKEN:
        print("   ❌ SPLUNK_HEC_TOKEN is not set in .env")
        return False
    try:
        r = requests.post(
            f"http://{SPLUNK_HOST}:{SPLUNK_HEC_PORT}/services/collector/event",
            headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
            json={"index": SPLUNK_INDEX, "sourcetype": SPLUNK_SOURCETYPE,
                  "event": {"test": "oasis_hec_connectivity_check"}},
            timeout=5,
            verify=False,
        )
        if r.status_code == 200:
            print(f"   ✅ HEC OK — {r.json()}")
            return True
        else:
            print(f"   ❌ HEC returned {r.status_code}: {r.text}")
            return False
    except Exception as e:
        print(f"   ❌ HEC unreachable: {e}")
        return False


def check_rest():
    print("2. Testing Splunk REST API (port 8089) ...")
    if not SPLUNK_REST_TOKEN:
        print("   ⚠️  SPLUNK_REST_TOKEN not set — skipping REST check")
        return False
    try:
        r = requests.get(
            f"https://{SPLUNK_HOST}:{SPLUNK_REST_PORT}/services/server/info",
            headers={"Authorization": f"Bearer {SPLUNK_REST_TOKEN}"},
            params={"output_mode": "json"},
            timeout=5,
            verify=False,
        )
        if r.status_code == 200:
            info = r.json()
            version = info.get("entry", [{}])[0].get("content", {}).get("version", "?")
            print(f"   ✅ REST OK — Splunk version {version}")
            return True
        else:
            print(f"   ❌ REST returned {r.status_code}: {r.text[:200]}")
            return False
    except Exception as e:
        print(f"   ❌ REST unreachable: {e}")
        return False


def check_mcp_server():
    print("3. Testing Splunk MCP Server app (port 8089/mcp) ...")
    if not SPLUNK_REST_TOKEN:
        print("   ⚠️  SPLUNK_REST_TOKEN not set — skipping MCP Server check")
        return False
    try:
        r = requests.get(
            f"https://{SPLUNK_HOST}:{SPLUNK_REST_PORT}"
            "/servicesNS/nobody/Splunk_MCP_Server/mcp/v1/tools/list",
            headers={"Authorization": f"Bearer {SPLUNK_REST_TOKEN}"},
            timeout=5,
            verify=False,
        )
        if r.status_code == 200:
            tools = r.json().get("result", {}).get("tools", [])
            names = [t.get("name") for t in tools]
            print(f"   ✅ Splunk MCP Server OK — tools: {names}")
            return True
        else:
            print(f"   ❌ Splunk MCP Server returned {r.status_code}")
            print("   Install: cp -r Splunk_MCP_Server $SPLUNK_HOME/etc/apps/")
            print("            $SPLUNK_HOME/bin/splunk restart")
            return False
    except Exception as e:
        print(f"   ❌ Splunk MCP Server unreachable: {e}")
        return False


if __name__ == "__main__":
    print("Oasis — Splunk Connectivity Test\n")
    hec  = check_hec()
    rest = check_rest()
    mcp  = check_mcp_server()
    print()
    if hec and rest and mcp:
        print("✅ All checks passed — ready to run demo.py")
    elif hec and rest:
        print("⚠️  HEC and REST OK, but Splunk MCP Server not found.")
        print("   Install it to enable Splunk AI (generate_spl / ask_splunk_question).")
    elif hec:
        print("⚠️  HEC OK — events will be logged, but REST/MCP features won't work.")
    else:
        print("❌ HEC failed — check SPLUNK_HEC_TOKEN and that Splunk is running.")
