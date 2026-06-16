"""
SplunkMCPClient — connects to the official Splunk MCP Server app
and calls its tools: search_splunk, generate_spl, ask_splunk_question.

This is what makes Oasis use the Splunk MCP Server as a first-class
dependency — not raw REST calls, not stubs.

Install the Splunk MCP Server app first:
    cp -r Splunk_MCP_Server $SPLUNK_HOME/etc/apps/
    $SPLUNK_HOME/bin/splunk restart
    curl -k -H "Authorization: Bearer $SPLUNK_REST_TOKEN" \
         https://localhost:8089/servicesNS/nobody/Splunk_MCP_Server/mcp/v1/tools/list
"""

import os
import json
import httpx
from dotenv import load_dotenv

load_dotenv()

SPLUNK_HOST       = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_REST_PORT  = int(os.getenv("SPLUNK_REST_PORT", "8089"))
SPLUNK_REST_TOKEN = os.getenv("SPLUNK_REST_TOKEN", "")
SPLUNK_REST_USER  = os.getenv("SPLUNK_REST_USER", "admin")
SPLUNK_REST_PASSWORD = os.getenv("SPLUNK_REST_PASSWORD", "")

MCP_BASE = (
    f"https://{SPLUNK_HOST}:{SPLUNK_REST_PORT}"
    "/servicesNS/nobody/Splunk_MCP_Server/mcp/v1"
)


class SplunkMCPClient:
    """
    Thin client that speaks the Splunk MCP Server REST protocol.
    Every public method maps to one tool exposed by the Splunk MCP Server.
    """

    def __init__(self):
        if SPLUNK_REST_TOKEN:
            self._headers = {
                "Authorization": f"Bearer {SPLUNK_REST_TOKEN}",
                "Content-Type": "application/json",
            }
        else:
            import base64
            creds = base64.b64encode(
                f"{SPLUNK_REST_USER}:{SPLUNK_REST_PASSWORD}".encode()
            ).decode()
            self._headers = {
                "Authorization": f"Basic {creds}",
                "Content-Type": "application/json",
            }

    async def _call_tool(self, tool_name: str, arguments: dict) -> str:
        """POST to Splunk MCP Server and extract the text result."""
        payload = {
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            r = await client.post(
                f"{MCP_BASE}/messages",
                headers=self._headers,
                json=payload,
            )
            r.raise_for_status()
            data = r.json()

        content = data.get("result", {}).get("content", [])
        for block in content:
            if block.get("type") == "text":
                return block["text"]
        return ""

    async def list_tools(self) -> list:
        """GET /mcp/v1/tools/list — confirm Splunk MCP Server is running."""
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            r = await client.get(f"{MCP_BASE}/tools/list", headers=self._headers)
            r.raise_for_status()
            data = r.json()
        return data.get("result", {}).get("tools", [])

    async def search_splunk(self, query: str, earliest: str = "-24h") -> str:
        """Call Splunk MCP Server's search_splunk tool — runs SPL, returns results."""
        return await self._call_tool(
            "search_splunk", {"query": query, "earliest_time": earliest}
        )

    async def generate_spl(self, prompt: str) -> str:
        """
        Call Splunk MCP Server's generate_spl tool (Splunk AI).
        Converts natural language into SPL at runtime.
        """
        return await self._call_tool("generate_spl", {"prompt": prompt})

    async def ask_splunk_question(self, question: str) -> str:
        """
        Call Splunk MCP Server's ask_splunk_question tool (Splunk AI).
        Returns a plain-English answer from Splunk AI.
        """
        return await self._call_tool("ask_splunk_question", {"question": question})
