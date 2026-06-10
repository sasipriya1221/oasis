import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_URL = "https://localhost:8088/services/collector/event"
SPLUNK_TOKEN = "650b8078-2310-4ffb-bfd4-7d54c73599a2"
headers = {"Authorization": f"Splunk {SPLUNK_TOKEN}"}

print("Check 1 — Splunk UI reachable...")
try:
    r = requests.get("http://localhost:8000", timeout=3)
    print("  ✅ Splunk UI is up")
except:
    print("  ❌ Splunk UI not reachable")

print("Check 2 — HEC port open...")
try:
    r = requests.get("https://localhost:8088", timeout=3, verify=False)
    print("  ✅ HEC port 8088 is open")
except:
    print("  ❌ HEC port not reachable")

print("Check 3 — Sending test event...")
try:
    payload = {"event": {"source": "test", "message": "SentinelGuard HEC test"}, "sourcetype": "sentinelguard", "index": "main"}
    r = requests.post(SPLUNK_URL, headers=headers, json=payload, timeout=3, verify=False)
    if r.status_code == 200:
        print("  ✅ Event sent successfully!")
    else:
        print(f"  ❌ Failed: {r.status_code} — {r.text}")
except Exception as e:
    print(f"  ❌ Error: {e}")