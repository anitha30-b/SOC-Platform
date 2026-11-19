import os
import time
import platform
import socket
import requests

API_URL = os.getenv("SOC_API_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_ID = os.getenv("SOC_AGENT_ID", "1")
AGENT_KEY = os.getenv("SOC_AGENT_KEY")

if not AGENT_KEY:
    raise SystemExit("Error: Set SOC_AGENT_KEY before running.")

payload = {
    "hostname": socket.gethostname(),
    "operating_system": platform.system() + " " + platform.release(),
    "agent_version": "1.0.0",
}

while True:
    try:
        response = requests.post(
            f"{API_URL}/agent-health/{AGENT_ID}/heartbeat",
            headers={"X-Agent-Key": AGENT_KEY},
            json=payload,
            timeout=10,
        )

        if response.ok:
            print("Heartbeat accepted:", response.json(), flush=True)
        else:
            print("Heartbeat failed:", response.status_code, response.text, flush=True)

    except requests.RequestException as exc:
        print("Connection error:", exc, flush=True)

    time.sleep(30)
