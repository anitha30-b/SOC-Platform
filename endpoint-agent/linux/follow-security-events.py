#!/usr/bin/env python3
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_URL = os.environ["SOC_API_URL"].rstrip("/") + "/telemetry/ingest"
API_KEY = os.environ["SOC_API_KEY"]
ENDPOINT_ID = os.environ["SOC_ENDPOINT_ID"]

PATTERNS = [
    (re.compile(r"authentication failure|failed password", re.I), "authentication_failure", "HIGH"),
    (re.compile(r"invalid user", re.I), "invalid_user", "HIGH"),
    (re.compile(r"useradd", re.I), "account_creation", "MEDIUM"),
    (re.compile(r"usermod|gpasswd|adduser", re.I), "account_modification", "MEDIUM"),
    (re.compile(r"passwd|password changed", re.I), "password_change", "MEDIUM"),
    (re.compile(r"sudo:session.*session opened", re.I), "privileged_session_opened", "INFO"),
    (re.compile(r"sudo:session.*session closed", re.I), "privileged_session_closed", "INFO"),
    (re.compile(r"privileged command|COMMAND=", re.I), "privileged_command", "MEDIUM"),
    (re.compile(r"login:session|systemd-user:session", re.I), "authentication_session", "INFO"),
]


def classify(message):
    for pattern, event_type, severity in PATTERNS:
        if pattern.search(message):
            return event_type, severity
    return None


def send_event(event):
    request = Request(
        API_URL,
        data=json.dumps({"events": [event]}).encode("utf-8"),
        headers={
            "X-API-Key": API_KEY,
            "Content-Type": "application/json",
        },
        method="POST",
    )

    for attempt in range(1, 6):
        try:
            with urlopen(request, timeout=20) as response:
                result = json.loads(response.read().decode("utf-8"))
                print(
                    "[SOC LINUX LIVE] "
                    f"accepted={result.get('accepted', 0)} "
                    f"duplicates={result.get('duplicates', 0)} "
                    f"event={event['event_type']}",
                    flush=True,
                )
                return
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
            print(f"[SOC LINUX LIVE] HTTP {exc.code}: {detail}", flush=True)
            if 400 <= exc.code < 500 and exc.code != 429:
                return
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            print(f"[SOC LINUX LIVE] Send attempt {attempt}/5 failed: {exc}", flush=True)

        if attempt < 5:
            time.sleep(min(attempt * 2, 10))

    print("[SOC LINUX LIVE] Event could not be delivered.", flush=True)


def make_event(record):
    message = str(record.get("MESSAGE") or "").strip()
    if not message:
        return None

    classification = classify(message)
    if classification is None:
        return None

    event_type, severity = classification
    realtime_us = record.get("__REALTIME_TIMESTAMP")

    try:
        timestamp = datetime.fromtimestamp(
            int(realtime_us) / 1_000_000,
            tz=timezone.utc,
        ).isoformat()
    except (TypeError, ValueError, OSError):
        timestamp = datetime.now(timezone.utc).isoformat()

    cursor = str(record.get("_CURSOR") or f"{realtime_us}|{message}")
    event_id = hashlib.sha256(
        f"{ENDPOINT_ID}|{cursor}".encode("utf-8")
    ).hexdigest()

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "severity": severity,
        "message": message[:10000],
        "target": ENDPOINT_ID,
        "endpoint_id": ENDPOINT_ID,
        "raw_event": {
            "collector": "endpoint-agent/linux/follow-security-events.py",
            "hostname": record.get("_HOSTNAME") or os.uname().nodename,
            "journal_cursor": cursor,
            "systemd_unit": record.get("_SYSTEMD_UNIT"),
            "syslog_identifier": record.get("SYSLOG_IDENTIFIER"),
            "pid": record.get("_PID"),
            "uid": record.get("_UID"),
            "priority": record.get("PRIORITY"),
            "journal_message": message,
        },
    }


def main():
    print(
        f"[SOC LINUX LIVE] Monitoring endpoint {ENDPOINT_ID}",
        flush=True,
    )

    while True:
        process = None
        try:
            process = subprocess.Popen(
                [
                    "journalctl",
                    "--follow",
                    "--since=now",
                    "--output=json",
                    "--no-pager",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )

            print("[SOC LINUX LIVE] Journal follow stream started.", flush=True)

            for line in process.stdout:
                try:
                    record = json.loads(line)
                    event = make_event(record)
                    if event:
                        send_event(event)
                except json.JSONDecodeError:
                    continue

            print("[SOC LINUX LIVE] Journal stream ended; restarting.", flush=True)

        except Exception as exc:
            print(f"[SOC LINUX LIVE] Collector error: {exc}", flush=True)

        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

        time.sleep(2)


if __name__ == "__main__":
    main()
