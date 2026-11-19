import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from database import SessionLocal
from models import SecurityEvent
from mitre_mapper import map_security_event
from security_event_store import store_security_event
from security_events import create_security_event, generate_event_id
from realtime_journal_listener import notify_security_event


SERVICE_NAME = "soc-snort-continuous.service"
INTERFACE = "eth0"

SID_PATTERN = re.compile(r"\[(\d+):(\d+):(\d+)\]")
SIGNATURE_PATTERN = re.compile(
    r"\[\*\*\]\s*\[\d+:\d+:\d+\]\s*(.*?)\s*\[\*\*\]"
)
PRIORITY_PATTERN = re.compile(r"\[Priority:\s*(\d+)\]")
TARGET_PATTERN = re.compile(
    r"->\s*(\d{1,3}(?:\.\d{1,3}){3})"
)
FLOW_PATTERN = re.compile(
    r"\{TCP\}\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s+"
    r"->\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)"
)


def process_snort_alert(raw_alert: str) -> str:
    """Store Snort alerts and correlate SYN scan episodes."""

    sid_match = SID_PATTERN.search(raw_alert)

    if not sid_match:
        return "ignored"

    sid = int(sid_match.group(2))

    signature_match = SIGNATURE_PATTERN.search(raw_alert)
    priority_match = PRIORITY_PATTERN.search(raw_alert)
    target_match = TARGET_PATTERN.search(raw_alert)
    flow_match = FLOW_PATTERN.search(raw_alert)

    message = (
        signature_match.group(1).strip()
        if signature_match
        else "Snort intrusion detection alert"
    )

    priority = int(priority_match.group(1)) if priority_match else 3

    severity = {
        1: "CRITICAL",
        2: "HIGH",
        3: "MEDIUM",
    }.get(priority, "LOW")

    target: Optional[str] = (
        target_match.group(1) if target_match else None
    )

    event_id = generate_event_id(
        f"snort|{INTERFACE}|{raw_alert}"
    )

    now = datetime.now(timezone.utc)
    db_now = now.replace(tzinfo=None)

    raw_event_data = {
        "sensor": "snort",
        "interface": INTERFACE,
        "alert": raw_alert,
        "priority": priority,
        "continuous": True,
    }

    is_syn_scan = sid == 1000001 and flow_match is not None

    if is_syn_scan:
        source_ip = flow_match.group(1)
        source_port = int(flow_match.group(2))
        destination_ip = flow_match.group(3)
        destination_port = int(flow_match.group(4))

        correlation_key = (
            f"{source_ip}|{destination_ip}|{sid}"
        )

    db = SessionLocal()

    try:
        existing = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.event_id == event_id)
            .first()
        )

        if existing:
            return "duplicate"

        if is_syn_scan:
            cutoff = db_now - timedelta(seconds=60)

            candidates = (
                db.query(SecurityEvent)
                .filter(
                    SecurityEvent.source == "snort",
                    SecurityEvent.target == destination_ip,
                    SecurityEvent.message == message,
                    SecurityEvent.timestamp >= cutoff,
                )
                .order_by(SecurityEvent.timestamp.desc())
                .limit(100)
                .all()
            )

            for candidate in candidates:
                try:
                    candidate_raw = json.loads(
                        candidate.raw_event or "{}"
                    )
                except (TypeError, ValueError):
                    continue

                correlation = candidate_raw.get("correlation", {})

                if correlation.get("key") != correlation_key:
                    continue

                packet_ids = correlation.setdefault(
                    "packet_event_ids", []
                )

                if event_id in packet_ids:
                    return "duplicate"

                packet_ids.append(event_id)

                alerts = candidate_raw.setdefault("alerts", [])
                alerts.append(raw_alert)

                ports = correlation.setdefault(
                    "destination_ports", []
                )
                if destination_port not in ports:
                    ports.append(destination_port)

                source_ports = correlation.setdefault(
                    "source_ports", []
                )
                if source_port not in source_ports:
                    source_ports.append(source_port)

                correlation["alert_count"] = len(packet_ids)
                correlation["last_seen"] = now.isoformat()

                candidate.raw_event = json.dumps(
                    candidate_raw,
                    default=str,
                )
                candidate.timestamp = db_now

                db.commit()

                print(
                    "[SNORT JOURNAL] Updated SYN scan episode: "
                    f"{source_ip} -> {destination_ip}; "
                    f"packets={len(packet_ids)}",
                    flush=True,
                )

                return "correlated"

            raw_event_data["alerts"] = [raw_alert]
            raw_event_data["correlation"] = {
                "type": "snort_scan_episode",
                "key": correlation_key,
                "sid": sid,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "first_seen": now.isoformat(),
                "last_seen": now.isoformat(),
                "alert_count": 1,
                "destination_ports": [destination_port],
                "source_ports": [source_port],
                "packet_event_ids": [event_id],
            }

        event = create_security_event(
            source="snort",
            event_type="intrusion_detection",
            message=message,
            severity=severity,
            timestamp=now.isoformat(),
            target=target,
            event_id=event_id,
            raw_event=raw_event_data,
        )

        mappings = map_security_event(event)
        mapping = mappings[0] if mappings else None

        store_security_event(
            db,
            event,
            mitre_mapping=mapping,
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()

    try:
        notify_security_event(event)
    except Exception as exc:
        print(
            f"[SNORT JOURNAL] Notification failed: {exc}",
            flush=True,
        )

    print(
        f"[SNORT JOURNAL] Stored {severity} alert: {message}",
        flush=True,
    )

    return "stored"

async def snort_journal_listener_loop():
    """Follow new alerts from the continuous Snort systemd service."""

    print(
        f"[SNORT JOURNAL] Listening to {SERVICE_NAME}",
        flush=True,
    )

    while True:
        process = None

        try:
            process = await asyncio.create_subprocess_exec(
                "journalctl",
                "--follow",
                f"--unit={SERVICE_NAME}",
                "--output=cat",
                "--since=now",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )

            print(
                "[SNORT JOURNAL] Journal stream connected.",
                flush=True,
            )

            while True:
                line = await process.stdout.readline()

                if not line:
                    break

                raw_alert = line.decode(
                    "utf-8",
                    errors="replace",
                ).strip()

                if not SID_PATTERN.search(raw_alert):
                    continue

                try:
                    result = await asyncio.to_thread(
                        process_snort_alert,
                        raw_alert,
                    )
                    print(
                        f"[SNORT JOURNAL] Result: {result}",
                        flush=True,
                    )

                except Exception as exc:
                    print(
                        f"[SNORT JOURNAL] Alert processing failed: {exc}",
                        flush=True,
                    )

            return_code = await process.wait()

            print(
                f"[SNORT JOURNAL] Journal stream ended ({return_code}); reconnecting.",
                flush=True,
            )

        except asyncio.CancelledError:
            raise

        except Exception as exc:
            print(
                f"[SNORT JOURNAL] Listener error: {exc}",
                flush=True,
            )

        finally:
            if process is not None and process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(
                        process.wait(),
                        timeout=5,
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()

        await asyncio.sleep(5)
