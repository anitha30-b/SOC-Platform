
import asyncio
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

import requests
from sqlalchemy.orm import Session

from database import SessionLocal
from models import SIEMIntegration, SIEMIngestionState, SecurityEvent
from security_event_store import store_security_event
from security_events import create_security_event, generate_event_id
from siem_integrations_router import decrypt_credentials
from realtime_journal_listener import notify_security_event


POLL_SECONDS = max(30, int(os.getenv("SIEM_INGESTION_INTERVAL", "60")))
OVERLAP_SECONDS = max(0, int(os.getenv("SIEM_INGESTION_OVERLAP", "120")))
BATCH_SIZE = min(1000, max(1, int(os.getenv("SIEM_INGESTION_BATCH_SIZE", "500"))))
REQUEST_TIMEOUT = 30


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso_utc(value):
    return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value):
    if not value:
        return utc_now()

    try:
        if isinstance(value, (int, float)):
            # Elastic/Splunk epoch timestamps.
            if value > 10_000_000_000:
                value = value / 1000
            return datetime.fromtimestamp(value, timezone.utc).replace(tzinfo=None)

        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except (ValueError, TypeError, OverflowError):
        return utc_now()


def get_auth(provider, credentials):
    headers = {}
    auth = None

    if provider == "splunk":
        if credentials.get("token"):
            headers["Authorization"] = "Bearer " + credentials["token"]
        else:
            auth = (credentials["username"], credentials["password"])

    elif provider == "elastic":
        if credentials.get("api_key"):
            headers["Authorization"] = "ApiKey " + credentials["api_key"]
        else:
            auth = (credentials["username"], credentials["password"])

    return headers, auth


def fetch_splunk(item, credentials, start, end):
    endpoint = item.base_url.rstrip("/") + "/services/search/jobs/export"
    headers, auth = get_auth("splunk", credentials)

    response = requests.post(
        endpoint,
        headers=headers,
        auth=auth,
        data={
            "search": "search index=*",
            "earliest_time": iso_utc(start),
            "latest_time": iso_utc(end),
            "output_mode": "json",
            "count": BATCH_SIZE,
        },
        timeout=REQUEST_TIMEOUT,
        verify=True,
        allow_redirects=False,
        stream=True,
    )

    if response.is_redirect:
        raise RuntimeError("Splunk returned a redirect.")
    response.raise_for_status()

    events = []
    try:
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                payload = json.loads(line)
            except (ValueError, TypeError):
                continue

            result = payload.get("result")
            if isinstance(result, dict):
                events.append(result)
            elif isinstance(payload, dict) and not payload.get("preview"):
                events.append(payload)
            if len(events) >= BATCH_SIZE:
                break
    finally:
        response.close()

    return events


def fetch_elastic(item, credentials, start, end):
    index = str(
        credentials.get("index")
        or os.getenv("SIEM_ELASTIC_INDEX_PATTERN", "logs-*")
    ).strip()

    if not re.fullmatch(r"[A-Za-z0-9_.*,-]+", index):
        raise RuntimeError("Invalid Elastic index pattern.")

    endpoint = item.base_url.rstrip("/") + "/" + index + "/_search"
    headers, auth = get_auth("elastic", credentials)
    headers["Content-Type"] = "application/json"

    query = {
        "size": BATCH_SIZE,
        "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
        "query": {
            "range": {
                "@timestamp": {
                    "gte": iso_utc(start),
                    "lte": iso_utc(end),
                }
            }
        },
    }

    response = requests.post(
        endpoint,
        headers=headers,
        auth=auth,
        json=query,
        timeout=REQUEST_TIMEOUT,
        verify=True,
        allow_redirects=False,
    )

    if response.is_redirect:
        raise RuntimeError("Elastic returned a redirect.")
    response.raise_for_status()

    payload = response.json()
    hits = payload.get("hits", {}).get("hits", [])
    return [
        hit.get("_source", {})
        for hit in hits
        if isinstance(hit.get("_source"), dict)
    ]


def normalize_external_event(raw, item):
    event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
    log = raw.get("log") if isinstance(raw.get("log"), dict) else {}
    host = raw.get("host") if isinstance(raw.get("host"), dict) else {}
    source_data = raw.get("source") if isinstance(raw.get("source"), dict) else {}
    destination = raw.get("destination") if isinstance(raw.get("destination"), dict) else {}
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}

    severity_value = (
        event.get("severity")
        or raw.get("severity")
        or log.get("level")
        or raw.get("level")
        or "INFO"
    )
    severity_text = str(severity_value).upper()

    severity_map = {
        "0": "CRITICAL", "1": "CRITICAL",
        "2": "HIGH", "3": "HIGH",
        "4": "MEDIUM", "5": "LOW",
        "6": "INFO", "7": "INFO",
        "DEBUG": "INFO", "INFORMATIONAL": "INFO",
        "WARNING": "MEDIUM", "WARN": "MEDIUM",
        "ERROR": "HIGH", "FATAL": "CRITICAL",
    }
    severity = severity_map.get(severity_text, severity_text)
    if severity not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        severity = "INFO"

    message = (
        raw.get("message")
        or raw.get("event.original")
        or log.get("original")
        or rule.get("name")
        or event.get("action")
        or "External SIEM event"
    )

    target = (
        host.get("name")
        or host.get("hostname")
        or raw.get("host")
        or destination.get("ip")
        or source_data.get("ip")
    )
    if isinstance(target, dict):
        target = target.get("name") or target.get("ip")

    timestamp = (
        raw.get("@timestamp")
        or raw.get("timestamp")
        or event.get("created")
        or event.get("start")
    )

    event_type = (
        event.get("category")
        or event.get("type")
        or event.get("kind")
        or raw.get("event_type")
        or "external_log"
    )
    if isinstance(event_type, list):
        event_type = ",".join(str(x) for x in event_type)

    identity = json.dumps(
        {"integration_id": item.id, "raw": raw},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    event_id = generate_event_id(identity)

    return create_security_event(
        source=f"{item.provider}:{item.id}",
        event_type=str(event_type)[:100],
        message=str(message)[:10000],
        severity=severity,
        timestamp=iso_utc(parse_timestamp(timestamp)),
        target=str(target)[:255] if target else None,
        raw_event={
            "integration_id": item.id,
            "integration_name": item.name,
            "provider": item.provider,
            "original": raw,
        },
        event_id=event_id,
    )


def ingest_one_integration(db: Session, item):
    state = db.query(SIEMIngestionState).filter(
        SIEMIngestionState.integration_id == item.id
    ).first()

    if state is None:
        state = SIEMIngestionState(integration_id=item.id)
        db.add(state)
        db.flush()

    end = utc_now()
    start = (
        state.last_ingested_at - timedelta(seconds=OVERLAP_SECONDS)
        if state.last_ingested_at
        else end - timedelta(minutes=5)
    )

    credentials = decrypt_credentials(item)

    if item.provider == "splunk":
        raw_events = fetch_splunk(item, credentials, start, end)
    elif item.provider == "elastic":
        raw_events = fetch_elastic(item, credentials, start, end)
    else:
        raise RuntimeError("Unsupported SIEM provider.")

    notifications = []
    inserted = 0

    for raw in raw_events:
        normalized = normalize_external_event(raw, item)

        exists = db.query(SecurityEvent.id).filter(
            SecurityEvent.event_id == normalized["event_id"]
        ).first()

        if exists:
            continue

        store_security_event(db, normalized)
        notifications.append(normalized)
        inserted += 1

    # Event rows and checkpoint are committed together.
    state.last_ingested_at = end
    state.last_success_at = end
    state.last_error = None
    state.total_events = (state.total_events or 0) + inserted
    state.updated_at = end

    item.status = "CONNECTED"
    item.last_error = None
    item.updated_at = end

    db.commit()

    for event in notifications:
        try:
            notify_security_event(event)
        except Exception as exc:
            print(f"[SIEM INGESTION] Notification failed: {exc}")

    return inserted


def ingest_enabled_integrations_once():
    # Splunk and Elastic polling has been retired.
    # Snort writes alerts directly through the existing Security Events pipeline.
    return 0


async def siem_ingestion_loop():
    print(
        f"[SIEM INGESTION] Worker started; interval={POLL_SECONDS}s"
    )
    while True:
        try:
            await asyncio.to_thread(ingest_enabled_integrations_once)
        except Exception as exc:
            print(f"[SIEM INGESTION] Worker cycle failed: {exc}")
        await asyncio.sleep(POLL_SECONDS)

