from datetime import datetime
import ipaddress
import socket
import time
from urllib.parse import urlparse

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Session

from database import Base, SessionLocal
from assets_router import Asset


class ServerMonitorResult(Base):
    __tablename__ = "soc_server_monitor_results"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("soc_assets.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    status = Column(String(20), nullable=False, default="unknown")
    port = Column(Integer, nullable=False, default=443)
    response_time_ms = Column(Float, nullable=True)
    checked_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    reason = Column(String(250), nullable=True)


def check_server(asset, port=443, timeout=2.0):
    target = (asset.ip_address or "").strip()
    started = time.monotonic()

    # Use the registered URL hostname when no IP address is configured.
    if not target:
        url = (getattr(asset, "url", None) or "").strip()
        if not url:
            return "unknown", None, "No IP address or URL registered"

        parsed = urlparse(url if "://" in url else f"https://{url}")
        target = parsed.hostname or ""
        if not target:
            return "unknown", None, "Invalid URL: hostname missing"

        # Honor an explicit URL port, otherwise use the monitor's port.
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

    else:
        try:
            target = str(ipaddress.ip_address(target))
        except ValueError:
            return "unknown", None, "Invalid IP address"

    try:
        with socket.create_connection((target, port), timeout=timeout):
            elapsed = round((time.monotonic() - started) * 1000, 2)
        return "reachable", elapsed, None
    except (OSError, TimeoutError) as exc:
        elapsed = round((time.monotonic() - started) * 1000, 2)
        return "unreachable", elapsed, str(exc)[:250]


def publish_security_event(event):
    """Publish a committed event to the existing SOC event channel."""
    import json
    import psycopg2
    from database import DATABASE_URL

    payload = dict(event)
    payload.pop("raw_event", None)
    connection = psycopg2.connect(
        DATABASE_URL.replace(
            "postgresql+psycopg2://", "postgresql://", 1
        )
    )
    try:
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_notify(%s, %s)",
                ("security_events", json.dumps(payload, default=str)),
            )
    finally:
        connection.close()


def monitor_servers_once():
    import hashlib
    import json

    from models import SecurityEvent

    db: Session = SessionLocal()
    events_to_publish = []
    checked_count = 0

    try:
        assets = (
            db.query(Asset)
            .filter(Asset.asset_type.ilike("server"))
            .all()
        )

        for asset in assets:
            port = 443
            status, response_time, reason = check_server(asset, port)

            result = (
                db.query(ServerMonitorResult)
                .filter(ServerMonitorResult.asset_id == asset.id)
                .first()
            )
            previous_status = result.status if result else "unknown"

            # Use a consistent target even when an asset has only a URL.
            target = (
                asset.ip_address
                or asset.hostname
                or asset.url
                or f"asset:{asset.id}"
            )

            if result is None:
                result = ServerMonitorResult(asset_id=asset.id)
                db.add(result)
                db.flush()

            result.status = status
            result.port = port
            result.response_time_ms = response_time
            result.checked_at = datetime.utcnow()
            result.reason = reason
            checked_count += 1

            # Alert only after a known reachable -> unreachable transition.
            if status == "unreachable" and previous_status == "reachable":
                now = datetime.utcnow()
                event_id = hashlib.sha256(
                    f"server-down:{asset.id}:{now.isoformat()}".encode()
                ).hexdigest()
                event = {
                    "event_id": event_id,
                    "timestamp": now.isoformat(),
                    "source": "server-monitor",
                    "event_type": "server_down",
                    "severity": "HIGH",
                    "message": (
                        f"Server asset {asset.id} failed its TCP port "
                        f"{port} check. Reason: {reason or 'Connection failed'}"
                    ),
                    "target": target,
                    "assessment_id": None,
                    "raw_event": {
                        "asset_id": asset.id,
                        "port": port,
                        "previous_status": previous_status,
                        "status": status,
                        "reason": reason,
                    },
                }
                db.add(SecurityEvent(
                    event_id=event_id,
                    timestamp=now,
                    source=event["source"],
                    event_type=event["event_type"],
                    severity=event["severity"],
                    message=event["message"],
                    target=event["target"],
                    assessment_id=None,
                    raw_event=json.dumps(event, default=str),
                    alert_status="ACTIVE",
                ))
                events_to_publish.append(event)

            # Resolve the active outage event when the server recovers.
            elif status == "reachable" and previous_status == "unreachable":
                now = datetime.utcnow()
                active_alerts = (
                    db.query(SecurityEvent)
                    .filter(
                        SecurityEvent.source == "server-monitor",
                        SecurityEvent.event_type == "server_down",
                        SecurityEvent.alert_status == "ACTIVE",
                        SecurityEvent.target == target,
                    )
                    .with_for_update()
                    .all()
                )

                resolved_count = 0
                for alert in active_alerts:
                    try:
                        details = json.loads(alert.raw_event or "{}")
                        if "raw_event" in details and isinstance(
                            details["raw_event"], dict
                        ):
                            details = details["raw_event"]
                    except (ValueError, TypeError):
                        details = {}

                    try:
                        alert_asset_id = int(details.get("asset_id"))
                    except (ValueError, TypeError):
                        continue

                    if alert_asset_id != asset.id:
                        continue

                    alert.alert_status = "RESOLVED"
                    alert.resolved_at = now
                    resolved_count += 1

                print(
                    f"[SERVER MONITOR] Asset {asset.id} recovered; "
                    f"resolved {resolved_count} matching outage alert(s).",
                    flush=True,
                )

                recovery_id = hashlib.sha256(
                    f"server-recovered:{asset.id}:{now.isoformat()}".encode()
                ).hexdigest()
                event = {
                    "event_id": recovery_id,
                    "timestamp": now.isoformat(),
                    "source": "server-monitor",
                    "event_type": "server_recovered",
                    "severity": "INFO",
                    "message": (
                        f"Server asset {asset.id} is reachable again "
                        f"on TCP port {port}."
                    ),
                    "target": target,
                    "assessment_id": None,
                    "raw_event": {
                        "asset_id": asset.id,
                        "port": port,
                        "previous_status": previous_status,
                        "status": status,
                    },
                }
                db.add(SecurityEvent(
                    event_id=recovery_id,
                    timestamp=now,
                    source=event["source"],
                    event_type=event["event_type"],
                    severity=event["severity"],
                    message=event["message"],
                    target=event["target"],
                    assessment_id=None,
                    raw_event=json.dumps(event, default=str),
                    alert_status="RESOLVED",
                    resolved_at=now,
                ))
                events_to_publish.append(event)

        db.commit()

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    for event in events_to_publish:
        try:
            publish_security_event(event)
        except Exception as exc:
            print(
                f"[SERVER MONITOR] Event publish failed: {exc}",
                flush=True,
            )

    print(
        f"[SERVER MONITOR] Checked {checked_count} server asset(s); "
        f"published {len(events_to_publish)} transition event(s).",
        flush=True,
    )
    return checked_count

