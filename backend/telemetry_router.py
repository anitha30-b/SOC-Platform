import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from database import get_db
from models import (
    CollectorExecutionRun,
    EndpointAsset,
    SecurityEvent,
    TelemetrySource,
    User,
)
from rbac import require_role
from security_event_store import parse_event_timestamp, store_security_event
from security_events import generate_event_id
from telemetry_detection import process_ingested_telemetry
from client_realtime_events import notify_client_security_event
from realtime_journal_listener import notify_security_event


router = APIRouter(
    prefix="/telemetry",
    tags=["Client Telemetry"],
)

ALLOWED_SEVERITIES = {
    "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "WARNING", "ERROR"
}
MAX_BATCH_SIZE = 100


class TelemetrySourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)

    class Config:
        extra = "forbid"


class TelemetryEventInput(BaseModel):
    event_id: str | None = Field(default=None, max_length=255)
    timestamp: str | None = Field(default=None, max_length=64)
    event_type: str = Field(min_length=1, max_length=100)
    severity: str = Field(default="INFO", max_length=20)
    message: str = Field(min_length=1, max_length=10000)
    target: str | None = Field(default=None, max_length=255)
    endpoint_id: str | None = Field(default=None, max_length=255)
    raw_event: dict[str, Any] | None = None

    class Config:
        extra = "forbid"


class TelemetryBatchInput(BaseModel):
    events: list[TelemetryEventInput]

    class Config:
        extra = "forbid"


class CollectorExecutionReportInput(BaseModel):
    run_id: str = Field(min_length=1, max_length=100)
    endpoint_id: str = Field(min_length=1, max_length=255)
    started_at: datetime
    completed_at: datetime | None = None
    status: str = Field(min_length=1, max_length=20)
    collected_count: int = Field(default=0, ge=0)
    accepted_count: int = Field(default=0, ge=0)
    duplicate_count: int = Field(default=0, ge=0)
    error_count: int = Field(default=0, ge=0)
    error_details: str | None = Field(default=None, max_length=4000)

    class Config:
        extra = "forbid"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _owned_sources_query(db: Session, user: User):
    query = db.query(TelemetrySource)

    if user.client_id is not None:
        return query.filter(TelemetrySource.client_id == user.client_id)

    return query.filter(TelemetrySource.owner_user_id == user.id)


def _source_response(source: TelemetrySource) -> dict:
    return {
        "id": source.id,
        "name": source.name,
        "enabled": source.enabled,
        "created_at": source.created_at.isoformat() if source.created_at else None,
        "last_seen_at": (
            source.last_seen_at.isoformat() if source.last_seen_at else None
        ),
    }


@router.post("/sources", status_code=201)
def create_telemetry_source(
    payload: TelemetrySourceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Source name cannot be blank")

    raw_token = secrets.token_urlsafe(32)
    source = TelemetrySource(
        name=name,
        client_id=current_user.client_id,
        owner_user_id=current_user.id,
        token_hash=_hash_token(raw_token),
        enabled=True,
        created_by=current_user.id,
    )

    try:
        db.add(source)
        db.commit()
        db.refresh(source)
    except Exception:
        db.rollback()
        raise

    response = _source_response(source)
    response["api_key"] = raw_token
    response["api_key_notice"] = (
        "Copy this key now. It will not be returned by later requests."
    )
    return response


@router.post("/sources/{source_id}/regenerate-key")
def regenerate_telemetry_source_key(
    source_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    source = _owned_sources_query(db, current_user).filter(
        TelemetrySource.id == source_id
    ).first()

    if source is None:
        raise HTTPException(status_code=404, detail="Telemetry source not found")

    if not source.enabled:
        raise HTTPException(status_code=409, detail="Telemetry source is revoked")

    raw_token = secrets.token_urlsafe(32)
    source.token_hash = _hash_token(raw_token)

    try:
        db.commit()
        db.refresh(source)
    except Exception:
        db.rollback()
        raise

    return {
        "source_id": source.id,
        "api_key": raw_token,
        "api_key_notice": (
            "Copy this key now. It will not be returned by later requests."
        ),
    }


@router.get("/sources")
def list_telemetry_sources(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    sources = (
        _owned_sources_query(db, current_user)
        .order_by(TelemetrySource.created_at.desc())
        .all()
    )
    return [_source_response(source) for source in sources]


@router.delete("/sources/{source_id}")
def revoke_telemetry_source(
    source_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    source = _owned_sources_query(db, current_user).filter(
        TelemetrySource.id == source_id
    ).first()

    if source is None:
        raise HTTPException(status_code=404, detail="Telemetry source not found")

    source.enabled = False
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {"revoked": True, "source_id": source.id}


@router.get("/execution-runs")
def list_collector_execution_runs(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="Limit must be between 1 and 200")

    owned_source_ids = _owned_sources_query(db, current_user).with_entities(
        TelemetrySource.id
    )

    runs = (
        db.query(CollectorExecutionRun, EndpointAsset)
        .join(
            EndpointAsset,
            CollectorExecutionRun.endpoint_asset_id == EndpointAsset.id,
        )
        .filter(CollectorExecutionRun.telemetry_source_id.in_(owned_source_ids))
        .order_by(
            CollectorExecutionRun.started_at.desc(),
            CollectorExecutionRun.id.desc(),
        )
        .limit(limit)
        .all()
    )

    return {
        "runs": [
            {
                "id": run.id,
                "run_id": run.run_id,
                "telemetry_source_id": run.telemetry_source_id,
                "endpoint_asset_id": run.endpoint_asset_id,
                "endpoint_id": endpoint.endpoint_id,
                "hostname": endpoint.hostname,
                "status": run.status,
                "collected_count": run.collected_count,
                "accepted_count": run.accepted_count,
                "duplicate_count": run.duplicate_count,
                "error_count": run.error_count,
                "error_details": run.error_details,
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
                "created_at": run.created_at.isoformat() if run.created_at else None,
            }
            for run, endpoint in runs
        ],
        "count": len(runs),
    }


@router.post("/execution-runs", status_code=201)
def report_collector_execution(
    payload: CollectorExecutionReportInput,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    if not x_api_key or not x_api_key.strip():
        raise HTTPException(status_code=401, detail="Missing telemetry API key")

    source = db.query(TelemetrySource).filter(
        TelemetrySource.token_hash == _hash_token(x_api_key.strip()),
        TelemetrySource.enabled.is_(True),
    ).first()

    if source is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked telemetry API key")

    if source.client_id is None and source.owner_user_id is None:
        raise HTTPException(status_code=403, detail="Telemetry source has no owner")

    run_id = payload.run_id.strip()
    endpoint_id = payload.endpoint_id.strip()
    status = payload.status.strip().upper()

    if not run_id or not endpoint_id:
        raise HTTPException(status_code=422, detail="Run ID and endpoint ID cannot be blank")

    if status not in {"SUCCESS", "PARTIAL", "FAILED"}:
        raise HTTPException(status_code=422, detail="Unsupported execution status")

    if payload.accepted_count + payload.duplicate_count > payload.collected_count:
        raise HTTPException(
            status_code=422,
            detail="Accepted plus duplicate counts cannot exceed collected count",
        )

    started_at = payload.started_at
    completed_at = payload.completed_at
    if started_at.tzinfo is not None:
        started_at = started_at.astimezone(timezone.utc).replace(tzinfo=None)
    if completed_at is not None and completed_at.tzinfo is not None:
        completed_at = completed_at.astimezone(timezone.utc).replace(tzinfo=None)

    if completed_at is not None and completed_at < started_at:
        raise HTTPException(status_code=422, detail="Completion time precedes start time")

    endpoint = db.query(EndpointAsset).filter(
        EndpointAsset.endpoint_id == endpoint_id,
        EndpointAsset.telemetry_source_id == source.id,
    ).first()

    if endpoint is None:
        raise HTTPException(
            status_code=422,
            detail="Endpoint ID is not registered to this telemetry source",
        )

    existing = db.query(CollectorExecutionRun).filter(
        CollectorExecutionRun.telemetry_source_id == source.id,
        CollectorExecutionRun.run_id == run_id,
    ).first()

    if existing is not None:
        return {
            "created": False,
            "duplicate": True,
            "run_id": existing.run_id,
            "status": existing.status,
        }

    report = CollectorExecutionRun(
        run_id=run_id,
        telemetry_source_id=source.id,
        endpoint_asset_id=endpoint.id,
        started_at=started_at,
        completed_at=completed_at,
        status=status,
        collected_count=payload.collected_count,
        accepted_count=payload.accepted_count,
        duplicate_count=payload.duplicate_count,
        error_count=payload.error_count,
        error_details=payload.error_details.strip() if payload.error_details else None,
    )

    try:
        db.add(report)
        db.commit()
        db.refresh(report)
    except IntegrityError:
        db.rollback()
        existing = db.query(CollectorExecutionRun).filter(
            CollectorExecutionRun.telemetry_source_id == source.id,
            CollectorExecutionRun.run_id == run_id,
        ).first()
        if existing is not None:
            return {
                "created": False,
                "duplicate": True,
                "run_id": existing.run_id,
                "status": existing.status,
            }
        raise
    except Exception:
        db.rollback()
        raise

    return {
        "created": True,
        "duplicate": False,
        "run_id": report.run_id,
        "endpoint_id": endpoint.endpoint_id,
        "status": report.status,
        "collected_count": report.collected_count,
        "accepted_count": report.accepted_count,
        "duplicate_count": report.duplicate_count,
        "error_count": report.error_count,
        "started_at": report.started_at.isoformat(),
        "completed_at": report.completed_at.isoformat() if report.completed_at else None,
    }


@router.post("/ingest")
def ingest_telemetry(
    payload: TelemetryBatchInput,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    if not x_api_key or not x_api_key.strip():
        raise HTTPException(status_code=401, detail="Missing telemetry API key")

    source = db.query(TelemetrySource).filter(
        TelemetrySource.token_hash == _hash_token(x_api_key.strip()),
        TelemetrySource.enabled.is_(True),
    ).first()

    if source is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked telemetry API key")

    if source.client_id is None and source.owner_user_id is None:
        raise HTTPException(status_code=403, detail="Telemetry source has no owner")

    if not payload.events or len(payload.events) > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=422,
            detail=f"Submit between 1 and {MAX_BATCH_SIZE} events per request",
        )

    accepted = 0
    duplicates = 0
    batch_ids: set[str] = set()
    accepted_events = []

    try:
        for item in payload.events:
            severity = item.severity.strip().upper()
            if severity not in ALLOWED_SEVERITIES:
                raise HTTPException(
                    status_code=422,
                    detail=f"Unsupported severity: {item.severity}",
                )

            event_type = item.event_type.strip()
            message = item.message.strip()
            if not event_type or not message:
                raise HTTPException(
                    status_code=422,
                    detail="Event type and message cannot be blank",
                )

            try:
                event_timestamp = parse_event_timestamp(item.timestamp)
            except (ValueError, TypeError, OverflowError):
                raise HTTPException(
                    status_code=422,
                    detail="Event timestamp must be a valid ISO 8601 timestamp",
                )

            timestamp_string = event_timestamp.isoformat()
            identity = (item.event_id or "").strip()

            if not identity:
                identity = json.dumps(
                    {
                        "timestamp": timestamp_string,
                        "event_type": event_type,
                        "severity": severity,
                        "message": message,
                        "target": item.target,
                        "endpoint_id": item.endpoint_id,
                        "raw_event": item.raw_event,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                )

            # Scope deduplication to this source; never trust a caller's raw ID.
            stored_event_id = generate_event_id(
                f"telemetry-source:{source.id}:{identity}"
            )

            if stored_event_id in batch_ids:
                duplicates += 1
                continue
            batch_ids.add(stored_event_id)

            already_stored = db.query(SecurityEvent.id).filter(
                SecurityEvent.event_id == stored_event_id
            ).first()
            if already_stored:
                duplicates += 1
                continue

            endpoint_asset_id = None
            if item.endpoint_id:
                endpoint = db.query(EndpointAsset).filter(
                    EndpointAsset.endpoint_id == item.endpoint_id.strip(),
                    EndpointAsset.telemetry_source_id == source.id,
                ).first()

                if endpoint is None:
                    raise HTTPException(
                        status_code=422,
                        detail="Endpoint ID is not registered to this telemetry source",
                    )

                endpoint_asset_id = endpoint.id

            event = {
                "event_id": stored_event_id,
                "timestamp": timestamp_string,
                "source": f"telemetry:{source.id}",
                "event_type": event_type,
                "severity": severity,
                "message": message,
                "target": item.target,
                "assessment_id": None,
                "client_id": source.client_id,
                "owner_user_id": source.owner_user_id,
                "telemetry_source_id": source.id,
                "endpoint_asset_id": endpoint_asset_id,
                "_tenant_scope_key": (
                    f"client:{source.client_id}"
                    if source.client_id is not None
                    else f"user:{source.owner_user_id}"
                ),
                "raw_event": {
                    "payload": item.raw_event or {},
                    "telemetry_source_id": source.id,
                    "endpoint_id": item.endpoint_id,
                },
            }

            store_security_event(db, event)
            db.flush()
            accepted += 1
            accepted_events.append(event)

        source.last_seen_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()
    except Exception:
        db.rollback()
        raise

    # Run detection only after the telemetry transaction commits.
    # A detection error must not undo already-accepted telemetry.
    for accepted_event in accepted_events:
        try:
            notify_client_security_event(accepted_event)
        except Exception as exc:
            print(f"[SOC TELEMETRY REALTIME ERROR] {exc}", flush=True)

        try:
            notify_security_event(accepted_event)
        except Exception as exc:
            print(f"[SOC TELEMETRY SIEM NOTIFY ERROR] {exc}", flush=True)

        try:
            process_ingested_telemetry(accepted_event)
        except Exception as exc:
            print(f"[SOC TELEMETRY DETECTION ERROR] {exc}", flush=True)

    return {
        "source_id": source.id,
        "received": len(payload.events),
        "accepted": accepted,
        "duplicates": duplicates,
    }
