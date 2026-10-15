import ipaddress
import re
from datetime import timezone
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import IOCIndicator, SecurityEvent
from rbac import require_role

router = APIRouter(prefix="/ioc", tags=["IOC Detection"])

IndicatorType = Literal["IP", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"]
Severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class IOCCreate(BaseModel):
    indicator_type: IndicatorType
    value: str = Field(min_length=1, max_length=2048)
    description: str | None = Field(default=None, max_length=4000)
    source: str | None = Field(default=None, max_length=255)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    confidence: int = Field(default=50, ge=0, le=100)


def normalize_indicator(kind: str, value: str) -> str:
    value = value.strip()
    if not value:
        raise HTTPException(status_code=422, detail="Indicator value cannot be empty.")

    try:
        if kind == "IP":
            return str(ipaddress.ip_address(value))

        if kind == "DOMAIN":
            if "://" in value or "/" in value:
                raise ValueError("Enter a hostname, not a URL.")
            domain = value.rstrip(".").encode("idna").decode("ascii").lower()
            if len(domain) > 253 or not domain or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in domain.split(".")
            ):
                raise ValueError("Invalid domain format.")
            if "." not in domain:
                raise ValueError("A fully qualified domain is required.")
            return domain

        if kind == "URL":
            parsed = urlsplit(value)
            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not parsed.hostname
                or any(ch.isspace() for ch in value)
            ):
                raise ValueError("URL must be a valid HTTP or HTTPS URL.")
            return value

        lengths = {"MD5": 32, "SHA1": 40, "SHA256": 64}
        if kind in lengths:
            if not re.fullmatch(r"[0-9a-fA-F]+", value) or len(value) != lengths[kind]:
                raise ValueError(f"{kind} must contain exactly {lengths[kind]} hexadecimal characters.")
            return value.lower()

    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    raise HTTPException(status_code=422, detail="Unsupported indicator type.")


def scope_indicators(db: Session, user):
    query = db.query(IOCIndicator)
    if user.client_id is not None:
        return query.filter(IOCIndicator.client_id == user.client_id)
    return query.filter(
        IOCIndicator.client_id.is_(None),
        IOCIndicator.created_by == user.id,
    )


def serialize_indicator(item):
    created = item.created_at
    if created and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    return {
        "id": item.id,
        "indicator_type": item.indicator_type,
        "value": item.value,
        "description": item.description,
        "source": item.source,
        "severity": item.severity,
        "confidence": item.confidence,
        "enabled": item.enabled,
        "created_at": created.isoformat() if created else None,
    }


def indicator_pattern(item):
    escaped = re.escape(item.value)
    if item.indicator_type == "DOMAIN":
        return re.compile(r"(?<![a-z0-9.-])" + escaped + r"(?![a-z0-9.-])", re.I)
    if item.indicator_type in {"IP", "MD5", "SHA1", "SHA256"}:
        return re.compile(r"(?<![a-z0-9])" + escaped + r"(?![a-z0-9])", re.I)
    return re.compile(escaped, re.I)


@router.get("/indicators")
def list_indicators(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    items = (
        scope_indicators(db, current_user)
        .order_by(IOCIndicator.created_at.desc())
        .limit(500)
        .all()
    )
    return {"count": len(items), "indicators": [serialize_indicator(i) for i in items]}


@router.post("/indicators", status_code=201)
def create_indicator(
    payload: IOCCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    kind = payload.indicator_type.upper()
    value = normalize_indicator(kind, payload.value)

    existing = scope_indicators(db, current_user).filter(
        IOCIndicator.indicator_type == kind,
        IOCIndicator.value == value,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="This indicator already exists in your registry.")

    item = IOCIndicator(
        indicator_type=kind,
        value=value,
        description=payload.description.strip() if payload.description else None,
        source=payload.source.strip() if payload.source else None,
        severity=payload.severity,
        confidence=payload.confidence,
        enabled=True,
        client_id=current_user.client_id,
        created_by=current_user.id,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return {"indicator": serialize_indicator(item)}


@router.delete("/indicators/{indicator_id}")
def delete_indicator(
    indicator_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    item = scope_indicators(db, current_user).filter(
        IOCIndicator.id == indicator_id
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Indicator not found.")

    db.delete(item)
    db.commit()
    return {"deleted": True, "id": indicator_id}


@router.get("/indicators/{indicator_id}/matches")
def check_indicator_matches(
    indicator_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    item = scope_indicators(db, current_user).filter(
        IOCIndicator.id == indicator_id,
        IOCIndicator.enabled.is_(True),
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Enabled indicator not found.")

    events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(500)
        .all()
    )
    pattern = indicator_pattern(item)
    match_count = 0

    for event in events:
        searchable = " ".join(
            str(value) for value in (
                event.source,
                event.target,
                event.message,
                event.raw_event,
            ) if value
        )
        if pattern.search(searchable):
            match_count += 1

    return {
        "indicator_id": item.id,
        "indicator_type": item.indicator_type,
        "value": item.value,
        "candidate_match_count": match_count,
        "events_scanned": len(events),
        "scan_scope": "Latest 500 persisted SOC events",
        "tenant_scope_note": (
            "The security_events table does not currently carry client_id. "
            "Only aggregate match counts are returned; matches are candidates, "
            "not confirmed malicious activity."
        ),
    }
