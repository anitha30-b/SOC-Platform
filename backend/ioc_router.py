from pydantic import StrictBool
import ipaddress
import re
from datetime import timezone
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import IOCIndicator, SecurityEvent
from rbac import require_role
from security_event_scope import owned_security_event_filter

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


def normalize_http_url(value: str) -> str:
    """Canonicalize HTTP(S) URLs for exact IOC comparison."""
    value = value.strip()
    if not value or any(ch.isspace() or ord(ch) < 32 for ch in value):
        raise ValueError("URL must not contain whitespace or control characters.")

    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must be a valid HTTP or HTTPS URL.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not accepted.")

    hostname = parsed.hostname.rstrip(".")
    if not hostname:
        raise ValueError("URL hostname cannot be empty.")

    is_ipv6 = False
    try:
        address = ipaddress.ip_address(hostname)
        hostname = address.compressed.lower()
        is_ipv6 = address.version == 6
    except ValueError:
        try:
            hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("URL hostname is invalid.") from exc

        if len(hostname) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in hostname.split(".")
        ):
            raise ValueError("URL hostname is invalid.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL port is invalid.") from exc

    if port == (443 if scheme == "https" else 80):
        port = None

    authority = f"[{hostname}]" if is_ipv6 else hostname
    if port is not None:
        authority = f"{authority}:{port}"

    # Fragments are client-side and are not sent to the web server.
    return urlunsplit((scheme, authority, parsed.path or "/", parsed.query, ""))


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
            return normalize_http_url(value)

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


_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def url_candidate_matches(indicator_value: str, searchable: str) -> bool:
    """Match a canonical full URL in text, not an arbitrary URL substring."""
    expected = normalize_http_url(indicator_value)

    for candidate in _URL_RE.findall(searchable):
        candidate = candidate.rstrip(".,;!}")
        while candidate.endswith(")") and candidate.count(")") > candidate.count("("):
            candidate = candidate[:-1]

        try:
            normalized = normalize_http_url(candidate)
        except ValueError:
            continue

        if normalized == expected:
            return True

    return False


def scope_security_events_to_user(db: Session, user):
    """Return only assessment- or telemetry-owned events in the user's scope."""
    return db.query(SecurityEvent).filter(
        owned_security_event_filter(db, user)
    )


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

    events_query = scope_security_events_to_user(db, current_user)
    events = (
        events_query
        .order_by(SecurityEvent.timestamp.desc())
        .limit(500)
        .all()
    )
    pattern = (
        None if item.indicator_type == "URL"
        else indicator_pattern(item)
    )
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
        matched = (
            url_candidate_matches(item.value, searchable)
            if item.indicator_type == "URL"
            else bool(pattern.search(searchable))
        )
        if matched:
            match_count += 1

    scope_status = "NO_SCOPED_EVENTS" if not events else "SCANNED"
    scope_message = (
        "No events linked to assessments owned by this user/client are available "
        "to scan. Unlinked system-wide telemetry was excluded to protect tenant isolation."
        if not events
        else
        "Matching used only assessment- or telemetry-owned events within this user/client scope. "
        "Candidate matches are not proof of malicious activity."
    )

    return {
        "indicator_id": item.id,
        "indicator_type": item.indicator_type,
        "value": item.value,
        "candidate_match_count": match_count,
        "events_scanned": len(events),
        "scope_status": scope_status,
        "scope_message": scope_message,
        "scan_scope": (
            "Latest 500 persisted events linked to assessments or registered telemetry sources owned by this client."
            if current_user.client_id is not None
            else "Latest 500 persisted events linked to your assessments or registered telemetry sources."
        ),
        "tenant_scope_note": (
            "Events are scoped through Assessment.user_id and User.client_id. "
            "Events without an ownership-linked assessment_id are excluded. "
            "Only aggregate counts are returned; matches are candidates, not "
            "confirmed malicious activity."
        ),
    }


@router.get("/registry-summary")
def get_registry_summary(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    from sqlalchemy import func

    query = scope_indicators(db, current_user)
    groups = (
        query.with_entities(
            IOCIndicator.indicator_type,
            IOCIndicator.severity,
            IOCIndicator.enabled,
            func.count(IOCIndicator.id),
        )
        .group_by(
            IOCIndicator.indicator_type,
            IOCIndicator.severity,
            IOCIndicator.enabled,
        )
        .all()
    )

    result = {
        "total": 0,
        "enabled": 0,
        "disabled": 0,
        "high_critical": 0,
        "by_type": {
            key: 0 for key in ("IP", "DOMAIN", "URL", "MD5", "SHA1", "SHA256")
        },
        "scope": "client" if current_user.client_id is not None else "personal",
    }
    for kind, severity, enabled, count in groups:
        result["total"] += count
        result["enabled" if enabled else "disabled"] += count
        if severity in {"HIGH", "CRITICAL"}:
            result["high_critical"] += count
        result["by_type"][kind] = result["by_type"].get(kind, 0) + count
    return result


@router.get("/registry")
def get_registry_page(
    search: str = "",
    indicator_type: str = "ALL",
    severity: str = "ALL",
    enabled: bool | None = None,
    offset: int = 0,
    page_size: int = 25,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    from sqlalchemy import func, or_

    if offset < 0 or not 1 <= page_size <= 100:
        raise HTTPException(
            status_code=400,
            detail="Use a nonnegative offset and page size between 1 and 100.",
        )
    if len(search) > 200:
        raise HTTPException(status_code=400, detail="Search is limited to 200 characters.")

    kind = indicator_type.strip().upper()
    level = severity.strip().upper()
    if kind not in {"ALL", "IP", "DOMAIN", "URL", "HASH", "MD5", "SHA1", "SHA256"}:
        raise HTTPException(status_code=400, detail="Invalid indicator type.")
    if level not in {"ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(status_code=400, detail="Invalid severity.")

    query = scope_indicators(db, current_user)
    if kind == "HASH":
        query = query.filter(
            IOCIndicator.indicator_type.in_(["MD5", "SHA1", "SHA256"])
        )
    elif kind != "ALL":
        query = query.filter(IOCIndicator.indicator_type == kind)
    if level != "ALL":
        query = query.filter(IOCIndicator.severity == level)
    if enabled is not None:
        query = query.filter(IOCIndicator.enabled == enabled)

    term = search.strip().lower()
    if term:
        query = query.filter(or_(*[
            func.lower(field).contains(term, autoescape=True)
            for field in (
                IOCIndicator.value,
                IOCIndicator.description,
                IOCIndicator.source,
            )
        ]))

    total = query.count()
    items = (
        query.order_by(IOCIndicator.created_at.desc(), IOCIndicator.id.desc())
        .offset(offset).limit(page_size).all()
    )
    return {
        "total": total,
        "count": len(items),
        "offset": offset,
        "page_size": page_size,
        "next_offset": (
            offset + len(items) if offset + len(items) < total else None
        ),
        "indicators": [serialize_indicator(item) for item in items],
    }


class IOCEnabledUpdate(BaseModel):
    enabled: StrictBool


@router.patch("/indicators/{indicator_id}/enabled")
def set_indicator_enabled(
    indicator_id: int,
    payload: IOCEnabledUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    from datetime import datetime
    import json
    from models import AuditLog

    item = (
        scope_indicators(db, current_user)
        .filter(IOCIndicator.id == indicator_id)
        .with_for_update()
        .first()
    )
    if item is None:
        raise HTTPException(status_code=404, detail="Indicator not found.")

    if item.enabled == payload.enabled:
        return {"changed": False, "indicator": serialize_indicator(item)}

    previous = item.enabled
    item.enabled = payload.enabled
    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="IOC_ENABLED" if payload.enabled else "IOC_DISABLED",
        module="Threat Intelligence",
        status="SUCCESS",
        details=json.dumps({
            "indicator_id": item.id,
            "indicator_type": item.indicator_type,
            "previous_enabled": previous,
            "enabled": item.enabled,
        }),
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
    ))
    db.commit()
    db.refresh(item)
    return {"changed": True, "indicator": serialize_indicator(item)}


@router.get("/source-status")
def get_intelligence_source_status(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    from datetime import datetime
    from sqlalchemy import func
    from mitre import MITRE_DATA_PATH
    from threat_knowledge_router import _objects
    from cve import NVD_API_KEY

    snapshot = {
        "name": "Enterprise ATT&CK",
        "mode": "Local snapshot",
        "status": "Unavailable",
        "dataset": MITRE_DATA_PATH.name,
        "file_modified_at": None,
        "latest_record_modified_at": None,
        "records": {},
    }
    try:
        objects = _objects()
        kinds = {
            "actors": "intrusion-set",
            "campaigns": "campaign",
            "malware": "malware",
        }
        snapshot["records"] = {
            label: sum(obj.get("type") == kind for obj in objects)
            for label, kind in kinds.items()
        }
        snapshot["file_modified_at"] = datetime.fromtimestamp(
            MITRE_DATA_PATH.stat().st_mtime, timezone.utc
        ).isoformat()
        modified = [
            obj.get("modified") for obj in objects
            if obj.get("type") in kinds.values()
            and isinstance(obj.get("modified"), str)
        ]
        snapshot["latest_record_modified_at"] = max(modified, default=None)
        snapshot["status"] = "Readable"
    except (HTTPException, OSError):
        pass

    sources = (
        scope_indicators(db, current_user)
        .with_entities(IOCIndicator.source, func.count(IOCIndicator.id))
        .group_by(IOCIndicator.source)
        .all()
    )
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "snapshot": snapshot,
        "nvd": {
            "mode": "On-demand CVE lookup",
            "status": "Configured; connectivity not checked",
            "api_key_configured": bool(NVD_API_KEY),
        },
        "registry": {
            "scope": "client" if current_user.client_id is not None else "personal",
            "total": sum(count for _, count in sources),
            "sources": [
                {"label": label or "Not provided", "count": count}
                for label, count in sorted(sources, key=lambda row: row[0] or "")
            ],
        },
        "automated_ingestion": "Not configured",
        "import_history": "Not recorded",
    }
