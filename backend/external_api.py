import hashlib
import hmac
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from database import get_db
from models import (
    APIKey,
    SecurityEvent,
    SecurityFinding,
    Assessment,
    SecurityTool,
    User,
)


router = APIRouter(
    prefix="/external-api/v1",
    tags=["External API"],
)

api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


# ============================================================
# API KEY AUTHENTICATION
# ============================================================

def get_authenticated_api_key(
    api_key: str = Depends(api_key_header),
    db: Session = Depends(get_db),
):
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key is required.",
        )

    key_hash = hashlib.sha256(
        api_key.encode("utf-8")
    ).hexdigest()

    stored_key = (
        db.query(APIKey)
        .filter(APIKey.key_prefix == api_key[:12])
        .first()
    )

    if not stored_key or not hmac.compare_digest(
        stored_key.key_hash,
        key_hash,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key.",
        )

    if not stored_key.enabled:
        raise HTTPException(
            status_code=403,
            detail="API key is disabled.",
        )

    if stored_key.revoked_at is not None:
        raise HTTPException(
            status_code=403,
            detail="API key has been revoked.",
        )

    now = datetime.utcnow()

    if stored_key.expires_at and stored_key.expires_at <= now:
        raise HTTPException(
            status_code=403,
            detail="API key has expired.",
        )

    stored_key.last_used_at = now
    db.commit()
    db.refresh(stored_key)

    return stored_key


# ============================================================
# COMMON PAGINATION RESPONSE
# ============================================================

def paginated_response(items, total, limit, offset):
    return {
        "success": True,
        "total": total,
        "limit": limit,
        "offset": offset,
        "returned": len(items),
        "data": items,
    }


# ============================================================
# CLIENT AND PERMISSION AUTHORIZATION
# ============================================================

def require_client_permission(api_key, permission):
    if api_key.client_id is None:
        raise HTTPException(
            status_code=403,
            detail="This API key is not assigned to a client.",
        )

    permissions = api_key.permissions or []

    if not isinstance(permissions, list) or permission not in permissions:
        raise HTTPException(
            status_code=403,
            detail=f"API key does not have the required permission: {permission}",
        )


# ============================================================
# API STATUS
# ============================================================

@router.get("/status")
def external_api_status(
    authenticated_key: APIKey = Depends(
        get_authenticated_api_key
    ),
):
    return {
        "authenticated": True,
        "message": "External API authentication successful.",
        "api_key": {
            "id": authenticated_key.id,
            "name": authenticated_key.name,
            "key_prefix": authenticated_key.key_prefix,
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


# ============================================================
# SECURITY ALERTS
# ============================================================

@router.get("/alerts")
def get_external_alerts(
    severity: str | None = None,
    status: str | None = None,
    assessment_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    authenticated_key: APIKey = Depends(
        get_authenticated_api_key
    ),
    db: Session = Depends(get_db),
):
    require_client_permission(authenticated_key, "alerts:read")

    query = (
        db.query(SecurityEvent)
        .join(Assessment, SecurityEvent.assessment_id == Assessment.id)
        .join(User, Assessment.user_id == User.id)
        .filter(User.client_id == authenticated_key.client_id)
    )

    if severity:
        query = query.filter(
            SecurityEvent.severity.ilike(severity)
        )

    if status:
        query = query.filter(
            SecurityEvent.alert_status.ilike(status)
        )

    if assessment_id is not None:
        query = query.filter(
            SecurityEvent.assessment_id == assessment_id
        )

    total = query.count()

    events = (
        query.order_by(SecurityEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    items = [
        {
            "id": event.id,
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "source": event.source,
            "event_type": event.event_type,
            "severity": event.severity,
            "message": event.message,
            "target": event.target,
            "assessment_id": event.assessment_id,
            "mitre_technique_id": event.mitre_technique_id,
            "mitre_technique_name": event.mitre_technique_name,
            "mitre_tactic": event.mitre_tactic,
            "alert_status": event.alert_status,
            "acknowledged_at": event.acknowledged_at,
            "resolved_at": event.resolved_at,
            "created_at": event.created_at,
        }
        for event in events
    ]

    return paginated_response(
        items, total, limit, offset
    )


# ============================================================
# VULNERABILITY FINDINGS
# ============================================================

@router.get("/findings")
def get_external_findings(
    severity: str | None = None,
    status: str | None = None,
    assessment_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    authenticated_key: APIKey = Depends(
        get_authenticated_api_key
    ),
    db: Session = Depends(get_db),
):
    require_client_permission(authenticated_key, "findings:read")

    query = (
        db.query(SecurityFinding)
        .join(User, SecurityFinding.user_id == User.id)
        .filter(User.client_id == authenticated_key.client_id)
    )

    if severity:
        query = query.filter(
            SecurityFinding.severity.ilike(severity)
        )

    if status:
        query = query.filter(
            SecurityFinding.status.ilike(status)
        )

    if assessment_id is not None:
        query = query.filter(
            SecurityFinding.assessment_id == assessment_id
        )

    total = query.count()

    findings = (
        query.order_by(SecurityFinding.detected_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    items = [
        {
            "id": finding.id,
            "finding_id": finding.finding_id,
            "assessment_id": finding.assessment_id,
            "tool_name": finding.tool_name,
            "tool_category": finding.tool_category,
            "title": finding.title,
            "vulnerability": finding.vulnerability,
            "description": finding.description,
            "owasp_category": finding.owasp_category,
            "owasp_api_category": finding.owasp_api_category,
            "cve_id": finding.cve_id,
            "cwe_id": finding.cwe_id,
            "cvss_score": finding.cvss_score,
            "severity": finding.severity,
            "risk_level": finding.risk_level,
            "affected_asset": finding.affected_asset,
            "affected_url": finding.affected_url,
            "endpoint": finding.endpoint,
            "parameter": finding.parameter,
            "impact": finding.impact,
            "remediation": finding.remediation,
            "status": finding.status,
            "detected_at": finding.detected_at,
            "created_at": finding.created_at,
            "updated_at": finding.updated_at,
        }
        for finding in findings
    ]

    return paginated_response(
        items, total, limit, offset
    )


# ============================================================
# ASSESSMENTS
# ============================================================

@router.get("/assessments")
def get_external_assessments(
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    authenticated_key: APIKey = Depends(
        get_authenticated_api_key
    ),
    db: Session = Depends(get_db),
):
    require_client_permission(authenticated_key, "assessments:read")

    query = (
        db.query(Assessment)
        .join(User, Assessment.user_id == User.id)
        .filter(User.client_id == authenticated_key.client_id)
    )

    if status:
        query = query.filter(
            Assessment.overall_status.ilike(status)
        )

    total = query.count()

    assessments = (
        query.order_by(Assessment.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    items = [
        {
            "id": assessment.id,
            "target": assessment.target,
            "vapt_status": assessment.vapt_status,
            "vapt_findings_count": assessment.vapt_findings_count,
            "qa_status": assessment.qa_status,
            "qa_score": assessment.qa_score,
            "monitoring_status": assessment.monitoring_status,
            "report_status": assessment.report_status,
            "overall_status": assessment.overall_status,
            "created_at": assessment.created_at,
            "updated_at": assessment.updated_at,
        }
        for assessment in assessments
    ]

    return paginated_response(
        items, total, limit, offset
    )


# ============================================================
# SECURITY TOOL CATALOG
# ============================================================

@router.get("/tools")
def get_external_tools(
    category: str | None = None,
    tool_type: str | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    authenticated_key: APIKey = Depends(
        get_authenticated_api_key
    ),
    db: Session = Depends(get_db),
):
    require_client_permission(authenticated_key, "tools:read")

    query = db.query(SecurityTool).filter(
        SecurityTool.enabled.is_(True)
    )

    if category:
        query = query.filter(
            SecurityTool.category.ilike(category)
        )

    if tool_type:
        query = query.filter(
            SecurityTool.tool_type.ilike(tool_type)
        )

    total = query.count()

    tools = (
        query.order_by(
            SecurityTool.category.asc(),
            SecurityTool.name.asc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )

    items = [
        {
            "id": tool.id,
            "name": tool.name,
            "category": tool.category,
            "description": tool.description,
            "tool_type": tool.tool_type,
            "enabled": tool.enabled,
            "created_at": tool.created_at,
        }
        for tool in tools
    ]

    return paginated_response(
        items, total, limit, offset
    )
