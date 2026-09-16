from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import get_db
from models import AuditLog, User
from rbac import require_role


router = APIRouter(
    prefix="/audit",
    tags=["Audit Trail"],
)


# ============================================================
# CREATE AUDIT LOG
# ============================================================

@router.post("/log")
def create_audit_log(
    request: Request,
    action: str = "",
    module: str | None = None,
    status: str = "SUCCESS",
    details: str | None = None,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """
    Create an audit record for the authenticated user.

    user_id and username are taken from the authenticated
    account instead of trusting values supplied by the client.
    """

    client_ip = request.client.host if request.client else None

    if not action.strip():
        raise HTTPException(
            status_code=400,
            detail="Audit action is required.",
        )

    audit = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=action.strip(),
        module=module,
        ip_address=client_ip,
        status=status,
        details=details,
        created_at=datetime.utcnow(),
    )

    db.add(audit)
    db.commit()
    db.refresh(audit)

    return {
        "message": "Audit log created successfully",
        "audit_id": audit.id,
    }


# ============================================================
# ADMIN - FULL AUDIT TRAIL
# ============================================================

@router.get("/logs")
def get_audit_logs(
    limit: int = 100,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    """
    Return the complete audit trail.

    Admin only.
    """

    limit = min(max(limit, 1), 500)

    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "username": log.username,
            "action": log.action,
            "module": log.module,
            "ip_address": log.ip_address,
            "status": log.status,
            "details": log.details,
            "created_at": (
                log.created_at.isoformat()
                if log.created_at
                else None
            ),
        }
        for log in logs
    ]


# ============================================================
# USER / ANALYST - MY ACTIVITY
# ============================================================

@router.get("/my-activity")
def get_my_activity(
    limit: int = 100,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """
    Return only audit records belonging to the authenticated
    user.

    The filtering is performed on the backend.
    """

    limit = min(max(limit, 1), 500)

    logs = (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == current_user.id
        )
        .order_by(
            AuditLog.created_at.desc()
        )
        .limit(limit)
        .all()
    )

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "username": log.username,
            "action": log.action,
            "module": log.module,
            "ip_address": log.ip_address,
            "status": log.status,
            "details": log.details,
            "created_at": (
                log.created_at.isoformat()
                if log.created_at
                else None
            ),
        }
        for log in logs
    ]