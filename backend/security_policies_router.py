import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import get_db
from models import SecurityPolicy, AuditLog, User
from rbac import require_role


router = APIRouter(
    prefix="/admin/security-policies",
    tags=["Admin Security Policies"],
)


VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class SecurityPolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    category: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1)
    severity: str = "MEDIUM"
    enabled: bool = True
    policy_content: str | None = None


class SecurityPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    category: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, min_length=1)
    severity: str | None = None
    enabled: bool | None = None
    policy_content: str | None = None


def serialize_policy(policy):
    return {
        "id": policy.id,
        "name": policy.name,
        "category": policy.category,
        "description": policy.description,
        "severity": policy.severity,
        "enabled": policy.enabled,
        "policy_content": policy.policy_content,
        "created_by": policy.created_by,
        "created_at": policy.created_at.isoformat() if policy.created_at else None,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
    }


def validate_severity(value):
    value = str(value or "MEDIUM").strip().upper()
    if value not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail="severity must be LOW, MEDIUM, HIGH, or CRITICAL.",
        )
    return value


def record_audit(db, request, current_user, action, details):
    db.add(
        AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action=action,
            module="Security Policies",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details=details,
        )
    )


@router.get("")
def list_security_policies(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    policies = (
        db.query(SecurityPolicy)
        .order_by(SecurityPolicy.created_at.desc())
        .all()
    )
    return {
        "count": len(policies),
        "policies": [serialize_policy(item) for item in policies],
    }


@router.post("")
def create_security_policy(
    payload: SecurityPolicyCreate,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Policy name cannot be empty.")

    existing = db.query(SecurityPolicy).filter(
        SecurityPolicy.name == name
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="A policy with this name already exists.")

    policy = SecurityPolicy(
        name=name,
        category=payload.category.strip(),
        description=payload.description.strip(),
        severity=validate_severity(payload.severity),
        enabled=payload.enabled,
        policy_content=payload.policy_content,
        created_by=current_user.username,
    )

    try:
        db.add(policy)
        db.flush()
        record_audit(
            db, request, current_user, "Security policy created",
            f"Created policy id={policy.id}, name={policy.name}, "
            f"category={policy.category}, severity={policy.severity}, enabled={policy.enabled}",
        )
        db.commit()
        db.refresh(policy)
        return {"message": "Security policy created successfully", "policy": serialize_policy(policy)}
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="A policy with this name already exists.")
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Could not create security policy.")


@router.put("/{policy_id}")
def update_security_policy(
    policy_id: int,
    payload: SecurityPolicyUpdate,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    policy = db.query(SecurityPolicy).filter(
        SecurityPolicy.id == policy_id
    ).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Security policy not found.")

    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No changes supplied.")

    if "name" in changes:
        changes["name"] = (changes["name"] or "").strip()
        if not changes["name"]:
            raise HTTPException(status_code=400, detail="Policy name cannot be empty.")
        duplicate = db.query(SecurityPolicy).filter(
            SecurityPolicy.name == changes["name"],
            SecurityPolicy.id != policy_id,
        ).first()
        if duplicate:
            raise HTTPException(status_code=409, detail="A policy with this name already exists.")

    if "category" in changes:
        changes["category"] = (changes["category"] or "").strip()
        if not changes["category"]:
            raise HTTPException(status_code=400, detail="Category cannot be empty.")

    if "description" in changes:
        changes["description"] = (changes["description"] or "").strip()
        if not changes["description"]:
            raise HTTPException(status_code=400, detail="Description cannot be empty.")

    if "severity" in changes and changes["severity"] is not None:
        changes["severity"] = validate_severity(changes["severity"])

    before = {
        key: getattr(policy, key)
        for key in changes
    }

    try:
        for key, value in changes.items():
            setattr(policy, key, value)

        record_audit(
            db, request, current_user, "Security policy updated",
            f"Policy id={policy.id}; before={json.dumps(before, default=str)}; "
            f"after={json.dumps(changes, default=str)}",
        )
        db.commit()
        db.refresh(policy)
        return {"message": "Security policy updated successfully", "policy": serialize_policy(policy)}
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="A policy with this name already exists.")
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Could not update security policy.")


@router.patch("/{policy_id}/status")
def set_security_policy_status(
    policy_id: int,
    enabled: bool,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    policy = db.query(SecurityPolicy).filter(
        SecurityPolicy.id == policy_id
    ).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Security policy not found.")

    previous = policy.enabled
    policy.enabled = enabled

    try:
        record_audit(
            db, request, current_user, "Security policy status changed",
            f"Policy id={policy.id}, name={policy.name}, "
            f"enabled changed from {previous} to {enabled}",
        )
        db.commit()
        db.refresh(policy)
        return {"message": "Security policy status updated", "policy": serialize_policy(policy)}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Could not update policy status.")


@router.delete("/{policy_id}")
def delete_security_policy(
    policy_id: int,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    policy = db.query(SecurityPolicy).filter(
        SecurityPolicy.id == policy_id
    ).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Security policy not found.")

    details = (
        f"Deleted policy id={policy.id}, name={policy.name}, "
        f"category={policy.category}, severity={policy.severity}, enabled={policy.enabled}"
    )

    try:
        record_audit(
            db, request, current_user, "Security policy deleted", details
        )
        db.delete(policy)
        db.commit()
        return {"message": "Security policy deleted successfully", "id": policy_id}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Could not delete security policy.")
