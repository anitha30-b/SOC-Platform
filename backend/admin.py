import hashlib
import secrets
from datetime import datetime

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import get_db
from models import (
    User,
    Role,
    Client,
    Assessment,
    SecurityTool,
    UserToolPermission,
    RoleToolPermission,
    ServiceAccount,
    APIKey,
    UserSession,
    AuditLog,
    Team,
    TeamMember,
)
from schemas import (
    UserCreate,
    UserClientAssign,
    SecurityToolResponse,
    UserToolPermissionDetail,
    UserToolPermissionsUpdate,
    RoleToolPermissionsUpdate,
)
from security import hash_password
from rbac import require_role


# ==================================================
# ADMIN ROUTER
# ==================================================

router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
)


# ==================================================
# ADMIN DASHBOARD
# ==================================================

@router.get("/dashboard")
def admin_dashboard(
    current_user: User = Depends(require_role(3)),
):
    return {
        "message": "Welcome to the Admin Dashboard",
        "user": current_user.username,
        "role": "Admin",
    }


@router.get("/roles")
def get_all_roles(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    roles = db.query(Role).order_by(Role.id).all()

    return {
        "total_roles": len(roles),
        "roles": [
            {
                "id": role.id,
                "name": role.name,
                "user_count": db.query(User).filter(
                    User.role_id == role.id
                ).count(),
                "tool_permission_count": db.query(RoleToolPermission).filter(
                    RoleToolPermission.role_id == role.id
                ).count(),
            }
            for role in roles
        ],
    }


# ==================================================
# USER MANAGEMENT
# ==================================================

@router.get("/users")
def get_all_users(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    users = db.query(User).all()

    return {
        "total_users": len(users),
        "users": [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role_id": user.role_id,
                "client_id": user.client_id,
            }
            for user in users
        ],
    }


# ==================================================
# CREATE USER
# ==================================================

@router.post("/users")
def create_user(
    user_data: UserCreate,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    existing_user = (
        db.query(User)
        .filter(User.email == user_data.email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered",
        )

    existing_username = (
        db.query(User)
        .filter(User.username == user_data.username)
        .first()
    )

    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already exists",
        )

    # Role 1 represents the single User/Client actor.
    user_role = (
        db.query(Role)
        .filter(Role.id == 1)
        .first()
    )

    if not user_role:
        raise HTTPException(
            status_code=500,
            detail="User role has not been created",
        )

    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(
            user_data.password
        ),
        role_id=user_role.id,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    try:
        db.add(AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action="User created",
            module="User Management",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details=f"Created user id={new_user.id}, username={new_user.username}",
        ))
        db.commit()
    except Exception:
        db.rollback()

    return {
        "message": "User created successfully",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "role_id": new_user.role_id,
        },
    }


# ==================================================
# LEGACY CLIENT ASSIGNMENT
# ==================================================
#
# Kept for compatibility with the current database.
#
# In the application design, User and Client are treated
# as the same actor. This endpoint is retained so existing
# data and older frontend code do not break.
# ==================================================

@router.put("/users/{user_id}/client")
def assign_user_to_client(
    user_id: int,
    assignment: UserClientAssign,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    client = (
        db.query(Client)
        .filter(Client.id == assignment.client_id)
        .first()
    )

    if not client:
        raise HTTPException(
            status_code=404,
            detail="Client not found",
        )

    previous_client_id = user.client_id
    user.client_id = client.id

    try:
        db.add(AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action="User client assignment updated",
            module="Admin Activity",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details=(
                f"Target user id={user.id}, username={user.username}; "
                f"previous client id={previous_client_id}; "
                f"new client id={client.id}, name={client.name}"
            ),
        ))
        db.commit()
        db.refresh(user)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Client assignment and audit record could not be saved.",
        )

    return {
        "message": "User assigned to client successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role_id": user.role_id,
            "client_id": user.client_id,
        },
        "client": {
            "id": client.id,
            "name": client.name,
            "organization": client.organization,
        },
    }

# ==================================================
# ASSESSMENT MONITORING
# ==================================================
#
# Admin can view assessments created by Users.
#
# Admin does NOT run VAPT here.
# Admin only monitors the assessment lifecycle:
#
# VAPT → QA → Live Monitoring → Report
# ==================================================

@router.get("/assessments")
def get_all_assessments(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    assessments = (
        db.query(Assessment)
        .order_by(
            Assessment.created_at.desc()
        )
        .all()
    )

    result = []

    for assessment in assessments:

        user = (
            db.query(User)
            .filter(
                User.id == assessment.user_id
            )
            .first()
        )

        result.append(
            {
                "id": assessment.id,

                # ----------------------------------
                # USER / CLIENT
                # ----------------------------------

                "user": {
                    "id": user.id
                    if user else None,

                    "username": user.username
                    if user else None,

                    "email": user.email
                    if user else None,
                },

                # ----------------------------------
                # TARGET
                # ----------------------------------

                "target": assessment.target,

                # ----------------------------------
                # VAPT
                # ----------------------------------

                "vapt_status": (
                    assessment.vapt_status
                ),

                "vapt_findings_count": (
                    assessment.vapt_findings_count
                ),

                # ----------------------------------
                # QA
                # ----------------------------------

                "qa_status": (
                    assessment.qa_status
                ),

                "qa_score": (
                    assessment.qa_score
                ),

                # ----------------------------------
                # LIVE MONITORING
                # ----------------------------------

                "monitoring_status": (
                    assessment.monitoring_status
                ),

                # ----------------------------------
                # REPORT
                # ----------------------------------

                "report_status": (
                    assessment.report_status
                ),

                # ----------------------------------
                # OVERALL
                # ----------------------------------

                "overall_status": (
                    assessment.overall_status
                ),

                # ----------------------------------
                # TIMESTAMPS
                # ----------------------------------

                "created_at": (
                    assessment.created_at
                ),

                "updated_at": (
                    assessment.updated_at
                ),
            }
        )

    return {
        "total_assessments": len(result),
        "assessments": result,
    }


# ==================================================
# ASSESSMENT DETAILS
# ==================================================

@router.get(
    "/assessments/{assessment_id}"
)
def get_assessment_details(
    assessment_id: int,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    assessment = (
        db.query(Assessment)
        .filter(
            Assessment.id == assessment_id
        )
        .first()
    )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found",
        )

    user = (
        db.query(User)
        .filter(
            User.id == assessment.user_id
        )
        .first()
    )

    return {
        "id": assessment.id,

        # ----------------------------------
        # USER / CLIENT
        # ----------------------------------

        "user": {
            "id": user.id
            if user else None,

            "username": user.username
            if user else None,

            "email": user.email
            if user else None,
        },

        # ----------------------------------
        # TARGET
        # ----------------------------------

        "target": assessment.target,

        # ----------------------------------
        # STATUS
        # ----------------------------------

        "vapt": {
            "status": assessment.vapt_status,
            "findings_count": (
                assessment.vapt_findings_count
            ),
        },

        "qa": {
            "status": assessment.qa_status,
            "score": assessment.qa_score,
        },

        "monitoring": {
            "status": assessment.monitoring_status,
        },

        "report": {
            "status": assessment.report_status,
        },

        "overall_status": (
            assessment.overall_status
        ),

        # ----------------------------------
        # TIMESTAMPS
        # ----------------------------------

        "created_at": assessment.created_at,
        "updated_at": assessment.updated_at,
    }

# ==================================================
# TOOL PERMISSIONS
# ==================================================
#
# Admin controls which individual security tools each
# User/Client is allowed to use.
#
# No permission record = DENIED.
# ==================================================

VAPT_PERMISSION_TOOL_NAMES = {
    'dig',
    'DNS Recon',
    'nslookup',
    'Ping',
    'WHOIS',
    'Masscan',
    'Nmap',
    'Nikto',
    'Nuclei',
    'OWASP ZAP',
    'hping3',
    'Snort',
    'TShark',
    'Wireshark',
    'Metasploit Framework',
    'Hydra',
    'John the Ripper',
    'Access / Impact Validation',
    'Risk Assessment Engine',
    'VAPT Report Generator',
}


@router.get(
    "/tool-permissions/tools",
    response_model=list[SecurityToolResponse],
)
def get_security_tools_for_permissions(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    """Return all enabled security tools available for Admin assignment."""
    return (
        db.query(SecurityTool)
        .filter(
            SecurityTool.enabled.is_(True),
            SecurityTool.name.in_(VAPT_PERMISSION_TOOL_NAMES),
        )
        .order_by(SecurityTool.category.asc(), SecurityTool.name.asc())
        .all()
    )


@router.get(
    "/users/{user_id}/tool-permissions",
    response_model=list[UserToolPermissionDetail],
)
def get_user_tool_permissions(
    user_id: int,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    """Return every enabled tool with the selected user's allow/deny state."""

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    tools = (
        db.query(SecurityTool)
        .filter(
            SecurityTool.enabled.is_(True),
            SecurityTool.name.in_(VAPT_PERMISSION_TOOL_NAMES),
        )
        .order_by(SecurityTool.category.asc(), SecurityTool.name.asc())
        .all()
    )

    permission_map = {
        permission.tool_id: permission
        for permission in db.query(UserToolPermission)
        .filter(UserToolPermission.user_id == user_id)
        .all()
    }

    return [
        {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "tool_id": tool.id,
            "tool_name": tool.name,
            "category": tool.category,
            "description": tool.description,
            "tool_type": tool.tool_type,
            "tool_enabled": tool.enabled,
            "allowed": (
                permission_map[tool.id].allowed
                if tool.id in permission_map else False
            ),
            "permission_state": (
                "allow"
                if permission_map[tool.id].allowed
                else "deny"
            ) if tool.id in permission_map else "inherit",
        }
        for tool in tools
    ]


@router.put(
    "/users/{user_id}/tool-permissions",
)
def update_user_tool_permissions(
    user_id: int,
    permission_data: UserToolPermissionsUpdate,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    """Replace individual overrides; omitted tools inherit role permissions."""

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    tools = (
        db.query(SecurityTool)
        .filter(
            SecurityTool.enabled.is_(True),
            SecurityTool.name.in_(VAPT_PERMISSION_TOOL_NAMES),
        )
        .all()
    )
    tool_by_id = {tool.id: tool for tool in tools}
    valid_tool_ids = set(tool_by_id)

    submitted_ids = [item.tool_id for item in permission_data.permissions]
    submitted_tool_ids = set(submitted_ids)

    if len(submitted_ids) != len(submitted_tool_ids):
        raise HTTPException(
            status_code=400,
            detail="Duplicate tool IDs are not allowed.",
        )

    invalid_tool_ids = submitted_tool_ids - valid_tool_ids
    if invalid_tool_ids:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "One or more tools are invalid or disabled",
                "tool_ids": sorted(invalid_tool_ids),
            },
        )

    previous_permissions = {
        permission.tool_id: permission.allowed
        for permission in db.query(UserToolPermission)
        .filter(UserToolPermission.user_id == user_id)
        .all()
    }

    new_permissions = {
        item.tool_id: item.allowed
        for item in permission_data.permissions
    }

    granted_ids = sorted(
        tool_id for tool_id, allowed in new_permissions.items()
        if allowed and previous_permissions.get(tool_id) is not True
    )
    denied_ids = sorted(
        tool_id for tool_id, allowed in new_permissions.items()
        if not allowed and previous_permissions.get(tool_id) is not False
    )
    inherited_ids = sorted(
        tool_id for tool_id in previous_permissions
        if tool_id not in submitted_tool_ids
    )
    allowed_ids = sorted(
        tool_id for tool_id, allowed in new_permissions.items() if allowed
    )

    try:
        db.query(UserToolPermission).filter(
            UserToolPermission.user_id == user_id,
            UserToolPermission.tool_id.in_(valid_tool_ids),
        ).delete(synchronize_session=False)

        for item in permission_data.permissions:
            db.add(
                UserToolPermission(
                    user_id=user_id,
                    tool_id=item.tool_id,
                    allowed=item.allowed,
                )
            )

        db.add(AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action="User tool permissions updated",
            module="Permission Changes",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details=(
                f"Target user id={user.id}, username={user.username}; "
                f"allowed tool IDs={granted_ids}; "
                f"denied tool IDs={denied_ids}; "
                f"changed to inherit tool IDs={inherited_ids}; "
                f"allowed tool IDs after update={allowed_ids}"
            ),
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Permission update failed; changes were rolled back.",
        )

    return {
        "message": "Individual tool permissions updated successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        },
        "allowed_tool_ids": allowed_ids,
        "denied_tool_ids": sorted(
            tool_id for tool_id, allowed in new_permissions.items() if not allowed
        ),
        "inherited_tool_ids": sorted(valid_tool_ids - submitted_tool_ids),
        "total_permissions": len(permission_data.permissions),
    }


# ==================================================
# ROLE-BASED TOOL PERMISSIONS
# ==================================================

@router.get("/roles/{role_id}/tool-permissions")
def get_role_tool_permissions(
    role_id: int,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    """Return enabled tools and their permission state for a role."""

    if role_id not in (1, 2):
        raise HTTPException(
            status_code=400,
            detail="Only Client and Analyst roles can be configured.",
        )

    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    tools = (
        db.query(SecurityTool)
        .filter(
            SecurityTool.enabled.is_(True),
            SecurityTool.name.in_(VAPT_PERMISSION_TOOL_NAMES),
        )
        .order_by(SecurityTool.category.asc(), SecurityTool.name.asc())
        .all()
    )

    permission_map = {
        permission.tool_id: permission.allowed
        for permission in db.query(RoleToolPermission)
        .filter(RoleToolPermission.role_id == role_id)
        .all()
    }

    return {
        "role_id": role.id,
        "role_name": role.name,
        "permissions": [
            {
                "tool_id": tool.id,
                "tool_name": tool.name,
                "category": tool.category,
                "description": tool.description,
                "tool_type": tool.tool_type,
                "tool_enabled": tool.enabled,
                "allowed": permission_map.get(tool.id, False),
            }
            for tool in tools
        ],
    }


@router.put("/roles/{role_id}/tool-permissions")
def update_role_tool_permissions(
    role_id: int,
    permission_data: RoleToolPermissionsUpdate,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    """Replace role permissions and record the change in the audit log."""

    if role_id not in (1, 2):
        raise HTTPException(
            status_code=400,
            detail="Only Client and Analyst roles can be configured.",
        )

    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    tools = (
        db.query(SecurityTool)
        .filter(
            SecurityTool.enabled.is_(True),
            SecurityTool.name.in_(VAPT_PERMISSION_TOOL_NAMES),
        )
        .all()
    )
    tool_by_id = {tool.id: tool for tool in tools}
    submitted_id_list = [
        item.tool_id for item in permission_data.permissions
    ]

    if len(submitted_id_list) != len(set(submitted_id_list)):
        raise HTTPException(
            status_code=400,
            detail="Duplicate tool IDs are not allowed.",
        )

    submitted_ids = set(submitted_id_list)

    invalid_ids = submitted_ids - set(tool_by_id)
    if invalid_ids:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "One or more tools are invalid or disabled.",
                "tool_ids": sorted(invalid_ids),
            },
        )

    previous_permissions = {
        permission.tool_id: permission.allowed
        for permission in db.query(RoleToolPermission)
        .filter(RoleToolPermission.role_id == role_id)
        .all()
    }

    new_permissions = {
        item.tool_id: item.allowed
        for item in permission_data.permissions
    }

    allowed_ids = sorted(
        tool_id
        for tool_id, allowed in new_permissions.items()
        if allowed
    )

    granted_ids = sorted(
        tool_id for tool_id in allowed_ids
        if previous_permissions.get(tool_id) is not True
    )

    revoked_ids = sorted(
        tool_id for tool_id, was_allowed in previous_permissions.items()
        if was_allowed and new_permissions.get(tool_id, False) is not True
    )

    granted_names = [
        tool_by_id[tool_id].name
        for tool_id in granted_ids if tool_id in tool_by_id
    ]
    revoked_names = [
        tool_by_id[tool_id].name
        for tool_id in revoked_ids if tool_id in tool_by_id
    ]

    try:
        db.query(RoleToolPermission).filter(
            RoleToolPermission.role_id == role_id,
            RoleToolPermission.tool_id.in_(set(tool_by_id)),
        ).delete(synchronize_session=False)

        for item in permission_data.permissions:
            db.add(
                RoleToolPermission(
                    role_id=role_id,
                    tool_id=item.tool_id,
                    allowed=item.allowed,
                )
            )

        db.add(AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action="Role tool permissions updated",
            module="Permission Changes",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details=(
                f"Target role id={role.id}, name={role.name}; "
                f"granted tool IDs={granted_ids} names={granted_names}; "
                f"revoked tool IDs={revoked_ids} names={revoked_names}; "
                f"allowed tool IDs after update={allowed_ids}"
            ),
        ))

        db.commit()

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Role permission update failed; changes were rolled back.",
        )

    return {
        "message": "Role tool permissions updated successfully.",
        "role_id": role.id,
        "role_name": role.name,
        "allowed_tool_ids": allowed_ids,
        "total_permissions": len(permission_data.permissions),
    }

# ==================================================
# SERVICE ACCOUNT MANAGEMENT
# ==================================================

@router.put("/service-accounts/{account_id}/status")
def update_service_account_status(
    account_id: int,
    request: Request,
    enabled: bool,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    account = db.query(ServiceAccount).filter(
        ServiceAccount.id == account_id
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Service account not found.")

    if account.revoked_at is not None:
        raise HTTPException(
            status_code=400,
            detail="A revoked service account cannot be reactivated.",
        )

    account.enabled = enabled

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="Service account activated" if enabled else "Service account deactivated",
        module="Service Account Management",
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
        details=f"Service account id={account.id}, name={account.name}",
    ))

    db.commit()

    return {
        "message": "Service account activated." if enabled else "Service account deactivated.",
        "id": account.id,
        "enabled": account.enabled,
    }


@router.post("/service-accounts/{account_id}/revoke")
def revoke_service_account(
    account_id: int,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    account = db.query(ServiceAccount).filter(
        ServiceAccount.id == account_id
    ).first()

    if not account:
        raise HTTPException(status_code=404, detail="Service account not found.")

    if account.revoked_at is not None:
        raise HTTPException(
            status_code=400,
            detail="Service account has already been revoked.",
        )

    account.enabled = False
    account.revoked_at = datetime.utcnow()

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="Service account revoked",
        module="Service Account Management",
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
        details=f"Revoked service account id={account.id}, name={account.name}",
    ))

    db.commit()

    return {
        "message": "Service account permanently revoked.",
        "id": account.id,
        "enabled": False,
        "revoked_at": account.revoked_at,
    }


@router.get("/service-accounts")
def get_service_accounts(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    accounts = (
        db.query(ServiceAccount)
        .order_by(ServiceAccount.created_at.desc())
        .all()
    )

    return {
        "total_accounts": len(accounts),
        "service_accounts": [
            {
                "id": account.id,
                "name": account.name,
                "description": account.description,
                "key_prefix": account.key_prefix,
                "role_id": account.role_id,
                "role_name": account.role.name if account.role else None,
                "enabled": account.enabled,
                "created_by": account.created_by,
                "created_at": account.created_at,
                "expires_at": account.expires_at,
                "last_used_at": account.last_used_at,
                "revoked_at": account.revoked_at,
            }
            for account in accounts
        ],
    }


@router.post("/service-accounts")
async def create_service_account(
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid request body.")

    name = str(data.get("name", "")).strip()
    description = str(data.get("description") or "").strip() or None
    role_id = data.get("role_id")

    if not name or len(name) > 150:
        raise HTTPException(
            status_code=400,
            detail="Name is required and must be at most 150 characters.",
        )

    if description and len(description) > 2000:
        raise HTTPException(
            status_code=400,
            detail="Description must be at most 2000 characters.",
        )

    try:
        role_id = int(role_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="A valid role ID is required.")

    if role_id not in (1, 2):
        raise HTTPException(
            status_code=400,
            detail="Service accounts can only use Client or Analyst roles.",
        )

    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Selected role not found.")

    expires_at = None
    if data.get("expires_at"):
        try:
            expires_at = datetime.fromisoformat(
                str(data["expires_at"]).replace("Z", "+00:00")
            )
            if expires_at.tzinfo is not None:
                expires_at = expires_at.astimezone().replace(tzinfo=None)
            if expires_at <= datetime.utcnow():
                raise ValueError()
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=400,
                detail="Expiry must be a valid future date and time.",
            )

    raw_key = "soc_" + secrets.token_urlsafe(36)
    key_prefix = raw_key[:12]
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    account = ServiceAccount(
        name=name,
        description=description,
        key_prefix=key_prefix,
        key_hash=key_hash,
        role_id=role_id,
        enabled=True,
        created_by=current_user.id,
        expires_at=expires_at,
    )

    try:
        db.add(account)
        db.flush()

        db.add(AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action="Service account created",
            module="Service Account Management",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details=(
                f"Created service account id={account.id}, "
                f"name={name}, role={role.name}"
            ),
        ))

        db.commit()
        db.refresh(account)

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Service account creation failed.",
        )

    return {
        "message": "Service account created successfully. Copy the API key now; it will not be shown again.",
        "service_account": {
            "id": account.id,
            "name": account.name,
            "key_prefix": account.key_prefix,
            "role_id": account.role_id,
            "role_name": role.name,
            "enabled": account.enabled,
            "expires_at": account.expires_at,
        },
        "api_key": raw_key,
    }




# ============================================================
# API KEY MANAGEMENT
# ============================================================

@router.get("/api-keys")
def get_api_keys(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    keys = db.query(APIKey).order_by(APIKey.created_at.desc()).all()
    return {
        "total_keys": len(keys),
        "api_keys": [
            {
                "id": key.id,
                "name": key.name,
                "description": key.description,
                "key_prefix": key.key_prefix,
                "enabled": key.enabled,
                "created_at": key.created_at,
                "expires_at": key.expires_at,
                "last_used_at": key.last_used_at,
                "revoked_at": key.revoked_at,
            }
            for key in keys
        ],
    }


@router.post("/api-keys")
async def create_api_key(
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    data = await request.json()
    name = str(data.get("name", "")).strip()
    description = data.get("description")
    if not name or len(name) > 150:
        raise HTTPException(status_code=400, detail="A name of 1–150 characters is required.")
    if description is not None and len(str(description)) > 2000:
        raise HTTPException(status_code=400, detail="Description must not exceed 2000 characters.")

    expires_at = None
    expiry = data.get("expires_at")
    if expiry:
        try:
            expires_at = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
            if expires_at.tzinfo is not None:
                from datetime import timezone
                expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)
            if expires_at <= datetime.utcnow():
                raise ValueError()
        except ValueError:
            raise HTTPException(status_code=400, detail="Expiry must be a valid future date and time.")

    raw_key = "soc_api_" + secrets.token_urlsafe(36)
    key = APIKey(
        name=name,
        description=str(description).strip() if description else None,
        key_prefix=raw_key[:12],
        key_hash=hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
        enabled=True,
        created_by=current_user.id,
        expires_at=expires_at,
    )
    db.add(key)
    db.flush()
    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="API key created",
        module="API Key Management",
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
        details=f"Created API key id={key.id}, name={name}",
    ))
    db.commit()
    db.refresh(key)

    return {
        "message": "API key created. Copy it now; it will not be shown again.",
        "api_key_record": {
            "id": key.id,
            "name": key.name,
            "key_prefix": key.key_prefix,
            "enabled": key.enabled,
            "expires_at": key.expires_at,
        },
        "api_key": raw_key,
    }


@router.put("/api-keys/{key_id}/status")
def update_api_key_status(
    key_id: int,
    request: Request,
    enabled: bool,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    key = db.query(APIKey).filter(APIKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found.")
    if key.revoked_at is not None:
        raise HTTPException(status_code=400, detail="A revoked API key cannot be reactivated.")

    key.enabled = enabled
    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="API key activated" if enabled else "API key deactivated",
        module="API Key Management",
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
        details=f"API key id={key.id}, name={key.name}",
    ))
    db.commit()
    return {"id": key.id, "enabled": key.enabled}


@router.post("/api-keys/{key_id}/revoke")
def revoke_api_key(
    key_id: int,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    key = db.query(APIKey).filter(APIKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found.")
    if key.revoked_at is not None:
        raise HTTPException(status_code=400, detail="API key has already been revoked.")

    key.enabled = False
    key.revoked_at = datetime.utcnow()
    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="API key revoked",
        module="API Key Management",
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
        details=f"Revoked API key id={key.id}, name={key.name}",
    ))
    db.commit()
    return {"message": "API key permanently revoked.", "id": key.id, "enabled": False}



# ==================================================
# CLIENT-SPECIFIC API KEY MANAGEMENT
# ==================================================

ALLOWED_EXTERNAL_API_PERMISSIONS = {
    "alerts:read",
    "findings:read",
    "assessments:read",
    "tools:read",
}


@router.post("/api-keys/client")
async def create_client_api_key(
    request: Request,
    data: dict = Body(...),
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):

    name = str(data.get("name", "")).strip()
    client_id = data.get("client_id")
    permissions = data.get("permissions", [])
    description = data.get("description")
    expiry = data.get("expires_at")

    if not name or len(name) > 150:
        raise HTTPException(
            status_code=400,
            detail="A name of 1-150 characters is required.",
        )

    if not isinstance(client_id, int) or isinstance(client_id, bool):
        raise HTTPException(
            status_code=400,
            detail="A valid client_id is required.",
        )

    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found.")

    if not isinstance(permissions, list) or not permissions:
        raise HTTPException(
            status_code=400,
            detail="Select at least one API permission.",
        )

    if any(not isinstance(item, str) for item in permissions):
        raise HTTPException(
            status_code=400,
            detail="Permissions must be strings.",
        )

    permissions = list(dict.fromkeys(permissions))
    invalid = set(permissions) - ALLOWED_EXTERNAL_API_PERMISSIONS

    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported permissions: {sorted(invalid)}",
        )

    if description is not None and len(str(description)) > 2000:
        raise HTTPException(
            status_code=400,
            detail="Description must not exceed 2000 characters.",
        )

    expires_at = None
    if expiry:
        try:
            expires_at = datetime.fromisoformat(
                str(expiry).replace("Z", "+00:00")
            )
            if expires_at.tzinfo is not None:
                from datetime import timezone
                expires_at = expires_at.astimezone(
                    timezone.utc
                ).replace(tzinfo=None)

            if expires_at <= datetime.utcnow():
                raise ValueError()
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Expiry must be a valid future date and time.",
            )

    raw_key = "soc_api_" + secrets.token_urlsafe(36)

    key = APIKey(
        name=name,
        description=str(description).strip() if description else None,
        key_prefix=raw_key[:12],
        key_hash=hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
        enabled=True,
        created_by=current_user.id,
        client_id=client.id,
        permissions=permissions,
        expires_at=expires_at,
    )

    db.add(key)
    db.flush()

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="Client API key created",
        module="API Key Management",
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
        details=(
            f"Created client API key id={key.id}, "
            f"client_id={client.id}, permissions={permissions}"
        ),
    ))

    db.commit()
    db.refresh(key)

    return {
        "message": "Client API key created. Copy it now; it will not be shown again.",
        "api_key_record": {
            "id": key.id,
            "name": key.name,
            "client_id": key.client_id,
            "client_name": client.name,
            "permissions": key.permissions,
            "key_prefix": key.key_prefix,
            "enabled": key.enabled,
            "expires_at": key.expires_at,
        },
        "api_key": raw_key,
    }


@router.get("/api-keys/clients")
def get_api_key_clients(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    clients = db.query(Client).order_by(Client.id).all()

    return {
        "total": len(clients),
        "clients": [
            {
                "id": client.id,
                "name": client.name,
                "organization": client.organization,
            }
            for client in clients
        ],
    }


# ==================================================
# ADMIN SESSION MANAGEMENT
# ==================================================

@router.get("/sessions")
def get_admin_sessions(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    sessions = (
        db.query(UserSession)
        .order_by(UserSession.created_at.desc())
        .all()
    )

    result = []
    for item in sessions:
        user = db.query(User).filter(User.id == item.user_id).first()
        if item.revoked_at is not None:
            status = "TERMINATED"
        elif item.expires_at <= now:
            status = "EXPIRED"
        else:
            status = "ACTIVE"

        result.append({
            "id": item.id,
            "user_id": item.user_id,
            "username": item.username,
            "role_id": item.role_id,
            "role": user.role.name if user and user.role else "Unknown",
            "ip_address": item.ip_address,
            "user_agent": item.user_agent,
            "created_at": item.created_at,
            "expires_at": item.expires_at,
            "last_activity_at": item.last_activity_at,
            "revoked_at": item.revoked_at,
            "revocation_reason": item.revocation_reason,
            "status": status,
        })

    return {
        "total": len(result),
        "active": sum(1 for x in result if x["status"] == "ACTIVE"),
        "expired": sum(1 for x in result if x["status"] == "EXPIRED"),
        "terminated": sum(1 for x in result if x["status"] == "TERMINATED"),
        "sessions": result,
    }


@router.post("/sessions/{session_id}/terminate")
def terminate_admin_session(
    session_id: int,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    item = db.query(UserSession).filter(
        UserSession.id == session_id
    ).first()

    if not item:
        raise HTTPException(status_code=404, detail="Session not found")

    if item.revoked_at is not None:
        raise HTTPException(status_code=400, detail="Session is already terminated")

    item.revoked_at = datetime.utcnow()
    item.revoked_by = current_user.id
    item.revocation_reason = "Terminated by administrator"

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="User session terminated",
        module="Session Management",
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
        details=f"Terminated session id={item.id}, user id={item.user_id}, username={item.username}",
    ))
    db.commit()

    return {"message": "Session terminated successfully", "session_id": item.id}


@router.post("/sessions/user/{user_id}/terminate")
def terminate_user_sessions(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    now = datetime.utcnow()
    sessions = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.revoked_at.is_(None),
        UserSession.expires_at > now,
    ).all()

    for item in sessions:
        item.revoked_at = now
        item.revoked_by = current_user.id
        item.revocation_reason = "All sessions terminated by administrator"

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="All user sessions terminated",
        module="Session Management",
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
        details=f"Terminated {len(sessions)} active session(s) for user id={user_id}, username={target_user.username}",
    ))
    db.commit()

    return {
        "message": "User sessions terminated successfully",
        "user_id": user_id,
        "terminated_count": len(sessions),
    }


# ==================================================
# TEAM MANAGEMENT
# ==================================================

@router.get("/teams")
def get_teams(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    teams = db.query(Team).order_by(Team.created_at.desc()).all()

    return {
        "total": len(teams),
        "teams": [
            {
                "id": team.id,
                "name": team.name,
                "description": team.description,
                "created_at": team.created_at,
                "member_count": len(team.members),
                "members": [
                    {
                        "id": member.user.id,
                        "username": member.user.username,
                        "email": member.user.email,
                        "role_id": member.user.role_id,
                        "client_id": member.user.client_id,
                    }
                    for member in team.members
                    if member.user is not None
                ],
            }
            for team in teams
        ],
    }


@router.post("/teams")
def create_team(
    data: dict = Body(...),
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    name = str(data.get("name", "")).strip()
    description = data.get("description")

    if not name or len(name) > 150:
        raise HTTPException(status_code=400, detail="Team name must contain 1-150 characters.")

    if description is not None and len(str(description)) > 2000:
        raise HTTPException(status_code=400, detail="Description is too long.")

    if db.query(Team).filter(Team.name.ilike(name)).first():
        raise HTTPException(status_code=409, detail="A team with this name already exists.")

    team = Team(
        name=name,
        description=str(description).strip() if description else None,
        created_by=current_user.id,
    )
    db.add(team)
    db.commit()
    db.refresh(team)

    return {"message": "Team created successfully.", "team_id": team.id}


@router.put("/teams/{team_id}")
def update_team(
    team_id: int,
    data: dict = Body(...),
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    team = db.query(Team).filter(Team.id == team_id).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found.")

    if "name" in data:
        name = str(data["name"]).strip()
        if not name or len(name) > 150:
            raise HTTPException(status_code=400, detail="Invalid team name.")
        duplicate = db.query(Team).filter(
            Team.name.ilike(name), Team.id != team_id
        ).first()
        if duplicate:
            raise HTTPException(status_code=409, detail="Team name already exists.")
        team.name = name

    if "description" in data:
        description = data["description"]
        if description is not None and len(str(description)) > 2000:
            raise HTTPException(status_code=400, detail="Description is too long.")
        team.description = str(description).strip() if description else None

    db.commit()
    return {"message": "Team updated successfully."}


@router.delete("/teams/{team_id}")
def delete_team(
    team_id: int,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    team = db.query(Team).filter(Team.id == team_id).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found.")

    db.delete(team)
    db.commit()
    return {"message": "Team and its team memberships deleted successfully."}


@router.post("/teams/{team_id}/members")
def add_team_member(
    team_id: int,
    data: dict = Body(...),
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    team = db.query(Team).filter(Team.id == team_id).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found.")

    user_id = data.get("user_id")
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        raise HTTPException(status_code=400, detail="A valid user_id is required.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    existing = db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == user_id,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="User is already a member of this team.")

    membership = TeamMember(team_id=team_id, user_id=user_id)
    db.add(membership)
    db.commit()

    return {"message": "User added to team successfully."}


@router.delete("/teams/{team_id}/members/{user_id}")
def remove_team_member(
    team_id: int,
    user_id: int,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    membership = db.query(TeamMember).filter(
        TeamMember.team_id == team_id,
        TeamMember.user_id == user_id,
    ).first()

    if not membership:
        raise HTTPException(status_code=404, detail="Team membership not found.")

    db.delete(membership)
    db.commit()
    return {"message": "User removed from team successfully."}
