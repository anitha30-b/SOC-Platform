from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import (
    User,
    Role,
    Client,
    Assessment,
)
from schemas import (
    UserCreate,
    UserClientAssign,
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
        .filter(
            Client.id == assignment.client_id
        )
        .first()
    )

    if not client:
        raise HTTPException(
            status_code=404,
            detail="Client not found",
        )

    user.client_id = client.id

    db.commit()
    db.refresh(user)

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