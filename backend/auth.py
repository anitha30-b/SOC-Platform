from datetime import datetime, timedelta
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from database import get_db
from models import User, Role, AuditLog, UserSession
from schemas import (
    UserCreate,
    UserResponse,
    LoginRequest,
    TokenResponse,
    UserMeResponse
)
from security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


security = HTTPBearer()


@router.post(
    "/register",
    response_model=UserResponse
)
def register_user(
    user_data: UserCreate,
    request: Request,
    db: Session = Depends(get_db)
):

    existing_user = db.query(User).filter(
        User.email == user_data.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    existing_username = db.query(User).filter(
        User.username == user_data.username
    ).first()

    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    client_role = db.query(Role).filter(
        Role.name == "Client"
    ).first()

    if not client_role:
        raise HTTPException(
            status_code=500,
            detail="Client role has not been created"
        )

    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        role_id=client_role.id
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    try:
        db.add(AuditLog(
            user_id=new_user.id,
            username=new_user.username,
            action="User registered",
            module="Authentication",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details="New client account registered",
        ))
        db.commit()
    except Exception:
        db.rollback()

    return new_user


@router.post(
    "/login",
    response_model=TokenResponse
)
def login_user(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(
        User.email == login_data.email
    ).first()

    if not user:
        try:
            db.add(AuditLog(
                user_id=None,
                username=login_data.email[:100],
                action="Login failed",
                module="Authentication",
                ip_address=request.client.host if request.client else None,
                status="FAILED",
                details="Login rejected: account not found",
            ))
            db.commit()
        except Exception:
            db.rollback()

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    password_valid = verify_password(
        login_data.password,
        user.hashed_password
    )

    if not password_valid:
        try:
            db.add(AuditLog(
                user_id=user.id,
                username=user.username,
                action="Login failed",
                module="Authentication",
                ip_address=request.client.host if request.client else None,
                status="FAILED",
                details="Login rejected: invalid password",
            ))
            db.commit()
        except Exception:
            db.rollback()

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    session_jti = secrets.token_urlsafe(32)
    session_created_at = datetime.utcnow()
    session_expires_at = session_created_at + timedelta(minutes=60)

    access_token = create_access_token({
        "sub": str(user.id),
        "username": user.username,
        "role_id": user.role_id,
        "jti": session_jti
    })

    db.add(UserSession(
        jti=session_jti,
        user_id=user.id,
        username=user.username,
        role_id=user.role_id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        created_at=session_created_at,
        expires_at=session_expires_at,
        last_activity_at=session_created_at,
    ))

    try:
        db.add(AuditLog(
            user_id=user.id,
            username=user.username,
            action="Login successful",
            module="Authentication",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details="User authenticated successfully",
        ))
        db.commit()
    except Exception:
        db.rollback()

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@router.post("/logout")
def logout_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    payload = decode_access_token(token)

    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    user_id = payload.get("sub")
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    session_jti = payload.get("jti")
    if session_jti:
        tracked_session = db.query(UserSession).filter(
            UserSession.jti == session_jti,
            UserSession.user_id == user.id,
            UserSession.revoked_at.is_(None),
        ).first()
        if tracked_session:
            tracked_session.revoked_at = datetime.utcnow()
            tracked_session.revocation_reason = "User logout"

    try:
        db.add(AuditLog(
            user_id=user.id,
            username=user.username,
            action="Logout successful",
            module="Authentication",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details="User logged out",
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not record logout audit event"
        )

    return {"message": "Logout recorded"}


@router.get(
    "/me",
    response_model=UserMeResponse
)
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):

    token = credentials.credentials

    payload = decode_access_token(token)

    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    session_jti = payload.get("jti")
    if session_jti:
        tracked_session = db.query(UserSession).filter(
            UserSession.jti == session_jti,
            UserSession.user_id == int(user_id),
        ).first()
        if (
            not tracked_session
            or tracked_session.revoked_at is not None
            or tracked_session.expires_at <= datetime.utcnow()
        ):
            raise HTTPException(
                status_code=401,
                detail="Session has expired or been terminated. Please log in again."
            )

    user = db.query(User).filter(
        User.id == int(user_id)
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return user