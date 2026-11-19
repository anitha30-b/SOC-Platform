from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from database import get_db
from models import User, UserSession
from security import decode_access_token
from datetime import datetime


security = HTTPBearer()


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


def require_role(required_role_id: int):

    def role_checker(
        current_user: User = Depends(get_current_user)
    ):

        if current_user.role_id != required_role_id:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to access this resource"
            )

        return current_user

    return role_checker