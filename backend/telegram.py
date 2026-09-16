import hashlib
import os
import secrets
from datetime import datetime, timedelta

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import TelegramLinkToken, User


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/telegram",
    tags=["Telegram Integration"],
)


# ============================================================
# CONFIGURATION
# ============================================================

TELEGRAM_BOT_USERNAME = os.getenv(
    "TELEGRAM_BOT_USERNAME",
    "SOC_Security_Platform_Bot",
)

LINK_TOKEN_MINUTES = 10


# ============================================================
# HELPER — HASH TEMPORARY TOKEN
# ============================================================

def hash_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


# ============================================================
# HELPER — USER ROLE CHECK
# ============================================================

def require_user(current_user: User):
    """
    Role 1 = User / Client
    """

    if current_user.role_id != 1:
        raise HTTPException(
            status_code=403,
            detail="Only users can connect a Telegram account.",
        )


# ============================================================
# CREATE TELEGRAM CONNECTION LINK
# ============================================================

@router.post("/connect")
def create_telegram_connection(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_user(current_user)

    # --------------------------------------------------------
    # Already connected
    # --------------------------------------------------------

    if current_user.telegram_connected:
        return {
            "connected": True,
            "message": "Telegram is already connected.",
            "telegram_username": current_user.telegram_username,
        }

    # --------------------------------------------------------
    # Invalidate old unused tokens
    # --------------------------------------------------------

    old_tokens = (
        db.query(TelegramLinkToken)
        .filter(
            TelegramLinkToken.user_id == current_user.id,
            TelegramLinkToken.used == False,
        )
        .all()
    )

    for old_token in old_tokens:
        old_token.used = True

    # --------------------------------------------------------
    # Generate cryptographically secure temporary token
    # --------------------------------------------------------

    raw_token = secrets.token_urlsafe(32)

    token_hash = hash_token(raw_token)

    expires_at = datetime.utcnow() + timedelta(
        minutes=LINK_TOKEN_MINUTES
    )

    link_token = TelegramLinkToken(
        user_id=current_user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        used=False,
        created_at=datetime.utcnow(),
    )

    db.add(link_token)
    db.commit()

    # --------------------------------------------------------
    # Telegram deep link
    # --------------------------------------------------------

    telegram_link = (
        f"https://t.me/"
        f"{TELEGRAM_BOT_USERNAME}"
        f"?start={raw_token}"
    )

    return {
        "connected": False,
        "message": "Telegram connection link created.",
        "telegram_username": TELEGRAM_BOT_USERNAME,
        "telegram_link": telegram_link,
        "expires_in_minutes": LINK_TOKEN_MINUTES,
    }


# ============================================================
# TELEGRAM CONNECTION STATUS
# ============================================================

@router.get("/status")
def telegram_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_user(current_user)

    return {
        "connected": bool(current_user.telegram_connected),
        "telegram_username": current_user.telegram_username,
        "connected_at": (
            current_user.telegram_connected_at.isoformat()
            if current_user.telegram_connected_at
            else None
        ),
    }