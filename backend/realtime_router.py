from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from database import SessionLocal
from models import User, UserSession
from security import decode_access_token
from realtime_broadcaster import security_event_broadcaster


router = APIRouter(
    tags=["SOC Real-Time Events"],
)


@router.websocket("/ws/security-events")
async def security_events_websocket(websocket: WebSocket):
    """
    Authenticated real-time security-event stream.

    Only Analysts (role 2) and Admins (role 3) are allowed.
    The JWT must contain a valid jti linked to an active
    UserSession record.
    """

    token = websocket.query_params.get("token")

    if not token:
        await websocket.close(
            code=1008,
            reason="Authentication required",
        )
        return

    payload = decode_access_token(token)

    if not payload:
        await websocket.close(
            code=1008,
            reason="Invalid or expired token",
        )
        return

    user_id = payload.get("sub")
    session_jti = payload.get("jti")

    if not user_id or not session_jti:
        await websocket.close(
            code=1008,
            reason="Invalid session token",
        )
        return

    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        await websocket.close(
            code=1008,
            reason="Invalid user identity",
        )
        return

    db = SessionLocal()

    try:
        user = (
            db.query(User)
            .filter(User.id == user_id)
            .first()
        )

        if not user:
            await websocket.close(
                code=1008,
                reason="User not found",
            )
            return

        if user.role_id not in (2, 3):
            await websocket.close(
                code=1008,
                reason="Analyst or Admin access required",
            )
            return

        session = (
            db.query(UserSession)
            .filter(
                UserSession.jti == session_jti,
                UserSession.user_id == user_id,
            )
            .first()
        )

        if not session:
            await websocket.close(
                code=1008,
                reason="Session not found",
            )
            return

        if session.revoked_at is not None:
            await websocket.close(
                code=1008,
                reason="Session has been revoked",
            )
            return

        if session.expires_at <= datetime.utcnow():
            await websocket.close(
                code=1008,
                reason="Session has expired",
            )
            return

        if session.role_id != user.role_id:
            await websocket.close(
                code=1008,
                reason="Session role mismatch",
            )
            return

    except Exception:
        await websocket.close(
            code=1008,
            reason="Authentication validation failed",
        )
        return

    finally:
        db.close()

    await websocket.accept()

    queue = security_event_broadcaster.subscribe()

    try:
        while True:
            payload = await queue.get()
            await websocket.send_text(payload)

    except WebSocketDisconnect:
        pass

    except RuntimeError:
        pass

    finally:
        security_event_broadcaster.unsubscribe(queue)
