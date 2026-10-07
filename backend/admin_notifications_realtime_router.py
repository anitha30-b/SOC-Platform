from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from database import SessionLocal
from models import User
from notification_broadcaster import notification_broadcaster
from security import decode_access_token


router = APIRouter(
    tags=["Admin Notification Real-Time"],
)


@router.websocket("/ws/admin/notifications")
async def admin_notifications_websocket(
    websocket: WebSocket,
):
    token = websocket.query_params.get("token")

    if not token:
        await websocket.close(code=1008, reason="Authentication required")
        return

    payload = decode_access_token(token)

    if not payload:
        await websocket.close(code=1008, reason="Invalid or expired token")
        return

    user_id = payload.get("sub")

    if not user_id:
        await websocket.close(code=1008, reason="Invalid token")
        return

    db: Session = SessionLocal()

    try:
        user = db.query(User).filter(
            User.id == int(user_id)
        ).first()

        if not user:
            await websocket.close(code=1008, reason="User not found")
            return

        if user.role_id != 3:
            await websocket.close(code=1008, reason="Admin access required")
            return

    except (TypeError, ValueError):
        await websocket.close(code=1008, reason="Invalid token subject")
        return

    finally:
        db.close()

    await websocket.accept()

    queue = notification_broadcaster.subscribe()

    try:
        while True:
            payload = await queue.get()
            await websocket.send_text(payload)

    except WebSocketDisconnect:
        pass

    finally:
        notification_broadcaster.unsubscribe(queue)
