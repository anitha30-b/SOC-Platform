from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from database import SessionLocal
from models import User
from security import decode_access_token
from user_notification_broadcaster import user_notification_broadcaster

router = APIRouter()


@router.websocket("/ws/notifications")
async def user_notifications_websocket(websocket: WebSocket):
    token = websocket.query_params.get("token")

    if not token:
        await websocket.close(code=1008)
        return

    db = SessionLocal()

    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")

        if not user_id:
            await websocket.close(code=1008)
            return

        user = db.query(User).filter(User.id == int(user_id)).first()

        if not user or user.role_id != 1:
            await websocket.close(code=1008)
            return

        await websocket.accept()

        queue = user_notification_broadcaster.subscribe(user.id)

        try:
            while True:
                notification = await queue.get()
                await websocket.send_text(notification)

        except WebSocketDisconnect:
            pass

        finally:
            user_notification_broadcaster.unsubscribe(user.id, queue)

    except Exception:
        try:
            await websocket.close(code=1008)
        except Exception:
            pass

    finally:
        db.close()
