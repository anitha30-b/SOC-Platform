"""Session-authenticated analyst/admin event stream.

Role-1 clients use the separate tenant-scoped client_realtime_events router.
Database sessions remain inside worker threads, including revalidation.
"""
import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from database import SessionLocal
from models import User, UserSession
from security import decode_access_token
from realtime_broadcaster import security_event_broadcaster

router = APIRouter(tags=["SOC Real-Time Events"])


def _admin_ws_session_valid(user_id, session_jti):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user is None or user.role_id not in (2, 3):
            return False
        session = db.query(UserSession).filter(
            UserSession.jti == session_jti,
            UserSession.user_id == user_id,
        ).first()
        if session is None or session.revoked_at is not None:
            return False
        expiry = session.expires_at
        if expiry is None:
            return False
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return (
            expiry > datetime.now(timezone.utc)
            and session.role_id == user.role_id
        )
    finally:
        db.close()


@router.websocket("/ws/security-events")
async def security_events_websocket(websocket: WebSocket):
    token = websocket.query_params.get("token")
    try:
        payload = decode_access_token(token) if token else None
        if not payload or not payload.get("sub") or not payload.get("jti"):
            await websocket.close(code=1008, reason="Authentication required")
            return
        user_id = int(payload["sub"])
        session_jti = payload["jti"]
        authorized = await asyncio.to_thread(
            _admin_ws_session_valid, user_id, session_jti
        )
        if not authorized:
            await websocket.close(code=1008, reason="Valid SOC session required")
            return
    except Exception:
        await websocket.close(code=1008, reason="Authentication validation failed")
        return

    await websocket.accept()
    queue = security_event_broadcaster.subscribe()
    try:
        while True:
            event_task = asyncio.create_task(queue.get())
            receive_task = asyncio.create_task(websocket.receive_text())
            tasks = {event_task, receive_task}
            try:
                done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                pending_tasks = [task for task in tasks if not task.done()]
                for task in pending_tasks:
                    task.cancel()
                if pending_tasks:
                    await asyncio.gather(*pending_tasks, return_exceptions=True)

            if receive_task in done:
                receive_task.result()
            if event_task not in done:
                continue

            # Revocation, expiry, and role changes apply before each message.
            authorized = bool(decode_access_token(token)) and await asyncio.to_thread(
                _admin_ws_session_valid, user_id, session_jti
            )
            if not authorized:
                await websocket.close(code=1008, reason="Session no longer valid")
                return
            await websocket.send_text(event_task.result())
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
    finally:
        security_event_broadcaster.unsubscribe(queue)
