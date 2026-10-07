from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from realtime_broadcaster import security_event_broadcaster


router = APIRouter(
    tags=["SOC Real-Time Events"],
)


@router.websocket("/ws/security-events")
async def security_events_websocket(
    websocket: WebSocket,
):
    """
    Stream newly processed SOC security events
    to connected WebSocket clients.
    """

    await websocket.accept()

    queue = security_event_broadcaster.subscribe()

    try:
        while True:
            payload = await queue.get()
            await websocket.send_text(payload)

    except WebSocketDisconnect:
        pass

    finally:
        security_event_broadcaster.unsubscribe(queue)