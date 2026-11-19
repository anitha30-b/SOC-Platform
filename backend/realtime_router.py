from fastapi import APIRouter, WebSocket


router = APIRouter(
    tags=["SOC Real-Time Events"],
)


@router.websocket("/ws/security-events")
async def security_events_websocket(websocket: WebSocket):
    """
    Deprecated insecure global event stream.
    Customer SIEM clients must use the authenticated tenant-scoped route.
    """
    await websocket.close(code=1008, reason="Authentication required")
