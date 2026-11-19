from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from assets_router import Asset, require_role
from server_monitor import ServerMonitorResult

router = APIRouter(tags=["Server Monitoring"])


@router.get("/monitoring/servers/latest")
def get_latest_server_monitoring(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(3)),
):
    rows = (
        db.query(ServerMonitorResult, Asset)
        .join(Asset, Asset.id == ServerMonitorResult.asset_id)
        .order_by(Asset.name.asc())
        .all()
    )

    return {
        "total": len(rows),
        "servers": [
            {
                "asset_id": asset.id,
                "name": asset.name,
                "ip_address": asset.ip_address,
                "status": result.status,
                "port": result.port,
                "response_time_ms": result.response_time_ms,
                "checked_at": result.checked_at.isoformat(),
                "reason": result.reason,
            }
            for result, asset in rows
        ],
    }
