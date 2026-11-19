import json
from pathlib import Path
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from models import User
from rbac import require_role

router = APIRouter(prefix="/system", tags=["Admin System Logs"])

ACCESS_LOG_FILE = (
    Path(__file__).resolve().parent
    / "runtime_logs"
    / "access.log"
)


@router.get("/logs")
def get_system_logs(
    search: str = Query(default="", max_length=200),
    status: str = Query(default="all"),
    limit: int = Query(default=200, ge=1, le=1000),
    current_user: User = Depends(require_role(3)),
):
    allowed_statuses = {"all", "2xx", "4xx", "5xx"}

    if status not in allowed_statuses:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail="Status must be all, 2xx, 4xx or 5xx.",
        )

    logs = []

    if ACCESS_LOG_FILE.exists():
        try:
            with ACCESS_LOG_FILE.open(
                "r", encoding="utf-8", errors="replace"
            ) as file:
                lines = file.readlines()[-limit:]
        except OSError:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=500,
                detail="Unable to read system access logs.",
            )

        for index, line in enumerate(lines):
            try:
                entry = json.loads(line)
                code = int(entry.get("status_code", 0))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue

            if status == "2xx" and not 200 <= code < 300:
                continue
            if status == "4xx" and not 400 <= code < 500:
                continue
            if status == "5xx" and not 500 <= code < 600:
                continue

            record = {
                "id": f"access-{index}-{entry.get('timestamp', '')}",
                "timestamp": entry.get("timestamp", ""),
                "method": entry.get("method", "—"),
                "path": entry.get("path", "—"),
                "status_code": code,
                "duration_ms": entry.get("duration_ms", 0),
                "client_ip": entry.get("client_ip", "—"),
            }

            searchable = " ".join(str(value) for value in record.values())
            if search.strip().lower() in searchable.lower():
                logs.append(record)

    logs.reverse()

    return {
        "logs": logs,
        "count": len(logs),
        "source": str(ACCESS_LOG_FILE),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
