from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from models import BackgroundJob
from models import User
from rbac import require_role
from vapt import NMAP_JOBS, MASSCAN_JOBS, NIKTO_JOBS

router = APIRouter(prefix="/background-jobs", tags=["Background Jobs"])


def to_iso(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    return str(value)


@router.get("")
def list_background_jobs(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    # Load persistent history from PostgreSQL.
    records = (
        db.query(BackgroundJob)
        .order_by(BackgroundJob.created_at.desc())
        .limit(500)
        .all()
    )

    jobs = []
    for record in records:
        created = record.created_at
        updated = record.updated_at
        duration = (
            max(0, int((updated - created).total_seconds()))
            if created and updated else None
        )
        jobs.append({
            "job_id": record.job_id,
            "tool": record.tool,
            "target": record.target,
            "scan_type": record.scan_type or "",
            "status": str(record.status).upper(),
            "progress": record.progress,
            "stage": record.stage or "",
            "created_at": created.isoformat() if created else None,
            "updated_at": updated.isoformat() if updated else None,
            "duration_seconds": duration,
            "error": record.error,
        })

    counts = {
        "queued": sum(j["status"] == "QUEUED" for j in jobs),
        "running": sum(j["status"] == "RUNNING" for j in jobs),
        "completed": sum(
            j["status"] in {"COMPLETED", "COMPLETED_WITH_ERRORS"}
            for j in jobs
        ),
        "failed": sum(j["status"] == "FAILED" for j in jobs),
    }

    return {
        "total": len(jobs),
        **counts,
        "jobs": jobs,
        "source": "PostgreSQL background job history",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
