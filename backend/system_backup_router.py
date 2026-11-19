import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.engine import URL
from database import engine
from models import User
from rbac import require_role

router = APIRouter(prefix="/system/backups", tags=["Admin Backups"])

BACKUP_DIR = Path(__file__).resolve().parent / "runtime_backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

FILENAME_PATTERN = re.compile(
    r"^soc_platform_\d{8}T\d{6}Z_[0-9a-f]{8}\.dump$"
)


def admin_only():
    return Depends(require_role(3))


def list_backups():
    records = []

    for path in BACKUP_DIR.iterdir():
        if not path.is_file() or not FILENAME_PATTERN.fullmatch(path.name):
            continue

        stat = path.stat()
        records.append({
            "filename": path.name,
            "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(
                stat.st_mtime, timezone.utc
            ).isoformat(),
            "status": "available",
        })

    return sorted(records, key=lambda item: item["created_at"], reverse=True)


@router.get("")
def get_backups(current_user: User = Depends(require_role(3))):
    return {
        "backups": list_backups(),
        "count": len(list_backups()),
    }


@router.post("")
def create_backup(current_user: User = Depends(require_role(3))):
    db_url = engine.url

    if not isinstance(db_url, URL) or db_url.get_backend_name() != "postgresql":
        raise HTTPException(
            status_code=500,
            detail="The configured database is not PostgreSQL.",
        )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"soc_platform_{timestamp}_{uuid.uuid4().hex[:8]}.dump"
    destination = BACKUP_DIR / filename
    temporary = BACKUP_DIR / f".{filename}.partial"

    env = os.environ.copy()
    env.pop("PGPASSWORD", None)

    if db_url.password:
        env["PGPASSWORD"] = db_url.password

    command = [
        "pg_dump",
        "--format=custom",
        "--no-owner",
        "--no-privileges",
        "--file", str(temporary),
        "--dbname", db_url.database or "",
    ]

    if db_url.username:
        command.extend(["--username", db_url.username])
    if db_url.host:
        command.extend(["--host", db_url.host])
    if db_url.port:
        command.extend(["--port", str(db_url.port)])

    query = dict(db_url.query)
    if query.get("sslmode"):
        env["PGSSLMODE"] = str(query["sslmode"])

    try:
        result = subprocess.run(
            command,
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )

        if result.returncode != 0:
            temporary.unlink(missing_ok=True)
            raise HTTPException(
                status_code=500,
                detail="Database backup failed. Check backend logs and database permissions.",
            )

        if not temporary.exists() or temporary.stat().st_size == 0:
            temporary.unlink(missing_ok=True)
            raise HTTPException(
                status_code=500,
                detail="Backup failed: PostgreSQL produced an empty archive.",
            )

        os.replace(temporary, destination)

    except subprocess.TimeoutExpired:
        temporary.unlink(missing_ok=True)
        raise HTTPException(
            status_code=504,
            detail="Backup timed out. Check database size and backend logs.",
        )
    except HTTPException:
        raise
    except Exception:
        temporary.unlink(missing_ok=True)
        raise HTTPException(
            status_code=500,
            detail="Unable to create database backup.",
        )

    return {
        "message": "Database backup created successfully.",
        "backup": {
            "filename": filename,
            "size_bytes": destination.stat().st_size,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "available",
        },
    }


@router.get("/{filename}/download")
def download_backup(
    filename: str,
    current_user: User = Depends(require_role(3)),
):
    if not FILENAME_PATTERN.fullmatch(filename):
        raise HTTPException(status_code=400, detail="Invalid backup filename.")

    path = BACKUP_DIR / filename

    if not path.is_file():
        raise HTTPException(status_code=404, detail="Backup file not found.")

    return FileResponse(
        path=str(path),
        filename=filename,
        media_type="application/octet-stream",
    )
