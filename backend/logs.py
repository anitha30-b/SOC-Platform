import json
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import Assessment, User
from rbac import require_role


# ==================================================
# ROUTER
# ==================================================

router = APIRouter(
    prefix="/logs",
    tags=["Live Log Monitoring"],
)


# ==================================================
# PATHS
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

ACCESS_LOG_FILE = (
    BASE_DIR
    / "runtime_logs"
    / "access.log"
)


# ==================================================
# TARGET SCHEMAS
# ==================================================

class MonitoringStartRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        max_length=500,
    )


class MonitoringStopRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        max_length=500,
    )


# ==================================================
# TARGET HELPERS
# ==================================================

def normalize_target(
    target: str,
) -> str:
    """
    Treat:
        http://example.com
    and:
        http://example.com/

    as the same assessment target.
    """

    return target.strip().rstrip("/")


def find_user_assessment(
    db: Session,
    current_user: User,
    target: str,
):
    """
    Find the assessment belonging to the current User
    and matching the selected VAPT target.
    """

    normalized_target = normalize_target(
        target
    )

    assessments = (
        db.query(Assessment)
        .filter(
            Assessment.user_id
            == current_user.id
        )
        .order_by(
            Assessment.created_at.desc()
        )
        .all()
    )

    for assessment in assessments:

        if (
            normalize_target(
                assessment.target
            )
            == normalized_target
        ):
            return assessment

    return None


# ==================================================
# JOURNAL READER
# ==================================================

def read_journal(
    limit: int = 100,
    search: Optional[str] = None,
):
    command = [
        "journalctl",
        "--no-pager",
        "-n",
        str(limit),
        "--output",
        "short-iso",
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    except subprocess.TimeoutExpired:

        raise HTTPException(
            status_code=504,
            detail="Journal query timed out.",
        )

    except OSError as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to access system journal: "
                f"{exc}"
            ),
        )

    if result.returncode != 0:

        raise HTTPException(
            status_code=500,
            detail=(
                result.stderr.strip()
                or
                "journalctl returned an error."
            ),
        )

    lines = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    if search:

        search_value = (
            search.strip().lower()
        )

        lines = [
            line
            for line in lines
            if search_value
            in line.lower()
        ]

    return lines


# ==================================================
# LEVEL DETECTION
# ==================================================

def detect_level(
    line: str,
) -> str:

    text = line.lower()

    if any(
        word in text
        for word in [
            "emerg",
            "alert",
            "critical",
            "crit",
            "fatal",
            "error",
            "failed",
            "failure",
            "denied",
        ]
    ):
        return "ERROR"

    if any(
        word in text
        for word in [
            "warn",
            "warning",
            "invalid",
            "unauthorized",
            "forbidden",
        ]
    ):
        return "WARN"

    return "INFO"


# ==================================================
# AUTH LOG FILTER
# ==================================================

def filter_auth_logs(
    lines,
):
    auth_keywords = [
        "sudo",
        "sshd",
        "ssh",
        "pam",
        "authentication",
        "login",
        "logout",
        "session opened",
        "session closed",
        "failed password",
        "invalid user",
        "useradd",
        "usermod",
        "passwd",
    ]

    return [
        line
        for line in lines
        if any(
            keyword in line.lower()
            for keyword in auth_keywords
        )
    ]


# ==================================================
# FORMAT JOURNAL LOGS
# ==================================================

def format_journal_logs(
    lines,
    log_type,
):
    logs = []

    for index, line in enumerate(lines):

        parts = line.split(
            maxsplit=3
        )

        timestamp = (
            parts[0]
            if len(parts) > 0
            else "—"
        )

        source = (
            parts[2]
            if len(parts) > 2
            else "system"
        )

        message = (
            parts[3]
            if len(parts) > 3
            else line
        )

        logs.append(
            {
                "id":
                    f"{log_type}-{index}",

                "timestamp":
                    timestamp,

                "source":
                    source,

                "level":
                    detect_level(line),

                "event":
                    source,

                "message":
                    message,
            }
        )

    return logs


# ==================================================
# ACCESS LOG READER
# ==================================================

def read_access_logs(
    limit: int = 200,
):
    if not ACCESS_LOG_FILE.exists():
        return []

    try:

        with ACCESS_LOG_FILE.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:

            lines = file.readlines()[
                -limit:
            ]

    except OSError as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to read access log: "
                f"{exc}"
            ),
        )

    logs = []

    for index, line in enumerate(lines):

        line = line.strip()

        if not line:
            continue

        try:

            entry = json.loads(line)

        except json.JSONDecodeError:

            continue

        status_code = int(
            entry.get(
                "status_code",
                0,
            )
        )

        if status_code >= 500:

            level = "ERROR"

        elif status_code >= 400:

            level = "WARN"

        else:

            level = "INFO"

        method = entry.get(
            "method",
            "—",
        )

        path = entry.get(
            "path",
            "—",
        )

        duration = entry.get(
            "duration_ms",
            0,
        )

        client_ip = entry.get(
            "client_ip",
            "—",
        )

        logs.append(
            {
                "id":
                    (
                        f"access-{index}-"
                        f"{entry.get('timestamp', '')}"
                    ),

                "timestamp":
                    entry.get(
                        "timestamp",
                        "—",
                    ),

                "source":
                    "soc-api",

                "level":
                    level,

                "event":
                    f"{method} {path}",

                "message":
                    (
                        f"HTTP {status_code} • "
                        f"{duration} ms • "
                        f"{client_ip}"
                    ),

                "status_code":
                    status_code,

                "method":
                    method,

                "path":
                    path,

                "duration_ms":
                    duration,

                "client_ip":
                    client_ip,
            }
        )

    logs.reverse()

    return logs


# ==================================================
# SEARCH + SEVERITY
# ==================================================

def apply_filters(
    logs,
    search: Optional[str],
    severity: str,
):

    filtered = logs

    if search:

        query = (
            search.strip().lower()
        )

        filtered = [
            log
            for log in filtered
            if query
            in str(log).lower()
        ]

    severity_value = (
        severity.strip().upper()
    )

    if severity_value != "ALL":

        filtered = [
            log
            for log in filtered
            if str(
                log.get(
                    "level",
                    "",
                )
            ).upper()
            == severity_value
        ]

    return filtered


# ==================================================
# START MONITORING
# ==================================================

@router.post(
    "/monitoring/start"
)
def start_monitoring(
    payload: MonitoringStartRequest,
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    target = payload.target.strip()
    if not target:
        raise HTTPException(400, "Target cannot be blank.")

    assessment = find_user_assessment(
        db=db,
        current_user=current_user,
        target=target,
    )
    if assessment is None:
        raise HTTPException(
            status_code=404,
            detail="No assessment exists for this target.",
        )
    if assessment.vapt_status != "completed":
        raise HTTPException(
            status_code=400,
            detail="Monitoring requires a completed VAPT assessment.",
        )

    # Do not mark collection active when no scoped collector is available.
    raise HTTPException(
        status_code=503,
        detail='Scoped log collection is unavailable. The backend host journal and application access log are shared infrastructure records and cannot be attributed safely to your selected assessment. Use Security Events or Log Explorer for authorized persisted telemetry.',
    )


# ==================================================
# STOP MONITORING
# ==================================================

@router.post(
    "/monitoring/stop"
)
def stop_monitoring(
    payload: MonitoringStopRequest,
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    target = payload.target.strip()

    assessment = find_user_assessment(
        db=db,
        current_user=current_user,
        target=target,
    )

    if assessment is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "No assessment exists for this target."
            ),
        )

    assessment.monitoring_status = (
        "not_started"
    )

    db.commit()

    db.refresh(assessment)

    return {
        "message":
            "Live monitoring stopped.",

        "assessment_id":
            assessment.id,

        "target":
            assessment.target,

        "monitoring_status":
            assessment.monitoring_status,
    }


# ==================================================
# MONITORING STATUS
# ==================================================

@router.get(
    "/monitoring/status"
)
def monitoring_status(
    target: str = Query(
        ...,
        min_length=1,
        max_length=500,
    ),
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    if not target.strip():
        raise HTTPException(400, "Target cannot be blank.")

    assessment = find_user_assessment(
        db=db,
        current_user=current_user,
        target=target,
    )
    if assessment is None:
        raise HTTPException(
            status_code=404,
            detail="No assessment exists for this target.",
        )

    return {
        "assessment_id": assessment.id,
        "target": assessment.target,
        "monitoring_status": "unavailable",
        "stored_monitoring_status": assessment.monitoring_status,
        "collection_available": False,
        "log_sources": [],
        "vapt_status": assessment.vapt_status,
        "qa_status": assessment.qa_status,
        "overall_status": assessment.overall_status,
        "detail": 'Scoped log collection is unavailable. The backend host journal and application access log are shared infrastructure records and cannot be attributed safely to your selected assessment. Use Security Events or Log Explorer for authorized persisted telemetry.',
    }


# ==================================================
# GET LOGS
# ==================================================

@router.get(
    "/{log_type}"
)
def get_logs(
    log_type: str,

    target: Optional[str] = Query(
        default=None,
        max_length=500,
    ),

    search: Optional[str] = Query(
        default=None,
        max_length=200,
    ),

    severity: str = Query(
        default="all",
    ),

    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),

    current_user: User = Depends(
        require_role(1)
    ),

    db: Session = Depends(
        get_db
    ),
):
    """Never expose unscoped backend-host logs through user endpoints."""
    # SCOPED_LOG_COLLECTION_UNAVAILABLE
    if log_type not in {"syslog", "auth", "access"}:
        raise HTTPException(
            status_code=404,
            detail="Unknown log type. Use syslog, auth or access.",
        )

    if target is not None:
        if not target.strip():
            raise HTTPException(400, "Target cannot be blank.")

        assessment = find_user_assessment(
            db=db,
            current_user=current_user,
            target=target,
        )
        if assessment is None:
            raise HTTPException(
                status_code=404,
                detail="No assessment exists for the selected target.",
            )

    raise HTTPException(
        status_code=503,
        detail='Scoped log collection is unavailable. The backend host journal and application access log are shared infrastructure records and cannot be attributed safely to your selected assessment. Use Security Events or Log Explorer for authorized persisted telemetry.',
    )
