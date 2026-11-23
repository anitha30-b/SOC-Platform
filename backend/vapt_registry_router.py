import asyncio
import json
import os
import time
import uuid
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db, SessionLocal
from models import User, SecurityEvent
from rbac import require_role
from security_event_store import store_security_event
from security_events import create_security_event, generate_event_id
from realtime_journal_listener import notify_security_event
from vapt import (
    ALLOW_LOCAL_TARGETS,
    is_local_host,
    is_private_or_reserved_host,
    require_user_tool_permission,
    persist_masscan_security_events,
)
from vapt_tools.registry import build_registry
from vapt_tools.scripts.nuclei import NucleiError, run_nuclei



def _persist_nuclei_security_events(result: dict, user_id: int, client_id: int | None, job_id=None) -> int:
    """Atomically save the owned assessment, canonical findings and SIEM events."""
    from nuclei_workflow import persist_nuclei_result
    db = SessionLocal()
    try:
        summary, notifications = persist_nuclei_result(db, result, user_id, client_id, job_id)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    result['assessment_id'] = summary['assessment_id']
    result['persistence'] = dict(summary, status='saved')
    for event in notifications:
        try:
            notify_security_event(event)
        except Exception as exc:
            result.setdefault('execution_status', result.get('status'))
            if result.get('status') == 'completed':
                result['status'] = 'completed_with_errors'
            result.setdefault('notification_errors', []).append('Live notification failed; saved findings remain available by refresh.')
            print('[SOC NUCLEI EVENT] Notification failed:', type(exc).__name__)
    return summary['new_events']


router = APIRouter(
    prefix="/vapt/registry",
    tags=["VAPT Registry"],
)

NUCLEI_ALLOW_PRIVATE_TARGETS = (
    os.getenv("NUCLEI_ALLOW_PRIVATE_TARGETS", "false").lower()
    in {"true", "1", "yes"}
)

NUCLEI_JOBS: dict[str, dict] = {}


class NucleiRunRequest(BaseModel):
    target: str


def validate_nuclei_target(target: str) -> str:
    """Apply the existing VAPT URL and target-safety rules."""
    target = str(target or "").strip()

    if not target:
        raise HTTPException(
            status_code=400,
            detail="Nuclei target cannot be empty.",
        )

    parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="Nuclei currently supports only HTTP and HTTPS targets.",
        )

    hostname = parsed.hostname

    if not hostname:
        raise HTTPException(
            status_code=400,
            detail="Invalid Nuclei target URL.",
        )

    if is_private_or_reserved_host(hostname):
        if NUCLEI_ALLOW_PRIVATE_TARGETS:
            return target

        if is_local_host(hostname) and not ALLOW_LOCAL_TARGETS:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Localhost/loopback targets are disabled. "
                    "Set NUCLEI_ALLOW_PRIVATE_TARGETS=true only "
                    "for authorized lab testing."
                ),
            )

        raise HTTPException(
            status_code=400,
            detail=(
                "Private, loopback, link-local, or reserved targets "
                "are not allowed. Set NUCLEI_ALLOW_PRIVATE_TARGETS=true "
                "only for authorized lab testing."
            ),
        )

    return target


@router.get("")
def get_vapt_registry(
    current_user: User = Depends(require_role(1)),
):
    """
    Return the VAPT framework registry.

    The registry is generated from the manifests in
    backend/vapt_tools/manifests/.
    """
    return build_registry()


def _new_nuclei_job(
    target: str,
    user_id: int,
    client_id: int | None = None,
) -> str:
    job_id = str(uuid.uuid4())

    NUCLEI_JOBS[job_id] = {
        "job_id": job_id,
        "target": target,
        "user_id": user_id,
        "client_id": client_id,
        "status": "queued",
        "progress": 0,
        "stage": "Queued",
        "result": None,
        "error": None,
        "created_at": time.time(),
        "updated_at": time.time(),
    }

    return job_id


async def _run_nuclei_job(job_id: str, target: str):
    from nuclei_workflow import mark_persistence_failure
    job = NUCLEI_JOBS.get(job_id)
    if not job:
        return
    try:
        job.update(status='running', progress=20, stage='Running vulnerability discovery', updated_at=time.time())
        result = await asyncio.to_thread(run_nuclei, target)
        job['result'] = result
        try:
            job['security_events_persisted'] = await asyncio.to_thread(
                _persist_nuclei_security_events, result, job['user_id'], job.get('client_id'), job_id)
        except Exception as exc:
            job['security_event_persistence_error'] = type(exc).__name__
            mark_persistence_failure(result)
        status = result.get('status', 'failed')
        job.update(status=status, progress=100, stage=('Completed' if status == 'completed' else
            'Completed with warnings' if status == 'completed_with_errors' else 'Finished with errors'), updated_at=time.time())
    except Exception as exc:
        job.update(status='failed', error=str(exc), progress=100, stage='Failed', updated_at=time.time())


@router.post("/tools/nuclei/run-async")
async def run_nuclei_tool_async(
    request: NucleiRunRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    require_user_tool_permission(
        db,
        current_user,
        "Nuclei",
    )

    target = validate_nuclei_target(request.target)

    job_id = _new_nuclei_job(
        target,
        current_user.id,
        current_user.client_id,
    )

    asyncio.create_task(
        _run_nuclei_job(
            job_id,
            target,
        )
    )

    return {
        "message": "Nuclei scan started",
        "tool": "Nuclei",
        "username": current_user.username,
        "target": target,
        "job_id": job_id,
        "status": "queued",
        "progress": 0,
    }


@router.get("/tools/nuclei/progress/{job_id}")
async def get_nuclei_progress(job_id: str, current_user: User = Depends(require_role(1))):
    job = NUCLEI_JOBS.get(job_id)
    if job and job.get('user_id') != current_user.id:
        raise HTTPException(status_code=403, detail='You do not have access to this Nuclei job.')
    if not job or (job.get('result') or {}).get('persistence', {}).get('status') == 'failed':
        user_id, client_id = current_user.id, current_user.client_id
        def stored_result():
            from nuclei_workflow import load_saved_nuclei_job
            db = SessionLocal()
            try:
                return load_saved_nuclei_job(db, job_id, user_id, client_id)
            finally:
                db.close()
        stored = await asyncio.to_thread(stored_result)
        if stored:
            return dict(stored, username=current_user.username)
    if not job:
        raise HTTPException(status_code=404, detail='Nuclei job not found or expired.')
    return {key:job.get(key) for key in ('job_id','target','status','progress','stage','result','error','updated_at')} | {
        'tool':'Nuclei','username':current_user.username}


@router.post("/tools/nuclei/run")
async def run_nuclei_tool(
    request: NucleiRunRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """
    Execute the integrated Nuclei scanner against an authorized target.
    """
    require_user_tool_permission(
        db,
        current_user,
        "Nuclei",
    )

    target = validate_nuclei_target(request.target)
    scan_user_id, scan_client_id = current_user.id, current_user.client_id
    scan_job_id = str(uuid.uuid4())

    try:
        result = await __import__("asyncio").to_thread(
            run_nuclei,
            target,
        )
    except NucleiError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    try:
        security_events_persisted = await asyncio.to_thread(
            _persist_nuclei_security_events,
            result,
            scan_user_id,
            scan_client_id,
            scan_job_id,
        )
        persistence_error = None
    except Exception as event_exc:
        security_events_persisted = 0
        from nuclei_workflow import mark_persistence_failure
        persistence_error = type(event_exc).__name__
        mark_persistence_failure(result)

    return {
        "message": "Nuclei scan completed" if result.get("status") == "completed" else "Nuclei scan finished with warnings or errors",
        "tool": "Nuclei",
        "username": current_user.username,
        "target": target,
        "result": result,
        "security_events_persisted": security_events_persisted,
        "security_event_persistence_error": persistence_error,
    }


# ============================================================
# GENERIC REGISTRY TOOL EXECUTION
# ============================================================

from vapt_tools.generic_runner import (
    GenericToolError,
    run_generic_tool,
)

GENERIC_TOOL_JOBS = {}


class GenericToolRunRequest(BaseModel):
    target: str


def _get_registry_tool(tool_id: str):
    registry = build_registry()

    for tool in registry.get("tools", []):
        if tool.get("id") == tool_id:
            return tool

    raise HTTPException(
        status_code=404,
        detail=f"VAPT tool '{tool_id}' was not found in the registry.",
    )


def _generic_target_type(target: str) -> str:
    value = str(target or "").strip().lower()

    if value.startswith(("http://", "https://")):
        return "url"

    if "/" in value:
        return "cidr"

    # Basic IPv4 detection.
    parts = value.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return "ip"

    return "domain"


def _new_generic_job(tool_id: str, target: str, user_id: int, client_id: int | None = None):
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("A valid initiating user is required for a generic job.")

    job_id = str(uuid.uuid4())

    GENERIC_TOOL_JOBS[job_id] = {
        "job_id": job_id,
        "tool": tool_id,
        "target": target,
        "user_id": user_id,
        "client_id": client_id,
        "status": "queued",
        "progress": 0,
        "stage": "Queued",
        "message": "Tool execution queued.",
        "result": None,
        "error": None,
        "started_at": time.time(),
        "finished_at": None,
    }

    return job_id


async def _run_generic_job(
    job_id: str,
    tool: dict,
    target: str,
):
    job = GENERIC_TOOL_JOBS[job_id]

    def update_progress(progress: int, stage: str, message: str):
        job["progress"] = max(0, min(100, int(progress)))
        job["stage"] = stage
        job["message"] = message

    job["status"] = "running"
    update_progress(
        10,
        "Starting",
        f"{tool['name']} execution started.",
    )

    try:
        update_progress(
            25,
            "Preparing",
            f"Preparing {tool['name']} against {target}.",
        )

        result = await asyncio.to_thread(
            run_generic_tool,
            tool_id=tool["id"],
            tool_name=tool["name"],
            executable=tool.get("executable"),
            target=target,
            execution_type=tool.get("execution_type", ""),
            progress_callback=update_progress,
        )

        update_progress(
            90,
            "Finalizing",
            f"Collecting {tool['name']} results.",
        )

        if tool.get("id") == "masscan":
            try:
                result["security_events_persisted"] = await asyncio.to_thread(
                    persist_masscan_security_events,
                    result,
                    job["user_id"],
                    job.get("client_id"),
                )
            except Exception as event_exc:
                job["security_event_persistence_error"] = str(event_exc)
                print(f"[SOC MASSCAN EVENT] Persistence failed: {event_exc}")

        job["result"] = result
        job["status"] = result.get("status", "completed")

        if job["status"] == "completed":
            update_progress(
                100,
                "Completed",
                f"{tool['name']} completed successfully.",
            )
        elif job["status"] == "completed_with_errors":
            update_progress(
                100,
                "Completed with errors",
                f"{tool['name']} completed with warnings or errors.",
            )
        else:
            update_progress(
                100,
                "Finished",
                f"{tool['name']} finished with status {job['status']}.",
            )

    except GenericToolError as exc:
        job["error"] = str(exc)
        job["status"] = "failed"
        update_progress(
            100,
            "Failed",
            str(exc),
        )

    except Exception as exc:
        job["error"] = str(exc)
        job["status"] = "failed"
        update_progress(
            100,
            "Failed",
            str(exc),
        )

    finally:
        job["finished_at"] = time.time()


@router.post("/tools/{tool_id}/run-async")
async def run_registry_tool_async(
    tool_id: str,
    request: GenericToolRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    """
    Generic registry-driven VAPT tool execution.

    Existing Nmap, Nikto and Nuclei execution routes remain
    separate specialized workflows.
    """
    tool = _get_registry_tool(tool_id)

    if not tool.get("enabled", True):
        raise HTTPException(
            status_code=400,
            detail=f"Tool '{tool['name']}' is disabled.",
        )

    permission_name = tool.get("permission_name") or tool["name"]

    require_user_tool_permission(
        db,
        current_user,
        permission_name,
    )

    target = str(request.target or "").strip()

    if not target:
        raise HTTPException(
            status_code=400,
            detail="A target is required.",
        )

    target_type = _generic_target_type(target)
    supported_types = tool.get("target_types", [])

    # A hostname can be a valid host target for network tools such as
    # Masscan and hping3 even though it is classified as a domain by
    # the generic URL/domain detector.
    if target_type == "domain" and "host" in supported_types:
        target_type = "host"

    if target_type not in supported_types:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"{tool['name']} cannot use this target format.",
                "tool": tool_id,
                "target_type": target_type,
                "supported_target_types": supported_types,
            },
        )

    executable = tool.get("executable")

    if not executable:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"{tool['name']} requires a dedicated workflow.",
                "tool": tool_id,
                "execution_type": tool.get("execution_type"),
                "target_types": supported_types,
                "input_required": True,
            },
        )

    job_id = _new_generic_job(tool_id, target, current_user.id, current_user.client_id)

    asyncio.create_task(
        _run_generic_job(
            job_id,
            tool,
            target,
        )
    )

    return {
        "message": f"{tool['name']} execution started",
        "job_id": job_id,
        "tool": tool_id,
        "tool_name": tool["name"],
        "target": target,
        "target_type": target_type,
        "status": "queued",
    }


@router.get("/tools/{tool_id}/progress/{job_id}")
async def get_registry_tool_progress(
    tool_id: str,
    job_id: str,
    current_user: User = Depends(require_role(1)),
):
    job = GENERIC_TOOL_JOBS.get(job_id)

    # Scan jobs remain private to their initiating user, including within a client.
    # Legacy jobs without an owner fail closed; do not infer ownership.
    if not job or job.get("user_id") is None or job.get("user_id") != current_user.id:
        raise HTTPException(
            status_code=404,
            detail="Generic VAPT job not found.",
        )

    if job.get("tool") != tool_id:
        raise HTTPException(
            status_code=404,
            detail="Job does not belong to the requested tool.",
        )

    return job
