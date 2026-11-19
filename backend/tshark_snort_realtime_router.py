import asyncio
import os
import re
import signal
import time
import uuid
from pathlib import Path
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from database import SessionLocal
from models import SecurityEvent
from mitre_mapper import map_security_event
from security_event_store import store_security_event
from security_events import create_security_event, generate_event_id


router = APIRouter(prefix="/vapt/network", tags=["Real-Time Network Analysis"])

TSHARK_JOBS: Dict[str, dict] = {}
SNORT_JOBS: Dict[str, dict] = {}


class TSharkRequest(BaseModel):
    interface: str = "eth0"
    duration: int = 10
    display_filter: Optional[str] = None


class SnortRequest(BaseModel):
    interface: str = "eth0"
    duration: int = 10


def _safe_interface(interface: str) -> str:
    allowed = {"eth0", "docker0", "lo", "any"}
    if interface not in allowed:
        raise HTTPException(status_code=400, detail="Interface is not allowed")
    return interface


async def _run_tshark(job_id: str, request: TSharkRequest):
    job = TSHARK_JOBS[job_id]
    start = time.time()

    cmd = [
        "sudo", "-n", "/usr/bin/tshark",
        "-i", request.interface,
        "-a", f"duration:{request.duration}",
        "-l",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    ]

    if request.display_filter:
        cmd.extend(["-Y", request.display_filter])

    job["command"] = " ".join(cmd)
    job["status"] = "running"
    job["stage"] = "Capturing packets"

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        job["pid"] = process.pid

        stdout_lines = []
        job["live_packets"] = []

        while True:
            if job.get("cancel_requested"):
                try:
                    os.kill(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                job["status"] = "cancelled"
                job["stage"] = "Capture cancelled"
                break

            try:
                line = await asyncio.wait_for(
                    process.stdout.readline(), timeout=0.5
                )
            except asyncio.TimeoutError:
                elapsed = time.time() - start
                job["progress"] = min(95, int((elapsed / request.duration) * 95))
                continue

            if line:
                text = line.decode(errors="replace").strip()
                if text:
                    stdout_lines.append(text)
                    job["packet_count"] = len(stdout_lines)
                    job["live_packets"] = stdout_lines[-100:]
                    job["stage"] = f"Packets captured: {len(stdout_lines)}"
                    job["elapsed"] = round(time.time() - start, 1)

            if process.returncode is not None:
                break

            if process.returncode is not None:
                break

            elapsed = time.time() - start
            job["progress"] = min(95, int((elapsed / request.duration) * 95))

        stdout, stderr = await process.communicate()

        if stdout:
            for line in stdout.decode(errors="replace").splitlines():
                if line.strip() and line.strip() not in stdout_lines:
                    stdout_lines.append(line.strip())

        job["output"] = stdout_lines[-500:]
        job["live_packets"] = stdout_lines[-100:]
        job["stderr"] = stderr.decode(errors="replace")[-4000:]
        job["return_code"] = process.returncode

        if job["status"] != "cancelled":
            job["status"] = "completed" if process.returncode == 0 else "failed"
            job["stage"] = "Capture completed" if process.returncode == 0 else "Capture failed"
            job["progress"] = 100

    except Exception as exc:
        job["status"] = "failed"
        job["stage"] = "TShark execution failed"
        job["error"] = str(exc)
        job["progress"] = 100

    job["duration"] = round(time.time() - start, 2)


async def _run_snort(job_id: str, request: SnortRequest):
    job = SNORT_JOBS[job_id]
    start = time.time()

    cmd = [
        "sudo", "-n", "/usr/local/bin/soc-snort",
        request.interface,
        str(request.duration),
    ]

    job["command"] = " ".join(cmd)
    job["status"] = "running"
    job["stage"] = "Monitoring traffic"
    job["alert_count"] = 0
    job["stored_events"] = 0
    job["duplicate_events"] = 0
    job["live_alerts"] = []
    job["output"] = []

    process = None
    stderr_task = None
    output_lines = []
    cancelled = False

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        job["pid"] = process.pid
        job["duration_completed"] = False

        stderr_task = asyncio.create_task(process.stderr.read())

        while True:
            if job.get("cancel_requested"):
                cancelled = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                job["stage"] = "Stopping Snort capture"
                break

            try:
                line = await asyncio.wait_for(
                    process.stdout.readline(),
                    timeout=0.5,
                )
            except asyncio.TimeoutError:
                elapsed = time.time() - start
                job["progress"] = min(
                    95, int((elapsed / request.duration) * 95)
                )
                job["elapsed"] = round(elapsed, 1)
                continue

            if not line:
                break

            text = line.decode(errors="replace").strip()
            if text:
                output_lines.append(text)
                is_alert = (
                    "[**]" in text
                    and re.search(r"\[\d+:\d+:\d+\]", text) is not None
                )
                alerts_so_far = [
                    item for item in output_lines
                    if "[**]" in item
                    and re.search(r"\[\d+:\d+:\d+\]", item) is not None
                ]
                job["alert_count"] = len(alerts_so_far)
                job["live_alerts"] = alerts_so_far[-100:]
                job["stage"] = (
                    f"Monitoring — alerts: {job['alert_count']}"
                )
                job["elapsed"] = round(time.time() - start, 1)

        if cancelled:
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
        else:
            try:
                await asyncio.wait_for(process.wait(), timeout=10)
            except asyncio.TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()

        stderr = await stderr_task if stderr_task else b""
        stderr_text = stderr.decode(errors="replace")

        alerts = [
            line for line in output_lines
            if "[**]" in line
            and re.search(r"\[\d+:\d+:\d+\]", line) is not None
        ]

        job["output"] = output_lines[-500:]
        job["live_alerts"] = alerts[-100:]
        job["alert_count"] = len(alerts)
        job["stderr"] = stderr_text[-4000:]
        job["return_code"] = process.returncode

        # Store genuine Snort alerts using the existing SIEM event pipeline.
        if alerts and not cancelled:
            db = SessionLocal()
            stored = 0
            duplicates = 0

            try:
                for raw_alert in alerts:
                    signature = re.search(
                        r"\[\*\*\]\s*\[\d+:\d+:\d+\]\s*(.*?)\s*\[\*\*\]",
                        raw_alert,
                    )
                    message = (
                        signature.group(1).strip()
                        if signature and signature.group(1).strip()
                        else raw_alert
                    )

                    priority_match = re.search(
                        r"\[Priority:\s*(\d+)\]",
                        raw_alert,
                        re.IGNORECASE,
                    )
                    priority = int(priority_match.group(1)) if priority_match else None

                    severity = {
                        1: "CRITICAL",
                        2: "HIGH",
                        3: "MEDIUM",
                    }.get(priority, "LOW")

                    destination_match = re.search(
                        r"->\s*(\d{1,3}(?:\.\d{1,3}){3})",
                        raw_alert,
                    )
                    target = (
                        destination_match.group(1)
                        if destination_match
                        else None
                    )

                    event_id = generate_event_id(
                        f"snort|{request.interface}|{raw_alert}"
                    )

                    event = create_security_event(
                        source="snort",
                        event_type="intrusion_detection",
                        message=message,
                        severity=severity,
                        target=target,
                        event_id=event_id,
                        raw_event={
                            "sensor": "snort",
                            "interface": request.interface,
                            "alert": raw_alert,
                            "priority": priority,
                        },
                    )

                    existing = (
                        db.query(SecurityEvent)
                        .filter(SecurityEvent.event_id == event_id)
                        .first()
                    )

                    if existing:
                        duplicates += 1
                        continue

                    mappings = map_security_event(event)

                    if mappings:
                        for mapping in mappings:
                            store_security_event(
                                db,
                                event,
                                mitre_mapping=mapping,
                            )
                    else:
                        store_security_event(db, event)

                    stored += 1

                db.commit()
                job["stored_events"] = stored
                job["duplicate_events"] = duplicates

            except Exception as exc:
                db.rollback()
                job["stored_events"] = 0
                job["ingestion_error"] = (
                    f"{type(exc).__name__}: {exc}"
                )
            finally:
                db.close()

        if cancelled:
            job["status"] = "cancelled"
            job["stage"] = "Monitoring cancelled"
        elif process.returncode == 0:
            job["duration_completed"] = True
            job["status"] = "completed"
            job["stage"] = "Monitoring completed"
        else:
            job["status"] = "failed"
            job["stage"] = "Monitoring failed"

        job["progress"] = 100

    except Exception as exc:
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()

        job["status"] = "failed"
        job["stage"] = "Snort execution failed"
        job["error"] = f"{type(exc).__name__}: {exc}"
        job["progress"] = 100

    finally:
        job["duration"] = round(time.time() - start, 2)


@router.post("/tshark/run")
async def run_tshark(request: TSharkRequest):
    request.interface = _safe_interface(request.interface)

    if not 1 <= request.duration <= 300:
        raise HTTPException(status_code=400, detail="Duration must be between 1 and 300 seconds")

    job_id = str(uuid.uuid4())
    TSHARK_JOBS[job_id] = {
        "job_id": job_id,
        "tool": "tshark",
        "status": "queued",
        "progress": 0,
        "packet_count": 0,
        "created_at": time.time(),
        "cancel_requested": False,
    }

    asyncio.create_task(_run_tshark(job_id, request))
    return TSHARK_JOBS[job_id]


@router.get("/tshark/{job_id}/progress")
async def tshark_progress(job_id: str):
    job = TSHARK_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="TShark job not found")
    return job


@router.get("/tshark/{job_id}/results")
async def tshark_results(job_id: str):
    job = TSHARK_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="TShark job not found")
    return job


@router.post("/tshark/{job_id}/cancel")
async def cancel_tshark(job_id: str):
    job = TSHARK_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="TShark job not found")
    job["cancel_requested"] = True
    return {"status": "cancellation_requested", "job_id": job_id}


@router.post("/snort/run")
async def run_snort(request: SnortRequest):
    request.interface = _safe_interface(request.interface)

    if not 1 <= request.duration <= 300:
        raise HTTPException(status_code=400, detail="Duration must be between 1 and 300 seconds")

    job_id = str(uuid.uuid4())
    SNORT_JOBS[job_id] = {
        "job_id": job_id,
        "tool": "snort",
        "status": "queued",
        "progress": 0,
        "alert_count": 0,
        "created_at": time.time(),
        "cancel_requested": False,
    }

    asyncio.create_task(_run_snort(job_id, request))
    return SNORT_JOBS[job_id]


@router.get("/snort/{job_id}/progress")
async def snort_progress(job_id: str):
    job = SNORT_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Snort job not found")
    return job


@router.get("/snort/{job_id}/results")
async def snort_results(job_id: str):
    job = SNORT_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Snort job not found")
    return job


@router.post("/snort/{job_id}/cancel")
async def cancel_snort(job_id: str):
    job = SNORT_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Snort job not found")
    job["cancel_requested"] = True
    return {"status": "cancellation_requested", "job_id": job_id}
