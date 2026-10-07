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

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        job["pid"] = process.pid
        job["duration_completed"] = False

        output_lines = []
        job["live_alerts"] = []

        while True:
            if job.get("cancel_requested"):
                try:
                    os.kill(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                job["status"] = "cancelled"
                job["stage"] = "Monitoring cancelled"
                break

            elapsed = time.time() - start

            if elapsed >= request.duration:
                job["duration_completed"] = True
                job["stage"] = "Waiting for Snort to finish"
                job["progress"] = 98

            try:
                line = await asyncio.wait_for(
                    process.stdout.readline(), timeout=0.5
                )
            except asyncio.TimeoutError:
                elapsed = time.time() - start
                job["progress"] = min(95, int((elapsed / request.duration) * 95))
                job["elapsed"] = round(elapsed, 1)
                continue

            if line:
                text = line.decode(errors="replace").strip()
                if text:
                    output_lines.append(text)
                    job["alert_count"] = sum(
                        1 for x in output_lines if "[**]" in x or "[Classification:" in x
                    )
                    job["live_alerts"] = output_lines[-100:]
                    job["stage"] = f"Monitoring — alerts: {job['alert_count']}"
                    job["elapsed"] = round(time.time() - start, 1)

            if process.returncode is not None:
                break

            elapsed = time.time() - start
            job["progress"] = min(95, int((elapsed / request.duration) * 95))
            job["elapsed"] = round(elapsed, 1)

        stdout = b""
        stderr = b""

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=2
            )
        except asyncio.TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=1
                )
            except asyncio.TimeoutError:
                stdout, stderr = b"", b""

        combined = output_lines
        if stdout:
            combined.extend(stdout.decode(errors="replace").splitlines())
        if stderr:
            combined.extend(stderr.decode(errors="replace").splitlines())

        job["output"] = combined[-500:]
        job["live_alerts"] = combined[-100:]
        job["stderr"] = stderr.decode(errors="replace")[-4000:]
        job["return_code"] = process.returncode

        if job["status"] != "cancelled":
            if job.get("duration_completed"):
                job["status"] = "completed"
                job["stage"] = "Monitoring completed"
            else:
                job["status"] = "completed" if process.returncode == 0 else "failed"
                job["stage"] = (
                    "Monitoring completed"
                    if process.returncode == 0
                    else "Monitoring failed"
                )
            job["progress"] = 100

    except Exception as exc:
        job["status"] = "failed"
        job["stage"] = "Snort execution failed"
        job["error"] = str(exc)
        job["progress"] = 100

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
