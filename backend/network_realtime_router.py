from __future__ import annotations

import asyncio
import ipaddress
import re
import shlex
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/vapt/network",
    tags=["Real-Time Network Tools"],
)

HPING_JOBS: dict[str, dict[str, Any]] = {}


class Hping3Request(BaseModel):
    target: str
    port: int = Field(default=3000, ge=1, le=65535)
    count: int = Field(default=5, ge=1, le=100)
    interval_ms: int = Field(default=500, ge=100, le=10000)


def validate_target(target: str) -> str:
    target = target.strip()

    if not target:
        raise HTTPException(status_code=400, detail="Target is required")

    # Accept IPv4/IPv6 addresses.
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Accept a simple DNS hostname.
    if len(target) <= 253 and re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?",
        target,
    ):
        return target

    raise HTTPException(status_code=400, detail="Invalid target")


async def run_hping3(job_id: str, request: Hping3Request) -> None:
    job = HPING_JOBS[job_id]

    interval_seconds = request.interval_ms / 1000.0

    command = [
        "sudo",
        "-n",
        "/usr/sbin/hping3",
        "-S",
        "-p",
        str(request.port),
        "-c",
        str(request.count),
        "-i",
        f"u{request.interval_ms * 1000}",
        request.target,
    ]

    job["command"] = " ".join(shlex.quote(x) for x in command)
    job["status"] = "running"
    job["started_at"] = datetime.now(timezone.utc).isoformat()

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        job["pid"] = process.pid

        while True:
            if job["cancel_requested"]:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                break

            line = await process.stdout.readline()

            if not line:
                break

            decoded = line.decode("utf-8", errors="replace").rstrip()
            if decoded:
                job["output"].append(decoded)

                packet_match = re.search(
                    r"len=(\d+).*ip=([^\s]+).*ttl=(\d+).*sport=(\d+).*flags=([^\s]+).*seq=(\d+).*rtt=([\d.]+)\s*ms",
                    decoded,
                )

                if packet_match:
                    response_ip = packet_match.group(2)

                    packet = {
                        "length": int(packet_match.group(1)),
                        "ip": response_ip,
                        "source": response_ip,
                        "destination": job["target"],
                        "ttl": int(packet_match.group(3)),
                        "sport": int(packet_match.group(4)),
                        "flags": packet_match.group(5),
                        "seq": int(packet_match.group(6)),
                        "rtt_ms": float(packet_match.group(7)),
                    }

                    job["packets"].append(packet)
                    job["received"] = len(job["packets"])

            await asyncio.sleep(0)

        await process.wait()

        if job["cancel_requested"]:
            job["status"] = "cancelled"
        else:
            job["status"] = "completed"

        job["return_code"] = process.returncode

        output = "\n".join(job["output"])

        transmitted_match = re.search(
            r"(\d+)\s+packets transmitted,\s+(\d+)\s+packets received,\s+([\d.]+)% packet loss",
            output,
        )

        if transmitted_match:
            job["transmitted"] = int(transmitted_match.group(1))
            job["received"] = int(transmitted_match.group(2))
            job["packet_loss"] = float(transmitted_match.group(3))

        rtt_match = re.search(
            r"round-trip min/avg/max = ([\d.]+)/([\d.]+)/([\d.]+) ms",
            output,
        )

        if rtt_match:
            job["rtt_min_ms"] = float(rtt_match.group(1))
            job["rtt_avg_ms"] = float(rtt_match.group(2))
            job["rtt_max_ms"] = float(rtt_match.group(3))

    except FileNotFoundError:
        job["status"] = "failed"
        job["error"] = "hping3 was not found at /usr/sbin/hping3"

    except Exception as exc:
        job["status"] = "failed"
        job["error"] = str(exc)

    finally:
        job["finished_at"] = datetime.now(timezone.utc).isoformat()


@router.post("/hping3/scan")
async def start_hping3_scan(request: Hping3Request):
    target = validate_target(request.target)

    job_id = str(uuid.uuid4())

    HPING_JOBS[job_id] = {
        "id": job_id,
        "tool": "hping3",
        "target": target,
        "port": request.port,
        "count": request.count,
        "interval_ms": request.interval_ms,
        "status": "starting",
        "output": [],
        "packets": [],
        "transmitted": 0,
        "received": 0,
        "packet_loss": None,
        "rtt_min_ms": None,
        "rtt_avg_ms": None,
        "rtt_max_ms": None,
        "pid": None,
        "cancel_requested": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    asyncio.create_task(run_hping3(job_id, request))

    return {
        "success": True,
        "scan_id": job_id,
        "status": "starting",
        "tool": "hping3",
        "target": target,
        "port": request.port,
        "count": request.count,
        "interval_ms": request.interval_ms,
    }


@router.get("/hping3/scan/{scan_id}/progress")
async def get_hping3_progress(scan_id: str):
    job = HPING_JOBS.get(scan_id)

    if not job:
        raise HTTPException(status_code=404, detail="hping3 scan not found")

    return {
        "success": True,
        "scan_id": scan_id,
        "tool": "hping3",
        "status": job["status"],
        "target": job["target"],
        "port": job["port"],
        "count": job["count"],
        "transmitted": job["transmitted"],
        "received": job["received"],
        "packet_loss": job["packet_loss"],
        "rtt_min_ms": job["rtt_min_ms"],
        "rtt_avg_ms": job["rtt_avg_ms"],
        "rtt_max_ms": job["rtt_max_ms"],
        "packets": job["packets"],
        "output": job["output"],
        "error": job.get("error"),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
    }


@router.get("/hping3/scan/{scan_id}/results")
async def get_hping3_results(scan_id: str):
    job = HPING_JOBS.get(scan_id)

    if not job:
        raise HTTPException(status_code=404, detail="hping3 scan not found")

    return {
        "success": True,
        "scan_id": scan_id,
        "tool": "hping3",
        "status": job["status"],
        "target": job["target"],
        "port": job["port"],
        "summary": {
            "transmitted": job["transmitted"],
            "received": job["received"],
            "packet_loss": job["packet_loss"],
            "rtt_min_ms": job["rtt_min_ms"],
            "rtt_avg_ms": job["rtt_avg_ms"],
            "rtt_max_ms": job["rtt_max_ms"],
        },
        "packets": job["packets"],
        "output": job["output"],
        "error": job.get("error"),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
    }


@router.post("/hping3/scan/{scan_id}/cancel")
async def cancel_hping3_scan(scan_id: str):
    job = HPING_JOBS.get(scan_id)

    if not job:
        raise HTTPException(status_code=404, detail="hping3 scan not found")

    if job["status"] in {"completed", "failed", "cancelled"}:
        return {
            "success": True,
            "scan_id": scan_id,
            "status": job["status"],
        }

    job["cancel_requested"] = True

    return {
        "success": True,
        "scan_id": scan_id,
        "status": "cancellation_requested",
    }

# ==================== WIRESHARK REAL-TIME CAPTURE ====================
import os as _ws_os
import re as _ws_re
import uuid as _ws_uuid
import time as _ws_time
import asyncio as _ws_asyncio
import subprocess as _ws_subprocess
from pathlib import Path as _ws_Path
from fastapi.responses import FileResponse as _ws_FileResponse

WIRESHARK_JOBS = {}

class WiresharkCaptureRequest(BaseModel):
    interface: str = "eth0"
    duration: int = 10

def _ws_new_job(interface, duration):
    job_id = str(_ws_uuid.uuid4())
    WIRESHARK_JOBS[job_id] = {
        "id": job_id,
        "status": "starting",
        "progress": 0,
        "stage": "Preparing Wireshark capture",
        "interface": interface,
        "duration": duration,
        "packet_count": 0,
        "file": None,
        "started_at": None,
        "completed_at": None,
        "error": None,
    }
    return job_id

async def _ws_run_capture(job_id):
    job = WIRESHARK_JOBS[job_id]
    capture_file = f"/tmp/soc-wireshark-{job_id}.pcapng"
    job["file"] = capture_file
    job["started_at"] = _ws_time.time()
    job["status"] = "running"
    job["stage"] = f"Capturing packets on {job['interface']}"

    try:
        process = await _ws_asyncio.create_subprocess_exec(
            "sudo", "-n", "/usr/bin/dumpcap",
            "-i", job["interface"],
            "-a", f"duration:{job['duration']}",
            "-w", capture_file,
            stdout=_ws_subprocess.PIPE,
            stderr=_ws_subprocess.STDOUT,
        )

        start_time = _ws_time.time()

        while True:
            elapsed = _ws_time.time() - start_time

            if elapsed >= job["duration"]:
                break

            job["progress"] = min(
                95,
                int((elapsed / job["duration"]) * 95)
            )
            job["stage"] = (
                f"Capturing packets... "
                f"{min(job['duration'], int(elapsed))}/{job['duration']} seconds"
            )

            await _ws_asyncio.sleep(0.25)

        await process.wait()

        if process.returncode != 0:
            raise RuntimeError("Wireshark dumpcap capture failed")

        packet_count = 0

        try:
            info = _ws_subprocess.run(
                ["sudo", "-n", "/usr/bin/capinfos", "-c", capture_file],
                capture_output=True,
                text=True,
                timeout=10,
            )

            output = (info.stdout or "") + "\n" + (info.stderr or "")

            match = _ws_re.search(
                r"Number of packets:\s*([\d,]+)",
                output
            )

            if match:
                packet_count = int(
                    match.group(1).replace(",", "")
                )

        except Exception:
            packet_count = 0

        job["packet_count"] = packet_count
        job["progress"] = 100
        job["status"] = "completed"
        job["stage"] = "Wireshark capture completed"
        job["completed_at"] = _ws_time.time()

    except Exception as exc:
        job["status"] = "failed"
        job["stage"] = "Wireshark capture failed"
        job["error"] = str(exc)
        job["completed_at"] = _ws_time.time()

@router.post("/vapt/network/wireshark/capture")
async def start_wireshark_capture(request: WiresharkCaptureRequest):
    if request.interface not in {"eth0", "docker0", "any", "lo"}:
        raise HTTPException(status_code=400, detail="Unsupported capture interface")

    if not 1 <= request.duration <= 60:
        raise HTTPException(status_code=400, detail="Duration must be 1-60 seconds")

    job_id = _ws_new_job(request.interface, request.duration)
    _ws_asyncio.create_task(_ws_run_capture(job_id))

    return {
        "capture_id": job_id,
        "status": "starting",
        "interface": request.interface,
        "duration": request.duration,
    }

@router.get("/vapt/network/wireshark/capture/{capture_id}/progress")
async def wireshark_capture_progress(capture_id: str):
    job = WIRESHARK_JOBS.get(capture_id)
    if not job:
        raise HTTPException(status_code=404, detail="Capture not found")
    return job

@router.get("/vapt/network/wireshark/capture/{capture_id}/results")
async def wireshark_capture_results(capture_id: str):
    job = WIRESHARK_JOBS.get(capture_id)
    if not job:
        raise HTTPException(status_code=404, detail="Capture not found")
    if job["status"] != "completed":
        return job
    return job

@router.get("/vapt/network/wireshark/capture/{capture_id}/download")
async def download_wireshark_capture(capture_id: str):
    job = WIRESHARK_JOBS.get(capture_id)
    if not job or not job.get("file"):
        raise HTTPException(status_code=404, detail="Capture file not found")
    if not _ws_os.path.exists(job["file"]):
        raise HTTPException(status_code=404, detail="Capture file no longer exists")
    return _ws_FileResponse(
        job["file"],
        media_type="application/vnd.tcpdump.pcap",
        filename=f"wireshark-{capture_id}.pcapng",
    )

@router.post("/vapt/network/wireshark/capture/{capture_id}/cancel")
async def cancel_wireshark_capture(capture_id: str):
    job = WIRESHARK_JOBS.get(capture_id)
    if not job:
        raise HTTPException(status_code=404, detail="Capture not found")
    job["status"] = "cancelled"
    job["stage"] = "Capture cancelled"
    job["progress"] = 0
    return job

# ==================== WIRESHARK CAPTURE ====================
WIRESHARK_JOBS: dict[str, dict[str, Any]] = {}

class WiresharkRequest(BaseModel):
    interface: str = "eth0"
    duration: int = Field(default=10, ge=1, le=60)

async def _run_wireshark(job_id: str, req: WiresharkRequest):
    job = WIRESHARK_JOBS[job_id]
    path = f"/tmp/soc-wireshark-{job_id}.pcapng"

    job.update(
        status="running",
        progress=0,
        stage=f"Capturing on {req.interface}",
        file=path,
        started_at=datetime.now(timezone.utc).isoformat()
    )

    command = [
        "sudo", "-n", "/usr/bin/dumpcap",
        "-i", req.interface,
        "-a", f"duration:{req.duration}",
        "-w", path
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )

        start = asyncio.get_running_loop().time()

        while process.returncode is None:
            await asyncio.sleep(0.25)

            elapsed = asyncio.get_running_loop().time() - start
            job["progress"] = min(
                95,
                int((elapsed / req.duration) * 95)
            )

            job["stage"] = (
                f"Capturing packets... "
                f"{min(req.duration, int(elapsed))}/{req.duration}s"
            )

            if process.returncode is None:
                try:
                    await asyncio.wait_for(process.wait(), timeout=0.01)
                except asyncio.TimeoutError:
                    pass

        await process.wait()

        if process.returncode != 0:
            raise RuntimeError("Wireshark dumpcap capture failed")

        packet_count = 0

        try:
            import subprocess

            info = subprocess.run(
                ["sudo", "-n", "/usr/bin/capinfos", "-c", path],
                capture_output=True,
                text=True,
                timeout=10
            )

            match = re.search(
                r"Number of packets:\s*([\d,]+)",
                info.stdout
            )

            if match:
                packet_count = int(
                    match.group(1).replace(",", "")
                )

        except Exception:
            pass

        job.update(
            status="completed",
            progress=100,
            stage="Wireshark capture completed",
            packet_count=packet_count,
            finished_at=datetime.now(timezone.utc).isoformat()
        )

    except Exception as exc:
        job.update(
            status="failed",
            stage="Wireshark capture failed",
            error=str(exc),
            finished_at=datetime.now(timezone.utc).isoformat()
        )


@router.post("/wireshark/capture")
async def start_wireshark_capture(req: WiresharkRequest):

    if req.interface not in {
        "eth0",
        "docker0",
        "any",
        "lo"
    }:
        raise HTTPException(
            status_code=400,
            detail="Unsupported capture interface"
        )

    job_id = str(uuid.uuid4())

    WIRESHARK_JOBS[job_id] = {
        "id": job_id,
        "tool": "wireshark",
        "status": "starting",
        "progress": 0,
        "stage": "Preparing Wireshark capture",
        "interface": req.interface,
        "duration": req.duration,
        "packet_count": 0,
        "file": None,
        "error": None
    }

    asyncio.create_task(
        _run_wireshark(job_id, req)
    )

    return WIRESHARK_JOBS[job_id]


@router.get("/wireshark/capture/{capture_id}/progress")
async def wireshark_progress(capture_id: str):

    job = WIRESHARK_JOBS.get(capture_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Wireshark capture not found"
        )

    return job


@router.get("/wireshark/capture/{capture_id}/results")
async def wireshark_results(capture_id: str):

    job = WIRESHARK_JOBS.get(capture_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Wireshark capture not found"
        )

    return job
