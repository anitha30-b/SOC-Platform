from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


router = APIRouter(
    prefix="/vapt/credential",
    tags=["Real-Time Credential Testing"],
)

HYDRA_JOBS: dict[str, dict[str, Any]] = {}
JOHN_JOBS: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> float:
    return time.time()


def _is_lab_target(target: str) -> bool:
    """Allow only localhost/loopback/private/link-local lab targets."""
    target = target.strip()

    if target in {"localhost", "127.0.0.1", "::1"}:
        return True

    try:
        ip = ipaddress.ip_address(target)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
        )
    except ValueError:
        # Hostnames are allowed only for obvious local lab names.
        return target.endswith((".local", ".lab", ".test"))


def _validate_existing_file(path: str, label: str) -> str:
    resolved = Path(path).expanduser().resolve()

    if not resolved.is_file():
        raise ValueError(f"{label} file does not exist: {resolved}")

    return str(resolved)


def _safe_hydra_output(line: str) -> str:
    # Avoid returning passwords discovered by Hydra in the live UI/log.
    line = re.sub(
        r"password\s*[:=]\s*\S+",
        "password: [REDACTED]",
        line,
        flags=re.IGNORECASE,
    )
    return line[:1000]


# ---------------------------------------------------------------------------
# Hydra
# ---------------------------------------------------------------------------

class HydraRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    service: str = Field(..., min_length=1, max_length=32)
    username: str = Field(..., min_length=1, max_length=128)
    password_list: str = Field(..., min_length=1, max_length=500)
    port: int | None = Field(default=None, ge=1, le=65535)
    extra_options: list[str] = Field(default_factory=list, max_length=10)


def _validate_hydra_request(request: HydraRequest) -> str:
    target = request.target.strip()

    if not _is_lab_target(target):
        raise ValueError(
            "Hydra target must be localhost or a private/link-local lab target."
        )

    service = request.service.strip().lower()

    # Explicit allowlist of common lab authentication services.
    allowed_services = {
        "ssh",
        "ftp",
        "telnet",
        "smtp",
        "pop3",
        "imap",
        "http-get",
        "http-post-form",
    }

    if service not in allowed_services:
        raise ValueError(f"Unsupported Hydra service: {service}")

    password_list = _validate_existing_file(
        request.password_list,
        "Password wordlist",
    )

    return password_list


async def _run_hydra(job_id: str, request: HydraRequest):
    job = HYDRA_JOBS[job_id]

    try:
        password_list = _validate_hydra_request(request)

        executable = shutil.which("hydra")
        if not executable:
            raise RuntimeError("Hydra executable was not found.")

        command = [
            executable,
            "-l",
            request.username,
            "-P",
            password_list,
            "-t",
            "4",
        ]

        if request.port:
            command.extend(["-s", str(request.port)])

        command.extend([request.target, request.service])

        job["command_display"] = " ".join(
            "[REDACTED]" if arg == password_list else arg
            for arg in command
        )
        job["status"] = "running"
        job["stage"] = "Starting Hydra credential test"
        job["progress"] = 5
        job["started_at"] = _now()

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        job["pid"] = process.pid
        output_lines: list[str] = []

        while True:
            line = await process.stdout.readline()

            if not line:
                if process.returncode is not None:
                    break
                await asyncio.sleep(0.1)
                continue

            decoded = line.decode(errors="replace").rstrip()
            safe_line = _safe_hydra_output(decoded)

            if safe_line:
                output_lines.append(safe_line)
                output_lines[:] = output_lines[-100:]

            job["output"] = "\n".join(output_lines)

            lower = decoded.lower()

            if "login:" in lower or "login found" in lower:
                job["stage"] = "Credential match reported by Hydra"
            elif "attack finished" in lower:
                job["stage"] = "Hydra attack completed"
            else:
                job["stage"] = "Testing authorized credentials"

            # Hydra does not provide a reliable universal percentage.
            job["progress"] = min(95, max(10, job["progress"] + 1))

            if job.get("cancel_requested"):
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                break

        return_code = await process.wait()

        job["return_code"] = return_code
        job["pid"] = None

        if job.get("cancel_requested"):
            job["status"] = "cancelled"
            job["stage"] = "Hydra test cancelled"
        elif return_code == 0:
            job["status"] = "completed"
            job["stage"] = "Hydra credential test completed"
            job["progress"] = 100
        else:
            job["status"] = "completed"
            job["stage"] = "Hydra completed with no successful result or a tool error"
            job["progress"] = 100

        job["completed_at"] = _now()

    except Exception as exc:
        job["status"] = "failed"
        job["stage"] = "Hydra credential test failed"
        job["error"] = str(exc)
        job["completed_at"] = _now()


@router.post("/hydra/run")
async def start_hydra(request: HydraRequest):
    try:
        _validate_hydra_request(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    job_id = str(uuid.uuid4())

    HYDRA_JOBS[job_id] = {
        "job_id": job_id,
        "tool": "hydra",
        "status": "queued",
        "stage": "Queued",
        "progress": 0,
        "target": request.target,
        "service": request.service,
        "username": request.username,
        "port": request.port,
        "output": "",
        "error": None,
        "pid": None,
        "cancel_requested": False,
        "started_at": None,
        "completed_at": None,
    }

    asyncio.create_task(_run_hydra(job_id, request))

    return {
        "job_id": job_id,
        "tool": "hydra",
        "status": "queued",
    }


@router.get("/hydra/{job_id}/progress")
async def hydra_progress(job_id: str):
    job = HYDRA_JOBS.get(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="Hydra job not found")

    return job


@router.get("/hydra/{job_id}/results")
async def hydra_results(job_id: str):
    job = HYDRA_JOBS.get(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="Hydra job not found")

    return job


@router.post("/hydra/{job_id}/cancel")
async def cancel_hydra(job_id: str):
    job = HYDRA_JOBS.get(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="Hydra job not found")

    job["cancel_requested"] = True

    return {
        "job_id": job_id,
        "status": "cancellation_requested",
    }


# ---------------------------------------------------------------------------
# John the Ripper
# ---------------------------------------------------------------------------

class JohnRequest(BaseModel):
    hash_file: str = Field(..., min_length=1, max_length=500)
    wordlist: str | None = Field(default=None, max_length=500)
    format: str = Field(default="Raw-MD5", max_length=100)


def _validate_john_request(request: JohnRequest) -> tuple[str, str | None]:
    hash_file = _validate_existing_file(
        request.hash_file,
        "Hash",
    )

    wordlist = None

    if request.wordlist:
        wordlist = _validate_existing_file(
            request.wordlist,
            "Wordlist",
        )

    return hash_file, wordlist


async def _run_john(job_id: str, request: JohnRequest):
    job = JOHN_JOBS[job_id]

    try:
        hash_file, wordlist = _validate_john_request(request)

        executable = shutil.which("john")
        if not executable:
            raise RuntimeError("John the Ripper executable was not found.")

        command = [executable, f"--format={request.format}"]

        if wordlist:
            command.append(f"--wordlist={wordlist}")

        command.append(hash_file)

        job["command_display"] = " ".join(
            "[REDACTED]" if arg in {hash_file, wordlist} else arg
            for arg in command
        )
        job["status"] = "running"
        job["stage"] = "Starting John the Ripper"
        job["progress"] = 5
        job["started_at"] = _now()

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        job["pid"] = process.pid
        output_lines: list[str] = []

        while True:
            line = await process.stdout.readline()

            if not line:
                if process.returncode is not None:
                    break
                await asyncio.sleep(0.1)
                continue

            decoded = line.decode(errors="replace").rstrip()

            if decoded:
                output_lines.append(decoded[:1000])
                output_lines[:] = output_lines[-100:]

            job["output"] = "\n".join(output_lines)
            job["stage"] = "Auditing password hashes"
            job["progress"] = min(95, max(10, job["progress"] + 1))

            if job.get("cancel_requested"):
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                break

        return_code = await process.wait()

        job["return_code"] = return_code
        job["pid"] = None

        if job.get("cancel_requested"):
            job["status"] = "cancelled"
            job["stage"] = "John the Ripper test cancelled"
        elif return_code == 0:
            job["status"] = "completed"
            job["stage"] = "John the Ripper completed"
            job["progress"] = 100
        else:
            job["status"] = "completed"
            job["stage"] = "John completed with no recovered password or a tool error"
            job["progress"] = 100

        job["completed_at"] = _now()

    except Exception as exc:
        job["status"] = "failed"
        job["stage"] = "John the Ripper test failed"
        job["error"] = str(exc)
        job["completed_at"] = _now()


@router.post("/john/run")
async def start_john(request: JohnRequest):
    try:
        _validate_john_request(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    job_id = str(uuid.uuid4())

    JOHN_JOBS[job_id] = {
        "job_id": job_id,
        "tool": "john",
        "status": "queued",
        "stage": "Queued",
        "progress": 0,
        "hash_file": request.hash_file,
        "wordlist": request.wordlist,
        "format": request.format,
        "output": "",
        "error": None,
        "pid": None,
        "cancel_requested": False,
        "started_at": None,
        "completed_at": None,
    }

    asyncio.create_task(_run_john(job_id, request))

    return {
        "job_id": job_id,
        "tool": "john",
        "status": "queued",
    }


@router.get("/john/{job_id}/progress")
async def john_progress(job_id: str):
    job = JOHN_JOBS.get(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="John job not found")

    return job


@router.get("/john/{job_id}/results")
async def john_results(job_id: str):
    job = JOHN_JOBS.get(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="John job not found")

    return job


@router.post("/john/{job_id}/cancel")
async def cancel_john(job_id: str):
    job = JOHN_JOBS.get(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="John job not found")

    job["cancel_requested"] = True

    return {
        "job_id": job_id,
        "status": "cancellation_requested",
    }
