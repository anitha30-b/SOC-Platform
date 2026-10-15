from __future__ import annotations

import asyncio
import ipaddress
import shutil
import time
import uuid
from urllib.parse import urlparse

from vapt import is_private_or_reserved_host
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/vapt/metasploit",
    tags=["Metasploit"],
)

METASPLOIT_JOBS: dict[str, dict[str, Any]] = {}


def _now() -> float:
    return time.time()


def _validate_module(module: str) -> str:
    module = module.strip()

    if not module.startswith("auxiliary/scanner/"):
        raise ValueError(
            "Only authorized auxiliary/scanner modules are allowed."
        )

    if any(char in module for char in [";", "|", "&", "$", "`"]):
        raise ValueError("Invalid Metasploit module.")

    allowed = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "/_-."
    )

    if any(char not in allowed for char in module):
        raise ValueError("Invalid Metasploit module.")

    return module


class MetasploitRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    module: str = Field(..., min_length=1, max_length=150)
    port: int | None = Field(default=None, ge=1, le=65535)


def _validate_request(request: MetasploitRequest):
    target = request.target.strip()

    # Accept URL input such as http://127.0.0.1:3000 or
    # https://app.local/test and convert it to Metasploit options.
    if "://" in target:
        parsed = urlparse(target)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Enter a valid HTTP/HTTPS target URL.")

        hostname = parsed.hostname
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target_path = parsed.path or "/"
        use_ssl = parsed.scheme == "https"

        if is_private_or_reserved_host(hostname):
            raise ValueError(
                "Metasploit target resolves to a private, local, link-local, reserved, or multicast address."
            )

        if request.port is None:
            request.port = target_port

        request.target = hostname
        module = _validate_module(request.module)
        return hostname, module, target_path, use_ssl
    else:
        if is_private_or_reserved_host(target):
            raise ValueError(
                "Metasploit target resolves to a private, local, link-local, reserved, or multicast address."
            )

        request.target = target
        return target, request.module, "/", False

    module = _validate_module(request.module)

    return request.target, module, "/", False


async def _run_metasploit(
    job_id: str,
    request: MetasploitRequest,
):
    job = METASPLOIT_JOBS[job_id]
    start = _now()
    process = None

    try:
        original_target = request.target.strip()
        target, module, target_path, use_ssl = _validate_request(request)

        executable = shutil.which("msfconsole")

        if not executable:
            raise RuntimeError("msfconsole executable was not found.")

        commands = [
            f"use {module}",
            f"set RHOSTS {target}",
        ]

        if module == "auxiliary/scanner/http/title":
            commands.append(f"set TARGETURI {target_path}")
            commands.append(f"set SSL {'true' if use_ssl else 'false'}")

        # Portscan modules use PORTS.
        if module.startswith("auxiliary/scanner/portscan/") and request.port:
            commands.append(f"set PORTS {request.port}")
        elif request.port:
            commands.append(f"set RPORT {request.port}")

        commands.extend([
            "show options",
            "run",
            "exit -y",
        ])

        command = [
            executable,
            "-q",
            "-x",
            "; ".join(commands),
        ]

        job["command_display"] = (
            f"msfconsole -q -x "
            f"'use {module}; set RHOSTS {target}; "
            f"{'set TARGETURI ' + target_path + '; set SSL ' + ('true' if use_ssl else 'false') + '; ' if module == 'auxiliary/scanner/http/title' else ''}"
            f"{'set PORTS ' + str(request.port) + '; ' if module.startswith('auxiliary/scanner/portscan/') and request.port else ''}"
            f"{'set RPORT ' + str(request.port) + '; ' if request.port and not module.startswith('auxiliary/scanner/portscan/') else ''}"
            f"show options; run; exit -y'"
        )

        job["status"] = "running"
        job["stage"] = "Starting Metasploit"
        job["progress"] = 5
        job["started_at"] = start

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        job["pid"] = process.pid

        output_lines: list[str] = []
        job["live_output"] = []
        job["elapsed"] = 0

        while True:

            if job.get("cancel_requested"):
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass

                job["status"] = "cancelled"
                job["stage"] = "Cancelling Metasploit"
                break

            try:
                line = await asyncio.wait_for(
                    process.stdout.readline(),
                    timeout=0.5,
                )
            except asyncio.TimeoutError:

                elapsed = _now() - start
                job["elapsed"] = round(elapsed, 1)

                if job["status"] == "running":
                    job["progress"] = min(
                        95,
                        max(
                            10,
                            job["progress"] + 1,
                        ),
                    )

                continue

            if not line:
                break

            if line:
                text = line.decode(
                    errors="replace"
                ).replace("\x1b", "").strip()

                if text:
                    output_lines.append(text)
                    output_lines[:] = output_lines[-500:]

                    job["live_output"] = output_lines[-100:]
                    job["output"] = output_lines[-500:]
                    job["elapsed"] = round(
                        _now() - start,
                        1,
                    )

                    lower = text.lower()

                    if "auxiliary module execution completed" in lower:
                        job["stage"] = "Metasploit module completed"
                    elif "scanning" in lower:
                        job["stage"] = "Metasploit scanning target"
                    elif "tcp open" in lower:
                        job["stage"] = "Open service discovered"
                    elif "module options" in lower:
                        job["stage"] = "Loading module options"
                    elif "error" in lower or "failed" in lower:
                        job["stage"] = "Metasploit reported an error"
                    else:
                        job["stage"] = "Metasploit module running"

                    job["progress"] = min(
                        95,
                        max(
                            10,
                            job["progress"] + 1,
                        ),
                    )

            if process.returncode is not None:
                break

        try:
            await asyncio.wait_for(
                process.wait(),
                timeout=5,
            )
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass

            await process.wait()

        job["return_code"] = process.returncode
        job["pid"] = None
        job["elapsed"] = round(
            _now() - start,
            2,
        )

        if job.get("cancel_requested"):
            job["status"] = "cancelled"
            job["stage"] = "Metasploit scan cancelled"
        elif process.returncode == 0:
            job["status"] = "completed"
            job["stage"] = "Metasploit scan completed"
            job["progress"] = 100
        else:
            job["status"] = "failed"
            job["stage"] = "Metasploit execution failed"
            job["progress"] = 100

        job["completed_at"] = _now()

    except Exception as exc:

        job["status"] = "failed"
        job["stage"] = "Metasploit execution failed"
        job["error"] = str(exc)
        job["pid"] = None
        job["progress"] = 100
        job["completed_at"] = _now()


@router.post("/run")
async def start_metasploit(
    request: MetasploitRequest,
):
    try:
        validation_request = request.model_copy(deep=True)
        _validate_request(validation_request)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    job_id = str(uuid.uuid4())

    METASPLOIT_JOBS[job_id] = {
        "job_id": job_id,
        "tool": "metasploit",
        "status": "queued",
        "stage": "Queued",
        "progress": 0,
        "target": request.target,
        "module": request.module,
        "port": request.port,
        "output": [],
        "live_output": [],
        "error": None,
        "return_code": None,
        "pid": None,
        "elapsed": 0,
        "cancel_requested": False,
        "started_at": None,
        "completed_at": None,
        "command_display": None,
    }

    asyncio.create_task(
        _run_metasploit(
            job_id,
            request,
        )
    )

    return {
        "job_id": job_id,
        "tool": "metasploit",
        "status": "queued",
    }


@router.get("/{job_id}/progress")
async def metasploit_progress(
    job_id: str,
):
    job = METASPLOIT_JOBS.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Metasploit job not found.",
        )

    return {
        "job_id": job_id,
        "status": job["status"],
        "stage": job["stage"],
        "progress": job["progress"],
        "target": job["target"],
        "module": job["module"],
        "elapsed": job["elapsed"],
        "live_output": job["live_output"],
        "error": job["error"],
    }


@router.get("/{job_id}/results")
async def metasploit_results(
    job_id: str,
):
    job = METASPLOIT_JOBS.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Metasploit job not found.",
        )

    return job


@router.post("/{job_id}/cancel")
async def cancel_metasploit(
    job_id: str,
):
    job = METASPLOIT_JOBS.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Metasploit job not found.",
        )

    if job["status"] not in {"queued", "running"}:
        return {
            "job_id": job_id,
            "status": job["status"],
        }

    job["cancel_requested"] = True
    job["stage"] = "Cancelling Metasploit"

    return {
        "job_id": job_id,
        "status": "cancelling",
    }
