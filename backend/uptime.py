from datetime import datetime, timezone
from threading import RLock
from typing import Optional
from urllib.parse import urlsplit
import time

import requests
from fastapi import APIRouter, Depends, HTTPException
from rbac import require_role

router = APIRouter(prefix="/uptime", tags=["Uptime"])

# Process-local samples, isolated by authenticated account.
monitors = {}
_monitors_lock = RLock()


def _target(value):
    value = value.strip()
    try:
        parsed = urlsplit(value)
        port = parsed.port
        valid = (
            parsed.scheme in ("http", "https")
            and parsed.hostname
            and not parsed.username
            and not parsed.password
        )
    except ValueError:
        valid = False
    if not valid:
        raise HTTPException(400, "Enter a valid HTTP or HTTPS target URL.")
    return value


def check_website(url):
    started = time.perf_counter()
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "SOC-Platform-Uptime-Monitor/1.0"},
        )
        return {
            "status": "UP" if response.ok else "DOWN",
            "http_status": response.status_code,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
    except requests.RequestException:
        return {
            "status": "DOWN",
            "http_status": None,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "error": "The HTTP availability check failed.",
        }


def _snapshot(monitor):
    total = monitor["total_requests"]
    checks = [dict(check) for check in monitor["checks"]]
    return {
        "monitoring": True,
        "website_name": monitor["website_name"],
        "target_url": monitor["target_url"],
        "started_at": monitor["started_at"],
        "current": dict(monitor["current"]),
        "total_requests": total,
        "successful_requests": monitor["successful_requests"],
        "failed_requests": monitor["failed_requests"],
        "uptime_percentage": (
            round(monitor["successful_requests"] / total * 100, 2)
            if total else 0
        ),
        "recent_checks": checks,
        "checks": checks,
    }


def _record(monitor, result):
    monitor["checks"].append(result)
    monitor["checks"] = monitor["checks"][-100:]
    monitor["total_requests"] += 1
    monitor["successful_requests"] += int(result["status"] == "UP")
    monitor["failed_requests"] += int(result["status"] != "UP")
    monitor["current"] = result


@router.post("/start")
def start_monitor(
    website_name: str,
    target_url: str,
    current_user=Depends(require_role(1)),
):
    target_url = _target(target_url)
    website_name = website_name.strip()
    if not website_name or len(website_name) > 200:
        raise HTTPException(400, "Enter a website name of 1 to 200 characters.")

    key = (current_user.id, target_url)
    monitor = {
        "website_name": website_name,
        "target_url": target_url,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "checks": [],
        "total_requests": 0,
        "successful_requests": 0,
        "failed_requests": 0,
        "current": {},
        "_check_lock": RLock(),
    }

    # Register before checking so stop can invalidate an in-flight start.
    with _monitors_lock:
        if key in monitors:
            return _snapshot(monitors[key])
        monitors[key] = monitor

    with monitor["_check_lock"]:
        result = check_website(target_url)
        with _monitors_lock:
            if monitors.get(key) is not monitor:
                raise HTTPException(404, "Monitor no longer exists.")
            _record(monitor, result)
            return _snapshot(monitor)


@router.post("/check")
def check_monitor(
    target_url: str,
    current_user=Depends(require_role(1)),
):
    target_url = _target(target_url)
    key = (current_user.id, target_url)
    with _monitors_lock:
        monitor = monitors.get(key)
    if monitor is None:
        raise HTTPException(404, "Monitor not found.")

    # Serialize checks for this monitor without blocking other accounts.
    with monitor["_check_lock"]:
        with _monitors_lock:
            if monitors.get(key) is not monitor:
                raise HTTPException(404, "Monitor not found.")
        result = check_website(target_url)
        with _monitors_lock:
            if monitors.get(key) is not monitor:
                raise HTTPException(404, "Monitor no longer exists.")
            _record(monitor, result)
            return _snapshot(monitor)


@router.get("/status")
def uptime_status(
    target_url: Optional[str] = None,
    current_user=Depends(require_role(1)),
):
    with _monitors_lock:
        if target_url:
            monitor = monitors.get((current_user.id, _target(target_url)))
        else:
            owned = [
                monitor for (owner, _), monitor in monitors.items()
                if owner == current_user.id
            ]
            monitor = owned[-1] if owned else None
        return _snapshot(monitor) if monitor else {"monitoring": False}


@router.post("/stop")
def stop_monitor(
    target_url: str,
    current_user=Depends(require_role(1)),
):
    target_url = _target(target_url)
    with _monitors_lock:
        removed = monitors.pop((current_user.id, target_url), None)
    if removed is None:
        raise HTTPException(404, "Monitor not found.")
    return {"message": "Monitor stopped.", "target_url": target_url}
