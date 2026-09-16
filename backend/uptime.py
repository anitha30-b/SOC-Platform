from datetime import datetime, timezone
from typing import Optional
import time

import requests
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db

router = APIRouter(prefix="/uptime", tags=["Uptime"])


# Temporary in-memory storage for the MVP.
# We will replace this with database storage after the feature is working.
monitors = {}


def check_website(url: str):
    start = time.perf_counter()

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "SOC-Platform-Uptime-Monitor/1.0"
            },
        )

        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        return {
            "status": "UP" if response.ok else "DOWN",
            "http_status": response.status_code,
            "latency_ms": latency_ms,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    except requests.RequestException as e:
        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        return {
            "status": "DOWN",
            "http_status": None,
            "latency_ms": latency_ms,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
        }


@router.post("/start")
def start_monitor(
    website_name: str,
    target_url: str,
    db: Session = Depends(get_db),
):
    target_url = target_url.strip()

    if not target_url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://",
        )

    result = check_website(target_url)

    monitors[target_url] = {
        "website_name": website_name,
        "target_url": target_url,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "checks": [result],
        "total_requests": 1,
        "successful_requests": 1 if result["status"] == "UP" else 0,
        "failed_requests": 1 if result["status"] == "DOWN" else 0,
        "current": result,
    }

    return monitors[target_url]


@router.post("/check")
def check_monitor(target_url: str):
    target_url = target_url.strip()

    monitor = monitors.get(target_url)

    if not monitor:
        raise HTTPException(
            status_code=404,
            detail="Uptime monitoring has not been started for this website",
        )

    result = check_website(target_url)

    monitor["checks"].append(result)
    monitor["current"] = result
    monitor["total_requests"] += 1

    if result["status"] == "UP":
        monitor["successful_requests"] += 1
    else:
        monitor["failed_requests"] += 1

    # Keep only recent checks for the MVP
    monitor["checks"] = monitor["checks"][-100:]

    return monitor


@router.get("/status")
def uptime_status(target_url: Optional[str] = None):
    if not target_url:
        if not monitors:
            return {"monitoring": False}

        monitor = list(monitors.values())[-1]
    else:
        monitor = monitors.get(target_url)

    if not monitor:
        return {"monitoring": False}

    total = monitor["total_requests"]
    successful = monitor["successful_requests"]

    uptime_percentage = (
        round((successful / total) * 100, 2)
        if total > 0
        else 0
    )

    return {
        "monitoring": True,
        "website_name": monitor["website_name"],
        "target_url": monitor["target_url"],
        "started_at": monitor["started_at"],
        "current": monitor["current"],
        "total_requests": monitor["total_requests"],
        "successful_requests": monitor["successful_requests"],
        "failed_requests": monitor["failed_requests"],
        "uptime_percentage": uptime_percentage,
        "recent_checks": monitor["checks"],
    }


@router.post("/stop")
def stop_monitor(target_url: str):
    if target_url not in monitors:
        raise HTTPException(
            status_code=404,
            detail="Monitoring not found",
        )

    del monitors[target_url]

    return {
        "message": "Uptime monitoring stopped",
        "target_url": target_url,
    }