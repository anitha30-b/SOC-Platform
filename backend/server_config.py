import platform
import socket
import psutil

from datetime import datetime, timezone
from fastapi import APIRouter

router = APIRouter(prefix="/server", tags=["Server Configuration"])


def format_uptime(seconds: int) -> str:
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60

    parts = []

    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")

    parts.append(f"{secs}s")

    return " ".join(parts)


@router.get("/configuration")
def server_configuration():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    cpu_usage = psutil.cpu_percent(interval=0.5)

    boot_time = psutil.boot_time()
    uptime_seconds = int(datetime.now().timestamp() - boot_time)

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "Unknown"

    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "Unknown"

    return {
        "server_status": "ONLINE",
        "hostname": hostname,
        "ip_address": ip_address,
        "operating_system": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "Unknown",

        "cpu_usage_percent": round(cpu_usage, 2),

        "memory_total_gb": round(memory.total / (1024 ** 3), 2),
        "memory_used_gb": round(memory.used / (1024 ** 3), 2),
        "memory_usage_percent": round(memory.percent, 2),

        "disk_total_gb": round(disk.total / (1024 ** 3), 2),
        "disk_used_gb": round(disk.used / (1024 ** 3), 2),
        "disk_free_gb": round(disk.free / (1024 ** 3), 2),
        "disk_usage_percent": round(disk.percent, 2),

        "uptime_seconds": uptime_seconds,
        "uptime": format_uptime(uptime_seconds),

        "last_checked": datetime.now(timezone.utc).isoformat(),
    }