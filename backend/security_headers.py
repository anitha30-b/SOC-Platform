import asyncio
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from vapt import is_private_or_reserved_host


SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def _validate_target(target_url: str) -> str:
    parsed = urlparse(target_url)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Security Headers requires an HTTP or HTTPS target.")

    if not parsed.hostname:
        raise ValueError("Security Headers target hostname is required.")

    hostname = parsed.hostname

    if is_private_or_reserved_host(hostname):
        raise ValueError(
            "Private, loopback, link-local, reserved, or multicast "
            "targets are not allowed."
        )

    return target_url


def _score_headers(header_results: list[dict[str, Any]]) -> float:
    if not header_results:
        return 0.0

    present = sum(1 for item in header_results if item["present"])
    return round((present / len(header_results)) * 10.0, 2)


async def inspect_security_headers(target_url: str) -> dict[str, Any]:
    """
    Perform a real HTTP/HTTPS Security Headers inspection.

    The function is intentionally stateless. Persistence is handled by
    the client portal background runner.
    """

    target_url = _validate_target(target_url)

    headers = {
        "User-Agent": "SOC-Platform-Security-Headers/1.0",
        "Accept": "*/*",
    }

    started_at = datetime.utcnow()

    try:
        timeout = httpx.Timeout(15.0)

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            headers=headers,
        ) as client:
            response = await client.get(target_url)

        response_headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        header_results = []

        for header_name in SECURITY_HEADERS:
            value = response_headers.get(header_name)

            header_results.append(
                {
                    "header": header_name,
                    "present": value is not None,
                    "value": value,
                }
            )

        present_count = sum(
            1 for item in header_results if item["present"]
        )
        missing_count = len(header_results) - present_count

        return {
            "status": "COMPLETED",
            "target_url": target_url,
            "final_url": str(response.url),
            "http_status": response.status_code,
            "headers": header_results,
            "header_count": len(header_results),
            "present_header_count": present_count,
            "missing_header_count": missing_count,
            "security_score": _score_headers(header_results),
            "inspected_at": started_at.isoformat(),
        }

    except asyncio.TimeoutError:
        return {
            "status": "TIMEOUT",
            "target_url": target_url,
            "error": "HTTP request timed out after 15 seconds.",
            "inspected_at": started_at.isoformat(),
        }

    except httpx.TimeoutException:
        return {
            "status": "TIMEOUT",
            "target_url": target_url,
            "error": "HTTP request timed out after 15 seconds.",
            "inspected_at": started_at.isoformat(),
        }

    except httpx.RequestError as exc:
        return {
            "status": "FAILED",
            "target_url": target_url,
            "error": str(exc),
            "inspected_at": started_at.isoformat(),
        }

    except Exception as exc:
        return {
            "status": "FAILED",
            "target_url": target_url,
            "error": str(exc),
            "inspected_at": started_at.isoformat(),
        }
