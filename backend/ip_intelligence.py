import ipaddress
import json
import re
import socket
from datetime import datetime
from typing import Any, Dict

import requests


IPINFO_URL = "https://ipinfo.io/{ip}/json"
IPINFO_TIMEOUT_SECONDS = 10


def _classify_ip(ip_address: str) -> str:
    ip = ipaddress.ip_address(ip_address)

    if ip.is_loopback:
        return "LOOPBACK"
    if ip.is_private:
        return "PRIVATE"
    if ip.is_link_local:
        return "LINK_LOCAL"
    if ip.is_multicast:
        return "MULTICAST"
    if ip.is_reserved:
        return "RESERVED"
    if ip.is_unspecified:
        return "UNSPECIFIED"

    return "PUBLIC"


def _reverse_dns(ip_address: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname.rstrip(".") if hostname else None
    except (socket.herror, socket.gaierror, OSError):
        return None


def _extract_asn(org: str | None) -> str | None:
    if not org:
        return None

    match = re.search(r"\bAS\d+\b", org.upper())
    return match.group(0) if match else None


def _parse_coordinates(value: str | None) -> tuple[float | None, float | None]:
    if not value:
        return None, None

    try:
        latitude, longitude = value.split(",", 1)
        return float(latitude.strip()), float(longitude.strip())
    except (ValueError, TypeError):
        return None, None


def enrich_ip_address(ip_address: str) -> Dict[str, Any]:
    started_at = datetime.utcnow()

    try:
        normalized_ip = str(ipaddress.ip_address(ip_address))
    except ValueError:
        return {
            "ip_address": ip_address,
            "address_type": "INVALID",
            "lookup_status": "FAILED",
            "provider": None,
            "error": "Invalid IP address",
            "lookup_started_at": started_at.isoformat(),
        }

    address_type = _classify_ip(normalized_ip)
    ptr_hostname = _reverse_dns(normalized_ip)

    result: Dict[str, Any] = {
        "ip_address": normalized_ip,
        "address_type": address_type,
        "ptr_hostname": ptr_hostname,
        "asn": None,
        "organization": None,
        "isp": None,
        "country": None,
        "region": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "lookup_status": "COMPLETED",
        "provider": "IPinfo",
        "lookup_started_at": started_at.isoformat(),
        "lookup_completed_at": datetime.utcnow().isoformat(),
    }

    # Private/reserved addresses do not have meaningful public-IP
    # geolocation/ASN data. We still return their local classification
    # and reverse DNS result.
    if address_type != "PUBLIC":
        result["provider"] = "local"
        return result

    try:
        response = requests.get(
            IPINFO_URL.format(ip=normalized_ip),
            timeout=IPINFO_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        data = response.json()

        org = data.get("org")
        latitude, longitude = _parse_coordinates(data.get("loc"))

        result.update(
            {
                "asn": _extract_asn(org),
                "organization": org,
                "isp": org,
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "latitude": latitude,
                "longitude": longitude,
                "lookup_status": "COMPLETED",
                "provider": "IPinfo",
                "result_data": data,
            }
        )

    except requests.RequestException as exc:
        result["lookup_status"] = "FAILED"
        result["error"] = f"IP intelligence provider request failed: {exc}"
    except (ValueError, TypeError) as exc:
        result["lookup_status"] = "FAILED"
        result["error"] = f"Invalid provider response: {exc}"

    result["lookup_completed_at"] = datetime.utcnow().isoformat()
    return result
