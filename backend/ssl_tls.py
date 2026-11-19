import ipaddress
import json
import socket
import ssl
from datetime import datetime, timezone
from typing import Any


TLS_TIMEOUT = 15.0


def _normalize_host(host: str) -> str:
    host = str(host or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("A TLS hostname is required.")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host

    raise ValueError("SSL/TLS inspection requires a hostname, not an IP address.")


def _certificate_name(cert: dict[str, Any], key: str) -> str | None:
    values = cert.get(key) or []
    parts = []

    for section in values:
        for name, value in section:
            if name == "commonName":
                parts.append(str(value))

    return parts[0] if parts else None


def _certificate_sans(cert: dict[str, Any]) -> list[str]:
    sans = []

    for name, value in cert.get("subjectAltName") or []:
        if name == "DNS":
            sans.append(str(value))

    return sans


def _certificate_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        parsed = datetime.strptime(
            value,
            "%b %d %H:%M:%S %Y %Z",
        )
        return parsed.replace(tzinfo=timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def inspect_tls(host: str, port: int = 443) -> dict[str, Any]:
    host = _normalize_host(host)

    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("TLS port must be between 1 and 65535.")

    started_at = datetime.utcnow()

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    result: dict[str, Any] = {
        "status": "FAILED",
        "target": {
            "host": host,
            "port": port,
        },
        "connection": {},
        "certificate": {},
        "error": None,
        "inspected_at": started_at.isoformat(),
    }

    try:
        with socket.create_connection(
            (host, port),
            timeout=TLS_TIMEOUT,
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname=host,
            ) as tls_socket:
                cert = tls_socket.getpeercert()
                cipher = tls_socket.cipher()

                valid_from = _certificate_datetime(
                    cert.get("notBefore")
                )
                valid_until = _certificate_datetime(
                    cert.get("notAfter")
                )

                now = datetime.utcnow()
                days_remaining = None

                if valid_until:
                    days_remaining = (valid_until - now).days

                sans = _certificate_sans(cert)

                result["status"] = "COMPLETED"
                result["connection"] = {
                    "tls_protocol": tls_socket.version(),
                    "cipher_name": cipher[0] if cipher else None,
                    "cipher_protocol": cipher[1] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "hostname_verified": True,
                    "certificate_verified": True,
                }

                result["certificate"] = {
                    "subject": _certificate_name(cert, "subject"),
                    "issuer": _certificate_name(cert, "issuer"),
                    "serial_number": cert.get("serialNumber"),
                    "valid_from": (
                        valid_from.isoformat()
                        if valid_from
                        else None
                    ),
                    "valid_until": (
                        valid_until.isoformat()
                        if valid_until
                        else None
                    ),
                    "days_remaining": days_remaining,
                    "san_count": len(sans),
                    "subject_alt_names": sans,
                }

                return result

    except ssl.CertificateError as exc:
        result["error"] = {
            "type": "certificate_error",
            "message": str(exc),
        }
        return result

    except ssl.SSLError as exc:
        result["error"] = {
            "type": "ssl_error",
            "message": str(exc),
        }
        return result

    except (socket.timeout, TimeoutError) as exc:
        result["error"] = {
            "type": "timeout",
            "message": str(exc) or "TLS connection timed out.",
        }
        return result

    except OSError as exc:
        result["error"] = {
            "type": "connection_error",
            "message": str(exc),
        }
        return result

    except Exception as exc:
        result["error"] = {
            "type": "unexpected_error",
            "message": str(exc),
        }
        return result
