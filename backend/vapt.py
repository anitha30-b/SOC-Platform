import asyncio
import json
import re
import xml.etree.ElementTree as ET
import os
import shutil
import socket
import time
import tempfile
from pathlib import Path
from ipaddress import ip_address
from urllib.parse import urlparse
from typing import Literal, Optional

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db, SessionLocal
from cve import fetch_cve_information
from models import (
    Assessment,
    AssetDiscoveryRun,
    SecurityFinding,
    SecurityTool,
    SecurityEvent,
    User,
    UserToolPermission,
    RoleToolPermission,
)
from rbac import require_role, get_current_user
from security_event_store import store_security_event
from security_events import create_security_event, generate_event_id
from realtime_journal_listener import notify_security_event


# ==================================================
# ENVIRONMENT
# ==================================================

load_dotenv()

ALLOW_LOCAL_TARGETS = (
    os.getenv(
        "ALLOW_LOCAL_TARGETS",
        "false",
    ).lower()
    in {"true", "1", "yes"}
)

# ==================================================
# NMAP CONFIGURATION
# ==================================================

NMAP_PATH = (
    os.getenv("NMAP_PATH", "")
    or shutil.which("nmap")
    or "/usr/bin/nmap"
)


# ==================================================
# NIKTO CONFIGURATION
# ==================================================

NIKTO_PATH = (
    os.getenv("NIKTO_PATH", "")
    or shutil.which("nikto")
    or shutil.which("nikto.pl")
    or "/usr/bin/nikto"
)
NIKTO_TIMEOUT_SECONDS = int(os.getenv("NIKTO_TIMEOUT_SECONDS", "60"))
NIKTO_MAXTIME_QUICK = os.getenv("NIKTO_MAXTIME_QUICK", "30s")
NIKTO_MAXTIME_DETAILED = os.getenv("NIKTO_MAXTIME_DETAILED", "10m")
NIKTO_JOBS: dict[str, dict] = {}

def _persist_background_job(job: dict, tool: str) -> None:
    """Insert or update a VAPT job record in PostgreSQL."""
    import json
    from datetime import datetime, timezone
    from models import BackgroundJob

    db = SessionLocal()
    try:
        record = (
            db.query(BackgroundJob)
            .filter(BackgroundJob.job_id == job["job_id"])
            .first()
        )

        def as_datetime(value):
            if isinstance(value, (int, float)):
                return datetime.fromtimestamp(value, timezone.utc).replace(tzinfo=None)
            if isinstance(value, datetime):
                return value.replace(tzinfo=None)
            return datetime.utcnow()

        if record is None:
            record = BackgroundJob(
                job_id=job["job_id"],
                tool=tool,
                target=str(job.get("target", ""))[:2048],
                scan_type=job.get("scan_type"),
                user_id=job["user_id"],
                created_at=as_datetime(job.get("created_at")),
            )
            db.add(record)

        record.status = str(job.get("status", "unknown"))[:40]
        record.progress = int(job.get("progress", 0) or 0)
        record.stage = str(job.get("stage", ""))[:255]
        record.updated_at = as_datetime(job.get("updated_at"))
        record.error = str(job["error"])[:4000] if job.get("error") else None

        result = job.get("result")
        record.result_json = (
            json.dumps(result, default=str) if result is not None else None
        )

        db.commit()
    except Exception as exc:
        db.rollback()
        print(f"[BACKGROUND JOB PERSISTENCE ERROR] {tool}: {exc}")
    finally:
        db.close()



NMAP_TIMEOUT_SECONDS = int(
    os.getenv("NMAP_TIMEOUT_SECONDS", "120")
)

# Detailed scans can legitimately take several minutes, especially when
# scanning all TCP ports and running NSE vulnerability scripts.
NMAP_DETAILED_TIMEOUT_SECONDS = int(
    os.getenv("NMAP_DETAILED_TIMEOUT_SECONDS", "240")
)

NMAP_API_TIMEOUT_SECONDS = int(
    os.getenv("NMAP_API_TIMEOUT_SECONDS", "300")
)

# In-memory job store for the development/single-process FastAPI server.
# For production, replace this with Redis/Celery or a database-backed queue.
NMAP_JOBS: dict[str, dict] = {}

# Private/local targets are disabled by default.
# Enable only for authorized lab testing.
NMAP_ALLOW_PRIVATE_TARGETS = (
    os.getenv("NMAP_ALLOW_PRIVATE_TARGETS", "false").lower()
    in {"true", "1", "yes"}
)


# ==================================================
# ROUTER
# ==================================================

router = APIRouter(
    prefix="/vapt",
    tags=["VAPT Testing"],
)


# ==================================================
# SECURITY TOOL PERMISSION ENFORCEMENT
# ==================================================

def require_user_tool_permission(
    db: Session,
    current_user: User,
    tool_name: str,
) -> SecurityTool:
    """Check admin, individual override, then role-based permission."""

    tool = (
        db.query(SecurityTool)
        .filter(func.lower(SecurityTool.name) == tool_name.lower())
        .first()
    )

    if tool is None:
        raise HTTPException(
            status_code=403,
            detail=f"Security tool '{tool_name}' is not available.",
        )

    if not tool.enabled:
        raise HTTPException(
            status_code=403,
            detail=f"Security tool '{tool.name}' is currently disabled.",
        )

    # Admins can use all enabled tools.
    if current_user.role_id == 3:
        return tool

    # Individual permission takes priority, including explicit Deny.
    user_permission = (
        db.query(UserToolPermission)
        .filter(
            UserToolPermission.user_id == current_user.id,
            UserToolPermission.tool_id == tool.id,
        )
        .first()
    )

    if user_permission is not None:
        if user_permission.allowed:
            return tool

        raise HTTPException(
            status_code=403,
            detail=f"You do not have permission to use the security tool '{tool.name}'.",
        )

    # No individual override: inherit the role permission.
    role_permission = (
        db.query(RoleToolPermission)
        .filter(
            RoleToolPermission.role_id == current_user.role_id,
            RoleToolPermission.tool_id == tool.id,
        )
        .first()
    )

    if role_permission is None or not role_permission.allowed:
        raise HTTPException(
            status_code=403,
            detail=f"You do not have permission to use the security tool '{tool.name}'.",
        )

    return tool


# ==================================================
# REQUEST SCHEMA
# ==================================================

class VAPTScanRequest(BaseModel):
    target_url: HttpUrl
    scan_type: Literal["quick", "detailed"] = "quick"


class NmapToolRequest(BaseModel):
    target: str
    scan_type: Literal["comprehensive", "quick", "service", "detailed", "api"] = "comprehensive"


# ==================================================
# HOST SAFETY
# ==================================================

LOCAL_HOST_NAMES = {
    "localhost",
    "localhost.localdomain",
}


def is_local_host(hostname: str) -> bool:
    """
    Returns True only for localhost / loopback targets.
    """

    hostname_lower = hostname.lower()

    if hostname_lower in LOCAL_HOST_NAMES:
        return True

    try:
        ip = ip_address(hostname)
        return ip.is_loopback

    except ValueError:
        return False


def is_private_or_reserved_host(
    hostname: str,
) -> bool:
    """
    Blocks private, loopback, link-local, reserved
    and multicast addresses.

    Localhost/loopback may be explicitly enabled for
    local development using ALLOW_LOCAL_TARGETS=true.
    """

    if is_local_host(hostname):
        return not ALLOW_LOCAL_TARGETS

    try:
        ip = ip_address(hostname)

        if (
            ALLOW_LOCAL_TARGETS
            and ip.is_loopback
        ):
            return False

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )

    except ValueError:
        pass

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        for address in addresses:
            resolved_ip = address[4][0]

            try:
                ip = ip_address(
                    resolved_ip
                )

                # Allow loopback only when explicitly enabled.
                if (
                    ALLOW_LOCAL_TARGETS
                    and ip.is_loopback
                ):
                    continue

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                ):
                    return True

            except ValueError:
                continue

    except socket.gaierror:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unable to resolve the target hostname."
            ),
        )

    return False


# ==================================================
# ASSESSMENT MANAGEMENT
# ==================================================

def create_or_update_assessment(
    db: Session,
    current_user: User,
    target: str,
    findings_count: int,
):
    """
    Create a new assessment for the User/Client target,
    or update the existing assessment for the same
    User + target.

    User and Client are treated as the same application actor.
    """

    assessment = (
        db.query(Assessment)
        .filter(
            Assessment.user_id
            == current_user.id,

            Assessment.target
            == target,
        )
        .order_by(
            Assessment.created_at.desc()
        )
        .first()
    )

    if assessment is None:

        assessment = Assessment(
            user_id=current_user.id,
            target=target,

            vapt_status="completed",
            vapt_findings_count=findings_count,

            qa_status="not_started",
            qa_score=None,

            monitoring_status="not_started",

            report_status="not_generated",

            overall_status="active",
        )

        db.add(assessment)

    else:

        assessment.vapt_status = "completed"

        assessment.vapt_findings_count = (
            findings_count
        )

        # A new VAPT scan does not automatically erase
        # existing QA or monitoring state.
        assessment.overall_status = "active"

    db.commit()
    db.refresh(assessment)

    return assessment


# ==================================================
# SECURITY FINDING SYNC
# ==================================================

def sync_vapt_security_findings(
    db: Session,
    current_user: User,
    assessment: Assessment,
    missing_headers: list[str],
):
    """
    Synchronize the current safe-stage VAPT findings
    into the SecurityFinding table.

    These findings represent the SOC Platform's current
    HTTP security-header checks.

    They do not represent a full external scanner such as
    Nmap or other approved security tools.

    CVE is intentionally left empty because a missing
    security header normally does not have a specific CVE.
    """

    # --------------------------------------------------
    # Find the framework/tool used for this safe VAPT
    # --------------------------------------------------

    tool = (
        db.query(SecurityTool)
        .filter(
            SecurityTool.name
            == "OWASP Top 10"
        )
        .first()
    )

    # If the catalog has not been seeded yet, create it.
    if tool is None:

        tool = SecurityTool(
            name="OWASP Top 10",
            category="Web Application Security",
            description=(
                "OWASP framework for identifying "
                "and classifying major web "
                "application security risks."
            ),
            tool_type="framework",
            enabled=True,
        )

        db.add(tool)
        db.commit()
        db.refresh(tool)

    # --------------------------------------------------
    # Find existing VAPT-generated findings
    # --------------------------------------------------

    existing_findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.user_id
            == current_user.id,

            SecurityFinding.assessment_id
            == assessment.id,

            SecurityFinding.tool_name
            == "OWASP Top 10",
        )
        .all()
    )

    active_titles = set()

    # --------------------------------------------------
    # Create / update current findings
    # --------------------------------------------------

    for header in missing_headers:

        title = (
            f"VAPT: Missing security header: "
            f"{header}"
        )

        active_titles.add(title)

        existing = None

        for item in existing_findings:

            if item.title == title:
                existing = item
                break

        now = time.time()

        if existing:

            existing.description = (
                "The target response does not "
                f"include the recommended {header} "
                "security header."
            )

            existing.vulnerability = (
                "Security Header Misconfiguration"
            )

            existing.owasp_category = (
                "A05:2021 Security Misconfiguration"
            )

            existing.cve_id = None
            existing.cwe_id = None

            # Same controlled score used by the
            # existing Security Findings sample.
            existing.cvss_score = 5.3
            existing.severity = "MEDIUM"
            existing.risk_level = "LEVEL_2"

            existing.affected_asset = (
                assessment.target
            )

            existing.affected_url = (
                assessment.target
            )

            existing.endpoint = "/"

            existing.parameter = None

            existing.evidence = (
                "SOC Platform VAPT HTTP security "
                f"header check detected that "
                f"{header} is missing."
            )

            existing.request_data = None

            existing.response_data = None

            existing.impact = (
                "Missing security headers can "
                "reduce browser-side security "
                "protections and increase exposure "
                "to certain web attacks."
            )

            existing.remediation = (
                f"Configure the target application "
                f"to return the {header} security "
                "header with an appropriate value."
            )

            existing.references = (
                "https://owasp.org/"
                "www-project-secure-headers/"
            )

            existing.status = "OPEN"

            existing.detected_at = (
                __import__(
                    "datetime"
                ).datetime.utcnow()
            )

            existing.updated_at = (
                __import__(
                    "datetime"
                ).datetime.utcnow()
            )

        else:

            from datetime import datetime

            finding = SecurityFinding(

                finding_id=generate_finding_id(
                    db
                ),

                user_id=current_user.id,

                assessment_id=assessment.id,

                tool_name=tool.name,

                tool_category=tool.category,

                title=title,

                vulnerability=(
                    "Security Header Misconfiguration"
                ),

                description=(
                    "The target response does not "
                    f"include the recommended {header} "
                    "security header."
                ),

                owasp_category=(
                    "A05:2021 Security Misconfiguration"
                ),

                owasp_api_category=None,

                # No specific CVE applies to this
                # configuration finding.
                cve_id=None,

                cwe_id=None,

                cvss_score=5.3,

                severity="MEDIUM",

                risk_level="LEVEL_2",

                affected_asset=assessment.target,

                affected_url=assessment.target,

                endpoint="/",

                parameter=None,

                evidence=(
                    "SOC Platform VAPT HTTP security "
                    f"header check detected that "
                    f"{header} is missing."
                ),

                request_data=None,

                response_data=None,

                impact=(
                    "Missing security headers can "
                    "reduce browser-side security "
                    "protections and increase exposure "
                    "to certain web attacks."
                ),

                remediation=(
                    f"Configure the target application "
                    f"to return the {header} security "
                    "header with an appropriate value."
                ),

                references=(
                    "https://owasp.org/"
                    "www-project-secure-headers/"
                ),

                status="OPEN",

                detected_at=datetime.utcnow(),

                created_at=datetime.utcnow(),

                updated_at=datetime.utcnow(),
            )

            db.add(finding)
            db.flush()

    # --------------------------------------------------
    # Mark previously detected but now-fixed VAPT
    # findings as FIXED
    # --------------------------------------------------

    for existing in existing_findings:

        if existing.title.startswith(
            "VAPT: Missing security header:"
        ):

            if existing.title not in active_titles:

                existing.status = "FIXED"

                from datetime import datetime

                existing.updated_at = (
                    datetime.utcnow()
                )

    db.commit()


# ==================================================
# FINDING ID GENERATOR
# ==================================================

def generate_finding_id(
    db: Session,
) -> str:
    """
    Generate IDs such as:
    FIND-000001
    FIND-000002
    """

    latest = (
        db.query(SecurityFinding)
        .order_by(
            SecurityFinding.id.desc()
        )
        .first()
    )

    if latest is None:
        next_id = 1
    else:
        next_id = latest.id + 1

    return f"FIND-{next_id:06d}"


# ==================================================
# NMAP TARGET VALIDATION
# ==================================================

def validate_nmap_target(target: str) -> str:
    """Validate a hostname/IP before passing it to Nmap."""

    target = target.strip()

    if not target:
        raise HTTPException(status_code=400, detail="Nmap target cannot be empty.")

    if len(target) > 253:
        raise HTTPException(status_code=400, detail="Nmap target is too long.")

    # The API accepts a target only; arbitrary shell/Nmap arguments are rejected.
    if any(character in target for character in [
        ";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r", "\x00"
    ]):
        raise HTTPException(status_code=400, detail="Invalid characters in Nmap target.")

    hostname_pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:]*$")
    if not hostname_pattern.fullmatch(target):
        raise HTTPException(status_code=400, detail="Invalid hostname or IP address.")

    try:
        ip = ip_address(target)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ) and not NMAP_ALLOW_PRIVATE_TARGETS:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Private/local Nmap targets are disabled. Set "
                    "NMAP_ALLOW_PRIVATE_TARGETS=true only for authorized lab testing."
                ),
            )
    except ValueError:
        try:
            resolved = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            for address in resolved:
                resolved_ip = address[4][0]
                try:
                    resolved_obj = ip_address(resolved_ip)
                    if (
                        resolved_obj.is_private
                        or resolved_obj.is_loopback
                        or resolved_obj.is_link_local
                        or resolved_obj.is_reserved
                        or resolved_obj.is_multicast
                    ) and not NMAP_ALLOW_PRIVATE_TARGETS:
                        raise HTTPException(
                            status_code=403,
                            detail=(
                                "The target resolves to a private/local address. "
                                "Private Nmap targets are disabled."
                            ),
                        )
                except ValueError:
                    continue
        except socket.gaierror:
            raise HTTPException(
                status_code=400,
                detail="Unable to resolve Nmap target.",
            )

    return target


# ==================================================
# NMAP XML PARSER
# ==================================================

def _parse_nmap_script(script_element: ET.Element) -> dict:
    """Parse one NSE <script> element into frontend-friendly JSON."""

    script = {
        "id": script_element.get("id"),
        "output": script_element.get("output", ""),
        "elements": {},
    }

    for elem in script_element.findall("elem"):
        key = elem.get("key") or "value"
        script["elements"][key] = elem.text or ""

    for table in script_element.findall("table"):
        key = table.get("key") or "table"
        values = {}
        for elem in table.findall("elem"):
            values[elem.get("key") or "value"] = elem.text or ""
        script["elements"][key] = values

    return script


def parse_nmap_xml(xml_output: str) -> dict:
    """Convert Nmap XML output to structured JSON, including NSE and OS data."""

    hosts = []

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        return {"hosts": [], "host_count": 0, "parse_error": str(exc)}

    if root.tag != "nmaprun":
        return {"hosts": [], "host_count": 0, "parse_error": "Expected an Nmap XML document."}

    for host in root.findall("host"):
        status_element = host.find("status")
        status = status_element.get("state") if status_element is not None else "unknown"

        addresses = []
        for address in host.findall("address"):
            address_value = address.get("addr")
            if address_value:
                addresses.append({
                    "address": address_value,
                    "type": address.get("addrtype"),
                })

        hostnames = []
        hostnames_element = host.find("hostnames")
        if hostnames_element is not None:
            for hostname in hostnames_element.findall("hostname"):
                name = hostname.get("name")
                if name:
                    hostnames.append(name)

        ports = []
        ports_element = host.find("ports")
        if ports_element is not None:
            for port in ports_element.findall("port"):
                state_element = port.find("state")
                service_element = port.find("service")
                service = {}
                if service_element is not None:
                    service = {
                        "name": service_element.get("name"),
                        "product": service_element.get("product"),
                        "version": service_element.get("version"),
                        "extrainfo": service_element.get("extrainfo"),
                        "tunnel": service_element.get("tunnel"),
                        "method": service_element.get("method"),
                    }

                try:
                    port_number = int(port.get("portid", "0"))
                except ValueError:
                    port_number = 0

                scripts = [
                    _parse_nmap_script(script)
                    for script in port.findall("script")
                ]

                ports.append({
                    "protocol": port.get("protocol", "unknown"),
                    "port": port_number,
                    "state": (
                        state_element.get("state")
                        if state_element is not None
                        else "unknown"
                    ),
                    "reason": (
                        state_element.get("reason")
                        if state_element is not None
                        else None
                    ),
                    "service": service,
                    "scripts": scripts,
                })

        host_scripts = [
            _parse_nmap_script(script)
            for script in host.findall("hostscript/script")
        ]

        os_matches = []
        os_element = host.find("os")
        if os_element is not None:
            for match in os_element.findall("osmatch"):
                os_matches.append({
                    "name": match.get("name"),
                    "accuracy": match.get("accuracy"),
                    "line": match.get("line"),
                })

        uptime_element = host.find("uptime")
        uptime = None
        if uptime_element is not None:
            uptime = {
                "seconds": uptime_element.get("seconds"),
                "lastboot": uptime_element.get("lastboot"),
            }

        hosts.append({
            "status": status,
            "addresses": addresses,
            "hostnames": hostnames,
            "ports": ports,
            "scripts": host_scripts,
            "os_matches": os_matches,
            "uptime": uptime,
        })

    parsed = {"hosts": hosts, "host_count": len(hosts)}
    finished = root.find("runstats/finished")
    if finished is not None and finished.get("exit") == "error":
        parsed["scan_error"] = finished.get("errormsg") or "Nmap reported a scan error."
    return parsed


# ==================================================
# NMAP WORKFLOW / PERFORMANCE OPTIMIZATION
# ==================================================

# The platform keeps Nmap functionality available, but each profile now
# performs only the work promised by the UI. The old implementation forced
# every request into the heaviest comprehensive workflow, which made even
# "Quick" scans perform a 65,535-port scan plus vulnerability NSE.
#
# Full functionality is still available through the "detailed" and
# "comprehensive" profiles. The detailed/comprehensive profiles reduce
# wall-clock time by:
#   1. using -T4 and one-retry behavior for controlled scans,
#   2. discovering ports once and reusing the resulting open-port list,
#   3. running independent service/vulnerability/HTTP checks concurrently,
#   4. avoiding traceroute in quick/service profiles,
#   5. limiting HTTP NSE to confirmed web ports.

NMAP_VULN_SCRIPTS = "vuln"
NMAP_HTTP_SCRIPTS = (
    "http-title,http-headers,http-methods,http-security-headers,"
    "http-enum,http-auth-finder,http-cors,ssl-cert"
)

NMAP_QUICK_TIMEOUT = int(
    os.getenv("NMAP_QUICK_TIMEOUT_SECONDS", "300")
)
NMAP_SERVICE_TIMEOUT = int(
    os.getenv("NMAP_SERVICE_TIMEOUT_SECONDS", "180")
)
NMAP_DETAILED_TIMEOUT = int(
    os.getenv("NMAP_DETAILED_TIMEOUT_SECONDS", "600")
)
NMAP_COMPREHENSIVE_TIMEOUT = int(
    os.getenv("NMAP_COMPREHENSIVE_TIMEOUT_SECONDS", "900")
)
NMAP_PORT_SCAN_TIMEOUT = int(
    os.getenv("NMAP_PORT_SCAN_TIMEOUT_SECONDS", "600")
)

# Nmap rate controls. These are intentionally moderate so that scan speed
# improves without turning the application into an uncontrolled packet flood.
NMAP_MIN_RATE = os.getenv("NMAP_MIN_RATE", "300")
NMAP_MAX_RATE = os.getenv("NMAP_MAX_RATE", "3000")

NMAP_PROFILES = {
    "quick": {
        "profile": "top_1000_fast",
        "timeout": NMAP_QUICK_TIMEOUT,
        "stage": "Quick Nmap scan",
    },
    "service": {
        "profile": "top_1000_service_detection",
        "timeout": NMAP_SERVICE_TIMEOUT,
        "stage": "Nmap service detection",
    },
    "detailed": {
        "profile": "all_tcp_service_os_nse_vuln_http",
        "timeout": NMAP_DETAILED_TIMEOUT,
        "stage": "Detailed Nmap assessment",
    },
    "api": {
        "profile": "http_api_security",
        "timeout": NMAP_SERVICE_TIMEOUT,
        "stage": "Nmap HTTP/API security checks",
    },
    "comprehensive": {
        "profile": "all_tcp_service_os_nse_vuln_http_traceroute",
        "timeout": NMAP_COMPREHENSIVE_TIMEOUT,
        "stage": "Comprehensive Nmap assessment",
    },
}


async def _run_nmap_pass(
    command,
    timeout,
    stderr_lines,
    progress_callback,
    progress_start,
    progress_end,
    stage,
):
    """Run one controlled Nmap pass and return XML + diagnostics."""

    if progress_callback:
        await progress_callback(progress_start, stage)

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass

        stdout, stderr = await process.communicate()
        stderr_text = stderr.decode("utf-8", errors="replace")
        stderr_lines.extend(
            [x.strip() for x in stderr_text.splitlines() if x.strip()][-30:]
        )

        if progress_callback:
            await progress_callback(
                progress_end,
                f"{stage} timed out",
            )

        return {
            "return_code": None,
            "timed_out": True,
            "xml": stdout.decode("utf-8", errors="replace"),
        }

    stderr_text = stderr.decode("utf-8", errors="replace")
    stderr_lines.extend(
        [x.strip() for x in stderr_text.splitlines() if x.strip()][-30:]
    )

    if progress_callback:
        await progress_callback(
            progress_end,
            stage + " completed",
        )

    return {
        "return_code": process.returncode,
        "timed_out": False,
        "xml": stdout.decode("utf-8", errors="replace"),
    }


def _nmap_rate_args():
    """Return conservative rate controls for faster authorized scanning."""
    args = []

    if NMAP_MIN_RATE:
        args.extend(["--min-rate", NMAP_MIN_RATE])

    if NMAP_MAX_RATE:
        args.extend(["--max-rate", NMAP_MAX_RATE])

    return args


def _extract_open_ports(parsed: dict) -> list[int]:
    """Extract unique open TCP ports from parsed Nmap XML."""
    return sorted({
        int(port.get("port"))
        for host in parsed.get("hosts", [])
        for port in host.get("ports", [])
        if (
            port.get("state") == "open"
            and str(port.get("port", "")).isdigit()
        )
    })


async def _execute_nmap_command(
    target: str,
    scan_type: str,
    progress_callback=None,
    result_callback=None,
) -> dict:
    """
    Execute an Nmap profile while preserving the full Nmap feature set.

    Profiles:
      quick         -> top 1,000 TCP ports
      service       -> top 1,000 + service/version/default NSE
      detailed      -> all TCP + service/version + OS + default NSE +
                       vulnerability NSE + HTTP/TLS NSE
      api           -> top 1,000 + HTTP/API/TLS NSE
      comprehensive -> all TCP + service/version + OS + default NSE +
                       vulnerability NSE + HTTP/TLS NSE + traceroute
    """

    from nmap_result_integrity import analyze_nmap_pass, apply_nmap_outcomes, merge_nmap_results

    analyses = {}

    def pass_report(scan_pass):
        key = id(scan_pass)
        if key not in analyses:
            analyses[key] = analyze_nmap_pass(scan_pass, parse_nmap_xml)
        return analyses[key]

    async def run_pass(*args, **kwargs):
        try:
            return await _run_nmap_pass(*args, **kwargs)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Preserve other stages and any earlier evidence if one process fails.
            return {"xml": "", "return_code": None, "timed_out": False,
                    "execution_error": f"{type(exc).__name__}: {exc}"}

    def full_inventory_complete():
        return any(name == "all_tcp_ports" and pass_report(data)["complete"]
                   for name, data in passes)

    def finish_result(result):
        return apply_nmap_outcomes(result, [(name, pass_report(data)) for name, data in passes])


    target = validate_nmap_target(target)

    if scan_type not in NMAP_PROFILES:
        scan_type = "quick"

    profile = NMAP_PROFILES[scan_type]

    if not NMAP_PATH or not os.path.exists(NMAP_PATH):
        return {
            "tool": "Nmap",
            "available": False,
            "status": "not_available",
            "target": target,
            "scan_type": scan_type,
            "results": {"hosts": [], "host_count": 0},
            "errors": ["Nmap executable was not found."],
        }

    started = time.perf_counter()
    stderr_lines: list[str] = []
    passes = []
    timed_out = False

    async def publish(parsed, stage, percent, extra=None):
        payload = {
            "tool": "Nmap",
            "available": True,
            "status": "running",
            "target": target,
            "scan_type": scan_type,
            "command_profile": profile["profile"],
            "elapsed_seconds": round(
                time.perf_counter() - started,
                2,
            ),
            "results": parsed,
            "open_ports": _extract_open_ports(parsed),
            "errors": stderr_lines[-30:],
            "workflow": {
                "passes": [name for name, _ in passes],
                "stage": stage,
                **(extra or {}),
            },
        }

        if "all_tcp_ports_scanned" in payload["workflow"]:
            payload["workflow"]["all_tcp_ports_scanned"] = full_inventory_complete()

        if result_callback:
            await result_callback(payload)

        if progress_callback:
            await progress_callback(percent, stage)

    try:
        # --------------------------------------------------
        # PROFILE: QUICK
        # --------------------------------------------------
        if scan_type == "quick":
            command = [
                NMAP_PATH,
                "-Pn",
                "-T5",
                "-sT",
                "--top-ports",
                "1000",
                "--max-retries",
                "0",
                "--host-timeout",
                "30s",
                "--min-rate",
                "1000",
                "--max-rate",
                "5000",
                "-oX",
                "-",
                target,
            ]

            scan_pass = await run_pass(
                command,
                NMAP_QUICK_TIMEOUT,
                stderr_lines,
                progress_callback,
                5,
                95,
                "Fast discovery of top 1,000 TCP ports",
            )

            passes.append(("top_1000_tcp", scan_pass))
            timed_out = scan_pass["timed_out"]

            parsed = parse_nmap_xml(scan_pass["xml"])
            for key in ("parse_error", "scan_error"):
                if parsed.get(key):
                    stderr_lines.append(str(parsed[key]))
            if scan_pass["return_code"] not in (None, 0):
                stderr_lines.append(f"Nmap exited with code {scan_pass['return_code']}.")
            result = {
                "tool": "Nmap",
                "available": True,
                "status": (
                    "completed_with_errors"
                    if (timed_out or scan_pass["return_code"] != 0
                        or parsed.get("parse_error") or parsed.get("scan_error"))
                    else "completed"
                ),
                "return_code": (
                    None if timed_out else scan_pass["return_code"]
                ),
                "target": target,
                "scan_type": scan_type,
                "command_profile": profile["profile"],
                "command_display": (
                    "Top 1,000 TCP ports with fast discovery"
                ),
                "elapsed_seconds": round(
                    time.perf_counter() - started,
                    2,
                ),
                "results": parsed,
                "open_ports": _extract_open_ports(parsed),
                "errors": stderr_lines[-40:],
                "nse": {
                    "enabled": False,
                    "description": (
                        "Quick profile does not run vulnerability NSE."
                    ),
                },
                "workflow": {
                    "passes": [name for name, _ in passes],
                    "open_port_count": len(
                        _extract_open_ports(parsed)
                    ),
                    "all_tcp_ports_scanned": False,
                    "final_result_only": True,
                },
            }

            result = finish_result(result)

            if result_callback:
                await result_callback(result)

            if progress_callback:
                await progress_callback(
                    100,
                    "Quick Nmap scan completed" if result["status"] == "completed" else "Quick Nmap scan finished with errors",
                )

            return result

        # --------------------------------------------------
        # PROFILE: SERVICE
        # --------------------------------------------------
        if scan_type == "service":
            command = [
                NMAP_PATH,
                "-Pn",
                "-T4",
                "-sT",
                "--top-ports",
                "1000",
                "-sV",
                "-sC",
                "--version-light",
                "--max-retries",
                "1",
                "--host-timeout",
                "150s",
                *_nmap_rate_args(),
                "-oX",
                "-",
                target,
            ]

            scan_pass = await run_pass(
                command,
                NMAP_SERVICE_TIMEOUT,
                stderr_lines,
                progress_callback,
                5,
                95,
                "Service/version detection on top 1,000 ports",
            )

            passes.append(("top_1000_service_default_nse", scan_pass))
            timed_out = scan_pass["timed_out"]

            parsed = parse_nmap_xml(scan_pass["xml"])
            for key in ("parse_error", "scan_error"):
                if parsed.get(key):
                    stderr_lines.append(str(parsed[key]))
            if scan_pass["return_code"] not in (None, 0):
                stderr_lines.append(f"Nmap exited with code {scan_pass['return_code']}.")
            result = {
                "tool": "Nmap",
                "available": True,
                "status": (
                    "completed_with_errors"
                    if (timed_out or scan_pass["return_code"] != 0
                        or parsed.get("parse_error") or parsed.get("scan_error"))
                    else "completed"
                ),
                "return_code": (
                    None if timed_out else scan_pass["return_code"]
                ),
                "target": target,
                "scan_type": scan_type,
                "command_profile": profile["profile"],
                "command_display": (
                    "Top 1,000 TCP ports → service/version detection → default NSE"
                ),
                "elapsed_seconds": round(
                    time.perf_counter() - started,
                    2,
                ),
                "results": parsed,
                "open_ports": _extract_open_ports(parsed),
                "errors": stderr_lines[-40:],
                "nse": {
                    "enabled": True,
                    "category": "default",
                },
                "workflow": {
                    "passes": [name for name, _ in passes],
                    "open_port_count": len(
                        _extract_open_ports(parsed)
                    ),
                    "all_tcp_ports_scanned": False,
                    "final_result_only": True,
                },
            }

            result = finish_result(result)

            if result_callback:
                await result_callback(result)

            if progress_callback:
                await progress_callback(
                    100,
                    "Nmap service scan completed" if result["status"] == "completed" else "Nmap service scan finished with errors",
                )

            return result

        # --------------------------------------------------
        # PROFILE: API
        # --------------------------------------------------
        if scan_type == "api":
            discovery_command = [
                NMAP_PATH,
                "-Pn",
                "-T4",
                "-sT",
                "--top-ports",
                "1000",
                "--max-retries",
                "1",
                "--host-timeout",
                "90s",
                *_nmap_rate_args(),
                "-oX",
                "-",
                target,
            ]

            discovery_pass = await run_pass(
                discovery_command,
                NMAP_QUICK_TIMEOUT,
                stderr_lines,
                progress_callback,
                5,
                35,
                "Discovering web/API ports",
            )

            passes.append(("top_1000_api_discovery", discovery_pass))
            timed_out = discovery_pass["timed_out"]

            parsed_discovery = parse_nmap_xml(
                discovery_pass["xml"]
            )
            open_ports = _extract_open_ports(parsed_discovery)

            http_ports = [
                port
                for port in open_ports
                if port in {
                    80,
                    443,
                    8000,
                    8080,
                    8443,
                    8888,
                    3000,
                    5000,
                    8008,
                    9000,
                }
            ]

            if http_ports:
                http_command = [
                    NMAP_PATH,
                    "-Pn",
                    "-T4",
                    "-sT",
                    "-p",
                    ",".join(map(str, http_ports)),
                    "--script",
                    NMAP_HTTP_SCRIPTS,
                    "--max-retries",
                    "1",
                    *_nmap_rate_args(),
                    "-oX",
                    "-",
                    target,
                ]

                http_pass = await run_pass(
                    http_command,
                    min(120, NMAP_SERVICE_TIMEOUT),
                    stderr_lines,
                    progress_callback,
                    40,
                    95,
                    "HTTP/API/TLS security checks",
                )

                passes.append(("http_api_tls_nse", http_pass))
                timed_out = timed_out or http_pass["timed_out"]
                parsed_http = parse_nmap_xml(
                    http_pass["xml"]
                )
            else:
                parsed_http = {
                    "hosts": [],
                    "host_count": 0,
                }
                if progress_callback:
                    await progress_callback(
                        95,
                        "No common HTTP/API ports discovered",
                    )

            final_results = merge_nmap_results(parsed_discovery, parsed_http)
            open_ports = _extract_open_ports(final_results)

            result = {
                "tool": "Nmap",
                "available": True,
                "status": (
                    "completed_with_errors"
                    if timed_out
                    else "completed"
                ),
                "return_code": None if timed_out else 0,
                "target": target,
                "scan_type": scan_type,
                "command_profile": profile["profile"],
                "command_display": (
                    "Top 1,000 discovery → confirmed HTTP/API/TLS NSE"
                ),
                "elapsed_seconds": round(
                    time.perf_counter() - started,
                    2,
                ),
                "results": final_results,
                "open_ports": open_ports,
                "errors": stderr_lines[-40:],
                "nse": {
                    "enabled": True,
                    "category": "http-security",
                    "scripts": NMAP_HTTP_SCRIPTS,
                },
                "workflow": {
                    "passes": [name for name, _ in passes],
                    "open_port_count": len(open_ports),
                    "http_ports": http_ports,
                    "all_tcp_ports_scanned": False,
                    "final_result_only": True,
                },
            }

            result = finish_result(result)

            if result_callback:
                await result_callback(result)

            if progress_callback:
                await progress_callback(
                    100,
                    "Nmap API security scan completed" if result["status"] == "completed" else "Nmap API security scan finished with errors",
                )

            return result

        # --------------------------------------------------
        # PROFILES: DETAILED / COMPREHENSIVE
        # --------------------------------------------------

        # Stage 1: discover top ports first. This gives quick feedback and
        # prevents vulnerability scripts from being run against closed ports.
        discovery_command = [
            NMAP_PATH,
            "-Pn",
            "-T5",
            "-sT",
            "--top-ports",
            "1000",
            "--max-retries",
            "0",
            "--host-timeout",
            "45s",
            "--min-rate",
            "1000",
            "--max-rate",
            "10000",
            "-oX",
            "-",
            target,
        ]

        discovery_pass = await run_pass(
            discovery_command,
            110,
            stderr_lines,
            progress_callback,
            5,
            18,
            "Fast discovery of top 1,000 TCP ports",
        )

        passes.append(("top_1000_tcp_discovery", discovery_pass))
        timed_out = discovery_pass["timed_out"]

        parsed_discovery = parse_nmap_xml(
            discovery_pass["xml"]
        )

        await publish(
            parsed_discovery,
            "Initial discovery completed",
            18,
            {
                "preliminary": True,
                "all_tcp_ports_scanned": False,
            },
        )

        # Stage 2: full TCP inventory. This remains available for detailed
        # and comprehensive scans, but it happens only once.
        full_command = [
            NMAP_PATH,
            "-Pn",
            "-T5",
            "-sT",
            "-p-",
            "--max-retries",
            "0",
            "--host-timeout",
            f"{NMAP_PORT_SCAN_TIMEOUT}s",
            "--min-rate",
            "1000",
            "--max-rate",
            "10000",
            "-oX",
            "-",
            target,
        ]

        full_pass = await run_pass(
            full_command,
            NMAP_PORT_SCAN_TIMEOUT + 30,
            stderr_lines,
            progress_callback,
            19,
            43,
            "Authoritative scan of all 65,535 TCP ports",
        )

        passes.append(("all_tcp_ports", full_pass))
        timed_out = timed_out or full_pass["timed_out"]

        parsed_ports = parse_nmap_xml(full_pass["xml"])

        if pass_report(full_pass)["complete"]:
            base = parsed_ports
            await publish(
                parsed_ports,
                "Full TCP discovery completed",
                43,
                {
                    "preliminary": False,
                    "all_tcp_ports_scanned": not full_pass["timed_out"],
                },
            )
        else:
            base = merge_nmap_results(parsed_discovery, parsed_ports)
            await publish(
                base,
                "Full TCP pass incomplete; retaining discovery results",
                43,
                {
                    "preliminary": True,
                    "all_tcp_ports_scanned": False,
                },
            )

        open_ports = _extract_open_ports(base)

        if not open_ports:
            result = {
                "tool": "Nmap",
                "available": True,
                "status": (
                    "completed_with_errors"
                    if timed_out
                    else "completed"
                ),
                "return_code": None if timed_out else 0,
                "target": target,
                "scan_type": scan_type,
                "command_profile": profile["profile"],
                "command_display": (
                    "Top 1,000 discovery → all TCP ports → "
                    "service/OS/default NSE → vulnerability NSE → "
                    "HTTP/TLS NSE"
                ),
                "elapsed_seconds": round(
                    time.perf_counter() - started,
                    2,
                ),
                "results": base,
                "open_ports": [],
                "errors": stderr_lines[-40:],
                "nse": {
                    "enabled": True,
                    "category": "default,vuln,http-security",
                },
                "workflow": {
                    "passes": [name for name, _ in passes],
                    "open_port_count": 0,
                    "all_tcp_ports_scanned": not timed_out,
                    "final_result_only": True,
                },
            }

            result = finish_result(result)

            if result_callback:
                await result_callback(result)

            if progress_callback:
                await progress_callback(
                    100,
                    "Completed - no open TCP ports discovered" if result["status"] == "completed" else "Finished with errors; no open TCP ports confirmed",
                )

            return result

        port_list = ",".join(map(str, open_ports))

        # Independent post-discovery checks are run concurrently. This is the
        # main wall-clock optimization: service/OS/default NSE and vulnerability
        # NSE no longer wait for one another.
        detail_args = [
            NMAP_PATH,
            "-Pn",
            "-T5",
            "-sT",
            "-p",
            port_list,
            "-sV",
            "-sC",
            "-O",
            "--version-light",
            "--max-retries",
            "0",
            "--script-timeout",
            "90s",
            "--min-rate",
            "500",
            "--max-rate",
            "10000",
        ]

        if scan_type in {"quick", "comprehensive"}:
            detail_args.append("--traceroute")

        detail_command = [
            *detail_args,
            "-oX",
            "-",
            target,
        ]

        vuln_command = [
            NMAP_PATH,
            "-Pn",
            "-T5",
            "-sT",
            "-p",
            port_list,
            "--script",
            NMAP_VULN_SCRIPTS,
            "--script-timeout",
            "90s",
            "--max-retries",
            "0",
            "--min-rate",
            "500",
            "--max-rate",
            "10000",
            "-oX",
            "-",
            target,
        ]

        detail_task = run_pass(
            detail_command,
            NMAP_DETAILED_TIMEOUT,
            stderr_lines,
            None,
            0,
            0,
            "Service/version/OS/default NSE",
        )

        vuln_task = run_pass(
            vuln_command,
            NMAP_DETAILED_TIMEOUT,
            stderr_lines,
            None,
            0,
            0,
            "Vulnerability NSE",
        )

        detail_pass, vuln_pass = await asyncio.gather(
            detail_task,
            vuln_task,
        )

        passes.append(
            ("service_version_os_default_nse", detail_pass)
        )
        passes.append(
            ("vulnerability_nse", vuln_pass)
        )

        timed_out = (
            timed_out
            or detail_pass["timed_out"]
            or vuln_pass["timed_out"]
        )

        parsed_detail = parse_nmap_xml(
            detail_pass["xml"]
        )
        parsed_vuln = parse_nmap_xml(
            vuln_pass["xml"]
        )

        current = merge_nmap_results(base, parsed_detail)

        await publish(
            current,
            "Service, version, OS and vulnerability results available",
            82,
            {
                "all_tcp_ports_scanned": not timed_out,
                "vulnerability_hosts": len(
                    parsed_vuln.get("hosts", [])
                ),
                "parallel_post_discovery_checks": True,
            },
        )

        # HTTP/TLS checks are also limited to confirmed common web ports.
        http_ports = [
            port
            for port in open_ports
            if port in {
                80,
                443,
                8000,
                8080,
                8443,
                8888,
                3000,
                5000,
                8008,
                9000,
            }
        ]

        parsed_http = {
            "hosts": [],
            "host_count": 0,
        }

        if http_ports:
            http_command = [
                NMAP_PATH,
                "-Pn",
                "-T5",
                "-sT",
                "-p",
                ",".join(map(str, http_ports)),
                "--script",
                NMAP_HTTP_SCRIPTS,
                "--script-timeout",
                "60s",
                "--max-retries",
                "0",
                "--min-rate",
                "500",
                "--max-rate",
                "10000",
                "-oX",
                "-",
                target,
            ]

            http_pass = await run_pass(
                http_command,
                min(120, NMAP_DETAILED_TIMEOUT),
                stderr_lines,
                progress_callback,
                83,
                95,
                "HTTP/API/TLS security checks",
            )

            passes.append(("http_tls_nse", http_pass))
            timed_out = timed_out or http_pass["timed_out"]
            parsed_http = parse_nmap_xml(
                http_pass["xml"]
            )
        else:
            if progress_callback:
                await progress_callback(
                    95,
                    "No common HTTP ports open — HTTP/TLS checks skipped",
                )

        final_results = merge_nmap_results(base, parsed_detail, parsed_vuln, parsed_http)
        open_ports = _extract_open_ports(final_results)

        result = {
            "tool": "Nmap",
            "available": True,
            "status": (
                "completed_with_errors"
                if timed_out
                else "completed"
            ),
            "return_code": None if timed_out else 0,
            "target": target,
            "scan_type": scan_type,
            "command_profile": profile["profile"],
            "command_display": (
                "Top 1,000 discovery → all TCP ports → "
                "service/version → default NSE/OS"
                + (
                    " → traceroute"
                    if scan_type == "comprehensive"
                    else ""
                )
                + " → vuln NSE → HTTP/TLS NSE"
            ),
            "elapsed_seconds": round(
                time.perf_counter() - started,
                2,
            ),
            "results": final_results,
            "open_ports": open_ports,
            "errors": stderr_lines[-40:] + (
                [
                    "One or more scan stages timed out; "
                    "displayed results are the actual Nmap evidence "
                    "obtained before timeout."
                ]
                if timed_out
                else []
            ),
            "nse": {
                "enabled": True,
                "category": "default,vuln,http-security",
                "description": (
                    "Controlled NSE categories were executed against "
                    "confirmed open services."
                ),
            },
            "workflow": {
                "passes": [name for name, _ in passes],
                "open_port_count": len(open_ports),
                "http_ports": http_ports,
                "all_tcp_ports_scanned": not timed_out,
                "parallel_post_discovery_checks": True,
                "final_result_only": True,
            },
        }

        result = finish_result(result)

        if result_callback:
            await result_callback(result)

        if progress_callback:
            await progress_callback(
                100,
                f"{scan_type.title()} Nmap assessment completed" if result["status"] == "completed" else f"{scan_type.title()} Nmap assessment finished with errors",
            )

        return result

    except asyncio.CancelledError:
        raise

    except Exception as exc:
        error_result = {
            "tool": "Nmap",
            "available": True,
            "status": "failed",
            "target": target,
            "scan_type": scan_type,
            "command_profile": profile["profile"],
            "results": {
                "hosts": [],
                "host_count": 0,
            },
            "errors": (
                [str(exc)]
                + stderr_lines[-20:]
            ),
        }

        if result_callback:
            await result_callback(error_result)

        return error_result


# ==================================================
# NMAP BACKGROUND JOBS / PROGRESS
# ==================================================


def _new_nmap_job(target: str, scan_type: str, user_id: int, client_id: int | None = None) -> str:
    import uuid

    job_id = str(uuid.uuid4())
    NMAP_JOBS[job_id] = {
        "job_id": job_id,
        "target": target,
        "scan_type": scan_type,
        "user_id": user_id,
        "client_id": client_id,
        "status": "queued",
        "progress": 0,
        "stage": "Queued",
        "result": None,
        "error": None,
        "created_at": time.time(),
        "updated_at": time.time(),
    }
    _persist_background_job(NMAP_JOBS[job_id], "Nmap")
    return job_id



def _save_nmap_hosts_to_asset_inventory(result, user_id, client_id, job_id):
    """Commit owned scan inventory and its event as one transaction."""
    from nmap_workflow import persist_nmap_completion
    db = SessionLocal()
    try:
        summary, notification = persist_nmap_completion(db, result, user_id, client_id, job_id)
        db.commit()
        return summary, notification
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


async def _run_nmap_job(job_id: str, target: str, scan_type: str):
    job = NMAP_JOBS.get(job_id)
    if not job:
        return

    async def update_progress(percent, stage):
        job.update(status='running', progress=percent, stage=stage, updated_at=time.time())
        await asyncio.to_thread(_persist_background_job, job.copy(), 'Nmap')

    async def update_result(partial_result):
        return

    try:
        job.update(status='running', progress=3, stage='Starting Nmap', updated_at=time.time())
        result = await _execute_nmap_command(target=target, scan_type=scan_type,
                    progress_callback=update_progress, result_callback=update_result)
        job['result'] = result
        if result.get('status') in {'completed', 'completed_with_errors'}:
            # Persistence uses the authenticated job scope, never result payload ownership.
            summary, notification = await asyncio.to_thread(_save_nmap_hosts_to_asset_inventory,
                result, job.get('user_id'), job.get('client_id'), job_id)
            result['asset_sync'] = summary
            result['assessment_id'] = summary['assessment_id']
            job['asset_sync'] = summary
            job['asset_sync_error'] = None
            try:
                await asyncio.to_thread(notify_security_event, notification)
            except Exception as exc:
                # The committed evidence remains available through scoped API refresh.
                job['notification_error'] = str(exc)
                result['execution_status'] = result.get('status')
                result['status'] = 'completed_with_errors'
                result.setdefault('errors', []).append('Live notification failed; saved results are available by refresh.')
        status = result.get('status', 'failed')
        job.update(status=status, progress=100, stage=('Completed' if status == 'completed' else
                    'Completed with warnings' if status == 'completed_with_errors' else 'Finished with errors'),
                   updated_at=time.time())
    except Exception as exc:
        job.update(status='failed', error=str(exc), progress=100, stage='Failed', updated_at=time.time())
    finally:
        await asyncio.to_thread(_persist_background_job, job.copy(), 'Nmap')






# ==================================================
# MASSCAN BACKGROUND JOBS / PROGRESS
# ==================================================

MASSCAN_PATH = (
    os.getenv("MASSCAN_PATH", "")
    or shutil.which("masscan")
    or "/usr/bin/masscan"
)

MASSCAN_TIMEOUT_SECONDS = int(
    os.getenv("MASSCAN_TIMEOUT_SECONDS", "300")
)

MASSCAN_JOBS: dict[str, dict] = {}


def _new_masscan_job(target: str, user_id: int, client_id: int | None = None) -> str:
    import uuid

    job_id = str(uuid.uuid4())

    MASSCAN_JOBS[job_id] = {
        "job_id": job_id,
        "target": target,
        "user_id": user_id,
        "client_id": client_id,
        "status": "queued",
        "progress": 0,
        "stage": "Queued",
        "result": None,
        "error": None,
        "created_at": time.time(),
        "updated_at": time.time(),
    }

    _persist_background_job(MASSCAN_JOBS[job_id], "Masscan")
    return job_id


async def _execute_masscan_command(
    target: str,
    progress_callback=None,
) -> dict:
    target = str(target).strip()

    if not target:
        raise ValueError("Masscan target is required.")

    # Masscan requires an IP address or CIDR, so resolve hostnames first.
    masscan_target = target
    try:
        from ipaddress import ip_address, ip_network

        try:
            ip_address(target)
        except ValueError:
            try:
                ip_network(target, strict=False)
            except ValueError:
                masscan_target = socket.gethostbyname(target)
    except Exception as exc:
        raise ValueError(
            f"Unable to resolve Masscan target '{target}': {exc}"
        )

    if not MASSCAN_PATH or not os.path.exists(MASSCAN_PATH):
        return {
            "tool": "Masscan",
            "available": False,
            "status": "not_available",
            "target": target,
            "results": {
                "hosts": [],
                "host_count": 0,
                "open_ports": [],
            },
            "errors": ["Masscan executable was not found."],
        }

    started = time.perf_counter()

    command = [
        "sudo",
        "-n",
        MASSCAN_PATH,
        masscan_target,
        "-p80,443",
        "--rate",
        "100",
        "--wait",
        "0",
        "--output-format",
        "json",
        "--output-filename",
        "-",
    ]

    if progress_callback:
        await progress_callback(
            10,
            "Starting Masscan",
        )

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=MASSCAN_TIMEOUT_SECONDS,
        )

    except asyncio.TimeoutError:
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass

        return {
            "tool": "Masscan",
            "available": True,
            "status": "completed_with_errors",
            "target": target,
            "results": {
                "hosts": [],
                "host_count": 0,
                "open_ports": [],
            },
            "errors": [
                f"Masscan timed out after {MASSCAN_TIMEOUT_SECONDS} seconds."
            ],
            "command": command,
            "elapsed_seconds": round(
                time.perf_counter() - started,
                2,
            ),
        }

    stderr_text = stderr.decode(
        "utf-8",
        errors="replace",
    ).strip()

    stdout_text = stdout.decode(
        "utf-8",
        errors="replace",
    ).strip()

    if progress_callback:
        await progress_callback(
            80,
            "Processing Masscan results",
        )

    hosts = {}
    parse_errors = []

    if stdout_text:
        try:
            raw_items = json.loads(stdout_text)

            if isinstance(raw_items, dict):
                raw_items = [raw_items]

            for item in raw_items:
                if not isinstance(item, dict):
                    continue

                ip = item.get("ip")

                if not ip:
                    continue

                host = hosts.setdefault(
                    ip,
                    {
                        "host": ip,
                        "ports": [],
                    },
                )

                for port_data in item.get("ports", []):
                    if not isinstance(port_data, dict):
                        continue

                    port = port_data.get("port")

                    if port is None:
                        continue

                    port_entry = {
                        "port": port,
                        "protocol": port_data.get(
                            "proto",
                            "tcp",
                        ),
                        "state": port_data.get(
                            "status",
                            "open",
                        ),
                    }

                    if port_entry not in host["ports"]:
                        host["ports"].append(port_entry)

        except json.JSONDecodeError as exc:
            parse_errors.append(
                f"Unable to parse Masscan JSON output: {exc}"
            )

    result_status = (
        "completed"
        if process.returncode == 0 and not parse_errors
        else "completed_with_errors"
    )

    result = {
        "tool": "Masscan",
        "available": True,
        "status": result_status,
        "target": target,
        "results": {
            "hosts": list(hosts.values()),
            "host_count": len(hosts),
            "open_ports": [
                {
                    "host": host["host"],
                    **port,
                }
                for host in hosts.values()
                for port in host["ports"]
            ],
        },
        "errors": (
            ([stderr_text] if stderr_text else [])
            + parse_errors
        ),
        "return_code": process.returncode,
        "command": command,
        "elapsed_seconds": round(
            time.perf_counter() - started,
            2,
        ),
        "raw_output": stdout_text,
    }

    if progress_callback:
        await progress_callback(
            95,
            "Finalizing Masscan results",
        )

    return result




def persist_masscan_security_events(result: dict, user_id: int, client_id: int | None) -> int:
    """Persist real open-port discoveries from either Masscan route."""
    from scan_event_ownership import resolve_scan_event_owner

    target = str(result.get("target") or "").strip()
    open_ports = []

    structured = (
        result.get("results", {}).get("open_ports", [])
        if isinstance(result.get("results"), dict)
        else []
    )

    for item in structured:
        if not isinstance(item, dict):
            continue
        if str(item.get("state", "open")).lower() != "open":
            continue
        open_ports.append({
            "host": str(item.get("host") or ""),
            "port": item.get("port"),
            "protocol": str(item.get("protocol") or "tcp").lower(),
        })

    # Generic registry Masscan output is plain text, e.g.
    # "Discovered open port 443/tcp on 192.0.2.10"
    stdout = str(result.get("stdout") or "")
    for match in re.finditer(
        r"Discovered open port\s+(\d+)/(tcp|udp)\s+on\s+([0-9a-fA-F:.]+)",
        stdout,
        flags=re.IGNORECASE,
    ):
        open_ports.append({
            "host": match.group(3),
            "port": int(match.group(1)),
            "protocol": match.group(2).lower(),
        })

    if not open_ports:
        return 0

    db = SessionLocal()
    notifications = []
    inserted = 0

    try:
        ownership = resolve_scan_event_owner(db, user_id, client_id)
        seen = set()

        for item in open_ports:
            host = item["host"]
            port = item["port"]
            protocol = item["protocol"]

            if not host or port is None:
                continue

            identity = {
                **ownership,
                "source": "masscan",
                "target": target,
                "host": host,
                "port": port,
                "protocol": protocol,
            }
            event_id = generate_event_id(
                json.dumps(identity, sort_keys=True, default=str)
            )

            if event_id in seen:
                continue
            seen.add(event_id)

            if db.query(SecurityEvent).filter(
                SecurityEvent.event_id == event_id
            ).first():
                continue

            event = create_security_event(
                source="masscan",
                event_type="port_discovered",
                message=(
                    f"Masscan discovered open {protocol.upper()} "
                    f"port {port} on {host}"
                ),
                severity="INFO",
                target=target or host,
                raw_event={
                    "tool": "Masscan",
                    "target": target,
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "result": item,
                },
                event_id=event_id,
            )

            event.update(ownership)
            store_security_event(db, event)
            notifications.append(event)
            inserted += 1

        db.commit()

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    for event in notifications:
        try:
            notify_security_event(event)
        except Exception as exc:
            print(f"[SOC MASSCAN EVENT] Notification failed: {exc}")

    return inserted

async def _run_masscan_job(
    job_id: str,
    target: str,
):
    job = MASSCAN_JOBS.get(job_id)

    if not job:
        return

    async def update_progress(percent, stage):
        job["status"] = "running"
        job["progress"] = percent
        job["stage"] = stage
        job["updated_at"] = time.time()
        _persist_background_job(job, "Masscan")

    try:
        await update_progress(
            5,
            "Starting Masscan",
        )

        result = await _execute_masscan_command(
            target=target,
            progress_callback=update_progress,
        )

        try:
            job["security_events_persisted"] = await asyncio.to_thread(
                persist_masscan_security_events,
                result,
                job["user_id"],
                job.get("client_id"),
            )
        except Exception as event_exc:
            job["security_event_persistence_error"] = str(event_exc)
            print(f"[SOC MASSCAN EVENT] Persistence failed: {event_exc}")

        job["result"] = result

        result_status = result.get(
            "status",
            "failed",
        )

        job["status"] = result_status

        if result_status == "completed":
            job["progress"] = 100
            job["stage"] = "Completed"
        elif result_status == "completed_with_errors":
            job["progress"] = 100
            job["stage"] = "Completed with warnings"
        else:
            job["stage"] = "Finished with errors"

        job["updated_at"] = time.time()
        _persist_background_job(job, "Masscan")

    except Exception as exc:
        job["status"] = "failed"
        job["error"] = str(exc)
        job["stage"] = "Failed"
        job["updated_at"] = time.time()
        _persist_background_job(job, "Masscan")


# ==================================================
# MASSCAN API
# ==================================================

class MasscanRunRequest(BaseModel):
    target: str


@router.post("/masscan/run-async")
async def run_masscan_async(
    request: MasscanRunRequest,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    require_user_tool_permission(
        db,
        current_user,
        "Masscan",
    )

    target = str(request.target or "").strip()

    if not target:
        raise HTTPException(
            status_code=400,
            detail="A Masscan target is required.",
        )

    job_id = _new_masscan_job(
        target,
        current_user.id,
        current_user.client_id,
    )

    asyncio.create_task(
        _run_masscan_job(
            job_id,
            target,
        )
    )

    return {
        "message": "Masscan scan started",
        "tool": "Masscan",
        "username": current_user.username,
        "target": target,
        "job_id": job_id,
        "status": "queued",
        "progress": 0,
    }


@router.get("/masscan/progress/{job_id}")
async def get_masscan_progress(
    job_id: str,
    current_user: User = Depends(require_role(1)),
):
    job = MASSCAN_JOBS.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Masscan job not found or expired.",
        )

    if job.get("user_id") != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You do not have access to this Masscan job.",
        )

    return {
        "job_id": job["job_id"],
        "tool": "Masscan",
        "target": job["target"],
        "status": job["status"],
        "progress": job["progress"],
        "stage": job["stage"],
        "result": job["result"],
        "error": job["error"],
        "updated_at": job["updated_at"],
        "username": current_user.username,
    }


# ==================================================
# VAPT TOOL EXECUTION
# ==================================================

@router.get("/tools/permissions")
def get_my_tool_permissions(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return the authenticated User/Client's current tool permissions."""
    tools = (
        db.query(SecurityTool)
        .order_by(SecurityTool.category, SecurityTool.name)
        .all()
    )

    permissions = (
        db.query(UserToolPermission)
        .filter(UserToolPermission.user_id == current_user.id)
        .all()
    )

    permission_map = {p.tool_id: p.allowed for p in permissions}

    return [
        {
            "tool_id": tool.id,
            "tool_name": tool.name,
            "category": tool.category,
            "description": tool.description,
            "tool_type": tool.tool_type,
            "tool_enabled": tool.enabled,
            "allowed": bool(tool.enabled and permission_map.get(tool.id, False)),
        }
        for tool in tools
    ]


def require_nmap_access(current_user: User = Depends(get_current_user)):
    if current_user.role_id not in (1, 3):
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to access Nmap."
        )
    return current_user


@router.post("/tools/run")
async def run_vapt_tool(
    request: NmapToolRequest,
    current_user: User = Depends(require_nmap_access),
    db: Session = Depends(get_db),
):
    """Execute an approved Nmap profile synchronously."""

    require_user_tool_permission(db, current_user, "Nmap")
    target = validate_nmap_target(request.target)
    result = await _execute_nmap_command(
        target=target,
        scan_type=request.scan_type,
    )

    return {
        "message": "VAPT tool execution completed",
        "tool": "Nmap",
        "username": current_user.username,
        "target": target,
        "result": result,
    }


@router.post("/tools/run-async")
async def run_vapt_tool_async(
    request: NmapToolRequest,
    current_user: User = Depends(require_nmap_access),
    db: Session = Depends(get_db),
):
    """Start an Nmap job and return immediately so the frontend can show progress."""

    require_user_tool_permission(db, current_user, "Nmap")
    target = validate_nmap_target(request.target)

    if request.scan_type not in NMAP_PROFILES:
        raise HTTPException(status_code=400, detail="Unsupported Nmap scan request.")

    job_id = _new_nmap_job(target, request.scan_type, current_user.id, current_user.client_id)
    asyncio.create_task(_run_nmap_job(job_id, target, request.scan_type))

    return {
        "message": "Nmap scan started",
        "tool": "Nmap",
        "username": current_user.username,
        "target": target,
        "scan_type": request.scan_type,
        "job_id": job_id,
        "status": "queued",
        "progress": 0,
    }


@router.get("/tools/progress/{job_id}")
async def get_nmap_progress(
    job_id: str,
    current_user: User = Depends(require_nmap_access),
):
    """Return live status/progress/result for an Nmap background job."""

    job = NMAP_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Nmap job not found or expired.")

    if job.get("user_id") != current_user.id:
        raise HTTPException(403, "You do not have access to this Nmap job.")

    return {
        "job_id": job["job_id"],
        "tool": "Nmap",
        "target": job["target"],
        "scan_type": job["scan_type"],
        "status": job["status"],
        "progress": job["progress"],
        "stage": job["stage"],
        "result": job["result"],
        "error": job["error"],
        "asset_sync": job.get("asset_sync"),
        "asset_sync_error": job.get("asset_sync_error"),
        "updated_at": job["updated_at"],
        "username": current_user.username,
    }



# ==================================================
# NIKTO WEB SERVER SCANNER
# ==================================================

class NiktoToolRequest(BaseModel):
    target_url: HttpUrl
    scan_type: Literal["quick", "detailed"] = "quick"


def validate_nikto_target(target_url: str) -> str:
    target_url = target_url.strip()
    if not target_url or len(target_url) > 2048:
        raise HTTPException(status_code=400, detail="Invalid Nikto target URL.")
    parsed = urlparse(target_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Nikto supports only valid HTTP/HTTPS URLs.")
    if is_private_or_reserved_host(parsed.hostname):
        raise HTTPException(
            status_code=400,
            detail="Private, loopback, link-local, or reserved targets are not allowed."
        )
    return target_url


def _extract_nikto_findings(data: dict, raw_output: str) -> list[dict]:
    findings = []

    def add_item(item, metadata=None):
        if isinstance(item, str):
            if item.strip():
                findings.append({
                    "id": None,
                    "message": item.strip(),
                    "severity": "INFO",
                    "evidence": item.strip(),
                    **(metadata or {}),
                })
            return

        if not isinstance(item, dict):
            return

        vulnerabilities = item.get("vulnerabilities")

        if isinstance(vulnerabilities, list):
            item_metadata = {
                "host": item.get("host"),
                "ip": item.get("ip"),
                "port": item.get("port"),
                "server": item.get("server"),
                "banner": item.get("banner"),
                "server_banner": item.get("server_banner"),
                "ssl_info": item.get("ssl_info"),
                "start_time": item.get("start_time"),
                "end_time": item.get("end_time"),
            }

            for vulnerability in vulnerabilities:
                add_item(vulnerability, item_metadata)
            return

        message = (
            item.get("msg")
            or item.get("message")
            or item.get("description")
            or item.get("text")
            or item.get("output")
            or item.get("finding")
        )

        if not message:
            message = json.dumps(item, ensure_ascii=False)

        finding = {
            "id": item.get("id") or item.get("osvdb") or item.get("reference"),
            "message": str(message),
            "severity": str(
                item.get("severity") or item.get("risk") or "INFO"
            ).upper(),
            "method": item.get("method"),
            "url": item.get("url") or item.get("uri"),
            "evidence": item,
        }

        if metadata:
            finding.update(metadata)

        findings.append(finding)

    for key in ("vulnerabilities", "findings", "items", "results", "checks"):
        value = data.get(key)

        if isinstance(value, list):
            for item in value:
                add_item(item)

        elif isinstance(value, dict):
            for item in value.values():
                add_item(item)

    if not findings:
        for line in raw_output.splitlines():
            line = line.strip()
            if line.startswith("+ "):
                add_item(line[2:].strip())

    return findings


async def _execute_nikto_scan(target_url: str, scan_type: str = "quick", progress_callback=None) -> dict:
    target_url = validate_nikto_target(target_url)
    if not NIKTO_PATH or not os.path.exists(NIKTO_PATH):
        return {
            "tool":"Nikto","available":False,"status":"not_available",
            "target":target_url,"scan_type":scan_type,"findings":[],
            "errors":["Nikto executable was not found."]
        }

    maxtime = NIKTO_MAXTIME_DETAILED if scan_type == "detailed" else NIKTO_MAXTIME_QUICK
    started=time.perf_counter()
    temp_json=None

    if progress_callback:
        await progress_callback(5, "Starting Nikto")

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", prefix="soc_nikto_", delete=False) as f:
            temp_json=f.name

        command=[
            NIKTO_PATH, "-h", target_url, "-nointeractive",
            "-maxtime", maxtime, "-Format", "json", "-output", temp_json
        ]

        if progress_callback:
            await progress_callback(10, "Nikto web server checks running")

        process=await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout,stderr=await asyncio.wait_for(
                process.communicate(), timeout=NIKTO_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            try: process.kill()
            except ProcessLookupError: pass
            stdout,stderr=await process.communicate()
            return {
                "tool":"Nikto","available":True,"status":"completed_with_errors",
                "target":target_url,"scan_type":scan_type,"return_code":None,
                "elapsed_seconds":round(time.perf_counter()-started,2),
                "findings":[],"raw_output":stdout.decode("utf-8","replace"),
                "errors":["Nikto execution exceeded the platform timeout."]
            }

        raw_output=stdout.decode("utf-8","replace")
        raw_stderr=stderr.decode("utf-8","replace")
        structured={}
        try:
            json_text=Path(temp_json).read_text(encoding="utf-8",errors="replace")
            if json_text.strip():
                parsed=json.loads(json_text)
                structured=parsed if isinstance(parsed,dict) else {"items":parsed}
        except (OSError,json.JSONDecodeError):
            pass

        findings=_extract_nikto_findings(structured, raw_output)
        errors=[x.strip() for x in raw_stderr.splitlines() if x.strip()][-40:]

        if progress_callback:
            await progress_callback(90, "Parsing Nikto findings")

        result={
            "tool":"Nikto","available":True,
            "status":"completed" if process.returncode == 0 else "completed_with_errors",
            "target":target_url,"scan_type":scan_type,
            "command_profile": "Nikto standard web server assessment" if scan_type=="quick"
                               else "Nikto extended web server assessment",
            "return_code":process.returncode,
            "elapsed_seconds":round(time.perf_counter()-started,2),
            "findings_count":len(findings),"findings":findings,
            "results":structured,"raw_output":raw_output,"errors":errors,
            "workflow":{"scanner":"Nikto","max_time":maxtime,"target_validated":True}
        }
        if progress_callback:
            await progress_callback(100, "Nikto scan completed")
        return result
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return {
            "tool":"Nikto","available":True,"status":"failed",
            "target":target_url,"scan_type":scan_type,"findings":[],
            "errors":[str(exc)]
        }
    finally:
        if temp_json:
            try: os.unlink(temp_json)
            except (FileNotFoundError,OSError): pass


def _new_nikto_job(target_url: str, scan_type: str, user_id: int, client_id: int | None = None) -> str:
    import uuid
    job_id=str(uuid.uuid4())
    NIKTO_JOBS[job_id]={
        "job_id":job_id,"target":target_url,"scan_type":scan_type,
        "user_id":user_id,"client_id":client_id,"status":"queued","progress":0,"stage":"Queued",
        "result":None,"error":None,"created_at":time.time(),"updated_at":time.time()
    }
    _persist_background_job(NIKTO_JOBS[job_id], "Nikto")
    return job_id


async def _run_nikto_job(job_id: str, target_url: str, scan_type: str):
    job = NIKTO_JOBS.get(job_id)
    if not job:
        return

    async def update_progress(percent, stage):
        job.update(
            status="running",
            progress=percent,
            stage=stage,
            updated_at=time.time(),
        )
        _persist_background_job(job, "Nikto")

    try:
        job.update(
            status="running",
            progress=3,
            stage="Starting Nikto",
            updated_at=time.time(),
        )

        result = await _execute_nikto_scan(
            target_url,
            scan_type,
            update_progress,
        )

        # Publish the real Nikto scanner result immediately.
        # SecurityEvent persistence must never delay terminal state.
        job["result"] = result

        terminal_status = result.get("status", "failed")

        job.update(
            status=terminal_status,
            progress=100,
            stage=(
                "Completed"
                if terminal_status == "completed"
                else (
                    "Completed with warnings"
                    if terminal_status == "completed_with_errors"
                    else "Finished with errors"
                )
            ),
            updated_at=time.time(),
        )
        _persist_background_job(job, "Nikto")

        # Persist SecurityEvent independently so a slow/locked database
        # cannot keep the real Nikto job stuck in running state.
        if terminal_status in {
            "completed",
            "completed_with_errors",
        }:

            def persist_security_event():
                security_event = SecurityEvent(
                    event_id=generate_event_id(
                        json.dumps(
                            result,
                            sort_keys=True,
                            default=str,
                        )
                    ),
                    timestamp=__import__("datetime").datetime.utcnow(),
                    source="nikto",
                    event_type="vapt_scan",
                    severity=(
                        "INFO"
                        if terminal_status == "completed"
                        else "ERROR"
                    ),
                    message=(
                        f"Nikto {scan_type} scan completed "
                        f"for {target_url}"
                    ),
                    target=target_url,
                    owner_user_id=job.get("user_id"),
                    client_id=job.get("client_id"),
                    raw_event=json.dumps(
                        result,
                        default=str,
                    ),
                    mitre_technique_id="T1595.002",
                    mitre_technique_name="Vulnerability Scanning",
                    mitre_tactic="reconnaissance",
                    mitre_mapping_source="security_tool_context",
                    mitre_confidence="low",
                    mitre_evidence=(
                        "Nikto vulnerability scanning was performed "
                        "against the authorized assessment target."
                    ),
                )

                db = SessionLocal()
                try:
                    db.add(security_event)
                    db.commit()

                    notify_security_event({
                        "event_id": security_event.event_id,
                        "timestamp": security_event.timestamp.isoformat(),
                        "source": security_event.source,
                        "event_type": security_event.event_type,
                        "severity": security_event.severity,
                        "message": security_event.message,
                        "target": security_event.target,
                        "assessment_id": security_event.assessment_id,
                    })
                    return True, None
                except Exception as db_exc:
                    db.rollback()
                    return False, str(db_exc)
                finally:
                    db.close()

            try:
                persisted, db_error = await asyncio.wait_for(
                    asyncio.to_thread(persist_security_event),
                    timeout=5,
                )

                result["security_event_persisted"] = persisted

                if db_error:
                    result["security_event_error"] = db_error

            except asyncio.TimeoutError:
                result["security_event_persisted"] = False
                result["security_event_error"] = (
                    "SecurityEvent persistence exceeded 5 seconds."
                )

            except Exception as db_exc:
                result["security_event_persisted"] = False
                result["security_event_error"] = str(db_exc)

            job["result"] = result
            job["updated_at"] = time.time()

    except asyncio.CancelledError:
        raise

    except Exception as exc:
        job.update(
            status="failed",
            progress=100,
            stage="Failed",
            error=str(exc),
            updated_at=time.time(),
        )
        _persist_background_job(job, "Nikto")


# ==================================================
# NIKTO VAPT ENDPOINTS
# ==================================================

@router.post("/nikto/run")
async def run_nikto_tool(
    request: NiktoToolRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    require_user_tool_permission(db, current_user, "Nikto")
    target_url=validate_nikto_target(str(request.target_url))
    result=await _execute_nikto_scan(target_url,request.scan_type)
    return {
        "message":"Nikto scan completed","tool":"Nikto",
        "username":current_user.username,"target":target_url,"result":result
    }


@router.post("/nikto/run-async")
async def run_nikto_tool_async(
    request: NiktoToolRequest,
    current_user: User = Depends(require_nmap_access),
    db: Session = Depends(get_db),
):
    require_user_tool_permission(db,current_user,"Nikto")
    target_url=validate_nikto_target(str(request.target_url))
    job_id=_new_nikto_job(target_url,request.scan_type,current_user.id,current_user.client_id)
    asyncio.create_task(_run_nikto_job(job_id,target_url,request.scan_type))
    return {
        "message":"Nikto scan started","tool":"Nikto","username":current_user.username,
        "target":target_url,"scan_type":request.scan_type,"job_id":job_id,
        "status":"queued","progress":0
    }


@router.get("/nikto/progress/{job_id}")
async def get_nikto_progress(
    job_id: str,
    current_user: User = Depends(require_nmap_access),
):
    job=NIKTO_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404,detail="Nikto job not found or expired.")
    if job.get("user_id") != current_user.id:
        raise HTTPException(status_code=403,detail="You do not have access to this Nikto job.")
    return {
        "job_id":job["job_id"],"tool":"Nikto","target":job["target"],
        "scan_type":job["scan_type"],"status":job["status"],
        "progress":job["progress"],"stage":job["stage"],
        "result":job["result"],"error":job["error"],
        "updated_at":job["updated_at"],"username":current_user.username
    }

# ==================================================
# VAPT SCAN
# ==================================================

@router.post("/scan")
async def scan_url(
    scan_request: VAPTScanRequest,
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    """
    Safe first-stage VAPT web assessment.

    Role 1 is the User/Client.

    A successful scan automatically creates or updates
    the User's Assessment record and synchronizes the
    detected safe-stage findings into SecurityFinding.
    """

    target_url = str(
        scan_request.target_url
    )

    parsed = urlparse(
        target_url
    )

    # --------------------------------------------------
    # URL VALIDATION
    # --------------------------------------------------

    if parsed.scheme not in {
        "http",
        "https",
    }:

        raise HTTPException(
            status_code=400,
            detail=(
                "Only HTTP and HTTPS URLs "
                "are supported."
            ),
        )

    hostname = parsed.hostname

    if not hostname:

        raise HTTPException(
            status_code=400,
            detail="Invalid target URL.",
        )

    # --------------------------------------------------
    # TARGET SAFETY CHECK
    # --------------------------------------------------

    if is_private_or_reserved_host(
        hostname
    ):

        if (
            is_local_host(hostname)
            and not ALLOW_LOCAL_TARGETS
        ):

            raise HTTPException(
                status_code=400,
                detail=(
                    "Localhost/loopback targets "
                    "are disabled. Set "
                    "ALLOW_LOCAL_TARGETS=true "
                    "only for development testing."
                ),
            )

        raise HTTPException(
            status_code=400,
            detail=(
                "Private, loopback, link-local, "
                "or reserved targets are not allowed."
            ),
        )

    # --------------------------------------------------
    # HTTP REQUEST
    # --------------------------------------------------

    start_time = time.perf_counter()

    try:

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=15.0,
            headers={
                "User-Agent":
                    "SOC-Platform-VAPT/1.0"
            },
        ) as client:

            response = await client.get(
                target_url
            )

    except httpx.TimeoutException:

        raise HTTPException(
            status_code=408,
            detail=(
                "The target did not respond "
                "within the timeout period."
            ),
        )

    except httpx.RequestError as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to reach target: "
                f"{str(exc)}"
            ),
        )

    duration = (
        time.perf_counter()
        - start_time
    )

    response_time_ms = round(
        duration * 1000,
        2,
    )

    # ==================================================
    # SECURITY HEADERS
    # ==================================================

    headers = {
        key.lower(): value
        for key, value
        in response.headers.items()
    }

    security_headers = {

        "content-security-policy":
            headers.get(
                "content-security-policy"
            ),

        "strict-transport-security":
            headers.get(
                "strict-transport-security"
            ),

        "x-frame-options":
            headers.get(
                "x-frame-options"
            ),

        "x-content-type-options":
            headers.get(
                "x-content-type-options"
            ),

        "referrer-policy":
            headers.get(
                "referrer-policy"
            ),

        "permissions-policy":
            headers.get(
                "permissions-policy"
            ),
    }

    header_results = []

    for header_name, value in (
        security_headers.items()
    ):

        header_results.append({
            "header": header_name,
            "present": value is not None,
            "value": value,
        })

    missing_headers = [
        item["header"]
        for item in header_results
        if not item["present"]
    ]

    # ==================================================
    # FINDINGS
    # ==================================================

    findings = []

    for header in missing_headers:

        findings.append({

            "severity": "MEDIUM",

            "title":
                f"Missing security header: {header}",

            "category":
                "Security Headers",

            "status":
                "Open",

            "description":
                (
                    "The target response does not "
                    f"include the recommended {header} "
                    "security header."
                ),
        })

    # ==================================================
    # CREATE / UPDATE ASSESSMENT
    # ==================================================

    assessment = create_or_update_assessment(
        db=db,
        current_user=current_user,
        target=target_url,
        findings_count=len(findings),
    )

    # ==================================================
    # SYNC SECURITY FINDINGS
    # ==================================================

    sync_vapt_security_findings(
        db=db,
        current_user=current_user,
        assessment=assessment,
        missing_headers=missing_headers,
    )

    # --------------------------------------------------
    # Recalculate the assessment finding count from
    # persisted SecurityFinding records.
    # --------------------------------------------------

    persisted_count = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.assessment_id
            == assessment.id
        )
        .count()
    )

    assessment.vapt_findings_count = (
        persisted_count
    )

    db.commit()
    db.refresh(assessment)

    # ==================================================
    # RESPONSE
    # ==================================================

    return {

        "message":
            "VAPT assessment completed",

        "target":
            target_url,

        "scan_type":
            scan_request.scan_type,

        "username":
            current_user.username,

        "assessment": {

            "id":
                assessment.id,

            "status":
                assessment.overall_status,

            "vapt_status":
                assessment.vapt_status,

            "findings_count":
                assessment.vapt_findings_count,
        },

        "scan": {

            "status":
                "completed",

            "http_status":
                response.status_code,

            "final_url":
                str(response.url),

            "response_time_ms":
                response_time_ms,

            "https_enabled":
                parsed.scheme == "https",

            "local_target":
                is_local_host(
                    hostname
                ),
        },

        "security_headers":
            header_results,

        "summary": {

            "total_findings":
                len(findings),

            "missing_security_headers":
                len(missing_headers),

        },

        "findings":
            findings,

        "security_findings":
            {
                "synced": True,
                "source": "SOC Platform Safe VAPT",
                "cve_enrichment": "Not performed by the Nmap workflow.",
            },

        "security_scanners": {
            "scan_type": scan_request.scan_type,
            "executed_tools": ["SOC Platform HTTP Checks"],
            "skipped_tools": [],
            "not_yet_integrated": [
                "Nmap is available through the dedicated /vapt/tools/run and /vapt/tools/run-async endpoints.",
            ],
        },
    }