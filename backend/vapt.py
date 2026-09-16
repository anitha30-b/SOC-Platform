import asyncio
import json
import os
import shutil
import socket
import time
from ipaddress import ip_address
from urllib.parse import urlparse
from typing import Literal, Optional

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from database import get_db
from cve import fetch_cve_information
from models import (
    Assessment,
    SecurityFinding,
    SecurityTool,
    User,
)
from rbac import require_role


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

NUCLEI_PATH = os.getenv("NUCLEI_PATH", "") or shutil.which("nuclei") or "/usr/bin/nuclei"

NUCLEI_TIMEOUT_SECONDS = int(
    os.getenv("NUCLEI_TIMEOUT_SECONDS", "120")
)

NUCLEI_RATE_LIMIT = os.getenv("NUCLEI_RATE_LIMIT", "50")


# ==================================================
# ROUTER
# ==================================================

router = APIRouter(
    prefix="/vapt",
    tags=["VAPT Testing"],
)


# ==================================================
# REQUEST SCHEMA
# ==================================================

class VAPTScanRequest(BaseModel):
    target_url: HttpUrl
    scan_type: Literal["quick", "detailed"] = "quick"


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
    Nmap, Nuclei, ZAP, Nessus or Trivy.

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
# NUCLEI SCAN
# ==================================================

async def run_all_security_scanners(target_url: str, scan_type: str = "quick") -> dict:
    """Run the integrated scanners according to the selected scan mode.

    Quick mode intentionally skips Nuclei so the user gets a lightweight
    assessment based on the native HTTP/security-header checks. Detailed mode
    runs Nuclei for deeper CVE/misconfiguration coverage.
    """
    if scan_type == "quick":
        return {
            "scan_type": "quick",
            "scanners": {
                "nuclei": {
                    "available": bool(NUCLEI_PATH and os.path.exists(NUCLEI_PATH)),
                    "status": "skipped",
                    "message": "Nuclei is skipped in Quick Scan for faster results.",
                    "results": [],
                    "errors": [],
                    "scan_type": "quick",
                },
            },
            "executed_tools": ["SOC Platform HTTP Checks"],
            "skipped_tools": ["Nuclei"],
            "not_yet_integrated": [
                "Security tools in the catalog without an executable backend integration"
            ],
        }

    nuclei_result = await run_nuclei_scan(
        target_url=target_url,
        scan_type="detailed",
    )

    return {
        "scan_type": "detailed",
        "scanners": {
            "nuclei": nuclei_result,
        },
        "executed_tools": ["SOC Platform HTTP Checks", "Nuclei"],
        "skipped_tools": [],
        "not_yet_integrated": [
            "Security tools in the catalog without an executable backend integration"
        ],
    }


async def run_nuclei_scan(target_url: str, scan_type: str = "quick") -> dict:
    """Run Nuclei in quick or detailed mode against an authorized target."""

    if not NUCLEI_PATH or not os.path.exists(NUCLEI_PATH):
        return {
            "available": False,
            "status": "not_available",
            "message": "Nuclei executable was not found.",
            "results": [],
            "errors": [],
            "scan_type": scan_type,
        }

    if scan_type == "detailed":
        command = [
            NUCLEI_PATH,
            "-u", target_url,
            "-jsonl",
            "-silent",
            "-tags", "cve,misconfig,exposure",
            "-severity", "low,medium,high,critical",
            "-rl", NUCLEI_RATE_LIMIT,
            "-timeout", "10",
            "-retries", "1",
        ]
        timeout_seconds = max(NUCLEI_TIMEOUT_SECONDS, 180)
    else:
        command = [
            NUCLEI_PATH,
            "-u", target_url,
            "-jsonl",
            "-silent",
            "-tags", "cve,misconfig",
            "-severity", "medium,high,critical",
            "-rl", "100",
            "-timeout", "5",
            "-retries", "0",
        ]
        timeout_seconds = min(60, max(30, NUCLEI_TIMEOUT_SECONDS))

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            return {
                "available": True,
                "status": "timeout",
                "message": f"Nuclei {scan_type} scan timed out after {timeout_seconds} seconds.",
                "results": [],
                "errors": ["timeout"],
                "scan_type": scan_type,
            }

        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")

        results = []
        parse_errors = []
        for line in stdout_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    results.append(item)
            except json.JSONDecodeError:
                parse_errors.append(line[:500])

        errors = parse_errors
        if stderr_text.strip():
            errors.extend([
                line.strip()[:500]
                for line in stderr_text.splitlines()
                if line.strip()
            ][:25])

        return {
            "available": True,
            "status": (
                "completed" if process.returncode == 0
                else "completed_with_errors"
            ),
            "return_code": process.returncode,
            "results": results,
            "errors": errors,
            "scan_type": scan_type,
            "command_profile": (
                "extended_cve_misconfig_exposure"
                if scan_type == "detailed"
                else "fast_cve_misconfig"
            ),
        }

    except Exception as exc:
        return {
            "available": True,
            "status": "failed",
            "message": str(exc),
            "results": [],
            "errors": [str(exc)],
            "scan_type": scan_type,
        }


def first_value(value):
    """Return a useful first value from a string/list-like field."""

    if isinstance(value, list):
        return value[0] if value else None

    if isinstance(value, str):
        return value.strip() or None

    return value


def extract_nuclei_cve(item: dict) -> Optional[str]:
    """Extract the first CVE identifier from a Nuclei result."""

    classification = (
        item.get("info", {}).get("classification", {})
    )

    cve_value = classification.get("cve-id")

    if isinstance(cve_value, list):
        for value in cve_value:
            if value:
                return str(value).upper()

    if cve_value:
        return str(cve_value).upper()

    return None


def extract_nuclei_cwe(item: dict) -> Optional[str]:
    """Extract CWE identifiers from a Nuclei result."""

    classification = (
        item.get("info", {}).get("classification", {})
    )

    cwe_value = classification.get("cwe-id")

    if isinstance(cwe_value, list):
        values = [
            str(value).upper()
            for value in cwe_value
            if value
        ]
        return ", ".join(dict.fromkeys(values)) or None

    if cwe_value:
        return str(cwe_value).upper()

    return None


def extract_nuclei_cvss(item: dict) -> Optional[float]:
    """Extract a CVSS score when the Nuclei template provides one."""

    info = item.get("info", {})
    metadata = info.get("metadata", {}) or {}

    candidates = [
        metadata.get("cvss-score"),
        metadata.get("cvss_score"),
        metadata.get("cvss"),
        info.get("cvss-score"),
    ]

    for candidate in candidates:
        if candidate is None:
            continue

        try:
            score = float(candidate)

            if 0.0 <= score <= 10.0:
                return score

        except (TypeError, ValueError):
            continue

    return None


def extract_nuclei_references(item: dict) -> Optional[str]:
    """Extract references from the Nuclei template metadata."""

    info = item.get("info", {})
    references = info.get("reference")

    if isinstance(references, list):
        values = [str(value) for value in references if value]
        return "\n".join(dict.fromkeys(values)) or None

    if isinstance(references, str) and references.strip():
        return references.strip()

    return None


async def sync_nuclei_security_findings(
    db: Session,
    current_user: User,
    assessment: Assessment,
    nuclei_results: list[dict],
) -> list[dict]:
    """
    Convert meaningful Nuclei JSONL results into SecurityFinding rows.

    Informational technology-discovery results and the Nuclei
    security-header template are skipped here because the platform
    already handles the built-in security-header assessment and
    technology inventory is not itself a vulnerability.
    """

    # Make sure the Nuclei tool exists in the local catalog.
    tool = (
        db.query(SecurityTool)
        .filter(
            func.lower(SecurityTool.name) == "nuclei"
        )
        .first()
    )

    if tool is None:
        tool = SecurityTool(
            name="Nuclei",
            category="Web Application Security",
            description=(
                "Template-based vulnerability and exposure scanner."
            ),
            tool_type="scanner",
            enabled=True,
        )
        db.add(tool)
        db.commit()
        db.refresh(tool)

    imported = []

    for item in nuclei_results:
        info = item.get("info", {}) or {}
        template_id = item.get("template-id") or "unknown-template"
        matcher_name = item.get("matcher-name")
        template_name = (
            info.get("name")
            or template_id
        )
        nuclei_severity = str(
            info.get("severity") or "info"
        ).upper()

        # Skip the exact header template because the SOC Platform
        # already performs and persists its own header checks.
        if template_id == "http-missing-security-headers":
            continue

        # Skip technology-discovery results, but keep useful INFO-level
        # security/misconfiguration findings.
        nuclei_tags = info.get("tags") or []

        if isinstance(nuclei_tags, str):
            nuclei_tags = [
                tag.strip().lower()
                for tag in nuclei_tags.split(",")
                if tag.strip()
            ]

        is_technology_result = (
            template_id.startswith("tech-detect")
            or "tech" in nuclei_tags
            or "technology" in nuclei_tags
        )

        if is_technology_result:
            continue

        cve_id = extract_nuclei_cve(item)
        cwe_id = extract_nuclei_cwe(item)
        cvss_score = extract_nuclei_cvss(item)
        description = info.get("description")
        references = extract_nuclei_references(item)

        # If a CVE exists, enrich from NVD. Failure to enrich must
        # never prevent saving the scanner finding.
        if cve_id:
            try:
                nvd = await asyncio.to_thread(
                    fetch_cve_information,
                    cve_id,
                )

                if not cwe_id:
                    nvd_cwe = nvd.get("cwe", [])
                    if nvd_cwe:
                        cwe_id = ", ".join(nvd_cwe)

                if not description:
                    description = nvd.get("description")

                if cvss_score is None:
                    nvd_cvss = nvd.get("cvss", {}) or {}
                    cvss_score = nvd_cvss.get("score")

                nvd_references = nvd.get("references", []) or []
                if nvd_references:
                    nvd_reference_text = "\n".join(nvd_references)
                    references = (
                        f"{references}\n{nvd_reference_text}"
                        if references
                        else nvd_reference_text
                    )

            except Exception as exc:
                print(
                    "NVD enrichment failed for",
                    cve_id,
                    ":",
                    str(exc),
                )

        # Map Nuclei severity when a CVSS score is unavailable.
        if cvss_score is not None:
            severity = calculate_severity(
                float(cvss_score)
            )
        else:
            severity = (
                nuclei_severity
                if nuclei_severity
                in {
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                }
                else "LOW"
            )

        risk_level = calculate_risk_level(
            severity
        )

        matched_url = item.get("matched-at") or item.get("url")
        parsed_matched = urlparse(
            str(matched_url)
        ) if matched_url else None

        title_parts = [template_name]

        if matcher_name:
            title_parts.append(
                f"({matcher_name})"
            )

        if cve_id:
            title_parts.append(
                f"[{cve_id}]"
            )

        title = " ".join(title_parts)

        # Avoid creating duplicate findings on repeated VAPT scans.
        existing = (
            db.query(SecurityFinding)
            .filter(
                SecurityFinding.user_id
                == current_user.id,
                SecurityFinding.assessment_id
                == assessment.id,
                SecurityFinding.tool_name
                == "Nuclei",
                SecurityFinding.title
                == title,
                SecurityFinding.affected_url
                == matched_url,
            )
            .first()
        )

        evidence_parts = [
            f"Template: {template_id}",
        ]

        if matcher_name:
            evidence_parts.append(
                f"Matcher: {matcher_name}"
            )

        if item.get("ip"):
            evidence_parts.append(
                f"IP: {item.get('ip')}"
            )

        finding_values = {
            "tool_name": "Nuclei",
            "tool_category": tool.category,
            "title": title,
            "vulnerability": template_name,
            "description": description,
            "owasp_category": None,
            "owasp_api_category": None,
            "cve_id": cve_id,
            "cwe_id": cwe_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "risk_level": risk_level,
            "affected_asset": item.get("host") or item.get("ip"),
            "affected_url": matched_url,
            "endpoint": (
                parsed_matched.path
                if parsed_matched
                else item.get("path")
            ),
            "parameter": None,
            "evidence": "\n".join(evidence_parts),
            "request_data": item.get("request"),
            "response_data": item.get("response"),
            "impact": (
                "Nuclei identified a security finding matching the "
                f"{template_id} template."
            ),
            "remediation": info.get("remediation"),
            "references": references,
            "status": "OPEN",
            "updated_at": datetime.utcnow(),
        }

        if existing:
            for key, value in finding_values.items():
                setattr(existing, key, value)

            finding = existing

        else:
            finding = SecurityFinding(
                finding_id=generate_finding_id(db),
                user_id=current_user.id,
                assessment_id=assessment.id,
                created_at=datetime.utcnow(),
                detected_at=datetime.utcnow(),
                **finding_values,
            )

            db.add(finding)
            db.flush()

        imported.append({
            "finding_id": (
                finding.finding_id
                if finding.finding_id
                else None
            ),
            "template_id": template_id,
            "title": title,
            "cve_id": cve_id,
            "cwe_id": cwe_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "risk_level": risk_level,
        })

    db.commit()

    return imported


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

    # ==================================================
    # ALL INTEGRATED SECURITY SCANNERS
    # ==================================================
    # The orchestrator runs every scanner that is actually integrated
    # with this backend. Scanner results are consolidated into the same
    # SecurityFinding workflow.

    scanner_execution = await run_all_security_scanners(
        target_url=target_url,
        scan_type=scan_request.scan_type,
    )

    nuclei_result = scanner_execution["scanners"]["nuclei"]
    nuclei_imported = []

    if (
        scan_request.scan_type == "detailed"
        and nuclei_result.get("results")
    ):
        nuclei_imported = await sync_nuclei_security_findings(
            db=db,
            current_user=current_user,
            assessment=assessment,
            nuclei_results=nuclei_result["results"],
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
                "source": "SOC Platform Safe VAPT + Nuclei",
                "cve_enrichment": (
                    "Applied automatically for Nuclei results "
                    "that contain a CVE."
                ),
                "nuclei_imported_count": len(
                    nuclei_imported
                ),
            },

        "security_scanners": {
            "scan_type": scanner_execution.get("scan_type", scan_request.scan_type),
            "executed_tools": scanner_execution.get("executed_tools", []),
            "skipped_tools": scanner_execution.get("skipped_tools", []),
            "not_yet_integrated": scanner_execution.get("not_yet_integrated", []),
        },
        "nuclei_scan": {
            "scan_type": nuclei_result.get("scan_type", scan_request.scan_type),
            "status": nuclei_result.get("status"),
            "available": nuclei_result.get("available", False),
            "matched_results": len(
                nuclei_result.get("results", [])
            ),
            "imported_findings": nuclei_imported,
            "errors": nuclei_result.get("errors", []),
        },
    }