from sqlalchemy.exc import IntegrityError
import asyncio
import uuid
import json
from urllib.parse import urlparse
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import SessionLocal, get_db
from models import AssetDiscoveryRun, Assessment, Client, DatabaseAsset, EndpointAsset, EndpointProcess, EndpointService, EndpointFirewallRule, EndpointSystemHardening, EndpointServerConfiguration, ExternalAttackSurfaceRun, DomainDiscoveryRun, SubdomainDiscoveryRun, InternalAttackSurfaceRun, NetworkDeviceAsset, Report, SecurityFinding, SecurityEvent, ServerAsset, TelemetrySource, User, DNSSecurityRun, SSLTLSRun, SecurityHeadersRun, ReportIssue
from rbac import require_role
from telemetry_router import _hash_token
from vapt import _execute_masscan_command, _execute_nmap_command, validate_nmap_target
from vapt_tools.generic_runner import run_generic_tool
from dns_security import scan_dns_security
from ssl_tls import inspect_tls
from security_headers import inspect_security_headers
from security_findings import calculate_risk_level, calculate_severity


router = APIRouter(
    prefix="/client",
    tags=["Client Portal"],
)


class ClientDNSSecurityRequest(BaseModel):
    assessment_id: int = Field(gt=0)


class ClientSSLTLSRequest(BaseModel):
    assessment_id: int = Field(gt=0)


class ClientSecurityHeadersRequest(BaseModel):
    assessment_id: int = Field(gt=0)


async def _run_client_dns_security(run_id: int, target_domain: str):
    db = SessionLocal()
    try:
        run = db.query(DNSSecurityRun).filter(DNSSecurityRun.id == run_id).first()
        if not run:
            return

        run.status = "RUNNING"
        run.started_at = datetime.utcnow()
        db.commit()

        result = await asyncio.to_thread(scan_dns_security, target_domain)

        # Persist each DNS Security finding into the shared SecurityFinding table.
        for item in result.get("findings", []):
            title = str(item.get("title") or "DNS Security Finding").strip()
            severity = str(item.get("severity") or "NONE").upper()
            risk_level = str(
                item.get("risk_level")
                or calculate_risk_level(severity)
            )
            cvss_score = item.get("cvss_score")

            existing = (
                db.query(SecurityFinding)
                .filter(
                    SecurityFinding.user_id == run.user_id,
                    SecurityFinding.assessment_id == run.assessment_id,
                    SecurityFinding.tool_name == "DNS Security",
                    SecurityFinding.affected_asset == target_domain,
                    SecurityFinding.endpoint.is_(None),
                    SecurityFinding.title == title,
                )
                .first()
            )

            now = datetime.utcnow()
            evidence = item.get("evidence")
            if isinstance(evidence, (dict, list)):
                evidence = json.dumps(
                    evidence,
                    ensure_ascii=False,
                )
            elif evidence is not None:
                evidence = str(evidence)

            references = item.get("references")
            if isinstance(references, (dict, list)):
                references = json.dumps(
                    references,
                    ensure_ascii=False,
                )
            elif references is not None:
                references = str(references)

            if existing:
                existing.vulnerability = item.get("vulnerability")
                existing.description = item.get("description")
                existing.severity = severity
                existing.risk_level = risk_level
                existing.cvss_score = cvss_score
                existing.evidence = evidence
                existing.impact = item.get("impact")
                existing.remediation = item.get("remediation")
                existing.references = references
                existing.status = item.get("status") or "OPEN"
                existing.updated_at = now
            else:
                finding = SecurityFinding(
                    finding_id=f"FIND-PENDING-{uuid.uuid4().hex}",
                    user_id=run.user_id,
                    assessment_id=run.assessment_id,
                    tool_name="DNS Security",
                    tool_category="DNS Security",
                    title=title[:500],
                    vulnerability=str(item.get("vulnerability") or "")[:500],
                    description=item.get("description"),
                    owasp_category=None,
                    cve_id=None,
                    cwe_id=None,
                    cvss_score=cvss_score,
                    severity=severity,
                    risk_level=risk_level,
                    affected_asset=target_domain,
                    affected_url=f"https://{target_domain}",
                    endpoint=None,
                    parameter=None,
                    evidence=evidence,
                    request_data=None,
                    response_data=None,
                    impact=item.get("impact"),
                    remediation=item.get("remediation"),
                    references=references,
                    status=item.get("status") or "OPEN",
                    detected_at=now,
                    created_at=now,
                    updated_at=now,
                )
                db.add(finding)
                db.flush()
                finding.finding_id = f"FIND-{finding.id:06d}"

        run.status = result.get("status", "FAILED")
        run.security_score = result.get("security_score")
        run.finding_count = result.get("finding_count", 0)
        run.critical_count = result.get("critical_count", 0)
        run.high_count = result.get("high_count", 0)
        run.medium_count = result.get("medium_count", 0)
        run.low_count = result.get("low_count", 0)
        run.info_count = result.get("info_count", 0)
        run.result_data = json.dumps(result, default=str)
        run.completed_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        db.commit()

    except Exception as exc:
        db.rollback()

        run = db.query(DNSSecurityRun).filter(DNSSecurityRun.id == run_id).first()
        if run:
            run.status = "FAILED"
            run.result_data = json.dumps({"error": str(exc)})
            run.completed_at = datetime.utcnow()
            run.updated_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


async def _run_client_security_headers(run_id: int, target_url: str):
    db = SessionLocal()
    try:
        run = (
            db.query(SecurityHeadersRun)
            .filter(SecurityHeadersRun.id == run_id)
            .first()
        )
        if not run:
            return

        run.status = "RUNNING"
        run.started_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        db.commit()

        result = await inspect_security_headers(target_url)

        header_results = result.get("headers") or []
        for item in header_results:
            if item.get("present"):
                continue

            header_name = str(item.get("header") or "").strip().lower()
            if not header_name:
                continue

            title = f"Missing security header: {header_name}"
            severity = "MEDIUM"
            risk_level = calculate_risk_level(severity)
            now = datetime.utcnow()

            evidence = json.dumps(
                {
                    "header": header_name,
                    "present": False,
                    "http_status": result.get("http_status"),
                    "final_url": result.get("final_url"),
                },
                ensure_ascii=False,
            )

            remediation = (
                f"Configure the {header_name} HTTP response header "
                "with a policy appropriate for the application."
            )

            existing = (
                db.query(SecurityFinding)
                .filter(
                    SecurityFinding.user_id == run.user_id,
                    SecurityFinding.assessment_id == run.assessment_id,
                    SecurityFinding.tool_name == "Security Headers",
                    SecurityFinding.affected_asset == target_url,
                    SecurityFinding.endpoint.is_(None),
                    SecurityFinding.title == title,
                )
                .first()
            )

            if existing:
                existing.vulnerability = header_name[:500]
                existing.description = (
                    f"The target response does not include the recommended "
                    f"{header_name} security header."
                )
                existing.severity = severity
                existing.risk_level = risk_level
                existing.evidence = evidence
                existing.impact = (
                    "The absence of this security header may reduce the "
                    "application's protection against relevant web-based attacks."
                )
                existing.remediation = remediation
                existing.status = "OPEN"
                existing.updated_at = now
            else:
                finding = SecurityFinding(
                    finding_id=f"FIND-PENDING-{uuid.uuid4().hex}",
                    user_id=run.user_id,
                    assessment_id=run.assessment_id,
                    tool_name="Security Headers",
                    tool_category="Security Headers",
                    title=title[:500],
                    vulnerability=header_name[:500],
                    description=(
                        f"The target response does not include the recommended "
                        f"{header_name} security header."
                    ),
                    owasp_category=None,
                    cve_id=None,
                    cwe_id=None,
                    cvss_score=None,
                    severity=severity,
                    risk_level=risk_level,
                    affected_asset=target_url,
                    affected_url=result.get("final_url") or target_url,
                    endpoint=None,
                    parameter=None,
                    evidence=evidence,
                    request_data=None,
                    response_data=None,
                    impact=(
                        "The absence of this security header may reduce the "
                        "application's protection against relevant web-based attacks."
                    ),
                    remediation=remediation,
                    references=None,
                    status="OPEN",
                    detected_at=now,
                    created_at=now,
                    updated_at=now,
                )
                db.add(finding)
                db.flush()
                finding.finding_id = f"FIND-{finding.id:06d}"

        run.target_url = result.get("target_url") or target_url
        run.final_url = result.get("final_url")
        run.http_status = result.get("http_status")
        run.header_count = int(result.get("header_count") or 0)
        run.present_header_count = int(result.get("present_header_count") or 0)
        run.missing_header_count = int(result.get("missing_header_count") or 0)
        run.security_score = result.get("security_score")
        run.status = str(result.get("status") or "FAILED").upper()
        run.result_data = json.dumps(result, default=str)
        run.completed_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        db.commit()

    except Exception as exc:
        db.rollback()

        run = (
            db.query(SecurityHeadersRun)
            .filter(SecurityHeadersRun.id == run_id)
            .first()
        )
        if run:
            run.status = "FAILED"
            run.result_data = json.dumps({"error": str(exc)})
            run.completed_at = datetime.utcnow()
            run.updated_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


async def _run_client_ssl_tls(run_id: int, target_host: str, target_port: int):
    db = SessionLocal()
    try:
        run = db.query(SSLTLSRun).filter(SSLTLSRun.id == run_id).first()
        if not run:
            return

        run.status = "RUNNING"
        run.started_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        db.commit()

        result = await asyncio.to_thread(
            inspect_tls,
            target_host,
            target_port,
        )

        connection = result.get("connection") or {}
        certificate = result.get("certificate") or {}

        run.tls_protocol = connection.get("tls_protocol")
        run.cipher_name = connection.get("cipher_name")
        run.cipher_bits = connection.get("cipher_bits")
        run.certificate_subject = certificate.get("subject")
        run.certificate_issuer = certificate.get("issuer")
        run.certificate_serial = certificate.get("serial_number")
        run.certificate_valid_from = certificate.get("valid_from")
        run.certificate_valid_until = certificate.get("valid_until")
        run.san_count = int(certificate.get("san_count") or 0)
        run.hostname_verified = connection.get("hostname_verified")
        run.certificate_verified = connection.get("certificate_verified")
        run.days_remaining = certificate.get("days_remaining")
        run.status = str(result.get("status") or "FAILED").upper()
        run.result_data = json.dumps(result, default=str)
        run.completed_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        db.commit()

    except Exception as exc:
        db.rollback()

        run = db.query(SSLTLSRun).filter(SSLTLSRun.id == run_id).first()
        if run:
            run.status = "FAILED"
            run.result_data = json.dumps({"error": str(exc)})
            run.completed_at = datetime.utcnow()
            run.updated_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


class ClientEndpointRegistrationRequest(BaseModel):
    endpoint_id: str = Field(min_length=1, max_length=255)
    agent_id: str | None = Field(default=None, max_length=255)
    hostname: str | None = Field(default=None, max_length=500)
    ip_address: str | None = Field(default=None, max_length=100)
    mac_address: str | None = Field(default=None, max_length=100)
    os_name: str | None = Field(default=None, max_length=500)
    os_version: str | None = Field(default=None, max_length=500)
    device_type: str | None = Field(default=None, max_length=100)
    status: str = Field(default="ONLINE", min_length=1, max_length=30)

    class Config:
        extra = "forbid"


class ClientProcessSnapshotItem(BaseModel):
    pid: int = Field(ge=0)
    parent_pid: int | None = Field(default=None, ge=0)
    name: str = Field(min_length=1, max_length=500)
    executable: str | None = None
    command_line: str | None = None
    username: str | None = Field(default=None, max_length=255)
    status: str | None = Field(default=None, max_length=50)
    cpu_percent: float | None = None
    memory_percent: float | None = None

    class Config:
        extra = "forbid"


class ClientProcessSnapshotRequest(BaseModel):
    endpoint_id: str = Field(min_length=1, max_length=255)
    processes: list[ClientProcessSnapshotItem] = Field(
        min_length=1,
        max_length=5000,
    )

    class Config:
        extra = "forbid"


class ClientServiceSnapshotItem(BaseModel):
    service_name: str = Field(min_length=1, max_length=500)
    display_name: str | None = Field(default=None, max_length=500)
    status: str | None = Field(default=None, max_length=50)
    startup_type: str | None = Field(default=None, max_length=50)
    executable: str | None = None
    command_line: str | None = None
    username: str | None = Field(default=None, max_length=255)
    pid: int | None = Field(default=None, ge=0)

    class Config:
        extra = "forbid"


class ClientServiceSnapshotRequest(BaseModel):
    endpoint_id: str = Field(min_length=1, max_length=255)
    services: list[ClientServiceSnapshotItem] = Field(
        min_length=1,
        max_length=2000,
    )

    class Config:
        extra = "forbid"


class ClientSystemHardeningSnapshotItem(BaseModel):
    control_id: str = Field(min_length=1, max_length=255)
    control_name: str = Field(min_length=1, max_length=500)
    category: str = Field(min_length=1, max_length=255)
    status: str = Field(min_length=1, max_length=30)
    observed_value: str | None = None
    details: str | None = None

    class Config:
        extra = "forbid"


class ClientSystemHardeningSnapshotRequest(BaseModel):
    endpoint_id: str = Field(min_length=1, max_length=255)
    controls: list[ClientSystemHardeningSnapshotItem] = Field(
        min_length=1,
        max_length=100,
    )

    class Config:
        extra = "forbid"


class ClientServerConfigurationSnapshotRequest(BaseModel):
    endpoint_id: str = Field(min_length=1, max_length=255)
    hostname: str | None = Field(default=None, max_length=500)
    os_name: str | None = Field(default=None, max_length=500)
    os_version: str | None = Field(default=None, max_length=500)
    architecture: str | None = Field(default=None, max_length=100)
    processor: str | None = Field(default=None, max_length=1000)
    memory_total_gb: float | None = Field(default=None, ge=0)
    disk_total_gb: float | None = Field(default=None, ge=0)
    disk_free_gb: float | None = Field(default=None, ge=0)
    disk_usage_percent: float | None = Field(default=None, ge=0, le=100)
    uptime_seconds: int | None = Field(default=None, ge=0)
    uptime: str | None = Field(default=None, max_length=255)
    timezone: str | None = Field(default=None, max_length=255)
    domain_or_workgroup: str | None = Field(default=None, max_length=500)
    windows_edition: str | None = Field(default=None, max_length=500)
    power_plan: str | None = Field(default=None, max_length=500)

    class Config:
        extra = "forbid"


class ClientFirewallRuleSnapshotItem(BaseModel):
    instance_id: str = Field(min_length=1, max_length=500)
    rule_name: str | None = Field(default=None, max_length=500)
    display_name: str | None = Field(default=None, max_length=1000)
    description: str | None = None
    enabled: bool | None = None
    direction: str | None = Field(default=None, max_length=50)
    action: str | None = Field(default=None, max_length=50)
    profile: str | None = Field(default=None, max_length=255)
    protocol: str | None = Field(default=None, max_length=100)
    local_port: str | None = None
    remote_port: str | None = None
    local_address: str | None = None
    remote_address: str | None = None
    program: str | None = None
    service_name: str | None = Field(default=None, max_length=500)
    policy_store_source: str | None = Field(default=None, max_length=500)

    class Config:
        extra = "forbid"


class ClientFirewallRuleSnapshotRequest(BaseModel):
    endpoint_id: str = Field(min_length=1, max_length=255)
    rules: list[ClientFirewallRuleSnapshotItem] = Field(
        min_length=0,
        max_length=10000,
    )
    snapshot_complete: bool = False

    class Config:
        extra = "forbid"





class ClientNetworkDeviceRegistrationRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=255)
    hostname: str | None = Field(default=None, max_length=500)
    ip_address: str | None = Field(default=None, max_length=100)
    mac_address: str | None = Field(default=None, max_length=100)
    device_type: str = Field(default="UNKNOWN", min_length=1, max_length=100)
    vendor: str | None = Field(default=None, max_length=255)
    model: str | None = Field(default=None, max_length=255)
    os_name: str | None = Field(default=None, max_length=500)
    os_version: str | None = Field(default=None, max_length=500)
    status: str = Field(default="ONLINE", min_length=1, max_length=30)

    class Config:
        extra = "forbid"


class ClientDatabaseRegistrationRequest(BaseModel):
    database_id: str = Field(min_length=1, max_length=255)
    name: str | None = Field(default=None, max_length=255)
    hostname: str | None = Field(default=None, max_length=500)
    ip_address: str | None = Field(default=None, max_length=100)
    port: int | None = Field(default=None, ge=1, le=65535)
    database_type: str = Field(default="UNKNOWN", min_length=1, max_length=100)
    version: str | None = Field(default=None, max_length=255)
    environment: str | None = Field(default=None, max_length=100)
    status: str = Field(default="ONLINE", min_length=1, max_length=30)

    class Config:
        extra = "forbid"


@router.post("/network-devices/register")
def register_network_device(
    payload: ClientNetworkDeviceRegistrationRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    if not x_api_key or not x_api_key.strip():
        raise HTTPException(status_code=401, detail="Missing telemetry API key")

    source = (
        db.query(TelemetrySource)
        .filter(
            TelemetrySource.token_hash == _hash_token(x_api_key.strip()),
            TelemetrySource.enabled.is_(True),
        )
        .first()
    )

    if source is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked telemetry API key",
        )

    if source.client_id is None and source.owner_user_id is None:
        raise HTTPException(
            status_code=403,
            detail="Telemetry source has no owner",
        )

    if source.client_id is not None:
        owner_user = (
            db.query(User.id)
            .filter(User.client_id == source.client_id)
            .order_by(User.id.asc())
            .first()
        )

        if owner_user is None:
            raise HTTPException(
                status_code=403,
                detail="Telemetry source owner could not be resolved",
            )

        owner_user_id = owner_user[0]
    else:
        owner_user_id = source.owner_user_id

    device_id = payload.device_id.strip()

    # REJECT_BLANK_ASSET_FIELDS
    if not device_id:
        raise HTTPException(
            status_code=422,
            detail="Asset identifier cannot be blank",
        )
    if not payload.status.strip():
        raise HTTPException(
            status_code=422,
            detail="Asset status cannot be blank",
        )
    if not payload.device_type.strip():
        raise HTTPException(
            status_code=422,
            detail="Asset type cannot be blank",
        )

    existing = (
        db.query(NetworkDeviceAsset)
        .filter(
            NetworkDeviceAsset.device_id == device_id,
            NetworkDeviceAsset.user_id == owner_user_id,
        )
        .first()
    )

    # An API key must not reassign another source's asset.
    if (
        existing is not None
        and existing.telemetry_source_id != source.id
    ):
        raise HTTPException(
            status_code=409,
            detail="Asset identifier belongs to another telemetry source",
        )

    source_asset = (
        db.query(NetworkDeviceAsset)
        .filter(
            NetworkDeviceAsset.device_id == device_id,
            NetworkDeviceAsset.telemetry_source_id == source.id,
        )
        .first()
    )
    if source_asset is not None and source_asset.user_id != owner_user_id:
        raise HTTPException(
            status_code=409,
            detail="Asset ownership requires administrator reconciliation",
        )

    now = datetime.utcnow()

    if existing is None:
        asset = NetworkDeviceAsset(
            user_id=owner_user_id,
            telemetry_source_id=source.id,
            device_id=device_id,
            created_at=now,
        )
        db.add(asset)
    else:
        asset = existing
        asset.telemetry_source_id = source.id
        asset.updated_at = now

    asset.hostname = payload.hostname.strip() if payload.hostname else None
    asset.ip_address = payload.ip_address.strip() if payload.ip_address else None
    asset.mac_address = payload.mac_address.strip() if payload.mac_address else None
    asset.device_type = payload.device_type.strip().upper()
    asset.vendor = payload.vendor.strip() if payload.vendor else None
    asset.model = payload.model.strip() if payload.model else None
    asset.os_name = payload.os_name.strip() if payload.os_name else None
    asset.os_version = payload.os_version.strip() if payload.os_version else None
    asset.status = payload.status.strip().upper()
    asset.last_seen = now
    asset.updated_at = now

    source.last_seen_at = now

    try:
        db.commit()
        db.refresh(asset)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Asset registration conflicts with an existing record",
        ) from None
    except Exception:
        db.rollback()
        raise


    return {
        "registered": True,
        "device_id": asset.device_id,
        "network_device_asset_id": asset.id,
        "telemetry_source_id": source.id,
        "user_id": owner_user_id,
        "status": asset.status,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }



@router.get("/services")
def client_services(
    endpoint_asset_id: int | None = None,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted endpoint service inventory."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    query = (
        db.query(EndpointService, EndpointAsset)
        .join(
            EndpointAsset,
            EndpointAsset.id == EndpointService.endpoint_asset_id,
        )
        .filter(
            EndpointAsset.user_id.in_(scoped_users)
        )
    )

    if endpoint_asset_id is not None:
        query = query.filter(
            EndpointService.endpoint_asset_id == endpoint_asset_id
        )

    rows = query.order_by(
        EndpointService.last_seen.desc(),
        EndpointService.service_name.asc(),
    ).all()

    services = [
        {
            "id": service.id,
            "endpoint_asset_id": endpoint.id,
            "endpoint_id": endpoint.endpoint_id,
            "hostname": endpoint.hostname,
            "ip_address": endpoint.ip_address,
            "os_name": endpoint.os_name,
            "os_version": endpoint.os_version,
            "endpoint_status": endpoint.status,
            "service_name": service.service_name,
            "display_name": service.display_name,
            "status": service.status,
            "startup_type": service.startup_type,
            "executable": service.executable,
            "command_line": service.command_line,
            "username": service.username,
            "pid": service.pid,
            "first_seen": (
                service.first_seen.isoformat()
                if service.first_seen
                else None
            ),
            "last_seen": (
                service.last_seen.isoformat()
                if service.last_seen
                else None
            ),
            "created_at": (
                service.created_at.isoformat()
                if service.created_at
                else None
            ),
            "updated_at": (
                service.updated_at.isoformat()
                if service.updated_at
                else None
            ),
        }
        for service, endpoint in rows
    ]

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "service_count": len(services),
        "services": services,
    }


@router.post("/endpoints/services")
def ingest_endpoint_services(
    payload: ClientServiceSnapshotRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """Persist the current service snapshot reported by a registered endpoint."""

    if not x_api_key or not x_api_key.strip():
        raise HTTPException(status_code=401, detail="Missing telemetry API key")

    source = (
        db.query(TelemetrySource)
        .filter(
            TelemetrySource.token_hash == _hash_token(x_api_key.strip()),
            TelemetrySource.enabled.is_(True),
        )
        .first()
    )

    if source is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked telemetry API key",
        )

    if source.client_id is None and source.owner_user_id is None:
        raise HTTPException(
            status_code=403,
            detail="Telemetry source has no owner",
        )

    if source.client_id is not None:
        owner_user = (
            db.query(User.id)
            .filter(User.client_id == source.client_id)
            .order_by(User.id.asc())
            .first()
        )
        if owner_user is None:
            raise HTTPException(
                status_code=403,
                detail="Telemetry source owner could not be resolved",
            )
        owner_user_id = owner_user[0]
    else:
        owner_user_id = source.owner_user_id

    endpoint_id = payload.endpoint_id.strip()

    endpoint = (
        db.query(EndpointAsset)
        .filter(
            EndpointAsset.endpoint_id == endpoint_id,
            EndpointAsset.telemetry_source_id == source.id,
            EndpointAsset.user_id == owner_user_id,
        )
        .first()
    )

    if endpoint is None:
        raise HTTPException(
            status_code=404,
            detail="Endpoint is not registered for this telemetry source",
        )

    now = datetime.utcnow()
    persisted = 0

    for item in payload.services:
        service_name = item.service_name.strip()

        service = (
            db.query(EndpointService)
            .filter(
                EndpointService.endpoint_asset_id == endpoint.id,
                EndpointService.service_name == service_name,
            )
            .first()
        )

        if service is None:
            service = EndpointService(
                endpoint_asset_id=endpoint.id,
                service_name=service_name,
                first_seen=now,
                created_at=now,
            )
            db.add(service)

        service.display_name = (
            item.display_name.strip()
            if item.display_name
            else None
        )
        service.status = (
            item.status.strip()
            if item.status
            else None
        )
        service.startup_type = (
            item.startup_type.strip()
            if item.startup_type
            else None
        )
        service.executable = item.executable
        service.command_line = item.command_line
        service.username = (
            item.username.strip()
            if item.username
            else None
        )
        service.pid = item.pid
        service.last_seen = now
        service.updated_at = now
        persisted += 1

    endpoint.last_seen = now
    endpoint.updated_at = now
    source.last_seen_at = now

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "ingested": True,
        "endpoint_id": endpoint.endpoint_id,
        "endpoint_asset_id": endpoint.id,
        "telemetry_source_id": source.id,
        "service_count": persisted,
        "last_seen": now.isoformat(),
    }


@router.post("/endpoints/processes")
def ingest_endpoint_processes(
    payload: ClientProcessSnapshotRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """Persist the current process snapshot reported by a registered endpoint."""

    if not x_api_key or not x_api_key.strip():
        raise HTTPException(status_code=401, detail="Missing telemetry API key")

    source = (
        db.query(TelemetrySource)
        .filter(
            TelemetrySource.token_hash == _hash_token(x_api_key.strip()),
            TelemetrySource.enabled.is_(True),
        )
        .first()
    )

    if source is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked telemetry API key",
        )

    if source.client_id is None and source.owner_user_id is None:
        raise HTTPException(
            status_code=403,
            detail="Telemetry source has no owner",
        )

    if source.client_id is not None:
        owner_user = (
            db.query(User.id)
            .filter(User.client_id == source.client_id)
            .order_by(User.id.asc())
            .first()
        )
        if owner_user is None:
            raise HTTPException(
                status_code=403,
                detail="Telemetry source owner could not be resolved",
            )
        owner_user_id = owner_user[0]
    else:
        owner_user_id = source.owner_user_id

    endpoint_id = payload.endpoint_id.strip()

    endpoint = (
        db.query(EndpointAsset)
        .filter(
            EndpointAsset.endpoint_id == endpoint_id,
            EndpointAsset.telemetry_source_id == source.id,
            EndpointAsset.user_id == owner_user_id,
        )
        .first()
    )

    if endpoint is None:
        raise HTTPException(
            status_code=404,
            detail="Endpoint is not registered for this telemetry source",
        )

    now = datetime.utcnow()
    persisted = 0

    for item in payload.processes:
        process = (
            db.query(EndpointProcess)
            .filter(
                EndpointProcess.endpoint_asset_id == endpoint.id,
                EndpointProcess.pid == item.pid,
            )
            .first()
        )

        if process is None:
            process = EndpointProcess(
                endpoint_asset_id=endpoint.id,
                pid=item.pid,
                first_seen=now,
                created_at=now,
            )
            db.add(process)

        process.parent_pid = item.parent_pid
        process.name = item.name.strip()
        process.executable = item.executable
        process.command_line = item.command_line
        process.username = item.username.strip() if item.username else None
        process.status = item.status.strip() if item.status else None
        process.cpu_percent = item.cpu_percent
        process.memory_percent = item.memory_percent
        process.last_seen = now
        process.updated_at = now
        persisted += 1

    endpoint.last_seen = now
    endpoint.updated_at = now
    source.last_seen_at = now

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "ingested": True,
        "endpoint_id": endpoint.endpoint_id,
        "endpoint_asset_id": endpoint.id,
        "telemetry_source_id": source.id,
        "process_count": persisted,
        "last_seen": now.isoformat(),
    }


@router.get("/firewall")
def client_firewall(
    endpoint_asset_id: int | None = None,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted endpoint firewall rule inventory."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    query = (
        db.query(EndpointFirewallRule, EndpointAsset)
        .join(
            EndpointAsset,
            EndpointAsset.id == EndpointFirewallRule.endpoint_asset_id,
        )
        .filter(
            EndpointAsset.user_id.in_(scoped_users)
        )
    )

    if endpoint_asset_id is not None:
        query = query.filter(
            EndpointFirewallRule.endpoint_asset_id == endpoint_asset_id
        )

    rows = query.order_by(
        EndpointFirewallRule.last_seen.desc(),
        EndpointFirewallRule.display_name.asc(),
        EndpointFirewallRule.rule_name.asc(),
    ).all()

    rules = [
        {
            "id": rule.id,
            "endpoint_asset_id": endpoint.id,
            "endpoint_id": endpoint.endpoint_id,
            "hostname": endpoint.hostname,
            "ip_address": endpoint.ip_address,
            "os_name": endpoint.os_name,
            "os_version": endpoint.os_version,
            "endpoint_status": endpoint.status,
            "instance_id": rule.instance_id,
            "rule_name": rule.rule_name,
            "display_name": rule.display_name,
            "description": rule.description,
            "enabled": rule.enabled,
            "direction": rule.direction,
            "action": rule.action,
            "profile": rule.profile,
            "protocol": rule.protocol,
            "local_port": rule.local_port,
            "remote_port": rule.remote_port,
            "local_address": rule.local_address,
            "remote_address": rule.remote_address,
            "program": rule.program,
            "service_name": rule.service_name,
            "policy_store_source": rule.policy_store_source,
            "first_seen": (
                rule.first_seen.isoformat()
                if rule.first_seen
                else None
            ),
            "last_seen": (
                rule.last_seen.isoformat()
                if rule.last_seen
                else None
            ),
            "is_present": bool(rule.is_present),
            "removed_at": (
                rule.removed_at.isoformat()
                if rule.removed_at
                else None
            ),
            "created_at": (
                rule.created_at.isoformat()
                if rule.created_at
                else None
            ),
            "updated_at": (
                rule.updated_at.isoformat()
                if rule.updated_at
                else None
            ),
        }
        for rule, endpoint in rows
    ]

    current_count = sum(1 for rule in rules if rule["is_present"])
    removed_count = len(rules) - current_count

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "firewall_rule_count": len(rules),
        "current_firewall_rule_count": current_count,
        "removed_firewall_rule_count": removed_count,
        "rules": rules,
    }


@router.post("/endpoints/firewall")
def ingest_endpoint_firewall_rules(
    payload: ClientFirewallRuleSnapshotRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """Persist the current Windows firewall rule snapshot reported by a registered endpoint."""

    if not x_api_key or not x_api_key.strip():
        raise HTTPException(status_code=401, detail="Missing telemetry API key")

    source = (
        db.query(TelemetrySource)
        .filter(
            TelemetrySource.token_hash == _hash_token(x_api_key.strip()),
            TelemetrySource.enabled.is_(True),
        )
        .first()
    )

    if source is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked telemetry API key",
        )

    if source.client_id is None and source.owner_user_id is None:
        raise HTTPException(
            status_code=403,
            detail="Telemetry source has no owner",
        )

    if source.client_id is not None:
        owner_user = (
            db.query(User.id)
            .filter(User.client_id == source.client_id)
            .order_by(User.id.asc())
            .first()
        )
        if owner_user is None:
            raise HTTPException(
                status_code=403,
                detail="Telemetry source owner could not be resolved",
            )
        owner_user_id = owner_user[0]
    else:
        owner_user_id = source.owner_user_id

    endpoint_id = payload.endpoint_id.strip()

    endpoint = (
        db.query(EndpointAsset)
        .filter(
            EndpointAsset.endpoint_id == endpoint_id,
            EndpointAsset.telemetry_source_id == source.id,
            EndpointAsset.user_id == owner_user_id,
        )
        .with_for_update()
        .first()
    )

    if endpoint is None:
        raise HTTPException(
            status_code=404,
            detail="Endpoint is not registered for this telemetry source",
        )

    now = datetime.utcnow()

    # Validate the complete snapshot before making any database changes.
    snapshot_instance_id_list = [
        item.instance_id.strip()
        for item in payload.rules
    ]

    if any(not instance_id for instance_id in snapshot_instance_id_list):
        raise HTTPException(
            status_code=422,
            detail="Firewall snapshot contains an empty rule instance ID.",
        )

    if len(snapshot_instance_id_list) != len(set(snapshot_instance_id_list)):
        raise HTTPException(
            status_code=422,
            detail="Firewall snapshot contains duplicate rule instance IDs.",
        )

    snapshot_instance_ids = set(snapshot_instance_id_list)
    persisted = 0

    for item, instance_id in zip(payload.rules, snapshot_instance_id_list):
        rule = (
            db.query(EndpointFirewallRule)
            .filter(
                EndpointFirewallRule.endpoint_asset_id == endpoint.id,
                EndpointFirewallRule.instance_id == instance_id,
            )
            .first()
        )

        if rule is None:
            rule = EndpointFirewallRule(
                endpoint_asset_id=endpoint.id,
                instance_id=instance_id,
                first_seen=now,
                created_at=now,
            )
            db.add(rule)

        rule.rule_name = item.rule_name.strip() if item.rule_name else None
        rule.display_name = item.display_name.strip() if item.display_name else None
        rule.description = item.description
        rule.enabled = item.enabled
        rule.direction = item.direction.strip() if item.direction else None
        rule.action = item.action.strip() if item.action else None
        rule.profile = item.profile.strip() if item.profile else None
        rule.protocol = item.protocol.strip() if item.protocol else None
        rule.local_port = item.local_port
        rule.remote_port = item.remote_port
        rule.local_address = item.local_address
        rule.remote_address = item.remote_address
        rule.program = item.program
        rule.service_name = item.service_name.strip() if item.service_name else None
        rule.policy_store_source = (
            item.policy_store_source.strip()
            if item.policy_store_source
            else None
        )
        rule.last_seen = now
        rule.updated_at = now
        rule.is_present = True
        rule.removed_at = None
        persisted += 1

    # Reconcile historical presence only when the collector confirms
    # that this is a complete snapshot. Partial/legacy uploads cannot
    # mark rules as removed.
    removed_count = 0
    if payload.snapshot_complete:
        removed_count = db.query(EndpointFirewallRule).filter(
            EndpointFirewallRule.endpoint_asset_id == endpoint.id,
            EndpointFirewallRule.is_present.is_(True),
            EndpointFirewallRule.instance_id.notin_(snapshot_instance_id_list),
        ).update(
            {
                "is_present": False,
                "removed_at": now,
                "updated_at": now,
            },
            synchronize_session=False,
        )

    endpoint.last_seen = now
    endpoint.updated_at = now
    source.last_seen_at = now

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "ingested": True,
        "endpoint_id": endpoint.endpoint_id,
        "endpoint_asset_id": endpoint.id,
        "telemetry_source_id": source.id,
        "firewall_rule_count": persisted,
        "snapshot_complete": payload.snapshot_complete,
        "received_rule_count": len(snapshot_instance_id_list),
        "removed_rule_count": removed_count,
        "last_seen": now.isoformat(),
    }


@router.get("/system-hardening")
def client_system_hardening(
    endpoint_asset_id: int | None = None,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted endpoint system hardening results."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    query = (
        db.query(EndpointSystemHardening, EndpointAsset)
        .join(
            EndpointAsset,
            EndpointAsset.id == EndpointSystemHardening.endpoint_asset_id,
        )
        .filter(
            EndpointAsset.user_id.in_(scoped_users)
        )
    )

    if endpoint_asset_id is not None:
        query = query.filter(
            EndpointSystemHardening.endpoint_asset_id == endpoint_asset_id
        )

    rows = query.order_by(
        EndpointSystemHardening.last_seen.desc(),
        EndpointSystemHardening.category.asc(),
        EndpointSystemHardening.control_name.asc(),
    ).all()

    controls = [
        {
            "id": control.id,
            "endpoint_asset_id": endpoint.id,
            "endpoint_id": endpoint.endpoint_id,
            "hostname": endpoint.hostname,
            "ip_address": endpoint.ip_address,
            "os_name": endpoint.os_name,
            "os_version": endpoint.os_version,
            "endpoint_status": endpoint.status,
            "control_id": control.control_id,
            "control_name": control.control_name,
            "category": control.category,
            "status": control.status,
            "observed_value": control.observed_value,
            "details": control.details,
            "first_seen": (
                control.first_seen.isoformat()
                if control.first_seen
                else None
            ),
            "last_seen": (
                control.last_seen.isoformat()
                if control.last_seen
                else None
            ),
            "created_at": (
                control.created_at.isoformat()
                if control.created_at
                else None
            ),
            "updated_at": (
                control.updated_at.isoformat()
                if control.updated_at
                else None
            ),
        }
        for control, endpoint in rows
    ]

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "hardening_control_count": len(controls),
        "controls": controls,
    }


@router.post("/endpoints/system-hardening")
def ingest_endpoint_system_hardening(
    payload: ClientSystemHardeningSnapshotRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """Persist the current Windows system hardening control snapshot reported by a registered endpoint."""

    if not x_api_key or not x_api_key.strip():
        raise HTTPException(status_code=401, detail="Missing telemetry API key")

    source = (
        db.query(TelemetrySource)
        .filter(
            TelemetrySource.token_hash == _hash_token(x_api_key.strip()),
            TelemetrySource.enabled.is_(True),
        )
        .first()
    )

    if source is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked telemetry API key",
        )

    if source.client_id is None and source.owner_user_id is None:
        raise HTTPException(
            status_code=403,
            detail="Telemetry source has no owner",
        )

    if source.client_id is not None:
        owner_user = (
            db.query(User.id)
            .filter(User.client_id == source.client_id)
            .order_by(User.id.asc())
            .first()
        )
        if owner_user is None:
            raise HTTPException(
                status_code=403,
                detail="Telemetry source owner could not be resolved",
            )
        owner_user_id = owner_user[0]
    else:
        owner_user_id = source.owner_user_id

    endpoint_id = payload.endpoint_id.strip()

    endpoint = (
        db.query(EndpointAsset)
        .filter(
            EndpointAsset.endpoint_id == endpoint_id,
            EndpointAsset.telemetry_source_id == source.id,
            EndpointAsset.user_id == owner_user_id,
        )
        .first()
    )

    if endpoint is None:
        raise HTTPException(
            status_code=404,
            detail="Endpoint is not registered for this telemetry source",
        )

    now = datetime.utcnow()
    persisted = 0

    for item in payload.controls:
        control_id = item.control_id.strip()

        control = (
            db.query(EndpointSystemHardening)
            .filter(
                EndpointSystemHardening.endpoint_asset_id == endpoint.id,
                EndpointSystemHardening.control_id == control_id,
            )
            .first()
        )

        if control is None:
            control = EndpointSystemHardening(
                endpoint_asset_id=endpoint.id,
                control_id=control_id,
                first_seen=now,
                created_at=now,
            )
            db.add(control)

        control.control_name = item.control_name.strip()
        control.category = item.category.strip()
        control.status = item.status.strip()
        control.observed_value = item.observed_value
        control.details = item.details
        control.last_seen = now
        control.updated_at = now
        persisted += 1

    endpoint.last_seen = now
    endpoint.updated_at = now
    source.last_seen_at = now

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "ingested": True,
        "endpoint_id": endpoint.endpoint_id,
        "endpoint_asset_id": endpoint.id,
        "telemetry_source_id": source.id,
        "hardening_control_count": persisted,
        "last_seen": now.isoformat(),
    }


@router.post("/endpoints/server-configuration")
def ingest_endpoint_server_configuration(
    payload: ClientServerConfigurationSnapshotRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """Persist the current server configuration snapshot reported by a registered endpoint."""

    if not x_api_key or not x_api_key.strip():
        raise HTTPException(status_code=401, detail="Missing telemetry API key")

    source = (
        db.query(TelemetrySource)
        .filter(
            TelemetrySource.token_hash == _hash_token(x_api_key.strip()),
            TelemetrySource.enabled.is_(True),
        )
        .first()
    )

    if source is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked telemetry API key",
        )

    if source.client_id is None and source.owner_user_id is None:
        raise HTTPException(
            status_code=403,
            detail="Telemetry source has no owner",
        )

    if source.client_id is not None:
        owner_user = (
            db.query(User.id)
            .filter(User.client_id == source.client_id)
            .order_by(User.id.asc())
            .first()
        )
        if owner_user is None:
            raise HTTPException(
                status_code=403,
                detail="Telemetry source owner could not be resolved",
            )
        owner_user_id = owner_user[0]
    else:
        owner_user_id = source.owner_user_id

    endpoint_id = payload.endpoint_id.strip()

    endpoint = (
        db.query(EndpointAsset)
        .filter(
            EndpointAsset.endpoint_id == endpoint_id,
            EndpointAsset.telemetry_source_id == source.id,
            EndpointAsset.user_id == owner_user_id,
        )
        .first()
    )

    if endpoint is None:
        raise HTTPException(
            status_code=404,
            detail="Endpoint is not registered for this telemetry source",
        )

    now = datetime.utcnow()

    configuration = (
        db.query(EndpointServerConfiguration)
        .filter(
            EndpointServerConfiguration.endpoint_asset_id == endpoint.id,
        )
        .first()
    )

    if configuration is None:
        configuration = EndpointServerConfiguration(
            endpoint_asset_id=endpoint.id,
            first_seen=now,
            created_at=now,
        )
        db.add(configuration)

    configuration.hostname = payload.hostname
    configuration.os_name = payload.os_name
    configuration.os_version = payload.os_version
    configuration.architecture = payload.architecture
    configuration.processor = payload.processor
    configuration.memory_total_gb = payload.memory_total_gb
    configuration.disk_total_gb = payload.disk_total_gb
    configuration.disk_free_gb = payload.disk_free_gb
    configuration.disk_usage_percent = payload.disk_usage_percent
    configuration.uptime_seconds = payload.uptime_seconds
    configuration.uptime = payload.uptime
    configuration.timezone = payload.timezone
    configuration.domain_or_workgroup = payload.domain_or_workgroup
    configuration.windows_edition = payload.windows_edition
    configuration.power_plan = payload.power_plan
    configuration.last_seen = now
    configuration.updated_at = now

    endpoint.last_seen = now
    endpoint.updated_at = now
    source.last_seen_at = now

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "ingested": True,
        "endpoint_id": endpoint.endpoint_id,
        "endpoint_asset_id": endpoint.id,
        "telemetry_source_id": source.id,
        "configuration_updated": True,
        "last_seen": now.isoformat(),
    }


@router.get("/server-configuration")
def client_server_configuration(
    endpoint_asset_id: int | None = None,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted endpoint server configuration."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    query = (
        db.query(EndpointServerConfiguration, EndpointAsset)
        .join(
            EndpointAsset,
            EndpointAsset.id == EndpointServerConfiguration.endpoint_asset_id,
        )
        .filter(
            EndpointAsset.user_id.in_(scoped_users)
        )
    )

    if endpoint_asset_id is not None:
        query = query.filter(
            EndpointServerConfiguration.endpoint_asset_id == endpoint_asset_id
        )

    rows = query.order_by(
        EndpointServerConfiguration.last_seen.desc(),
        EndpointServerConfiguration.hostname.asc(),
    ).all()

    configurations = [
        {
            "id": configuration.id,
            "endpoint_asset_id": endpoint.id,
            "endpoint_id": endpoint.endpoint_id,
            "hostname": configuration.hostname,
            "ip_address": endpoint.ip_address,
            "endpoint_status": endpoint.status,
            "os_name": configuration.os_name,
            "os_version": configuration.os_version,
            "architecture": configuration.architecture,
            "processor": configuration.processor,
            "memory_total_gb": float(configuration.memory_total_gb) if configuration.memory_total_gb is not None else None,
            "disk_total_gb": float(configuration.disk_total_gb) if configuration.disk_total_gb is not None else None,
            "disk_free_gb": float(configuration.disk_free_gb) if configuration.disk_free_gb is not None else None,
            "disk_usage_percent": float(configuration.disk_usage_percent) if configuration.disk_usage_percent is not None else None,
            "uptime_seconds": configuration.uptime_seconds,
            "uptime": configuration.uptime,
            "timezone": configuration.timezone,
            "domain_or_workgroup": configuration.domain_or_workgroup,
            "windows_edition": configuration.windows_edition,
            "power_plan": configuration.power_plan,
            "first_seen": configuration.first_seen.isoformat() if configuration.first_seen else None,
            "last_seen": configuration.last_seen.isoformat() if configuration.last_seen else None,
            "created_at": configuration.created_at.isoformat() if configuration.created_at else None,
            "updated_at": configuration.updated_at.isoformat() if configuration.updated_at else None,
        }
        for configuration, endpoint in rows
    ]

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "configuration_count": len(configurations),
        "configurations": configurations,
    }


@router.post("/endpoints/register")
def register_endpoint(
    payload: ClientEndpointRegistrationRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    if not x_api_key or not x_api_key.strip():
        raise HTTPException(status_code=401, detail="Missing telemetry API key")

    source = (
        db.query(TelemetrySource)
        .filter(
            TelemetrySource.token_hash == _hash_token(x_api_key.strip()),
            TelemetrySource.enabled.is_(True),
        )
        .first()
    )

    if source is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked telemetry API key",
        )

    if source.client_id is None and source.owner_user_id is None:
        raise HTTPException(
            status_code=403,
            detail="Telemetry source has no owner",
        )

    if source.client_id is not None:
        owner_user = (
            db.query(User.id)
            .filter(User.client_id == source.client_id)
            .order_by(User.id.asc())
            .first()
        )
        if owner_user is None:
            raise HTTPException(
                status_code=403,
                detail="Telemetry source owner could not be resolved",
            )
        owner_user_id = owner_user[0]
    else:
        owner_user_id = source.owner_user_id

    endpoint_id = payload.endpoint_id.strip()

    # REJECT_BLANK_ASSET_FIELDS
    if not endpoint_id:
        raise HTTPException(
            status_code=422,
            detail="Asset identifier cannot be blank",
        )
    if not payload.status.strip():
        raise HTTPException(
            status_code=422,
            detail="Asset status cannot be blank",
        )
    existing = (
        db.query(EndpointAsset)
        .filter(
            EndpointAsset.endpoint_id == endpoint_id,
            EndpointAsset.user_id == owner_user_id,
        )
        .first()
    )

    # An API key must not reassign another source's asset.
    if (
        existing is not None
        and existing.telemetry_source_id != source.id
    ):
        raise HTTPException(
            status_code=409,
            detail="Asset identifier belongs to another telemetry source",
        )

    source_asset = (
        db.query(EndpointAsset)
        .filter(
            EndpointAsset.endpoint_id == endpoint_id,
            EndpointAsset.telemetry_source_id == source.id,
        )
        .first()
    )
    if source_asset is not None and source_asset.user_id != owner_user_id:
        raise HTTPException(
            status_code=409,
            detail="Asset ownership requires administrator reconciliation",
        )

    now = datetime.utcnow()

    if existing is None:
        asset = EndpointAsset(
            user_id=owner_user_id,
            telemetry_source_id=source.id,
            endpoint_id=endpoint_id,
            created_at=now,
        )
        db.add(asset)
    else:
        asset = existing
        asset.telemetry_source_id = source.id
        asset.updated_at = now

    asset.agent_id = payload.agent_id.strip() if payload.agent_id else None
    asset.hostname = payload.hostname.strip() if payload.hostname else None
    asset.ip_address = payload.ip_address.strip() if payload.ip_address else None
    asset.mac_address = payload.mac_address.strip() if payload.mac_address else None
    asset.os_name = payload.os_name.strip() if payload.os_name else None
    asset.os_version = payload.os_version.strip() if payload.os_version else None
    asset.device_type = payload.device_type.strip() if payload.device_type else None
    asset.status = payload.status.strip().upper()
    asset.last_seen = now
    asset.updated_at = now

    source.last_seen_at = now

    try:
        db.commit()
        db.refresh(asset)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Asset registration conflicts with an existing record",
        ) from None
    except Exception:
        db.rollback()
        raise


    return {
        "registered": True,
        "endpoint_id": asset.endpoint_id,
        "endpoint_asset_id": asset.id,
        "telemetry_source_id": source.id,
        "user_id": asset.user_id,
        "status": asset.status,
        "last_seen": asset.last_seen,
    }


@router.post("/databases/register")
def register_database(
    payload: ClientDatabaseRegistrationRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """Register or update a database asset through an authenticated telemetry source."""

    token_hash = _hash_token(x_api_key)

    source = (
        db.query(TelemetrySource)
        .filter(
            TelemetrySource.token_hash == token_hash,
            TelemetrySource.enabled.is_(True),
        )
        .first()
    )

    if source is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked telemetry API key",
        )

    if source.client_id is None and source.owner_user_id is None:
        raise HTTPException(
            status_code=403,
            detail="Telemetry source has no owner",
        )

    if source.client_id is not None:
        owner_user = (
            db.query(User.id)
            .filter(User.client_id == source.client_id)
            .order_by(User.id.asc())
            .first()
        )
        if owner_user is None:
            raise HTTPException(
                status_code=403,
                detail="Telemetry source owner could not be resolved",
            )
        owner_user_id = owner_user[0]
    else:
        owner_user_id = source.owner_user_id

    database_id = payload.database_id.strip()

    # REJECT_BLANK_ASSET_FIELDS
    if not database_id:
        raise HTTPException(
            status_code=422,
            detail="Asset identifier cannot be blank",
        )
    if not payload.status.strip():
        raise HTTPException(
            status_code=422,
            detail="Asset status cannot be blank",
        )
    if not payload.database_type.strip():
        raise HTTPException(
            status_code=422,
            detail="Asset type cannot be blank",
        )

    existing = (
        db.query(DatabaseAsset)
        .filter(
            DatabaseAsset.database_id == database_id,
            DatabaseAsset.user_id == owner_user_id,
        )
        .first()
    )

    # An API key must not reassign another source's asset.
    if (
        existing is not None
        and existing.telemetry_source_id != source.id
    ):
        raise HTTPException(
            status_code=409,
            detail="Asset identifier belongs to another telemetry source",
        )

    source_asset = (
        db.query(DatabaseAsset)
        .filter(
            DatabaseAsset.database_id == database_id,
            DatabaseAsset.telemetry_source_id == source.id,
        )
        .first()
    )
    if source_asset is not None and source_asset.user_id != owner_user_id:
        raise HTTPException(
            status_code=409,
            detail="Asset ownership requires administrator reconciliation",
        )

    now = datetime.utcnow()

    if existing is None:
        asset = DatabaseAsset(
            user_id=owner_user_id,
            telemetry_source_id=source.id,
            database_id=database_id,
            created_at=now,
        )
        db.add(asset)
    else:
        asset = existing
        asset.telemetry_source_id = source.id
        asset.updated_at = now

    asset.name = payload.name.strip() if payload.name else None
    asset.hostname = payload.hostname.strip() if payload.hostname else None
    asset.ip_address = payload.ip_address.strip() if payload.ip_address else None
    asset.port = payload.port
    asset.database_type = payload.database_type.strip().upper()
    asset.version = payload.version.strip() if payload.version else None
    asset.environment = payload.environment.strip() if payload.environment else None
    asset.status = payload.status.strip().upper()
    asset.last_seen = now
    asset.updated_at = now

    source.last_seen_at = now

    try:
        db.commit()
        db.refresh(asset)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Asset registration conflicts with an existing record",
        ) from None
    except Exception:
        db.rollback()
        raise


    return {
        "registered": True,
        "database_id": asset.database_id,
        "database_asset_id": asset.id,
        "telemetry_source_id": source.id,
        "user_id": asset.user_id,
        "status": asset.status,
        "last_seen": asset.last_seen,
    }


@router.get("/environment-health")
def client_environment_health(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted environment/assessment health."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    assessments = (
        db.query(Assessment)
        .filter(Assessment.user_id.in_(scoped_users))
        .order_by(
            Assessment.updated_at.desc(),
            Assessment.id.desc(),
        )
        .all()
    )

    environments = [
        {
            "assessment_id": assessment.id,
            "target": assessment.target,
            "vapt_status": assessment.vapt_status,
            "qa_status": assessment.qa_status,
            "monitoring_status": assessment.monitoring_status,
            "overall_status": assessment.overall_status,
            "finding_count": int(assessment.vapt_findings_count or 0),
            "created_at": (
                assessment.created_at.isoformat()
                if assessment.created_at
                else None
            ),
            "updated_at": (
                assessment.updated_at.isoformat()
                if assessment.updated_at
                else None
            ),
        }
        for assessment in assessments
    ]

    status_counts = {}
    for environment in environments:
        status = str(environment["overall_status"] or "unknown").lower()
        status_counts[status] = status_counts.get(status, 0) + 1

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "environment_count": len(environments),
        "status_counts": status_counts,
        "environments": environments,
    }


@router.get("/asset-inventory")
def client_asset_inventory(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped inventory derived only from persisted assessments."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    assessments = (
        db.query(Assessment)
        .filter(Assessment.user_id.in_(scoped_users))
        .order_by(
            Assessment.updated_at.desc(),
            Assessment.id.desc(),
        )
        .all()
    )

    assets = []
    for assessment in assessments:
        target = str(assessment.target or "").strip()

        asset_type = (
            "Code Assessment"
            if target.lower().startswith("code://")
            else "Target Assessment"
        )

        finding_count = (
            db.query(func.count(SecurityFinding.id))
            .filter(
                SecurityFinding.assessment_id == assessment.id,
                SecurityFinding.user_id.in_(scoped_users),
            )
            .scalar()
            or 0
        )

        assets.append({
            "asset_id": assessment.id,
            "assessment_id": assessment.id,
            "target": target,
            "asset_type": asset_type,
            "source": "VAPT Assessment",
            "vapt_status": assessment.vapt_status,
            "qa_status": assessment.qa_status,
            "monitoring_status": assessment.monitoring_status,
            "overall_status": assessment.overall_status,
            "finding_count": int(finding_count),
            "first_observed": (
                assessment.created_at.isoformat()
                if assessment.created_at
                else None
            ),
            "last_updated": (
                assessment.updated_at.isoformat()
                if assessment.updated_at
                else None
            ),
        })

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "asset_count": len(assets),
        "assets": assets,
    }


@router.get("/servers")
def client_servers(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped server assets materialized from Asset Discovery."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    assets = (
        db.query(ServerAsset)
        .filter(ServerAsset.user_id.in_(scoped_users))
        .order_by(
            ServerAsset.last_seen.desc(),
            ServerAsset.id.desc(),
        )
        .all()
    )

    servers = []

    for asset in assets:
        services = None

        if asset.services_data:
            try:
                services = json.loads(asset.services_data)
            except (TypeError, ValueError):
                services = None

        servers.append({
            "id": asset.id,
            "user_id": asset.user_id,
            "assessment_id": asset.assessment_id,
            "discovery_run_id": asset.discovery_run_id,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "target": asset.target,
            "host_status": asset.host_status,
            "os_name": asset.os_name,
            "open_port_count": int(asset.open_port_count or 0),
            "services": services,
            "last_seen": (
                asset.last_seen.isoformat()
                if asset.last_seen
                else None
            ),
            "created_at": (
                asset.created_at.isoformat()
                if asset.created_at
                else None
            ),
            "updated_at": (
                asset.updated_at.isoformat()
                if asset.updated_at
                else None
            ),
        })

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "server_count": len(servers),
        "servers": servers,
    }



@router.get("/databases")
def client_databases(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted database assets."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    assets = (
        db.query(DatabaseAsset)
        .filter(DatabaseAsset.user_id.in_(scoped_users))
        .order_by(
            DatabaseAsset.last_seen.desc(),
            DatabaseAsset.id.desc(),
        )
        .all()
    )

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "database_count": len(assets),
        "databases": [
            {
                "id": asset.id,
                "user_id": asset.user_id,
                "telemetry_source_id": asset.telemetry_source_id,
                "database_id": asset.database_id,
                "name": asset.name,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "port": asset.port,
                "database_type": asset.database_type,
                "version": asset.version,
                "environment": asset.environment,
                "status": asset.status,
                "last_seen": (
                    asset.last_seen.isoformat()
                    if asset.last_seen
                    else None
                ),
                "created_at": (
                    asset.created_at.isoformat()
                    if asset.created_at
                    else None
                ),
                "updated_at": (
                    asset.updated_at.isoformat()
                    if asset.updated_at
                    else None
                ),
            }
            for asset in assets
        ],
    }


@router.get("/network-devices")
def client_network_devices(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return ownership-scoped persisted network device assets."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    devices = (
        db.query(NetworkDeviceAsset)
        .filter(NetworkDeviceAsset.user_id.in_(scoped_users))
        .order_by(
            NetworkDeviceAsset.last_seen.desc(),
            NetworkDeviceAsset.id.desc(),
        )
        .all()
    )

    device_rows = [
        {
            "id": device.id,
            "user_id": device.user_id,
            "telemetry_source_id": device.telemetry_source_id,
            "device_id": device.device_id,
            "hostname": device.hostname,
            "ip_address": device.ip_address,
            "mac_address": device.mac_address,
            "device_type": device.device_type,
            "vendor": device.vendor,
            "model": device.model,
            "os_name": device.os_name,
            "os_version": device.os_version,
            "status": device.status,
            "last_seen": (
                device.last_seen.isoformat()
                if device.last_seen
                else None
            ),
            "created_at": (
                device.created_at.isoformat()
                if device.created_at
                else None
            ),
            "updated_at": (
                device.updated_at.isoformat()
                if device.updated_at
                else None
            ),
        }
        for device in devices
    ]

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "network_device_count": len(device_rows),
        "network_devices": device_rows,
    }



@router.get("/applications")
def client_applications(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return scoped assessment rows with explicit HTTP/HTTPS targets."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    assessments = (
        db.query(Assessment)
        .filter(
            Assessment.user_id.in_(scoped_users),
            ~Assessment.target.startswith("code://"),
        )
        .order_by(
            Assessment.updated_at.desc(),
            Assessment.id.desc(),
        )
        .all()
    )

    applications = []

    for assessment in assessments:
        # VALIDATE_WEB_APPLICATION_TARGET
        target = str(assessment.target or "").strip()
        if not target or any(ord(char) <= 32 or ord(char) == 127 for char in target):
            continue

        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port
        except (TypeError, ValueError):
            continue

        if (
            parsed.scheme not in {"http", "https"}
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or (port is not None and not 1 <= port <= 65535)
        ):
            continue

        finding_count = (
            db.query(func.count(SecurityFinding.id))
            .filter(
                SecurityFinding.assessment_id == assessment.id,
                SecurityFinding.user_id == assessment.user_id,
            )
            .scalar()
            or 0
        )

        applications.append({
            "assessment_id": assessment.id,
            "user_id": assessment.user_id,
            "target": target,
            "scheme": parsed.scheme or None,
            "hostname": hostname,
            "port": port,
            "path": parsed.path or "/",
            "application_type": "Web Application",
            "vapt_status": assessment.vapt_status,
            "vapt_findings_count": assessment.vapt_findings_count,
            "finding_count": finding_count,
            "qa_status": assessment.qa_status,
            "qa_score": assessment.qa_score,
            "monitoring_status": assessment.monitoring_status,
            "overall_status": assessment.overall_status,
            "report_status": assessment.report_status,
            "created_at": (
                assessment.created_at.isoformat()
                if assessment.created_at
                else None
            ),
            "updated_at": (
                assessment.updated_at.isoformat()
                if assessment.updated_at
                else None
            ),
        })

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "application_count": len(applications),
        "applications": applications,
    }


@router.get("/ip-addresses")
def client_ip_addresses(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return ownership-scoped IP addresses from verified asset and assessment sources."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    scoped_user_ids = [row[0] for row in scoped_users.all()]

    if not scoped_user_ids:
        return {
            "scope": "client" if current_user.client_id is not None else "personal",
            "ip_count": 0,
            "ip_addresses": [],
        }

    import ipaddress

    ip_assets = {}

    def ensure_ip(ip_value):
        if not ip_value:
            return None

        value = str(ip_value).strip()
        if not value:
            return None

        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    def get_item(ip):
        if ip not in ip_assets:
            ip_assets[ip] = {
                "ip_address": ip,
                "source_types": set(),
                "asset_count": 0,
                "assessment_ids": set(),
                "hostnames": set(),
                "statuses": set(),
                "first_observed": None,
                "last_seen": None,
            }
        return ip_assets[ip]

    def update_times(item, created_at=None, last_seen=None):
        if created_at and (
            item["first_observed"] is None
            or created_at < item["first_observed"]
        ):
            item["first_observed"] = created_at

        if last_seen and (
            item["last_seen"] is None
            or last_seen > item["last_seen"]
        ):
            item["last_seen"] = last_seen

    # ------------------------------------------------------------
    # 1. Direct IP-based assessment targets
    # ------------------------------------------------------------
    assessments = (
        db.query(Assessment)
        .filter(
            Assessment.user_id.in_(scoped_user_ids),
            ~Assessment.target.startswith("code://"),
        )
        .all()
    )

    for assessment in assessments:
        parsed = urlparse(assessment.target)
        hostname = parsed.hostname

        ip = ensure_ip(hostname)

        if not ip:
            raw_target = str(assessment.target).strip()
            ip = ensure_ip(raw_target)

        if not ip:
            continue

        item = get_item(ip)
        item["source_types"].add("Assessment")
        item["asset_count"] += 1
        item["assessment_ids"].add(assessment.id)

        if assessment.created_at:
            update_times(
                item,
                created_at=assessment.created_at,
                last_seen=assessment.updated_at,
            )

    # ------------------------------------------------------------
    # 2. Discovered Server assets
    # ------------------------------------------------------------
    servers = (
        db.query(ServerAsset)
        .filter(ServerAsset.user_id.in_(scoped_user_ids))
        .all()
    )

    for server in servers:
        ip = ensure_ip(server.ip_address)
        if not ip:
            continue

        item = get_item(ip)
        item["source_types"].add("Server")
        item["asset_count"] += 1

        if server.assessment_id:
            item["assessment_ids"].add(server.assessment_id)

        if server.hostname:
            item["hostnames"].add(server.hostname)

        if server.host_status:
            item["statuses"].add(server.host_status)

        update_times(
            item,
            created_at=server.created_at,
            last_seen=server.last_seen or server.updated_at,
        )

    # ------------------------------------------------------------
    # 3. Registered Endpoint assets
    # ------------------------------------------------------------
    endpoints = (
        db.query(EndpointAsset)
        .filter(EndpointAsset.user_id.in_(scoped_user_ids))
        .all()
    )

    for endpoint in endpoints:
        ip = ensure_ip(endpoint.ip_address)
        if not ip:
            continue

        item = get_item(ip)
        item["source_types"].add("Endpoint")
        item["asset_count"] += 1

        if endpoint.hostname:
            item["hostnames"].add(endpoint.hostname)

        if endpoint.status:
            item["statuses"].add(endpoint.status)

        update_times(
            item,
            created_at=endpoint.created_at,
            last_seen=endpoint.last_seen or endpoint.updated_at,
        )

    # ------------------------------------------------------------
    # 4. Registered Network Device assets
    # ------------------------------------------------------------
    network_devices = (
        db.query(NetworkDeviceAsset)
        .filter(NetworkDeviceAsset.user_id.in_(scoped_user_ids))
        .all()
    )

    for device in network_devices:
        ip = ensure_ip(device.ip_address)
        if not ip:
            continue

        item = get_item(ip)
        item["source_types"].add("Network Device")
        item["asset_count"] += 1

        if device.hostname:
            item["hostnames"].add(device.hostname)

        if device.status:
            item["statuses"].add(device.status)

        update_times(
            item,
            created_at=device.created_at,
            last_seen=device.last_seen or device.updated_at,
        )

    # ------------------------------------------------------------
    # 5. Registered Database assets
    # ------------------------------------------------------------
    databases = (
        db.query(DatabaseAsset)
        .filter(DatabaseAsset.user_id.in_(scoped_user_ids))
        .all()
    )

    for database in databases:
        ip = ensure_ip(database.ip_address)
        if not ip:
            continue

        item = get_item(ip)
        item["source_types"].add("Database")
        item["asset_count"] += 1

        if database.hostname:
            item["hostnames"].add(database.hostname)

        if database.status:
            item["statuses"].add(database.status)

        update_times(
            item,
            created_at=database.created_at,
            last_seen=database.last_seen or database.updated_at,
        )

    # ------------------------------------------------------------
    # Serialize deterministic JSON-safe response
    # ------------------------------------------------------------
    results = []

    for item in ip_assets.values():
        results.append(
            {
                "ip_address": item["ip_address"],
                "source_types": sorted(item["source_types"]),
                "asset_count": item["asset_count"],
                "assessment_ids": sorted(item["assessment_ids"]),
                "hostnames": sorted(item["hostnames"]),
                "statuses": sorted(item["statuses"]),
                "first_observed": (
                    item["first_observed"].isoformat()
                    if item["first_observed"]
                    else None
                ),
                "last_seen": (
                    item["last_seen"].isoformat()
                    if item["last_seen"]
                    else None
                ),
            }
        )

    results.sort(
        key=lambda item: (
            item["last_seen"] or "",
            item["ip_address"],
        ),
        reverse=True,
    )

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "ip_count": len(results),
        "ip_addresses": results,
    }


@router.get("/domains")
def client_domains(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return ownership-scoped domains derived from real web assessments."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    assessments = (
        db.query(Assessment)
        .filter(
            Assessment.user_id.in_(scoped_users),
            ~Assessment.target.startswith("code://"),
        )
        .order_by(
            Assessment.updated_at.desc(),
            Assessment.id.desc(),
        )
        .all()
    )

    domains = {}

    for assessment in assessments:
        parsed = urlparse(assessment.target)
        hostname = parsed.hostname

        if not hostname:
            continue

        try:
            import ipaddress
            ipaddress.ip_address(hostname)
            continue
        except ValueError:
            pass

        key = hostname.lower()

        finding_count = (
            db.query(func.count(SecurityFinding.id))
            .filter(
                SecurityFinding.assessment_id == assessment.id,
                SecurityFinding.user_id == assessment.user_id,
            )
            .scalar()
            or 0
        )

        if key not in domains:
            domains[key] = {
                "domain": hostname,
                "assessment_ids": [],
                "assessment_count": 0,
                "finding_count": 0,
                "vapt_statuses": set(),
                "qa_statuses": set(),
                "monitoring_statuses": set(),
                "overall_statuses": set(),
                "first_observed": assessment.created_at,
                "last_updated": assessment.updated_at,
            }

        item = domains[key]

        if assessment.id not in item["assessment_ids"]:
            item["assessment_ids"].append(assessment.id)

        item["assessment_count"] += 1
        item["finding_count"] += finding_count

        if assessment.vapt_status:
            item["vapt_statuses"].add(assessment.vapt_status)

        if assessment.qa_status:
            item["qa_statuses"].add(assessment.qa_status)

        if assessment.monitoring_status:
            item["monitoring_statuses"].add(assessment.monitoring_status)

        if assessment.overall_status:
            item["overall_statuses"].add(assessment.overall_status)

        if assessment.created_at and (
            item["first_observed"] is None
            or assessment.created_at < item["first_observed"]
        ):
            item["first_observed"] = assessment.created_at

        if assessment.updated_at and (
            item["last_updated"] is None
            or assessment.updated_at > item["last_updated"]
        ):
            item["last_updated"] = assessment.updated_at

    result = []

    for item in domains.values():
        result.append({
            "domain": item["domain"],
            "assessment_ids": sorted(item["assessment_ids"]),
            "assessment_count": item["assessment_count"],
            "finding_count": item["finding_count"],
            "vapt_statuses": sorted(item["vapt_statuses"]),
            "qa_statuses": sorted(item["qa_statuses"]),
            "monitoring_statuses": sorted(item["monitoring_statuses"]),
            "overall_statuses": sorted(item["overall_statuses"]),
            "first_observed": (
                item["first_observed"].isoformat()
                if item["first_observed"]
                else None
            ),
            "last_updated": (
                item["last_updated"].isoformat()
                if item["last_updated"]
                else None
            ),
        })

    result.sort(
        key=lambda item: (
            item["last_updated"] or "",
            item["domain"].lower(),
        ),
        reverse=True,
    )

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "domain_count": len(result),
        "domains": result,
    }


@router.get("/endpoints")
def client_endpoints(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return ownership-scoped persisted endpoint assets."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    endpoints = (
        db.query(EndpointAsset)
        .filter(EndpointAsset.user_id.in_(scoped_users))
        .order_by(
            EndpointAsset.last_seen.desc(),
            EndpointAsset.id.desc(),
        )
        .all()
    )

    endpoint_rows = [
        {
            "id": endpoint.id,
            "user_id": endpoint.user_id,
            "telemetry_source_id": endpoint.telemetry_source_id,
            "endpoint_id": endpoint.endpoint_id,
            "agent_id": endpoint.agent_id,
            "hostname": endpoint.hostname,
            "ip_address": endpoint.ip_address,
            "mac_address": endpoint.mac_address,
            "os_name": endpoint.os_name,
            "os_version": endpoint.os_version,
            "device_type": endpoint.device_type,
            "status": endpoint.status,
            "last_seen": (
                endpoint.last_seen.isoformat()
                if endpoint.last_seen
                else None
            ),
            "created_at": (
                endpoint.created_at.isoformat()
                if endpoint.created_at
                else None
            ),
            "updated_at": (
                endpoint.updated_at.isoformat()
                if endpoint.updated_at
                else None
            ),
        }
        for endpoint in endpoints
    ]

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "endpoint_count": len(endpoint_rows),
        "endpoints": endpoint_rows,
    }


@router.get("/processes")
def client_processes(
    endpoint_asset_id: int | None = None,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted endpoint process inventory."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    query = (
        db.query(EndpointProcess, EndpointAsset)
        .join(
            EndpointAsset,
            EndpointAsset.id == EndpointProcess.endpoint_asset_id,
        )
        .filter(
            EndpointAsset.user_id.in_(scoped_users)
        )
    )

    if endpoint_asset_id is not None:
        query = query.filter(
            EndpointProcess.endpoint_asset_id == endpoint_asset_id
        )

    rows = query.order_by(
        EndpointProcess.last_seen.desc(),
        EndpointProcess.name.asc(),
        EndpointProcess.pid.asc(),
    ).all()

    processes = [
        {
            "id": process.id,
            "endpoint_asset_id": endpoint.id,
            "endpoint_id": endpoint.endpoint_id,
            "hostname": endpoint.hostname,
            "ip_address": endpoint.ip_address,
            "os_name": endpoint.os_name,
            "os_version": endpoint.os_version,
            "endpoint_status": endpoint.status,
            "pid": process.pid,
            "parent_pid": process.parent_pid,
            "name": process.name,
            "executable": process.executable,
            "command_line": process.command_line,
            "username": process.username,
            "status": process.status,
            "cpu_percent": process.cpu_percent,
            "memory_percent": process.memory_percent,
            "first_seen": (
                process.first_seen.isoformat()
                if process.first_seen
                else None
            ),
            "last_seen": (
                process.last_seen.isoformat()
                if process.last_seen
                else None
            ),
            "created_at": (
                process.created_at.isoformat()
                if process.created_at
                else None
            ),
            "updated_at": (
                process.updated_at.isoformat()
                if process.updated_at
                else None
            ),
        }
        for process, endpoint in rows
    ]

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "process_count": len(processes),
        "processes": processes,
    }


@router.get("/security-events")
def client_security_events(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted endpoint security events."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    scoped_endpoint_ids = (
        db.query(EndpointAsset.id)
        .filter(EndpointAsset.user_id.in_(scoped_users))
        .subquery()
    )

    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.endpoint_asset_id.in_(scoped_endpoint_ids)
        )
        .order_by(
            SecurityEvent.timestamp.desc(),
            SecurityEvent.id.desc(),
        )
        .limit(500)
        .all()
    )

    event_rows = [
        {
            "id": event.id,
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "event_type": event.event_type,
            "severity": event.severity,
            "message": event.message,
            "target": event.target,
            "endpoint_asset_id": event.endpoint_asset_id,
            "telemetry_source_id": event.telemetry_source_id,
            "mitre_technique_id": event.mitre_technique_id,
            "mitre_technique_name": event.mitre_technique_name,
            "mitre_tactic": event.mitre_tactic,
            "alert_status": event.alert_status,
            "created_at": (
                event.created_at.isoformat()
                if event.created_at
                else None
            ),
        }
        for event in events
    ]

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "event_count": len(event_rows),
        "events": event_rows,
    }


@router.get("/asset-discovery")
def client_asset_discovery(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted Asset Discovery runs."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    runs = (
        db.query(AssetDiscoveryRun)
        .filter(AssetDiscoveryRun.user_id.in_(scoped_users))
        .order_by(
            AssetDiscoveryRun.updated_at.desc(),
            AssetDiscoveryRun.id.desc(),
        )
        .all()
    )

    discovery_runs = []

    for run in runs:
        result = None

        if run.result_data:
            try:
                result = json.loads(run.result_data)
            except (TypeError, ValueError):
                result = None

        discovery_runs.append({
            "id": run.id,
            "job_id": run.job_id,
            "assessment_id": run.assessment_id,
            "target": run.target,
            "scan_type": run.scan_type,
            "status": run.status,
            "host_count": int(run.host_count or 0),
            "open_port_count": int(run.open_port_count or 0),
            "started_at": (
                run.started_at.isoformat()
                if run.started_at
                else None
            ),
            "completed_at": (
                run.completed_at.isoformat()
                if run.completed_at
                else None
            ),
            "created_at": (
                run.created_at.isoformat()
                if run.created_at
                else None
            ),
            "updated_at": (
                run.updated_at.isoformat()
                if run.updated_at
                else None
            ),
            "result": result,
        })

    return {
        "scope": (
            "client"
            if current_user.client_id is not None
            else "personal"
        ),
        "run_count": len(discovery_runs),
        "runs": discovery_runs,
    }




@router.get("/exposed-services")
def client_exposed_services(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return ownership-scoped services discovered by completed Nmap runs."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    assets = (
        db.query(ServerAsset)
        .filter(ServerAsset.user_id.in_(scoped_users))
        .order_by(
            ServerAsset.last_seen.desc(),
            ServerAsset.id.desc(),
        )
        .all()
    )

    services = []
    seen = set()

    for asset in assets:
        try:
            data = json.loads(asset.services_data or "{}")
        except (TypeError, ValueError):
            data = {}

        ports = data.get("ports") or []

        for port_data in ports:
            if not isinstance(port_data, dict):
                continue

            state = str(port_data.get("state") or "").lower()
            if state and state != "open":
                continue

            service = port_data.get("service") or {}
            if not isinstance(service, dict):
                service = {}

            protocol = str(
                port_data.get("protocol") or "tcp"
            ).lower()

            try:
                port_number = int(port_data.get("port") or 0)
            except (TypeError, ValueError):
                continue

            if not 1 <= port_number <= 65535:
                continue

            service_name = service.get("name")
            product = service.get("product")
            version = service.get("version")
            extrainfo = service.get("extrainfo")
            tunnel = service.get("tunnel")
            method = service.get("method")

            # A service must have meaningful Nmap service identification.
            if not any([
                service_name,
                product,
                version,
                extrainfo,
            ]):
                continue

            key = (
                asset.user_id,
                asset.hostname or asset.ip_address or asset.target,
                protocol,
                port_number,
                str(service_name or "").lower(),
                str(product or "").lower(),
                str(version or "").lower(),
            )

            if key in seen:
                continue

            seen.add(key)

            services.append({
                "target": asset.target,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "port": port_number,
                "protocol": protocol,
                "state": port_data.get("state") or "open",
                "reason": port_data.get("reason"),
                "service_name": service_name,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "tunnel": tunnel,
                "method": method,
                "source": "Nmap",
                "discovery_run_id": asset.discovery_run_id,
                "assessment_id": asset.assessment_id,
                "asset_id": asset.id,
            })

    services.sort(
        key=lambda item: (
            str(item.get("hostname") or item.get("ip_address") or ""),
            int(item.get("port") or 0),
            str(item.get("protocol") or ""),
        )
    )

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "total_services": len(services),
        "targets_with_services": len({
            item["hostname"] or item["ip_address"] or item["target"]
            for item in services
        }),
        "services": services,
    }


@router.get("/open-ports")
def client_open_ports(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped open ports from persisted Nmap and Masscan runs."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    scoped_user_ids = scoped_users.subquery()

    nmap_runs = (
        db.query(AssetDiscoveryRun)
        .filter(
            AssetDiscoveryRun.user_id.in_(
                db.query(scoped_user_ids.c.id)
            ),
            AssetDiscoveryRun.status == "COMPLETED",
        )
        .order_by(
            AssetDiscoveryRun.updated_at.desc(),
            AssetDiscoveryRun.id.desc(),
        )
        .all()
    )

    masscan_runs = (
        db.query(InternalAttackSurfaceRun)
        .filter(
            InternalAttackSurfaceRun.user_id.in_(
                db.query(scoped_user_ids.c.id)
            ),
            InternalAttackSurfaceRun.status == "COMPLETED",
        )
        .order_by(
            InternalAttackSurfaceRun.updated_at.desc(),
            InternalAttackSurfaceRun.id.desc(),
        )
        .all()
    )

    ports = []
    seen = set()

    def add_port(
        port,
        protocol,
        target,
        source,
        run_id,
        assessment_id=None,
        asset_type=None,
        asset_id=None,
    ):
        try:
            port_number = int(port)
        except (TypeError, ValueError):
            return

        if not 1 <= port_number <= 65535:
            return

        protocol_value = str(protocol or "tcp").lower()
        target_value = str(target or "unknown")

        key = (
            target_value,
            protocol_value,
            port_number,
        )

        if key in seen:
            return

        seen.add(key)

        ports.append({
            "port": port_number,
            "protocol": protocol_value,
            "target": target_value,
            "source": source,
            "run_id": run_id,
            "assessment_id": assessment_id,
            "asset_type": asset_type,
            "asset_id": asset_id,
        })

    for run in nmap_runs:
        try:
            result = json.loads(run.result_data or "{}")
        except (TypeError, ValueError):
            continue

        for item in result.get("open_ports") or []:
            if isinstance(item, dict):
                add_port(
                    item.get("port"),
                    item.get("protocol"),
                    result.get("target") or run.target,
                    "Nmap",
                    run.id,
                    run.assessment_id,
                )
            else:
                add_port(
                    item,
                    "tcp",
                    result.get("target") or run.target,
                    "Nmap",
                    run.id,
                    run.assessment_id,
                )

    for run in masscan_runs:
        try:
            data = json.loads(run.result_data or "{}")
        except (TypeError, ValueError):
            continue

        execution = data.get("execution") or {}
        results = execution.get("results") or {}

        for item in results.get("open_ports") or []:
            if isinstance(item, dict):
                add_port(
                    item.get("port"),
                    item.get("protocol"),
                    (data.get("asset") or {}).get("target_ip")
                    or run.target_ip,
                    "Masscan",
                    run.id,
                    asset_type=run.asset_type,
                    asset_id=run.asset_id,
                )
            else:
                add_port(
                    item,
                    "tcp",
                    (data.get("asset") or {}).get("target_ip")
                    or run.target_ip,
                    "Masscan",
                    run.id,
                    asset_type=run.asset_type,
                    asset_id=run.asset_id,
                )

    ports.sort(
        key=lambda item: (
            str(item["target"]),
            int(item["port"]),
            str(item["protocol"]),
        )
    )

    return {
        "scope": (
            "client"
            if current_user.client_id is not None
            else "personal"
        ),
        "source_runs": {
            "nmap": len(nmap_runs),
            "masscan": len(masscan_runs),
        },
        "total_open_ports": len(ports),
        "targets_with_open_ports": len({
            item["target"] for item in ports
        }),
        "ports": ports,
    }

@router.get("/external-attack-surface")
def client_external_attack_surface(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted External Attack Surface runs."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    runs = (
        db.query(ExternalAttackSurfaceRun)
        .filter(
            ExternalAttackSurfaceRun.user_id.in_(scoped_users)
        )
        .order_by(
            ExternalAttackSurfaceRun.updated_at.desc(),
            ExternalAttackSurfaceRun.id.desc(),
        )
        .all()
    )

    attack_surface_runs = []

    for run in runs:
        result = None

        if run.result_data:
            try:
                result = json.loads(run.result_data)
            except (TypeError, ValueError):
                result = None

        attack_surface_runs.append({
            "id": run.id,
            "job_id": run.job_id,
            "assessment_id": run.assessment_id,
            "target_domain": run.target_domain,
            "status": run.status,
            "discovered_domain_count": int(
                run.discovered_domain_count or 0
            ),
            "discovered_host_count": int(
                run.discovered_host_count or 0
            ),
            "discovered_ip_count": int(
                run.discovered_ip_count or 0
            ),
            "discovered_port_count": int(
                run.discovered_port_count or 0
            ),
            "started_at": (
                run.started_at.isoformat()
                if run.started_at
                else None
            ),
            "completed_at": (
                run.completed_at.isoformat()
                if run.completed_at
                else None
            ),
            "created_at": (
                run.created_at.isoformat()
                if run.created_at
                else None
            ),
            "updated_at": (
                run.updated_at.isoformat()
                if run.updated_at
                else None
            ),
            "result": result,
        })

    return {
        "scope": (
            "client"
            if current_user.client_id is not None
            else "personal"
        ),
        "run_count": len(attack_surface_runs),
        "runs": attack_surface_runs,
    }


def _get_client_internal_attack_surface_asset(
    db: Session,
    current_user: User,
    asset_type: str,
    asset_id: int,
):
    """Resolve one tenant-owned RFC1918 asset for an internal surface scan."""

    normalized_type = asset_type.strip().upper()

    if normalized_type not in {
        "ENDPOINT",
        "NETWORK_DEVICE",
        "DATABASE",
        "SERVER",
    }:
        raise HTTPException(
            status_code=400,
            detail="Unsupported internal asset type.",
        )

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    user_ids = [row[0] for row in scoped_users.all()]

    if not user_ids:
        raise HTTPException(
            status_code=404,
            detail="No assets are available in the current scope.",
        )

    model_map = {
        "ENDPOINT": EndpointAsset,
        "NETWORK_DEVICE": NetworkDeviceAsset,
        "DATABASE": DatabaseAsset,
        "SERVER": ServerAsset,
    }

    model = model_map[normalized_type]

    asset = (
        db.query(model)
        .filter(
            model.id == asset_id,
            model.user_id.in_(user_ids),
        )
        .first()
    )

    if asset is None:
        raise HTTPException(
            status_code=404,
            detail="Internal asset not found in the current scope.",
        )

    target_ip = (
        getattr(asset, "ip_address", None)
        or ""
    ).strip()

    if not target_ip:
        raise HTTPException(
            status_code=400,
            detail="The selected asset has no IP address.",
        )

    import ipaddress

    try:
        parsed_ip = ipaddress.ip_address(target_ip)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="The selected asset has an invalid IP address.",
        )

    # Internal Attack Surface is intentionally restricted to
    # RFC1918 private IPv4 ranges. This excludes loopback, public,
    # link-local, multicast, and other non-RFC1918 addresses.
    if parsed_ip.version != 4 or not (
        parsed_ip in ipaddress.ip_network("10.0.0.0/8")
        or parsed_ip in ipaddress.ip_network("172.16.0.0/12")
        or parsed_ip in ipaddress.ip_network("192.168.0.0/16")
    ):
        raise HTTPException(
            status_code=400,
            detail="Internal Attack Surface scans require an RFC1918 private IPv4 asset.",
        )

    return {
        "asset_type": normalized_type,
        "asset_id": asset.id,
        "target_ip": target_ip,
        "asset": asset,
    }


class ClientInternalAttackSurfaceRequest(BaseModel):
    asset_type: str
    asset_id: int


async def _run_client_internal_attack_surface(
    run_id: int,
):
    """Execute Masscan against one persisted, tenant-owned internal asset."""

    db = SessionLocal()

    try:
        run = (
            db.query(InternalAttackSurfaceRun)
            .filter(InternalAttackSurfaceRun.id == run_id)
            .first()
        )

        if run is None:
            return

        run.status = "RUNNING"
        run.started_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        db.commit()

        result = await _execute_masscan_command(
            run.target_ip,
        )

        discovered_hosts = (
            result.get("results", {}).get("hosts", [])
            if isinstance(result, dict)
            else []
        )

        open_ports = (
            result.get("results", {}).get("open_ports", [])
            if isinstance(result, dict)
            else []
        )

        execution_status = (
            str(result.get("status", "")).lower()
            if isinstance(result, dict)
            else ""
        )

        run.discovered_host_count = len(discovered_hosts)
        run.discovered_port_count = len(open_ports)

        run.result_data = json.dumps(
            {
                "tool": "Masscan",
                "asset": {
                    "asset_type": run.asset_type,
                    "asset_id": run.asset_id,
                    "target_ip": run.target_ip,
                },
                "execution": result,
            },
            default=str,
        )

        run.status = (
            "COMPLETED"
            if execution_status == "completed"
            else "FAILED"
        )
        run.completed_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()

        db.commit()

    except Exception as exc:
        db.rollback()

        run = (
            db.query(InternalAttackSurfaceRun)
            .filter(InternalAttackSurfaceRun.id == run_id)
            .first()
        )

        if run is not None:
            run.status = "FAILED"
            run.result_data = json.dumps(
                {
                    "tool": "Masscan",
                    "asset": {
                        "asset_type": run.asset_type,
                        "asset_id": run.asset_id,
                        "target_ip": run.target_ip,
                    },
                    "error": str(exc),
                },
                default=str,
            )
            run.completed_at = datetime.utcnow()
            run.updated_at = datetime.utcnow()
            db.commit()

    finally:
        db.close()


@router.post("/internal-attack-surface/run")
async def client_run_internal_attack_surface(
    payload: ClientInternalAttackSurfaceRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Queue a real Masscan run against one verified internal asset."""

    resolved = _get_client_internal_attack_surface_asset(
        db=db,
        current_user=current_user,
        asset_type=payload.asset_type,
        asset_id=payload.asset_id,
    )

    job_id = (
        f"client-internal-surface-"
        f"{current_user.id}-"
        f"{resolved['asset_type'].lower()}-"
        f"{resolved['asset_id']}-"
        f"{int(datetime.utcnow().timestamp() * 1000)}"
    )

    run = InternalAttackSurfaceRun(
        job_id=job_id,
        user_id=current_user.id,
        asset_type=resolved["asset_type"],
        asset_id=resolved["asset_id"],
        target_ip=resolved["target_ip"],
        status="QUEUED",
        discovered_host_count=0,
        discovered_port_count=0,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    db.add(run)
    db.commit()
    db.refresh(run)

    background_tasks.add_task(
        _run_client_internal_attack_surface,
        run.id,
    )

    return {
        "queued": True,
        "run_id": run.id,
        "job_id": run.job_id,
        "asset_type": run.asset_type,
        "asset_id": run.asset_id,
        "target_ip": run.target_ip,
        "status": run.status,
    }


@router.get("/internal-attack-surface")
def client_internal_attack_surface(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted Internal Attack Surface runs."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    runs = (
        db.query(InternalAttackSurfaceRun)
        .filter(
            InternalAttackSurfaceRun.user_id.in_(scoped_users)
        )
        .order_by(
            InternalAttackSurfaceRun.updated_at.desc(),
            InternalAttackSurfaceRun.id.desc(),
        )
        .all()
    )

    attack_surface_runs = []

    for run in runs:
        result = None

        if run.result_data:
            try:
                result = json.loads(run.result_data)
            except (TypeError, ValueError):
                result = None

        attack_surface_runs.append({
            "id": run.id,
            "job_id": run.job_id,
            "asset_type": run.asset_type,
            "asset_id": run.asset_id,
            "target_ip": run.target_ip,
            "status": run.status,
            "discovered_host_count": int(
                run.discovered_host_count or 0
            ),
            "discovered_port_count": int(
                run.discovered_port_count or 0
            ),
            "started_at": (
                run.started_at.isoformat()
                if run.started_at
                else None
            ),
            "completed_at": (
                run.completed_at.isoformat()
                if run.completed_at
                else None
            ),
            "created_at": (
                run.created_at.isoformat()
                if run.created_at
                else None
            ),
            "updated_at": (
                run.updated_at.isoformat()
                if run.updated_at
                else None
            ),
            "result": result,
        })

    return {
        "scope": (
            "client"
            if current_user.client_id is not None
            else "personal"
        ),
        "run_count": len(attack_surface_runs),
        "runs": attack_surface_runs,
    }


@router.get("/dashboard")
def client_dashboard(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    from models import VAPTReportRun

    """Personal overview metrics aligned with user findings and report library."""
    total_assessments = (
        db.query(func.count(Assessment.id))
        .filter(Assessment.user_id == current_user.id)
        .scalar() or 0
    )
    total_findings = (
        db.query(func.count(SecurityFinding.id))
        .filter(SecurityFinding.user_id == current_user.id)
        .scalar() or 0
    )
    completed_reports = (
        db.query(func.count(VAPTReportRun.id))
        .filter(
            VAPTReportRun.user_id == current_user.id,
            VAPTReportRun.status == "COMPLETED",
        )
        .scalar() or 0
    )

    client = None
    if current_user.client_id is not None:
        client = db.query(Client).filter(
            Client.id == current_user.client_id
        ).first()

    client_data = {
        "id": client.id,
        "name": client.name,
        "organization": client.organization,
    } if client else None

    return {
        "message": "Personal account overview",
        "user": current_user.username,
        "username": current_user.username,
        "email": current_user.email,
        "client_id": current_user.client_id,
        "client_name": client.name if client else None,
        "organization": client.organization if client else None,
        "client": client_data,
        "role": "Client",
        "metrics_scope": "personal",
        "total_assessments": int(total_assessments),
        # Compatibility alias: this counts assessments, not tool executions.
        "total_scans": int(total_assessments),
        "total_vulnerabilities": int(total_findings),
        "total_findings": int(total_findings),
        "total_reports": int(completed_reports),
        "report_metric": "completed_vapt_report_runs",
    }


# ==================================================
# CLIENT DOMAIN DISCOVERY
# ==================================================

@router.get("/dns-security")
def get_client_dns_security(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    if current_user.client_id:
        scoped_users = (
            db.query(User.id)
            .filter(User.client_id == current_user.client_id)
            .subquery()
        )
        runs = (
            db.query(DNSSecurityRun)
            .filter(DNSSecurityRun.user_id.in_(scoped_users))
            .order_by(DNSSecurityRun.created_at.desc())
            .all()
        )
    else:
        runs = (
            db.query(DNSSecurityRun)
            .filter(DNSSecurityRun.user_id == current_user.id)
            .order_by(DNSSecurityRun.created_at.desc())
            .all()
        )

    return [
        {
            "id": run.id,
            "job_id": run.job_id,
            "user_id": run.user_id,
            "assessment_id": run.assessment_id,
            "target_domain": run.target_domain,
            "status": run.status,
            "security_score": run.security_score,
            "finding_count": run.finding_count,
            "critical_count": run.critical_count,
            "high_count": run.high_count,
            "medium_count": run.medium_count,
            "low_count": run.low_count,
            "info_count": run.info_count,
            "result_data": json.loads(run.result_data) if run.result_data else None,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            "created_at": run.created_at.isoformat() if run.created_at else None,
        }
        for run in runs
    ]


@router.get("/security-headers")
def get_client_security_headers(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    if current_user.client_id:
        user_scope = (
            db.query(User.id)
            .filter(User.client_id == current_user.client_id)
            .subquery()
        )
        runs = (
            db.query(SecurityHeadersRun)
            .filter(SecurityHeadersRun.user_id.in_(user_scope))
            .order_by(SecurityHeadersRun.created_at.desc())
            .all()
        )
    else:
        runs = (
            db.query(SecurityHeadersRun)
            .filter(SecurityHeadersRun.user_id == current_user.id)
            .order_by(SecurityHeadersRun.created_at.desc())
            .all()
        )

    return {
        "scope": "client",
        "run_count": len(runs),
        "runs": [
            {
                "id": run.id,
                "job_id": run.job_id,
                "user_id": run.user_id,
                "assessment_id": run.assessment_id,
                "target_url": run.target_url,
                "final_url": run.final_url,
                "status": run.status,
                "http_status": run.http_status,
                "header_count": run.header_count,
                "present_header_count": run.present_header_count,
                "missing_header_count": run.missing_header_count,
                "security_score": float(run.security_score) if run.security_score is not None else None,
                "result_data": json.loads(run.result_data) if run.result_data else None,
                "started_at": run.started_at,
                "completed_at": run.completed_at,
                "created_at": run.created_at,
                "updated_at": run.updated_at,
            }
            for run in runs
        ],
    }


@router.get("/ssl-tls")
def get_client_ssl_tls(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    if current_user.client_id:
        scoped_users = (
            db.query(User.id)
            .filter(User.client_id == current_user.client_id)
            .subquery()
        )
        runs = (
            db.query(SSLTLSRun)
            .filter(SSLTLSRun.user_id.in_(scoped_users))
            .order_by(SSLTLSRun.created_at.desc())
            .all()
        )
    else:
        runs = (
            db.query(SSLTLSRun)
            .filter(SSLTLSRun.user_id == current_user.id)
            .order_by(SSLTLSRun.created_at.desc())
            .all()
        )

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "run_count": len(runs),
        "runs": [
            {
                "id": run.id,
                "job_id": run.job_id,
                "user_id": run.user_id,
                "assessment_id": run.assessment_id,
                "target_host": run.target_host,
                "target_port": run.target_port,
                "status": run.status,
                "tls_protocol": run.tls_protocol,
                "cipher_name": run.cipher_name,
                "cipher_bits": run.cipher_bits,
                "certificate_subject": run.certificate_subject,
                "certificate_issuer": run.certificate_issuer,
                "certificate_serial": run.certificate_serial,
                "certificate_valid_from": (
                    run.certificate_valid_from.isoformat()
                    if run.certificate_valid_from
                    else None
                ),
                "certificate_valid_until": (
                    run.certificate_valid_until.isoformat()
                    if run.certificate_valid_until
                    else None
                ),
                "san_count": run.san_count,
                "hostname_verified": run.hostname_verified,
                "certificate_verified": run.certificate_verified,
                "days_remaining": run.days_remaining,
                "result_data": (
                    json.loads(run.result_data)
                    if run.result_data
                    else None
                ),
                "started_at": (
                    run.started_at.isoformat()
                    if run.started_at
                    else None
                ),
                "completed_at": (
                    run.completed_at.isoformat()
                    if run.completed_at
                    else None
                ),
                "created_at": (
                    run.created_at.isoformat()
                    if run.created_at
                    else None
                ),
            }
            for run in runs
        ],
    }


@router.post("/security-headers")
async def start_client_security_headers(
    request: ClientSecurityHeadersRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(1)),
):
    if current_user.client_id:
        scoped_users = (
            db.query(User.id)
            .filter(User.client_id == current_user.client_id)
            .subquery()
        )
        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.id == request.assessment_id,
                Assessment.user_id.in_(scoped_users),
            )
            .first()
        )
    else:
        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.id == request.assessment_id,
                Assessment.user_id == current_user.id,
            )
            .first()
        )

    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found.")

    target_url = str(assessment.target or "").strip()

    if not target_url:
        raise HTTPException(
            status_code=400,
            detail="Assessment does not contain a target URL.",
        )

    if target_url.lower().startswith("code://"):
        raise HTTPException(
            status_code=400,
            detail="Security Headers requires an HTTP or HTTPS target.",
        )

    parsed = urlparse(target_url)

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="Security Headers requires a valid HTTP or HTTPS target.",
        )

    job_id = (
        f"client-security-headers-"
        f"{current_user.id}-{assessment.id}-{int(datetime.utcnow().timestamp())}"
    )

    run = SecurityHeadersRun(
        job_id=job_id,
        user_id=current_user.id,
        assessment_id=assessment.id,
        target_url=target_url,
        status="QUEUED",
        header_count=0,
        present_header_count=0,
        missing_header_count=0,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    db.add(run)
    db.commit()
    db.refresh(run)

    asyncio.create_task(
        _run_client_security_headers(
            run.id,
            target_url,
        )
    )

    return {
        "message": "Security Headers scan started.",
        "run_id": run.id,
        "job_id": run.job_id,
        "assessment_id": run.assessment_id,
        "target_url": run.target_url,
    }


@router.post("/ssl-tls")
async def run_client_ssl_tls(
    request: ClientSSLTLSRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    if current_user.client_id:
        scoped_users = (
            db.query(User.id)
            .filter(User.client_id == current_user.client_id)
            .subquery()
        )
        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.id == request.assessment_id,
                Assessment.user_id.in_(scoped_users),
            )
            .first()
        )
    else:
        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.id == request.assessment_id,
                Assessment.user_id == current_user.id,
            )
            .first()
        )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found or access denied.",
        )

    target_url = (assessment.target or "").strip()
    if not target_url:
        raise HTTPException(
            status_code=400,
            detail="Assessment has no target URL.",
        )

    if target_url.startswith("code://"):
        raise HTTPException(
            status_code=400,
            detail="SSL/TLS requires a web assessment with a resolvable hostname.",
        )

    parsed = urlparse(target_url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="SSL/TLS requires an HTTP or HTTPS assessment target.",
        )

    target_host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not target_host:
        raise HTTPException(
            status_code=400,
            detail="Unable to determine target hostname.",
        )

    import ipaddress
    try:
        ipaddress.ip_address(target_host)
        raise HTTPException(
            status_code=400,
            detail="SSL/TLS hostname verification requires a domain name, not an IP address.",
        )
    except ValueError:
        pass

    target_port = 443

    job_id = (
        f"client-ssl-tls-{current_user.id}-"
        f"{assessment.id}-{int(datetime.utcnow().timestamp() * 1000)}"
    )

    run = SSLTLSRun(
        job_id=job_id,
        user_id=current_user.id,
        assessment_id=assessment.id,
        target_host=target_host,
        target_port=target_port,
        status="QUEUED",
        san_count=0,
    )

    db.add(run)
    db.commit()
    db.refresh(run)

    asyncio.create_task(
        _run_client_ssl_tls(
            run.id,
            target_host,
            target_port,
        )
    )

    return {
        "message": "SSL/TLS inspection started.",
        "run_id": run.id,
        "job_id": run.job_id,
        "assessment_id": assessment.id,
        "target_host": target_host,
        "target_port": target_port,
    }


@router.post("/dns-security")
async def run_client_dns_security(
    request: ClientDNSSecurityRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    if current_user.client_id:
        scoped_users = (
            db.query(User.id)
            .filter(User.client_id == current_user.client_id)
            .subquery()
        )
        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.id == request.assessment_id,
                Assessment.user_id.in_(scoped_users),
            )
            .first()
        )
    else:
        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.id == request.assessment_id,
                Assessment.user_id == current_user.id,
            )
            .first()
        )

    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found or access denied.")

    target_url = (assessment.target or "").strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="Assessment has no target URL.")

    if target_url.startswith("code://"):
        raise HTTPException(
            status_code=400,
            detail="DNS Security requires a web assessment with a resolvable domain.",
        )

    parsed = urlparse(target_url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="DNS Security requires an HTTP or HTTPS assessment target.",
        )

    target_domain = (parsed.hostname or "").strip().lower().rstrip(".")
    if not target_domain:
        raise HTTPException(status_code=400, detail="Unable to determine target domain.")

    import ipaddress
    try:
        ipaddress.ip_address(target_domain)
        raise HTTPException(
            status_code=400,
            detail="DNS Security requires a domain name, not an IP address.",
        )
    except ValueError:
        pass

    job_id = (
        f"client-dns-security-{current_user.id}-"
        f"{assessment.id}-{int(datetime.utcnow().timestamp() * 1000)}"
    )

    run = DNSSecurityRun(
        job_id=job_id,
        user_id=current_user.id,
        assessment_id=assessment.id,
        target_domain=target_domain,
        status="QUEUED",
        finding_count=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0,
    )

    db.add(run)
    db.commit()
    db.refresh(run)

    asyncio.create_task(_run_client_dns_security(run.id, target_domain))

    return {
        "message": "DNS Security scan started.",
        "run_id": run.id,
        "job_id": run.job_id,
        "assessment_id": assessment.id,
        "target_domain": target_domain,
    }


@router.get("/domain-discovery")
def get_client_domain_discovery(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return persisted domain discovery runs within the current client scope."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    runs = (
        db.query(DomainDiscoveryRun)
        .filter(DomainDiscoveryRun.user_id.in_(scoped_users))
        .order_by(DomainDiscoveryRun.created_at.desc())
        .all()
    )

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "run_count": len(runs),
        "runs": [
            {
                "id": run.id,
                "job_id": run.job_id,
                "user_id": run.user_id,
                "assessment_id": run.assessment_id,
                "target_domain": run.target_domain,
                "status": run.status,
                "discovered_domain_count": run.discovered_domain_count,
                "discovered_host_count": run.discovered_host_count,
                "discovered_ip_count": run.discovered_ip_count,
                "started_at": run.started_at,
                "completed_at": run.completed_at,
                "created_at": run.created_at,
                "updated_at": run.updated_at,
                "result": json.loads(run.result_data)
                if run.result_data
                else None,
            }
            for run in runs
        ],
    }


# ==================================================
# CLIENT DOMAIN DISCOVERY RUN
# ==================================================

class ClientDomainDiscoveryRequest(BaseModel):
    assessment_id: int


async def _run_client_domain_discovery(
    run_id: int,
    target_domain: str,
):
    """Execute real DNSRecon for a client-owned domain discovery run."""
    db = SessionLocal()

    try:
        run = (
            db.query(DomainDiscoveryRun)
            .filter(DomainDiscoveryRun.id == run_id)
            .first()
        )

        if not run:
            return

        run.status = "RUNNING"
        run.started_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        db.commit()

        result = run_generic_tool(
            tool_id="dns-recon",
            tool_name="DNSRecon",
            executable="/usr/bin/dnsrecon",
            target=target_domain,
            execution_type="scanner",
            timeout_seconds=300,
        )

        parsed = _parse_dnsrecon_output(target_domain, result)

        run.result_data = json.dumps(
            {
                "tool": "DNSRecon",
                "execution": result,
                "discovery": parsed,
            },
            default=str,
        )

        run.discovered_domain_count = len(parsed["discovered_domains"])
        run.discovered_host_count = len(parsed["discovered_hosts"])
        run.discovered_ip_count = len(parsed["discovered_ips"])

        execution_status = str(result.get("status") or "").lower()
        run.status = (
            "COMPLETED"
            if execution_status == "completed"
            else "FAILED"
        )

        run.completed_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        db.commit()

    except Exception as exc:
        db.rollback()

        run = (
            db.query(DomainDiscoveryRun)
            .filter(DomainDiscoveryRun.id == run_id)
            .first()
        )

        if run:
            run.status = "FAILED"
            run.result_data = json.dumps(
                {
                    "tool": "DNSRecon",
                    "status": "failed",
                    "target_domain": target_domain,
                    "error": str(exc),
                },
                default=str,
            )
            run.completed_at = datetime.utcnow()
            run.updated_at = datetime.utcnow()
            db.commit()

    finally:
        db.close()


@router.post("/domain-discovery/run")
async def run_client_domain_discovery(
    request: ClientDomainDiscoveryRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """
    Start a real DNSRecon domain discovery run against a client-owned
    web assessment.

    The target domain is always derived from the persisted Assessment.
    Arbitrary targets cannot be supplied through this endpoint.
    """

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    assessment = (
        db.query(Assessment)
        .filter(
            Assessment.id == request.assessment_id,
            Assessment.user_id.in_(scoped_users),
        )
        .first()
    )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found in the current client scope.",
        )

    assessment_target = str(assessment.target or "").strip()

    if not assessment_target or assessment_target.lower().startswith("code://"):
        raise HTTPException(
            status_code=400,
            detail="Domain discovery requires a web assessment.",
        )

    parsed_target = urlparse(assessment_target)

    if parsed_target.scheme.lower() not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="Domain discovery requires an HTTP or HTTPS assessment target.",
        )

    target_domain = (parsed_target.hostname or "").strip().rstrip(".")

    if not target_domain:
        raise HTTPException(
            status_code=400,
            detail="Unable to derive a domain from the assessment target.",
        )

    import ipaddress

    try:
        ipaddress.ip_address(target_domain)
    except ValueError:
        pass
    else:
        raise HTTPException(
            status_code=400,
            detail="Domain discovery requires a domain target, not an IP address.",
        )

    run = DomainDiscoveryRun(
        job_id=(
            f"client-domain-discovery-{current_user.id}-"
            f"{assessment.id}-{int(datetime.utcnow().timestamp() * 1000)}"
        ),
        user_id=current_user.id,
        assessment_id=assessment.id,
        target_domain=target_domain,
        status="QUEUED",
        discovered_domain_count=0,
        discovered_host_count=0,
        discovered_ip_count=0,
        started_at=None,
        completed_at=None,
    )

    db.add(run)
    db.commit()
    db.refresh(run)

    asyncio.create_task(
        _run_client_domain_discovery(
            run.id,
            target_domain,
        )
    )

    return {
        "message": "Domain discovery started.",
        "run_id": run.id,
        "job_id": run.job_id,
        "assessment_id": assessment.id,
        "target_domain": target_domain,
        "status": run.status,
    }


# ==================================================
# CLIENT EXTERNAL ATTACK SURFACE
# ==================================================

class ClientExternalAttackSurfaceRequest(BaseModel):
    assessment_id: int


def _parse_dnsrecon_output(target_domain: str, result: dict) -> dict:
    """Parse DNSRecon output into conservative discovery metadata.

    Only values actually present in the DNSRecon output are recorded.
    Discovered names are treated as discovery results, not automatically
    authorized assets.
    """
    stdout = str(result.get("stdout") or "")
    stderr = str(result.get("stderr") or "")
    combined = f"{stdout}\n{stderr}"

    discovered_domains: set[str] = set()
    discovered_hosts: set[str] = set()
    discovered_ips: set[str] = set()

    import ipaddress
    import re

    domain_pattern = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[A-Za-z]{2,63}\b"
    )
    ipv4_pattern = re.compile(
        r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)"
        r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
    )

    for value in domain_pattern.findall(combined):
        normalized = value.rstrip(".").lower()
        if normalized == target_domain.lower() or normalized.endswith(
            "." + target_domain.lower().lstrip("www.")
        ):
            discovered_domains.add(normalized)
            discovered_hosts.add(normalized)

    for value in ipv4_pattern.findall(combined):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        discovered_ips.add(value)

    # Always retain the authorized assessment domain as the root discovery
    # context, even when DNSRecon returns no additional records.
    root_domain = target_domain.rstrip(".").lower()
    discovered_domains.add(root_domain)
    discovered_hosts.add(root_domain)

    return {
        "target_domain": root_domain,
        "discovered_domains": sorted(discovered_domains),
        "discovered_hosts": sorted(discovered_hosts),
        "discovered_ips": sorted(discovered_ips),
    }


async def _run_client_external_attack_surface(
    run_id: int,
    target_domain: str,
):
    """Execute DNSRecon for a client-owned assessment and persist the result."""

    db = SessionLocal()

    try:
        run = (
            db.query(ExternalAttackSurfaceRun)
            .filter(ExternalAttackSurfaceRun.id == run_id)
            .first()
        )

        if not run:
            return

        run.status = "RUNNING"
        run.started_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        db.commit()

        result = run_generic_tool(
            tool_id="dns-recon",
            tool_name="DNSRecon",
            executable="/usr/bin/dnsrecon",
            target=target_domain,
            execution_type="scanner",
            timeout_seconds=300,
        )

        parsed = _parse_dnsrecon_output(target_domain, result)

        run.result_data = json.dumps(
            {
                "tool": "DNSRecon",
                "execution": result,
                "discovery": parsed,
            },
            default=str,
        )

        run.discovered_domain_count = len(parsed["discovered_domains"])
        run.discovered_host_count = len(parsed["discovered_hosts"])
        run.discovered_ip_count = len(parsed["discovered_ips"])
        run.discovered_port_count = 0

        execution_status = str(result.get("status") or "").lower()
        if execution_status == "completed":
            run.status = "COMPLETED"
        else:
            run.status = "FAILED"

        run.completed_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        db.commit()

    except Exception as exc:
        db.rollback()

        run = (
            db.query(ExternalAttackSurfaceRun)
            .filter(ExternalAttackSurfaceRun.id == run_id)
            .first()
        )

        if run:
            run.status = "FAILED"
            run.result_data = json.dumps(
                {
                    "tool": "DNSRecon",
                    "status": "failed",
                    "target_domain": target_domain,
                    "error": str(exc),
                },
                default=str,
            )
            run.completed_at = datetime.utcnow()
            run.updated_at = datetime.utcnow()
            db.commit()

    finally:
        db.close()


@router.post("/external-attack-surface/run")
async def run_client_external_attack_surface(
    request: ClientExternalAttackSurfaceRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """
    Start a real DNSRecon discovery run against a client-owned web assessment.

    The target domain is always derived from the persisted Assessment.
    Arbitrary targets cannot be supplied through this endpoint.
    """

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    assessment = (
        db.query(Assessment)
        .filter(
            Assessment.id == request.assessment_id,
            Assessment.user_id.in_(scoped_users),
        )
        .first()
    )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found in the current client scope.",
        )

    assessment_target = str(assessment.target or "").strip()

    if not assessment_target or assessment_target.lower().startswith("code://"):
        raise HTTPException(
            status_code=400,
            detail="External attack surface discovery requires a web assessment.",
        )

    parsed_target = urlparse(assessment_target)

    if parsed_target.scheme.lower() not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="External attack surface discovery requires an HTTP or HTTPS assessment target.",
        )

    target_domain = (parsed_target.hostname or "").strip().rstrip(".")

    if not target_domain:
        raise HTTPException(
            status_code=400,
            detail="Unable to derive a domain from the assessment target.",
        )

    import ipaddress

    try:
        ipaddress.ip_address(target_domain)
    except ValueError:
        pass
    else:
        raise HTTPException(
            status_code=400,
            detail="External attack surface discovery requires a domain target, not an IP address.",
        )

    run = ExternalAttackSurfaceRun(
        job_id=(
            f"client-external-surface-{current_user.id}-"
            f"{assessment.id}-{int(datetime.utcnow().timestamp() * 1000)}"
        ),
        user_id=current_user.id,
        assessment_id=assessment.id,
        target_domain=target_domain,
        status="QUEUED",
        discovered_domain_count=0,
        discovered_host_count=0,
        discovered_ip_count=0,
        discovered_port_count=0,
        started_at=None,
        completed_at=None,
    )

    db.add(run)
    db.commit()
    db.refresh(run)

    asyncio.create_task(
        _run_client_external_attack_surface(
            run.id,
            target_domain,
        )
    )

    return {
        "message": "External attack surface discovery started.",
        "run_id": run.id,
        "job_id": run.job_id,
        "assessment_id": assessment.id,
        "target_domain": target_domain,
        "status": run.status,
    }


# ==================================================
# CLIENT SUBDOMAIN DISCOVERY
# ==================================================

class ClientSubdomainDiscoveryRequest(BaseModel):
    assessment_id: int


def _parse_subdomain_discovery_output(target_domain: str, result: dict) -> dict:
    from subdomain_workflow import parse_discovery
    return parse_discovery(target_domain, result)


async def _run_client_subdomain_discovery(run_id: int, target_domain: str):
    from subdomain_workflow import execute_run
    await asyncio.to_thread(execute_run, SessionLocal, run_generic_tool, run_id, target_domain)


@router.get("/subdomain-discovery")
async def get_client_subdomain_discovery(
    q: str = Query(default='', max_length=200),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    from subdomain_workflow import list_runs
    return list_runs(db, current_user, q=q, limit=limit, offset=offset)


@router.post("/subdomain-discovery/run")
async def run_client_subdomain_discovery(
    request: ClientSubdomainDiscoveryRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """
    Start real DNSRecon brute-force subdomain discovery.

    The domain is always derived from a client-owned persisted Assessment.
    Arbitrary domains cannot be supplied through this endpoint.
    """

    from vapt import require_user_tool_permission
    from subdomain_workflow import new_run
    require_user_tool_permission(db, current_user, 'Subdomain Discovery')
    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    assessment = (
        db.query(Assessment)
        .filter(
            Assessment.id == request.assessment_id,
            Assessment.user_id.in_(scoped_users),
        )
        .first()
    )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found in the current client scope.",
        )

    assessment_target = str(assessment.target or "").strip()

    if not assessment_target or assessment_target.lower().startswith(
        "code://"
    ):
        raise HTTPException(
            status_code=400,
            detail="Subdomain discovery requires a web assessment.",
        )

    parsed_target = urlparse(assessment_target)

    if parsed_target.scheme.lower() not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail=(
                "Subdomain discovery requires an HTTP or HTTPS "
                "assessment target."
            ),
        )

    target_domain = (
        parsed_target.hostname or ""
    ).strip().rstrip(".").lower()

    # Subdomain discovery operates against the registrable assessment
    # domain rather than a specific www host.
    if target_domain.startswith("www."):
        target_domain = target_domain[4:]

    if not target_domain:
        raise HTTPException(
            status_code=400,
            detail="Unable to derive a domain from the assessment target.",
        )

    import ipaddress

    try:
        ipaddress.ip_address(target_domain)
    except ValueError:
        pass
    else:
        raise HTTPException(
            status_code=400,
            detail=(
                "Subdomain discovery requires a domain target, "
                "not an IP address."
            ),
        )

    run = new_run(db, current_user, assessment, target_domain)

    db.add(run)
    db.commit()
    db.refresh(run)

    asyncio.create_task(
        _run_client_subdomain_discovery(
            run.id,
            target_domain,
        )
    )

    return {
        "message": "Subdomain discovery started.",
        "run_id": run.id,
        "job_id": run.job_id,
        "assessment_id": assessment.id,
        "target_domain": target_domain,
        "status": run.status,
    }


# ==================================================
# CLIENT ASSET DISCOVERY
# ==================================================

class ClientAssetDiscoveryRequest(BaseModel):
    assessment_id: int
    scan_type: str = "comprehensive"


async def _run_client_asset_discovery(
    run_id: int,
    target: str,
    scan_type: str,
):
    """Execute Nmap for a client-owned assessment and persist the final result."""

    db = SessionLocal()

    try:
        run = (
            db.query(AssetDiscoveryRun)
            .filter(AssetDiscoveryRun.id == run_id)
            .first()
        )

        if not run:
            return

        run.status = "RUNNING"
        run.started_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        db.commit()

        result = await _execute_nmap_command(
            target=target,
            scan_type=scan_type,
        )

        results_data = result.get("results") or {}
        hosts = results_data.get("hosts") or []
        open_ports = result.get("open_ports") or []

        run.result_data = json.dumps(result, default=str)
        run.host_count = len(hosts)
        run.open_port_count = len(open_ports)
        run.status = str(
            result.get("status") or "completed"
        ).upper()

        # Materialize only real hosts returned by this completed Nmap run.
        # Ownership is inherited from the persisted AssetDiscoveryRun.
        if run.status == "COMPLETED":
            for host in hosts:
                addresses = host.get("addresses") or []
                hostnames = host.get("hostnames") or []
                ports = host.get("ports") or []
                os_matches = host.get("os_matches") or []

                ip_address = next(
                    (
                        str(address.get("address"))
                        for address in addresses
                        if address.get("type") == "ipv4" and address.get("address")
                    ),
                    None,
                )

                hostname = next(
                    (str(value) for value in hostnames if value),
                    None,
                )

                os_name = next(
                    (
                        str(match.get("name"))
                        for match in os_matches
                        if match.get("name")
                    ),
                    None,
                )

                existing_asset = (
                    db.query(ServerAsset)
                    .filter(
                        ServerAsset.discovery_run_id == run.id,
                        ServerAsset.user_id == run.user_id,
                        ServerAsset.assessment_id == run.assessment_id,
                    )
                    .filter(
                        ServerAsset.ip_address == ip_address
                        if ip_address
                        else ServerAsset.hostname == hostname
                    )
                    .first()
                )

                services_data = json.dumps(
                    {
                        "ports": ports,
                        "scripts": host.get("scripts") or [],
                    },
                    default=str,
                )

                if existing_asset:
                    asset = existing_asset
                else:
                    asset = ServerAsset(
                        user_id=run.user_id,
                        assessment_id=run.assessment_id,
                        discovery_run_id=run.id,
                        target=run.target,
                        created_at=datetime.utcnow(),
                    )
                    db.add(asset)

                asset.hostname = hostname
                asset.ip_address = ip_address
                asset.target = run.target
                asset.host_status = str(host.get("status") or "unknown")
                asset.os_name = os_name
                asset.open_port_count = len(ports)
                asset.services_data = services_data
                asset.last_seen = datetime.utcnow()
                asset.updated_at = datetime.utcnow()

        run.completed_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()

        db.commit()

    except Exception as exc:
        db.rollback()

        run = (
            db.query(AssetDiscoveryRun)
            .filter(AssetDiscoveryRun.id == run_id)
            .first()
        )

        if run:
            run.status = "FAILED"
            run.result_data = json.dumps({
                "tool": "Nmap",
                "available": True,
                "status": "failed",
                "target": target,
                "scan_type": scan_type,
                "error": str(exc),
            })
            run.completed_at = datetime.utcnow()
            run.updated_at = datetime.utcnow()
            db.commit()

    finally:
        db.close()


@router.post("/asset-discovery/run")
async def run_client_asset_discovery(
    request: ClientAssetDiscoveryRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """
    Start a real Nmap asset-discovery run against a client-owned assessment.

    The target is always taken from the persisted Assessment record.
    Arbitrary targets cannot be supplied through this endpoint.
    """

    allowed_scan_types = {
        "comprehensive",
        "quick",
        "service",
        "detailed",
        "api",
    }

    if request.scan_type not in allowed_scan_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid Nmap scan type.",
        )

    # Preserve the same tenant/client ownership boundary used by
    # the existing client portal endpoints.
    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    assessment = (
        db.query(Assessment)
        .filter(
            Assessment.id == request.assessment_id,
            Assessment.user_id.in_(scoped_users),
        )
        .first()
    )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found in the current client scope.",
        )

    # Assessment targets may be stored as HTTP/HTTPS URLs because they
    # originate from web VAPT assessments. Nmap requires a hostname/IP,
    # so normalize only for the discovery execution target.
    discovery_target = assessment.target.strip()
    parsed_target = urlparse(discovery_target)

    if parsed_target.scheme.lower() in {"http", "https"}:
        discovery_target = parsed_target.hostname or ""

    target = validate_nmap_target(discovery_target)

    run = AssetDiscoveryRun(
        job_id=f"client-discovery-{current_user.id}-{assessment.id}-{int(datetime.utcnow().timestamp() * 1000)}",
        user_id=current_user.id,
        assessment_id=assessment.id,
        target=target,
        scan_type=request.scan_type,
        status="QUEUED",
        host_count=0,
        open_port_count=0,
        started_at=None,
        completed_at=None,
    )

    db.add(run)
    db.commit()
    db.refresh(run)

    asyncio.create_task(
        _run_client_asset_discovery(
            run.id,
            target,
            request.scan_type,
        )
    )

    return {
        "message": "Asset discovery started.",
        "run_id": run.id,
        "job_id": run.job_id,
        "assessment_id": assessment.id,
        "target": target,
        "scan_type": request.scan_type,
        "status": "QUEUED",
    }


# ============================================================
# USER ASSET GROUPS
# ============================================================


class ClientAssetGroupCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)


class ClientAssetGroupMemberRequest(BaseModel):
    asset_type: str = Field(..., min_length=1, max_length=50)
    asset_id: int = Field(..., gt=0)


def _client_scoped_user_query(db: Session, current_user: User):
    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    return scoped_users


def _asset_group_asset(
    db: Session,
    current_user: User,
    asset_type: str,
    asset_id: int,
):
    """Resolve one real persisted asset inside the caller's ownership scope."""

    normalized_type = asset_type.strip().upper()
    scoped_users = _client_scoped_user_query(db, current_user)

    model_map = {
        "ASSESSMENT": Assessment,
        "SERVER": ServerAsset,
        "ENDPOINT": EndpointAsset,
        "NETWORK_DEVICE": NetworkDeviceAsset,
        "DATABASE": DatabaseAsset,
    }

    model = model_map.get(normalized_type)

    if model is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported asset_type. Supported types: "
                "ASSESSMENT, SERVER, ENDPOINT, NETWORK_DEVICE, DATABASE."
            ),
        )

    asset = (
        db.query(model)
        .filter(
            model.id == asset_id,
            model.user_id.in_(scoped_users),
        )
        .first()
    )

    if asset is None:
        raise HTTPException(
            status_code=404,
            detail="Asset not found in the current ownership scope.",
        )

    return normalized_type, asset


def _asset_group_member_details(
    db: Session,
    current_user: User,
    member: AssetGroupMember,
):
    """Return current real asset details for one group membership."""

    asset_type, asset = _asset_group_asset(
        db,
        current_user,
        member.asset_type,
        member.asset_id,
    )

    if asset_type == "ASSESSMENT":
        return {
            "member_id": member.id,
            "asset_type": asset_type,
            "asset_id": asset.id,
            "label": asset.target,
            "target": asset.target,
            "status": asset.overall_status,
            "vapt_status": asset.vapt_status,
            "finding_count": int(asset.vapt_findings_count or 0),
        }

    if asset_type == "SERVER":
        return {
            "member_id": member.id,
            "asset_type": asset_type,
            "asset_id": asset.id,
            "label": asset.hostname or asset.target or f"Server #{asset.id}",
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "status": asset.host_status,
            "os_name": asset.os_name,
            "open_port_count": int(asset.open_port_count or 0),
            "last_seen": (
                asset.last_seen.isoformat()
                if asset.last_seen
                else None
            ),
        }

    if asset_type == "ENDPOINT":
        return {
            "member_id": member.id,
            "asset_type": asset_type,
            "asset_id": asset.id,
            "label": (
                asset.hostname
                or asset.endpoint_id
                or f"Endpoint #{asset.id}"
            ),
            "endpoint_id": asset.endpoint_id,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "status": asset.status,
            "os_name": asset.os_name,
            "os_version": asset.os_version,
            "device_type": asset.device_type,
            "last_seen": (
                asset.last_seen.isoformat()
                if asset.last_seen
                else None
            ),
        }

    if asset_type == "NETWORK_DEVICE":
        return {
            "member_id": member.id,
            "asset_type": asset_type,
            "asset_id": asset.id,
            "label": (
                asset.hostname
                or asset.device_id
                or f"Network Device #{asset.id}"
            ),
            "device_id": asset.device_id,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "status": asset.status,
            "device_type": asset.device_type,
            "vendor": asset.vendor,
            "model": asset.model,
            "os_name": asset.os_name,
            "os_version": asset.os_version,
            "last_seen": (
                asset.last_seen.isoformat()
                if asset.last_seen
                else None
            ),
        }

    if asset_type == "DATABASE":
        return {
            "member_id": member.id,
            "asset_type": asset_type,
            "asset_id": asset.id,
            "label": (
                asset.name
                or asset.database_id
                or f"Database #{asset.id}"
            ),
            "database_id": asset.database_id,
            "name": asset.name,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "port": asset.port,
            "database_type": asset.database_type,
            "version": asset.version,
            "environment": asset.environment,
            "status": asset.status,
            "last_seen": (
                asset.last_seen.isoformat()
                if asset.last_seen
                else None
            ),
        }

    raise HTTPException(
        status_code=500,
        detail="Unable to resolve asset group member.",
    )


@router.get("/asset-groups")
def client_asset_groups(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return ownership-scoped user asset groups and verified members."""

    from models import AssetGroup, AssetGroupMember

    scoped_users = _client_scoped_user_query(db, current_user)

    groups = (
        db.query(AssetGroup)
        .filter(AssetGroup.user_id.in_(scoped_users))
        .order_by(
            AssetGroup.updated_at.desc(),
            AssetGroup.id.desc(),
        )
        .all()
    )

    group_rows = []

    for group in groups:
        members = (
            db.query(AssetGroupMember)
            .filter(
                AssetGroupMember.group_id == group.id,
                AssetGroupMember.user_id.in_(scoped_users),
            )
            .order_by(AssetGroupMember.id.asc())
            .all()
        )

        member_rows = []

        for member in members:
            try:
                member_rows.append(
                    _asset_group_member_details(
                        db,
                        current_user,
                        member,
                    )
                )
            except HTTPException:
                # Do not expose stale/cross-scope membership records.
                continue

        group_rows.append({
            "id": group.id,
            "user_id": group.user_id,
            "name": group.name,
            "description": group.description,
            "status": group.status,
            "member_count": len(member_rows),
            "members": member_rows,
            "created_at": (
                group.created_at.isoformat()
                if group.created_at
                else None
            ),
            "updated_at": (
                group.updated_at.isoformat()
                if group.updated_at
                else None
            ),
        })

    return {
        "scope": (
            "client"
            if current_user.client_id is not None
            else "personal"
        ),
        "group_count": len(group_rows),
        "groups": group_rows,
    }


@router.post("/asset-groups")
def create_client_asset_group(
    payload: ClientAssetGroupCreateRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Create an empty ownership-scoped asset group."""

    from models import AssetGroup

    scoped_users = _client_scoped_user_query(db, current_user)
    scoped_user_ids = {
        row[0]
        for row in scoped_users.all()
    }

    owner_id = current_user.id

    if owner_id not in scoped_user_ids:
        raise HTTPException(
            status_code=403,
            detail="User is outside the current ownership scope.",
        )

    name = payload.name.strip()

    if not name:
        raise HTTPException(
            status_code=400,
            detail="Group name cannot be empty.",
        )

    duplicate = (
        db.query(AssetGroup)
        .filter(
            AssetGroup.user_id == owner_id,
            func.lower(AssetGroup.name) == name.lower(),
        )
        .first()
    )

    if duplicate is not None:
        raise HTTPException(
            status_code=409,
            detail="An asset group with this name already exists.",
        )

    group = AssetGroup(
        user_id=owner_id,
        name=name,
        description=payload.description,
        status="ACTIVE",
    )

    db.add(group)
    db.commit()
    db.refresh(group)

    return {
        "created": True,
        "group": {
            "id": group.id,
            "user_id": group.user_id,
            "name": group.name,
            "description": group.description,
            "status": group.status,
            "member_count": 0,
            "members": [],
            "created_at": (
                group.created_at.isoformat()
                if group.created_at
                else None
            ),
            "updated_at": (
                group.updated_at.isoformat()
                if group.updated_at
                else None
            ),
        },
    }


@router.post("/asset-groups/{group_id}/members")
def add_client_asset_group_member(
    group_id: int,
    payload: ClientAssetGroupMemberRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Add one verified real asset to an ownership-scoped group."""

    from models import AssetGroup, AssetGroupMember

    scoped_users = _client_scoped_user_query(db, current_user)

    group = (
        db.query(AssetGroup)
        .filter(
            AssetGroup.id == group_id,
            AssetGroup.user_id.in_(scoped_users),
        )
        .first()
    )

    if group is None:
        raise HTTPException(
            status_code=404,
            detail="Asset group not found in the current ownership scope.",
        )

    asset_type, asset = _asset_group_asset(
        db,
        current_user,
        payload.asset_type,
        payload.asset_id,
    )

    existing = (
        db.query(AssetGroupMember)
        .filter(
            AssetGroupMember.group_id == group.id,
            AssetGroupMember.asset_type == asset_type,
            AssetGroupMember.asset_id == asset.id,
        )
        .first()
    )

    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="This asset is already a member of the group.",
        )

    member = AssetGroupMember(
        group_id=group.id,
        user_id=current_user.id,
        asset_type=asset_type,
        asset_id=asset.id,
    )

    db.add(member)
    db.commit()
    db.refresh(member)

    return {
        "added": True,
        "group_id": group.id,
        "member": _asset_group_member_details(
            db,
            current_user,
            member,
        ),
    }


@router.delete("/asset-groups/{group_id}/members/{member_id}")
def remove_client_asset_group_member(
    group_id: int,
    member_id: int,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Remove one membership from an ownership-scoped group."""

    from models import AssetGroup, AssetGroupMember

    scoped_users = _client_scoped_user_query(db, current_user)

    group = (
        db.query(AssetGroup)
        .filter(
            AssetGroup.id == group_id,
            AssetGroup.user_id.in_(scoped_users),
        )
        .first()
    )

    if group is None:
        raise HTTPException(
            status_code=404,
            detail="Asset group not found in the current ownership scope.",
        )

    member = (
        db.query(AssetGroupMember)
        .filter(
            AssetGroupMember.id == member_id,
            AssetGroupMember.group_id == group.id,
            AssetGroupMember.user_id.in_(scoped_users),
        )
        .first()
    )

    if member is None:
        raise HTTPException(
            status_code=404,
            detail="Asset group member not found.",
        )

    db.delete(member)
    db.commit()

    return {
        "removed": True,
        "group_id": group.id,
        "member_id": member_id,
    }


@router.delete("/asset-groups/{group_id}")
def delete_client_asset_group(
    group_id: int,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Delete an ownership-scoped asset group and its memberships."""

    from models import AssetGroup

    scoped_users = _client_scoped_user_query(db, current_user)

    group = (
        db.query(AssetGroup)
        .filter(
            AssetGroup.id == group_id,
            AssetGroup.user_id.in_(scoped_users),
        )
        .first()
    )

    if group is None:
        raise HTTPException(
            status_code=404,
            detail="Asset group not found in the current ownership scope.",
        )

    db.delete(group)
    db.commit()

    return {
        "deleted": True,
        "group_id": group_id,
    }

# ============================================================
# IP INTELLIGENCE
# Separate enrichment layer for the existing IP inventory.
# Does not modify /client/ip-addresses.
# ============================================================

from ip_intelligence import enrich_ip_address
from models import IPIntelligence


@router.get("/ip-intelligence")
def client_ip_intelligence(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return ownership-scoped IP intelligence with real enrichment data."""

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    scoped_user_ids = [row[0] for row in scoped_users.all()]

    if not scoped_user_ids:
        return {
            "scope": "client" if current_user.client_id is not None else "personal",
            "ip_count": 0,
            "ips": [],
        }

    # Reuse the existing ownership-scoped IP inventory route logic
    # without changing that route's implementation.
    import ipaddress

    discovered_ips = set()

    def add_ip(value):
        if not value:
            return

        raw = str(value).strip()
        if not raw:
            return

        try:
            discovered_ips.add(str(ipaddress.ip_address(raw)))
        except ValueError:
            return

    assessments = (
        db.query(Assessment)
        .filter(
            Assessment.user_id.in_(scoped_user_ids),
            ~Assessment.target.startswith("code://"),
        )
        .all()
    )

    for assessment in assessments:
        parsed = urlparse(assessment.target)
        add_ip(parsed.hostname)
        add_ip(assessment.target)

    servers = (
        db.query(ServerAsset)
        .filter(ServerAsset.user_id.in_(scoped_user_ids))
        .all()
    )

    for asset in servers:
        add_ip(asset.ip_address)

    endpoints = (
        db.query(EndpointAsset)
        .filter(EndpointAsset.user_id.in_(scoped_user_ids))
        .all()
    )

    for asset in endpoints:
        add_ip(asset.ip_address)

    network_devices = (
        db.query(NetworkDeviceAsset)
        .filter(NetworkDeviceAsset.user_id.in_(scoped_user_ids))
        .all()
    )

    for asset in network_devices:
        add_ip(asset.ip_address)

    databases = (
        db.query(DatabaseAsset)
        .filter(DatabaseAsset.user_id.in_(scoped_user_ids))
        .all()
    )

    for asset in databases:
        add_ip(asset.ip_address)

    results = []

    for ip_address in sorted(discovered_ips):
        record = (
            db.query(IPIntelligence)
            .filter(
                IPIntelligence.user_id == current_user.id,
                IPIntelligence.ip_address == ip_address,
            )
            .first()
        )

        # Perform enrichment when no record exists.
        if record is None:
            enriched = enrich_ip_address(ip_address)

            record = IPIntelligence(
                user_id=current_user.id,
                ip_address=ip_address,
                address_type=enriched.get("address_type", "UNKNOWN"),
                ptr_hostname=enriched.get("ptr_hostname"),
                asn=enriched.get("asn"),
                organization=enriched.get("organization"),
                isp=enriched.get("isp"),
                country=enriched.get("country"),
                region=enriched.get("region"),
                city=enriched.get("city"),
                latitude=enriched.get("latitude"),
                longitude=enriched.get("longitude"),
                lookup_status=enriched.get("lookup_status", "FAILED"),
                provider=enriched.get("provider"),
                result_data=json.dumps(
                    enriched.get("result_data", enriched),
                    default=str,
                ),
                first_lookup_at=datetime.utcnow(),
                last_lookup_at=datetime.utcnow(),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )

            db.add(record)
            db.commit()
            db.refresh(record)

        results.append(
            {
                "id": record.id,
                "ip_address": record.ip_address,
                "address_type": record.address_type,
                "ptr_hostname": record.ptr_hostname,
                "asn": record.asn,
                "organization": record.organization,
                "isp": record.isp,
                "country": record.country,
                "region": record.region,
                "city": record.city,
                "latitude": record.latitude,
                "longitude": record.longitude,
                "lookup_status": record.lookup_status,
                "provider": record.provider,
                "first_lookup_at": (
                    record.first_lookup_at.isoformat()
                    if record.first_lookup_at
                    else None
                ),
                "last_lookup_at": (
                    record.last_lookup_at.isoformat()
                    if record.last_lookup_at
                    else None
                ),
            }
        )

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "ip_count": len(results),
        "ips": results,
    }


# ============================================================
# CLIENT - REMEDIATION
# ============================================================

@router.get("/remediation")
def client_remediation(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped persisted remediation issues."""

    from report_issues import serialize_issue

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    issues = (
        db.query(ReportIssue)
        .join(
            Assessment,
            ReportIssue.assessment_id == Assessment.id,
        )
        .filter(
            Assessment.user_id.in_(scoped_users),
        )
        .order_by(ReportIssue.created_at.desc())
        .all()
    )

    return {
        "scope": (
            "client"
            if current_user.client_id is not None
            else "personal"
        ),
        "total": len(issues),
        "issues": [
            serialize_issue(issue)
            for issue in issues
        ],
    }

# ============================================================
# CLIENT - REMEDIATION UPDATE
# ============================================================

class ClientRemediationUpdateRequest(BaseModel):
    status: str
    resolution: str | None = None


@router.put("/remediation/{issue_id}")
def client_update_remediation(
    issue_id: str,
    payload: ClientRemediationUpdateRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Update a tenant-scoped remediation issue from the client portal."""

    from report_issues import (
        ALLOWED_STATUSES,
        normalize,
        raise_support_ticket_for_issue,
        serialize_issue,
    )

    requested_status = normalize(payload.status)

    allowed_client_statuses = {
        "OPEN",
        "IN_PROGRESS",
        "RESOLVED",
        "NOT_RESOLVED",
    }

    if requested_status not in allowed_client_statuses:
        raise HTTPException(
            status_code=400,
            detail=(
                "Client remediation status must be one of: "
                "OPEN, IN_PROGRESS, RESOLVED, NOT_RESOLVED."
            ),
        )

    scoped_users = db.query(User.id)

    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
    else:
        scoped_users = scoped_users.filter(
            User.id == current_user.id
        )

    issue = (
        db.query(ReportIssue)
        .join(
            Assessment,
            ReportIssue.assessment_id == Assessment.id,
        )
        .filter(
            ReportIssue.issue_id == issue_id,
            Assessment.user_id.in_(scoped_users),
        )
        .first()
    )

    if not issue:
        raise HTTPException(
            status_code=404,
            detail="Remediation issue not found.",
        )

    resolution = (
        payload.resolution.strip()
        if payload.resolution is not None
        else None
    )

    if requested_status == "RESOLVED":
        if not resolution:
            raise HTTPException(
                status_code=400,
                detail="Resolution details are required when resolving an issue.",
            )

        issue.status = "RESOLVED"
        issue.resolution = resolution
        issue.resolved_at = datetime.utcnow()

    elif requested_status == "NOT_RESOLVED":
        issue.resolution = resolution
        issue.resolved_at = None
        raise_support_ticket_for_issue(db, issue)

    else:
        issue.status = requested_status
        issue.resolution = resolution
        issue.resolved_at = None

    db.commit()
    db.refresh(issue)

    return {
        "success": True,
        "message": "Remediation issue updated successfully.",
        "issue": serialize_issue(issue),
    }

