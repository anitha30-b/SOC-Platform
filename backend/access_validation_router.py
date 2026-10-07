from __future__ import annotations

import asyncio
import time
import uuid

import requests
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import (
    Assessment,
    PostExploitationValidation,
    SecurityFinding,
    User,
)
from rbac import require_role
from vapt import require_user_tool_permission


router = APIRouter(
    prefix="/vapt/access-validation",
    tags=["Access / Impact Validation"],
)


ACCESS_VALIDATION_JOBS: dict[str, dict[str, Any]] = {}


class AccessValidationRequest(BaseModel):
    assessment_id: int = Field(..., ge=1)
    finding_id: str = Field(..., min_length=1, max_length=50)


def _now() -> float:
    return time.time()


def _serialize_validation(record: PostExploitationValidation) -> dict[str, Any]:
    return {
        "id": record.id,
        "validation_id": record.validation_id,
        "job_id": record.job_id,
        "user_id": record.user_id,
        "assessment_id": record.assessment_id,
        "finding_id": record.finding_id,
        "status": record.status,
        "validation_result": record.validation_result,
        "access_validated": record.access_validated,
        "impact_validated": record.impact_validated,
        "evidence": record.evidence,
        "impact_details": record.impact_details,
        "validation_notes": record.validation_notes,
        "started_at": (
            record.started_at.isoformat()
            if record.started_at
            else None
        ),
        "completed_at": (
            record.completed_at.isoformat()
            if record.completed_at
            else None
        ),
        "created_at": (
            record.created_at.isoformat()
            if record.created_at
            else None
        ),
        "updated_at": (
            record.updated_at.isoformat()
            if record.updated_at
            else None
        ),
    }


def _live_http_validation(
    affected_resource: str,
    finding: SecurityFinding,
) -> dict[str, Any]:
    """
    Perform a controlled, read-only live validation against an HTTP/HTTPS
    affected resource. No exploit payloads or state-changing methods are used.
    """
    if not affected_resource:
        return {
            "supported": False,
            "validated": False,
            "reason": "No affected HTTP resource is recorded.",
        }

    resource = affected_resource.strip()

    if not resource.lower().startswith(("http://", "https://")):
        return {
            "supported": False,
            "validated": False,
            "reason": "Affected resource is not an HTTP/HTTPS URL.",
        }

    try:
        response = requests.get(
            resource,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "SOC-Platform-Validation/1.0",
                "Accept": "*/*",
            },
        )

        live_headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        evidence = (finding.evidence or "").strip()
        evidence_match = None

        if evidence:
            evidence_lower = evidence.lower()

            if ":" in evidence:
                header_name, expected_value = evidence.split(":", 1)
                header_name = header_name.strip().lower()
                expected_value = expected_value.strip().lower()

                actual_value = live_headers.get(header_name)

                if actual_value is not None:
                    evidence_match = expected_value in actual_value.lower()
                else:
                    evidence_match = False
            else:
                evidence_match = evidence_lower in response.text[:200000].lower()

        return {
            "supported": True,
            "validated": evidence_match is True,
            "status_code": response.status_code,
            "final_url": response.url,
            "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2),
            "content_type": response.headers.get("Content-Type"),
            "server": response.headers.get("Server"),
            "evidence_match": evidence_match,
            "matched_header": (
                evidence.split(":", 1)[0].strip()
                if evidence and ":" in evidence and evidence_match
                else None
            ),
        }

    except requests.RequestException as exc:
        return {
            "supported": True,
            "validated": False,
            "error": str(exc),
        }


def _finding_snapshot(finding: SecurityFinding) -> dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "vulnerability": finding.vulnerability,
        "tool_name": finding.tool_name,
        "tool_category": finding.tool_category,
        "severity": finding.severity,
        "risk_level": finding.risk_level,
        "cvss_score": finding.cvss_score,
        "affected_asset": finding.affected_asset,
        "affected_url": finding.affected_url,
        "endpoint": finding.endpoint,
        "parameter": finding.parameter,
        "evidence": finding.evidence,
        "request_data": finding.request_data,
        "response_data": finding.response_data,
        "impact": finding.impact,
        "remediation": finding.remediation,
        "status": finding.status,
        "cve_id": finding.cve_id,
        "cwe_id": finding.cwe_id,
        "owasp_category": finding.owasp_category,
    }


async def _run_validation(
    job_id: str,
    request: AccessValidationRequest,
    user_id: int,
) -> None:
    job = ACCESS_VALIDATION_JOBS[job_id]
    started = _now()

    db: Session | None = None
    record: PostExploitationValidation | None = None

    try:
        job["status"] = "running"
        job["stage"] = "Loading assessment"
        job["progress"] = 10
        job["started_at"] = started

        db = next(get_db())

        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.id == request.assessment_id,
                Assessment.user_id == user_id,
            )
            .first()
        )

        if not assessment:
            raise ValueError(
                "Assessment not found or does not belong to the current user."
            )

        if job.get("cancel_requested"):
            job["status"] = "cancelled"
            job["stage"] = "Validation cancelled"
            job["progress"] = 100
            return

        job["stage"] = "Loading security finding"
        job["progress"] = 25

        finding = (
            db.query(SecurityFinding)
            .filter(
                SecurityFinding.finding_id == request.finding_id,
                SecurityFinding.assessment_id == assessment.id,
                SecurityFinding.user_id == user_id,
            )
            .first()
        )

        if not finding:
            raise ValueError(
                "Security finding not found or does not belong to the assessment."
            )

        validation_id = f"VAL-{uuid.uuid4().hex[:12].upper()}"

        record = PostExploitationValidation(
            validation_id=validation_id,
            job_id=job_id,
            user_id=user_id,
            assessment_id=assessment.id,
            finding_id=finding.finding_id,
            status="RUNNING",
            started_at=datetime.utcnow(),
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        job["validation_id"] = validation_id
        job["finding"] = _finding_snapshot(finding)

        if job.get("cancel_requested"):
            record.status = "CANCELLED"
            record.completed_at = datetime.utcnow()
            record.validation_notes = "Validation cancelled by the user."
            db.commit()

            job["status"] = "cancelled"
            job["stage"] = "Validation cancelled"
            job["progress"] = 100
            job["result"] = _serialize_validation(record)
            return

        job["stage"] = "Validating affected resource"
        job["progress"] = 45
        await asyncio.sleep(0.1)

        affected_resource = (
            finding.affected_url
            or finding.endpoint
            or finding.affected_asset
        )

        resource_evidence = bool(affected_resource)

        live_result = _live_http_validation(
            affected_resource,
            finding,
        )

        job["live_validation"] = live_result

        if job.get("cancel_requested"):
            record.status = "CANCELLED"
            record.completed_at = datetime.utcnow()
            record.validation_notes = "Validation cancelled by the user."
            db.commit()

            job["status"] = "cancelled"
            job["stage"] = "Validation cancelled"
            job["progress"] = 100
            job["result"] = _serialize_validation(record)
            return

        job["stage"] = "Evaluating recorded evidence"
        job["progress"] = 60
        await asyncio.sleep(0.1)

        evidence = finding.evidence
        request_data = finding.request_data
        response_data = finding.response_data

        evidence_parts = []

        if live_result.get("supported"):
            status_code = live_result.get("status_code")
            final_url = live_result.get("final_url")
            response_time = live_result.get("response_time_ms")

            evidence_parts.append(
                f"Live HTTP validation completed with status {status_code}."
            )

            if final_url:
                evidence_parts.append(
                    f"Final URL: {final_url}"
                )

            if response_time is not None:
                evidence_parts.append(
                    f"Response time: {response_time} ms."
                )

            if live_result.get("evidence_match") is True:
                evidence_parts.append(
                    "Recorded finding evidence was matched in the live response."
                )
            elif live_result.get("evidence_match") is False:
                evidence_parts.append(
                    "Recorded finding evidence was not matched in the live response."
                )

        if live_result.get("error"):
            evidence_parts.append(
                f"Live HTTP validation error: {live_result['error']}"
            )

        if evidence:
            evidence_parts.append("Finding evidence is recorded.")

        if request_data:
            evidence_parts.append(
                "Associated request data is recorded."
            )

        if response_data:
            evidence_parts.append(
                "Associated response data is recorded."
            )

        if live_result.get("supported"):
            # For HTTP/HTTPS findings, fresh live evidence is authoritative.
            access_validated = live_result.get("evidence_match") is True
            evidence_supported = access_validated
        else:
            # Non-HTTP findings fall back to the stored finding evidence.
            evidence_supported = bool(
                evidence or request_data or response_data
            )
            access_validated = resource_evidence and evidence_supported

        job["stage"] = "Evaluating impact"
        job["progress"] = 75
        await asyncio.sleep(0.1)

        impact_supported = bool(finding.impact)

        if resource_evidence:
            evidence_parts.append(
                f"Affected resource recorded: {affected_resource}"
            )

        if finding.impact:
            impact_details = (
                "The finding contains a recorded impact description: "
                f"{finding.impact}"
            )
        else:
            impact_details = (
                "No explicit impact description is recorded for this finding."
            )

        access_validated = resource_evidence and evidence_supported
        impact_validated = impact_supported

        if access_validated and impact_validated:
            validation_result = "VALIDATED"
            notes = (
                "The finding contains an identifiable affected resource, "
                "supporting evidence, and an explicit impact description."
            )
        elif access_validated or impact_validated:
            validation_result = "PARTIALLY_VALIDATED"
            notes = (
                "Some validation evidence is present, but the available "
                "finding data does not support validation of both access "
                "and impact."
            )
        else:
            validation_result = "NOT_VALIDATED"
            notes = (
                "The finding does not contain sufficient recorded evidence "
                "to validate access and impact."
            )

        job["stage"] = "Finalizing validation"
        job["progress"] = 90

        record.status = "COMPLETED"
        record.validation_result = validation_result
        record.access_validated = access_validated
        record.impact_validated = impact_validated
        record.evidence = "\n".join(evidence_parts) or None
        record.impact_details = impact_details
        record.validation_notes = notes
        record.completed_at = datetime.utcnow()

        db.commit()
        db.refresh(record)

        job["status"] = "completed"
        job["stage"] = "Validation completed"
        job["progress"] = 100
        job["result"] = _serialize_validation(record)
        job["duration"] = round(_now() - started, 2)

    except Exception as exc:
        if db is not None:
            try:
                db.rollback()

                if record is not None:
                    record.status = "FAILED"
                    record.validation_result = "FAILED"
                    record.validation_notes = str(exc)
                    record.completed_at = datetime.utcnow()
                    db.commit()
            except Exception:
                db.rollback()

        job["status"] = "failed"
        job["stage"] = "Validation failed"
        job["progress"] = 100
        job["error"] = str(exc)
        job["duration"] = round(_now() - started, 2)

    finally:
        if db is not None:
            db.close()


@router.post("/run")
async def run_access_validation(
    request: AccessValidationRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    require_user_tool_permission(
        db,
        current_user,
        "Access / Impact Validation",
    )

    job_id = str(uuid.uuid4())

    ACCESS_VALIDATION_JOBS[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "stage": "Queued",
        "progress": 0,
        "assessment_id": request.assessment_id,
        "finding_id": request.finding_id,
        "user_id": current_user.id,
        "cancel_requested": False,
        "created_at": datetime.utcnow().isoformat(),
    }

    asyncio.create_task(
        _run_validation(
            job_id,
            request,
            current_user.id,
        )
    )

    return ACCESS_VALIDATION_JOBS[job_id]


@router.get("/{job_id}/progress")
async def access_validation_progress(
    job_id: str,
    current_user: User = Depends(require_role(1)),
):
    job = ACCESS_VALIDATION_JOBS.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Access validation job not found.",
        )

    if job["user_id"] != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to access this job.",
        )

    return job


@router.get("/{job_id}/results")
async def access_validation_results(
    job_id: str,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    job = ACCESS_VALIDATION_JOBS.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Access validation job not found.",
        )

    if job["user_id"] != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to access this job.",
        )

    validation = (
        db.query(PostExploitationValidation)
        .filter(
            PostExploitationValidation.job_id == job_id,
            PostExploitationValidation.user_id == current_user.id,
        )
        .order_by(PostExploitationValidation.created_at.desc())
        .first()
    )

    return {
        "job": job,
        "validation": (
            _serialize_validation(validation)
            if validation
            else job.get("result")
        ),
    }


@router.post("/{job_id}/cancel")
async def cancel_access_validation(
    job_id: str,
    current_user: User = Depends(require_role(1)),
):
    job = ACCESS_VALIDATION_JOBS.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Access validation job not found.",
        )

    if job["user_id"] != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to cancel this job.",
        )

    if job["status"] in {"completed", "failed", "cancelled"}:
        return {
            "status": job["status"],
            "job_id": job_id,
        }

    job["cancel_requested"] = True

    return {
        "status": "cancellation_requested",
        "job_id": job_id,
    }


@router.get("/history/{assessment_id}")
async def access_validation_history(
    assessment_id: int,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    assessment = (
        db.query(Assessment)
        .filter(
            Assessment.id == assessment_id,
            Assessment.user_id == current_user.id,
        )
        .first()
    )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found.",
        )

    validations = (
        db.query(PostExploitationValidation)
        .filter(
            PostExploitationValidation.assessment_id == assessment_id,
            PostExploitationValidation.user_id == current_user.id,
        )
        .order_by(PostExploitationValidation.created_at.desc())
        .all()
    )

    return {
        "assessment_id": assessment_id,
        "count": len(validations),
        "validations": [
            _serialize_validation(validation)
            for validation in validations
        ],
    }
