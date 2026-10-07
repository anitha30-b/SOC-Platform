from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import (
    Assessment,
    PostExploitationValidation,
    RiskAssessmentRun,
    SecurityFinding,
    User,
)
from rbac import require_role
from security_findings import calculate_risk_level, calculate_severity
from vapt import require_user_tool_permission


router = APIRouter(
    prefix="/vapt/risk-assessment",
    tags=["Risk Assessment"],
)


RISK_ASSESSMENT_JOBS: dict[str, dict[str, Any]] = {}


class RiskAssessmentRequest(BaseModel):
    assessment_id: int = Field(..., ge=1)


def _now() -> float:
    return time.time()


def _serialize_run(record: RiskAssessmentRun) -> dict[str, Any]:
    def load_json(value: str | None) -> Any:
        if not value:
            return {}
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return value

    return {
        "id": record.id,
        "assessment_run_id": record.assessment_run_id,
        "job_id": record.job_id,
        "user_id": record.user_id,
        "assessment_id": record.assessment_id,
        "status": record.status,
        "total_findings": record.total_findings,
        "average_cvss": record.average_cvss,
        "highest_cvss": record.highest_cvss,
        "overall_risk": record.overall_risk,
        "severity": load_json(record.severity_summary),
        "risk_levels": load_json(record.risk_level_summary),
        "finding_status": load_json(record.status_summary),
        "validation": load_json(record.validation_summary),
        "findings": load_json(record.findings_snapshot),
        "assessment_notes": record.assessment_notes,
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


def _finding_snapshot(
    finding: SecurityFinding,
    validation: PostExploitationValidation | None,
) -> dict[str, Any]:
    cvss = (
        float(finding.cvss_score)
        if finding.cvss_score is not None
        else None
    )

    calculated_severity = (
        calculate_severity(cvss)
        if cvss is not None
        else (finding.severity or "LOW").upper()
    )
    calculated_risk_level = calculate_risk_level(calculated_severity)

    return {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "vulnerability": finding.vulnerability,
        "tool_name": finding.tool_name,
        "tool_category": finding.tool_category,
        "cvss_score": cvss,
        "severity": finding.severity or calculated_severity,
        "calculated_severity": calculated_severity,
        "risk_level": finding.risk_level or calculated_risk_level,
        "calculated_risk_level": calculated_risk_level,
        "status": finding.status,
        "affected_asset": finding.affected_asset,
        "affected_url": finding.affected_url,
        "endpoint": finding.endpoint,
        "cve_id": finding.cve_id,
        "cwe_id": finding.cwe_id,
        "owasp_category": finding.owasp_category,
        "validation": (
            {
                "validation_id": validation.validation_id,
                "status": validation.status,
                "validation_result": validation.validation_result,
                "access_validated": validation.access_validated,
                "impact_validated": validation.impact_validated,
                "completed_at": (
                    validation.completed_at.isoformat()
                    if validation.completed_at
                    else None
                ),
            }
            if validation
            else None
        ),
    }


async def _run_risk_assessment(
    job_id: str,
    request: RiskAssessmentRequest,
    user_id: int,
) -> None:
    job = RISK_ASSESSMENT_JOBS[job_id]
    started = _now()

    db: Session | None = None
    record: RiskAssessmentRun | None = None

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
            job["stage"] = "Risk assessment cancelled"
            job["progress"] = 100
            return

        job["stage"] = "Loading security findings"
        job["progress"] = 25

        findings = (
            db.query(SecurityFinding)
            .filter(
                SecurityFinding.assessment_id == assessment.id,
                SecurityFinding.user_id == user_id,
            )
            .order_by(SecurityFinding.created_at.desc())
            .all()
        )

        job["finding_count"] = len(findings)

        validation_records = (
            db.query(PostExploitationValidation)
            .filter(
                PostExploitationValidation.assessment_id == assessment.id,
                PostExploitationValidation.user_id == user_id,
            )
            .order_by(
                PostExploitationValidation.created_at.desc()
            )
            .all()
        )

        latest_validation_by_finding: dict[str, PostExploitationValidation] = {}

        for validation in validation_records:
            if validation.finding_id not in latest_validation_by_finding:
                latest_validation_by_finding[
                    validation.finding_id
                ] = validation

        assessment_run_id = (
            f"RISK-{uuid.uuid4().hex[:12].upper()}"
        )

        record = RiskAssessmentRun(
            assessment_run_id=assessment_run_id,
            job_id=job_id,
            user_id=user_id,
            assessment_id=assessment.id,
            status="RUNNING",
            started_at=datetime.utcnow(),
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        job["assessment_run_id"] = assessment_run_id

        if job.get("cancel_requested"):
            record.status = "CANCELLED"
            record.completed_at = datetime.utcnow()
            record.assessment_notes = (
                "Risk assessment cancelled by the user."
            )
            db.commit()

            job["status"] = "cancelled"
            job["stage"] = "Risk assessment cancelled"
            job["progress"] = 100
            job["result"] = _serialize_run(record)
            return

        job["stage"] = "Calculating severity and risk levels"
        job["progress"] = 45

        severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0,
        }

        risk_levels = {
            "level_1": 0,
            "level_2": 0,
            "level_3": 0,
        }

        finding_status = {
            "open": 0,
            "in_progress": 0,
            "fixed": 0,
            "accepted": 0,
            "false_positive": 0,
        }

        cvss_values: list[float] = []
        snapshots: list[dict[str, Any]] = []

        for finding in findings:
            if job.get("cancel_requested"):
                record.status = "CANCELLED"
                record.completed_at = datetime.utcnow()
                record.assessment_notes = (
                    "Risk assessment cancelled by the user."
                )
                db.commit()

                job["status"] = "cancelled"
                job["stage"] = "Risk assessment cancelled"
                job["progress"] = 100
                job["result"] = _serialize_run(record)
                return

            cvss = (
                float(finding.cvss_score)
                if finding.cvss_score is not None
                else None
            )

            calculated_severity = (
                calculate_severity(cvss)
                if cvss is not None
                else (finding.severity or "LOW").upper()
            )
            calculated_risk = calculate_risk_level(calculated_severity)

            severity[calculated_severity.lower()] += 1

            risk_key = calculated_risk.lower()
            risk_levels[risk_key] += 1

            status_key = (finding.status or "OPEN").lower()
            if status_key in finding_status:
                finding_status[status_key] += 1

            if cvss is not None:
                cvss_values.append(cvss)

            snapshots.append(
                _finding_snapshot(
                    finding,
                    latest_validation_by_finding.get(
                        finding.finding_id
                    ),
                )
            )

        job["stage"] = "Evaluating validation coverage"
        job["progress"] = 65
        await asyncio.sleep(0.1)

        validated = 0
        partially_validated = 0
        not_validated = 0
        validation_not_run = 0

        for finding in findings:
            validation = latest_validation_by_finding.get(
                finding.finding_id
            )

            if validation is None:
                validation_not_run += 1
            elif validation.validation_result == "VALIDATED":
                validated += 1
            elif validation.validation_result == "PARTIALLY_VALIDATED":
                partially_validated += 1
            else:
                not_validated += 1

        validation_summary = {
            "total_findings": len(findings),
            "validated": validated,
            "partially_validated": partially_validated,
            "not_validated": not_validated,
            "validation_not_run": validation_not_run,
        }

        job["stage"] = "Determining overall risk"
        job["progress"] = 80
        await asyncio.sleep(0.1)

        highest_cvss = max(cvss_values) if cvss_values else 0.0
        average_cvss = (
            round(sum(cvss_values) / len(cvss_values), 2)
            if cvss_values
            else 0.0
        )

        if severity["critical"] > 0:
            overall_risk = "CRITICAL"
        elif severity["high"] > 0:
            overall_risk = "HIGH"
        elif severity["medium"] > 0:
            overall_risk = "MEDIUM"
        elif severity["low"] > 0:
            overall_risk = "LOW"
        else:
            overall_risk = "NONE"

        job["stage"] = "Finalizing risk assessment"
        job["progress"] = 90

        record.status = "COMPLETED"
        record.total_findings = len(findings)
        record.average_cvss = average_cvss
        record.highest_cvss = round(highest_cvss, 1)
        record.overall_risk = overall_risk
        record.severity_summary = json.dumps(severity)
        record.risk_level_summary = json.dumps(risk_levels)
        record.status_summary = json.dumps(finding_status)
        record.validation_summary = json.dumps(
            validation_summary
        )
        record.findings_snapshot = json.dumps(
            snapshots,
            default=str,
        )
        record.assessment_notes = (
            "Risk assessment calculated from the assessment's "
            "stored security findings using the existing CVSS "
            "severity and application risk-level classification. "
            "Stage 07 validation results are included as validation context."
        )
        record.completed_at = datetime.utcnow()

        db.commit()
        db.refresh(record)

        job["status"] = "completed"
        job["stage"] = "Risk assessment completed"
        job["progress"] = 100
        job["result"] = _serialize_run(record)
        job["duration"] = round(_now() - started, 2)

    except Exception as exc:
        if db is not None:
            try:
                db.rollback()

                if record is not None:
                    record.status = "FAILED"
                    record.assessment_notes = str(exc)
                    record.completed_at = datetime.utcnow()
                    db.commit()
            except Exception:
                db.rollback()

        job["status"] = "failed"
        job["stage"] = "Risk assessment failed"
        job["progress"] = 100
        job["error"] = str(exc)
        job["duration"] = round(_now() - started, 2)

    finally:
        if db is not None:
            db.close()


@router.post("/run")
async def run_risk_assessment(
    request: RiskAssessmentRequest,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    require_user_tool_permission(
        db,
        current_user,
        "Risk Assessment Engine",
    )

    job_id = str(uuid.uuid4())

    RISK_ASSESSMENT_JOBS[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "stage": "Queued",
        "progress": 0,
        "assessment_id": request.assessment_id,
        "user_id": current_user.id,
        "cancel_requested": False,
        "created_at": datetime.utcnow().isoformat(),
    }

    asyncio.create_task(
        _run_risk_assessment(
            job_id,
            request,
            current_user.id,
        )
    )

    return RISK_ASSESSMENT_JOBS[job_id]


@router.get("/{job_id}/progress")
async def risk_assessment_progress(
    job_id: str,
    current_user: User = Depends(require_role(1)),
):
    job = RISK_ASSESSMENT_JOBS.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Risk assessment job not found.",
        )

    if job["user_id"] != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to access this job.",
        )

    return job


@router.get("/{job_id}/results")
async def risk_assessment_results(
    job_id: str,
    current_user: User = Depends(require_role(1)),
):
    job = RISK_ASSESSMENT_JOBS.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Risk assessment job not found.",
        )

    if job["user_id"] != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to access this job.",
        )

    if job.get("status") != "completed":
        raise HTTPException(
            status_code=409,
            detail="Risk assessment has not completed.",
        )

    return job.get("result")


@router.post("/{job_id}/cancel")
async def cancel_risk_assessment(
    job_id: str,
    current_user: User = Depends(require_role(1)),
):
    job = RISK_ASSESSMENT_JOBS.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Risk assessment job not found.",
        )

    if job["user_id"] != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to cancel this job.",
        )

    if job.get("status") in {
        "completed",
        "failed",
        "cancelled",
    }:
        return job

    job["cancel_requested"] = True

    return {
        "job_id": job_id,
        "status": "cancellation_requested",
    }


@router.get("/history/{assessment_id}")
async def risk_assessment_history(
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

    records = (
        db.query(RiskAssessmentRun)
        .filter(
            RiskAssessmentRun.assessment_id == assessment_id,
            RiskAssessmentRun.user_id == current_user.id,
        )
        .order_by(
            RiskAssessmentRun.created_at.desc()
        )
        .all()
    )

    return [
        _serialize_run(record)
        for record in records
    ]
