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
    calculated_risk_level = "UNRATED" if calculated_severity == "UNRATED" else calculate_risk_level(calculated_severity)

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
            calculated_risk = "UNRATED" if calculated_severity == "UNRATED" else calculate_risk_level(calculated_severity)

            severity.setdefault(calculated_severity.lower(), 0)
            severity[calculated_severity.lower()] += 1

            risk_key = calculated_risk.lower()
            risk_levels.setdefault(risk_key, 0)
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
        elif severity.get("unrated", 0) > 0:
            overall_risk = "UNRATED"
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


@router.get("/overview")
def risk_assessment_overview(
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """Read-only, ownership-scoped summary for the SOC Risk Overview page."""

    scoped_users = db.query(User.id)
    if current_user.client_id is not None:
        scoped_users = scoped_users.filter(
            User.client_id == current_user.client_id
        )
        scope_label = "Client"
    else:
        scoped_users = scoped_users.filter(User.id == current_user.id)
        scope_label = "Personal"

    assessments = (
        db.query(Assessment)
        .filter(Assessment.user_id.in_(scoped_users))
        .all()
    )
    findings = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.user_id.in_(scoped_users))
        .all()
    )
    runs = (
        db.query(RiskAssessmentRun)
        .filter(RiskAssessmentRun.user_id.in_(scoped_users))
        .order_by(RiskAssessmentRun.created_at.desc(), RiskAssessmentRun.id.desc())
        .limit(20)
        .all()
    )

    severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
        "other": 0,
    }
    status_counts = {
        "open": 0,
        "in_progress": 0,
        "fixed": 0,
        "accepted": 0,
        "false_positive": 0,
        "other": 0,
    }
    cvss_values = []

    for finding in findings:
        level = str(finding.severity or "").strip().upper()
        if level == "CRITICAL":
            severity["critical"] += 1
        elif level == "HIGH":
            severity["high"] += 1
        elif level == "MEDIUM":
            severity["medium"] += 1
        elif level == "LOW":
            severity["low"] += 1
        elif level in {"INFO", "INFORMATIONAL", "NONE"}:
            severity["informational"] += 1
        else:
            severity["other"] += 1

        finding_status = str(finding.status or "").strip().upper()
        status_key = {
            "OPEN": "open",
            "IN_PROGRESS": "in_progress",
            "FIXED": "fixed",
            "ACCEPTED": "accepted",
            "FALSE_POSITIVE": "false_positive",
        }.get(finding_status, "other")
        status_counts[status_key] += 1

        if finding.cvss_score is not None:
            try:
                cvss_values.append(float(finding.cvss_score))
            except (TypeError, ValueError):
                pass

    from sqlalchemy import func as sql_func

    latest_completed = (
        db.query(RiskAssessmentRun)
        .filter(
            RiskAssessmentRun.user_id.in_(scoped_users),
            sql_func.lower(RiskAssessmentRun.status) == "completed",
        )
        .order_by(
            RiskAssessmentRun.completed_at.desc(),
            RiskAssessmentRun.created_at.desc(),
            RiskAssessmentRun.id.desc(),
        )
        .first()
    )
    assessment_by_id = {assessment.id: assessment for assessment in assessments}

    def serialize_run(run):
        assessment = assessment_by_id.get(run.assessment_id)
        return {
            "assessment_run_id": run.assessment_run_id,
            "assessment_id": run.assessment_id,
            "target": assessment.target if assessment else None,
            "status": run.status,
            "total_findings": int(run.total_findings or 0),
            "average_cvss": float(run.average_cvss or 0),
            "highest_cvss": float(run.highest_cvss or 0),
            "overall_risk": run.overall_risk,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            "created_at": run.created_at.isoformat() if run.created_at else None,
        }

    latest_risk = serialize_run(latest_completed) if latest_completed else None

    return {
        "scope": scope_label,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "metrics": {
            "total_assessments": len(assessments),
            "total_findings": len(findings),
            "severity": severity,
            "finding_status": status_counts,
            "average_cvss": (
                round(sum(cvss_values) / len(cvss_values), 2)
                if cvss_values else 0.0
            ),
            "highest_cvss": round(max(cvss_values), 1) if cvss_values else 0.0,
        },
        "latest_completed_risk_assessment": latest_risk,
        "recent_risk_assessments": [serialize_run(run) for run in runs],
        "risk_data_note": (
            "Severity and CVSS metrics are calculated from persisted findings in "
            "the authenticated user's scope. Overall risk is shown only when a "
            "completed persisted risk-assessment run exists."
        ),
    }


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


# Read-only metadata views. Match /security-findings personal ownership.
@router.get("/management")
def risk_management_metadata(
    view: str = "register",
    search: str = "",
    offset: int = 0,
    page_size: int = 25,
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    import math

    if view not in {"assets", "vulnerabilities", "register", "trends"}:
        raise HTTPException(status_code=422, detail="Invalid risk view.")
    if len(search) > 200 or offset < 0 or not 1 <= page_size <= 100:
        raise HTTPException(status_code=422, detail="Invalid search or pagination.")

    def iso(value):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.isoformat() + "Z"
        return value.isoformat()

    def score(value):
        try:
            number = float(value)
            return number if math.isfinite(number) and 0 <= number <= 10 else None
        except (TypeError, ValueError, OverflowError):
            return None

    finding_count = None
    excluded_scores = 0

    if view == "trends":
        columns = [
            RiskAssessmentRun.id,
            RiskAssessmentRun.assessment_run_id,
            RiskAssessmentRun.assessment_id,
            RiskAssessmentRun.status,
            RiskAssessmentRun.overall_risk,
            RiskAssessmentRun.total_findings,
            RiskAssessmentRun.average_cvss,
            RiskAssessmentRun.highest_cvss,
            RiskAssessmentRun.completed_at,
            RiskAssessmentRun.created_at,
        ]
        query = (
            db.query(*columns)
            .filter(RiskAssessmentRun.user_id == current_user.id)
            .order_by(
                RiskAssessmentRun.created_at.desc(),
                RiskAssessmentRun.id.desc(),
            )
        )
        rows = []
        for record in query.yield_per(200):
            item = dict(record._mapping)
            completed = str(item["status"] or "").upper() == "COMPLETED"
            item["created_at"] = iso(item["created_at"])
            item["completed_at"] = iso(item["completed_at"])
            # Defaults on unfinished runs are not completed measurements.
            if completed:
                item["average_cvss"] = score(item["average_cvss"])
                item["highest_cvss"] = score(item["highest_cvss"])
            else:
                for key in ("overall_risk", "total_findings", "average_cvss", "highest_cvss"):
                    item[key] = None
            rows.append(item)
    else:
        columns = [
            SecurityFinding.id,
            SecurityFinding.finding_id,
            SecurityFinding.assessment_id,
            SecurityFinding.title,
            SecurityFinding.vulnerability,
            SecurityFinding.tool_name,
            SecurityFinding.severity,
            SecurityFinding.risk_level,
            SecurityFinding.status,
            SecurityFinding.cvss_score,
            SecurityFinding.affected_asset,
            SecurityFinding.detected_at,
            SecurityFinding.updated_at,
        ]
        query = (
            db.query(*columns)
            .filter(SecurityFinding.user_id == current_user.id)
            .order_by(SecurityFinding.id.desc())
        )
        rows = []
        groups = {}
        finding_count = 0

        for record in query.yield_per(200):
            item = dict(record._mapping)
            finding_count += 1
            original_score = item["cvss_score"]
            item["cvss_score"] = score(original_score)
            if original_score is not None and item["cvss_score"] is None:
                excluded_scores += 1
            item["detected_at"] = iso(item["detected_at"])
            item["updated_at"] = iso(item["updated_at"])

            if view == "register":
                rows.append(item)
                continue

            if view == "assets":
                raw_label = item["affected_asset"]
                label = raw_label if raw_label else "Unspecified asset"
                key = (bool(raw_label), label)
            else:
                label = item["vulnerability"] or item["title"] or "Unspecified vulnerability"
                # Keep different scanner labels separate.
                key = (item["tool_name"], label)

            if key not in groups:
                groups[key] = {
                    "label": label,
                    "tool_name": item["tool_name"] if view == "vulnerabilities" else None,
                    "findings": 0,
                    "high_critical": 0,
                    "scored_findings": 0,
                    "highest_cvss": None,
                    "latest_detected_at": None,
                    "statuses": {},
                }
            group = groups[key]
            group["findings"] += 1
            severity = str(item["severity"] or "").strip().upper()
            group["high_critical"] += int(severity in {"HIGH", "CRITICAL"})
            value = item["cvss_score"]
            if value is not None:
                group["scored_findings"] += 1
                group["highest_cvss"] = (
                    value if group["highest_cvss"] is None
                    else max(value, group["highest_cvss"])
                )
            stamp = item["detected_at"]
            if stamp and (
                group["latest_detected_at"] is None
                or stamp > group["latest_detected_at"]
            ):
                group["latest_detected_at"] = stamp
            status = str(item["status"] or "UNKNOWN")
            group["statuses"][status] = group["statuses"].get(status, 0) + 1

        if view != "register":
            rows = sorted(
                groups.values(),
                key=lambda item: (-item["high_critical"], -item["findings"], item["label"]),
            )

    total = len(rows)
    needle = search.strip().casefold()

    def searchable(item):
        return " ".join(
            str(value)
            for key, value in item.items()
            if key != "id" and value is not None
        ).casefold()

    matched = [item for item in rows if not needle or needle in searchable(item)]
    page = matched[offset:offset + page_size]
    return {
        "scope": "personal",
        "view": view,
        "total": total,
        "matched_total": len(matched),
        "finding_count": finding_count,
        "excluded_invalid_cvss": excluded_scores,
        "offset": offset,
        "next_offset": offset + page_size if offset + page_size < len(matched) else None,
        "rows": page,
    }
