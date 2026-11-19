import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import RiskAssessmentRun, SecurityFinding, User
from rbac import require_role

router = APIRouter(
    prefix="/admin/risk-overview",
    tags=["Admin Risk Overview"],
)


def parse_json(value):
    if not value:
        return {}
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}


@router.get("/summary")
def get_risk_overview(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    runs = (
        db.query(RiskAssessmentRun)
        .order_by(RiskAssessmentRun.created_at.desc())
        .all()
    )

    findings = db.query(SecurityFinding).all()

    risk_categories = {}
    assessment_statuses = {}

    for run in runs:
        risk = (run.overall_risk or "UNSPECIFIED").upper()
        status = (run.status or "UNSPECIFIED").upper()

        risk_categories[risk] = risk_categories.get(risk, 0) + 1
        assessment_statuses[status] = (
            assessment_statuses.get(status, 0) + 1
        )

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "NONE": 0,
    }

    finding_statuses = {}

    for finding in findings:
        severity = (finding.severity or "NONE").upper()
        if severity in severity_counts:
            severity_counts[severity] += 1

        status = (finding.status or "UNSPECIFIED").upper()
        finding_statuses[status] = (
            finding_statuses.get(status, 0) + 1
        )

    cvss_values = [
        float(f.cvss_score)
        for f in findings
        if f.cvss_score is not None
    ]

    validation_totals = {}
    for run in runs:
        validation = parse_json(run.validation_summary)
        if isinstance(validation, dict):
            for key, value in validation.items():
                if isinstance(value, (int, float)):
                    validation_totals[key] = (
                        validation_totals.get(key, 0) + value
                    )

    recent_assessments = []
    for run in runs[:10]:
        recent_assessments.append({
            "id": run.id,
            "assessment_run_id": run.assessment_run_id,
            "assessment_id": run.assessment_id,
            "status": run.status,
            "overall_risk": run.overall_risk,
            "total_findings": run.total_findings,
            "average_cvss": run.average_cvss,
            "highest_cvss": run.highest_cvss,
            "started_at": (
                run.started_at.isoformat()
                if run.started_at else None
            ),
            "completed_at": (
                run.completed_at.isoformat()
                if run.completed_at else None
            ),
            "created_at": (
                run.created_at.isoformat()
                if run.created_at else None
            ),
        })

    return {
        "total_assessments": len(runs),
        "assessment_statuses": assessment_statuses,
        "risk_distribution": risk_categories,
        "total_findings": len(findings),
        "severity_distribution": severity_counts,
        "finding_statuses": finding_statuses,
        "cvss": {
            "scored_findings": len(cvss_values),
            "average": (
                round(sum(cvss_values) / len(cvss_values), 2)
                if cvss_values else None
            ),
            "highest": (
                round(max(cvss_values), 1)
                if cvss_values else None
            ),
        },
        "validation_summary": validation_totals,
        "recent_assessments": recent_assessments,
    }
