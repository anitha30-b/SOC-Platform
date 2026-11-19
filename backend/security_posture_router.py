from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import SecurityFinding, RiskAssessmentRun, User
from rbac import require_role

router = APIRouter(
    prefix="/admin/security-posture",
    tags=["Admin Security Posture"],
)


@router.get("/summary")
def get_security_posture(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    findings = db.query(SecurityFinding).all()

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    statuses = [
        "OPEN", "IN_PROGRESS", "FIXED",
        "ACCEPTED", "FALSE_POSITIVE"
    ]
    risk_levels = ["LEVEL_1", "LEVEL_2", "LEVEL_3"]

    severity_counts = {
        level.lower(): sum(
            1 for f in findings
            if (f.severity or "").upper() == level
        )
        for level in severities
    }

    status_counts = {
        status.lower(): sum(
            1 for f in findings
            if (f.status or "").upper() == status
        )
        for status in statuses
    }

    risk_counts = {
        level.lower(): sum(
            1 for f in findings
            if (f.risk_level or "").upper() == level
        )
        for level in risk_levels
    }

    cvss_values = [
        float(f.cvss_score)
        for f in findings
        if f.cvss_score is not None
    ]

    recent_findings = sorted(
        findings,
        key=lambda f: f.created_at or f.detected_at,
        reverse=True,
    )[:10]

    recent_runs = (
        db.query(RiskAssessmentRun)
        .order_by(RiskAssessmentRun.created_at.desc())
        .limit(10)
        .all()
    )

    return {
        "total_findings": len(findings),
        "severity": severity_counts,
        "status": status_counts,
        "risk_levels": risk_counts,
        "cvss": {
            "average": round(sum(cvss_values) / len(cvss_values), 2)
            if cvss_values else 0.0,
            "highest": round(max(cvss_values), 1)
            if cvss_values else 0.0,
        },
        "affected_assets": len({
            f.affected_asset for f in findings
            if f.affected_asset
        }),
        "recent_findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "risk_level": f.risk_level,
                "status": f.status,
                "cvss_score": f.cvss_score,
                "affected_asset": f.affected_asset,
                "tool_name": f.tool_name,
                "created_at": (
                    f.created_at.isoformat()
                    if f.created_at else None
                ),
            }
            for f in recent_findings
        ],
        "recent_assessments": [
            {
                "assessment_id": run.assessment_id,
                "status": run.status,
                "total_findings": run.total_findings,
                "average_cvss": run.average_cvss,
                "highest_cvss": run.highest_cvss,
                "overall_risk": run.overall_risk,
                "created_at": (
                    run.created_at.isoformat()
                    if run.created_at else None
                ),
            }
            for run in recent_runs
        ],
    }
