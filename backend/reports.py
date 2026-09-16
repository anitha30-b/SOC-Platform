from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from database import get_db
from models import Assessment, SecurityFinding, Report, User
from rbac import require_role


router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
)


# ============================================================
# GENERATED REPORT STORAGE
# ============================================================

GENERATED_REPORTS_DIR = (
    Path(__file__).resolve().parent / "generated_reports"
)

GENERATED_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# ADMIN REPORT SUMMARY
# ============================================================

@router.get("/admin/summary")
def get_admin_report_summary(
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    """
    Return platform-wide reporting statistics.

    Admin only.
    """

    assessments = db.query(Assessment).all()
    findings = db.query(SecurityFinding).all()

    total_assessments = len(assessments)

    completed_assessments = sum(
        1
        for assessment in assessments
        if str(assessment.overall_status or "").lower()
        in {"completed", "complete"}
    )

    in_progress_assessments = sum(
        1
        for assessment in assessments
        if str(assessment.overall_status or "").lower()
        in {"in_progress", "in-progress", "running"}
    )

    generated_reports = sum(
        1
        for assessment in assessments
        if str(assessment.report_status or "").lower()
        in {"generated", "completed"}
    )

    pending_reports = sum(
        1
        for assessment in assessments
        if str(assessment.report_status or "").lower()
        not in {"generated", "completed"}
    )

    total_findings = len(findings)

    critical_findings = sum(
        1
        for finding in findings
        if str(finding.severity or "").upper() == "CRITICAL"
    )

    high_findings = sum(
        1
        for finding in findings
        if str(finding.severity or "").upper() == "HIGH"
    )

    medium_findings = sum(
        1
        for finding in findings
        if str(finding.severity or "").upper() == "MEDIUM"
    )

    low_findings = sum(
        1
        for finding in findings
        if str(finding.severity or "").upper() == "LOW"
    )

    open_findings = sum(
        1
        for finding in findings
        if str(finding.status or "").upper() == "OPEN"
    )

    fixed_findings = sum(
        1
        for finding in findings
        if str(finding.status or "").upper() == "FIXED"
    )

    in_progress_findings = sum(
        1
        for finding in findings
        if str(finding.status or "").upper() == "IN_PROGRESS"
    )

    accepted_findings = sum(
        1
        for finding in findings
        if str(finding.status or "").upper() == "ACCEPTED"
    )

    false_positive_findings = sum(
        1
        for finding in findings
        if str(finding.status or "").upper() == "FALSE_POSITIVE"
    )

    return {
        "assessments": {
            "total": total_assessments,
            "completed": completed_assessments,
            "in_progress": in_progress_assessments,
        },
        "reports": {
            "generated": generated_reports,
            "pending": pending_reports,
        },
        "findings": {
            "total": total_findings,
            "critical": critical_findings,
            "high": high_findings,
            "medium": medium_findings,
            "low": low_findings,
        },
        "finding_status": {
            "open": open_findings,
            "in_progress": in_progress_findings,
            "fixed": fixed_findings,
            "accepted": accepted_findings,
            "false_positive": false_positive_findings,
        },
    }


# ============================================================
# ADMIN REPORT HISTORY
# ============================================================

@router.get("/admin/history")
def get_admin_report_history(
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    """
    Return generated report history.

    Admin only.
    """

    reports = (
        db.query(Report)
        .order_by(Report.generated_at.desc())
        .all()
    )

    history = []

    for report in reports:
        user = (
            db.query(User)
            .filter(User.id == report.user_id)
            .first()
        )

        assessment = (
            db.query(Assessment)
            .filter(Assessment.id == report.assessment_id)
            .first()
        )

        report_path = GENERATED_REPORTS_DIR / report.filename

        history.append({
            "id": report.id,
            "report_id": report.report_id,
            "assessment_id": report.assessment_id,
            "user_id": report.user_id,
            "user_name": (
                getattr(user, "name", None)
                or getattr(user, "username", None)
                or getattr(user, "email", None)
                or f"User {report.user_id}"
            ) if user else f"User {report.user_id}",
            "report_type": report.report_type,
            "filename": report.filename,
            "status": report.status,
            "file_available": report_path.is_file(),
            "generated_at": report.generated_at.isoformat()
            if report.generated_at
            else None,
            "assessment_status": (
                assessment.overall_status
                if assessment
                else None
            ),
        })

    return {
        "total": len(history),
        "reports": history,
    }


# ============================================================
# ADMIN REPORT RESTORE / REGENERATE
# ============================================================

@router.post("/admin/{report_id}/restore")
def restore_admin_report(
    report_id: str,
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    """
    Regenerate and restore a previously recorded report whose PDF
    file is missing from generated_reports.

    The existing report_id and database history record are preserved.

    Admin only.
    """

    report = (
        db.query(Report)
        .filter(Report.report_id == report_id)
        .first()
    )

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found.",
        )

    filename = Path(report.filename).name

    if filename != report.filename:
        raise HTTPException(
            status_code=400,
            detail="Invalid report filename.",
        )

    if not filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=400,
            detail="Invalid report file type.",
        )

    report_path = GENERATED_REPORTS_DIR / filename

    if report_path.is_file():
        return {
            "message": "Report file is already available.",
            "report_id": report.report_id,
            "filename": report.filename,
            "file_available": True,
        }

    assessment = (
        db.query(Assessment)
        .filter(Assessment.id == report.assessment_id)
        .first()
    )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail="Assessment linked to this report was not found.",
        )

    findings = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.assessment_id == report.assessment_id)
        .order_by(SecurityFinding.created_at.asc())
        .all()
    )

    try:
        from report_generator import build_pdf

        pdf_buffer = build_pdf(
            assessment=assessment,
            findings=findings,
            report_type=report.report_type,
        )

        pdf_bytes = pdf_buffer.getvalue()

        if not pdf_bytes:
            raise ValueError("Generated PDF is empty.")

        report_path.write_bytes(pdf_bytes)

        report.status = "GENERATED"
        assessment.report_status = "generated"

        db.add(report)
        db.add(assessment)
        db.commit()

    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Unable to restore report: {exc}",
        )

    return {
        "message": "Report restored successfully.",
        "report_id": report.report_id,
        "assessment_id": report.assessment_id,
        "filename": report.filename,
        "status": report.status,
        "file_available": True,
    }


# ============================================================
# ADMIN REPORT DOWNLOAD
# ============================================================

@router.get("/admin/{report_id}/download")
def download_admin_report(
    report_id: str,
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    """
    Download a previously generated PDF report.

    Admin only.
    """

    report = (
        db.query(Report)
        .filter(Report.report_id == report_id)
        .first()
    )

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found.",
        )

    filename = Path(report.filename).name

    if filename != report.filename:
        raise HTTPException(
            status_code=400,
            detail="Invalid report filename.",
        )

    if not filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=400,
            detail="Invalid report file type.",
        )

    report_path = GENERATED_REPORTS_DIR / filename

    if not report_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="The generated PDF file is no longer available.",
        )

    return FileResponse(
        path=str(report_path),
        media_type="application/pdf",
        filename=filename,
        headers={
            "X-Report-ID": report.report_id,
        },
    )
