from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import (
    Assessment,
    Report,
    ReportIssue,
    SecurityFinding,
    SupportTicket,
    User,
)
from rbac import require_role


router = APIRouter(
    prefix="/report-issues",
    tags=["Report Issues"],
)


# ============================================================
# REQUEST SCHEMAS
# ============================================================

class ReportIssueCreateRequest(BaseModel):
    report_id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1)
    severity: str = "MEDIUM"
    assigned_to: int | None = None


class ReportIssueUpdateRequest(BaseModel):
    status: str
    resolution: str | None = None
    assigned_to: int | None = None


# ============================================================
# HELPERS
# ============================================================

ALLOWED_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

ALLOWED_STATUSES = {
    "OPEN",
    "ASSIGNED",
    "IN_PROGRESS",
    "RESOLVED",
    "NOT_RESOLVED",
    "TICKET_RAISED",
}


def normalize(value):
    return str(value or "").strip().upper()


def build_issue_id():
    return (
        f"RI-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-"
        f"{uuid4().hex[:8].upper()}"
    )


def build_ticket_code():
    return (
        f"TKT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-"
        f"{uuid4().hex[:8].upper()}"
    )


def validate_assignee(db: Session, assigned_to: int | None):
    if assigned_to is None:
        return None

    user = (
        db.query(User)
        .filter(User.id == assigned_to)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Assigned team member was not found.",
        )

    # Role 3 is Admin. Report issues are assigned to working
    # team members, not another administrator.
    if int(getattr(user, "role_id", 0) or 0) == 3:
        raise HTTPException(
            status_code=400,
            detail="Report issues must be assigned to a team member, not an Admin.",
        )

    return user


def serialize_issue(issue: ReportIssue):
    assignee = getattr(issue, "assignee", None)
    creator = getattr(issue, "creator", None)
    report = getattr(issue, "report", None)
    ticket = getattr(issue, "support_ticket", None)

    return {
        "id": issue.id,
        "issue_id": issue.issue_id,
        "report_id": report.report_id if report else None,
        "report_record_id": issue.report_id,
        "assessment_id": issue.assessment_id,
        "created_by": issue.created_by,
        "created_by_name": (
            getattr(creator, "username", None)
            or getattr(creator, "email", None)
            or f"User {issue.created_by}"
        ) if creator else f"User {issue.created_by}",
        "assigned_to": issue.assigned_to,
        "assigned_to_name": (
            getattr(assignee, "username", None)
            or getattr(assignee, "email", None)
            or f"User {issue.assigned_to}"
        ) if assignee else None,
        "title": issue.title,
        "description": issue.description,
        "severity": issue.severity,
        "status": issue.status,
        "resolution": issue.resolution,
        "ticket_id": issue.ticket_id,
        "ticket_code": (
            getattr(ticket, "ticket_id", None)
            if ticket else None
        ),
        "created_at": (
            issue.created_at.isoformat()
            if issue.created_at
            else None
        ),
        "updated_at": (
            issue.updated_at.isoformat()
            if issue.updated_at
            else None
        ),
        "resolved_at": (
            issue.resolved_at.isoformat()
            if issue.resolved_at
            else None
        ),
    }


def raise_support_ticket_for_issue(
    db: Session,
    issue: ReportIssue,
):
    """
    Create exactly one Support Ticket for an unresolved
    report issue and link it back to the issue.
    """

    if issue.ticket_id:
        return (
            db.query(SupportTicket)
            .filter(SupportTicket.id == issue.ticket_id)
            .first()
        )

    assessment = (
        db.query(Assessment)
        .filter(Assessment.id == issue.assessment_id)
        .first()
    )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail="Assessment linked to report issue was not found.",
        )

    report = (
        db.query(Report)
        .filter(Report.id == issue.report_id)
        .first()
    )

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report linked to report issue was not found.",
        )

    assignee = (
        db.query(User)
        .filter(User.id == issue.assigned_to)
        .first()
        if issue.assigned_to
        else None
    )

    assignment_text = (
        getattr(assignee, "username", None)
        or getattr(assignee, "email", None)
        or None
    )

    ticket = SupportTicket(
        ticket_id=build_ticket_code(),
        # The ticket belongs to the User/Client whose assessment
        # generated the report.
        user_id=assessment.user_id,
        assessment_id=assessment.id,
        category="REPORT_ISSUE",
        subject=f"Report Issue: {issue.title}",
        description=(
            f"Report issue {issue.issue_id} was not resolved.\n\n"
            f"Report ID: {report.report_id}\n"
            f"Assessment ID: {assessment.id}\n"
            f"Problem: {issue.title}\n\n"
            f"{issue.description}\n\n"
            f"Original severity: {issue.severity}\n"
            f"Assigned team member: {assignment_text or 'Not assigned'}\n"
        ),
        priority=issue.severity,
        status="OPEN",
        assigned_to=assignment_text,
        assignment_channel="SOC_PLATFORM",
        assignment_status=(
            "ASSIGNED" if assignment_text else "NOT_ASSIGNED"
        ),
        admin_notes=(
            f"Automatically raised from report issue {issue.issue_id}."
        ),
    )

    db.add(ticket)
    db.flush()

    issue.ticket_id = ticket.id
    issue.status = "TICKET_RAISED"

    return ticket


# ============================================================
# ADMIN - LIST ISSUES
# ============================================================

@router.get("/admin")
def get_admin_report_issues(
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    issues = (
        db.query(ReportIssue)
        .order_by(ReportIssue.created_at.desc())
        .all()
    )

    return {
        "total": len(issues),
        "issues": [serialize_issue(issue) for issue in issues],
    }


# ============================================================
# ADMIN - CREATE ISSUE
# ============================================================

@router.post("/admin")
def create_admin_report_issue(
    request: ReportIssueCreateRequest,
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    report = (
        db.query(Report)
        .filter(Report.report_id == request.report_id.strip())
        .first()
    )

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found.",
        )

    assessment = (
        db.query(Assessment)
        .filter(Assessment.id == report.assessment_id)
        .first()
    )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail="Assessment linked to report was not found.",
        )

    severity = normalize(request.severity)

    if severity not in ALLOWED_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail="Severity must be LOW, MEDIUM, HIGH or CRITICAL.",
        )

    assignee = validate_assignee(
        db,
        request.assigned_to,
    )

    issue = ReportIssue(
        issue_id=build_issue_id(),
        report_id=report.id,
        assessment_id=assessment.id,
        created_by=current_user.id,
        assigned_to=assignee.id if assignee else None,
        title=request.title.strip(),
        description=request.description.strip(),
        severity=severity,
        status="ASSIGNED" if assignee else "OPEN",
    )

    db.add(issue)
    db.commit()
    db.refresh(issue)

    return serialize_issue(issue)


# ============================================================
# ADMIN - UPDATE / RESOLVE / ESCALATE ISSUE
# ============================================================

@router.put("/admin/{issue_id}")
def update_admin_report_issue(
    issue_id: str,
    request: ReportIssueUpdateRequest,
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    issue = (
        db.query(ReportIssue)
        .filter(ReportIssue.issue_id == issue_id)
        .first()
    )

    if not issue:
        raise HTTPException(
            status_code=404,
            detail="Report issue not found.",
        )

    status = normalize(request.status)

    if status not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid issue status. Allowed values: "
                + ", ".join(sorted(ALLOWED_STATUSES))
            ),
        )

    if request.assigned_to is not None:
        assignee = validate_assignee(
            db,
            request.assigned_to,
        )
        issue.assigned_to = assignee.id

        if status == "OPEN":
            status = "ASSIGNED"

    elif status == "ASSIGNED" and not issue.assigned_to:
        raise HTTPException(
            status_code=400,
            detail="Assign the report issue to a team member before using ASSIGNED status.",
        )

    if request.resolution is not None:
        issue.resolution = request.resolution.strip() or None

    if status == "RESOLVED":
        if not (issue.resolution or "").strip():
            issue.resolution = (
                "Problem reviewed and resolved by the assigned team member."
            )
        issue.resolved_at = datetime.utcnow()

    elif status in {"IN_PROGRESS", "NOT_RESOLVED", "OPEN", "ASSIGNED"}:
        issue.resolved_at = None

    if status == "NOT_RESOLVED":
        ticket = raise_support_ticket_for_issue(
            db,
            issue,
        )
        db.add(issue)
        db.add(ticket)
        db.commit()
        db.refresh(issue)

        return {
            **serialize_issue(issue),
            "ticket_raised": True,
            "ticket_id": getattr(ticket, "ticket_id", None),
            "message": (
                "Issue marked as not resolved and a Support Ticket "
                "was raised automatically."
            ),
        }

    issue.status = status

    db.add(issue)
    db.commit()
    db.refresh(issue)

    return {
        **serialize_issue(issue),
        "ticket_raised": False,
        "message": "Report issue updated successfully.",
    }


# ============================================================
# ADMIN - SINGLE ISSUE
# ============================================================

@router.get("/admin/{issue_id}")
def get_admin_report_issue(
    issue_id: str,
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    issue = (
        db.query(ReportIssue)
        .filter(ReportIssue.issue_id == issue_id)
        .first()
    )

    if not issue:
        raise HTTPException(
            status_code=404,
            detail="Report issue not found.",
        )

    return serialize_issue(issue)
