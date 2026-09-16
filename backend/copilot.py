from datetime import datetime
from typing import Any
import re
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from auth import get_current_user
from models import User, Assessment, SecurityFinding, SupportTicket, Report


router = APIRouter(prefix="/copilot", tags=["Security Copilot"])


# ============================================================
# REQUEST / RESPONSE SCHEMAS
# ============================================================

class CopilotChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)


class CopilotChatResponse(BaseModel):
    answer: str
    context: dict[str, Any] = {}


class CopilotTicketRequest(BaseModel):
    finding_id: str = Field(..., min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=4000)


class CopilotTicketResponse(BaseModel):
    message: str
    ticket_id: str
    finding_id: str
    status: str


# ============================================================
# HELPERS
# ============================================================

def _severity_counts(findings: list[SecurityFinding]) -> dict[str, int]:
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "NONE": 0,
    }

    for finding in findings:
        severity = str(finding.severity or "NONE").upper()
        counts[severity] = counts.get(severity, 0) + 1

    return counts


def _risk_summary(findings: list[SecurityFinding]) -> str:
    counts = _severity_counts(findings)

    if counts["CRITICAL"] > 0:
        return (
            f"You have {counts['CRITICAL']} Critical finding(s). "
            "These should be addressed first."
        )

    if counts["HIGH"] > 0:
        return (
            f"You have {counts['HIGH']} High finding(s). "
            "These should be prioritized for remediation."
        )

    if counts["MEDIUM"] > 0:
        return (
            f"You have {counts['MEDIUM']} Medium finding(s). "
            "Review and remediate them after Critical/High issues."
        )

    if findings:
        return "No Critical or High findings were found in your current records."

    return "No security findings are currently recorded for your account."


def _format_finding(finding: SecurityFinding) -> str:
    parts = [
        f"{finding.title or 'Untitled finding'} "
        f"(Severity: {str(finding.severity or 'NONE').upper()})"
    ]

    if getattr(finding, "cvss_score", None) is not None:
        parts.append(f"CVSS {finding.cvss_score}")

    if getattr(finding, "cve_id", None):
        parts.append(f"CVE {finding.cve_id}")

    if getattr(finding, "owasp_category", None):
        parts.append(f"OWASP {finding.owasp_category}")

    return " — ".join(parts)


def _build_context(
    user: User,
    findings: list[SecurityFinding],
    assessments: list[Assessment],
    tickets: list[SupportTicket],
    reports: list[Report],
) -> dict[str, Any]:
    severity_counts = _severity_counts(findings)

    return {
        "user_id": user.id,
        "username": getattr(user, "username", None),
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "total_assessments": len(assessments),
        "total_support_tickets": len(tickets),
        "open_support_tickets": sum(
            1
            for ticket in tickets
            if str(ticket.status or "").upper() in {"OPEN", "IN_PROGRESS", "WAITING_FOR_USER"}
        ),
        "total_reports": len(reports),
    }


def _general_answer(message: str) -> str | None:
    text = message.lower()

    # Specific CVE requests are handled from the authenticated user's
    # stored findings in the main chat function before generic definitions.
    if "what is cve" in text or "cve" == text.strip():
        return (
            "CVE stands for Common Vulnerabilities and Exposures. "
            "It is a standardized identifier used to reference a publicly known security vulnerability."
        )

    if "what is cvss" in text or "cvss" == text.strip():
        return (
            "CVSS stands for Common Vulnerability Scoring System. "
            "It provides a numerical severity score from 0.0 to 10.0 to help prioritize vulnerabilities."
        )

    if "what is owasp" in text or "owasp top 10" in text:
        return (
            "OWASP Top 10 is a widely used awareness list of important web application security risks. "
            "Your SOC Platform can store OWASP categories alongside security findings."
        )

    if "what is cwe" in text or "cwe" == text.strip():
        return (
            "CWE stands for Common Weakness Enumeration. "
            "It categorizes common software and design weaknesses, while CVE identifies specific known vulnerabilities."
        )

    return None


def _answer_from_user_context(
    message: str,
    findings: list[SecurityFinding],
    assessments: list[Assessment],
    tickets: list[SupportTicket],
    reports: list[Report],
) -> str:
    text = message.lower().strip()
    counts = _severity_counts(findings)

    # Specific CVE lookup
    cve_matches = re.findall(
        r"\bcve[-\s]?\d{4}-\d{4,7}\b",
        text,
        flags=re.IGNORECASE,
    )

    if cve_matches:
        requested_cve = cve_matches[0].upper().replace(" ", "-")

        matching_findings = [
            finding
            for finding in findings
            if str(getattr(finding, "cve_id", "") or "").upper() == requested_cve
        ]

        if not matching_findings:
            return (
                f"I could not find {requested_cve} in the security findings "
                "associated with your account."
            )

        # Prefer the finding with the most complete stored CVE context.
        matching_findings.sort(
            key=lambda item: (
                1 if getattr(item, "cvss_score", None) is not None else 0,
                1 if getattr(item, "cwe_id", None) else 0,
                1 if getattr(item, "impact", None) else 0,
                1 if getattr(item, "remediation", None) else 0,
            ),
            reverse=True,
        )

        finding = matching_findings[0]
        parts = [
            f"{requested_cve} is present in your security findings.",
        ]

        if getattr(finding, "title", None):
            parts.append(f"Finding: {finding.title}.")

        if getattr(finding, "description", None):
            parts.append(f"Description: {finding.description}")

        if getattr(finding, "cvss_score", None) is not None:
            parts.append(
                f"CVSS: {finding.cvss_score}. "
                f"Severity: {str(finding.severity or 'NONE').upper()}."
            )

        if getattr(finding, "cwe_id", None):
            parts.append(f"CWE: {finding.cwe_id}.")

        if getattr(finding, "owasp_category", None):
            parts.append(f"OWASP: {finding.owasp_category}.")

        if getattr(finding, "impact", None):
            parts.append(f"Impact: {finding.impact}")

        if getattr(finding, "remediation", None):
            parts.append(f"Remediation: {finding.remediation}")

        return " ".join(parts)

    # Risk / posture questions
    if any(
        phrase in text
        for phrase in [
            "security status",
            "security posture",
            "overall security",
            "biggest risk",
            "biggest risks",
            "what should i fix first",
            "what should i fix",
            "highest risk",
        ]
    ):
        return (
            f"You currently have {len(findings)} security finding(s): "
            f"{counts['CRITICAL']} Critical, {counts['HIGH']} High, "
            f"{counts['MEDIUM']} Medium, {counts['LOW']} Low. "
            f"{_risk_summary(findings)}"
        )

    # Counts / severity questions
    if "critical" in text and ("how many" in text or "number" in text or "count" in text):
        return f"You currently have {counts['CRITICAL']} Critical finding(s)."

    if "high" in text and ("how many" in text or "number" in text or "count" in text):
        return f"You currently have {counts['HIGH']} High finding(s)."

    if "medium" in text and ("how many" in text or "number" in text or "count" in text):
        return f"You currently have {counts['MEDIUM']} Medium finding(s)."

    if "low" in text and ("how many" in text or "number" in text or "count" in text):
        return f"You currently have {counts['LOW']} Low finding(s)."

    if "finding" in text and ("how many" in text or "count" in text or "total" in text):
        return (
            f"You currently have {len(findings)} security finding(s): "
            f"{counts['CRITICAL']} Critical, {counts['HIGH']} High, "
            f"{counts['MEDIUM']} Medium, {counts['LOW']} Low."
        )

    # Practical remediation guidance for the latest finding
    if (
        "finding" in text
        and "latest" in text
        and any(
            phrase in text
            for phrase in [
                "how can i fix",
                "how do i fix",
                "how to fix",
                "fix my",
                "fix the",
                "remediate",
                "remediation",
            ]
        )
    ):
        if not findings:
            return "You do not currently have any security findings to remediate."

        finding = findings[0]
        title = finding.title or "the latest security finding"
        guidance = [
            f"To fix your latest finding, '{title}', start by confirming the affected asset or endpoint and reproducing the issue safely."
        ]

        if getattr(finding, "remediation", None):
            guidance.append(f"Recommended remediation from the finding: {finding.remediation}")

        if getattr(finding, "impact", None):
            guidance.append(f"Why it matters: {finding.impact}")

        if getattr(finding, "affected_asset", None):
            guidance.append(f"Affected asset: {finding.affected_asset}")

        if getattr(finding, "affected_url", None):
            guidance.append(f"Affected URL: {finding.affected_url}")

        if getattr(finding, "affected_endpoint", None):
            guidance.append(f"Affected endpoint: {finding.affected_endpoint}")

        guidance.extend(
            [
                "After applying the change, rerun the relevant security test.",
                "Confirm that the finding is no longer reproducible, then record the remediation and move the finding to the appropriate status."
            ]
        )

        return " ".join(guidance)

    # Finding detail
    if "latest finding" in text or "last finding" in text:
        if not findings:
            return "You do not currently have any security findings."

        finding = findings[0]
        detail_lines = [
            f"Latest finding: {_format_finding(finding)}.",
        ]

        if getattr(finding, "description", None):
            detail_lines.append(f"Description: {finding.description}")

        if getattr(finding, "impact", None):
            detail_lines.append(f"Impact: {finding.impact}")

        if getattr(finding, "remediation", None):
            detail_lines.append(f"Recommended remediation: {finding.remediation}")

        return " ".join(detail_lines)

    if "finding" in text and ("explain" in text or "details" in text):
        if not findings:
            return "You do not currently have any security findings."

        finding = findings[0]
        answer = f"The most recent finding is {_format_finding(finding)}."
        if getattr(finding, "description", None):
            answer += f" {finding.description}"
        if getattr(finding, "remediation", None):
            answer += f" Recommended remediation: {finding.remediation}"
        return answer

    # Reports
    if "report" in text and (
        "latest" in text or "last" in text or "summary" in text or "summarize" in text
    ):
        if not reports:
            return "No generated security reports are currently associated with your account."

        report = reports[0]
        report_findings = [
            finding
            for finding in findings
            if finding.assessment_id == report.assessment_id
        ]
        report_counts = _severity_counts(report_findings)

        assessment = next(
            (item for item in assessments if item.id == report.assessment_id),
            None,
        )

        answer_parts = [
            f"Your latest report is {report.report_id} for Assessment {report.assessment_id}.",
            f"Report type: {report.report_type}. Status: {report.status}.",
            f"It contains {len(report_findings)} security finding(s): "
            f"{report_counts['CRITICAL']} Critical, {report_counts['HIGH']} High, "
            f"{report_counts['MEDIUM']} Medium, {report_counts['LOW']} Low.",
        ]

        if assessment:
            answer_parts.append(
                "Assessment status: "
                f"overall={assessment.overall_status or 'not available'}, "
                f"VAPT={assessment.vapt_status or 'not available'}, "
                f"QA={assessment.qa_status or 'not available'}, "
                f"monitoring={assessment.monitoring_status or 'not available'}, "
                f"report={assessment.report_status or 'not available'}."
            )

        priority_text = []
        if report_counts['CRITICAL']:
            priority_text.append(
                f"{report_counts['CRITICAL']} Critical finding(s) should be addressed first."
            )
        if report_counts['HIGH']:
            priority_text.append(
                f"{report_counts['HIGH']} High finding(s) should be prioritized next."
            )
        if report_counts['MEDIUM']:
            priority_text.append(
                f"{report_counts['MEDIUM']} Medium finding(s) should then be reviewed and remediated."
            )
        if priority_text:
            answer_parts.append("Priority: " + " ".join(priority_text))
        elif report_findings:
            answer_parts.append("No Critical or High findings are recorded in this assessment.")
        else:
            answer_parts.append("No findings are currently linked to this assessment.")

        top_findings = []
        for finding in report_findings[:3]:
            top_findings.append(_format_finding(finding))
        if top_findings:
            answer_parts.append("Recent findings: " + "; ".join(top_findings) + ".")

        return " ".join(answer_parts)

    if "report" in text and ("how many" in text or "count" in text or "total" in text):
        return f"You currently have {len(reports)} generated report(s)."

    # Assessments
    if "assessment" in text and ("how many" in text or "count" in text or "total" in text):
        return f"You currently have {len(assessments)} assessment(s)."

    if "assessment" in text and ("status" in text or "progress" in text):
        if not assessments:
            return "You do not currently have any assessments."

        assessment = assessments[0]
        return (
            f"Your latest assessment is Assessment {assessment.id}. "
            f"Overall status: {assessment.overall_status or 'not available'}. "
            f"VAPT status: {assessment.vapt_status or 'not available'}. "
            f"QA status: {assessment.qa_status or 'not available'}. "
            f"Monitoring status: {assessment.monitoring_status or 'not available'}. "
            f"Report status: {assessment.report_status or 'not available'}."
        )

    # Support tickets
    if "ticket" in text and (
        "how many" in text or "count" in text or "open" in text or "support" in text
    ):
        open_count = sum(
            1
            for ticket in tickets
            if str(ticket.status or "").upper()
            in {"OPEN", "IN_PROGRESS", "WAITING_FOR_USER"}
        )
        return (
            f"You have {len(tickets)} support ticket(s), "
            f"with {open_count} currently open or active."
        )

    if "latest ticket" in text or "last ticket" in text:
        if not tickets:
            return "You do not currently have any support tickets."

        ticket = tickets[0]
        return (
            f"Your latest support ticket is {ticket.ticket_id}. "
            f"Subject: {ticket.subject}. "
            f"Status: {ticket.status}. "
            f"Priority: {ticket.priority}."
        )

    # Critical vulnerability prioritization
    if (
        "critical" in text
        and any(
            phrase in text
            for phrase in [
                "which critical",
                "critical vulnerabilities",
                "critical findings",
            ]
        )
        and any(
            word in text
            for word in ["which", "why", "first", "prioritize", "fix"]
        )
    ):
        critical_findings = [
            finding
            for finding in findings
            if str(finding.severity or "").upper() == "CRITICAL"
        ]

        critical_findings.sort(
            key=lambda item: (
                float(item.cvss_score)
                if getattr(item, "cvss_score", None) is not None
                else -1.0
            ),
            reverse=True,
        )

        if not critical_findings:
            return "You currently have no Critical security findings."

        parts = [
            f"You have {len(critical_findings)} Critical finding(s), and they should be investigated first."
        ]

        for index, finding in enumerate(critical_findings[:5], start=1):
            detail = [f"{index}. {_format_finding(finding)}"]

            if getattr(finding, "description", None):
                detail.append(f"Description: {finding.description}")

            if getattr(finding, "impact", None):
                detail.append(f"Impact: {finding.impact}")

            if getattr(finding, "remediation", None):
                detail.append(f"Remediation: {finding.remediation}")

            parts.append(" ".join(detail))

        parts.append(
            "Priority is based first on Critical severity and then on the highest available CVSS score."
        )

        return " ".join(parts)

    # General cybersecurity concepts
    if "owasp top 10" in text or ("what is owasp" in text and "api" not in text):
        return (
            "OWASP Top 10 is a widely used awareness framework for the most important "
            "web application security risks. It helps security teams identify, assess, "
            "and prioritize common classes of web application vulnerabilities."
        )

    if "owasp api" in text or "owasp api security top 10" in text:
        return (
            "OWASP API Security Top 10 is an awareness list of important security risks "
            "specific to APIs, including issues involving authorization, authentication, "
            "excessive data exposure, and other API-specific weaknesses."
        )

    if "what is cwe" in text or text.strip() == "cwe":
        return (
            "CWE stands for Common Weakness Enumeration. It categorizes common software "
            "and design weaknesses, while CVE identifies specific publicly known vulnerabilities."
        )

    if "what is cvss" in text or text.strip() == "cvss":
        return (
            "CVSS stands for Common Vulnerability Scoring System. It provides a numerical "
            "severity score from 0.0 to 10.0 to help organizations prioritize vulnerabilities."
        )

    # Vulnerability terminology
    if "medium" in text and ("mean" in text or "why" in text or "explain" in text):
        return (
            "A Medium finding indicates a meaningful security risk that should be remediated, "
            "but it is generally below Critical and High priority in this platform's risk model."
        )

    if "critical" in text and ("mean" in text or "why" in text or "explain" in text):
        return (
            "A Critical finding represents the highest severity level in the platform. "
            "It should normally receive immediate investigation and remediation priority."
        )

    # Generic account security overview
    if any(word in text for word in ["hello", "hi", "help", "what can you do"]):
        return (
            "I am your Security Copilot. I can help you understand your findings, "
            "assessment status, security reports, support tickets, CVE/CVSS/OWASP concepts, "
            "and what to prioritize next."
        )

    return (
        "I can answer questions about your security findings, assessments, reports, "
        "support tickets, CVE/CVSS/CWE/OWASP concepts, and security prioritization. "
        "Try asking: 'How many critical vulnerabilities do I have?', "
        "'What should I fix first?', or 'What is OWASP Top 10?'"
    )


# ============================================================
# SUPPORT TICKET HELPERS
# ============================================================

def build_copilot_ticket_code():
    return (
        f"TKT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-"
        f"{uuid4().hex[:8].upper()}"
    )


def build_copilot_ticket_description(
    finding: SecurityFinding,
    user_description: str | None,
) -> str:
    parts = [
        "Support request raised from Security Copilot.",
        f"Finding ID: {finding.finding_id}",
        f"Finding: {finding.title or 'Untitled finding'}",
        f"Severity: {str(finding.severity or 'NONE').upper()}",
        f"Assessment ID: {finding.assessment_id}",
    ]

    if getattr(finding, "cvss_score", None) is not None:
        parts.append(f"CVSS: {finding.cvss_score}")

    if getattr(finding, "cve_id", None):
        parts.append(f"CVE: {finding.cve_id}")

    if getattr(finding, "owasp_category", None):
        parts.append(f"OWASP: {finding.owasp_category}")

    if getattr(finding, "affected_asset", None):
        parts.append(f"Affected Asset: {finding.affected_asset}")

    if getattr(finding, "affected_url", None):
        parts.append(f"Affected URL: {finding.affected_url}")

    if getattr(finding, "affected_endpoint", None):
        parts.append(f"Affected Endpoint: {finding.affected_endpoint}")

    if getattr(finding, "description", None):
        parts.append(f"Finding Description: {finding.description}")

    if getattr(finding, "impact", None):
        parts.append(f"Impact: {finding.impact}")

    if getattr(finding, "remediation", None):
        parts.append(f"Stored Remediation: {finding.remediation}")

    if user_description and user_description.strip():
        parts.append(f"User Request: {user_description.strip()}")

    return "\n".join(parts)


# ============================================================
# SUPPORT TICKET ENDPOINT
# ============================================================

@router.post("/support-ticket", response_model=CopilotTicketResponse)
def create_copilot_support_ticket(
    payload: CopilotTicketRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # User / Client role = 1
    if current_user.role_id != 1:
        raise HTTPException(
            status_code=403,
            detail="Security Copilot support tickets are available only to User/Client accounts.",
        )

    finding = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.finding_id == payload.finding_id,
            SecurityFinding.user_id == current_user.id,
        )
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="The selected security finding was not found in your account.",
        )

    # Prevent accidental duplicate open tickets for the same finding.
    existing_tickets = (
        db.query(SupportTicket)
        .filter(
            SupportTicket.user_id == current_user.id,
            SupportTicket.assessment_id == finding.assessment_id,
            SupportTicket.category == "SECURITY_FINDING",
            SupportTicket.status.in_(
                ["OPEN", "IN_PROGRESS", "WAITING_FOR_USER"]
            ),
        )
        .all()
    )

    finding_marker = f"Finding ID: {finding.finding_id}"

    for ticket in existing_tickets:
        if finding_marker in str(ticket.description or ""):
            return CopilotTicketResponse(
                message="An active support ticket already exists for this finding.",
                ticket_id=ticket.ticket_id,
                finding_id=finding.finding_id,
                status=ticket.status,
            )

    ticket = SupportTicket(
        ticket_id=build_copilot_ticket_code(),
        user_id=current_user.id,
        assessment_id=finding.assessment_id,
        category="SECURITY_FINDING",
        subject=f"Security Finding Assistance: {finding.title or finding.finding_id}",
        description=build_copilot_ticket_description(
            finding,
            payload.description,
        ),
        priority=str(finding.severity or "MEDIUM").upper(),
        status="OPEN",
        assignment_channel=None,
        assignment_status="NOT_ASSIGNED",
        admin_notes=(
            f"Created from Security Copilot for finding {finding.finding_id}."
        ),
    )

    db.add(ticket)
    db.commit()
    db.refresh(ticket)

    return CopilotTicketResponse(
        message="Support ticket created successfully.",
        ticket_id=ticket.ticket_id,
        finding_id=finding.finding_id,
        status=ticket.status,
    )


# ============================================================
# CHAT ENDPOINT
# ============================================================

@router.post("/chat", response_model=CopilotChatResponse)
def copilot_chat(
    payload: CopilotChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # User / Client role = 1
    if current_user.role_id != 1:
        raise HTTPException(
            status_code=403,
            detail="Security Copilot is available only to User/Client accounts.",
        )

    message = payload.message.strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    # IMPORTANT:
    # Every query below is restricted to the authenticated user's own records.
    findings = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.user_id == current_user.id)
        .order_by(SecurityFinding.created_at.desc())
        .all()
    )

    assessments = (
        db.query(Assessment)
        .filter(Assessment.user_id == current_user.id)
        .order_by(Assessment.created_at.desc())
        .all()
    )

    tickets = (
        db.query(SupportTicket)
        .filter(SupportTicket.user_id == current_user.id)
        .order_by(SupportTicket.created_at.desc())
        .all()
    )

    reports = (
        db.query(Report)
        .filter(Report.user_id == current_user.id)
        .order_by(Report.generated_at.desc())
        .all()
    )

    # Run user-context handling first so a question containing a
    # specific CVE ID (for example, "What is CVE-2021-44228?")
    # is not intercepted by the generic "what is CVE" definition.
    answer = _answer_from_user_context(
        message=message,
        findings=findings,
        assessments=assessments,
        tickets=tickets,
        reports=reports,
    )

    # _answer_from_user_context always returns a response. The generic
    # knowledge helper is retained for compatibility with other callers.

    return CopilotChatResponse(
        answer=answer,
        context=_build_context(
            user=current_user,
            findings=findings,
            assessments=assessments,
            tickets=tickets,
            reports=reports,
        ),
    )
