from io import BytesIO
from datetime import datetime
from uuid import uuid4
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import Assessment, SecurityFinding, Report
from rbac import require_role


router = APIRouter(
    prefix="/reports",
    tags=["Report Generator"],
)


# ============================================================
# REPORT STORAGE
# ============================================================

REPORTS_DIR = Path(__file__).resolve().parent / "generated_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# REQUEST MODEL
# ============================================================

class ReportGenerateRequest(BaseModel):
    assessment_id: int
    report_type: str = "COMPLETE_SOC_REPORT"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_value(value, default="—"):
    if value is None:
        return default

    text = str(value).strip()
    return text if text else default


def format_date(value):
    if not value:
        return "—"

    try:
        return value.strftime("%d %B %Y, %I:%M %p")
    except Exception:
        return str(value)


def normalize(value):
    return str(value or "").strip().upper()


def build_report_id():
    return f"REP-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8].upper()}"


# ============================================================
# PDF GENERATION
# ============================================================

def build_pdf(assessment, findings, report_type):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
    )

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="SOC Platform Security Report",
        author="SOC Platform",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=10,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=15,
        alignment=TA_CENTER,
        textColor=colors.grey,
        spaceAfter=20,
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=14,
        spaceAfter=7,
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=10,
    )

    story = []

    # --------------------------------------------------------
    # BASIC ASSESSMENT INFORMATION
    # --------------------------------------------------------

    assessment_id = safe_value(getattr(assessment, "id", None))

    target = safe_value(
        getattr(assessment, "target", None)
    )

    client_name = "—"

    if getattr(assessment, "user", None):
        client_name = safe_value(
            getattr(assessment.user, "username", None)
            or getattr(assessment.user, "email", None)
        )

    created_at = format_date(
        getattr(assessment, "created_at", None)
    )

    overall_status = safe_value(
        getattr(assessment, "overall_status", None)
    )

    vapt_status = safe_value(
        getattr(assessment, "vapt_status", None)
    )

    qa_status = safe_value(
        getattr(assessment, "qa_status", None)
    )

    monitoring_status = safe_value(
        getattr(assessment, "monitoring_status", None)
    )

    report_status = safe_value(
        getattr(assessment, "report_status", None)
    )

    qa_score = safe_value(
        getattr(assessment, "qa_score", None)
    )

    # --------------------------------------------------------
    # FINDING COUNTS
    # --------------------------------------------------------

    total_findings = len(findings)

    critical_count = sum(
        1 for f in findings
        if normalize(getattr(f, "severity", None)) == "CRITICAL"
    )

    high_count = sum(
        1 for f in findings
        if normalize(getattr(f, "severity", None)) == "HIGH"
    )

    medium_count = sum(
        1 for f in findings
        if normalize(getattr(f, "severity", None)) == "MEDIUM"
    )

    low_count = sum(
        1 for f in findings
        if normalize(getattr(f, "severity", None)) == "LOW"
    )

    open_count = sum(
        1 for f in findings
        if normalize(getattr(f, "status", None)) == "OPEN"
    )

    fixed_count = sum(
        1 for f in findings
        if normalize(getattr(f, "status", None)) == "FIXED"
    )

    in_progress_count = sum(
        1 for f in findings
        if normalize(getattr(f, "status", None)) == "IN_PROGRESS"
    )

    accepted_count = sum(
        1 for f in findings
        if normalize(getattr(f, "status", None)) == "ACCEPTED"
    )

    false_positive_count = sum(
        1 for f in findings
        if normalize(getattr(f, "status", None)) == "FALSE_POSITIVE"
    )

    # --------------------------------------------------------
    # COVER PAGE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "SOC PLATFORM",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Security Operations Center",
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            safe_value(report_type, "COMPLETE_SOC_REPORT").replace("_", " "),
            heading_style,
        )
    )

    cover_data = [
        ["Assessment ID", assessment_id],
        ["Client / User", client_name],
        ["Target", target],
        ["Assessment Date", created_at],
        ["Overall Status", overall_status],
        ["Report Status", report_status],
    ]

    cover_table = Table(
        cover_data,
        colWidths=[45 * mm, 115 * mm],
    )

    cover_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eeeeee")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(cover_table)
    story.append(Spacer(1, 15))

    # --------------------------------------------------------
    # EXECUTIVE SUMMARY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "1. Executive Summary",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            (
                "This security assessment report summarizes the security "
                "testing and findings recorded in the SOC Platform for "
                f"Assessment #{assessment_id}. The assessment currently "
                f"contains {total_findings} security finding(s), including "
                f"{critical_count} Critical, {high_count} High, "
                f"{medium_count} Medium and {low_count} Low severity finding(s). "
                f"The current overall assessment status is "
                f"<b>{overall_status}</b>."
            ),
            body_style,
        )
    )

    # --------------------------------------------------------
    # ASSESSMENT STATUS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "2. Assessment Status",
            heading_style,
        )
    )

    status_data = [
        ["Component", "Status"],
        ["VAPT Testing", vapt_status],
        ["QA Testing", qa_status],
        ["QA Score", qa_score],
        ["Live Monitoring", monitoring_status],
        ["Report Status", report_status],
        ["Overall Status", overall_status],
    ]

    status_table = Table(
        status_data,
        colWidths=[70 * mm, 90 * mm],
    )

    status_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    story.append(status_table)

    # --------------------------------------------------------
    # SECURITY FINDINGS SUMMARY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "3. Security Findings Summary",
            heading_style,
        )
    )

    severity_data = [
        ["Severity", "Count"],
        ["Critical", str(critical_count)],
        ["High", str(high_count)],
        ["Medium", str(medium_count)],
        ["Low", str(low_count)],
        ["Total", str(total_findings)],
    ]

    severity_table = Table(
        severity_data,
        colWidths=[70 * mm, 90 * mm],
    )

    severity_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )

    story.append(severity_table)
    story.append(Spacer(1, 10))

    status_summary_data = [
        ["Finding Status", "Count"],
        ["Open", str(open_count)],
        ["In Progress", str(in_progress_count)],
        ["Fixed", str(fixed_count)],
        ["Accepted", str(accepted_count)],
        ["False Positive", str(false_positive_count)],
    ]

    status_summary_table = Table(
        status_summary_data,
        colWidths=[70 * mm, 90 * mm],
    )

    status_summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )

    story.append(status_summary_table)

    # --------------------------------------------------------
    # DETAILED FINDINGS
    # --------------------------------------------------------

    story.append(PageBreak())

    story.append(
        Paragraph(
            "4. Detailed Security Findings",
            heading_style,
        )
    )

    if not findings:
        story.append(
            Paragraph(
                "No security findings were recorded for this assessment.",
                body_style,
            )
        )
    else:
        for index, finding in enumerate(findings, start=1):
            finding_id = safe_value(getattr(finding, "finding_id", None))
            title = safe_value(getattr(finding, "title", None))
            severity = safe_value(getattr(finding, "severity", None))
            status = safe_value(getattr(finding, "status", None))
            vulnerability = safe_value(getattr(finding, "vulnerability", None))
            description = safe_value(getattr(finding, "description", None))

            owasp = safe_value(
                getattr(finding, "owasp_category", None)
                or getattr(finding, "owasp_api_category", None)
            )

            cve = safe_value(getattr(finding, "cve_id", None))
            cwe = safe_value(getattr(finding, "cwe_id", None))
            cvss = safe_value(getattr(finding, "cvss_score", None))

            affected_asset = safe_value(
                getattr(finding, "affected_asset", None)
                or getattr(finding, "affected_url", None)
            )

            endpoint = safe_value(getattr(finding, "endpoint", None))
            parameter = safe_value(getattr(finding, "parameter", None))
            evidence = safe_value(getattr(finding, "evidence", None))
            impact = safe_value(getattr(finding, "impact", None))
            remediation = safe_value(getattr(finding, "remediation", None))
            references = safe_value(getattr(finding, "references", None))

            finding_heading_style = ParagraphStyle(
                f"FindingHeading{index}",
                parent=heading_style,
                fontSize=11,
                leading=14,
                spaceBefore=8,
                spaceAfter=5,
            )

            story.append(
                Paragraph(
                    f"{index}. {finding_id} — {title}",
                    finding_heading_style,
                )
            )

            finding_data = [
                ["Severity", severity],
                ["Status", status],
                ["Vulnerability", vulnerability],
                ["OWASP Category", owasp],
                ["CVE", cve],
                ["CWE", cwe],
                ["CVSS", cvss],
                ["Affected Asset", affected_asset],
                ["Endpoint", endpoint],
                ["Parameter", parameter],
                ["Description", description],
                ["Evidence", evidence],
                ["Impact", impact],
                ["Remediation", remediation],
                ["References", references],
            ]

            finding_table = Table(
                finding_data,
                colWidths=[42 * mm, 118 * mm],
            )

            finding_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eeeeee")),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )

            story.append(finding_table)
            story.append(Spacer(1, 8))

    # --------------------------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------------------------

    story.append(PageBreak())

    story.append(
        Paragraph(
            "5. Recommendations",
            heading_style,
        )
    )

    recommendations = [
        "Prioritize remediation of Critical and High severity findings.",
        "Review all open findings and assign responsible remediation owners.",
        "Validate remediation through follow-up security testing.",
        "Maintain current security monitoring and logging coverage.",
        "Review CVE/CVSS information for affected components where applicable.",
        "Perform periodic reassessment after security fixes are deployed.",
    ]

    for number, recommendation in enumerate(recommendations, start=1):
        story.append(
            Paragraph(
                f"{number}. {recommendation}",
                body_style,
            )
        )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            (
                "This report was generated by the SOC Platform. "
                "The information contained in this report is based on "
                "security assessment data recorded in the platform at "
                f"{datetime.utcnow().strftime('%d %B %Y, %I:%M %p')} UTC."
            ),
            small_style,
        )
    )

    document.build(story)

    buffer.seek(0)
    return buffer


# ============================================================
# GENERATE PDF REPORT
# ============================================================

@router.post("/generate")
def generate_report(
    request: ReportGenerateRequest,
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    assessment = (
        db.query(Assessment)
        .filter(Assessment.id == request.assessment_id)
        .first()
    )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail="Assessment not found.",
        )

    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.assessment_id == request.assessment_id
        )
        .order_by(SecurityFinding.created_at.asc())
        .all()
    )

    report_type = (
        request.report_type.strip()
        if request.report_type
        else "COMPLETE_SOC_REPORT"
    )

    try:
        # Generate the report ID first so the stored PDF filename is unique.
        report_id = build_report_id()

        # Keep the normal report filename readable while making it unique
        # so historical reports are never overwritten.
        filename = (
            f"SOC_Report_Assessment_{request.assessment_id}_{report_id}.pdf"
        )

        pdf_buffer = build_pdf(
            assessment=assessment,
            findings=findings,
            report_type=report_type,
        )

        # Read the generated PDF bytes once so the same content can be
        # persisted to disk and returned to the client.
        pdf_bytes = pdf_buffer.getvalue()

        storage_path = REPORTS_DIR / filename
        storage_path.write_bytes(pdf_bytes)

        # Keep the assessment lifecycle status in sync.
        assessment.report_status = "generated"

        # Create a permanent report-history record.
        report = Report(
            report_id=report_id,
            assessment_id=assessment.id,
            user_id=assessment.user_id,
            report_type=report_type,
            filename=filename,
            status="GENERATED",
            generated_at=datetime.utcnow(),
        )

        db.add(assessment)
        db.add(report)

        try:
            db.commit()
            db.refresh(report)
        except Exception:
            db.rollback()
            # Prevent orphaned PDF files when database persistence fails.
            if storage_path.exists():
                storage_path.unlink()
            raise

        pdf_buffer.seek(0)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Unable to generate report: {exc}",
        )

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),
            "X-Report-ID": report.report_id,
        },
    )
