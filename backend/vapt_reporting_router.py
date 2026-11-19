import asyncio
import json
from datetime import datetime
from uuid import uuid4
from io import BytesIO
from xml.etree.ElementTree import Element, SubElement, tostring

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import (
    Assessment,
    SecurityFinding,
    RiskAssessmentRun,
    VAPTReportRun,
)
from rbac import require_role


router = APIRouter(
    prefix="/vapt/reporting",
    tags=["VAPT Stage 09 Reporting"],
)

REPORT_JOBS = {}


class ReportRequest(BaseModel):
    assessment_id: int
    report_type: str = "COMPLETE"


def _serialize(record):
    def load(value):
        if not value:
            return {}
        try:
            return json.loads(value)
        except Exception:
            return value

    return {
        "report_run_id": record.report_run_id,
        "job_id": record.job_id,
        "assessment_id": record.assessment_id,
        "risk_assessment_run_id": record.risk_assessment_run_id,
        "status": record.status,
        "report_type": record.report_type,
        "formats": load(record.formats),
        "canonical_data": load(record.canonical_data),
        "started_at": record.started_at.isoformat() if record.started_at else None,
        "completed_at": record.completed_at.isoformat() if record.completed_at else None,
    }


def _canonical_data(assessment, risk_run, findings):
    return {
        "report_metadata": {
            "generated_at": datetime.utcnow().isoformat(),
            "assessment_id": assessment.id,
            "target": assessment.target,
            "report_type": "COMPLETE",
        },
        "risk_assessment": {
            "assessment_run_id": risk_run.assessment_run_id,
            "status": risk_run.status,
            "total_findings": risk_run.total_findings,
            "average_cvss": risk_run.average_cvss,
            "highest_cvss": risk_run.highest_cvss,
            "overall_risk": risk_run.overall_risk,
            "severity": json.loads(risk_run.severity_summary or "{}"),
            "risk_levels": json.loads(risk_run.risk_level_summary or "{}"),
            "finding_status": json.loads(risk_run.status_summary or "{}"),
            "validation": json.loads(risk_run.validation_summary or "{}"),
        },
        "findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "vulnerability": f.vulnerability,
                "tool_name": f.tool_name,
                "severity": f.severity,
                "risk_level": f.risk_level,
                "cvss_score": f.cvss_score,
                "status": f.status,
                "affected_asset": f.affected_asset,
                "affected_url": f.affected_url,
                "endpoint": f.endpoint,
                "cve_id": f.cve_id,
                "cwe_id": f.cwe_id,
                "owasp_category": f.owasp_category,
                "description": f.description,
                "evidence": f.evidence,
                "impact": f.impact,
                "remediation": f.remediation,
                "references": f.references,
            }
            for f in findings
        ],
    }


async def _run_report(job_id, request, user_id):
    job = REPORT_JOBS[job_id]
    db = SessionLocal = None

    try:
        from database import SessionLocal as DBSession
        db = DBSession()

        job["status"] = "running"
        job["stage"] = "Loading assessment"
        job["progress"] = 15
        await asyncio.sleep(0.1)

        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.id == request.assessment_id,
                Assessment.user_id == user_id,
            )
            .first()
        )

        if not assessment:
            raise ValueError("Assessment not found.")

        job["stage"] = "Loading latest risk assessment"
        job["progress"] = 35
        await asyncio.sleep(0.1)

        risk_run = (
            db.query(RiskAssessmentRun)
            .filter(
                RiskAssessmentRun.assessment_id == assessment.id,
                RiskAssessmentRun.user_id == user_id,
                RiskAssessmentRun.status == "COMPLETED",
            )
            .order_by(RiskAssessmentRun.id.desc())
            .first()
        )

        if not risk_run:
            raise ValueError(
                "Run Stage 08 Risk Assessment before generating the report."
            )

        findings = (
            db.query(SecurityFinding)
            .filter(
                SecurityFinding.assessment_id == assessment.id,
                SecurityFinding.user_id == user_id,
            )
            .order_by(SecurityFinding.created_at.asc())
            .all()
        )

        job["stage"] = "Building canonical report data"
        job["progress"] = 60
        await asyncio.sleep(0.1)

        canonical = _canonical_data(
            assessment,
            risk_run,
            findings,
        )

        record = VAPTReportRun(
            report_run_id=f"VAPT-REP-{uuid4().hex[:12].upper()}",
            job_id=job_id,
            user_id=user_id,
            assessment_id=assessment.id,
            risk_assessment_run_id=risk_run.id,
            status="COMPLETED",
            report_type=request.report_type,
            formats=json.dumps(["JSON", "XML", "PDF"]),
            canonical_data=json.dumps(canonical, default=str),
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        job["stage"] = "Report ready"
        job["progress"] = 100
        job["status"] = "completed"
        job["result"] = _serialize(record)

    except Exception as exc:
        if db:
            db.rollback()

        job["status"] = "failed"
        job["progress"] = 100
        job["error"] = str(exc)

    finally:
        if db:
            db.close()


@router.post("/run")
async def run_report(
    request: ReportRequest,
    current_user=Depends(require_role(1)),
):
    job_id = f"REPORT-{uuid4().hex[:12].upper()}"

    REPORT_JOBS[job_id] = {
        "user_id": current_user.id,
        "status": "queued",
        "progress": 0,
        "stage": "Queued",
        "cancel_requested": False,
    }

    asyncio.create_task(
        _run_report(
            job_id,
            request,
            current_user.id,
        )
    )

    return {
        "job_id": job_id,
        "status": "queued",
    }


@router.get("/{job_id}/progress")

def report_progress(
    job_id: str,
    current_user=Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    job = REPORT_JOBS.get(job_id)
    if job and job.get("user_id") == current_user.id:
        return {
            "job_id": job_id,
            "status": job.get("status"),
            "stage": job.get("stage"),
            "progress": job.get("progress", 0),
            "error": job.get("error"),
        }

    # A persisted completed report remains accessible after a restart.
    record = (
        db.query(VAPTReportRun)
        .filter(
            VAPTReportRun.job_id == job_id,
            VAPTReportRun.user_id == current_user.id,
            VAPTReportRun.status == "COMPLETED",
        )
        .first()
    )
    if record is None:
        raise HTTPException(404, "Report job not found.")

    return {
        "job_id": job_id,
        "status": "completed",
        "stage": "Stored report ready",
        "progress": 100,
        "error": None,
    }


@router.get("/{job_id}/results")

def report_results(
    job_id: str,
    current_user=Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    record = (
        db.query(VAPTReportRun)
        .filter(
            VAPTReportRun.job_id == job_id,
            VAPTReportRun.user_id == current_user.id,
            VAPTReportRun.status == "COMPLETED",
        )
        .first()
    )
    if record is None:
        raise HTTPException(404, "Completed report not found.")
    return _serialize(record)


def _build_canonical_pdf(canonical):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="VAPT Stage 09 Report",
        author="SOC Platform",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "VAPTTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        spaceAfter=12,
    )

    heading_style = ParagraphStyle(
        "VAPTHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        spaceBefore=10,
        spaceAfter=7,
    )

    body_style = ParagraphStyle(
        "VAPTBody",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=12,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "VAPTSmall",
        parent=styles["BodyText"],
        fontSize=7,
        leading=9,
    )

    metadata = canonical.get("report_metadata", {})
    risk = canonical.get("risk_assessment", {})
    severity = risk.get("severity", {})
    risk_levels = risk.get("risk_levels", {})
    validation = risk.get("validation", {})
    findings = canonical.get("findings", [])
    from report_cvss import report_cvss_summary
    cvss_summary = report_cvss_summary(findings)

    story = []

    story.append(Paragraph("VAPT SECURITY ASSESSMENT REPORT", title_style))
    story.append(
        Paragraph(
            f"Assessment #{metadata.get('assessment_id', 'N/A')} "
            f"| Report Type: {metadata.get('report_type', 'COMPLETE')}",
            body_style,
        )
    )
    story.append(
        Paragraph(
            f"<b>Target:</b> {metadata.get('target', 'N/A')}",
            body_style,
        )
    )
    story.append(
        Paragraph(
            f"<b>Generated:</b> {metadata.get('generated_at', 'N/A')}",
            body_style,
        )
    )

    story.append(Paragraph("Risk Assessment Summary", heading_style))

    summary_data = [
        ["Metric", "Value"],
        ["Overall Risk", str(risk.get("overall_risk", "N/A"))],
        ["Total Findings", str(risk.get("total_findings", 0))],
        ["Average CVSS", (
            f"{cvss_summary['average']:.2f}"
            if cvss_summary["average"] is not None
            else "Not available"
        )],
        ["Highest CVSS", (
            f"{cvss_summary['highest']:.1f}"
            if cvss_summary["highest"] is not None
            else "Not available"
        )],
        ["Scored Report Findings", str(cvss_summary["scored_count"])],
        ["Risk Assessment Status", str(risk.get("status", "N/A"))],
    ]

    summary_table = Table(summary_data, colWidths=[65 * mm, 100 * mm])
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(summary_table)
    story.append(Paragraph(
        "CVSS summary uses valid scores from the findings captured in this "
        "report. Unscored findings are excluded; a genuine score of zero is included.",
        body_style,
    ))

    story.append(Paragraph("Severity Distribution", heading_style))

    severity_data = [["Severity", "Count"]]
    for key in ["critical", "high", "medium", "low", "none"]:
        severity_data.append([key.upper(), str(severity.get(key, 0))])

    severity_table = Table(severity_data, colWidths=[65 * mm, 100 * mm])
    severity_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(severity_table)

    story.append(Paragraph("Risk Levels", heading_style))

    risk_data = [["Risk Level", "Count"]]
    for key in ["level_1", "level_2", "level_3"]:
        risk_data.append([key.upper(), str(risk_levels.get(key, 0))])

    risk_table = Table(risk_data, colWidths=[65 * mm, 100 * mm])
    risk_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(risk_table)

    story.append(Paragraph("Validation Summary", heading_style))

    validation_data = [
        ["Validation State", "Count"],
        ["Validated", str(validation.get("validated", 0))],
        ["Partially Validated", str(validation.get("partially_validated", 0))],
        ["Not Validated", str(validation.get("not_validated", 0))],
        ["Validation Not Run", str(validation.get("validation_not_run", 0))],
    ]

    validation_table = Table(
        validation_data,
        colWidths=[65 * mm, 100 * mm],
    )
    validation_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(validation_table)

    story.append(Paragraph("Findings", heading_style))

    finding_data = [[
        "Finding",
        "Tool",
        "Severity",
        "Risk",
        "CVSS",
    ]]

    for finding in findings:
        finding_data.append([
            Paragraph(
                str(finding.get("title") or finding.get("finding_id") or "N/A"),
                small_style,
            ),
            Paragraph(
                str(finding.get("tool_name") or "N/A"),
                small_style,
            ),
            str(finding.get("severity") or "N/A"),
            str(finding.get("risk_level") or "N/A"),
            str(
                finding.get("cvss_score")
                if finding.get("cvss_score") is not None
                else "N/A"
            ),
        ])

    findings_table = Table(
        finding_data,
        colWidths=[70 * mm, 30 * mm, 25 * mm, 25 * mm, 20 * mm],
        repeatRows=1,
    )

    findings_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ])
    )

    story.append(findings_table)

    document.build(story)
    buffer.seek(0)
    return buffer


@router.get("/{job_id}/download/{format_name}")
def download_report(
    job_id: str,
    format_name: str,
    current_user=Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    record = (
        db.query(VAPTReportRun)
        .filter(
            VAPTReportRun.job_id == job_id,
            VAPTReportRun.user_id == current_user.id,
            VAPTReportRun.status == "COMPLETED",
        )
        .first()
    )

    if not record:
        raise HTTPException(404, "Report record not found.")

    data = json.loads(record.canonical_data or "{}")
    fmt = format_name.upper()

    if fmt == "JSON":
        payload = json.dumps(data, indent=2, default=str).encode()
        return StreamingResponse(
            BytesIO(payload),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="VAPT_{record.assessment_id}.json"'},
        )

    if fmt == "XML":
        root = Element("VAPTReport")
        root.text = None

        def add(parent, key, value):
            node = SubElement(parent, str(key))
            if isinstance(value, dict):
                for k, v in value.items():
                    add(node, k, v)
            elif isinstance(value, list):
                for item in value:
                    add(node, "item", item)
            else:
                node.text = "" if value is None else str(value)

        for key, value in data.items():
            add(root, key, value)

        payload = tostring(root, encoding="utf-8", xml_declaration=True)

        return StreamingResponse(
            BytesIO(payload),
            media_type="application/xml",
            headers={"Content-Disposition": f'attachment; filename="VAPT_{record.assessment_id}.xml"'},
        )

    if fmt == "PDF":
        pdf = _build_canonical_pdf(data)

        return StreamingResponse(
            pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="VAPT_{record.assessment_id}.pdf"'},
        )

    raise HTTPException(400, "Supported formats: JSON, XML, PDF.")


@router.get("/history")
def user_report_history(
    search: str = "",
    offset: int = 0,
    page_size: int = 25,
    current_user=Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    if len(search) > 200 or offset < 0 or not 1 <= page_size <= 100:
        raise HTTPException(422, "Invalid search or pagination.")

    # Select metadata only; canonical report content is not part of this list.
    columns = [
        VAPTReportRun.id,
        VAPTReportRun.report_run_id,
        VAPTReportRun.job_id,
        VAPTReportRun.assessment_id,
        VAPTReportRun.risk_assessment_run_id,
        VAPTReportRun.status,
        VAPTReportRun.report_type,
        VAPTReportRun.formats,
        VAPTReportRun.started_at,
        VAPTReportRun.completed_at,
        VAPTReportRun.created_at,
    ]
    query = (
        db.query(*columns)
        .filter(VAPTReportRun.user_id == current_user.id)
        .order_by(VAPTReportRun.created_at.desc(), VAPTReportRun.id.desc())
    )
    needle = search.strip().casefold()
    total = 0
    matched = 0
    page = []

    for record in query.yield_per(200):
        item = dict(record._mapping)
        total += 1
        try:
            formats = json.loads(item["formats"] or "[]")
        except (TypeError, ValueError):
            formats = []
        item["formats"] = [
            value for value in ("PDF", "JSON", "XML")
            if isinstance(formats, list) and value in formats
        ]
        for key in ("started_at", "completed_at", "created_at"):
            value = item[key]
            item[key] = (
                value.isoformat() + ("Z" if value.tzinfo is None else "")
                if value else None
            )

        searchable = " ".join(
            str(item[key] or "")
            for key in (
                "report_run_id", "assessment_id", "status", "report_type",
                "completed_at", "created_at",
            )
        ).casefold()
        if needle and needle not in searchable:
            continue
        if offset <= matched < offset + page_size:
            page.append(item)
        matched += 1

    return {
        "scope": "personal",
        "source": "persisted_vapt_report_runs",
        "total": total,
        "matched_total": matched,
        "offset": offset,
        "next_offset": offset + page_size if offset + page_size < matched else None,
        "reports": page,
    }
