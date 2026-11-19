import re
from datetime import datetime
from email.parser import Parser, BytesParser
from email.policy import default
from email.utils import parseaddr

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import EmailHeaderAnalysis
from rbac import require_role


router = APIRouter(
    prefix="/admin/email-header-analysis",
    tags=["Admin Email Header Analysis"],
)

MAX_HEADER_SIZE = 64 * 1024
MAX_EML_SIZE = 1024 * 1024


class HeaderAnalysisRequest(BaseModel):
    raw_headers: str = Field(min_length=1, max_length=MAX_HEADER_SIZE)


def extract_domain(value):
    if not value:
        return None

    address = parseaddr(str(value))[1].strip().lower()

    if "@" not in address:
        return None

    domain = address.rsplit("@", 1)[1].rstrip(".")
    if not domain or "." not in domain:
        return None

    return domain


def analyze_headers(message):
    sender = str(message.get("From", "")) or None
    reply_to = str(message.get("Reply-To", "")) or None
    return_path = str(message.get("Return-Path", "")) or None
    subject = str(message.get("Subject", "")) or None

    from_domain = extract_domain(sender)
    reply_domain = extract_domain(reply_to)
    return_domain = extract_domain(return_path)

    indicators = []
    score = 0

    if not sender:
        indicators.append({
            "severity": "MEDIUM",
            "message": "The From header is missing.",
        })
        score += 15
    elif not from_domain:
        indicators.append({
            "severity": "MEDIUM",
            "message": "The From address could not be reliably parsed.",
        })
        score += 10

    if reply_domain and from_domain and reply_domain != from_domain:
        indicators.append({
            "severity": "HIGH",
            "message": "Reply-To domain differs from the From domain.",
        })
        score += 25

    if return_domain and from_domain and return_domain != from_domain:
        indicators.append({
            "severity": "LOW",
            "message": "Return-Path domain differs from the From domain. This can also occur with legitimate mailing services.",
        })
        score += 5

    auth_headers = message.get_all("Authentication-Results", [])
    received_spf_headers = message.get_all("Received-SPF", [])

    auth_text = " ".join(str(value) for value in auth_headers)
    spf_text = " ".join(str(value) for value in received_spf_headers)

    combined_auth = (auth_text + " " + spf_text).lower()

    authentication_results = {
        "spf": "NOT_REPORTED",
        "dkim": "NOT_REPORTED",
        "dmarc": "NOT_REPORTED",
        "source": "Reported by supplied email headers; not independently verified.",
    }

    def auth_status(method):
        match = re.search(
            rf"\b{method}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)\b",
            combined_auth,
        )
        return match.group(1).upper() if match else "NOT_REPORTED"

    authentication_results["spf"] = auth_status("spf")
    authentication_results["dkim"] = auth_status("dkim")
    authentication_results["dmarc"] = auth_status("dmarc")

    auth_weights = {
        "spf": {"FAIL": 25, "SOFTFAIL": 10, "PERMERROR": 15},
        "dkim": {"FAIL": 20, "PERMERROR": 15},
        "dmarc": {"FAIL": 25, "PERMERROR": 15},
    }

    for method, weights in auth_weights.items():
        status = authentication_results[method]

        if status in weights:
            indicators.append({
                "severity": "HIGH" if status == "FAIL" else "MEDIUM",
                "message": f"Header-reported {method.upper()} result: {status}.",
            })
            score += weights[status]

    if not auth_headers and not received_spf_headers:
        indicators.append({
            "severity": "INFO",
            "message": "No Authentication-Results or Received-SPF header was supplied.",
        })

    score = min(score, 100)

    if score >= 75:
        risk_level = "CRITICAL"
    elif score >= 50:
        risk_level = "HIGH"
    elif score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "from_domain": from_domain,
        "risk_score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "authentication_results": authentication_results,
        "received_hops": len(message.get_all("Received", [])),
        "message_id_present": bool(message.get("Message-ID")),
        "analysis_note": (
            "This is a heuristic header analysis, not a definitive phishing verdict. "
            "Authentication results are interpreted from supplied headers only."
        ),
    }


def save_analysis(db, current_user, result):
    record = EmailHeaderAnalysis(
        admin_user_id=current_user.id,
        sender=result["sender"],
        reply_to=result["reply_to"],
        subject=result["subject"],
        from_domain=result["from_domain"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        indicators=result["indicators"],
        authentication_results=result["authentication_results"],
    )

    try:
        db.add(record)
        db.commit()
        db.refresh(record)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to save email header analysis.",
        )

    result["id"] = record.id
    result["created_at"] = record.created_at.isoformat()
    return result


@router.post("/analyze")
def analyze_pasted_headers(
    request: HeaderAnalysisRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(3)),
):
    try:
        message = Parser(policy=default).parsestr(request.raw_headers)
        result = analyze_headers(message)
        return save_analysis(db, current_user, result)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to parse the supplied email headers.",
        )


@router.post("/analyze-eml")
async def analyze_eml_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(require_role(3)),
):
    filename = (file.filename or "").lower()

    if not filename.endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported.",
        )

    content = await file.read(MAX_EML_SIZE + 1)

    if len(content) > MAX_EML_SIZE:
        raise HTTPException(
            status_code=413,
            detail="The .eml file must not exceed 1 MB.",
        )

    await file.close()

    separator = b"\r\n\r\n"
    if separator not in content:
        separator = b"\n\n"

    header_bytes = content.split(separator, 1)[0]

    if not header_bytes or len(header_bytes) > MAX_HEADER_SIZE:
        raise HTTPException(
            status_code=400,
            detail="The email header is empty or exceeds the 64 KB limit.",
        )

    try:
        message = BytesParser(policy=default).parsebytes(header_bytes + b"\r\n\r\n")
        result = analyze_headers(message)
        return save_analysis(db, current_user, result)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to parse the uploaded email headers.",
        )


@router.get("/history")
def get_analysis_history(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(3)),
):
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100.",
        )

    records = (
        db.query(EmailHeaderAnalysis)
        .filter(EmailHeaderAnalysis.admin_user_id == current_user.id)
        .order_by(EmailHeaderAnalysis.created_at.desc())
        .limit(limit)
        .all()
    )

    return {
        "analyses": [
            {
                "id": record.id,
                "sender": record.sender,
                "reply_to": record.reply_to,
                "subject": record.subject,
                "from_domain": record.from_domain,
                "risk_score": record.risk_score,
                "risk_level": record.risk_level,
                "indicators": record.indicators,
                "authentication_results": record.authentication_results,
                "created_at": record.created_at.isoformat(),
            }
            for record in records
        ]
    }
