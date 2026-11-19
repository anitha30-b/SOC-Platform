from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import User
from rbac import require_role

router = APIRouter(prefix="/compliance", tags=["Compliance"])

FRAMEWORKS = {
    "ISO 27001": [
        ("A.5.1", "Policies for information security"),
        ("A.5.2", "Information security roles and responsibilities"),
        ("A.5.5", "Contact with authorities"),
        ("A.5.7", "Threat intelligence"),
        ("A.5.9", "Inventory of information and other associated assets"),
        ("A.5.10", "Acceptable use of information and other associated assets"),
        ("A.5.12", "Classification of information"),
        ("A.5.14", "Information transfer"),
        ("A.5.15", "Access control"),
        ("A.5.16", "Identity management"),
        ("A.5.17", "Authentication information"),
        ("A.5.18", "Access rights"),
        ("A.5.19", "Information security in supplier relationships"),
        ("A.5.20", "Addressing information security within supplier agreements"),
        ("A.5.23", "Information security for cloud services"),
        ("A.5.24", "Information security incident management planning and preparation"),
        ("A.5.25", "Assessment and decision on information security events"),
        ("A.5.26", "Response to information security incidents"),
        ("A.5.27", "Learning from information security incidents"),
        ("A.5.28", "Collection of evidence"),
        ("A.5.29", "Information security during disruption"),
        ("A.5.30", "ICT readiness for business continuity"),
        ("A.5.31", "Legal, statutory, regulatory and contractual requirements"),
        ("A.5.34", "Privacy and protection of personally identifiable information"),
        ("A.5.36", "Compliance with policies, rules and standards for information security"),
        ("A.6.3", "Information security awareness, education and training"),
        ("A.7.4", "Physical security monitoring"),
        ("A.8.1", "User endpoint devices"),
        ("A.8.2", "Privileged access rights"),
        ("A.8.5", "Secure authentication"),
        ("A.8.8", "Management of technical vulnerabilities"),
        ("A.8.9", "Configuration management"),
        ("A.8.12", "Data leakage prevention"),
        ("A.8.13", "Information backup"),
        ("A.8.15", "Logging"),
        ("A.8.16", "Monitoring activities"),
        ("A.8.20", "Network security"),
        ("A.8.21", "Security of network services"),
        ("A.8.22", "Segregation of networks"),
        ("A.8.24", "Use of cryptography"),
        ("A.8.25", "Secure development life cycle"),
        ("A.8.28", "Secure coding"),
        ("A.8.32", "Change management"),
    ],
    "SOC 2": [
        ("CC1.1", "Control environment"),
        ("CC1.2", "Board oversight and governance"),
        ("CC1.3", "Management structure and authority"),
        ("CC1.4", "Commitment to competence"),
        ("CC1.5", "Accountability for internal control"),
        ("CC2.1", "Internal communication"),
        ("CC2.2", "Communication with external parties"),
        ("CC2.3", "Communication of security responsibilities"),
        ("CC3.1", "Objectives and risk assessment"),
        ("CC3.2", "Risk identification"),
        ("CC3.3", "Fraud risk assessment"),
        ("CC3.4", "Assessment of significant changes"),
        ("CC4.1", "Ongoing and separate evaluations"),
        ("CC4.2", "Evaluation and communication of deficiencies"),
        ("CC5.1", "Control activities and risk mitigation"),
        ("CC5.2", "Technology general controls"),
        ("CC5.3", "Policies and procedures"),
        ("CC6.1", "Logical access security"),
        ("CC6.2", "User registration and authorization"),
        ("CC6.3", "Access removal and modification"),
        ("CC6.6", "Protection against external threats"),
        ("CC6.7", "Restriction of data transmission"),
        ("CC6.8", "Prevention and detection of malicious software"),
        ("CC7.1", "Vulnerability detection and monitoring"),
        ("CC7.2", "System monitoring"),
        ("CC7.3", "Evaluation of security events"),
        ("CC7.4", "Incident response"),
        ("CC7.5", "Recovery from security incidents"),
        ("CC8.1", "Change management"),
        ("CC9.1", "Risk mitigation related to business disruption"),
        ("CC9.2", "Vendor and business partner risk management"),
    ],
    "NIST CSF": [
        ("GV.OC", "Organizational context"),
        ("GV.RM", "Risk management strategy"),
        ("GV.RR", "Roles, responsibilities and authorities"),
        ("GV.PO", "Policy"),
        ("GV.OV", "Oversight"),
        ("GV.SC", "Cybersecurity supply chain risk management"),
        ("ID.AM", "Asset management"),
        ("ID.RA", "Risk assessment"),
        ("ID.IM", "Improvement"),
        ("PR.AA", "Identity management, authentication and access control"),
        ("PR.AT", "Awareness and training"),
        ("PR.DS", "Data security"),
        ("PR.PS", "Platform security"),
        ("PR.IR", "Technology infrastructure resilience"),
        ("DE.CM", "Continuous monitoring"),
        ("DE.AE", "Adverse event analysis"),
        ("RS.MA", "Incident management"),
        ("RS.AN", "Incident analysis"),
        ("RS.CO", "Incident response reporting and communication"),
        ("RS.MI", "Incident mitigation"),
        ("RC.RP", "Recovery planning"),
        ("RC.CO", "Recovery communication"),
    ],
    "CIS Controls": [
        ("CIS 1", "Inventory and control of enterprise assets"),
        ("CIS 2", "Inventory and control of software assets"),
        ("CIS 3", "Data protection"),
        ("CIS 4", "Secure configuration of enterprise assets and software"),
        ("CIS 5", "Account management"),
        ("CIS 6", "Access control management"),
        ("CIS 7", "Continuous vulnerability management"),
        ("CIS 8", "Audit log management"),
        ("CIS 9", "Email and web browser protections"),
        ("CIS 10", "Malware defenses"),
        ("CIS 11", "Data recovery"),
        ("CIS 12", "Network infrastructure management"),
        ("CIS 13", "Network monitoring and defense"),
        ("CIS 14", "Security awareness and skills training"),
        ("CIS 15", "Service provider management"),
        ("CIS 16", "Application software security"),
        ("CIS 17", "Incident response management"),
        ("CIS 18", "Penetration testing"),
    ],
    "PCI DSS": [
        ("PCI 1", "Install and maintain network security controls"),
        ("PCI 2", "Apply secure configurations to all system components"),
        ("PCI 3", "Protect stored account data"),
        ("PCI 4", "Protect cardholder data with strong cryptography during transmission over open public networks"),
        ("PCI 5", "Protect all systems and networks from malicious software"),
        ("PCI 6", "Develop and maintain secure systems and software"),
        ("PCI 7", "Restrict access to system components and cardholder data by business need to know"),
        ("PCI 8", "Identify users and authenticate access to system components"),
        ("PCI 9", "Restrict physical access to cardholder data"),
        ("PCI 10", "Log and monitor all access to system components and cardholder data"),
        ("PCI 11", "Test security of systems and networks regularly"),
        ("PCI 12", "Support information security with organizational policies and programs"),
    ],
}

STATUSES = {
    "Not Assessed",
    "Compliant",
    "Partially Compliant",
    "Non-Compliant",
    "Not Applicable",
}


class ControlUpdate(BaseModel):
    status: str = "Not Assessed"
    notes: str = Field(default="", max_length=5000)
    owner: str = Field(default="", max_length=150)
    evidence_reference: str = Field(default="", max_length=500)


def ensure_table(db: Session):
    from sqlalchemy import text

    db.execute(text("""
        CREATE TABLE IF NOT EXISTS compliance_assessments (
            id SERIAL PRIMARY KEY,
            framework VARCHAR(80) NOT NULL,
            control_id VARCHAR(80) NOT NULL,
            title VARCHAR(300) NOT NULL,
            status VARCHAR(40) NOT NULL DEFAULT 'Not Assessed',
            notes TEXT NOT NULL DEFAULT '',
            owner VARCHAR(150) NOT NULL DEFAULT '',
            evidence_reference VARCHAR(500) NOT NULL DEFAULT '',
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            updated_by VARCHAR(100) NOT NULL DEFAULT '',
            UNIQUE (framework, control_id)
        )
    """))
    db.commit()


def seed_framework(db: Session, framework: str):
    from sqlalchemy import text

    for control_id, title in FRAMEWORKS[framework]:
        db.execute(
            text("""
                INSERT INTO compliance_assessments
                    (framework, control_id, title)
                VALUES (:framework, :control_id, :title)
                ON CONFLICT (framework, control_id) DO NOTHING
            """),
            {
                "framework": framework,
                "control_id": control_id,
                "title": title,
            },
        )
    db.commit()


def ensure_all(db: Session):
    ensure_table(db)
    for framework in FRAMEWORKS:
        seed_framework(db, framework)


def row_dict(row):
    return {
        "id": row["id"],
        "framework": row["framework"],
        "control_id": row["control_id"],
        "title": row["title"],
        "status": row["status"],
        "notes": row["notes"],
        "owner": row["owner"],
        "evidence_reference": row["evidence_reference"],
        "updated_at": (
            row["updated_at"].isoformat()
            if row["updated_at"] else None
        ),
        "updated_by": row["updated_by"],
    }


@router.get("/frameworks")
def list_frameworks(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    ensure_all(db)
    from sqlalchemy import text

    result = db.execute(text("""
        SELECT framework, COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'Compliant') AS compliant,
            COUNT(*) FILTER (WHERE status = 'Partially Compliant') AS partial,
            COUNT(*) FILTER (WHERE status = 'Non-Compliant') AS non_compliant,
            COUNT(*) FILTER (WHERE status = 'Not Assessed') AS not_assessed
        FROM compliance_assessments
        GROUP BY framework
        ORDER BY framework
    """)).mappings().all()

    return {
        "frameworks": [dict(row) for row in result],
        "available_frameworks": list(FRAMEWORKS.keys()),
    }


@router.get("/controls")
def list_controls(
    framework: str = Query(...),
    status: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=400, detail="Unsupported framework.")

    ensure_table(db)
    seed_framework(db, framework)

    from sqlalchemy import text

    query = """
        SELECT * FROM compliance_assessments
        WHERE framework = :framework
    """
    params = {"framework": framework}

    if status:
        if status not in STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status.")
        query += " AND status = :status"
        params["status"] = status

    query += " ORDER BY control_id"

    rows = db.execute(text(query), params).mappings().all()
    return {
        "framework": framework,
        "controls": [row_dict(row) for row in rows],
        "statuses": sorted(STATUSES),
    }


@router.put("/controls/{control_id}")
def update_control(
    control_id: str,
    framework: str = Query(...),
    payload: ControlUpdate = ...,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=400, detail="Unsupported framework.")
    if payload.status not in STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status.")

    ensure_table(db)
    seed_framework(db, framework)

    from sqlalchemy import text

    user_name = getattr(current_user, "username", "") or ""
    result = db.execute(
        text("""
            UPDATE compliance_assessments
            SET status = :status,
                notes = :notes,
                owner = :owner,
                evidence_reference = :evidence_reference,
                updated_at = :updated_at,
                updated_by = :updated_by
            WHERE framework = :framework AND control_id = :control_id
            RETURNING *
        """),
        {
            "status": payload.status,
            "notes": payload.notes,
            "owner": payload.owner,
            "evidence_reference": payload.evidence_reference,
            "updated_at": datetime.now(timezone.utc),
            "updated_by": user_name,
            "framework": framework,
            "control_id": control_id,
        },
    ).mappings().first()

    if not result:
        db.rollback()
        raise HTTPException(status_code=404, detail="Control not found.")

    db.commit()
    return {"message": "Compliance assessment saved.", "control": row_dict(result)}


@router.get("/dashboard")
def compliance_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    ensure_all(db)
    from sqlalchemy import text

    rows = db.execute(text("""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'Compliant') AS compliant,
            COUNT(*) FILTER (WHERE status = 'Partially Compliant') AS partial,
            COUNT(*) FILTER (WHERE status = 'Non-Compliant') AS non_compliant,
            COUNT(*) FILTER (WHERE status = 'Not Assessed') AS not_assessed,
            COUNT(*) FILTER (WHERE status = 'Not Applicable') AS not_applicable
        FROM compliance_assessments
    """)).mappings().one()

    total = rows["total"] or 0
    applicable = total - rows["not_applicable"]
    assessed = applicable - rows["not_assessed"]
    percentage = round(
        rows["compliant"] * 100 / applicable, 1
    ) if applicable else 0

    return {
        "total_controls": total,
        "compliant": rows["compliant"],
        "partially_compliant": rows["partial"],
        "non_compliant": rows["non_compliant"],
        "not_assessed": rows["not_assessed"],
        "not_applicable": rows["not_applicable"],
        "assessed": assessed,
        "compliance_percentage": percentage,
        "open_gaps": rows["partial"] + rows["non_compliant"],
        "framework_count": len(FRAMEWORKS),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/reports")
def compliance_report(
    framework: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    ensure_all(db)
    from sqlalchemy import text

    if framework and framework not in FRAMEWORKS:
        raise HTTPException(status_code=400, detail="Unsupported framework.")

    query = "SELECT * FROM compliance_assessments"
    params = {}
    if framework:
        query += " WHERE framework = :framework"
        params["framework"] = framework
    query += " ORDER BY framework, control_id"

    rows = db.execute(text(query), params).mappings().all()
    controls = [row_dict(row) for row in rows]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework": framework or "All frameworks",
        "total_controls": len(controls),
        "compliant": sum(c["status"] == "Compliant" for c in controls),
        "open_gaps": sum(
            c["status"] in {"Partially Compliant", "Non-Compliant"}
            for c in controls
        ),
        "controls": controls,
    }
