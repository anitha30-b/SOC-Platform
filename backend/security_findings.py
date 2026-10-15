from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import Assessment, SecurityFinding, SecurityTool, User
from rbac import require_role
from cve import fetch_cve_information


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/security-findings",
    tags=["Security Findings"],
)


# ============================================================
# 30 SECURITY TOOLS
# ============================================================

SECURITY_TOOLS = [
    # --------------------------------------------------------
    # WEB APPLICATION SECURITY
    # --------------------------------------------------------
    {
        "name": "OWASP Top 10",
        "category": "Web Application Security",
        "description": "OWASP framework for identifying and classifying major web application security risks.",
        "tool_type": "framework",
    },
    {
        "name": "Burp Suite",
        "category": "Web Application Security",
        "description": "Web application security testing platform for intercepting, testing and analyzing HTTP traffic.",
        "tool_type": "scanner",
    },
    {
        "name": "OWASP ZAP",
        "category": "Web Application Security",
        "description": "OWASP open-source web application security scanner and proxy.",
        "tool_type": "scanner",
    },
    {
        "name": "Nikto",
        "category": "Web Application Security",
        "description": "Web server scanner for dangerous files, outdated software and server misconfigurations.",
        "tool_type": "scanner",
    },
    {
        "name": "Nuclei",
        "category": "Web Application Security",
        "description": "Template-based vulnerability and exposure scanner.",
        "tool_type": "scanner",
    },

    # --------------------------------------------------------
    # API SECURITY
    # --------------------------------------------------------
    {
        "name": "OWASP API Security Top 10",
        "category": "API Security",
        "description": "OWASP framework for identifying and classifying major API security risks.",
        "tool_type": "framework",
    },
    {
        "name": "OWASP API Security Testing Framework",
        "category": "API Security",
        "description": "Framework for automated API security testing aligned with OWASP API Security risks.",
        "tool_type": "framework",
    },
    {
        "name": "Postman",
        "category": "API Security",
        "description": "API development and testing platform that can be used for controlled security testing.",
        "tool_type": "testing",
    },
    {
        "name": "ffuf",
        "category": "API Security",
        "description": "Fast web and API content discovery and fuzzing utility.",
        "tool_type": "discovery",
    },
    {
        "name": "Kiterunner",
        "category": "API Security",
        "description": "API endpoint and route discovery tool.",
        "tool_type": "discovery",
    },

    # --------------------------------------------------------
    # NETWORK SECURITY
    # --------------------------------------------------------
    {
        "name": "Nmap",
        "category": "Network Security",
        "description": "Network discovery, port scanning and service identification tool.",
        "tool_type": "scanner",
    },
    {
        "name": "DNS Recon",
        "category": "Network Security",
        "description": "DNS reconnaissance and enumeration tool for discovering DNS records, name servers and related domain information.",
        "tool_type": "discovery",
    },
    {
        "name": "dig",
        "category": "Network Security",
        "description": "DNS query utility for retrieving DNS records and resolving domain information.",
        "tool_type": "discovery",
    },
    {
        "name": "nslookup",
        "category": "Network Security",
        "description": "DNS lookup utility for querying DNS servers and resolving domain and host information.",
        "tool_type": "discovery",
    },
    {
        "name": "Ping",
        "category": "Network Security",
        "description": "Network connectivity and host reachability testing utility using ICMP echo requests.",
        "tool_type": "discovery",
    },
    {
        "name": "WHOIS",
        "category": "Network Security",
        "description": "Domain and IP registration information lookup utility.",
        "tool_type": "discovery",
    },
    {
        "name": "Masscan",
        "category": "Network Security",
        "description": "High-speed TCP port scanner for large-scale network discovery.",
        "tool_type": "scanner",
    },
    {
        "name": "RustScan",
        "category": "Network Security",
        "description": "Fast port discovery scanner that can feed discovered ports into other security tools.",
        "tool_type": "scanner",
    },
    {
        "name": "Wireshark",
        "category": "Network Security",
        "description": "Network protocol and packet analysis platform.",
        "tool_type": "analysis",
    },
    {
        "name": "hping3",
        "category": "Network Security",
        "description": "Network packet crafting and protocol testing utility.",
        "tool_type": "testing",
    },
    {
        "name": "TShark",
        "category": "Network Security",
        "description": "Command-line packet capture and network protocol analysis utility.",
        "tool_type": "analysis",
    },
    {
        "name": "Snort",
        "category": "Network Security",
        "description": "Network intrusion detection and traffic analysis system.",
        "tool_type": "sensor",
    },

    # --------------------------------------------------------
    # INFRASTRUCTURE / VULNERABILITY MANAGEMENT
    # --------------------------------------------------------
    {
        "name": "OpenVAS / Greenbone",
        "category": "Infrastructure Security",
        "description": "Vulnerability assessment and management platform.",
        "tool_type": "scanner",
    },
    {
        "name": "Nessus",
        "category": "Infrastructure Security",
        "description": "Infrastructure and vulnerability assessment scanner.",
        "tool_type": "scanner",
    },
    {
        "name": "Lynis",
        "category": "Infrastructure Security",
        "description": "Security auditing and hardening assessment tool for Linux and Unix systems.",
        "tool_type": "auditor",
    },
    {
        "name": "OpenSCAP",
        "category": "Infrastructure Security",
        "description": "Security configuration, compliance and vulnerability assessment framework.",
        "tool_type": "compliance",
    },
    {
        "name": "Trivy",
        "category": "Infrastructure Security",
        "description": "Scanner for containers, images, dependencies, configurations and vulnerabilities.",
        "tool_type": "scanner",
    },

    # --------------------------------------------------------
    # PENETRATION TESTING
    # --------------------------------------------------------
    {
        "name": "Metasploit Framework",
        "category": "Penetration Testing",
        "description": "Penetration testing framework for controlled exploit validation.",
        "tool_type": "framework",
    },
    {
        "name": "SQLmap",
        "category": "Penetration Testing",
        "description": "Automated SQL injection testing and database security assessment tool.",
        "tool_type": "testing",
    },
    {
        "name": "Hydra",
        "category": "Penetration Testing",
        "description": "Network authentication security testing tool.",
        "tool_type": "testing",
    },
    {
        "name": "John the Ripper",
        "category": "Penetration Testing",
        "description": "Password hash auditing and password strength testing tool.",
        "tool_type": "testing",
    },
    {
        "name": "Hashcat",
        "category": "Penetration Testing",
        "description": "Password recovery and hash auditing platform used for controlled security testing.",
        "tool_type": "testing",
    },

    # --------------------------------------------------------
    # DISCOVERY / TLS / CODE / DEPENDENCY SECURITY
    # --------------------------------------------------------
    {
        "name": "Gobuster",
        "category": "Discovery",
        "description": "Directory, DNS and virtual host discovery utility.",
        "tool_type": "discovery",
    },
    {
        "name": "Amass",
        "category": "Discovery",
        "description": "Attack-surface discovery and external asset enumeration tool.",
        "tool_type": "discovery",
    },
    {
        "name": "testssl.sh",
        "category": "TLS Security",
        "description": "TLS/SSL protocol, cipher and certificate security analysis tool.",
        "tool_type": "scanner",
    },
    {
        "name": "Semgrep",
        "category": "Code Security",
        "description": "Static analysis and security rule engine for source code.",
        "tool_type": "sast",
    },
    {
        "name": "OWASP Dependency-Check",
        "category": "Software Supply Chain Security",
        "description": "Identifies known vulnerabilities in project dependencies.",
        "tool_type": "sca",
    },

    # --------------------------------------------------------
    # POST-EXPLOITATION / VALIDATION
    # --------------------------------------------------------
    {
        "name": "Access / Impact Validation",
        "category": "Post-Exploitation",
        "description": "Controlled validation workflow for verifying affected-resource access and assessing recorded security impact.",
        "tool_type": "validation",
    },

    # --------------------------------------------------------
    # RISK ASSESSMENT
    # --------------------------------------------------------
    {
        "name": "Risk Assessment Engine",
        "category": "Risk Assessment",
        "description": "Risk assessment workflow using actual security findings, CVSS severity, risk levels and validation results.",
        "tool_type": "assessment",
    },

    # --------------------------------------------------------
    # REPORTING
    # --------------------------------------------------------
    {
        "name": "VAPT Report Generator",
        "category": "Reporting",
        "description": "Generate evidence-based VAPT reports from actual assessment, finding and risk data.",
        "tool_type": "reporting",
    },
]


# ============================================================
# PYDANTIC SCHEMAS
# ============================================================

class SecurityToolResponse(BaseModel):
    id: int
    name: str
    category: str
    description: Optional[str] = None
    tool_type: str
    enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


class SecurityFindingCreate(BaseModel):
    assessment_id: int

    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=150,
    )

    tool_category: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    title: str = Field(
        ...,
        min_length=1,
        max_length=500,
    )

    vulnerability: Optional[str] = Field(
        default=None,
        max_length=500,
    )

    description: Optional[str] = None

    owasp_category: Optional[str] = Field(
        default=None,
        max_length=150,
    )

    owasp_api_category: Optional[str] = Field(
        default=None,
        max_length=150,
    )

    cve_id: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    cwe_id: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    cvss_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
    )

    affected_asset: Optional[str] = Field(
        default=None,
        max_length=500,
    )

    affected_url: Optional[str] = Field(
        default=None,
        max_length=1000,
    )

    endpoint: Optional[str] = Field(
        default=None,
        max_length=1000,
    )

    parameter: Optional[str] = Field(
        default=None,
        max_length=500,
    )

    evidence: Optional[str] = None

    request_data: Optional[str] = None

    response_data: Optional[str] = None

    impact: Optional[str] = None

    remediation: Optional[str] = None

    references: Optional[str] = None


class SecurityFindingResponse(BaseModel):
    id: int
    finding_id: str

    user_id: int
    assessment_id: int

    tool_name: str
    tool_category: Optional[str] = None

    title: str
    vulnerability: Optional[str] = None
    description: Optional[str] = None

    owasp_category: Optional[str] = None
    owasp_api_category: Optional[str] = None

    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None

    cvss_score: Optional[float] = None
    severity: str
    risk_level: str

    affected_asset: Optional[str] = None
    affected_url: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None

    evidence: Optional[str] = None
    request_data: Optional[str] = None
    response_data: Optional[str] = None

    impact: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[str] = None

    status: str

    detected_at: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SecurityFindingStatusUpdate(BaseModel):
    status: str = Field(
        ...,
        pattern="^(OPEN|IN_PROGRESS|FIXED|ACCEPTED|FALSE_POSITIVE)$",
    )


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_severity(
    cvss_score: Optional[float],
) -> str:
    """
    Convert CVSS score into qualitative severity.

    CVSS:
        0.0       -> NONE
        0.1-3.9   -> LOW
        4.0-6.9   -> MEDIUM
        7.0-8.9   -> HIGH
        9.0-10.0  -> CRITICAL
    """

    if cvss_score is None:
        return "LOW"

    if cvss_score == 0:
        return "NONE"

    if cvss_score < 4.0:
        return "LOW"

    if cvss_score < 7.0:
        return "MEDIUM"

    if cvss_score < 9.0:
        return "HIGH"

    return "CRITICAL"


def calculate_risk_level(
    severity: str,
) -> str:
    """
    Application-specific three-level classification.

    LEVEL_1 -> Critical / High
    LEVEL_2 -> Medium
    LEVEL_3 -> Low / None
    """

    severity = severity.upper()

    if severity in {"CRITICAL", "HIGH"}:
        return "LEVEL_1"

    if severity == "MEDIUM":
        return "LEVEL_2"

    return "LEVEL_3"


# ============================================================
# FINDING ID GENERATOR
# ============================================================

def generate_finding_id(
    db: Session,
) -> str:
    """
    Generate IDs such as:
    FIND-000001
    FIND-000002
    """

    latest = (
        db.query(SecurityFinding)
        .order_by(
            SecurityFinding.id.desc()
        )
        .first()
    )

    if not latest:
        next_id = 1
    else:
        next_id = latest.id + 1

    return f"FIND-{next_id:06d}"


# ============================================================
# SEED 30 TOOLS
# ============================================================

def seed_security_tools(
    db: Session,
):
    """
    Insert the 30 security tools if they do not already exist.
    Safe to run multiple times.
    """

    for tool_data in SECURITY_TOOLS:

        existing = (
            db.query(SecurityTool)
            .filter(
                SecurityTool.name
                == tool_data["name"]
            )
            .first()
        )

        if existing:
            continue

        tool = SecurityTool(
            name=tool_data["name"],
            category=tool_data["category"],
            description=tool_data["description"],
            tool_type=tool_data["tool_type"],
            enabled=True,
        )

        db.add(tool)

    db.commit()


# ============================================================
# GET SECURITY TOOLS
# ============================================================

@router.get(
    "/tools",
    response_model=list[SecurityToolResponse],
)
def get_security_tools(
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    """
    Return all enabled security tools
    for the logged-in User.
    """

    seed_security_tools(db)

    tools = (
        db.query(SecurityTool)
        .filter(
            SecurityTool.enabled == True
        )
        .order_by(
            SecurityTool.category.asc(),
            SecurityTool.name.asc(),
        )
        .all()
    )

    return tools


# ============================================================
# CREATE SECURITY FINDING
# ============================================================

@router.post(
    "",
    response_model=SecurityFindingResponse,
)
def create_security_finding(
    payload: SecurityFindingCreate,
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    """
    Create a finding only inside an assessment
    owned by the currently authenticated User.

    When a CVE is supplied, the backend automatically
    attempts NVD enrichment.
    """

    # --------------------------------------------------------
    # Validate assessment ownership
    # --------------------------------------------------------

    assessment = (
        db.query(Assessment)
        .filter(
            Assessment.id
            == payload.assessment_id,

            Assessment.user_id
            == current_user.id,
        )
        .first()
    )

    if not assessment:
        raise HTTPException(
            status_code=404,
            detail=(
                "Assessment not found or does not "
                "belong to the current user."
            ),
        )

    # --------------------------------------------------------
    # Validate security tool
    # --------------------------------------------------------

    seed_security_tools(db)

    tool = (
        db.query(SecurityTool)
        .filter(
            func.lower(SecurityTool.name)
            == payload.tool_name.lower()
        )
        .first()
    )

    if not tool:
        raise HTTPException(
            status_code=400,
            detail=(
                "Security tool is not registered "
                "in the SOC Platform tool catalog."
            ),
        )

    # --------------------------------------------------------
    # Prepare enrichment values
    # --------------------------------------------------------

    final_cve_id = payload.cve_id
    final_cwe_id = payload.cwe_id
    final_description = payload.description
    final_cvss_score = payload.cvss_score
    final_references = payload.references

    # --------------------------------------------------------
    # Automatic NVD CVE enrichment
    # --------------------------------------------------------

    if payload.cve_id:
        try:
            cve_intelligence = fetch_cve_information(
                payload.cve_id
            )

            final_cve_id = (
                cve_intelligence.get("cve_id")
                or payload.cve_id
            )

            # Use NVD CWE when scanner did not provide one
            if not final_cwe_id:
                nvd_cwe = cve_intelligence.get(
                    "cwe",
                    [],
                )

                if nvd_cwe:
                    final_cwe_id = ", ".join(
                        nvd_cwe
                    )

            # Use NVD description when local description
            # is missing
            if not final_description:
                final_description = (
                    cve_intelligence.get(
                        "description"
                    )
                )

            # Use NVD CVSS when scanner did not provide
            # a score
            if final_cvss_score is None:
                nvd_cvss = cve_intelligence.get(
                    "cvss",
                    {},
                )

                final_cvss_score = (
                    nvd_cvss.get("score")
                )

            # Use NVD references when local references
            # are missing
            if not final_references:
                nvd_references = (
                    cve_intelligence.get(
                        "references",
                        [],
                    )
                )

                if nvd_references:
                    final_references = "\n".join(
                        nvd_references
                    )

        except Exception as exc:
            # NVD should enrich the finding, but it should
            # never prevent the scanner result from being saved.
            print(
                "NVD enrichment failed:",
                str(exc),
            )

    # --------------------------------------------------------
    # CVSS calculation
    # --------------------------------------------------------

    severity = calculate_severity(
        final_cvss_score
    )

    risk_level = calculate_risk_level(
        severity
    )

    # --------------------------------------------------------
    # Create finding
    # --------------------------------------------------------

    now = datetime.utcnow()

    finding = SecurityFinding(
        finding_id=generate_finding_id(db),

        user_id=current_user.id,
        assessment_id=assessment.id,

        tool_name=tool.name,
        tool_category=(
            payload.tool_category
            or tool.category
        ),

        title=payload.title,
        vulnerability=payload.vulnerability,
        description=final_description,

        owasp_category=payload.owasp_category,
        owasp_api_category=(
            payload.owasp_api_category
        ),

        cve_id=final_cve_id,
        cwe_id=final_cwe_id,

        cvss_score=final_cvss_score,
        severity=severity,
        risk_level=risk_level,

        affected_asset=payload.affected_asset,
        affected_url=payload.affected_url,
        endpoint=payload.endpoint,
        parameter=payload.parameter,

        evidence=payload.evidence,
        request_data=payload.request_data,
        response_data=payload.response_data,

        impact=payload.impact,
        remediation=payload.remediation,
        references=final_references,

        status="OPEN",

        detected_at=now,
        created_at=now,
        updated_at=now,
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    # --------------------------------------------------------
    # Update assessment finding count
    # --------------------------------------------------------

    assessment.vapt_findings_count = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.assessment_id
            == assessment.id
        )
        .count()
    )

    db.commit()
    db.refresh(finding)

    return finding


# ============================================================
# GET CURRENT USER FINDINGS
# ============================================================

@router.get(
    "",
    response_model=list[SecurityFindingResponse],
)
def get_security_findings(
    assessment_id: Optional[int] = Query(
        default=None
    ),

    tool: Optional[str] = Query(
        default=None
    ),

    severity: Optional[str] = Query(
        default=None
    ),

    risk_level: Optional[str] = Query(
        default=None
    ),

    status: Optional[str] = Query(
        default=None
    ),

    cve: Optional[str] = Query(
        default=None
    ),

    owasp: Optional[str] = Query(
        default=None
    ),

    owasp_api: Optional[str] = Query(
        default=None
    ),

    current_user: User = Depends(
        require_role(1)
    ),

    db: Session = Depends(get_db),
):
    """
    Get findings belonging only to the
    authenticated User.
    """

    query = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.user_id
            == current_user.id
        )
    )

    if assessment_id is not None:
        query = query.filter(
            SecurityFinding.assessment_id
            == assessment_id
        )

    if tool:
        query = query.filter(
            func.lower(
                SecurityFinding.tool_name
            )
            == tool.lower()
        )

    if severity:
        query = query.filter(
            func.lower(
                SecurityFinding.severity
            )
            == severity.lower()
        )

    if risk_level:
        query = query.filter(
            func.lower(
                SecurityFinding.risk_level
            )
            == risk_level.lower()
        )

    if status:
        query = query.filter(
            func.lower(
                SecurityFinding.status
            )
            == status.lower()
        )

    if cve:
        query = query.filter(
            func.lower(
                SecurityFinding.cve_id
            )
            == cve.lower()
        )

    if owasp:
        query = query.filter(
            func.lower(
                SecurityFinding.owasp_category
            )
            == owasp.lower()
        )

    if owasp_api:
        query = query.filter(
            func.lower(
                SecurityFinding.owasp_api_category
            )
            == owasp_api.lower()
        )

    findings = (
        query
        .order_by(
            SecurityFinding.created_at.desc()
        )
        .all()
    )

    return findings


# ============================================================
# GET SECURITY FINDING STATISTICS
# ============================================================

@router.get(
    "/stats/summary",
)
def get_security_finding_statistics(
    assessment_id: Optional[int] = Query(
        default=None
    ),

    current_user: User = Depends(
        require_role(1)
    ),

    db: Session = Depends(get_db),
):
    """
    Return dashboard statistics for the
    current user's findings.
    """

    query = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.user_id
            == current_user.id
        )
    )

    if assessment_id is not None:
        query = query.filter(
            SecurityFinding.assessment_id
            == assessment_id
        )

    findings = query.all()

    total = len(findings)

    critical = sum(
        1
        for f in findings
        if f.severity == "CRITICAL"
    )

    high = sum(
        1
        for f in findings
        if f.severity == "HIGH"
    )

    medium = sum(
        1
        for f in findings
        if f.severity == "MEDIUM"
    )

    low = sum(
        1
        for f in findings
        if f.severity == "LOW"
    )

    none_count = sum(
        1
        for f in findings
        if f.severity == "NONE"
    )

    level_1 = sum(
        1
        for f in findings
        if f.risk_level == "LEVEL_1"
    )

    level_2 = sum(
        1
        for f in findings
        if f.risk_level == "LEVEL_2"
    )

    level_3 = sum(
        1
        for f in findings
        if f.risk_level == "LEVEL_3"
    )

    open_count = sum(
        1
        for f in findings
        if f.status == "OPEN"
    )

    in_progress_count = sum(
        1
        for f in findings
        if f.status == "IN_PROGRESS"
    )

    fixed_count = sum(
        1
        for f in findings
        if f.status == "FIXED"
    )

    accepted_count = sum(
        1
        for f in findings
        if f.status == "ACCEPTED"
    )

    false_positive_count = sum(
        1
        for f in findings
        if f.status == "FALSE_POSITIVE"
    )

    cvss_values = [
        float(f.cvss_score)
        for f in findings
        if f.cvss_score is not None
    ]

    average_cvss = (
        round(
            sum(cvss_values)
            / len(cvss_values),
            2,
        )
        if cvss_values
        else 0.0
    )

    highest_cvss = (
        round(
            max(cvss_values),
            1,
        )
        if cvss_values
        else 0.0
    )

    return {
        "total_findings": total,

        "severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "none": none_count,
        },

        "risk_levels": {
            "level_1": level_1,
            "level_2": level_2,
            "level_3": level_3,
        },

        "status": {
            "open": open_count,
            "in_progress": in_progress_count,
            "fixed": fixed_count,
            "accepted": accepted_count,
            "false_positive": false_positive_count,
        },

        "cvss": {
            "average": average_cvss,
            "highest": highest_cvss,
        },
    }


# ============================================================
# GET SINGLE FINDING
# ============================================================

@router.get(
    "/{finding_id}",
    response_model=SecurityFindingResponse,
)
def get_security_finding(
    finding_id: str,

    current_user: User = Depends(
        require_role(1)
    ),

    db: Session = Depends(get_db),
):
    """
    Get a single finding belonging to
    the authenticated User.
    """

    finding = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.finding_id
            == finding_id,

            SecurityFinding.user_id
            == current_user.id,
        )
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Security finding not found.",
        )

    return finding


# ============================================================
# UPDATE FINDING STATUS
# ============================================================

@router.put(
    "/{finding_id}/status",
    response_model=SecurityFindingResponse,
)
def update_security_finding_status(
    finding_id: str,

    payload: SecurityFindingStatusUpdate,

    current_user: User = Depends(
        require_role(1)
    ),

    db: Session = Depends(get_db),
):
    """
    Update a finding status.
    """

    finding = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.finding_id
            == finding_id,

            SecurityFinding.user_id
            == current_user.id,
        )
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Security finding not found.",
        )

    finding.status = payload.status
    finding.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(finding)

    return finding
# ============================================================
# VAPT ANALYTICS - FINDINGS BY SEVERITY
# ============================================================

@router.get("/stats/by-severity")
def get_findings_by_severity(
    assessment_id: Optional[int] = Query(default=None),
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """
    Return real SecurityFinding counts grouped by severity
    for VAPT tools belonging to the authenticated user.
    """

    vapt_tools = [
        "Nmap",
        "Nikto",
        "Nuclei",
        "OWASP ZAP",
        "Masscan",
        "hping3",
        "Tshark",
        "Wireshark",
        "Snort",
        "Hydra",
        "John the Ripper",
        "Metasploit",
        "DNS Recon",
        "dig",
        "nslookup",
        "Ping",
        "WHOIS",
    ]

    query = (
        db.query(
            SecurityFinding.severity,
            func.count(SecurityFinding.id).label("finding_count"),
        )
        .filter(
            SecurityFinding.user_id == current_user.id,
            SecurityFinding.tool_name.in_(vapt_tools),
        )
    )

    if assessment_id is not None:
        query = query.filter(
            SecurityFinding.assessment_id == assessment_id
        )

    rows = (
        query
        .group_by(SecurityFinding.severity)
        .all()
    )

    severity_order = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "NONE",
    ]

    counts = {
        str(severity).upper(): int(count)
        for severity, count in rows
        if severity
    }

    return {
        "assessment_id": assessment_id,
        "severities": [
            {
                "severity": severity,
                "findings": counts.get(severity, 0),
            }
            for severity in severity_order
        ],
        "total_findings": sum(counts.values()),
    }


# ============================================================
# VAPT ANALYTICS - FINDINGS BY TOOL
# ============================================================

@router.get("/stats/by-tool")
def get_findings_by_tool(
    assessment_id: Optional[int] = Query(default=None),
    current_user: User = Depends(require_role(1)),
    db: Session = Depends(get_db),
):
    """
    Return real SecurityFinding counts grouped by VAPT tool
    for the authenticated user.
    """

    vapt_tools = [
        "Nmap",
        "Nikto",
        "Nuclei",
        "OWASP ZAP",
        "Masscan",
        "hping3",
        "Tshark",
        "Wireshark",
        "Snort",
        "Hydra",
        "John the Ripper",
        "Metasploit",
        "DNS Recon",
        "dig",
        "nslookup",
        "Ping",
        "WHOIS",
    ]

    query = (
        db.query(
            SecurityFinding.tool_name,
            func.count(SecurityFinding.id).label("finding_count"),
        )
        .filter(
            SecurityFinding.user_id == current_user.id,
            SecurityFinding.tool_name.in_(vapt_tools),
        )
    )

    if assessment_id is not None:
        query = query.filter(
            SecurityFinding.assessment_id == assessment_id
        )

    rows = (
        query
        .group_by(SecurityFinding.tool_name)
        .order_by(
            func.count(SecurityFinding.id).desc()
        )
        .all()
    )

    return {
        "assessment_id": assessment_id,
        "tools": [
            {
                "tool": tool_name or "Unknown",
                "findings": int(finding_count),
            }
            for tool_name, finding_count in rows
        ],
        "total_findings": sum(
            int(finding_count)
            for _, finding_count in rows
        ),
    }
