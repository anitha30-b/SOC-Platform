from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from database import Base


# ============================================================
# ROLE
# ============================================================

class Role(Base):
    __tablename__ = "roles"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    name = Column(
        String(100),
        unique=True,
        nullable=False,
    )

    users = relationship(
        "User",
        back_populates="role",
    )

    tool_permissions = relationship(
        "RoleToolPermission",
        back_populates="role",
        cascade="all, delete-orphan",
    )


# ============================================================
# CLIENT
# ============================================================

class Client(Base):
    __tablename__ = "clients"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    name = Column(
        String(255),
        nullable=False,
    )

    email = Column(
        String(255),
        nullable=False,
    )

    organization = Column(
        String(255),
        nullable=True,
    )

    users = relationship(
        "User",
        back_populates="client",
    )


# ============================================================
# USER
# ============================================================

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    username = Column(
        String(100),
        unique=True,
        nullable=False,
    )

    email = Column(
        String(255),
        unique=True,
        nullable=False,
    )

    hashed_password = Column(
        String(255),
        nullable=False,
    )

    role_id = Column(
        Integer,
        ForeignKey("roles.id"),
        nullable=False,
    )

    # --------------------------------------------------------
    # Legacy Client compatibility
    # --------------------------------------------------------

    client_id = Column(
        Integer,
        ForeignKey("clients.id"),
        nullable=True,
    )

    # ========================================================
    # TELEGRAM ACCOUNT LINKING
    # ========================================================

    telegram_chat_id = Column(
        String(100),
        unique=True,
        nullable=True,
        index=True,
    )

    telegram_username = Column(
        String(255),
        nullable=True,
    )

    telegram_connected = Column(
        Boolean,
        nullable=False,
        default=False,
    )

    telegram_connected_at = Column(
        DateTime,
        nullable=True,
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    role = relationship(
        "Role",
        back_populates="users",
    )

    client = relationship(
        "Client",
        back_populates="users",
    )

    qa_records = relationship(
        "QARecord",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    qa_test_resources = relationship(
        "QATestResource",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    assessments = relationship(
        "Assessment",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    security_findings = relationship(
        "SecurityFinding",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    support_tickets = relationship(
        "SupportTicket",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    tool_permissions = relationship(
        "UserToolPermission",
        back_populates="user",
        cascade="all, delete-orphan",
    )


# ============================================================
# QA RECORD
# ============================================================

class QARecord(Base):
    __tablename__ = "qa_records"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
    )

    test_type = Column(
        String(100),
        nullable=False,
    )

    target = Column(
        String(500),
        nullable=True,
    )

    # ========================================================
    # UI / UX
    # ========================================================

    responsive = Column(
        Boolean,
        nullable=True,
    )

    navigation = Column(
        Boolean,
        nullable=True,
    )

    accessibility = Column(
        Boolean,
        nullable=True,
    )

    performance = Column(
        Boolean,
        nullable=True,
    )

    visual_consistency = Column(
        Boolean,
        nullable=True,
    )

    uiux_score = Column(
        Integer,
        nullable=True,
    )

    # ========================================================
    # API TESTING
    # ========================================================

    method = Column(
        String(20),
        nullable=True,
    )

    request_body = Column(
        String,
        nullable=True,
    )

    response_body = Column(
        String,
        nullable=True,
    )

    status_code = Column(
        Integer,
        nullable=True,
    )

    response_time_ms = Column(
        Integer,
        nullable=True,
    )

    # ========================================================
    # MARKET ANALYSIS
    # ========================================================

    product = Column(
        String(255),
        nullable=True,
    )

    industry = Column(
        String(255),
        nullable=True,
    )

    competitor = Column(
        String(255),
        nullable=True,
    )

    analysis_focus = Column(
        String(500),
        nullable=True,
    )

    # ========================================================
    # NOTES
    # ========================================================

    review_notes = Column(
        String,
        nullable=True,
    )

    market_notes = Column(
        String,
        nullable=True,
    )

    # ========================================================
    # TIMESTAMPS
    # ========================================================

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    user = relationship(
        "User",
        back_populates="qa_records",
    )


# ============================================================
# QA TEST RESOURCE
# ============================================================

class QATestResource(Base):
    __tablename__ = "qa_test_resources"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
    )

    name = Column(
        String(255),
        nullable=False,
    )

    description = Column(
        String,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    user = relationship(
        "User",
        back_populates="qa_test_resources",
    )


# ============================================================
# ASSESSMENT
# ============================================================

class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
    )

    target = Column(
        String(500),
        nullable=False,
    )

    # ========================================================
    # VAPT
    # ========================================================

    vapt_status = Column(
        String(50),
        default="not_started",
        nullable=False,
    )

    vapt_findings_count = Column(
        Integer,
        default=0,
        nullable=False,
    )

    # ========================================================
    # QA
    # ========================================================

    qa_status = Column(
        String(50),
        default="not_started",
        nullable=False,
    )

    qa_score = Column(
        Integer,
        nullable=True,
    )

    # ========================================================
    # LIVE MONITORING
    # ========================================================

    monitoring_status = Column(
        String(50),
        default="not_started",
        nullable=False,
    )

    # ========================================================
    # REPORT
    # ========================================================

    report_status = Column(
        String(50),
        default="not_generated",
        nullable=False,
    )

    # ========================================================
    # OVERALL
    # ========================================================

    overall_status = Column(
        String(50),
        default="active",
        nullable=False,
    )

    # ========================================================
    # TIMESTAMPS
    # ========================================================

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    user = relationship(
        "User",
        back_populates="assessments",
    )

    support_tickets = relationship(
        "SupportTicket",
        back_populates="assessment",
    )

    security_findings = relationship(
        "SecurityFinding",
        back_populates="assessment",
        cascade="all, delete-orphan",
    )


# ============================================================
# SECURITY TOOL CATALOG
# ============================================================

class SecurityTool(Base):
    __tablename__ = "security_tools"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    name = Column(
        String(150),
        unique=True,
        nullable=False,
    )

    category = Column(
        String(100),
        nullable=False,
    )

    description = Column(
        String,
        nullable=True,
    )

    tool_type = Column(
        String(50),
        nullable=False,
        default="scanner",
    )

    enabled = Column(
        Boolean,
        nullable=False,
        default=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    permissions = relationship(
        "UserToolPermission",
        back_populates="tool",
        cascade="all, delete-orphan",
    )

    role_permissions = relationship(
        "RoleToolPermission",
        back_populates="tool",
        cascade="all, delete-orphan",
    )


# ============================================================
# USER TOOL PERMISSION
# ============================================================

class UserToolPermission(Base):
    __tablename__ = "user_tool_permissions"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    tool_id = Column(
        Integer,
        ForeignKey("security_tools.id"),
        nullable=False,
        index=True,
    )

    allowed = Column(
        Boolean,
        nullable=False,
        default=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    user = relationship(
        "User",
        back_populates="tool_permissions",
    )

    tool = relationship(
        "SecurityTool",
        back_populates="permissions",
    )

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "tool_id",
            name="uq_user_tool_permission",
        ),
    )


# ============================================================
# SECURITY FINDING
# ============================================================

class RoleToolPermission(Base):
    __tablename__ = "role_tool_permissions"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)
    tool_id = Column(Integer, ForeignKey("security_tools.id"), nullable=False, index=True)
    allowed = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    role = relationship("Role", back_populates="tool_permissions")
    tool = relationship("SecurityTool", back_populates="role_permissions")

    __table_args__ = (
        UniqueConstraint("role_id", "tool_id", name="uq_role_tool_permission"),
    )


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    # ========================================================
    # FINDING IDENTIFICATION
    # ========================================================

    finding_id = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    assessment_id = Column(
        Integer,
        ForeignKey("assessments.id"),
        nullable=False,
        index=True,
    )

    # ========================================================
    # SECURITY TOOL
    # ========================================================

    tool_name = Column(
        String(150),
        nullable=False,
        index=True,
    )

    tool_category = Column(
        String(100),
        nullable=True,
    )

    # ========================================================
    # VULNERABILITY INFORMATION
    # ========================================================

    title = Column(
        String(500),
        nullable=False,
    )

    vulnerability = Column(
        String(500),
        nullable=True,
    )

    description = Column(
        String,
        nullable=True,
    )

    # ========================================================
    # OWASP MAPPING
    # ========================================================

    owasp_category = Column(
        String(150),
        nullable=True,
    )

    owasp_api_category = Column(
        String(150),
        nullable=True,
    )

    # ========================================================
    # CVE / CWE
    # ========================================================

    cve_id = Column(
        String(100),
        nullable=True,
        index=True,
    )

    cwe_id = Column(
        String(100),
        nullable=True,
    )

    # ========================================================
    # CVSS / RISK
    # ========================================================

    cvss_score = Column(
        Float,
        nullable=True,
    )

    severity = Column(
        String(30),
        nullable=False,
        default="LOW",
    )

    # Application-level 3-level risk system
    #
    # LEVEL_1 = Critical / High
    # LEVEL_2 = Medium
    # LEVEL_3 = Low
    #
    risk_level = Column(
        String(20),
        nullable=False,
        default="LEVEL_3",
    )

    # ========================================================
    # AFFECTED RESOURCE
    # ========================================================

    affected_asset = Column(
        String(500),
        nullable=True,
    )

    affected_url = Column(
        String(1000),
        nullable=True,
    )

    endpoint = Column(
        String(1000),
        nullable=True,
    )

    parameter = Column(
        String(500),
        nullable=True,
    )

    # ========================================================
    # SECURITY EVIDENCE
    # ========================================================

    evidence = Column(
        String,
        nullable=True,
    )

    request_data = Column(
        String,
        nullable=True,
    )

    response_data = Column(
        String,
        nullable=True,
    )

    # ========================================================
    # IMPACT / REMEDIATION
    # ========================================================

    impact = Column(
        String,
        nullable=True,
    )

    remediation = Column(
        String,
        nullable=True,
    )

    references = Column(
        String,
        nullable=True,
    )

    # ========================================================
    # STATUS
    # ========================================================

    status = Column(
        String(30),
        nullable=False,
        default="OPEN",
    )

    # ========================================================
    # TIMESTAMPS
    # ========================================================

    detected_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    user = relationship(
        "User",
        back_populates="security_findings",
    )

    assessment = relationship(
        "Assessment",
        back_populates="security_findings",
    )


# ============================================================
# POST-EXPLOITATION ACCESS / IMPACT VALIDATION
# ============================================================

class PostExploitationValidation(Base):
    __tablename__ = "post_exploitation_validations"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    validation_id = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    job_id = Column(
        String(100),
        nullable=False,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    assessment_id = Column(
        Integer,
        ForeignKey("assessments.id"),
        nullable=False,
        index=True,
    )

    finding_id = Column(
        String(50),
        ForeignKey("security_findings.finding_id"),
        nullable=False,
        index=True,
    )

    status = Column(
        String(30),
        nullable=False,
        default="RUNNING",
    )

    validation_result = Column(
        String(50),
        nullable=True,
    )

    access_validated = Column(
        Boolean,
        nullable=True,
    )

    impact_validated = Column(
        Boolean,
        nullable=True,
    )

    evidence = Column(
        Text,
        nullable=True,
    )

    impact_details = Column(
        Text,
        nullable=True,
    )

    validation_notes = Column(
        Text,
        nullable=True,
    )

    started_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    completed_at = Column(
        DateTime,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    user = relationship(
        "User",
    )

    assessment = relationship(
        "Assessment",
    )

    finding = relationship(
        "SecurityFinding",
    )


# ============================================================
# SUPPORT TICKET
# ============================================================

class SupportTicket(Base):
    __tablename__ = "support_tickets"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    ticket_id = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
    )

    assessment_id = Column(
        Integer,
        ForeignKey("assessments.id"),
        nullable=True,
    )

    # ========================================================
    # TICKET INFORMATION
    # ========================================================

    category = Column(
        String(100),
        nullable=False,
    )

    subject = Column(
        String(200),
        nullable=False,
    )

    description = Column(
        String,
        nullable=False,
    )

    priority = Column(
        String(20),
        default="MEDIUM",
        nullable=False,
    )

    status = Column(
        String(30),
        default="OPEN",
        nullable=False,
    )

    # ========================================================
    # ASSIGNMENT
    # ========================================================

    assigned_to = Column(
        String(200),
        nullable=True,
    )

    assignment_channel = Column(
        String(30),
        nullable=True,
    )

    assignment_status = Column(
        String(30),
        default="NOT_ASSIGNED",
        nullable=False,
    )

    # ========================================================
    # ADMIN / RESOLUTION
    # ========================================================

    admin_notes = Column(
        String,
        nullable=True,
    )

    resolution = Column(
        String,
        nullable=True,
    )

    final_admin_message = Column(
        String,
        nullable=True,
    )

    # ========================================================
    # TIMESTAMPS
    # ========================================================

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    resolved_at = Column(
        DateTime,
        nullable=True,
    )

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    user = relationship(
        "User",
        back_populates="support_tickets",
    )

    assessment = relationship(
        "Assessment",
        back_populates="support_tickets",
    )

    messages = relationship(
        "SupportTicketMessage",
        back_populates="ticket",
        cascade="all, delete-orphan",
    )


# ============================================================
# SUPPORT TICKET MESSAGE
# ============================================================

class SupportTicketMessage(Base):
    __tablename__ = "support_ticket_messages"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    ticket_id = Column(
        Integer,
        ForeignKey("support_tickets.id"),
        nullable=False,
    )

    sender_type = Column(
        String(30),
        nullable=False,
    )

    sender_name = Column(
        String(200),
        nullable=False,
    )

    message = Column(
        String,
        nullable=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    ticket = relationship(
        "SupportTicket",
        back_populates="messages",
    )


# ============================================================
# TELEGRAM LINK TOKEN
# ============================================================

class TelegramLinkToken(Base):
    __tablename__ = "telegram_link_tokens"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
    )

    token_hash = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    expires_at = Column(
        DateTime,
        nullable=False,
    )

    used = Column(
        Boolean,
        nullable=False,
        default=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    user = relationship(
        "User",
    )

# ============================================================
# AUDIT LOG
# ============================================================

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    username = Column(
        String(100),
        nullable=True,
        index=True,
    )

    action = Column(
        String(255),
        nullable=False,
    )

    module = Column(
        String(100),
        nullable=True,
        index=True,
    )

    ip_address = Column(
        String(100),
        nullable=True,
    )

    status = Column(
        String(50),
        nullable=False,
        default="SUCCESS",
    )

    details = Column(
        Text,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    user = relationship(
        "User",
    )




# ============================================================
# RISK ASSESSMENT
# ============================================================

class RiskAssessmentRun(Base):
    __tablename__ = "risk_assessment_runs"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    assessment_run_id = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    job_id = Column(
        String(100),
        nullable=False,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    assessment_id = Column(
        Integer,
        ForeignKey("assessments.id"),
        nullable=False,
        index=True,
    )

    status = Column(
        String(30),
        nullable=False,
        default="RUNNING",
    )

    total_findings = Column(
        Integer,
        nullable=False,
        default=0,
    )

    average_cvss = Column(
        Float,
        nullable=False,
        default=0.0,
    )

    highest_cvss = Column(
        Float,
        nullable=False,
        default=0.0,
    )

    overall_risk = Column(
        String(30),
        nullable=True,
    )

    severity_summary = Column(
        Text,
        nullable=True,
    )

    risk_level_summary = Column(
        Text,
        nullable=True,
    )

    status_summary = Column(
        Text,
        nullable=True,
    )

    validation_summary = Column(
        Text,
        nullable=True,
    )

    findings_snapshot = Column(
        Text,
        nullable=True,
    )

    assessment_notes = Column(
        Text,
        nullable=True,
    )

    started_at = Column(
        DateTime,
        nullable=True,
    )

    completed_at = Column(
        DateTime,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    user = relationship(
        "User",
    )

    assessment = relationship(
        "Assessment",
    )



# ============================================================
# GENERATED SECURITY REPORT
# ============================================================

class Report(Base):
    __tablename__ = "reports"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    report_id = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    assessment_id = Column(
        Integer,
        ForeignKey("assessments.id"),
        nullable=False,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    report_type = Column(
        String(100),
        nullable=False,
        default="COMPLETE_SOC_REPORT",
    )

    filename = Column(
        String(255),
        nullable=False,
    )

    status = Column(
        String(50),
        nullable=False,
        default="GENERATED",
    )

    generated_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    assessment = relationship(
        "Assessment",
    )

    user = relationship(
        "User",
    )

# ============================================================
# REPORT ISSUE / REMEDIATION TASK
# ============================================================

class ReportIssue(Base):
    __tablename__ = "report_issues"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    issue_id = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    report_id = Column(
        Integer,
        ForeignKey("reports.id"),
        nullable=False,
        index=True,
    )

    assessment_id = Column(
        Integer,
        ForeignKey("assessments.id"),
        nullable=False,
        index=True,
    )

    created_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    assigned_to = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    title = Column(
        String(300),
        nullable=False,
    )

    description = Column(
        String,
        nullable=False,
    )

    severity = Column(
        String(20),
        nullable=False,
        default="MEDIUM",
    )

    status = Column(
        String(30),
        nullable=False,
        default="OPEN",
        index=True,
    )

    resolution = Column(
        String,
        nullable=True,
    )

    ticket_id = Column(
        Integer,
        ForeignKey("support_tickets.id"),
        nullable=True,
        index=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    resolved_at = Column(
        DateTime,
        nullable=True,
    )

    report = relationship(
        "Report",
    )

    assessment = relationship(
        "Assessment",
    )

    creator = relationship(
        "User",
        foreign_keys=[created_by],
    )

    assignee = relationship(
        "User",
        foreign_keys=[assigned_to],
    )

    support_ticket = relationship(
        "SupportTicket",
    )


# ============================================================
# SECURITY EVENT
# ============================================================

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    event_id = Column(
        String(255),
        nullable=True,
        index=True,
    )

    timestamp = Column(
        DateTime,
        nullable=False,
        index=True,
    )

    source = Column(
        String(100),
        nullable=False,
        index=True,
    )

    event_type = Column(
        String(100),
        nullable=False,
        index=True,
    )

    severity = Column(
        String(50),
        nullable=False,
        index=True,
    )

    message = Column(
        Text,
        nullable=False,
    )

    target = Column(
        String(255),
        nullable=True,
        index=True,
    )

    assessment_id = Column(
        Integer,
        nullable=True,
        index=True,
    )

    mitre_technique_id = Column(
        String(50),
        nullable=True,
        index=True,
    )

    mitre_technique_name = Column(
        String(255),
        nullable=True,
    )

    mitre_tactic = Column(
        String(100),
        nullable=True,
    )

    mitre_mapping_source = Column(
        String(100),
        nullable=True,
    )

    mitre_confidence = Column(
        String(50),
        nullable=True,
    )

    mitre_evidence = Column(
        Text,
        nullable=True,
    )

    raw_event = Column(
        Text,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    alert_status = Column(
        String(30),
        nullable=False,
        default="ACTIVE",
        index=True,
    )

    acknowledged_at = Column(
        DateTime,
        nullable=True,
    )

    resolved_at = Column(
        DateTime,
        nullable=True,
    )


# ============================================================
# NOTIFICATION POLICY
# ============================================================

class NotificationPolicy(Base):
    __tablename__ = "notification_policies"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String(150), unique=True, nullable=False, index=True)

    enabled = Column(Boolean, nullable=False, default=True, index=True)

    source = Column(String(100), nullable=True, index=True)

    event_type = Column(String(100), nullable=True, index=True)

    minimum_severity = Column(
        String(50),
        nullable=False,
        default="INFO",
        index=True,
    )

    email_enabled = Column(Boolean, nullable=False, default=False)

    slack_enabled = Column(Boolean, nullable=False, default=False)

    teams_enabled = Column(Boolean, nullable=False, default=False)

    webhook_enabled = Column(Boolean, nullable=False, default=False)

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


# ============================================================
# ADMIN NOTIFICATION
# ============================================================

class Notification(Base):
    __tablename__ = "notifications"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    notification_id = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    event_id = Column(
        String(255),
        nullable=True,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    assessment_id = Column(
        Integer,
        ForeignKey("assessments.id"),
        nullable=True,
        index=True,
    )

    source = Column(
        String(100),
        nullable=False,
        index=True,
    )

    event_type = Column(
        String(100),
        nullable=False,
        index=True,
    )

    severity = Column(
        String(50),
        nullable=False,
        index=True,
    )

    title = Column(
        String(255),
        nullable=False,
    )

    message = Column(
        Text,
        nullable=False,
    )

    target = Column(
        String(255),
        nullable=True,
    )

    is_read = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    read_at = Column(
        DateTime,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    user = relationship("User")
    assessment = relationship("Assessment")




# ============================================================
# NOTIFICATION CHANNEL CONFIGURATION
# ============================================================

class NotificationChannelConfig(Base):
    __tablename__ = "notification_channel_configs"

    id = Column(Integer, primary_key=True, index=True)

    channel = Column(
        String(30),
        unique=True,
        nullable=False,
        index=True,
    )

    enabled = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    # Generic destination/configuration fields.
    endpoint = Column(
        String(1000),
        nullable=True,
    )

    username = Column(
        String(255),
        nullable=True,
    )

    # Stored secret/token/password.
    secret = Column(
        Text,
        nullable=True,
    )

    # Optional JSON configuration for channel-specific settings.
    configuration = Column(
        Text,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )



# ============================================================
# USER VAPT REPORT RUN
# ============================================================

class VAPTReportRun(Base):
    __tablename__ = "vapt_report_runs"

    id = Column(Integer, primary_key=True, index=True)
    report_run_id = Column(String(100), unique=True, nullable=False, index=True)
    job_id = Column(String(100), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    risk_assessment_run_id = Column(Integer, ForeignKey("risk_assessment_runs.id"), nullable=True, index=True)

    status = Column(String(30), nullable=False, default="RUNNING")
    report_type = Column(String(30), nullable=False, default="COMPLETE")
    formats = Column(Text, nullable=True)
    canonical_data = Column(Text, nullable=True)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User")
    assessment = relationship("Assessment")
    risk_assessment_run = relationship("RiskAssessmentRun")


# ============================================================
# BACKGROUND JOB HISTORY
# ============================================================

class BackgroundJob(Base):
    __tablename__ = "soc_background_jobs"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String(36), unique=True, nullable=False, index=True)
    tool = Column(String(50), nullable=False, index=True)
    target = Column(String(2048), nullable=False)
    scan_type = Column(String(50), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    status = Column(String(40), nullable=False, default="queued", index=True)
    progress = Column(Integer, nullable=False, default=0)
    stage = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    error = Column(Text, nullable=True)
    result_json = Column(Text, nullable=True)


# ============================================================
# SECURITY POLICIES
# ============================================================

class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), unique=True, nullable=False, index=True)
    category = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False, default="MEDIUM", index=True)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    policy_content = Column(Text, nullable=True)
    created_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# ============================================================
# SECURITY BASELINES
# ============================================================

class SecurityBaseline(Base):
    __tablename__ = "security_baselines"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), unique=True, nullable=False, index=True)
    framework = Column(String(100), nullable=False, index=True)
    category = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False, default="MEDIUM")
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    baseline_content = Column(Text, nullable=True)
    created_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# ============================================================
# DETECTION CONFIGURATION
# ============================================================

class DetectionConfiguration(Base):
    __tablename__ = "detection_configurations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), unique=True, nullable=False, index=True)
    category = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=False)
    detection_type = Column(String(100), nullable=False, default="Rule-Based")
    severity = Column(String(50), nullable=False, default="MEDIUM")
    conditions = Column(Text, nullable=True)
    threshold = Column(Integer, nullable=True)
    time_window_minutes = Column(Integer, nullable=True)
    source = Column(String(100), nullable=True)
    event_type = Column(String(100), nullable=True)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    created_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# ============================================================
# ALERT CONFIGURATION
# ============================================================

class AlertConfiguration(Base):
    __tablename__ = "alert_configurations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), unique=True, nullable=False, index=True)
    category = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False, default="MEDIUM")
    priority = Column(String(50), nullable=False, default="MEDIUM")
    source = Column(String(100), nullable=True)
    event_type = Column(String(100), nullable=True)
    threshold = Column(Integer, nullable=True)
    time_window_minutes = Column(Integer, nullable=True)
    conditions = Column(Text, nullable=True)
    notification_policy_id = Column(
        Integer,
        ForeignKey("notification_policies.id"),
        nullable=True,
    )
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    created_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# ============================================================
# RETENTION POLICIES
# ============================================================

class RetentionPolicy(Base):
    __tablename__ = "retention_policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), unique=True, nullable=False, index=True)
    data_type = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=False)
    retention_days = Column(Integer, nullable=False, default=90)
    archive_enabled = Column(Boolean, nullable=False, default=False)
    archive_after_days = Column(Integer, nullable=True)
    auto_delete = Column(Boolean, nullable=False, default=False)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    created_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# ============================================================
# PLATFORM CONFIGURATION
# ============================================================

class PlatformConfiguration(Base):
    __tablename__ = "platform_configurations"

    id = Column(Integer, primary_key=True, index=True)

    session_timeout_minutes = Column(Integer, nullable=False, default=30)

    password_min_length = Column(Integer, nullable=False, default=8)
    password_require_uppercase = Column(Boolean, nullable=False, default=True)
    password_require_lowercase = Column(Boolean, nullable=False, default=True)
    password_require_number = Column(Boolean, nullable=False, default=True)
    password_require_special = Column(Boolean, nullable=False, default=False)

    max_failed_login_attempts = Column(Integer, nullable=False, default=5)
    account_lockout_minutes = Column(Integer, nullable=False, default=15)

    created_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

# ============================================================
# SERVICE ACCOUNTS
# ============================================================

class ServiceAccount(Base):
    __tablename__ = "service_accounts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), nullable=False, index=True)
    description = Column(Text, nullable=True)
    key_prefix = Column(String(24), nullable=False, index=True)
    key_hash = Column(String(64), nullable=False, unique=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    role = relationship("Role")



# ============================================================
# API KEY MANAGEMENT
# ============================================================

class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), nullable=False, index=True)
    description = Column(Text, nullable=True)
    key_prefix = Column(String(24), nullable=False, index=True)
    key_hash = Column(String(64), nullable=False, unique=True)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=True, index=True)
    permissions = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)


# ============================================================
# USER SESSION MANAGEMENT
# ============================================================

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(128), nullable=False, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    username = Column(String(150), nullable=False, index=True)
    role_id = Column(Integer, nullable=False, index=True)
    ip_address = Column(String(100), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    last_activity_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True, index=True)
    revoked_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    revocation_reason = Column(String(255), nullable=True)

    user = relationship("User", foreign_keys=[user_id])
    administrator = relationship("User", foreign_keys=[revoked_by])


# ============================================================
# TEAM MANAGEMENT
# ============================================================

class Team(Base):
    __tablename__ = "teams"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow,
                        onupdate=datetime.utcnow)

    members = relationship(
        "TeamMember",
        back_populates="team",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    creator = relationship("User", foreign_keys=[created_by])


class TeamMember(Base):
    __tablename__ = "team_members"

    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    assigned_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("team_id", "user_id", name="uq_team_member"),
    )

    team = relationship("Team", back_populates="members")
    user = relationship("User")


# ============================================================
# SIEM INTEGRATION MANAGEMENT
# ============================================================

class SIEMIntegration(Base):
    __tablename__ = "siem_integrations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), nullable=False)
    provider = Column(String(50), nullable=False, index=True)
    base_url = Column(String(1000), nullable=False)
    encrypted_credentials = Column(Text, nullable=True)

    enabled = Column(Boolean, nullable=False, default=True, index=True)
    status = Column(String(30), nullable=False, default="PENDING")
    last_tested_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)

    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    __table_args__ = (
        UniqueConstraint(
            "provider",
            "name",
            name="uq_siem_provider_name",
        ),
    )


# ============================================================
# SIEM INGESTION CHECKPOINTS
# ============================================================

class SIEMIngestionState(Base):
    __tablename__ = "siem_ingestion_states"

    id = Column(Integer, primary_key=True, index=True)
    integration_id = Column(
        Integer,
        ForeignKey("siem_integrations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    last_ingested_at = Column(DateTime, nullable=True)
    last_success_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    total_events = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# ============================================================
# DETECTION ENGINE RESULTS
# ============================================================

class DetectionResult(Base):
    __tablename__ = "detection_results"

    __table_args__ = (
        UniqueConstraint(
            "security_event_id",
            "detection_config_id",
            name="uq_detection_event_rule",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    security_event_id = Column(
        Integer,
        ForeignKey("security_events.id"),
        nullable=False,
        index=True,
    )

    detection_config_id = Column(
        Integer,
        ForeignKey("detection_configurations.id"),
        nullable=False,
        index=True,
    )

    rule_name = Column(String(150), nullable=False)
    detection_type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)
    match_details = Column(Text, nullable=True)

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )


# ============================================================
# ALERT ENGINE RESULTS
# ============================================================

class AlertResult(Base):
    __tablename__ = "alert_results"

    __table_args__ = (
        UniqueConstraint(
            "security_event_id",
            "alert_config_id",
            name="uq_alert_event_rule",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    security_event_id = Column(
        Integer,
        ForeignKey("security_events.id"),
        nullable=False,
        index=True,
    )

    alert_config_id = Column(
        Integer,
        ForeignKey("alert_configurations.id"),
        nullable=False,
        index=True,
    )

    alert_name = Column(String(150), nullable=False)
    severity = Column(String(50), nullable=False)
    priority = Column(String(50), nullable=False)
    match_details = Column(Text, nullable=True)

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )


# ============================================================
# EMAIL HEADER ANALYSIS HISTORY
# ============================================================

class EmailHeaderAnalysis(Base):
    __tablename__ = "email_header_analyses"

    id = Column(Integer, primary_key=True, index=True)

    admin_user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    sender = Column(String(255), nullable=True)
    reply_to = Column(String(255), nullable=True)
    subject = Column(String(500), nullable=True)
    from_domain = Column(String(255), nullable=True)

    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(30), nullable=False, default="LOW")

    indicators = Column(JSON, nullable=False, default=list)
    authentication_results = Column(JSON, nullable=False, default=dict)

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )
