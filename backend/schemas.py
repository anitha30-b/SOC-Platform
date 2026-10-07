from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


# ==================================================
# USER SCHEMAS
# ==================================================

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role_id: int

    class Config:
        from_attributes = True


# ==================================================
# LOGIN SCHEMAS
# ==================================================

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class UserMeResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role_id: int


# ==================================================
# CLIENT SCHEMAS
# ==================================================

class ClientCreate(BaseModel):
    name: str
    email: EmailStr
    organization: str | None = None


class UserClientAssign(BaseModel):
    client_id: int


# ==================================================
# QA — UI / UX
# ==================================================

class QAUISaveRequest(BaseModel):
    target: Optional[str] = Field(
        default=None,
        max_length=500,
    )

    responsive: bool = False
    navigation: bool = False
    accessibility: bool = False
    performance: bool = False
    visual_consistency: bool = False

    uiux_score: int = Field(
        default=0,
        ge=0,
        le=100,
    )

    review_notes: Optional[str] = None


# ==================================================
# QA — AUTOMATED UI / UX TARGET REVIEW
# ==================================================

class QAUIUXTargetReviewRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        max_length=500,
    )


# ==================================================
# QA — MARKET ANALYSIS
# ==================================================

class QAMarketSaveRequest(BaseModel):
    target: Optional[str] = Field(
        default=None,
        max_length=500,
    )

    product: Optional[str] = None
    industry: Optional[str] = None
    competitor: Optional[str] = None
    analysis_focus: Optional[str] = None
    market_notes: Optional[str] = None


# ==================================================
# QA — API REQUEST TESTING
# ==================================================

class QAAPIRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        max_length=500,
    )

    endpoint_url: str = Field(
        ...,
        min_length=1,
        max_length=1000,
    )

    method: str = Field(
        default="GET",
        pattern="^(GET|POST|PUT|DELETE)$",
    )

    request_body: Optional[dict] = None


# ==================================================
# QA — AUTOMATIC API DISCOVERY
# ==================================================

class QADiscoverRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        max_length=500,
    )


class QAEndpointInfo(BaseModel):
    path: str
    methods: list[str]
    summary: Optional[str] = None
    operation_id: Optional[str] = None


class QADiscoverResponse(BaseModel):
    target: str
    openapi_url: str
    openapi_version: Optional[str] = None
    endpoint_count: int
    endpoints: list[QAEndpointInfo]


# ==================================================
# QA — TEST RESOURCE
# ==================================================

class QATestResourceResponse(BaseModel):
    id: int
    user_id: int
    name: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ==================================================
# QA — AUTOMATED API TEST SUITE
# ==================================================

class QAFullAPITestRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        max_length=500,
    )


class QATestStepResponse(BaseModel):
    method: str
    endpoint: str
    status_code: Optional[int] = None
    passed: bool
    response_time_ms: Optional[int] = None
    message: str


class QAFullAPITestResponse(BaseModel):
    target: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    overall_status: str
    steps: list[QATestStepResponse]


# ==================================================
# QA — API TEST RESPONSE
# ==================================================

class QAAPIResponse(BaseModel):
    id: int
    user_id: int
    test_type: str
    target: Optional[str] = None

    method: Optional[str] = None
    request_body: Optional[str] = None
    response_body: Optional[str] = None
    status_code: Optional[int] = None
    response_time_ms: Optional[int] = None

    api_endpoint: Optional[str] = None
    source: Optional[str] = None
    final_url: Optional[str] = None
    status_text: Optional[str] = None

    created_at: datetime

    class Config:
        from_attributes = True


# ==================================================
# QA — GENERAL RESPONSE
# ==================================================

class QARecordResponse(BaseModel):
    id: int
    user_id: int
    test_type: str

    target: Optional[str] = None

    # ----------------------------------------------
    # UI / UX
    # ----------------------------------------------

    responsive: Optional[bool] = None
    navigation: Optional[bool] = None
    accessibility: Optional[bool] = None
    performance: Optional[bool] = None
    visual_consistency: Optional[bool] = None
    uiux_score: Optional[int] = None

    # ----------------------------------------------
    # API TESTING
    # ----------------------------------------------

    method: Optional[str] = None
    request_body: Optional[str] = None
    response_body: Optional[str] = None
    status_code: Optional[int] = None
    response_time_ms: Optional[int] = None

    # ----------------------------------------------
    # MARKET ANALYSIS
    # ----------------------------------------------

    product: Optional[str] = None
    industry: Optional[str] = None
    competitor: Optional[str] = None
    analysis_focus: Optional[str] = None

    # ----------------------------------------------
    # NOTES
    # ----------------------------------------------

    review_notes: Optional[str] = None
    market_notes: Optional[str] = None

    # ----------------------------------------------
    # TIMESTAMPS
    # ----------------------------------------------

    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ==================================================
# SECURITY TOOL PERMISSIONS
# ==================================================

class SecurityToolResponse(BaseModel):
    id: int
    name: str
    category: str
    description: Optional[str] = None
    tool_type: str
    enabled: bool

    class Config:
        from_attributes = True


class UserToolPermissionResponse(BaseModel):
    id: int
    user_id: int
    tool_id: int
    allowed: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ToolPermissionItem(BaseModel):
    tool_id: int
    allowed: bool


class UserToolPermissionsUpdate(BaseModel):
    permissions: list[ToolPermissionItem] = Field(
        default_factory=list
    )


class UserToolPermissionDetail(BaseModel):
    user_id: int
    username: str
    email: EmailStr
    tool_id: int
    tool_name: str
    category: str
    description: Optional[str] = None
    tool_type: str
    tool_enabled: bool
    allowed: bool


class UserToolPermissionCheckResponse(BaseModel):
    user_id: int
    tool_id: int
    allowed: bool


# ==================================================
# SUPPORT TICKET — CREATE
# ==================================================

class SupportTicketCreate(BaseModel):
    category: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    subject: str = Field(
        ...,
        min_length=1,
        max_length=200,
    )

    description: str = Field(
        ...,
        min_length=1,
        max_length=5000,
    )

    priority: str = Field(
        default="MEDIUM",
        pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$",
    )

    assessment_id: Optional[int] = None


# ==================================================
# SUPPORT TICKET — MESSAGE CREATE
# ==================================================

class SupportTicketMessageCreate(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
    )


# ==================================================
# SUPPORT TICKET — UPDATE BY ADMIN
# ==================================================

class SupportTicketUpdate(BaseModel):
    status: Optional[str] = Field(
        default=None,
        pattern="^(OPEN|IN_PROGRESS|WAITING_FOR_USER|RESOLVED|CLOSED)$",
    )

    priority: Optional[str] = Field(
        default=None,
        pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$",
    )

    assigned_to: Optional[str] = Field(
        default=None,
        max_length=200,
    )

    assignment_channel: Optional[str] = Field(
        default=None,
        pattern="^(WHATSAPP|TELEGRAM|OTHER)$",
    )

    assignment_status: Optional[str] = Field(
        default=None,
        pattern="^(NOT_ASSIGNED|ASSIGNED|WORKING|COMPLETED)$",
    )

    admin_notes: Optional[str] = Field(
        default=None,
        max_length=5000,
    )

    resolution: Optional[str] = Field(
        default=None,
        max_length=5000,
    )

    final_admin_message: Optional[str] = Field(
        default=None,
        max_length=5000,
    )


# ==================================================
# SUPPORT TICKET — MESSAGE RESPONSE
# ==================================================

class SupportTicketMessageResponse(BaseModel):
    id: int
    ticket_id: int
    sender_type: str
    sender_name: str
    message: str
    created_at: datetime

    class Config:
        from_attributes = True


# ==================================================
# SUPPORT TICKET — RESPONSE
# ==================================================

class SupportTicketResponse(BaseModel):
    id: int
    ticket_id: str

    user_id: int
    assessment_id: Optional[int] = None

    category: str
    subject: str
    description: str
    priority: str
    status: str

    assigned_to: Optional[str] = None
    assignment_channel: Optional[str] = None
    assignment_status: str

    admin_notes: Optional[str] = None
    resolution: Optional[str] = None
    final_admin_message: Optional[str] = None

    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ==================================================
# SUPPORT TICKET — DETAIL RESPONSE
# ==================================================

class SupportTicketDetailResponse(BaseModel):
    id: int
    ticket_id: str

    user_id: int
    assessment_id: Optional[int] = None

    category: str
    subject: str
    description: str
    priority: str
    status: str

    assigned_to: Optional[str] = None
    assignment_channel: Optional[str] = None
    assignment_status: str

    admin_notes: Optional[str] = None
    resolution: Optional[str] = None
    final_admin_message: Optional[str] = None

    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    messages: list[SupportTicketMessageResponse] = []

    class Config:
        from_attributes = True