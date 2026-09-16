from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import Base, engine

from auth import router as auth_router
from admin import router as admin_router
from analyst import router as analyst_router
from client import router as client_router
from client_portal import router as client_portal_router
from vapt import router as vapt_router
from qa import router as qa_router
from logs import router as logs_router
from support import router as support_router
from telegram import router as telegram_router
from security_findings import router as security_findings_router
from cve import router as cve_router
from uptime import router as uptime_router
from server_config import router as server_config_router
from audit import router as audit_router
from reports import router as reports_router
from report_generator import router as report_generator_router

# Report Issues / Remediation
from report_issues import router as report_issues_router

# Security Copilot
from copilot import router as copilot_router


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="SOC Platform API",
    description="Security Operations Center Platform API",
    version="1.0.0",
)


# ============================================================
# CORS CONFIGURATION
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# API ROUTERS
# ============================================================

# Authentication
app.include_router(auth_router)

# Administration
app.include_router(admin_router)

# Security Analyst
app.include_router(analyst_router)

# User / Client
app.include_router(client_router)
app.include_router(client_portal_router)

# VAPT
app.include_router(vapt_router)

# QA
app.include_router(qa_router)

# Live Log Monitoring
app.include_router(logs_router)

# Support Tickets
app.include_router(support_router)

# Telegram Integration
app.include_router(telegram_router)

# Security Findings
app.include_router(security_findings_router)

# Security Copilot
app.include_router(copilot_router)

# CVE Intelligence / NVD
app.include_router(cve_router)

# Uptime Monitoring
app.include_router(uptime_router)

# Server Configuration
app.include_router(server_config_router)

# Audit Trail
app.include_router(audit_router)

# Reports - Dashboard / Summary
app.include_router(reports_router)

# Reports - PDF Generator
app.include_router(report_generator_router)

# Reports - Issues / Remediation
app.include_router(report_issues_router)


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():
    return {
        "message": "SOC Platform API is running",
        "version": "1.0.0",
        "status": "online",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SOC Platform API",
    }