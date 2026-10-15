from network_realtime_router import router as network_realtime_router
from credential_realtime_router import router as credential_realtime_router
from metasploit_realtime_router import router as metasploit_realtime_router
from access_validation_router import router as access_validation_router
from risk_assessment_router import router as risk_assessment_router
from tshark_snort_realtime_router import router as tshark_snort_realtime_router
from zap_router import router as zap_router
from juice_shop_router import router as juice_shop_router
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import Base, engine

from auth import router as auth_router
from admin import router as admin_router
from analyst import router as analyst_router
from client import router as client_router
from client_portal import router as client_portal_router
from vapt import router as vapt_router
from vapt_registry_router import router as vapt_registry_router
from qa import router as qa_router
from logs import router as logs_router
from support import router as support_router
from telegram import router as telegram_router
from security_findings import router as security_findings_router
from cve import router as cve_router
from uptime import router as uptime_router
from server_config import router as server_config_router
from system_health_router import router as system_health_router
from audit import router as audit_router
from reports import router as reports_router
from report_generator import router as report_generator_router
from vapt_reporting_router import router as vapt_reporting_router
from code_security_router import router as code_security_router

# Report Issues / Remediation
from report_issues import router as report_issues_router

# Security Copilot
from copilot import router as copilot_router

# MITRE ATT&CK
from mitre_router import router as mitre_router

# SOC Security Events
from security_events_router import router as security_events_router
from ioc_router import router as ioc_router
from sigma_router import router as sigma_router
from siem_correlation_engine import load_persistent_rule_configs

# SOC Real-Time Events
from realtime_router import router as realtime_router

# SOC PostgreSQL Real-Time Event Listener
from postgres_event_listener import postgres_event_listener
from realtime_journal_listener import start_listener as start_realtime_journal_listener
from admin_notifications_router import router as admin_notifications_router
from user_notifications_router import router as user_notifications_router
from user_notifications_realtime_router import router as user_notifications_realtime_router
from admin_notifications_realtime_router import router as admin_notifications_realtime_router
from admin_notification_policies_router import router as admin_notification_policies_router
from admin_notification_channels_router import router as admin_notification_channels_router

# SOC Incident Management
from incident import router as incident_router


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
# POSTGRESQL REAL-TIME EVENT LISTENER
# ============================================================

@app.on_event("startup")
def start_postgres_event_listener():
    try:
        loaded = load_persistent_rule_configs()
        print(f"[SOC SIEM] Loaded {loaded} persistent rule configuration(s).", flush=True)
    except Exception as exc:
        print(f"[SOC SIEM] Rule config load failed; using in-code defaults: {exc}", flush=True)

    from siem_response import ensure_firewall_chain

    try:
        firewall_status = ensure_firewall_chain()
        if firewall_status["success"]:
            print("[SOC SIEM] Firewall response chain ready.", flush=True)
        else:
            print(
                "[SOC SIEM] Firewall response unavailable: "
                f"{firewall_status.get('reason', 'unknown error')}",
                flush=True,
            )
    except Exception as exc:
        # Firewall setup failure must not prevent the SOC listeners from starting.
        print(f"[SOC SIEM] Firewall setup error: {exc}", flush=True)

    postgres_event_listener.start()
    start_realtime_journal_listener()


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
app.include_router(vapt_registry_router)
app.include_router(network_realtime_router)
app.include_router(metasploit_realtime_router)
app.include_router(access_validation_router)
app.include_router(risk_assessment_router)
app.include_router(credential_realtime_router)
app.include_router(tshark_snort_realtime_router)

# OWASP ZAP dedicated integration
app.include_router(zap_router)

# OWASP Juice Shop Lab Integration
app.include_router(juice_shop_router)

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
app.include_router(system_health_router)

# Audit Trail
app.include_router(audit_router)

# Reports - Dashboard / Summary
app.include_router(reports_router)

# Reports - PDF Generator
app.include_router(report_generator_router)
app.include_router(vapt_reporting_router)
app.include_router(code_security_router)

# Reports - Issues / Remediation
app.include_router(report_issues_router)

# MITRE ATT&CK
app.include_router(mitre_router)

# SOC Security Events
app.include_router(security_events_router)
app.include_router(ioc_router)
app.include_router(sigma_router)

# SOC Real-Time Events
app.include_router(realtime_router)
app.include_router(admin_notifications_router)
app.include_router(user_notifications_router)
app.include_router(user_notifications_realtime_router)
app.include_router(admin_notifications_realtime_router)
app.include_router(admin_notification_policies_router)
app.include_router(admin_notification_channels_router)

# SOC Incident Management
app.include_router(incident_router)


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