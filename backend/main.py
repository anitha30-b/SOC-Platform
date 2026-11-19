from security_policies_router import router as security_policies_router
from security_baselines_router import router as security_baselines_router
from detection_config_router import router as detection_config_router
from alert_config_router import router as alert_config_router
from retention_router import router as retention_router
from platform_config_router import router as platform_config_router
from security_posture_router import router as security_posture_router
from risk_overview_router import router as risk_overview_router
from risk_overview_router import router as risk_overview_router
import asyncio
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
from access_logging_middleware import AccessLoggingMiddleware

from database import Base, engine
from siem_integrations_router import router as siem_integrations_router
import models  # Register SQLAlchemy models

from auth import router as auth_router
from admin import router as admin_router
from assets_router import router as assets_router
from asset_groups_router import router as asset_groups_router
from asset_groups_router import AssetGroup, AssetGroupMember
from server_monitor import monitor_servers_once
from server_monitor_router import router as server_monitor_router
from analyst import router as analyst_router
from client import router as client_router
from client_portal import router as client_portal_router
from vapt import router as vapt_router
from vapt_registry_router import router as vapt_registry_router
from qa import router as qa_router
from logs import router as logs_router
from system_backup_router import router as system_backup_router
from system_license_router import router as system_license_router
from compliance_router import router as compliance_router
from system_logs_router import router as system_logs_router
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

# SOC Real-Time Events
from realtime_router import router as realtime_router

# SOC PostgreSQL Real-Time Event Listener
from postgres_event_listener import postgres_event_listener
from siem_ingestion import siem_ingestion_loop
from snort_journal_listener import snort_journal_listener_loop
from admin_notifications_router import router as admin_notifications_router
from user_notifications_router import router as user_notifications_router
from user_notifications_realtime_router import router as user_notifications_realtime_router
from admin_notifications_realtime_router import router as admin_notifications_realtime_router
from admin_notification_policies_router import router as admin_notification_policies_router
from admin_notification_channels_router import router as admin_notification_channels_router
from admin_email_header_analysis_router import router as admin_email_header_analysis_router

# SOC Incident Management
from incident import router as incident_router


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

from agent_health_router import SecurityAgent
from agent_health_router import router as agent_health_router
from background_jobs_router import router as background_jobs_router

Base.metadata.create_all(bind=engine)
with engine.begin() as connection:
    from sqlalchemy import text
    connection.execute(text(
        "ALTER TABLE soc_assets ADD COLUMN IF NOT EXISTS url VARCHAR(2048)"
    ))


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="SOC Platform API",
    description="Security Operations Center Platform API",
    version="1.0.0",
)

app.add_middleware(AccessLoggingMiddleware)



# ============================================================
# POSTGRESQL REAL-TIME EVENT LISTENER
# ============================================================

_siem_ingestion_task = None
_snort_journal_task = None


@app.on_event("startup")
async def start_siem_ingestion():
    global _siem_ingestion_task
    if _siem_ingestion_task is None or _siem_ingestion_task.done():
        _siem_ingestion_task = asyncio.create_task(siem_ingestion_loop())


@app.on_event("shutdown")
async def stop_siem_ingestion():
    global _siem_ingestion_task
    if _siem_ingestion_task is not None:
        _siem_ingestion_task.cancel()
        try:
            await _siem_ingestion_task
        except asyncio.CancelledError:
            pass
        _siem_ingestion_task = None


@app.on_event("startup")
async def start_snort_journal_listener():
    global _snort_journal_task
    if _snort_journal_task is None or _snort_journal_task.done():
        _snort_journal_task = asyncio.create_task(
            snort_journal_listener_loop()
        )


@app.on_event("shutdown")
async def stop_snort_journal_listener():
    global _snort_journal_task
    if _snort_journal_task is not None:
        _snort_journal_task.cancel()
        try:
            await _snort_journal_task
        except asyncio.CancelledError:
            pass
        _snort_journal_task = None


@app.on_event("startup")
def start_postgres_event_listener():
    postgres_event_listener.start()


# ============================================================
# AUTOMATIC SERVER MONITORING
# ============================================================

_server_monitor_task = None


async def server_monitor_loop():
    while True:
        try:
            count = await asyncio.to_thread(monitor_servers_once)
            print(f"[SERVER MONITOR] Checked {count} server asset(s).")
        except Exception as exc:
            print(f"[SERVER MONITOR] Check failed: {exc}")

        await asyncio.sleep(60)


@app.on_event("startup")
async def start_server_monitor():
    global _server_monitor_task
    if _server_monitor_task is None or _server_monitor_task.done():
        _server_monitor_task = asyncio.create_task(server_monitor_loop())


@app.on_event("shutdown")
async def stop_server_monitor():
    global _server_monitor_task
    if _server_monitor_task is not None:
        _server_monitor_task.cancel()
        try:
            await _server_monitor_task
        except asyncio.CancelledError:
            pass
        _server_monitor_task = None


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
from external_api import router as external_api_router

app.include_router(auth_router)
app.include_router(external_api_router)

# Administration
app.include_router(admin_router)
app.include_router(siem_integrations_router)
app.include_router(assets_router)
app.include_router(asset_groups_router)
app.include_router(server_monitor_router)

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
app.include_router(system_backup_router)
app.include_router(system_license_router)
app.include_router(compliance_router)
app.include_router(system_logs_router)

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
app.include_router(agent_health_router)
app.include_router(background_jobs_router)

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

# SOC Real-Time Events
app.include_router(realtime_router)
app.include_router(admin_notifications_router)
app.include_router(user_notifications_router)
app.include_router(user_notifications_realtime_router)
app.include_router(admin_notifications_realtime_router)
app.include_router(admin_notification_policies_router)
app.include_router(security_policies_router)
app.include_router(alert_config_router)
app.include_router(detection_config_router)
app.include_router(security_baselines_router)
app.include_router(retention_router)
app.include_router(security_posture_router)
app.include_router(risk_overview_router)
app.include_router(platform_config_router)
app.include_router(admin_notification_channels_router)
app.include_router(admin_email_header_analysis_router)

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

# Gracefully stop the PostgreSQL event listener on application shutdown.
@app.on_event("shutdown")
def stop_postgres_event_listener():
    postgres_event_listener.stop()
