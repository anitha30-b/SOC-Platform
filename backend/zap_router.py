from __future__ import annotations



import asyncio

from datetime import datetime

from urllib.parse import urlparse



import httpx

from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from sqlalchemy.orm import Session



from database import get_db

from models import Assessment, SecurityFinding, SecurityTool, User

from rbac import require_role

from security_findings import (

    calculate_risk_level,

    generate_finding_id,

    seed_security_tools,

)





router = APIRouter(

    prefix="/vapt/zap",

    tags=["OWASP ZAP"],

)





from zap_configuration import load_zap_configuration
ZAP_URL, ZAP_API_KEY = load_zap_configuration()




# Development/single-process job store.

# For production this should eventually move to Redis/database.

ZAP_JOBS: dict[str, dict] = {}





class ZapScanRequest(BaseModel):
    target: str
    scanPolicyName: str = "Dev CICD"
    recurse: bool = True
    inScopeOnly: bool = False
    followRedirects: bool = True





async def zap_get(

    path: str,

    params: dict | None = None,

):

    query = {"apikey": ZAP_API_KEY}



    if params:

        query.update(params)



    async with httpx.AsyncClient(

        timeout=30.0

    ) as client:

        response = await client.get(

            f"{ZAP_URL}{path}",

            params=query,

        )

        response.raise_for_status()

        return response.json()





def validate_target(target: str) -> str:

    target = target.strip()



    parsed = urlparse(target)



    if parsed.scheme not in {"http", "https"}:

        raise HTTPException(

            status_code=400,

            detail="ZAP target must be a full HTTP/HTTPS URL",

        )



    if not parsed.hostname:

        raise HTTPException(

            status_code=400,

            detail="ZAP target must contain a valid hostname",

        )



    return target.rstrip("/")





def get_or_create_assessment(db: Session, current_user: User, target: str) -> Assessment:
    assessment = Assessment(user_id=current_user.id, target=target, vapt_status='running', vapt_findings_count=0, qa_status='not_started', monitoring_status='not_started', report_status='not_generated', overall_status='active')
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return assessment





def zap_risk_to_severity(risk: str) -> str:
    from finding_severity import normalize_severity
    return normalize_severity(risk)





def zap_owasp_category(alert: dict) -> str | None:

    tags = alert.get("tags") or {}



    for key, value in tags.items():

        if key.startswith("OWASP_2025_"):

            return key



    for key, value in tags.items():

        if key.startswith("OWASP_2021_"):

            return key



    for key, value in tags.items():

        if key.startswith("OWASP_2017_"):

            return key



    return None





def alert_identity(alert: dict) -> str:

    return "|".join(

        [

            str(alert.get("pluginId") or ""),

            str(alert.get("name") or alert.get("alert") or ""),

            str(alert.get("url") or ""),

            str(alert.get("param") or ""),

            str(alert.get("evidence") or ""),

        ]

    )





def sync_zap_findings(db: Session, current_user: User, assessment: Assessment, alerts: list[dict]) -> list[SecurityFinding]:
    if assessment.user_id != current_user.id:
        raise HTTPException(status_code=403, detail='Assessment owner mismatch')
    if not isinstance(alerts, list) or any((not isinstance(alert, dict) for alert in alerts)):
        raise ValueError('Invalid ZAP alerts')
    seed_security_tools(db)
    tool = db.query(SecurityTool).filter(SecurityTool.name == 'OWASP ZAP').first()
    if tool is None:
        raise HTTPException(status_code=500, detail='OWASP ZAP is not registered in the security tool catalog')
    created_or_existing: list[SecurityFinding] = []
    for alert in alerts:
        zap_risk = (alert.get('risk') or '').strip().upper()
        title = alert.get('alert') or alert.get('name') or 'OWASP ZAP Finding'
        affected_url = alert.get('url')
        parameter = alert.get('param') or None
        evidence = alert.get('evidence') or None
        description = alert.get('description') or None
        remediation = alert.get('solution') or None
        references = alert.get('reference') or None
        cwe_id = alert.get('cweid')
        if cwe_id in {None, '', '-1'}:
            cwe_id = None
        elif not str(cwe_id).upper().startswith('CWE-'):
            cwe_id = f'CWE-{cwe_id}'
        owasp_category = zap_owasp_category(alert)
        severity = zap_risk_to_severity(alert.get('risk'))
        risk_level = 'UNRATED' if severity == 'UNRATED' else calculate_risk_level(severity)
        existing_findings = db.query(SecurityFinding).filter(SecurityFinding.assessment_id == assessment.id, SecurityFinding.user_id == current_user.id, SecurityFinding.tool_name == tool.name, SecurityFinding.title == title, SecurityFinding.affected_url == affected_url, SecurityFinding.parameter == parameter).all()
        existing = None
        for item in existing_findings:
            if (item.evidence or '') == (evidence or ''):
                existing = item
                break
        now = datetime.utcnow()
        if existing:
            existing.description = description
            existing.cwe_id = cwe_id
            existing.severity = severity
            existing.risk_level = risk_level
            existing.owasp_category = owasp_category
            existing.evidence = evidence
            existing.remediation = remediation
            existing.references = references
            existing.updated_at = now
            created_or_existing.append(existing)
            continue
        finding = SecurityFinding(finding_id=generate_finding_id(db), user_id=current_user.id, assessment_id=assessment.id, tool_name=tool.name, tool_category=tool.category or 'Web Application Security', title=title, vulnerability=title, description=description, owasp_category=owasp_category, owasp_api_category=None, cve_id=None, cwe_id=cwe_id, cvss_score=None, severity=severity, risk_level=risk_level, affected_asset=affected_url, affected_url=affected_url, endpoint=affected_url, parameter=parameter, evidence=evidence, request_data=None, response_data=None, impact=f"ZAP risk: {alert.get('risk')}" if alert.get('risk') else None, remediation=remediation, references=references, status='OPEN', detected_at=now, created_at=now, updated_at=now)
        db.add(finding)
        db.flush()
        created_or_existing.append(finding)
    assessment.vapt_status = 'completed'
    assessment.vapt_findings_count = db.query(SecurityFinding).filter(SecurityFinding.assessment_id == assessment.id).count()
    assessment.overall_status = 'active'
    db.commit()
    for finding in created_or_existing:
        db.refresh(finding)
    return created_or_existing





@router.get("/status")

async def zap_status(current_user: User=Depends(require_role(1))):
    try:
        version = await zap_get('/JSON/core/view/version/')
        return {'status': 'running', 'version': version.get('version'), 'url': ZAP_URL}
    except Exception:
        return {'status': 'offline', 'url': ZAP_URL, 'error': 'Unable to reach the configured ZAP service'}





# ============================================================

# COMPLETE ZAP SCAN START

# ============================================================



@router.post("/scan")

async def start_zap_scan(request: ZapScanRequest, current_user: User=Depends(require_role(1)), db: Session=Depends(get_db)):
    from uuid import uuid4
    _check_zap_start_permission(db, current_user)
    target = validate_target(request.target)
    if len(target) > 500:
        raise HTTPException(status_code=400, detail='ZAP target is too long')
    try:
        access_result = await zap_get('/JSON/core/action/accessUrl/', {'url': target, 'followRedirects': str(request.followRedirects).lower()})
        scan_result = await zap_get('/JSON/ascan/action/scan/', {'url': target, 'recurse': str(request.recurse).lower(), 'inScopeOnly': str(request.inScopeOnly).lower(), 'scanPolicyName': request.scanPolicyName or 'Dev CICD'})
        raw_id = scan_result.get('scan')
        if raw_id is None:
            raise ValueError('ZAP did not return an active scan ID')
        assessment = get_or_create_assessment(db, current_user, target)
        scan_id = str(uuid4())
        ZAP_JOBS[scan_id] = {'scan_id': scan_id, 'zap_scan_id': str(raw_id), 'target': target, 'user_id': current_user.id, 'client_id': current_user.client_id, 'assessment_id': assessment.id, 'status': 'running', 'access_result': access_result, 'created_at': datetime.utcnow().isoformat(), 'results_synced': False}
        return {'status': 'started', 'target': target, 'scan_id': scan_id, 'assessment_id': assessment.id}
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=502, detail='Unable to start or record ZAP scan')





# ============================================================

# SCAN PROGRESS

# ============================================================



@router.get(

    "/scan/{scan_id}/progress"

)

async def zap_scan_progress(scan_id: str, current_user: User=Depends(require_role(1)), db: Session=Depends(get_db)):
    if scan_id in ZAP_JOBS:
        job = _owned_zap_job(scan_id, current_user)
    else:
        job = None
    saved = _saved_zap_result(db, scan_id, current_user)
    if saved:
        return {'scan_id': scan_id, 'status': 100, 'state': saved['status'], 'assessment_id': saved['assessment_id']}
    if job is None:
        raise HTTPException(status_code=404, detail='ZAP scan not found')
    if job.get('status') == 'cancelled':
        return {'scan_id': scan_id, 'status': 0, 'state': 'cancelled'}
    try:
        result = await zap_get('/JSON/ascan/view/status/', {'scanId': job.get('zap_scan_id', scan_id)})
        progress = int(result['status'])
        if not 0 <= progress <= 100:
            raise ValueError('Invalid ZAP progress')
        return {'scan_id': scan_id, 'status': progress, 'state': 'completed' if progress == 100 else 'running'}
    except Exception:
        raise HTTPException(status_code=502, detail='Unable to read valid ZAP scan progress')





# ============================================================

# ============================================================
# SCAN CANCEL
# ============================================================


@router.post("/scan/{scan_id}/cancel")
async def cancel_zap_scan(scan_id: str, current_user: User=Depends(require_role(1)), db: Session=Depends(get_db)):
    job = _owned_zap_job(scan_id, current_user)
    if _saved_zap_result(db, scan_id, current_user):
        raise HTTPException(status_code=409, detail='ZAP scan already has saved results')
    try:
        response = await zap_get('/JSON/ascan/action/stop/', {'scanId': job.get('zap_scan_id', scan_id)})
        if response.get('Result') != 'OK':
            raise ValueError('ZAP did not confirm cancellation')
        job['status'] = 'cancelled'
        return {'status': 'cancelled', 'scan_id': scan_id, 'zap_response': response}
    except Exception:
        raise HTTPException(status_code=502, detail='Unable to confirm ZAP scan cancellation')


# SCAN RESULTS + SECURITY FINDING SYNC

# ============================================================



@router.get(

    "/scan/{scan_id}/results"

)

async def zap_scan_results(scan_id: str, current_user: User=Depends(require_role(1)), db: Session=Depends(get_db)):
    job = _owned_zap_job(scan_id, current_user) if scan_id in ZAP_JOBS else None
    try:
        saved = _saved_zap_result(db, scan_id, current_user)
        if saved:
            return saved
        if job is None:
            raise HTTPException(status_code=404, detail='ZAP scan not found')
        if job.get('status') == 'cancelled':
            return {'status': 'cancelled', 'scan_id': scan_id, 'alerts': [], 'findings': []}
        progress = await zap_get('/JSON/ascan/view/status/', {'scanId': job.get('zap_scan_id', scan_id)})
        status = int(progress['status'])
        if not 0 <= status <= 100:
            raise ValueError('Invalid ZAP progress')
        if status < 100:
            return {'status': 'running', 'scan_id': scan_id, 'progress': status, 'target': job['target'], 'alerts': []}
        alerts = await _zap_scan_alerts(job.get('zap_scan_id', scan_id))
        from zap_workflow import persist_zap_result
        result, events = persist_zap_result(db, job, alerts)
        db.commit()
        job['results_synced'] = True
        job['status'] = 'completed'
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        if job is not None:
            job['status'] = 'completed_with_errors'
        raise HTTPException(status_code=502, detail='Unable to retrieve or save valid ZAP results')
    try:
        await asyncio.to_thread(_publish_zap_events, events)
    except Exception:
        result = dict(result, status='completed_with_errors', execution_status='completed', notification_errors=['Saved ZAP evidence; live publication was not confirmed.'])
        job['status'] = 'completed_with_errors'
    return result





# ============================================================

# EXISTING COMPATIBILITY ENDPOINTS

# ============================================================



@router.post("/active-scan")

async def start_zap_active_scan(request: ZapScanRequest, current_user: User=Depends(require_role(1)), db: Session=Depends(get_db)):
    return await start_zap_scan(request, current_user, db)





@router.get(

    "/active-scan/{scan_id}/progress"

)

async def zap_active_progress(scan_id: str, current_user: User=Depends(require_role(1)), db: Session=Depends(get_db)):
    return await zap_scan_progress(scan_id, current_user, db)





@router.get("/alerts")

async def zap_alerts(target: str | None=None, scan_id: str | None=None, current_user: User=Depends(require_role(1)), db: Session=Depends(get_db)):
    if not scan_id:
        raise HTTPException(status_code=400, detail='An owned scan_id is required')
    job = _owned_zap_job(scan_id, current_user) if scan_id in ZAP_JOBS else _saved_zap_result(db, scan_id, current_user)
    if job is None:
        raise HTTPException(status_code=404, detail='ZAP scan not found')
    if target is not None and validate_target(target) != job['target']:
        raise HTTPException(status_code=400, detail='Target does not match the owned ZAP scan')
    result = await zap_scan_results(scan_id, current_user, db)
    return {'alerts': result.get('alerts', []), 'status': result.get('status'), 'scan_id': scan_id}





@router.post(

    "/active-scan/{scan_id}/stop"

)

async def stop_zap_active_scan(scan_id: str, current_user: User=Depends(require_role(1)), db: Session=Depends(get_db)):
    return await cancel_zap_scan(scan_id, current_user, db)





# Legacy spider endpoints retained for compatibility.



@router.post("/spider")

async def start_zap_spider(request: ZapScanRequest, current_user: User=Depends(require_role(1)), db: Session=Depends(get_db)):
    _check_zap_start_permission(db, current_user)
    target = validate_target(request.target)
    try:
        result = await zap_get('/JSON/spider/action/scan/', {'url': target, 'recurse': str(request.recurse).lower()})
        scan_id = result.get('scan')
        if scan_id is None:
            raise ValueError('Missing spider ID')
        ZAP_SPIDER_JOBS[str(scan_id)] = {'scan_id': str(scan_id), 'target': target, 'user_id': current_user.id, 'client_id': current_user.client_id, 'status': 'running'}
        return {'status': 'started', 'target': target, 'spider_id': str(scan_id)}
    except Exception:
        raise HTTPException(status_code=502, detail='Unable to start ZAP spider')
@router.get(

    "/spider/{scan_id}/progress"

)

async def zap_spider_progress(scan_id: str, current_user: User=Depends(require_role(1))):
    job = _owned_zap_job(scan_id, current_user, spider=True)
    try:
        result = await zap_get('/JSON/spider/view/status/', {'scanId': scan_id})
        progress = int(result['status'])
        if not 0 <= progress <= 100:
            raise ValueError('Invalid spider progress')
        job['status'] = 'completed' if progress == 100 else 'running'
        return {'status': progress, 'scan_id': str(scan_id)}
    except Exception:
        raise HTTPException(status_code=502, detail='Unable to read valid ZAP spider progress')


ZAP_SPIDER_JOBS = {}


def _check_zap_start_permission(db, current_user):
    from vapt import require_user_tool_permission
    require_user_tool_permission(db, current_user, 'OWASP ZAP')

def _owned_zap_job(scan_id, current_user, spider=False):
    jobs = ZAP_SPIDER_JOBS if spider else ZAP_JOBS
    job = jobs.get(str(scan_id))
    if not isinstance(job, dict):
        raise HTTPException(status_code=404, detail='ZAP scan not found')
    if job.get('user_id') != current_user.id:
        raise HTTPException(status_code=403, detail='You do not have access to this ZAP scan')
    if 'client_id' not in job or job['client_id'] != current_user.client_id:
        raise HTTPException(status_code=404, detail='ZAP scan not found in the current customer scope')
    return job

async def _zap_scan_alerts(scan_id):
    response = await zap_get('/JSON/ascan/view/alertsIds/', {'scanId': str(scan_id)})
    ids = response.get('alertsIds')
    if not isinstance(ids, list) or any((isinstance(value, bool) or not str(value).isdigit() for value in ids)):
        raise ValueError('ZAP did not return a valid scan-specific alert list')
    alerts = []
    for ident in dict.fromkeys((str(value) for value in ids)):
        response = await zap_get('/JSON/core/view/alert/', {'id': ident})
        alert = response.get('alert')
        if not isinstance(alert, dict) or str(alert.get('id')) != ident or (not isinstance(alert.get('url'), str)) or (not alert['url']) or (not (alert.get('name') or alert.get('alert'))):
            raise ValueError('ZAP returned invalid scan-specific alert evidence')
        alerts.append(alert)
    return alerts


def _saved_zap_result(db, scan_id, current_user):
    from uuid import UUID
    try:
        if str(UUID(str(scan_id))) != str(scan_id):
            return None
    except (ValueError, TypeError, AttributeError):
        return None
    from zap_workflow import load_saved_zap_result
    return load_saved_zap_result(db, scan_id, current_user.id, current_user.client_id)

def _publish_zap_events(events):
    from realtime_journal_listener import notify_security_event
    for event in events:
        notify_security_event(event)
