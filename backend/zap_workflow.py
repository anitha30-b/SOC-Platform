"""Owned ZAP findings, SIEM events and immutable completed-result snapshots."""
from datetime import datetime, timezone
import hashlib
import json
from uuid import UUID

from finding_severity import normalize_severity
from models import Assessment, BackgroundJob, SecurityFinding
from scan_event_ownership import resolve_scan_event_owner
from security_event_store import store_security_event


def storage_id(scan_id):
    try:
        value = str(UUID(str(scan_id)))
    except (ValueError, TypeError, AttributeError):
        return None
    return value if value == str(scan_id) else None


def bounded(value, limit):
    return str(value)[:limit] if value is not None and str(value) else None


def result_snapshot(record, scope):
    try:
        saved = json.loads(record.result_json)
    except (ValueError, TypeError):
        raise ValueError('Saved ZAP result is invalid.') from None
    if not isinstance(saved, dict) or saved.get('scope') != scope or not isinstance(saved.get('result'), dict):
        raise ValueError('Saved ZAP result ownership is invalid.')
    return saved


def load_saved_zap_result(db, scan_id, user_id, client_id):
    ident = storage_id(scan_id)
    if ident is None:
        return None
    scope = resolve_scan_event_owner(db, user_id, client_id)
    record = db.query(BackgroundJob).filter(BackgroundJob.job_id == ident,
        BackgroundJob.user_id == user_id, BackgroundJob.tool == 'OWASP ZAP').first()
    if record is None or record.status != 'completed':
        return None
    try:
        saved = json.loads(record.result_json)
    except (ValueError,TypeError):
        return None
    if not isinstance(saved,dict) or saved.get('scope') != scope or not isinstance(saved.get('result'),dict):
        return None
    assessment = db.get(Assessment, saved.get('assessment_id'))
    if assessment is None or assessment.user_id != user_id:
        return None
    result = saved['result']
    if result.get('scan_id') != ident or result.get('assessment_id') != assessment.id or result.get('status') != 'completed':
        return None
    return result


def persist_zap_result(db, job, alerts):
    user_id, client_id = job['user_id'], job['client_id']
    scope = resolve_scan_event_owner(db, user_id, client_id)
    ident = storage_id(job.get('scan_id'))
    if ident is None:
        raise ValueError('ZAP scan requires a server-generated storage UUID.')
    if not isinstance(alerts, list) or any(not isinstance(a, dict) or not (a.get('name') or a.get('alert'))
        or not isinstance(a.get('url'), str) or not a['url'] for a in alerts):
        raise ValueError('ZAP alert evidence is malformed.')
    # Serialize finalization for this assessment on PostgreSQL. All writes remain
    # in the caller's transaction, including the normal detection engine store.
    assessment = db.query(Assessment).filter(Assessment.id == job['assessment_id'],
        Assessment.user_id == user_id).with_for_update().first()
    if assessment is None or assessment.target != job['target']:
        raise ValueError('ZAP assessment does not match the captured scan scope.')
    record = db.query(BackgroundJob).filter(BackgroundJob.job_id == ident).first()
    if record is not None:
        if record.user_id != user_id or record.tool != 'OWASP ZAP':
            raise ValueError('ZAP storage identity belongs to another scan.')
        saved = result_snapshot(record, scope)
        if saved.get('assessment_id') != assessment.id or saved.get('alerts') != alerts:
            raise ValueError('ZAP scan replay differs from the saved evidence.')
        return saved['result'], []
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    unique = {}
    for alert in alerts:
        identity = json.dumps({key: alert.get(key) for key in ('pluginId','name','alert','url','param','evidence')},
                              sort_keys=True, default=str)
        unique.setdefault(identity, alert)
    findings, notifications = [], []
    for identity, alert in unique.items():
        digest = hashlib.sha256(json.dumps({'scope':scope,'scan_id':ident,'alert':identity},sort_keys=True).encode()).hexdigest()
        severity = normalize_severity(alert.get('risk'))
        risk = ('LEVEL_1' if severity in {'CRITICAL','HIGH'} else 'LEVEL_2' if severity=='MEDIUM'
                else 'LEVEL_3' if severity in {'LOW','NONE','INFO'} else 'UNRATED')
        title = str(alert.get('alert') or alert['name'])
        cwe = alert.get('cweid')
        cwe = None if cwe in (None,'','-1',-1) else str(cwe)
        if cwe and not cwe.upper().startswith('CWE-'):
            cwe = 'CWE-'+cwe
        tags = alert.get('tags') if isinstance(alert.get('tags'),dict) else {}
        owasp = next((key for year in ('2025','2021','2017') for key in tags
                      if str(key).startswith('OWASP_'+year+'_')),None)
        finding = SecurityFinding(finding_id='ZAP-'+digest[:44],user_id=user_id,assessment_id=assessment.id,
            tool_name='OWASP ZAP',tool_category='Web Application Security',title=title[:500],
            vulnerability=title[:500],description=bounded(alert.get('description'),1000000),
            severity=severity,risk_level=risk,cvss_score=None,status='OPEN',
            cwe_id=bounded(cwe,100),owasp_category=bounded(owasp,100),affected_asset=job['target'],
            affected_url=bounded(alert['url'],1000),endpoint=bounded(alert['url'],1000),
            parameter=bounded(alert.get('param'),500),evidence=bounded(alert.get('evidence'),1000000),
            impact=bounded('ZAP risk: '+str(alert.get('risk')),1000000),
            remediation=bounded(alert.get('solution'),1000000),references=bounded(alert.get('reference'),1000000))
        db.add(finding)
        findings.append(finding)
        event = {'event_id':digest,**scope,'assessment_id':assessment.id,'timestamp':now.isoformat(),
            'source':'owasp-zap','event_type':'vulnerability_finding','severity':severity,
            'target':job['target'],'message':f'OWASP ZAP reported {title} at {alert["url"]}',
            'raw_event':{'tool':'OWASP ZAP','scan_id':ident,'finding_id':finding.finding_id,'alert':alert}}
        store_security_event(db,event)
        notifications.append(event)
    db.flush()
    assessment.vapt_status = 'completed'
    assessment.vapt_findings_count = len(findings)
    assessment.overall_status = 'active'
    fields = ('id','finding_id','title','severity','risk_level','tool_name','cwe_id','affected_url',
              'parameter','evidence','description','remediation','owasp_category','status')
    result = {'status':'completed','scan_id':ident,'target':job['target'],'assessment_id':assessment.id,
        'progress':100,'total_alerts':len(alerts),'total_findings':len(findings),'alerts':alerts,
        'findings':[{field:getattr(finding,field) for field in fields} for finding in findings],
        'persistence':{'status':'saved','assessment_id':assessment.id}}
    record = BackgroundJob(job_id=ident,tool='OWASP ZAP',target=job['target'],scan_type='active',user_id=user_id,
        status='completed',progress=100,stage='Saved',created_at=now,updated_at=now,
        result_json=json.dumps({'scope':scope,'assessment_id':assessment.id,'alerts':alerts,'result':result},default=str))
    db.add(record)
    db.flush()
    return result, notifications
