"""Store Nuclei assessments, canonical findings and events in one owned transaction."""
from datetime import datetime, timezone
import hashlib
import json
import math

from models import Assessment, BackgroundJob, SecurityEvent, SecurityFinding
from scan_event_ownership import resolve_scan_event_owner
from security_event_store import store_security_event


def cvss_value(finding):
    raw=finding.get('raw') or {}
    info=(raw.get('info') or {}) if isinstance(raw,dict) else {}
    classification=(info.get('classification') or {}) if isinstance(info,dict) else {}
    value=classification.get('cvss-score') if isinstance(classification,dict) else None
    if value is None or isinstance(value,bool):
        return None
    try:
        value=float(value)
    except (TypeError,ValueError,OverflowError):
        return None
    return value if math.isfinite(value) and 0<=value<=10 else None


def finding_identity(finding):
    raw=finding.get('raw') if isinstance(finding.get('raw'),dict) else {}
    return {'template_id':finding.get('template_id') or finding.get('name'),
            'location':finding.get('matched_at') or finding.get('url') or finding.get('host'),
            'matcher':raw.get('matcher-name'),'extractor':raw.get('extractor-name')}


def joined(value,limit):
    if isinstance(value,list):
        value=', '.join(str(item) for item in value)
    return str(value)[:limit] if value else None


def mark_persistence_failure(result):
    """Retain scanner evidence while showing the saving failure to all result views."""
    result.setdefault('execution_status',result.get('status','unknown'))
    if result.get('status')=='completed':
        result['status']='completed_with_errors'
    result['persistence']={'status':'failed'}
    errors=result.setdefault('errors',[])
    if not isinstance(errors,list):
        errors=result['errors']=[str(errors)]
    errors.append('Scan results could not be saved to assessment/report history.')


def persist_nuclei_result(db,result,user_id,client_id,job_id=None):
    scope=resolve_scan_event_owner(db,user_id,client_id)
    if result.get('status') not in {'completed','completed_with_errors'}:
        raise ValueError('Only completed or partial Nuclei evidence can be saved.')
    target=str(result.get('target') or '').strip()
    if not target or len(target)>500:
        raise ValueError('Nuclei assessment target is missing or too long.')
    findings=result.get('findings',[])
    if not isinstance(findings,list) or any(not isinstance(f,dict) or not (f.get('template_id') or f.get('name')) for f in findings):
        raise ValueError('Nuclei findings are malformed.')
    # Explicit server-generated scan IDs distinguish repeated scans; legacy callers
    # retain deterministic replay behaviour through an evidence fingerprint.
    evidence=json.dumps(result,sort_keys=True,default=str)
    legacy_identity=json.dumps({'scope':scope,'evidence':json.loads(evidence)},sort_keys=True,default=str)
    scan_key='nuclei:'+str(job_id or hashlib.sha256(legacy_identity.encode()).hexdigest())
    if len(scan_key)>100:
        raise ValueError('Nuclei scan identity is too long.')
    record=db.query(BackgroundJob).filter(BackgroundJob.job_id==scan_key).first()
    if record is not None:
        try:
            stored=json.loads(record.result_json)
        except (ValueError,TypeError):
            raise ValueError('Existing Nuclei scan snapshot is invalid.') from None
        if record.user_id!=user_id or record.tool!='Nuclei' or stored.get('scope')!=scope or stored.get('evidence')!=json.loads(evidence):
            raise ValueError('Nuclei scan identity already belongs to different evidence or ownership.')
        assessment=db.get(Assessment,stored.get('assessment_id'))
        if assessment is None or assessment.user_id!=user_id:
            raise ValueError('Existing Nuclei assessment ownership is invalid.')
        return {'assessment_id':assessment.id,'scan_record_id':record.id,'new_events':0,
                'finding_count':assessment.vapt_findings_count,'replayed':True},[]
    unique={}
    for finding in findings:
        key=json.dumps(finding_identity(finding),sort_keys=True,default=str)
        unique.setdefault(key,finding)
    now=datetime.now(timezone.utc).replace(tzinfo=None)
    assessment=Assessment(user_id=user_id,target=target,vapt_status=result['status'],
                          vapt_findings_count=len(unique),overall_status=result['status'])
    db.add(assessment)
    db.flush()
    notifications=[]
    for identity,finding in unique.items():
        digest=hashlib.sha256(json.dumps({'scope':scope,'scan':scan_key,'finding':identity},sort_keys=True).encode()).hexdigest()
        severity=str(finding.get('severity') or 'INFO').upper()
        if severity=='INFORMATIONAL':
            severity='INFO'
        if severity not in {'CRITICAL','HIGH','MEDIUM','LOW','INFO'}:
            severity='UNRATED'
        risk='LEVEL_1' if severity in {'CRITICAL','HIGH'} else 'LEVEL_2' if severity=='MEDIUM' else 'LEVEL_3' if severity in {'LOW','INFO'} else 'UNRATED'
        name=str(finding.get('name') or finding.get('template_id'))
        location=str(finding.get('matched_at') or finding.get('url') or finding.get('host') or target)
        raw=finding.get('raw') if isinstance(finding.get('raw'),dict) else {}
        info=raw.get('info') if isinstance(raw.get('info'),dict) else {}
        canonical=SecurityFinding(finding_id='NUC-'+digest[:44],user_id=user_id,assessment_id=assessment.id,
            tool_name='Nuclei',tool_category='Web Application Security',title=name[:500],
            vulnerability=str(finding.get('template_id') or name)[:500],
            description=str(finding.get('description')) if finding.get('description') is not None else None,
            severity=severity,risk_level=risk,cvss_score=cvss_value(finding),status='OPEN',
            affected_asset=target,affected_url=location[:1000],endpoint=location[:1000],
            cve_id=joined(finding.get('cve'),100),cwe_id=joined(finding.get('cwe'),100),
            evidence=json.dumps(finding,default=str),remediation=str(info['remediation']) if info.get('remediation') else None,
            references=json.dumps(finding.get('reference'),default=str) if finding.get('reference') else None,
            request_data=str(raw['request']) if raw.get('request') else None,
            response_data=str(raw['response']) if raw.get('response') else None)
        db.add(canonical)
        event={'event_id':digest,**scope,'assessment_id':assessment.id,'timestamp':now.isoformat(),
               'source':'nuclei','event_type':'vulnerability_finding','severity':severity,
               'target':target,'message':f'Nuclei detected {name} at {location}',
               'raw_event':{'tool':'Nuclei','finding':finding,'finding_id':canonical.finding_id}}
        # The normal store applies configured detections after the event receives its ID.
        store_security_event(db,event)
        notifications.append(event)
    db.flush()
    record=BackgroundJob(job_id=scan_key,tool='Nuclei',target=target,scan_type='http_templates',
        user_id=user_id,status=result['status'],progress=100,stage='Saved',created_at=now,updated_at=now,
        result_json=json.dumps({'scope':scope,'assessment_id':assessment.id,'evidence':json.loads(evidence)},default=str))
    db.add(record)
    db.flush()
    return {'assessment_id':assessment.id,'scan_record_id':record.id,'new_events':len(notifications),
            'finding_count':len(unique),'replayed':False},notifications
