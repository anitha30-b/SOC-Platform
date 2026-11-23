"""Persist Nmap evidence in existing owned inventory and event tables."""
from datetime import datetime, timezone
from ipaddress import ip_address
import json

from models import Assessment, AssetDiscoveryRun, ServerAsset, SecurityEvent
from scan_event_ownership import resolve_scan_event_owner
from security_event_store import store_security_event
from security_events import generate_event_id


def normalized_hosts(result):
    """Keep canonical IP observations; open ports are not vulnerability findings."""
    hosts = result.get('results', {}).get('hosts', [])
    if not isinstance(hosts, list):
        raise ValueError('Nmap host evidence must be a list.')
    rows = {}
    skipped = 0
    for host in hosts:
        if not isinstance(host, dict):
            skipped += 1
            continue
        address = None
        for item in host.get('addresses', []):
            if isinstance(item, dict) and item.get('type') in {'ipv4', 'ipv6'}:
                try:
                    address = str(ip_address(item.get('address', '')))
                    break
                except ValueError:
                    pass
        if address is None:
            skipped += 1
            continue
        row = rows.setdefault(address, {'hostname':None, 'status':host.get('status'), 'ports':{}})
        for name in host.get('hostnames', []):
            value = name.get('name') if isinstance(name, dict) else name
            if isinstance(value, str) and value.strip() and row['hostname'] is None:
                row['hostname'] = value.strip()[:500]
        for port in host.get('ports', []):
            if not isinstance(port, dict) or port.get('state') != 'open':
                continue
            number = port.get('port')
            if isinstance(number, bool):
                continue
            try:
                number = int(number)
            except (ValueError, TypeError):
                continue
            protocol = str(port.get('protocol', 'tcp')).lower()
            if not 1 <= number <= 65535 or protocol not in {'tcp', 'udp', 'sctp'}:
                continue
            row['ports'][(protocol, number)] = dict(port, port=number, protocol=protocol)
    return rows, skipped


def save_nmap_inventory(db, result, user_id, client_id, job_id):
    resolve_scan_event_owner(db, user_id, client_id)
    if result.get('status') not in {'completed', 'completed_with_errors'}:
        raise ValueError('Only terminal Nmap evidence can enter inventory.')
    if not isinstance(job_id, str) or not job_id or len(job_id) > 90:
        raise ValueError('A valid Nmap job ID is required.')
    target = str(result.get('target') or '').strip()
    if not target or len(target) > 500:
        raise ValueError('Nmap inventory target is missing or too long.')
    run_key = 'nmap:' + job_id
    run = db.query(AssetDiscoveryRun).filter(AssetDiscoveryRun.job_id == run_key).first()
    if run is not None:
        assessment = db.get(Assessment, run.assessment_id)
        if run.user_id != user_id or assessment is None or assessment.user_id != user_id or run.target != target:
            raise ValueError('Existing Nmap inventory does not belong to this job owner.')
        try:
            same_evidence = json.loads(run.result_data) == json.loads(json.dumps(result, default=str))
        except (ValueError, TypeError):
            same_evidence = False
        if not same_evidence:
            raise ValueError('This Nmap job already has different saved evidence; start a new job.')
        return {'created':0, 'updated':0, 'skipped':0, 'assessment_id':run.assessment_id,
                'discovery_run_id':run.id, 'replayed':True, 'inventory':'owned_server_assets'}
    hosts, skipped = normalized_hosts(result)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    status = result['status']
    assessment = Assessment(user_id=user_id, target=target, vapt_status=status,
                            vapt_findings_count=0, overall_status=status)
    db.add(assessment)
    db.flush()
    run = AssetDiscoveryRun(job_id=run_key, user_id=user_id, assessment_id=assessment.id,
                            target=target, scan_type=str(result.get('scan_type') or 'quick')[:50],
                            status=status.upper(), host_count=len(hosts),
                            open_port_count=sum(len(row['ports']) for row in hosts.values()),
                            result_data=json.dumps(result, default=str), started_at=now, completed_at=now)
    db.add(run)
    db.flush()
    for address, row in hosts.items():
        db.add(ServerAsset(user_id=user_id, assessment_id=assessment.id, discovery_run_id=run.id,
                           target=target, ip_address=address, hostname=row['hostname'],
                           host_status=str(row['status'] or 'unknown')[:30],
                           open_port_count=len(row['ports']),
                           services_data=json.dumps(list(row['ports'].values()), default=str), last_seen=now))
    db.flush()
    return {'created':len(hosts), 'updated':0, 'skipped':skipped, 'assessment_id':assessment.id,
            'discovery_run_id':run.id, 'replayed':False, 'inventory':'owned_server_assets'}


def save_nmap_event(db, result, user_id, client_id, job_id, assessment_id):
    scope = resolve_scan_event_owner(db, user_id, client_id)
    assessment = db.get(Assessment, assessment_id)
    if assessment is None or assessment.user_id != user_id:
        raise ValueError('Nmap event assessment does not belong to the initiating user.')
    event_id = generate_event_id(json.dumps({'tool':'nmap', 'job_id':job_id, **scope}, sort_keys=True))
    existing = db.query(SecurityEvent).filter(SecurityEvent.event_id == event_id).first()
    if existing is not None:
        if (existing.owner_user_id, existing.client_id, existing.assessment_id) != (user_id, client_id, assessment_id):
            raise ValueError('Existing Nmap event has a different ownership scope.')
        return existing
    partial = result.get('status') == 'completed_with_errors'
    event = {'event_id':event_id, **scope, 'assessment_id':assessment_id,
             'timestamp':datetime.now(timezone.utc).isoformat(), 'source':'nmap', 'event_type':'vapt_scan',
             'severity':'WARNING' if partial else 'INFO', 'target':result.get('target'),
             'message':f"Nmap {result.get('scan_type', 'quick')} scan completed{' with warnings' if partial else ''} for {result.get('target')}",
             'raw_event':result}
    return store_security_event(db, event, mitre_mapping={
        'technique_id':'T1046', 'technique_name':'Network Service Discovery', 'tactics':['discovery'],
        'mapping_source':'security_tool_context', 'confidence':'low',
        'evidence':'Authorised scanner activity; this context alone is not evidence of an attack.'})


def persist_nmap_completion(db, result, user_id, client_id, job_id):
    """The caller commits inventory, assessment, event and detections together."""
    summary = save_nmap_inventory(db, result, user_id, client_id, job_id)
    event = save_nmap_event(db, result, user_id, client_id, job_id, summary['assessment_id'])
    notification = {name:getattr(event, name) for name in (
        'event_id', 'source', 'event_type', 'severity', 'message', 'target',
        'assessment_id', 'owner_user_id', 'client_id')}
    notification['timestamp'] = event.timestamp.isoformat()
    return summary, notification
