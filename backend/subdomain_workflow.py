"""Shared DNS observations for registry, customer and administrative views."""
import ipaddress
import json
import re
from datetime import datetime
from uuid import uuid4


def domain_name(value):
    if not isinstance(value, str):
        raise ValueError('A DNS hostname is required.')
    value = value.strip().rstrip('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('Invalid DNS hostname.') from exc
    labels = value.split('.')
    if (len(value) > 253 or len(labels) < 2 or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels)):
        raise ValueError('Invalid DNS hostname.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Use a DNS domain rather than an IP address.')


def parse_discovery(target_domain, result):
    root = domain_name(target_domain)
    records = result.get('json_output')
    if not isinstance(records, list):
        raise ValueError('DNSRecon did not return a JSON record list.')
    hosts, addresses, observations = set(), set(), set()
    for record in records:
        if not isinstance(record, dict):
            continue
        try:
            name = domain_name(record.get('name'))
        except ValueError:
            continue
        if name != root and not name.endswith('.' + root):
            continue
        kind = str(record.get('type') or '').upper()
        address = None
        if kind in {'A', 'AAAA'}:
            try:
                parsed = ipaddress.ip_address(str(record.get('address') or '').strip())
            except ValueError:
                continue
            if (kind == 'A' and parsed.version != 4) or (kind == 'AAAA' and parsed.version != 6):
                continue
            address = str(parsed)
            addresses.add(address)
        elif kind == 'CNAME':
            try:
                address = domain_name(record.get('target') or record.get('address'))
            except ValueError:
                continue
        else:
            continue
        hosts.add(name)
        observations.add((name, kind, address))
    return {'target_domain': root, 'discovered_subdomains': sorted(hosts - {root}),
            'discovered_hosts': sorted(hosts), 'discovered_ips': sorted(addresses),
            'observations': [{'name': name, 'type': kind, 'address': address}
                             for name, kind, address in sorted(observations)]}


def payload(run):
    try:
        data = json.loads(run.result_data or '{}')
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def owner_valid(owner, captured):
    if not isinstance(captured, dict):
        return False
    uid, cid = captured.get('user_id'), captured.get('client_id')
    if (isinstance(uid, bool) or not isinstance(uid, int) or uid <= 0 or
            (cid is not None and (isinstance(cid, bool) or not isinstance(cid, int) or cid <= 0))):
        return False
    return bool(owner and
                captured.get('user_id') == owner.id and
                captured.get('client_id') == owner.client_id)


def new_run(db, user, assessment, target, job_id=None):
    from models import SubdomainDiscoveryRun
    run = SubdomainDiscoveryRun(job_id=job_id or str(uuid4()), user_id=user.id,
        assessment_id=assessment.id, target_domain=domain_name(target), status='QUEUED',
        discovered_subdomain_count=0, discovered_host_count=0, discovered_ip_count=0,
        result_data=json.dumps({'scope': {'user_id': user.id, 'client_id': user.client_id},
                                'workflow': 'subdomain-discovery', 'tool': 'DNSRecon'}))
    db.add(run)
    db.flush()
    return run


def finish_run(db, run, result):
    data = payload(run)
    status = str(result.get('status') or 'failed').lower()
    data['execution_status'] = status
    data['discovery_profile'] = result.get('discovery_profile')
    data['candidate_count'] = result.get('candidate_count')
    data['elapsed_seconds'] = result.get('elapsed_seconds')
    try:
        discovery = parse_discovery(run.target_domain, result)
    except ValueError:
        discovery = parse_discovery(run.target_domain, {'json_output': []})
        data['parse_error'] = 'Structured DNS output is missing or invalid.'
        if status == 'completed':
            status = 'completed_with_errors'
    data['discovery'] = discovery
    data['status'] = status
    run.result_data = json.dumps(data)
    run.status = status.upper()
    run.discovered_subdomain_count = len(discovery['discovered_subdomains'])
    run.discovered_host_count = len(discovery['discovered_hosts'])
    run.discovered_ip_count = len(discovery['discovered_ips'])
    run.completed_at = datetime.utcnow()
    run.updated_at = run.completed_at
    db.flush()
    return discovery, status


def execute_run(session_factory, runner, run_id, target):
    """Called in a worker thread; its database session stays in that thread."""
    from models import SubdomainDiscoveryRun, User
    from vapt import require_user_tool_permission
    db = session_factory()
    try:
        run = db.query(SubdomainDiscoveryRun).filter(SubdomainDiscoveryRun.id == run_id).first()
        if not run or run.status != 'QUEUED':
            return
        owner = db.query(User).filter(User.id == run.user_id).first()
        if not owner_valid(owner, payload(run).get('scope')) or domain_name(target) != run.target_domain:
            raise ValueError('Discovery ownership or target changed before execution.')
        require_user_tool_permission(db, owner, 'Subdomain Discovery')
        validate_assessment_scope(db, owner, run.assessment_id)
        run.status = 'RUNNING'
        run.started_at = datetime.utcnow()
        db.commit()
        result = runner(tool_id='subdomain-discovery', tool_name='Subdomain Discovery',
                        executable='dnsrecon', target=run.target_domain,
                        execution_type='scanner', timeout_seconds=300)
        db.expire_all()
        owner = db.query(User).filter(User.id == run.user_id).first()
        if not owner_valid(owner, payload(run).get('scope')):
            raise ValueError('Discovery ownership changed during execution.')
        validate_assessment_scope(db, owner, run.assessment_id)
        finish_run(db, run, result)
        db.commit()
    except Exception:
        db.rollback()
        run = db.query(SubdomainDiscoveryRun).filter(SubdomainDiscoveryRun.id == run_id).first()
        if run:
            data = payload(run)
            data.update(status='failed', error='Discovery failed. Check server diagnostics; no successful result is claimed.')
            run.status = 'FAILED'
            run.result_data = json.dumps(data)
            run.completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


def validate_assessment_scope(db, owner, assessment_id):
    from models import Assessment, User
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    source_owner = db.query(User).filter(User.id == assessment.user_id).first() if assessment else None
    if not source_owner or not (source_owner.id == owner.id or
            (owner.client_id is not None and source_owner.client_id == owner.client_id)):
        raise ValueError('The assessment is outside the initiating account scope.')


def save_registry_result(session_factory, result, user_id, client_id, job_id, target):
    from models import Assessment, SubdomainDiscoveryRun, User
    db = session_factory()
    try:
        owner = db.query(User).filter(User.id == user_id).first()
        if not owner_valid(owner, {'user_id': user_id, 'client_id': client_id}):
            raise ValueError('The initiating account scope has changed.')
        run = db.query(SubdomainDiscoveryRun).filter(SubdomainDiscoveryRun.job_id == job_id).first()
        if run:
            if (run.user_id != user_id or not owner_valid(owner, payload(run).get('scope'))
                    or run.target_domain != domain_name(target)):
                raise ValueError('Discovery job ownership mismatch.')
            if run.completed_at:
                summary = {'run_id': run.id, 'assessment_id': run.assessment_id,
                           'discovery': payload(run).get('discovery', {}),
                           'status': run.status.lower()}
                return summary
        else:
            assessment = Assessment(user_id=user_id, target=domain_name(target))
            db.add(assessment)
            db.flush()
            run = new_run(db, owner, assessment, target, job_id)
            run.started_at = datetime.utcnow()
        discovery, status = finish_run(db, run, result)
        summary = {'run_id': run.id, 'assessment_id': run.assessment_id,
                   'discovery': discovery, 'status': status}
        db.commit()
        return summary
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def list_runs(db, user, admin=False, q='', limit=50, offset=0):
    from models import SubdomainDiscoveryRun, User
    query = db.query(SubdomainDiscoveryRun, User).join(User, User.id == SubdomainDiscoveryRun.user_id)
    if not admin:
        query = query.filter(User.id == user.id) if user.client_id is None else query.filter(User.client_id == user.client_id)
    # Captured scope lives in existing JSON text, so filter it before pagination.
    rows = []
    for run, owner in query.order_by(SubdomainDiscoveryRun.id.desc()).all():
        data = payload(run)
        scope = data.get('scope')
        if not admin and not owner_valid(owner, scope):
            continue
        if q.strip() and q.strip().lower() not in (run.target_domain + ' ' + owner.username + ' ' + run.job_id).lower():
            continue
        discovery = data.get('discovery') or {}
        rows.append({'id': run.id, 'job_id': run.job_id, 'user_id': run.user_id,
            'owner_username': owner.username, 'client_id': scope.get('client_id') if isinstance(scope, dict) else None,
            'assessment_id': run.assessment_id, 'target_domain': run.target_domain,
            'status': run.status, 'created_at': run.created_at, 'completed_at': run.completed_at,
            'discovered_subdomain_count': run.discovered_subdomain_count,
            'discovered_host_count': run.discovered_host_count, 'discovered_ip_count': run.discovered_ip_count,
            'discovery': discovery, 'error': data.get('error') or data.get('parse_error'),
            'discovery_profile': data.get('discovery_profile'),
            'candidate_count': data.get('candidate_count'), 'elapsed_seconds': data.get('elapsed_seconds'),
            'scope_verified': isinstance(scope, dict)})
    return {'runs': rows[offset:offset + limit], 'total': len(rows),
            'count': len(rows[offset:offset + limit]), 'limit': limit, 'offset': offset}
