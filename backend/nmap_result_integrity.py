"""Combine Nmap evidence without hiding incomplete stages."""
from copy import deepcopy
import json
import xml.etree.ElementTree as ET


def analyze_nmap_pass(scan_pass, parser):
    parsed = parser(scan_pass.get('xml') or '')
    errors = []
    if scan_pass.get('execution_error'):
        errors.append(str(scan_pass['execution_error']))
    if scan_pass.get('timed_out'):
        errors.append('Scan stage timed out.')
    code = scan_pass.get('return_code')
    if code is None and not scan_pass.get('timed_out') and not scan_pass.get('execution_error'):
        errors.append('Scan stage did not report an exit code.')
    elif code not in (None, 0):
        errors.append(f'Scan stage exited with code {code}.')
    for key in ('parse_error', 'scan_error'):
        if parsed.get(key):
            errors.append(str(parsed[key]))
    if not parsed.get('parse_error'):
        try:
            root = ET.fromstring(scan_pass.get('xml') or '')
            finished = root.find('runstats/finished')
            if root.tag != 'nmaprun':
                errors.append('Expected an Nmap XML document.')
            elif finished is None or finished.get('exit') != 'success':
                errors.append('Nmap XML does not report successful stage completion.')
        except ET.ParseError as exc:
            errors.append(str(exc))
    return {
        'complete': not errors, 'return_code': code,
        'timed_out': bool(scan_pass.get('timed_out')),
        'errors': list(dict.fromkeys(errors)), 'parsed': parsed,
    }


def _unique(values):
    seen, result = set(), []
    for value in values:
        key = json.dumps(value, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            result.append(deepcopy(value))
    return result


def _addresses(host):
    # MAC addresses and hostnames alone do not establish host identity.
    return {(item.get('type'), item.get('address'))
            for item in host.get('addresses', [])
            if item.get('type') in ('ipv4', 'ipv6') and item.get('address')}


def merge_nmap_results(*results):
    """Preserve the first inventory and enrich it with subsequent real evidence.

    Match hosts by IP and ports by protocol plus number. Existing inventory
    states remain attributable to that inventory pass. Later passes add service,
    OS and script evidence; absent ports never erase earlier observed ports.
    """
    hosts = []
    for parsed in results:
        for incoming in parsed.get('hosts', []):
            identity = _addresses(incoming)
            host = next((item for item in hosts if identity and identity & _addresses(item)), None)
            if host is None:
                hosts.append(deepcopy(incoming))
                continue
            for key in ('addresses', 'hostnames', 'scripts', 'os_matches'):
                host[key] = _unique(host.get(key, []) + incoming.get(key, []))
            if incoming.get('uptime') is not None:
                host['uptime'] = deepcopy(incoming['uptime'])
            if host.get('status') in (None, 'unknown') and incoming.get('status'):
                host['status'] = incoming['status']
            ports = host.setdefault('ports', [])
            by_port = {(item.get('protocol'), item.get('port')): item for item in ports}
            for incoming_port in incoming.get('ports', []):
                key = (incoming_port.get('protocol'), incoming_port.get('port'))
                port = by_port.get(key)
                if port is None:
                    port = deepcopy(incoming_port)
                    ports.append(port)
                    by_port[key] = port
                    continue
                port['scripts'] = _unique(port.get('scripts', []) + incoming_port.get('scripts', []))
                service = port.setdefault('service', {})
                service.update({key: deepcopy(value) for key, value in incoming_port.get('service', {}).items()
                                if value not in (None, '')})
    return {'hosts': hosts, 'host_count': len(hosts)}


def apply_nmap_outcomes(result, stages):
    summaries = []
    errors = list(result.get('errors') or [])
    for name, report in stages:
        summaries.append({
            'name': name, 'status': 'completed' if report['complete'] else
                ('timeout' if report['timed_out'] else 'completed_with_errors'),
            'return_code': report['return_code'], 'errors': report['errors'],
        })
        errors.extend(f'{name}: {message}' for message in report['errors'])
    complete = bool(stages) and all(report['complete'] for _, report in stages)
    result['status'] = 'completed' if complete else 'completed_with_errors'
    codes = [report['return_code'] for _, report in stages]
    if any(report['timed_out'] for _, report in stages) or None in codes:
        result['return_code'] = None
    else:
        result['return_code'] = next((code for code in codes if code != 0), 0)
    result['errors'] = list(dict.fromkeys(errors))
    workflow = result.setdefault('workflow', {})
    workflow['stage_results'] = summaries
    workflow['all_tcp_ports_scanned'] = any(
        name == 'all_tcp_ports' and report['complete'] for name, report in stages)
    if isinstance(result.get('nse'), dict):
        result['nse']['executed'] = any('_nse' in name for name, _ in stages)
    return result
