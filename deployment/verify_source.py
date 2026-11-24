"""One command for the reviewed isolated SOC verification suites and frontend build.

Does not launch the application, perform live scans, log in, or modify source.
Python test subprocesses use SQLite and block real network/process execution.
The allowlist is intentional: unreviewed test files are not executed automatically.
"""
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
HERE=Path(__file__).resolve().parent
USER_TESTS=[
    'admin_user_integration_regression.py','applications_accuracy_regression.py',
    'asset_list_scope_regression.py','asset_registration_regression.py',
    'copilot_regression.py','dashboard_accuracy_regression.py',
    'hunting_authorization_regression.py','incident_authorization_regression.py',
    'ioc_authorization_regression.py','logs_scope_regression.py',
    'nmap_profile_separation_regression.py','notification_authorization_regression.py',
    'report_authorization_regression.py','report_cvss_regression.py',
    'risk_management_regression.py','saved_searches_authorization_regression.py',
    'secrets_authorization_regression.py','security_events_authorization_regression.py',
    'support_authorization_regression.py','support_privacy_regression.py',
    'test_hunting_identity.py','test_ioc_url_matching.py','test_mitre_coverage_catalogue.py',
    'test_network_correlation.py','uptime_authorization_regression.py',
    'websocket_responsiveness_regression.py',
]
INTEGRATION_TESTS = ['detection_scope_regression.py', 'detection_legacy_scope_regression.py', 'detection_configuration_contract_regression.py', 'detection_display_linkage_regression.py', 'generic_tool_job_authorization_regression.py', 'nmap_multi_pass_regression.py', 'nmap_owned_inventory_regression.py', 'server_report_snapshot_regression.py', 'tool_event_ownership_regression.py', 'tool_output_accuracy_regression.py', 'admin_discovered_servers_regression.py', 'nuclei_assessment_linkage_regression.py', 'nuclei_report_contract_regression.py', 'report_display_linkage_regression.py', 'zap_access_regression.py', 'zap_assessment_linkage_regression.py', 'subdomain_workflow_regression.py', 'zap_configuration_regression.py', 'subdomain_permission_catalogue_regression.py', 'subdomain_profile_regression.py']
ENGINE_TESTS=[
    'test_detection_alert_engine.py','test_threshold_detection.py',
    'test_correlation_detection.py','test_anomaly_detection.py','test_telemetry_siem.py',
]
FRONTEND_TESTS = ['security_events_search_regression.cjs', 'tool_result_display_regression.cjs', 'tool_count_report_regression.cjs', 'admin_discovery_refresh_regression.cjs', 'deployment_api_regression.cjs', 'subdomain_results_refresh_regression.cjs', 'subdomain_vapt_display_regression.cjs', 'subdomain_profiles_ui_regression.cjs', 'user_navigation_regression.cjs']

BOOTSTRAP=r'''
import os, runpy, socket, sys, unittest
from pathlib import Path
os.environ['DATABASE_URL']='sqlite://'
os.environ['JWT_SECRET_KEY']='isolated-combined-soc-audit-not-for-deployment'
root=Path.cwd()
backend=root/'backend'
sys.path.insert(0,str(backend))
sys.path.insert(0,str(backend/'tests'))
path=Path(sys.argv[1]).resolve()
if not path.is_relative_to(backend.resolve()):
    raise SystemExit('Test path is outside the backend.')
def deny_execution(event,args):
    if event in {'socket.connect','socket.bind','subprocess.Popen','os.system','os.posix_spawn','os.spawn'}:
        raise RuntimeError('Isolated verification blocked real network/process execution: '+event)
sys.addaudithook(deny_execution)
if path.name in {'test_detection_alert_engine.py','test_threshold_detection.py',
    'test_correlation_detection.py','test_anomaly_detection.py','test_telemetry_siem.py',
    'detection_scope_regression.py','detection_legacy_scope_regression.py'}:
    import database, models
    assert database.engine.url.get_backend_name()=='sqlite'
    database.Base.metadata.create_all(database.engine)
    if path.name in {'test_telemetry_siem.py','detection_scope_regression.py','detection_legacy_scope_regression.py'}:
        suite=unittest.defaultTestLoader.loadTestsFromName(path.stem)
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        database.engine.dispose()
        raise SystemExit(not result.wasSuccessful())
    sys.argv=[str(path)]
    runpy.run_path(str(path),run_name='__main__')
    database.engine.dispose()
else:
    sys.argv=[str(path)]
    runpy.run_path(str(path),run_name='__main__')
'''


def manifest(root):
    checks=[]
    for name in USER_TESTS+INTEGRATION_TESTS:
        path=root/'backend/tests'/name
        checks.append((name,[sys.executable,'-c',BOOTSTRAP,str(path)],root,path,180))
    for name in ENGINE_TESTS:
        path=root/'backend'/name
        checks.append((name,[sys.executable,'-c',BOOTSTRAP,str(path)],root,path,180))
    for name in FRONTEND_TESTS:
        path=root/'frontend/tests'/name
        checks.append((name,['node',str(path)],root/'frontend',path,90))
    checks.append(('frontend_production_build',['npm','run','build'],root/'frontend',root/'frontend/package.json',240))
    return checks


def run_check(name,command,cwd,path,timeout,directory,env):
    started=time.monotonic()
    logfile=directory/(name+'.log')
    row={'name':name,'log':str(logfile)}
    if not path.is_file():
        row.update(status='MISSING',seconds=0)
        logfile.write_text('Reviewed test file is missing: '+str(path),encoding='utf-8')
        return row
    row['source_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    if command[0] in {'node','npm'} and not shutil.which(command[0]):
        row.update(status='MISSING_RUNTIME',seconds=0)
        logfile.write_text('Runtime is not on PATH: '+command[0],encoding='utf-8')
        return row
    try:
        with logfile.open('w',encoding='utf-8') as log:
            process=subprocess.run(command,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        row['status']='PASS' if process.returncode==0 else 'FAIL'
        row['returncode']=process.returncode
    except subprocess.TimeoutExpired:
        row['status']='TIMEOUT'
    except OSError as exc:
        row['status']='RUNNER_ERROR'
        row['error_type']=type(exc).__name__
    row['seconds']=round(time.monotonic()-started,2)
    return row


def main():
    if Path.cwd().resolve()!=ROOT:
        raise SystemExit('Run from the extracted SOC-Platform root.')
    os.umask(0o077)
    directory=ROOT/'.backups'/('combined_verification_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f'))
    directory.mkdir(parents=True)
    env=os.environ.copy()
    env.update(DATABASE_URL='sqlite://',JWT_SECRET_KEY='isolated-combined-soc-audit-not-for-deployment',
               SOC_NMAP_AUDIT_BACKEND=str(ROOT/'backend'),SOC_REPORT_AUDIT_BACKEND=str(ROOT/'backend'),
               SOC_SCAN_AUDIT_BACKEND=str(ROOT/'backend'),PYTHONUNBUFFERED='1')
    env['SOC_TOOL_AUDIT_BACKEND']=str(ROOT/'backend')
    env['PYTHONPATH']=str(ROOT/'backend')+os.pathsep+str(ROOT/'backend/tests')
    checks=manifest(ROOT)
    report={'started_at':datetime.now(timezone.utc).isoformat(),'checks':[], 'limits':[
        'Only the explicitly reviewed suites are included; this is not a certification of every endpoint or business feature.',
        'Python test networking and real process execution are blocked; scanner processes and subprocess callbacks are mocked.',
        'Does not verify all tools against live targets, browser rendering, deployment or billing.',
        'Does not change source, production database records, rules, collector configuration or server processes.',
    ]}
    print(f'Running {len(checks)} reviewed checks in one batch. No live scans or production database access.',flush=True)
    print('Failures will be collected; later checks will still run. This may take several minutes.',flush=True)
    try:
        for index,(name,command,cwd,path,timeout) in enumerate(checks,1):
            print(f'[{index}/{len(checks)}] RUN {name}',flush=True)
            row=run_check(name,command,cwd,path,timeout,directory,env)
            report['checks'].append(row)
            print(f'[{index}/{len(checks)}] {row["status"]} {name} ({row["seconds"]}s)',flush=True)
            if row['status']!='PASS':
                logpath=Path(row['log'])
                if logpath.is_file():
                    print(logpath.read_text(encoding='utf-8',errors='replace')[-2200:],flush=True)
            (directory/'summary.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    except KeyboardInterrupt:
        report['interrupted']=True
        print('\nVerification interrupted; completed results retained.',flush=True)
    finally:
        report['finished_at']=datetime.now(timezone.utc).isoformat()
        report['planned_checks']=len(checks)
        report['passed']=sum(row['status']=='PASS' for row in report['checks'])
        report['needs_attention']=[row['name'] for row in report['checks'] if row['status']!='PASS']
        report['not_run']=len(checks)-len(report['checks'])
        (directory/'summary.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        output=HERE/'outputs/combined_verification_review'
        output.mkdir(parents=True,exist_ok=True)
        (output/'summary.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        # Capture only relevant source for follow-up fixes; no environment/credential files.
        for relative in ('backend/vapt_registry_router.py','backend/vapt.py','backend/client_portal.py',
                         'backend/models.py','backend/vapt_tools/scripts/nuclei.py','frontend/src/App.jsx'):
            source=ROOT/relative
            if source.is_file():
                destination=output/relative
                destination.parent.mkdir(parents=True,exist_ok=True)
                destination.write_bytes(source.read_bytes())
        print(f'\nSUMMARY: {report["passed"]}/{len(checks)} checks passed; {len(report["needs_attention"])} need attention; {report["not_run"]} not run.',flush=True)
        for name in report['needs_attention']:
            print('NEEDS ATTENTION:',name,flush=True)
        print('Report:',directory/'summary.json',flush=True)
        print('No live scans, PostgreSQL changes, source edits, restarts, commits or pushes performed.',flush=True)
    return int(bool(report['needs_attention'] or report['not_run']))


if __name__=='__main__':
    raise SystemExit(main())
