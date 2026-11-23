"""Actual ZAP result handlers through owned history, events and risk/report workers."""
import ast
import asyncio
import __future__
from datetime import datetime
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import time
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(os.environ.get('SOC_TOOL_AUDIT_BACKEND', Path(__file__).resolve().parents[1]))
os.environ['DATABASE_URL'] = 'sqlite://'
os.environ['JWT_SECRET_KEY'] = 'isolated-zap-workflow-linkage'
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'tests'))
import zap_access_regression as zap
import nuclei_report_contract_regression as reports

models, support = reports.models, reports.support


class ZapAssessmentLinkageTests(unittest.TestCase):
    def setUp(self):
        with support.Factory() as db:
            for model in reversed(reports.EXTRA):
                db.query(model).delete()
            db.commit()
        self.zap = zap.ZapAccessTests()
        self.zap.setUp()
        reports.reporting.REPORT_JOBS.clear()

    def tearDown(self):
        reports.reporting.REPORT_JOBS.clear()
        self.zap.tearDown()

    def save_result(self):
        ident = self.zap.start()
        response = self.zap.client.get('/vapt/zap/scan/'+ident+'/results', headers=self.zap.headers)
        self.assertEqual(response.status_code, 200, response.text)
        return ident, response.json()

    def test_each_scan_preserves_a_separate_assessment_history(self):
        _, first = self.save_result()
        original_get = self.zap.ns['zap_get']
        async def second_get(path, params=None):
            if path.endswith('/scan/'):
                return {'scan':'second-independent-scan'}
            return await original_get(path, params)
        self.zap.ns['zap_get'] = second_get
        _, second = self.save_result()
        self.assertNotEqual(first['assessment_id'], second['assessment_id'],
            'Two distinct ZAP scans reused one assessment; the scan history can be overwritten.')
        with support.Factory() as db:
            self.assertEqual(db.query(models.Assessment).filter_by(user_id=1).count(), 2)

    def test_zap_event_links_the_same_finding_assessment_and_customer(self):
        _, result = self.save_result()
        with support.Factory() as db:
            finding = db.query(models.SecurityFinding).filter_by(assessment_id=result['assessment_id'],user_id=1).one()
            events = db.query(models.SecurityEvent).filter_by(assessment_id=finding.assessment_id).all()
            self.assertTrue(events, 'Saved ZAP finding has no assessment-linked SIEM event.')
            self.assertTrue(any(event.owner_user_id==1 and event.client_id==10 for event in events),
                'ZAP SIEM event does not retain the initiating owner/customer scope.')

    def test_completed_job_can_be_read_after_in_memory_jobs_are_lost(self):
        ident, _ = self.save_result()
        self.zap.ns['ZAP_JOBS'].clear()
        self.zap.calls.clear()
        response = self.zap.client.get('/vapt/zap/scan/'+ident+'/results', headers=self.zap.headers)
        self.assertEqual(response.status_code, 200,
            'Completed ZAP result cannot be restored without its in-memory job.')
        self.assertEqual(response.json()['status'], 'completed')
        self.assertFalse(self.zap.calls, 'Restoring persisted results should not contact the scanner.')

    def report_for_saved_assessment(self, result):
        helpers = reports.report_fixtures.snapshot_function()
        namespace = dict(helpers, datetime=datetime, json=json, time=time, uuid=uuid, asyncio=asyncio,
            RISK_ASSESSMENT_JOBS={'zap-risk-contract':{'cancel_requested':False}},
            Assessment=models.Assessment, SecurityFinding=models.SecurityFinding,
            RiskAssessmentRun=models.RiskAssessmentRun, PostExploitationValidation=models.PostExploitationValidation,
            get_db=lambda: iter([support.Factory()]))
        names = {'_now','_serialize_run','_finding_snapshot','_run_risk_assessment'}
        nodes = [n for n in ast.parse((ROOT/'risk_assessment_router.py').read_text(encoding='utf-8')).body
                 if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in names]
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'risk_assessment_router.py','exec',
                     flags=__future__.annotations.compiler_flag),namespace)
        asyncio.run(namespace['_run_risk_assessment']('zap-risk-contract',NS(assessment_id=result['assessment_id']),1))
        risk_job = namespace['RISK_ASSESSMENT_JOBS']['zap-risk-contract']
        self.assertEqual(risk_job['status'], 'completed', 'ZAP-owned risk assessment did not complete.')
        reports.reporting.REPORT_JOBS['zap-report-contract'] = {}
        with patch.object(reports.database, 'SessionLocal', support.Factory):
            asyncio.run(reports.reporting._run_report('zap-report-contract',
                NS(assessment_id=result['assessment_id'],report_type='COMPLETE'),1))
        report_job = reports.reporting.REPORT_JOBS['zap-report-contract']
        self.assertEqual(report_job['status'], 'completed', 'Report worker did not accept the saved ZAP findings.')
        canonical = report_job['result']['canonical_data']
        self.assertEqual({row['finding_id'] for row in canonical['findings']},
                         {row['finding_id'] for row in result['findings']})
        self.assertEqual(canonical['risk_assessment']['total_findings'], len(result['findings']))
        self.assertIsNone(canonical['risk_assessment']['average_cvss'])
        self.assertTrue(all(row['tool_name']=='OWASP ZAP' and row['cvss_score'] is None
                            for row in canonical['findings']))
        with support.Factory() as db:
            assessment = db.query(models.Assessment).filter_by(id=result['assessment_id'],user_id=1).one()
            self.assertEqual(assessment.report_status, 'completed')
        return canonical

    def test_info_findings_reach_actual_risk_and_report_without_invented_cvss(self):
        _, result = self.save_result()
        canonical = self.report_for_saved_assessment(result)
        self.assertEqual(canonical['findings'][0]['severity'], 'INFO')

    def test_unknown_findings_remain_unrated_in_actual_report(self):
        self.zap.alert['risk'] = 'unknown'
        _, result = self.save_result()
        canonical = self.report_for_saved_assessment(result)
        self.assertEqual(canonical['findings'][0]['severity'], 'UNRATED')
        self.assertEqual(canonical['risk_assessment']['overall_risk'], 'UNRATED')

    def test_valid_zero_findings_retain_history_and_generate_empty_report(self):
        self.zap.alert_ids = []
        _, result = self.save_result()
        self.assertEqual(result['total_findings'], 0)
        canonical = self.report_for_saved_assessment(result)
        self.assertEqual(canonical['findings'], [])

    def test_storage_failure_rolls_back_findings_and_does_not_claim_saved_success(self):
        ident = self.zap.start()
        def failing_session():
            with support.Factory() as db:
                with patch.object(db,'commit',side_effect=RuntimeError('synthetic storage failure')):
                    yield db
        self.zap.app.dependency_overrides[self.zap.ns['get_db']] = failing_session
        response = self.zap.client.get('/vapt/zap/scan/'+ident+'/results', headers=self.zap.headers)
        self.assertEqual(response.status_code, 502)
        with support.Factory() as db:
            self.assertEqual(db.query(models.SecurityFinding).filter_by(assessment_id=self.zap.assessment_id).count(),0)
            self.assertEqual(db.query(models.SecurityEvent).filter_by(assessment_id=self.zap.assessment_id).count(),0)
        self.assertFalse(self.zap.published)
        self.assertNotEqual(self.zap.ns['ZAP_JOBS'][ident]['status'], 'completed')

    def test_saved_result_is_hidden_from_other_accounts_after_restart(self):
        ident, _ = self.save_result()
        self.zap.ns['ZAP_JOBS'].clear()
        self.zap.calls.clear()
        for owner in ('2','4'):
            response = self.zap.client.get('/vapt/zap/scan/'+ident+'/results',headers={'X-Test-User':owner})
            self.assertEqual(response.status_code,404,response.text)
        self.assertFalse(self.zap.calls)

    def test_saved_result_does_not_follow_changed_customer_scope(self):
        ident, _ = self.save_result()
        self.zap.ns['ZAP_JOBS'].clear()
        self.zap.user_scope = 20
        with support.Factory() as db:
            db.get(models.User,1).client_id = 20
            db.commit()
        self.zap.calls.clear()
        response = self.zap.client.get('/vapt/zap/scan/'+ident+'/results',headers=self.zap.headers)
        self.assertEqual(response.status_code,404,response.text)
        self.assertFalse(self.zap.calls)

    def test_replay_preserves_one_event_and_publishes_only_after_commit(self):
        ident, result = self.save_result()
        self.assertEqual(len(self.zap.published),1)
        event = self.zap.published[0]
        self.assertEqual((event['owner_user_id'],event['client_id'],event['assessment_id']),
                         (1,10,result['assessment_id']))
        with support.Factory() as db:
            self.assertEqual(db.query(models.SecurityEvent).filter_by(event_id=event['event_id']).count(),1)
            rows = db.query(models.BackgroundJob).filter_by(tool='OWASP ZAP').all()
            self.assertEqual(len(rows),1)
            self.assertEqual(len(rows[0].job_id),36)
        again = self.zap.client.get('/vapt/zap/scan/'+ident+'/results',headers=self.zap.headers)
        self.assertEqual(again.json()['findings'],result['findings'])
        self.assertEqual(len(self.zap.published),1)

    def test_post_commit_notification_failure_retains_saved_evidence(self):
        ident = self.zap.start()
        def fail(events):
            raise RuntimeError('synthetic notification failure')
        self.zap.ns['_publish_zap_events'] = fail
        response = self.zap.client.get('/vapt/zap/scan/'+ident+'/results',headers=self.zap.headers)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['status'],'completed_with_errors')
        self.assertEqual(response.json()['persistence']['status'],'saved')
        self.zap.ns['ZAP_JOBS'].clear()
        self.zap.calls.clear()
        loaded = self.zap.client.get('/vapt/zap/scan/'+ident+'/results',headers=self.zap.headers)
        self.assertEqual(loaded.status_code,200,loaded.text)
        self.assertEqual(loaded.json()['total_findings'],1)
        self.assertFalse(self.zap.calls)

    def test_distinct_scans_keep_distinct_events_even_when_zap_reuses_numeric_id(self):
        first_id, first = self.save_result()
        second_id, second = self.save_result()
        self.assertNotEqual(first_id, second_id)
        self.assertNotEqual(first['assessment_id'],second['assessment_id'])
        with support.Factory() as db:
            events = db.query(models.SecurityEvent).all()
            self.assertEqual(len(events),2)
            self.assertEqual(len({row.event_id for row in events}),2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
