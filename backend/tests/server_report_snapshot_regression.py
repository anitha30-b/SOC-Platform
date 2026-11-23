"""Run the actual report worker and routes against isolated SQLite fixtures.

No application startup, production database, external API, scan or file download.
Report download responses and generated report records remain in memory only.
"""
import ast
import asyncio
from datetime import datetime
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Optional
import unittest
from unittest.mock import patch

os.environ['DATABASE_URL']='sqlite://'
os.environ['JWT_SECRET_KEY']='isolated-server-report-test-not-for-deployment'
ROOT=Path(os.environ.get('SOC_REPORT_AUDIT_BACKEND',Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))

import asset_registration_regression as support
import database
import models
import rbac
import vapt_reporting_router as reporting
from fastapi import FastAPI
from fastapi.testclient import TestClient

for model in (models.Assessment,models.SecurityFinding,models.RiskAssessmentRun,models.VAPTReportRun):
    model.__table__.create(support.engine,checkfirst=True)


def snapshot_function():
    namespace={'Optional':Optional,'SecurityFinding':models.SecurityFinding,
               'PostExploitationValidation':models.PostExploitationValidation}
    for filename,wanted in (
        ('security_findings.py',{'calculate_severity','calculate_risk_level'}),
        ('risk_assessment_router.py',{'_finding_snapshot'}),
    ):
        nodes=[node for node in ast.parse((ROOT/filename).read_text(encoding='utf-8')).body
               if isinstance(node,ast.FunctionDef) and node.name in wanted]
        if {node.name for node in nodes}!=wanted:
            raise RuntimeError('Snapshot fixture helpers differ from expected.')
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),
                     str(ROOT/filename),'exec'),namespace)
    return namespace


class ServerReportSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.helpers=snapshot_function()
        with support.Factory() as db:
            for model in (models.VAPTReportRun,models.RiskAssessmentRun,models.SecurityFinding,models.Assessment):
                db.query(model).delete()
            for model in reversed(support.TABLE_MODELS):
                db.query(model).delete()
            for uid in (1,2):
                db.add(support.fixture(models.User,id=uid,role_id=1,client_id=None))
                db.add(support.fixture(models.Assessment,id=uid,user_id=uid,target=f'https://fixture-{uid}.invalid'))
            db.flush()
            self.add_finding(db,1,1,1,'OWNED-FINDING',8.1)
            # A deliberately foreign row linked to the same assessment must stay hidden.
            self.add_finding(db,2,2,1,'FOREIGN-FINDING',9.9)
            db.flush()
            finding=db.get(models.SecurityFinding,1)
            self.add_risk(db,1,1,finding)
            self.add_risk(db,2,2,db.get(models.SecurityFinding,2))
            db.commit()
        reporting.REPORT_JOBS.clear()
        self.identity=SimpleNamespace(id=1,role_id=1,client_id=None)
        app=FastAPI()
        app.include_router(reporting.router)
        app.dependency_overrides[reporting.get_db]=support.get_db
        app.dependency_overrides[rbac.get_current_user]=lambda:self.identity
        self.client=TestClient(app)

    def tearDown(self):
        self.client.close()
        reporting.REPORT_JOBS.clear()

    def add_finding(self,db,ident,owner,assessment,finding_id,score):
        severity=self.helpers['calculate_severity'](score) if score is not None else 'HIGH'
        db.add(support.fixture(models.SecurityFinding,id=ident,user_id=owner,assessment_id=assessment,
            finding_id=finding_id,title=f'{finding_id} original title',vulnerability='Synthetic fixture only',
            tool_name='Nuclei',tool_category='Web Application Security',cvss_score=score,
            severity=severity,risk_level=self.helpers['calculate_risk_level'](severity),status='OPEN',
            description='Synthetic description',evidence='Synthetic evidence',remediation='Synthetic remediation'))

    def add_risk(self,db,ident,owner,finding):
        snapshot=self.helpers['_finding_snapshot'](finding,None)
        severity=snapshot['calculated_severity'].lower()
        level=snapshot['calculated_risk_level'].lower()
        db.add(support.fixture(models.RiskAssessmentRun,id=ident,user_id=owner,assessment_id=1,
            assessment_run_id=f'RISK-FIXTURE-{ident}',job_id=f'RISK-JOB-{ident}',status='COMPLETED',
            total_findings=1,average_cvss=float(finding.cvss_score or 0),highest_cvss=float(finding.cvss_score or 0),
            overall_risk=severity.upper(),severity_summary=json.dumps({severity:1}),
            risk_level_summary=json.dumps({level:1}),status_summary=json.dumps({'open':1}),
            validation_summary=json.dumps({'total_findings':1,'validation_not_run':1}),
            findings_snapshot=json.dumps([snapshot])))

    def run_worker(self,assessment=1):
        job_id='SYNTHETIC-REPORT-JOB'
        reporting.REPORT_JOBS[job_id]={'user_id':1,'status':'queued','progress':0}
        async def no_sleep(*args,**kwargs):
            return None
        with patch.object(database,'SessionLocal',support.Factory),patch.object(reporting.asyncio,'sleep',no_sleep):
            asyncio.run(reporting._run_report(job_id,SimpleNamespace(assessment_id=assessment,report_type='COMPLETE'),1))
        return reporting.REPORT_JOBS[job_id]

    def canonical(self):
        with support.Factory() as db:
            record=db.query(models.VAPTReportRun).filter(models.VAPTReportRun.user_id==1).one()
            return json.loads(record.canonical_data)

    def assert_no_completed_report(self,job):
        self.assertEqual(job['status'],'failed',job)
        with support.Factory() as db:
            self.assertEqual(db.query(models.VAPTReportRun).count(),0)

    def test_owned_generation_excludes_foreign_findings_and_risk_run(self):
        self.assertEqual(self.run_worker()['status'],'completed')
        data=self.canonical()
        self.assertEqual([row['finding_id'] for row in data['findings']],['OWNED-FINDING'])
        self.assertEqual(data['risk_assessment']['assessment_run_id'],'RISK-FIXTURE-1')
        self.assertEqual(data['risk_assessment']['total_findings'],len(data['findings']))

    def test_added_finding_requires_a_fresh_risk_assessment(self):
        with support.Factory() as db:
            self.add_finding(db,3,1,1,'NEW-OWNED-FINDING',5.0)
            db.commit()
        self.assert_no_completed_report(self.run_worker())

    def test_deleted_finding_requires_a_fresh_risk_assessment(self):
        with support.Factory() as db:
            db.delete(db.get(models.SecurityFinding,1))
            db.commit()
        self.assert_no_completed_report(self.run_worker())

    def test_changed_score_requires_a_fresh_risk_assessment(self):
        with support.Factory() as db:
            db.get(models.SecurityFinding,1).cvss_score=9.8
            db.commit()
        self.assert_no_completed_report(self.run_worker())

    def test_changed_finding_status_requires_a_fresh_risk_assessment(self):
        with support.Factory() as db:
            db.get(models.SecurityFinding,1).status='FIXED'
            db.commit()
        self.assert_no_completed_report(self.run_worker())

    def test_corrupt_risk_snapshot_does_not_generate_a_completed_report(self):
        with support.Factory() as db:
            db.get(models.RiskAssessmentRun,1).findings_snapshot='{invalid-json'
            db.commit()
        self.assert_no_completed_report(self.run_worker())

    def test_unscored_findings_remain_unavailable_in_canonical_json(self):
        with support.Factory() as db:
            finding=db.get(models.SecurityFinding,1)
            finding.cvss_score=None
            run=db.get(models.RiskAssessmentRun,1)
            run.findings_snapshot=json.dumps([self.helpers['_finding_snapshot'](finding,None)])
            # Existing Stage 08 stores zeros when no score exists; reporting must not call them real scores.
            run.average_cvss=run.highest_cvss=0.0
            db.commit()
        self.assertEqual(self.run_worker()['status'],'completed')
        data=self.canonical()
        self.assertIsNone(data['findings'][0]['cvss_score'])
        self.assertIsNone(data['risk_assessment']['average_cvss'])
        self.assertIsNone(data['risk_assessment']['highest_cvss'])

    def test_genuine_zero_score_is_preserved(self):
        with support.Factory() as db:
            finding=db.get(models.SecurityFinding,1)
            finding.cvss_score=0.0
            finding.severity=self.helpers['calculate_severity'](0.0)
            finding.risk_level=self.helpers['calculate_risk_level'](finding.severity)
            run=db.get(models.RiskAssessmentRun,1)
            run.findings_snapshot=json.dumps([self.helpers['_finding_snapshot'](finding,None)])
            run.average_cvss=run.highest_cvss=0.0
            run.severity_summary=json.dumps({'none':1})
            db.commit()
        self.assertEqual(self.run_worker()['status'],'completed')
        self.assertEqual(self.canonical()['findings'][0]['cvss_score'],0.0)

    def test_report_remains_immutable_after_generation(self):
        self.assertEqual(self.run_worker()['status'],'completed')
        original=self.client.get('/vapt/reporting/SYNTHETIC-REPORT-JOB/results').json()['canonical_data']
        with support.Factory() as db:
            finding=db.get(models.SecurityFinding,1)
            finding.title='Changed after report creation'
            finding.cvss_score=1.0
            db.commit()
        current=self.client.get('/vapt/reporting/SYNTHETIC-REPORT-JOB/results').json()['canonical_data']
        self.assertEqual(original,current)

    def test_foreign_assessment_cannot_generate_report(self):
        self.assert_no_completed_report(self.run_worker(assessment=2))

    def test_unfinished_risk_assessment_cannot_generate_report(self):
        with support.Factory() as db:
            db.get(models.RiskAssessmentRun,1).status='RUNNING'
            db.commit()
        self.assert_no_completed_report(self.run_worker())

    def test_json_and_xml_downloads_keep_the_stored_snapshot(self):
        self.assertEqual(self.run_worker()['status'],'completed')
        json_response=self.client.get('/vapt/reporting/SYNTHETIC-REPORT-JOB/download/JSON')
        xml_response=self.client.get('/vapt/reporting/SYNTHETIC-REPORT-JOB/download/XML')
        self.assertEqual(json_response.status_code,200,json_response.text)
        self.assertEqual(xml_response.status_code,200,xml_response.text)
        self.assertEqual(json_response.json(),self.canonical())
        self.assertIn('OWNED-FINDING',xml_response.text)
        self.assertNotIn('FOREIGN-FINDING',xml_response.text)


if __name__=='__main__':
    unittest.main(verbosity=2)
